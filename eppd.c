/* eppd.c — EPP (RFC 5730) registry front-end sidecar.
 *
 * Accepts registrar EPP/TLS sessions (RFC 5734, TCP/700, mandatory mutual
 * TLS), and will publish delegation records (NS/A/AAAA) into the zone:*
 * keyspace dnsd already serves — the same Valkey-bus pattern every other
 * sidecar in this project uses. Phase 1 scope; see CLAUDE-eppd.md.
 *
 * This file is the Phase-1 *skeleton*: Valkey wiring, TLS/mTLS listener
 * bring-up, live cert/CA reload, and the sandbox. The actual EPP session
 * protocol (RFC 5734 framing, RFC 5730 command/response XML, the RFC 5731/
 * 5732/5733 object mappings, and the zone:* publish pipeline) is the next
 * piece of work — accept_loop() below marks exactly where it plugs in.
 *
 * Why a separate sidecar, not inside dnsd (same rationale as certd/mdnsd/
 * doqd — CLAUDE.md "the authoritative daemon ... stays small"): dnsd holds
 * DNSSEC signing keys and the TSIG secret. A hand-rolled EPP/XML parser is a
 * large untrusted-input surface (registrar sessions, arbitrary XML) that
 * must not be able to reach those keys even if it has a bug. eppd never
 * answers DNS queries and dnsd never speaks EPP — they meet only through
 * zone:* and config:* in Valkey, per the ownership table.
 *
 * mTLS is NOT optional here the way it is for apid's DoH+mgmt split: RFC
 * 5734 requires a registrar client certificate for every session, so the CA
 * (config:eppd_mtls_ca_pem) is a hard startup requirement, not a fallback —
 * see tls_material_load().
 *
 * Config (Valkey):
 *   config:eppd_enabled          "1" to start (default off — never on by
 *                                accident, same convention as doqd)
 *   config:eppd_port             TCP listen port (RFC 5734 default 700)
 *   config:eppd_mtls_ca_pem      registrar CA bundle — REQUIRED, no plain-TLS
 *                                fallback (unlike apid's optional split)
 *   config:eppd_{chroot_dir,isolation_mode,privdrop_user,privdrop_group,
 *   seccomp_mode}                sandbox knobs, resolverd-style (own prefix
 *                                since eppd needs a different filesystem/
 *                                syscall profile: inbound TLS only, no
 *                                outbound network, no getaddrinfo needed)
 * TLS material: cert:current (written by certd), falling back to
 * config:eppd_tls_{cert,key}_pem — same hot-reload contract as dnsd/apid/
 * doqd. Writes nothing to zone:* or config:* yet (Phase 1's publish
 * pipeline is the next piece of work); the epp:* object-store namespace it
 * will own
 * is not yet touched by this skeleton.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "dns_wire.h"
#include "sandbox.h"

#define EPPD_DEFAULT_PORT 700

/* ── Logging ─────────────────────────────────────────────────────────────── */
static void dns_log(int level, const char *fmt, ...) {
    static const char *names[] = {"EMERG",   "ALERT",  "CRIT", "ERR",
                                  "WARNING", "NOTICE", "INFO", "DEBUG"};
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
    fprintf(stderr, "%s [%-6s] ", ts, level >= 0 && level <= 7 ? names[level] : "?");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* sandbox_apply's log callback has the same (int, const char *, ...)
 * signature as dns_log above, so it is passed directly (dnsd/resolverd do
 * the same — see sandbox.h). */

/* ── Config / state ──────────────────────────────────────────────────────── */
static char g_valkey_host[256] = "127.0.0.1";
static int g_valkey_port = 6379;
static char g_valkey_pass[256] = "";
static int g_eppd_enabled = 0;
static int g_eppd_port = EPPD_DEFAULT_PORT;
static char g_tls_cert_pem[VKC_BUF] = "";
static char g_tls_key_pem[VKC_BUF] = "";
static char g_mtls_ca_pem[VKC_BUF] = "";
static SSL_CTX *g_eppd_ctx = NULL;
static pthread_mutex_t g_tls_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

/* ── Valkey — thin wrappers over the shared libdnswire RESP client (see
 * dns_wire.h: vkc_connect_to/vkc_ensure_to/vkc_cmd). eppd is the first
 * caller of the hoisted version rather than carrying its own copy. ──────── */
static vkc_conn_t g_vk = {.fd = -1};
static pthread_mutex_t g_vk_mutex = PTHREAD_MUTEX_INITIALIZER;

static int vk_get(const char *key, char *out, int olen) {
    pthread_mutex_lock(&g_vk_mutex);
    if (vkc_ensure_to(&g_vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    vkc_reply_t r;
    if (vkc_cmd(&g_vk, &r, 2, "GET", key) < 0) {
        g_vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (r.type != 2)
        return 0;
    safe_strcpy(out, r.str, olen);
    return 1;
}

static int vk_set(const char *key, const char *val) {
    pthread_mutex_lock(&g_vk_mutex);
    if (vkc_ensure_to(&g_vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    vkc_reply_t r;
    int ok = vkc_cmd(&g_vk, &r, 3, "SET", key, val) == 0 && r.type == 0;
    pthread_mutex_unlock(&g_vk_mutex);
    return ok;
}

static int vk_incr(const char *key) {
    pthread_mutex_lock(&g_vk_mutex);
    if (vkc_ensure_to(&g_vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    vkc_reply_t r;
    int ok = vkc_cmd(&g_vk, &r, 2, "INCR", key) == 0;
    pthread_mutex_unlock(&g_vk_mutex);
    return ok ? 0 : -1;
}

/* KEYS (not SCAN) — matches this project's existing convention for bounded,
 * infrequent lookups; zone_table:* is small (one entry per configured
 * zone), never a large keyspace scan. Returns the number of keys found
 * (each copied into out[], caller-owned, bounded by maxkeys), or -1 on
 * error. */
static int vk_list_keys(const char *pattern, char out[][256], int maxkeys) {
    pthread_mutex_lock(&g_vk_mutex);
    if (vkc_ensure_to(&g_vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    vkc_reply_t r;
    if (vkc_cmd(&g_vk, &r, 2, "KEYS", pattern) < 0 || r.type != 5) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    int n = 0;
    for (int i = 0; i < r.count; i++) {
        vkc_reply_t kr;
        if (vkc_parse(&g_vk, &kr) < 0)
            break;
        if (kr.type == 2 && n < maxkeys)
            safe_strcpy(out[n++], kr.str, 256);
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return n;
}

/* ── TLS — cert:current / config:eppd_tls_*_pem hot-reload, mirroring doqd's
 * tls_reload contract. Reuses the shared tls_server_ctx_from_pem directly
 * (dns_wire.c) rather than a local reimplementation, unlike apid/doqd, which
 * each predate that helper and still carry their own. ──────────────────── */
static int tls_material_load(void) {
    char blob[VKC_BUF];
    if (vk_get("cert:current", blob, sizeof(blob)) && blob[0] &&
        cert_current_split(blob, g_tls_cert_pem, sizeof(g_tls_cert_pem), g_tls_key_pem,
                           sizeof(g_tls_key_pem)) == 0) {
        /* fall through to also (re)read the CA below */
    } else {
        char cert[VKC_BUF] = "", key[VKC_BUF] = "";
        int have_cert = vk_get("config:eppd_tls_cert_pem", cert, sizeof(cert)) && cert[0];
        int have_key = vk_get("config:eppd_tls_key_pem", key, sizeof(key)) && key[0];
        if (!have_cert || !have_key)
            return 0;
        safe_strcpy(g_tls_cert_pem, cert, sizeof(g_tls_cert_pem));
        safe_strcpy(g_tls_key_pem, key, sizeof(g_tls_key_pem));
    }
    /* RFC 5734 mandates a registrar client certificate for every session —
     * unlike apid's optional mTLS split, there is no plain-TLS fallback here.
     * No CA configured means eppd has no way to authenticate a registrar, so
     * it must not open the listener at all (fail closed, not fail open). */
    char ca[VKC_BUF] = "";
    if (!vk_get("config:eppd_mtls_ca_pem", ca, sizeof(ca)) || !ca[0]) {
        dns_log(LOG_ERR, "[TLS] config:eppd_mtls_ca_pem not set — RFC 5734 requires registrar "
                         "mTLS, refusing to open a listener with no way to verify a client\n");
        return 0;
    }
    safe_strcpy(g_mtls_ca_pem, ca, sizeof(g_mtls_ca_pem));
    return 1;
}

/* Reload the certificate + CA on the one persistent SSL_CTX (creating it
 * first, on the very first call). verify_client=1 is unconditional (see
 * tls_material_load's comment above). Safe to call from the keyspace-watch
 * thread at any time after startup. */
static void tls_reload(void) {
    if (!tls_material_load()) {
        dns_log(LOG_WARNING,
                "[TLS] cert/key/CA unavailable — EPP listener stays down until published\n");
        return;
    }
    SSL_CTX *ctx = tls_server_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, g_mtls_ca_pem, 1);
    if (!ctx) {
        dns_log(LOG_ERR, "[TLS] context build failed — keeping the previous certificate (if "
                         "any)\n");
        return;
    }
    pthread_mutex_lock(&g_tls_mutex);
    SSL_CTX *old = g_eppd_ctx;
    g_eppd_ctx = ctx;
    pthread_mutex_unlock(&g_tls_mutex);
    if (old)
        SSL_CTX_free(old);
    dns_log(LOG_INFO, "[TLS] EPP mTLS context (re)loaded\n");
}

/* ── Live reload via the shared keyspace_watch_loop (dns_wire.h) — eppd's
 * first real use of the hoisted watcher: only the callbacks are per-daemon,
 * the connect/backoff/PSUBSCRIBE/dispatch mechanics are not reimplemented
 * here at all. ─────────────────────────────────────────────────────────── */
static void keyspace_catchup(void *ctx) {
    (void) ctx;
    tls_reload();
}

static void keyspace_on_key(const char *key, void *ctx) {
    (void) ctx;
    if (strncmp(key, "cert:current", 13) == 0 || strncmp(key, "config:eppd_tls_", 16) == 0 ||
        strncmp(key, "config:eppd_mtls_ca_pem", 23) == 0)
        tls_reload();
}

/* ── Sandbox — eppd is the first inbound-TLS-only daemon to adopt
 * sandbox_apply() (certd/apid/mdnsd/doqd don't use it today); modeled on
 * resolverd's apply_sandbox. No SANDBOX_SYS_GETADDRINFO: Phase 1 has no
 * outbound network calls (no CDS scanning, no CA contact — that's certd's
 * job), and Valkey is always reached via 127.0.0.1/an IP literal in every
 * config this daemon has been run with, so no real getaddrinfo call has
 * ever been exercised (its only members, recvmmsg/sendmmsg, are already in
 * the base whitelist regardless).
 *
 * Harvest (2026-07-06): strace -f across startup, an mTLS-rejected
 * connection, a full EPP session (login/create/info/duplicate-reject/
 * logout) via tests/epp_client.py, and a malformed-frame (garbage declared
 * length) connection — 25 distinct syscalls post-filter-install, all
 * already covered by sandbox.c's base[] whitelist. Zero gaps; enforce ran
 * clean (full epp_client.py pass, no EPERM). One real bug found and fixed
 * during this harvest, not by inspection: an earlier version of main()
 * created the accept_loop thread (and everything it later spawns) BEFORE
 * calling apply_eppd_sandbox() — since sandbox.c's seccomp_load() has no
 * SCMP_FLTATR_CTL_TSYNC, the filter only ever covers the calling thread
 * going forward, never a thread that already exists, so the entire
 * connection-handling path ran completely unconfined. Fixed by binding the
 * listener synchronously in main() and applying the sandbox before any
 * thread is created (see accept_loop's own comment). Re-harvest with
 * seccomp_mode=audit first if this profile is ever ported to a different
 * libc/kernel. */
static void apply_eppd_sandbox(void) {
    sandbox_config_t sb;
    memset(&sb, 0, sizeof(sb));
    vk_get("config:eppd_chroot_dir", sb.chroot_dir, sizeof(sb.chroot_dir));
    sandbox_env_override(sb.chroot_dir, sizeof(sb.chroot_dir), "EPPD_CHROOT");
    vk_get("config:eppd_isolation_mode", sb.isolation_mode, sizeof(sb.isolation_mode));
    sandbox_env_override(sb.isolation_mode, sizeof(sb.isolation_mode), "EPPD_ISOLATION");
    vk_get("config:eppd_privdrop_user", sb.privdrop_user, sizeof(sb.privdrop_user));
    sandbox_env_override(sb.privdrop_user, sizeof(sb.privdrop_user), "EPPD_USER");
    vk_get("config:eppd_privdrop_group", sb.privdrop_group, sizeof(sb.privdrop_group));
    sandbox_env_override(sb.privdrop_group, sizeof(sb.privdrop_group), "EPPD_GROUP");
    vk_get("config:eppd_seccomp_mode", sb.seccomp_mode, sizeof(sb.seccomp_mode));
    sandbox_env_override(sb.seccomp_mode, sizeof(sb.seccomp_mode), "EPPD_SECCOMP");
    sb.seccomp_default = SANDBOX_SECCOMP_ENFORCE; /* harvest-validated, zero gaps — see above */
    sb.extra_syscall_groups = 0;
    sb.log = dns_log;
    sb.tag = "eppd";
    sandbox_apply(&sb);
}

/* ── RFC 5734 §4 transport framing ────────────────────────────────────────
 * A 4-byte big-endian TOTAL length (including the 4 header octets
 * themselves), followed by exactly that many bytes of EPP/XML. */
#define EPP_MAX_FRAME 65535 /* payload ceiling — a resource-exhaustion guard, ample for Phase 1 */

/* Pure, fuzzable (no I/O): given a buffer holding zero or more complete
 * frames or one partial frame, extract ONE frame. Mirrors doqd's
 * doq_frame_next contract exactly (make fuzz-doq's sibling here is
 * make fuzz-eppd, task #8).
 *   >0 : a complete frame was found; *xml_off / *xml_len locate its XML
 *        payload within buf, *consumed is the total byte count (including
 *        the 4-byte header) the caller should drop from the front of buf.
 *   0  : buf holds fewer than a complete frame — the caller needs more data.
 *   -1 : malformed (declared total length < 4 or > EPP_MAX_FRAME + 4) — the
 *        caller must fail closed and close the connection, never resync by
 *        guessing at a new frame boundary. */
static int epp_frame_next(const uint8_t *buf, int buflen, int *xml_off, int *xml_len,
                          int *consumed) {
    if (buflen < 4)
        return 0;
    uint32_t total = ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) |
                     ((uint32_t) buf[2] << 8) | (uint32_t) buf[3];
    if (total < 4 || total > (uint32_t) EPP_MAX_FRAME + 4)
        return -1;
    if ((uint32_t) buflen < total)
        return 0;
    *xml_off = 4;
    *xml_len = (int) (total - 4);
    *consumed = (int) total;
    return 1;
}

/* Read exactly one frame from a persistent connection: accumulate bytes into
 * `acc` (a per-connection scratch buffer the caller owns across calls, so a
 * client that pipelines multiple frames back-to-back doesn't lose the
 * trailing bytes of one read() to the next call) until epp_frame_next finds
 * a complete frame, then shift any leftover bytes to the front of `acc` for
 * the next call. Returns the XML payload length (out is NUL-terminated), 0
 * on a clean connection close with no partial frame pending, or -1 on any
 * I/O error, timeout, or malformed frame (fail closed: caller must close the
 * connection). */
static int epp_read_frame(SSL *ssl, uint8_t *acc, int *acclen, int acccap, char *out, int outcap) {
    for (;;) {
        int xoff, xlen, consumed;
        int r = epp_frame_next(acc, *acclen, &xoff, &xlen, &consumed);
        if (r < 0)
            return -1;
        if (r > 0) {
            if (xlen >= outcap)
                return -1; /* leave room for the NUL below */
            memcpy(out, acc + xoff, (size_t) xlen);
            out[xlen] = 0;
            memmove(acc, acc + consumed, (size_t) (*acclen - consumed));
            *acclen -= consumed;
            return xlen;
        }
        if (*acclen >= acccap)
            return -1; /* frame (once fully declared) would exceed EPP_MAX_FRAME anyway */
        int n = SSL_read(ssl, acc + *acclen, acccap - *acclen);
        if (n <= 0)
            return *acclen == 0 ? 0 : -1; /* clean close only counts if no partial frame pending */
        *acclen += n;
    }
}

static int epp_write_frame(SSL *ssl, const char *xml, int xlen) {
    if (xlen < 0 || (uint32_t) xlen > (uint32_t) EPP_MAX_FRAME)
        return -1;
    uint32_t total = (uint32_t) xlen + 4;
    uint8_t hdr[4] = {(uint8_t) (total >> 24), (uint8_t) (total >> 16), (uint8_t) (total >> 8),
                      (uint8_t) total};
    if (SSL_write(ssl, hdr, 4) != 4)
        return -1;
    int sent = 0;
    while (sent < xlen) {
        int n = SSL_write(ssl, xml + sent, xlen - sent);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return 0;
}

/* ── Minimal, bounded EPP/XML tokenizer ───────────────────────────────────
 * Not a general-purpose XML parser (no external entities, no DTD/internal
 * subset processing, no namespace URI resolution — a namespace PREFIX like
 * "domain:" is matched as a literal string, which is what every real EPP
 * client actually sends). Untrusted-input parser surface: fuzzed via
 * make fuzz-eppd (task #8), fails closed on anything it can't confidently
 * classify rather than guess. Depth-bounded to fail closed on adversarially
 * deep nesting instead of blowing the C stack (xml_skip_to_close recurses
 * one frame per nesting level). */
#define EPP_XML_MAX_DEPTH 32

typedef enum {
    XMLTAG_OPEN,      /* <name ...> (not self-closing) */
    XMLTAG_CLOSE,     /* </name> */
    XMLTAG_SELFCLOSE, /* <name .../> */
    XMLTAG_SKIP,      /* a comment, CDATA section, or PI — already consumed, no name */
    XMLTAG_ERROR,     /* malformed, or a rejected construct (see below) */
    XMLTAG_EOF,       /* reached `end` with no further '<' */
} xml_tagkind_t;

/* Scans forward from *pos (bounded by `end`) to the next tag-like construct,
 * skipping any interleaving text. `*tag_start` is always set to the offset
 * of the '<' that was found (distinct from the caller's original *pos,
 * which may have pointed at preceding text content — a caller that wants
 * "where does this element's content end" needs *this*, not *pos*). On
 * XMLTAG_OPEN/CLOSE/SELFCLOSE, fills *name / *name_len (pointing into buf,
 * NOT NUL-terminated) and advances *pos to just past the tag's '>'. On
 * XMLTAG_SKIP, *pos is advanced past a fully- consumed comment
 * ("<!--...-->"), CDATA section ("<![CDATA[...]]>"), or processing
 * instruction ("<?...?>") — no name is filled; the caller should just
 * continue scanning. A "<!DOCTYPE" is rejected outright as XMLTAG_ERROR — an
 * XXE guardrail: this parser never resolves external entities anyway, so
 * refusing a DOCTYPE outright is simpler and safer than parsing an internal
 * subset only to ignore it. Any other unrecognized "<!" markup declaration
 * is likewise rejected rather than guessed at. */
static xml_tagkind_t xml_next_tag(const char *buf, int *pos, int end, const char **name,
                                  int *name_len, int *tag_start) {
    int p = *pos;
    while (p < end && buf[p] != '<')
        p++;
    if (p >= end) {
        *pos = end;
        return XMLTAG_EOF;
    }
    *tag_start = p;
    if (p + 1 < end && buf[p + 1] == '!') {
        if (p + 3 < end && buf[p + 2] == '-' && buf[p + 3] == '-') {
            int q = p + 4;
            while (q + 2 < end && !(buf[q] == '-' && buf[q + 1] == '-' && buf[q + 2] == '>'))
                q++;
            if (q + 2 >= end)
                return XMLTAG_ERROR; /* unterminated comment */
            *pos = q + 3;
            return XMLTAG_SKIP;
        }
        if (p + 8 < end && memcmp(buf + p + 2, "[CDATA[", 7) == 0) {
            int q = p + 9;
            while (q + 2 < end && !(buf[q] == ']' && buf[q + 1] == ']' && buf[q + 2] == '>'))
                q++;
            if (q + 2 >= end)
                return XMLTAG_ERROR; /* unterminated CDATA */
            *pos = q + 3;
            return XMLTAG_SKIP;
        }
        return XMLTAG_ERROR; /* DOCTYPE or any other markup declaration — rejected */
    }
    if (p + 1 < end && buf[p + 1] == '?') {
        int q = p + 2;
        while (q + 1 < end && !(buf[q] == '?' && buf[q + 1] == '>'))
            q++;
        if (q + 1 >= end)
            return XMLTAG_ERROR;
        *pos = q + 2;
        return XMLTAG_SKIP;
    }
    int is_close = 0;
    p++; /* past '<' */
    if (p < end && buf[p] == '/') {
        is_close = 1;
        p++;
    }
    int nstart = p;
    while (p < end && buf[p] != '>' && buf[p] != '/' && buf[p] != ' ' && buf[p] != '\t' &&
           buf[p] != '\r' && buf[p] != '\n')
        p++;
    if (p == nstart || p >= end)
        return XMLTAG_ERROR; /* empty or unterminated tag name */
    *name = buf + nstart;
    *name_len = p - nstart;
    /* Skip attributes (if any) up to '>' or the self-close '/'. Values may
     * contain '>' inside quotes, so quoting must be tracked. */
    int selfclose = 0;
    int quote = 0;
    while (p < end) {
        char c = buf[p];
        if (quote) {
            if (c == quote)
                quote = 0;
            p++;
            continue;
        }
        if (c == '"' || c == '\'') {
            quote = c;
            p++;
            continue;
        }
        if (c == '/' && p + 1 < end && buf[p + 1] == '>') {
            selfclose = 1;
            p += 2;
            break;
        }
        if (c == '>') {
            p++;
            break;
        }
        p++;
    }
    if (quote)
        return XMLTAG_ERROR; /* unterminated attribute value */
    if (p > end)
        return XMLTAG_ERROR;
    *pos = p;
    if (is_close)
        return selfclose ? XMLTAG_ERROR : XMLTAG_CLOSE; /* "</a/>" is nonsense */
    return selfclose ? XMLTAG_SELFCLOSE : XMLTAG_OPEN;
}

/* `pos` is positioned right after the '>' of an already-consumed OPEN tag
 * named name[0..name_len). Scans forward, recursively skipping any nested
 * elements (any name), until the MATCHING close tag for `name` is found at
 * this nesting level. On success, fills *close_tag_start with the offset of
 * the '<' that begins that close tag (i.e. the end of this element's
 * content) and returns the offset just past the close tag's '>'. Returns -1
 * on malformed/unterminated/mismatched-nesting input, or if depth exceeds
 * EPP_XML_MAX_DEPTH (fail closed rather than recurse unboundedly). */
static int xml_skip_to_close(const char *buf, int pos, int end, const char *name, int name_len,
                             int depth, int *close_tag_start) {
    if (depth > EPP_XML_MAX_DEPTH)
        return -1;
    for (;;) {
        const char *tn;
        int tnl, tag_start;
        xml_tagkind_t k = xml_next_tag(buf, &pos, end, &tn, &tnl, &tag_start);
        switch (k) {
            case XMLTAG_SKIP:
                continue;
            case XMLTAG_OPEN: {
                int dummy;
                int np = xml_skip_to_close(buf, pos, end, tn, tnl, depth + 1, &dummy);
                if (np < 0)
                    return -1;
                pos = np;
                continue;
            }
            case XMLTAG_SELFCLOSE:
                continue; /* pos already advanced past its '/>' */
            case XMLTAG_CLOSE:
                if (tnl == name_len && memcmp(tn, name, (size_t) name_len) == 0) {
                    *close_tag_start = tag_start;
                    return pos;
                }
                return -1; /* mismatched nesting */
            case XMLTAG_ERROR:
            case XMLTAG_EOF:
            default:
                return -1;
        }
    }
}

/* Find the first direct child element named `tag` (exact byte match,
 * including any namespace prefix, e.g. "domain:name") within [start,end) —
 * "direct child" meaning at nesting depth 0 relative to `start` (a same-
 * named element nested deeper inside a non-matching sibling is correctly
 * skipped over, not matched). On a match, fills *content_start / *content_end
 * (the element's text/child-content byte range — empty, content_start ==
 * content_end, for a self-closing tag) and *next_pos (where a subsequent
 * search for a sibling should resume). Returns 1 on a match, 0 if the range
 * is exhausted with no match (reaching `end`, or the enclosing close tag,
 * counts as "no match" — not an error), -1 on malformed XML. */
static int xml_find_child(const char *buf, int start, int end, const char *tag, int *content_start,
                          int *content_end, int *next_pos) {
    int pos = start;
    int tag_len = (int) strlen(tag);
    for (;;) {
        const char *tn;
        int tnl, tag_start;
        xml_tagkind_t k = xml_next_tag(buf, &pos, end, &tn, &tnl, &tag_start);
        switch (k) {
            case XMLTAG_SKIP:
                continue;
            case XMLTAG_CLOSE:
            case XMLTAG_EOF:
                return 0; /* end of this element's children (or of the buffer) */
            case XMLTAG_SELFCLOSE:
                if (tnl == tag_len && memcmp(tn, tag, (size_t) tag_len) == 0) {
                    *content_start = *content_end = pos; /* empty content */
                    *next_pos = pos;
                    return 1;
                }
                continue;
            case XMLTAG_OPEN: {
                int cstart = pos;
                int close_start;
                int np = xml_skip_to_close(buf, pos, end, tn, tnl, 1, &close_start);
                if (np < 0)
                    return -1;
                if (tnl == tag_len && memcmp(tn, tag, (size_t) tag_len) == 0) {
                    *content_start = cstart;
                    *content_end = close_start;
                    *next_pos = np;
                    return 1;
                }
                pos = np; /* not the one we want — move past it and keep looking */
                continue;
            }
            case XMLTAG_ERROR:
            default:
                return -1;
        }
    }
}

/* To iterate repeated sibling elements (e.g. multiple <domain:name> in a
 * check — task #6), call xml_find_child again with `start` set to the
 * previous match's *next_pos; it already accepts an arbitrary start
 * position, so no separate "find next" entry point is needed. */

/* Decode XML entity references (&lt; &gt; &amp; &apos; &quot; &#NN; &#xNN;)
 * from buf[start,end) into out (NUL-terminated), bounded by outcap. A literal
 * "<![CDATA[...]]>" spanning the whole range is unwrapped verbatim (no entity
 * decoding inside it, per XML's own CDATA semantics). Returns the decoded
 * length, or -1 on overflow or a malformed/unterminated entity — fail
 * closed, never emit a partially-decoded value. */
static int xml_text_decode(const char *buf, int start, int end, char *out, int outcap) {
    if (end - start >= 12 && memcmp(buf + start, "<![CDATA[", 9) == 0 &&
        memcmp(buf + end - 3, "]]>", 3) == 0) {
        int len = (end - 3) - (start + 9);
        if (len < 0 || len >= outcap)
            return -1;
        memcpy(out, buf + start + 9, (size_t) len);
        out[len] = 0;
        return len;
    }
    int o = 0;
    for (int i = start; i < end;) {
        if (buf[i] != '&') {
            if (o >= outcap - 1)
                return -1;
            out[o++] = buf[i++];
            continue;
        }
        int semi = i + 1;
        while (semi < end && buf[semi] != ';' && semi - i < 12)
            semi++;
        if (semi >= end || buf[semi] != ';')
            return -1; /* unterminated / oversized entity reference */
        int elen = semi - i - 1;
        const char *e = buf + i + 1;
        int cp = -1;
        if (elen == 2 && memcmp(e, "lt", 2) == 0)
            cp = '<';
        else if (elen == 2 && memcmp(e, "gt", 2) == 0)
            cp = '>';
        else if (elen == 3 && memcmp(e, "amp", 3) == 0)
            cp = '&';
        else if (elen == 4 && memcmp(e, "apos", 4) == 0)
            cp = '\'';
        else if (elen == 4 && memcmp(e, "quot", 4) == 0)
            cp = '"';
        else if (elen >= 2 && e[0] == '#') {
            char numbuf[16];
            int base = 10, nstart = 1;
            if (elen >= 3 && (e[1] == 'x' || e[1] == 'X')) {
                base = 16;
                nstart = 2;
            }
            int nlen = elen - nstart;
            if (nlen <= 0 || nlen >= (int) sizeof(numbuf))
                return -1;
            memcpy(numbuf, e + nstart, (size_t) nlen);
            numbuf[nlen] = 0;
            char *endp = NULL;
            long v = strtol(numbuf, &endp, base);
            if (!endp || *endp || v <= 0 || v > 0x10FFFF)
                return -1;
            cp = (int) v;
        } else {
            return -1; /* unknown entity — fail closed rather than pass '&' through */
        }
        /* Encode cp as UTF-8 (EPP/XML text is UTF-8; codepoints here are
         * almost always ASCII punctuation, but handle the general case). */
        if (cp < 0x80) {
            if (o >= outcap - 1)
                return -1;
            out[o++] = (char) cp;
        } else if (cp < 0x800) {
            if (o >= outcap - 2)
                return -1;
            out[o++] = (char) (0xC0 | (cp >> 6));
            out[o++] = (char) (0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            if (o >= outcap - 3)
                return -1;
            out[o++] = (char) (0xE0 | (cp >> 12));
            out[o++] = (char) (0x80 | ((cp >> 6) & 0x3F));
            out[o++] = (char) (0x80 | (cp & 0x3F));
        } else {
            if (o >= outcap - 4)
                return -1;
            out[o++] = (char) (0xF0 | (cp >> 18));
            out[o++] = (char) (0x80 | ((cp >> 12) & 0x3F));
            out[o++] = (char) (0x80 | ((cp >> 6) & 0x3F));
            out[o++] = (char) (0x80 | (cp & 0x3F));
        }
        i = semi + 1;
    }
    out[o] = 0;
    return o;
}

/* ── RFC 5730 session shell: greeting, login/logout, command dispatch ────── */
typedef struct {
    char clid[64];
    int logged_in;
} epp_session_t;

static atomic_uint g_svtrid_counter = 0;

static void epp_gen_svtrid(char *out, int outcap) {
    unsigned n = atomic_fetch_add(&g_svtrid_counter, 1u) + 1;
    snprintf(out, (size_t) outcap, "eppd-%ld-%u", (long) getpid(), n);
}

/* RFC 5730 §2.4 greeting — sent unprompted on connect and in reply to a
 * bare <hello>. svcMenu lists the three Phase 1 object namespaces; no
 * svcExtension yet (Phase 3 territory per CLAUDE-eppd.md). */
static int epp_build_greeting(char *out, int outcap) {
    char sv_date[32];
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(sv_date, sizeof(sv_date), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return snprintf(out, (size_t) outcap,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
                    "<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\">"
                    "<greeting>"
                    "<svID>eppd</svID>"
                    "<svDate>%s</svDate>"
                    "<svcMenu>"
                    "<version>1.0</version>"
                    "<lang>en</lang>"
                    "<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>"
                    "<objURI>urn:ietf:params:xml:ns:host-1.0</objURI>"
                    "<objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>"
                    "</svcMenu>"
                    "<dcp>"
                    "<access><all/></access>"
                    "<statement>"
                    "<purpose><admin/><prov/></purpose>"
                    "<recipient><ours/></recipient>"
                    "<retention><stated/></retention>"
                    "</statement>"
                    "</dcp>"
                    "</greeting>"
                    "</epp>",
                    sv_date);
}

/* RFC 5730 §2.6 response envelope. `extra` (may be NULL/empty) is raw XML
 * inserted between </result> and <trID> — where a command's own result data
 * (e.g. <chkData>) goes once task #6 implements it. */
static int epp_build_result(char *out, int outcap, int code, const char *msg, const char *extra,
                            const char *cltrid) {
    char svtrid[64];
    epp_gen_svtrid(svtrid, sizeof(svtrid));
    char cltrid_xml[300] = "";
    if (cltrid && cltrid[0])
        snprintf(cltrid_xml, sizeof(cltrid_xml), "<clTRID>%s</clTRID>", cltrid);
    return snprintf(out, (size_t) outcap,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
                    "<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\">"
                    "<response>"
                    "<result code=\"%d\">"
                    "<msg>%s</msg>"
                    "</result>"
                    "%s"
                    "<trID>%s<svTRID>%s</svTRID></trID>"
                    "</response>"
                    "</epp>",
                    code, msg, extra ? extra : "", cltrid_xml, svtrid);
}

/* RFC 5730 §2.9.1.1 login. Phase 1 credential store: config:eppd_registrar_pw:<clID>
 * in Valkey (plaintext, gated by the same config:* trust boundary as
 * ddns_secret/tsig_secret — only the authenticated control plane can write
 * it). Real registrar provisioning tooling is a follow-up; this is the
 * minimum needed for the session protocol itself. */
static int epp_handle_login(epp_session_t *sess, const char *xml, int len, int cstart, int cend,
                            const char *cltrid, char *resp, int rcap) {
    (void) xml;
    (void) len;
    int idc_s, idc_e, np;
    char clid[64] = "";
    if (xml_find_child(xml, cstart, cend, "clID", &idc_s, &idc_e, &np) != 1 ||
        xml_text_decode(xml, idc_s, idc_e, clid, sizeof(clid)) < 0 || !clid[0])
        return epp_build_result(resp, rcap, 2001, "Command syntax error: missing clID", NULL,
                                cltrid);
    int pwc_s, pwc_e;
    char pw[256] = "";
    if (xml_find_child(xml, cstart, cend, "pw", &pwc_s, &pwc_e, &np) != 1 ||
        xml_text_decode(xml, pwc_s, pwc_e, pw, sizeof(pw)) < 0)
        return epp_build_result(resp, rcap, 2001, "Command syntax error: missing pw", NULL, cltrid);
    char vkey[128], expected[256] = "";
    snprintf(vkey, sizeof(vkey), "config:eppd_registrar_pw:%s", clid);
    if (!vk_get(vkey, expected, sizeof(expected)) || !expected[0] || strcmp(expected, pw) != 0) {
        dns_log(LOG_WARNING, "[eppd] login failed for clID=%s\n", clid);
        return epp_build_result(resp, rcap, 2200, "Authentication error", NULL, cltrid);
    }
    safe_strcpy(sess->clid, clid, sizeof(sess->clid));
    sess->logged_in = 1;
    dns_log(LOG_NOTICE, "[eppd] registrar %s logged in\n", clid);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
}

/* ── epp:* object store (RFC 5731/5732/5733), TLV-encoded per ADR-003 ─────
 * TLV blobs are hex-encoded before storing (same convention as ZONEMD/SVCB
 * elsewhere in this codebase): dns_wire.c's tlv_* codec is binary, but
 * vkc_cmd's argument encoding is strlen()-based text, so a raw blob
 * containing an embedded NUL would silently truncate. */
#define EPP_TAG_ROID 1
#define EPP_TAG_STATUS 2 /* repeated */
#define EPP_TAG_AUTHINFO 3
#define EPP_TAG_CRDATE 4     /* u32 unix time */
#define EPP_TAG_EXDATE 5     /* u32 unix time, domain only */
#define EPP_TAG_REGISTRANT 6 /* domain only */
#define EPP_TAG_NS 7         /* repeated, domain only */
#define EPP_TAG_ADDR_V4 8    /* repeated, host only */
#define EPP_TAG_ADDR_V6 9    /* repeated, host only */
#define EPP_TAG_NAME 10      /* contact only */
#define EPP_TAG_EMAIL 11     /* contact only */
#define EPP_TAG_VOICE 12     /* contact only */

#define EPP_MAX_ARR 16 /* status/ns/addr entries per object — ample for Phase 1 */

static atomic_uint g_roid_counter = 0;

static void epp_gen_roid(char *out, int cap, const char *suffix) {
    unsigned n = atomic_fetch_add(&g_roid_counter, 1u) + 1;
    snprintf(out, (size_t) cap, "%u-%s", n, suffix);
}

static uint32_t tlv_u32_of(const uint8_t *val, uint16_t vlen) {
    if (vlen != 4)
        return 0;
    return ((uint32_t) val[0] << 24) | ((uint32_t) val[1] << 16) | ((uint32_t) val[2] << 8) |
           (uint32_t) val[3];
}

typedef struct {
    char roid[32];
    char status[EPP_MAX_ARR][32];
    int nstatus;
    char authinfo[256];
    uint32_t crdate;
    uint32_t exdate;
    char registrant[64];
    char ns[EPP_MAX_ARR][256];
    int nns;
} epp_domain_t;

typedef struct {
    char roid[32];
    char status[EPP_MAX_ARR][32];
    int nstatus;
    char v4[EPP_MAX_ARR][16];
    int nv4;
    char v6[EPP_MAX_ARR][46];
    int nv6;
    uint32_t crdate;
} epp_host_t;

typedef struct {
    char roid[32];
    char name[128];
    char email[128];
    char voice[32];
    char authinfo[256];
    uint32_t crdate;
} epp_contact_t;

static int epp_domain_encode(const epp_domain_t *d, uint8_t *buf, int cap) {
    int off = tlv_begin(buf, cap, 1);
    if (off < 0)
        return -1;
    off = tlv_put(buf, cap, off, EPP_TAG_ROID, (const uint8_t *) d->roid, (int) strlen(d->roid));
    for (int i = 0; off >= 0 && i < d->nstatus; i++)
        off = tlv_put(buf, cap, off, EPP_TAG_STATUS, (const uint8_t *) d->status[i],
                      (int) strlen(d->status[i]));
    if (off >= 0 && d->authinfo[0])
        off = tlv_put(buf, cap, off, EPP_TAG_AUTHINFO, (const uint8_t *) d->authinfo,
                      (int) strlen(d->authinfo));
    if (off >= 0)
        off = tlv_put_u32(buf, cap, off, EPP_TAG_CRDATE, d->crdate);
    if (off >= 0 && d->exdate)
        off = tlv_put_u32(buf, cap, off, EPP_TAG_EXDATE, d->exdate);
    if (off >= 0 && d->registrant[0])
        off = tlv_put(buf, cap, off, EPP_TAG_REGISTRANT, (const uint8_t *) d->registrant,
                      (int) strlen(d->registrant));
    for (int i = 0; off >= 0 && i < d->nns; i++)
        off =
            tlv_put(buf, cap, off, EPP_TAG_NS, (const uint8_t *) d->ns[i], (int) strlen(d->ns[i]));
    return off;
}

static int epp_domain_decode(const uint8_t *buf, int len, epp_domain_t *d) {
    memset(d, 0, sizeof(*d));
    int off = 1;
    uint8_t tag;
    const uint8_t *val;
    uint16_t vlen;
    int r;
    while ((r = tlv_next(buf, len, &off, &tag, &val, &vlen)) == 1) {
        switch (tag) {
            case EPP_TAG_ROID:
                if (vlen < sizeof(d->roid)) {
                    memcpy(d->roid, val, vlen);
                    d->roid[vlen] = 0;
                }
                break;
            case EPP_TAG_STATUS:
                if (d->nstatus < EPP_MAX_ARR && vlen < sizeof(d->status[0])) {
                    memcpy(d->status[d->nstatus], val, vlen);
                    d->status[d->nstatus][vlen] = 0;
                    d->nstatus++;
                }
                break;
            case EPP_TAG_AUTHINFO:
                if (vlen < sizeof(d->authinfo)) {
                    memcpy(d->authinfo, val, vlen);
                    d->authinfo[vlen] = 0;
                }
                break;
            case EPP_TAG_CRDATE:
                d->crdate = tlv_u32_of(val, vlen);
                break;
            case EPP_TAG_EXDATE:
                d->exdate = tlv_u32_of(val, vlen);
                break;
            case EPP_TAG_REGISTRANT:
                if (vlen < sizeof(d->registrant)) {
                    memcpy(d->registrant, val, vlen);
                    d->registrant[vlen] = 0;
                }
                break;
            case EPP_TAG_NS:
                if (d->nns < EPP_MAX_ARR && vlen < sizeof(d->ns[0])) {
                    memcpy(d->ns[d->nns], val, vlen);
                    d->ns[d->nns][vlen] = 0;
                    d->nns++;
                }
                break;
            default:
                break; /* unknown tag — skip (ADR-003 forward compat) */
        }
    }
    return r < 0 ? -1 : 0;
}

static int epp_host_encode(const epp_host_t *h, uint8_t *buf, int cap) {
    int off = tlv_begin(buf, cap, 1);
    if (off < 0)
        return -1;
    off = tlv_put(buf, cap, off, EPP_TAG_ROID, (const uint8_t *) h->roid, (int) strlen(h->roid));
    for (int i = 0; off >= 0 && i < h->nstatus; i++)
        off = tlv_put(buf, cap, off, EPP_TAG_STATUS, (const uint8_t *) h->status[i],
                      (int) strlen(h->status[i]));
    for (int i = 0; off >= 0 && i < h->nv4; i++)
        off = tlv_put(buf, cap, off, EPP_TAG_ADDR_V4, (const uint8_t *) h->v4[i],
                      (int) strlen(h->v4[i]));
    for (int i = 0; off >= 0 && i < h->nv6; i++)
        off = tlv_put(buf, cap, off, EPP_TAG_ADDR_V6, (const uint8_t *) h->v6[i],
                      (int) strlen(h->v6[i]));
    if (off >= 0)
        off = tlv_put_u32(buf, cap, off, EPP_TAG_CRDATE, h->crdate);
    return off;
}

static int epp_host_decode(const uint8_t *buf, int len, epp_host_t *h) {
    memset(h, 0, sizeof(*h));
    int off = 1;
    uint8_t tag;
    const uint8_t *val;
    uint16_t vlen;
    int r;
    while ((r = tlv_next(buf, len, &off, &tag, &val, &vlen)) == 1) {
        switch (tag) {
            case EPP_TAG_ROID:
                if (vlen < sizeof(h->roid)) {
                    memcpy(h->roid, val, vlen);
                    h->roid[vlen] = 0;
                }
                break;
            case EPP_TAG_STATUS:
                if (h->nstatus < EPP_MAX_ARR && vlen < sizeof(h->status[0])) {
                    memcpy(h->status[h->nstatus], val, vlen);
                    h->status[h->nstatus][vlen] = 0;
                    h->nstatus++;
                }
                break;
            case EPP_TAG_ADDR_V4:
                if (h->nv4 < EPP_MAX_ARR && vlen < sizeof(h->v4[0])) {
                    memcpy(h->v4[h->nv4], val, vlen);
                    h->v4[h->nv4][vlen] = 0;
                    h->nv4++;
                }
                break;
            case EPP_TAG_ADDR_V6:
                if (h->nv6 < EPP_MAX_ARR && vlen < sizeof(h->v6[0])) {
                    memcpy(h->v6[h->nv6], val, vlen);
                    h->v6[h->nv6][vlen] = 0;
                    h->nv6++;
                }
                break;
            case EPP_TAG_CRDATE:
                h->crdate = tlv_u32_of(val, vlen);
                break;
            default:
                break;
        }
    }
    return r < 0 ? -1 : 0;
}

static int epp_contact_encode(const epp_contact_t *c, uint8_t *buf, int cap) {
    int off = tlv_begin(buf, cap, 1);
    if (off < 0)
        return -1;
    off = tlv_put(buf, cap, off, EPP_TAG_ROID, (const uint8_t *) c->roid, (int) strlen(c->roid));
    if (off >= 0 && c->name[0])
        off =
            tlv_put(buf, cap, off, EPP_TAG_NAME, (const uint8_t *) c->name, (int) strlen(c->name));
    if (off >= 0 && c->email[0])
        off = tlv_put(buf, cap, off, EPP_TAG_EMAIL, (const uint8_t *) c->email,
                      (int) strlen(c->email));
    if (off >= 0 && c->voice[0])
        off = tlv_put(buf, cap, off, EPP_TAG_VOICE, (const uint8_t *) c->voice,
                      (int) strlen(c->voice));
    if (off >= 0 && c->authinfo[0])
        off = tlv_put(buf, cap, off, EPP_TAG_AUTHINFO, (const uint8_t *) c->authinfo,
                      (int) strlen(c->authinfo));
    if (off >= 0)
        off = tlv_put_u32(buf, cap, off, EPP_TAG_CRDATE, c->crdate);
    return off;
}

static int epp_contact_decode(const uint8_t *buf, int len, epp_contact_t *c) {
    memset(c, 0, sizeof(*c));
    int off = 1;
    uint8_t tag;
    const uint8_t *val;
    uint16_t vlen;
    int r;
    while ((r = tlv_next(buf, len, &off, &tag, &val, &vlen)) == 1) {
        switch (tag) {
            case EPP_TAG_ROID:
                if (vlen < sizeof(c->roid)) {
                    memcpy(c->roid, val, vlen);
                    c->roid[vlen] = 0;
                }
                break;
            case EPP_TAG_NAME:
                if (vlen < sizeof(c->name)) {
                    memcpy(c->name, val, vlen);
                    c->name[vlen] = 0;
                }
                break;
            case EPP_TAG_EMAIL:
                if (vlen < sizeof(c->email)) {
                    memcpy(c->email, val, vlen);
                    c->email[vlen] = 0;
                }
                break;
            case EPP_TAG_VOICE:
                if (vlen < sizeof(c->voice)) {
                    memcpy(c->voice, val, vlen);
                    c->voice[vlen] = 0;
                }
                break;
            case EPP_TAG_AUTHINFO:
                if (vlen < sizeof(c->authinfo)) {
                    memcpy(c->authinfo, val, vlen);
                    c->authinfo[vlen] = 0;
                }
                break;
            case EPP_TAG_CRDATE:
                c->crdate = tlv_u32_of(val, vlen);
                break;
            default:
                break;
        }
    }
    return r < 0 ? -1 : 0;
}

static void epp_iso_date(uint32_t unixtime, char *out, int cap) {
    time_t t = (time_t) unixtime;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, (size_t) cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* Is `name` equal to, or a subdomain of, `zone`? Same shape as dnsd's own
 * name_in_zone (dns_server.c) — a separate small copy here, not shared,
 * since eppd and dnsd are different binaries with no common caller of this
 * one five-line check. */
static int name_in_zone(const char *name, const char *zone) {
    size_t nl = strlen(name), zl = strlen(zone);
    if (zl == 0 || zl > nl)
        return 0;
    if (zl == nl)
        return strcasecmp(name, zone) == 0;
    return nl > zl + 1 && name[nl - zl - 1] == '.' && strcasecmp(name + nl - zl, zone) == 0;
}

/* Longest-suffix match against configured zone_table:<zone> entries —
 * mirrors dnsd's zone_for_qname exactly, implemented from eppd's side
 * purely via Valkey reads since eppd keeps no in-memory zone table. */
static int find_parent_zone(const char *name, char *zone_out, int cap) {
    char keys[64][256];
    int n = vk_list_keys("zone_table:*", keys, 64);
    size_t best = 0;
    zone_out[0] = 0;
    for (int i = 0; i < n; i++) {
        const char *zn = keys[i] + strlen("zone_table:");
        if (name_in_zone(name, zn)) {
            size_t zl = strlen(zn);
            if (zl > best) {
                best = zl;
                safe_strcpy(zone_out, zn, cap);
            }
        }
    }
    /* The PRIMARY zone has no zone_table:<name> key at all (it's seeded
     * purely from config:zone_name/config:soa_* at boot, never persisted as
     * a zone_table: entry) — apid's own resolve_zone falls back to
     * config:zone_name unconditionally when no multi-zone match is found,
     * so a single-zone deployment (no zone_table:* keys) still resolves.
     * Mirrored here rather than inventing a stricter, differently-behaved
     * check. */
    if (!zone_out[0])
        vk_get("config:zone_name", zone_out, cap);
    return zone_out[0] ? 0 : -1;
}

/* SOA serial bump for the parent zone — mirrors apid.c's serial_bump_zone
 * exactly (the primary zone keeps the legacy config:zone_serial counter;
 * other zones use config:zone:<z>:serial). dnsd picks up the new serial
 * live via keyspace notifications (migration Step 6); no IXFR-journal entry
 * or NOTIFY is written here, matching the existing, already-accepted
 * precedent for apid's own zone-record REST writes — secondaries converge
 * via the normal periodic-refresh -> IXFR-gap -> AXFR-fallback path rather
 * than an immediate push. */
static void epp_serial_bump_zone(const char *zn) {
    char primary[256] = "";
    vk_get("config:zone_name", primary, sizeof(primary));
    char ikey[320];
    if (!zn[0] || strcasecmp(zn, primary) == 0)
        safe_strcpy(ikey, "config:zone_serial", sizeof(ikey));
    else
        snprintf(ikey, sizeof(ikey), "config:zone:%s:serial", zn);
    if (vk_incr(ikey) < 0)
        dns_log(LOG_WARNING, "[eppd] serial bump failed (Valkey down?)\n");
}

/* Publish a domain's delegation into the parent zone dnsd already serves:
 * writes zone:<parent>:NS:<name> (multi-value, P0b) and, for each
 * in-bailiwick NS target, zone:<parent>:A/AAAA:<ns> glue looked up from
 * that host's own epp:host:* record, then bumps the parent's serial. */
static void epp_publish_domain(const char *name, const char ns[][256], int nns) {
    char zone[256];
    if (find_parent_zone(name, zone, sizeof(zone)) < 0) {
        dns_log(LOG_WARNING, "[eppd] no configured parent zone for %s — not publishing\n", name);
        return;
    }
    char nsval[4096];
    int off = snprintf(nsval, sizeof(nsval), "%d", 3600);
    for (int i = 0; i < nns && off < (int) sizeof(nsval) - 1; i++)
        off += snprintf(nsval + off, sizeof(nsval) - off, "|%s", ns[i]);
    char key[900];
    snprintf(key, sizeof(key), "zone:%s:NS:%s", zone, name);
    vk_set(key, nsval);

    for (int i = 0; i < nns; i++) {
        if (!name_in_zone(ns[i], zone))
            continue; /* out of bailiwick — not ours to glue */
        char hkey[300];
        snprintf(hkey, sizeof(hkey), "epp:host:%s", ns[i]);
        char blob[VKC_BUF];
        if (!vk_get(hkey, blob, sizeof(blob)))
            continue;
        uint8_t tlv[4096];
        int tlen = hex_dec(blob, tlv, sizeof(tlv));
        epp_host_t h;
        if (tlen < 0 || epp_host_decode(tlv, tlen, &h) < 0)
            continue;
        if (h.nv4 > 0) {
            char aval[600];
            int aoff = snprintf(aval, sizeof(aval), "3600");
            for (int j = 0; j < h.nv4 && aoff < (int) sizeof(aval) - 1; j++)
                aoff += snprintf(aval + aoff, sizeof(aval) - aoff, "|%s", h.v4[j]);
            char gk[900];
            snprintf(gk, sizeof(gk), "zone:%s:A:%s", zone, ns[i]);
            vk_set(gk, aval);
        }
        if (h.nv6 > 0) {
            char aval[900];
            int aoff = snprintf(aval, sizeof(aval), "3600");
            for (int j = 0; j < h.nv6 && aoff < (int) sizeof(aval) - 1; j++)
                aoff += snprintf(aval + aoff, sizeof(aval) - aoff, "|%s", h.v6[j]);
            char gk[900];
            snprintf(gk, sizeof(gk), "zone:%s:AAAA:%s", zone, ns[i]);
            vk_set(gk, aval);
        }
    }
    epp_serial_bump_zone(zone);
    dns_log(LOG_NOTICE, "[eppd] published %s NS delegation into zone %s (%d ns)\n", name, zone,
            nns);
}

/* ── host:* command handlers (RFC 5732) ───────────────────────────────── */
static int epp_host_check(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                          int rcap) {
    char name[256] = "";
    int ns, ne, np;
    if (xml_find_child(xml, qs, qe, "host:name", &ns, &ne, &np) != 1 ||
        xml_text_decode(xml, ns, ne, name, sizeof(name)) < 0 || !name[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: host:name", NULL,
                                cltrid);
    strlower(name);
    char key[300], blob[16];
    snprintf(key, sizeof(key), "epp:host:%s", name);
    int exists = vk_get(key, blob, sizeof(blob));
    char extra[600];
    snprintf(extra, sizeof(extra),
             "<chkData xmlns=\"urn:ietf:params:xml:ns:host-1.0\">"
             "<cd><name avail=\"%d\">%s</name></cd></chkData>",
             exists ? 0 : 1, name);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

static int epp_host_create(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                           int rcap) {
    char name[256] = "";
    int ns, ne, np;
    if (xml_find_child(xml, qs, qe, "host:name", &ns, &ne, &np) != 1 ||
        xml_text_decode(xml, ns, ne, name, sizeof(name)) < 0 || !name[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: host:name", NULL,
                                cltrid);
    strlower(name);
    char key[300], existing[16];
    snprintf(key, sizeof(key), "epp:host:%s", name);
    if (vk_get(key, existing, sizeof(existing)))
        return epp_build_result(resp, rcap, 2302, "Object exists", NULL, cltrid);

    epp_host_t h;
    memset(&h, 0, sizeof(h));
    int pos = qs, as, ae, anp;
    while (h.nv4 + h.nv6 < EPP_MAX_ARR &&
           xml_find_child(xml, pos, qe, "host:addr", &as, &ae, &anp) == 1) {
        char addr[64] = "";
        xml_text_decode(xml, as, ae, addr, sizeof(addr));
        if (strchr(addr, ':')) {
            if (h.nv6 < EPP_MAX_ARR)
                safe_strcpy(h.v6[h.nv6++], addr, sizeof(h.v6[0]));
        } else if (addr[0] && h.nv4 < EPP_MAX_ARR)
            safe_strcpy(h.v4[h.nv4++], addr, sizeof(h.v4[0]));
        pos = anp;
    }
    epp_gen_roid(h.roid, sizeof(h.roid), "EPPD-H");
    h.crdate = (uint32_t) time(NULL);

    uint8_t tlv[4096];
    int tlen = epp_host_encode(&h, tlv, sizeof(tlv));
    if (tlen < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[8192];
    hex_enc(tlv, tlen, hexbuf);
    vk_set(key, hexbuf);

    char crdatestr[32];
    epp_iso_date(h.crdate, crdatestr, sizeof(crdatestr));
    char extra[512];
    snprintf(extra, sizeof(extra),
             "<creData xmlns=\"urn:ietf:params:xml:ns:host-1.0\">"
             "<name>%s</name><crDate>%s</crDate></creData>",
             name, crdatestr);
    dns_log(LOG_NOTICE, "[eppd] host created: %s (%d v4, %d v6)\n", name, h.nv4, h.nv6);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

static int epp_host_info(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                         int rcap) {
    char name[256] = "";
    int ns, ne, np;
    if (xml_find_child(xml, qs, qe, "host:name", &ns, &ne, &np) != 1 ||
        xml_text_decode(xml, ns, ne, name, sizeof(name)) < 0 || !name[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: host:name", NULL,
                                cltrid);
    strlower(name);
    char key[300], blob[VKC_BUF];
    snprintf(key, sizeof(key), "epp:host:%s", name);
    if (!vk_get(key, blob, sizeof(blob)))
        return epp_build_result(resp, rcap, 2303, "Object does not exist", NULL, cltrid);
    uint8_t tlv[4096];
    int tlen = hex_dec(blob, tlv, sizeof(tlv));
    epp_host_t h;
    if (tlen < 0 || epp_host_decode(tlv, tlen, &h) < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: corrupt object", NULL, cltrid);
    char addrs[2048] = "";
    int aoff = 0;
    for (int i = 0; i < h.nv4 && aoff < (int) sizeof(addrs) - 1; i++)
        aoff += snprintf(addrs + aoff, sizeof(addrs) - aoff, "<addr ip=\"v4\">%s</addr>", h.v4[i]);
    for (int i = 0; i < h.nv6 && aoff < (int) sizeof(addrs) - 1; i++)
        aoff += snprintf(addrs + aoff, sizeof(addrs) - aoff, "<addr ip=\"v6\">%s</addr>", h.v6[i]);
    char crdatestr[32];
    epp_iso_date(h.crdate, crdatestr, sizeof(crdatestr));
    char extra[3000];
    snprintf(extra, sizeof(extra),
             "<infData xmlns=\"urn:ietf:params:xml:ns:host-1.0\">"
             "<name>%s</name><roid>%s</roid><status s=\"ok\"/>%s"
             "<crDate>%s</crDate></infData>",
             name, h.roid, addrs, crdatestr);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* ── contact:* command handlers (RFC 5733, simplified for a private/
 * internal registry: name/email/voice only, no postalInfo address block) ── */
static int epp_contact_check(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                             int rcap) {
    char id[64] = "";
    int is, ie, inp;
    if (xml_find_child(xml, qs, qe, "contact:id", &is, &ie, &inp) != 1 ||
        xml_text_decode(xml, is, ie, id, sizeof(id)) < 0 || !id[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: contact:id", NULL,
                                cltrid);
    char key[300], blob[16];
    snprintf(key, sizeof(key), "epp:contact:%s", id);
    int exists = vk_get(key, blob, sizeof(blob));
    char extra[400];
    snprintf(extra, sizeof(extra),
             "<chkData xmlns=\"urn:ietf:params:xml:ns:contact-1.0\">"
             "<cd><id avail=\"%d\">%s</id></cd></chkData>",
             exists ? 0 : 1, id);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

static int epp_contact_create(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                              int rcap) {
    char id[64] = "";
    int is, ie, inp;
    if (xml_find_child(xml, qs, qe, "contact:id", &is, &ie, &inp) != 1 ||
        xml_text_decode(xml, is, ie, id, sizeof(id)) < 0 || !id[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: contact:id", NULL,
                                cltrid);
    char key[300], existing[16];
    snprintf(key, sizeof(key), "epp:contact:%s", id);
    if (vk_get(key, existing, sizeof(existing)))
        return epp_build_result(resp, rcap, 2302, "Object exists", NULL, cltrid);

    epp_contact_t c;
    memset(&c, 0, sizeof(c));
    int ns, ne, nnp;
    if (xml_find_child(xml, qs, qe, "contact:name", &ns, &ne, &nnp) == 1)
        xml_text_decode(xml, ns, ne, c.name, sizeof(c.name));
    int es, ee, enp;
    if (xml_find_child(xml, qs, qe, "contact:email", &es, &ee, &enp) == 1)
        xml_text_decode(xml, es, ee, c.email, sizeof(c.email));
    int vs, ve, vnp;
    if (xml_find_child(xml, qs, qe, "contact:voice", &vs, &ve, &vnp) == 1)
        xml_text_decode(xml, vs, ve, c.voice, sizeof(c.voice));
    epp_gen_roid(c.roid, sizeof(c.roid), "EPPD-C");
    c.crdate = (uint32_t) time(NULL);

    uint8_t tlv[2048];
    int tlen = epp_contact_encode(&c, tlv, sizeof(tlv));
    if (tlen < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[4096];
    hex_enc(tlv, tlen, hexbuf);
    vk_set(key, hexbuf);

    char crdatestr[32];
    epp_iso_date(c.crdate, crdatestr, sizeof(crdatestr));
    char extra[400];
    snprintf(extra, sizeof(extra),
             "<creData xmlns=\"urn:ietf:params:xml:ns:contact-1.0\">"
             "<id>%s</id><crDate>%s</crDate></creData>",
             id, crdatestr);
    dns_log(LOG_NOTICE, "[eppd] contact created: %s\n", id);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

static int epp_contact_info(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                            int rcap) {
    char id[64] = "";
    int is, ie, inp;
    if (xml_find_child(xml, qs, qe, "contact:id", &is, &ie, &inp) != 1 ||
        xml_text_decode(xml, is, ie, id, sizeof(id)) < 0 || !id[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: contact:id", NULL,
                                cltrid);
    char key[300], blob[VKC_BUF];
    snprintf(key, sizeof(key), "epp:contact:%s", id);
    if (!vk_get(key, blob, sizeof(blob)))
        return epp_build_result(resp, rcap, 2303, "Object does not exist", NULL, cltrid);
    uint8_t tlv[2048];
    int tlen = hex_dec(blob, tlv, sizeof(tlv));
    epp_contact_t c;
    if (tlen < 0 || epp_contact_decode(tlv, tlen, &c) < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: corrupt object", NULL, cltrid);
    char crdatestr[32];
    epp_iso_date(c.crdate, crdatestr, sizeof(crdatestr));
    char extra[900];
    snprintf(extra, sizeof(extra),
             "<infData xmlns=\"urn:ietf:params:xml:ns:contact-1.0\">"
             "<id>%s</id><roid>%s</roid><status s=\"ok\"/>%s%s%s"
             "<crDate>%s</crDate></infData>",
             id, c.roid, c.name[0] ? "<name>" : "", c.name[0] ? c.name : "",
             c.name[0] ? "</name>" : "", crdatestr);
    (void) c.email;
    (void) c.voice; /* Phase 1: not echoed in infData yet, stored for later use */
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* ── domain:* command handlers (RFC 5731) ─────────────────────────────── */
static int epp_domain_check(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                            int rcap) {
    char name[256] = "";
    int ns, ne, np;
    if (xml_find_child(xml, qs, qe, "domain:name", &ns, &ne, &np) != 1 ||
        xml_text_decode(xml, ns, ne, name, sizeof(name)) < 0 || !name[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: domain:name", NULL,
                                cltrid);
    strlower(name);
    char key[300], blob[16];
    snprintf(key, sizeof(key), "epp:domain:%s", name);
    int exists = vk_get(key, blob, sizeof(blob));
    char extra[600];
    snprintf(extra, sizeof(extra),
             "<chkData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\">"
             "<cd><name avail=\"%d\">%s</name></cd></chkData>",
             exists ? 0 : 1, name);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* Parses <domain:ns> (hostObj referencing a pre-existing host, or hostAttr
 * with inline name+addr that implicitly creates/updates that host object so
 * the publish pipeline's per-NS glue lookup works uniformly regardless of
 * which style the client used). Returns the number of NS names collected
 * (0 if there was no <domain:ns> at all — a domain with no delegation is
 * valid EPP, just not yet resolvable), or -1 on a hostObj referencing a
 * host that does not exist. */
static int epp_domain_parse_ns(const char *xml, int qs, int qe, char ns_out[][256]) {
    int nssec_s, nssec_e, nssecnp;
    if (xml_find_child(xml, qs, qe, "domain:ns", &nssec_s, &nssec_e, &nssecnp) != 1)
        return 0;
    int nns = 0;
    int pos = nssec_s;
    while (nns < EPP_MAX_ARR) {
        int hos, hoe, honp;
        if (xml_find_child(xml, pos, nssec_e, "domain:hostObj", &hos, &hoe, &honp) == 1) {
            char hn[256] = "";
            xml_text_decode(xml, hos, hoe, hn, sizeof(hn));
            strlower(hn);
            char hkey[300], hblob[16];
            snprintf(hkey, sizeof(hkey), "epp:host:%s", hn);
            if (!vk_get(hkey, hblob, sizeof(hblob)))
                return -1; /* hostObj must already exist (RFC 5731 §3.2.1) */
            safe_strcpy(ns_out[nns++], hn, 256);
            pos = honp;
            continue;
        }
        int has, hae, hanp;
        if (xml_find_child(xml, pos, nssec_e, "domain:hostAttr", &has, &hae, &hanp) == 1) {
            char hn[256] = "";
            int hns, hne, hnnp;
            if (xml_find_child(xml, has, hae, "domain:hostName", &hns, &hne, &hnnp) == 1)
                xml_text_decode(xml, hns, hne, hn, sizeof(hn));
            strlower(hn);
            if (hn[0]) {
                epp_host_t h;
                memset(&h, 0, sizeof(h));
                char hkey[300], existingblob[VKC_BUF];
                snprintf(hkey, sizeof(hkey), "epp:host:%s", hn);
                int had_existing = vk_get(hkey, existingblob, sizeof(existingblob));
                if (had_existing) {
                    uint8_t etlv[4096];
                    int elen = hex_dec(existingblob, etlv, sizeof(etlv));
                    if (elen >= 0)
                        epp_host_decode(etlv, elen, &h);
                }
                int apos = has, aas, aae, aanp;
                while (h.nv4 + h.nv6 < EPP_MAX_ARR &&
                       xml_find_child(xml, apos, hae, "domain:hostAddr", &aas, &aae, &aanp) == 1) {
                    char addr[64] = "";
                    xml_text_decode(xml, aas, aae, addr, sizeof(addr));
                    if (strchr(addr, ':')) {
                        if (h.nv6 < EPP_MAX_ARR)
                            safe_strcpy(h.v6[h.nv6++], addr, sizeof(h.v6[0]));
                    } else if (addr[0] && h.nv4 < EPP_MAX_ARR)
                        safe_strcpy(h.v4[h.nv4++], addr, sizeof(h.v4[0]));
                    apos = aanp;
                }
                if (!had_existing) {
                    epp_gen_roid(h.roid, sizeof(h.roid), "EPPD-H");
                    h.crdate = (uint32_t) time(NULL);
                }
                uint8_t tlv[4096];
                int tlen = epp_host_encode(&h, tlv, sizeof(tlv));
                if (tlen >= 0) {
                    char hexbuf[8192];
                    hex_enc(tlv, tlen, hexbuf);
                    vk_set(hkey, hexbuf);
                }
                safe_strcpy(ns_out[nns++], hn, 256);
            }
            pos = hanp;
            continue;
        }
        break;
    }
    return nns;
}

static int epp_domain_create(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                             int rcap) {
    char name[256] = "";
    int ns, ne, np;
    if (xml_find_child(xml, qs, qe, "domain:name", &ns, &ne, &np) != 1 ||
        xml_text_decode(xml, ns, ne, name, sizeof(name)) < 0 || !name[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: domain:name", NULL,
                                cltrid);
    strlower(name);
    char key[300], existing[16];
    snprintf(key, sizeof(key), "epp:domain:%s", name);
    if (vk_get(key, existing, sizeof(existing)))
        return epp_build_result(resp, rcap, 2302, "Object exists", NULL, cltrid);

    char nslist[EPP_MAX_ARR][256];
    int nns = epp_domain_parse_ns(xml, qs, qe, nslist);
    if (nns < 0)
        return epp_build_result(resp, rcap, 2303, "Object does not exist: hostObj", NULL, cltrid);

    char registrant[64] = "";
    int rs, re, rnp;
    if (xml_find_child(xml, qs, qe, "domain:registrant", &rs, &re, &rnp) == 1)
        xml_text_decode(xml, rs, re, registrant, sizeof(registrant));

    epp_domain_t d;
    memset(&d, 0, sizeof(d));
    epp_gen_roid(d.roid, sizeof(d.roid), "EPPD-D");
    d.crdate = (uint32_t) time(NULL);
    d.exdate = d.crdate + 365u * 24u * 3600u; /* Phase 1: fixed 1y; <domain:period> parsing TODO */
    safe_strcpy(d.registrant, registrant, sizeof(d.registrant));
    d.nns = nns;
    for (int i = 0; i < nns; i++)
        safe_strcpy(d.ns[i], nslist[i], sizeof(d.ns[0]));
    safe_strcpy(d.status[0], "ok", sizeof(d.status[0]));
    d.nstatus = 1;

    uint8_t tlv[4096];
    int tlen = epp_domain_encode(&d, tlv, sizeof(tlv));
    if (tlen < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[8192];
    hex_enc(tlv, tlen, hexbuf);
    vk_set(key, hexbuf);

    if (nns > 0)
        epp_publish_domain(name, nslist, nns);

    char crdatestr[32], exdatestr[32];
    epp_iso_date(d.crdate, crdatestr, sizeof(crdatestr));
    epp_iso_date(d.exdate, exdatestr, sizeof(exdatestr));
    char extra[512];
    snprintf(extra, sizeof(extra),
             "<creData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\">"
             "<name>%s</name><crDate>%s</crDate><exDate>%s</exDate></creData>",
             name, crdatestr, exdatestr);
    dns_log(LOG_NOTICE, "[eppd] domain created: %s (%d ns)\n", name, nns);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

static int epp_domain_info(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                           int rcap) {
    char name[256] = "";
    int ns, ne, np;
    if (xml_find_child(xml, qs, qe, "domain:name", &ns, &ne, &np) != 1 ||
        xml_text_decode(xml, ns, ne, name, sizeof(name)) < 0 || !name[0])
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: domain:name", NULL,
                                cltrid);
    strlower(name);
    char key[300], blob[VKC_BUF];
    snprintf(key, sizeof(key), "epp:domain:%s", name);
    if (!vk_get(key, blob, sizeof(blob)))
        return epp_build_result(resp, rcap, 2303, "Object does not exist", NULL, cltrid);
    uint8_t tlv[4096];
    int tlen = hex_dec(blob, tlv, sizeof(tlv));
    epp_domain_t d;
    if (tlen < 0 || epp_domain_decode(tlv, tlen, &d) < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: corrupt object", NULL, cltrid);
    char nsxml[3000] = "";
    int noff = 0;
    for (int i = 0; i < d.nns && noff < (int) sizeof(nsxml) - 1; i++)
        noff += snprintf(nsxml + noff, sizeof(nsxml) - noff, "<hostObj>%s</hostObj>", d.ns[i]);
    char crdatestr[32], exdatestr[32];
    epp_iso_date(d.crdate, crdatestr, sizeof(crdatestr));
    epp_iso_date(d.exdate, exdatestr, sizeof(exdatestr));
    char extra[4000];
    snprintf(extra, sizeof(extra),
             "<infData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\">"
             "<name>%s</name><roid>%s</roid><status s=\"ok\"/>"
             "%s%s%s"
             "<ns>%s</ns>"
             "<crDate>%s</crDate><exDate>%s</exDate></infData>",
             name, d.roid, d.registrant[0] ? "<registrant>" : "",
             d.registrant[0] ? d.registrant : "", d.registrant[0] ? "</registrant>" : "", nsxml,
             crdatestr, exdatestr);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* Recognized-but-not-yet-implemented (domain/host/contact update/delete —
 * RFC 3915 grace periods are explicitly Phase 2) gets 2400 (command
 * failed), distinct from 2101 (unimplemented option) or 2000 (unknown
 * command) so a real registrar client's logs distinguish "eppd doesn't have
 * this yet" from "eppd doesn't understand what you sent". */
static int epp_handle_object_command_stub(const char *op, const char *obj, const char *cltrid,
                                          char *resp, int rcap) {
    char msg[128];
    snprintf(msg, sizeof(msg), "Command failed: %s %s not yet implemented (Phase 2)", op, obj);
    return epp_build_result(resp, rcap, 2400, msg, NULL, cltrid);
}

typedef int (*epp_obj_handler_fn)(const char *xml, int qs, int qe, const char *cltrid, char *resp,
                                  int rcap);

/* Parse <command> and dispatch. Returns the response XML length, or -1 if
 * the input was too malformed to even build an error response for (the
 * caller must close the connection in that case — there is nothing safe
 * left to say). */
static int epp_handle_command(epp_session_t *sess, const char *xml, int len, int cmd_s, int cmd_e,
                              char *resp, int rcap) {
    (void) len;
    char cltrid[300] = "";
    int cs, ce, np;
    if (xml_find_child(xml, cmd_s, cmd_e, "clTRID", &cs, &ce, &np) == 1)
        xml_text_decode(xml, cs, ce, cltrid, sizeof(cltrid));

    static const struct {
        const char *tag;
        const char *op;
    } objcmds[] = {
        {"check", "check"},   {"info", "info"},     {"create", "create"},
        {"update", "update"}, {"delete", "delete"},
    };
    /* Implemented (op, obj) combinations — everything else recognized-but-
     * not-yet-implemented (update/delete for all three objects; RFC 3915
     * grace periods are explicitly Phase 2) falls through to the stub. */
    static const struct {
        const char *op;
        const char *obj;
        epp_obj_handler_fn fn;
    } handlers[] = {
        {"check", "domain", epp_domain_check},   {"create", "domain", epp_domain_create},
        {"info", "domain", epp_domain_info},     {"check", "host", epp_host_check},
        {"create", "host", epp_host_create},     {"info", "host", epp_host_info},
        {"check", "contact", epp_contact_check}, {"create", "contact", epp_contact_create},
        {"info", "contact", epp_contact_info},
    };
    for (size_t i = 0; i < sizeof(objcmds) / sizeof(objcmds[0]); i++) {
        int os, oe, onp;
        if (xml_find_child(xml, cmd_s, cmd_e, objcmds[i].tag, &os, &oe, &onp) != 1)
            continue;
        if (!sess->logged_in)
            return epp_build_result(resp, rcap, 2201, "Authorization error: not logged in", NULL,
                                    cltrid);
        static const char *objs[] = {"domain", "host", "contact"};
        for (size_t j = 0; j < 3; j++) {
            char qname[32];
            snprintf(qname, sizeof(qname), "%s:%s", objs[j], objcmds[i].tag);
            int qs, qe, qnp;
            if (xml_find_child(xml, os, oe, qname, &qs, &qe, &qnp) != 1)
                continue;
            for (size_t k = 0; k < sizeof(handlers) / sizeof(handlers[0]); k++)
                if (strcmp(handlers[k].op, objcmds[i].op) == 0 &&
                    strcmp(handlers[k].obj, objs[j]) == 0)
                    return handlers[k].fn(xml, qs, qe, cltrid, resp, rcap);
            return epp_handle_object_command_stub(objcmds[i].op, objs[j], cltrid, resp, rcap);
        }
        return epp_build_result(resp, rcap, 2000, "Unknown object type", NULL, cltrid);
    }
    return epp_build_result(resp, rcap, 2000, "Unknown or unsupported command", NULL, cltrid);
}

/* Top-level <epp> dispatch for one frame's worth of XML: <hello> (send
 * another greeting), <command><login>, <command><logout>, or any other
 * <command> (routed through epp_handle_command). Returns the response
 * length (0 for a bare <hello>'s... no — hello DOES get a greeting reply),
 * or -1 if the frame was too malformed to safely respond to at all. */
static int epp_dispatch(epp_session_t *sess, char *xml, int xlen, char *resp, int rcap,
                        int *should_close) {
    *should_close = 0;
    int es, ee, enp;
    if (xml_find_child(xml, 0, xlen, "epp", &es, &ee, &enp) != 1)
        return -1;
    int hs, he, hnp;
    if (xml_find_child(xml, es, ee, "hello", &hs, &he, &hnp) == 1)
        return epp_build_greeting(resp, rcap);
    int cs, ce, cnp;
    if (xml_find_child(xml, es, ee, "command", &cs, &ce, &cnp) == 1) {
        int ls, le, lnp;
        if (xml_find_child(xml, cs, ce, "logout", &ls, &le, &lnp) == 1) {
            char cltrid[300] = "";
            int clts, clte, clnp;
            if (xml_find_child(xml, cs, ce, "clTRID", &clts, &clte, &clnp) == 1)
                xml_text_decode(xml, clts, clte, cltrid, sizeof(cltrid));
            *should_close = 1;
            dns_log(LOG_NOTICE, "[eppd] registrar %s logged out\n",
                    sess->clid[0] ? sess->clid : "(none)");
            return epp_build_result(resp, rcap, 1500,
                                    "Command completed successfully; ending "
                                    "session",
                                    NULL, cltrid);
        }
        if (xml_find_child(xml, cs, ce, "login", &ls, &le, &lnp) == 1) {
            char cltrid[300] = "";
            int clts, clte, clnp;
            if (xml_find_child(xml, cs, ce, "clTRID", &clts, &clte, &clnp) == 1)
                xml_text_decode(xml, clts, clte, cltrid, sizeof(cltrid));
            return epp_handle_login(sess, xml, xlen, ls, le, cltrid, resp, rcap);
        }
        return epp_handle_command(sess, xml, xlen, cs, ce, resp, rcap);
    }
    return -1; /* neither <hello> nor <command> under <epp> — nothing safe to say */
}

/* ── Listener ────────────────────────────────────────────────────────────── */
static int listen_on(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons((uint16_t) port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        dns_log(LOG_ERR, "[eppd] bind :%d failed: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* One accepted, TLS-established, mTLS-verified registrar connection: send
 * the unprompted greeting (RFC 5730 §2.4), then loop reading/dispatching/
 * responding to frames until logout, an I/O error, or a frame too malformed
 * to safely answer (fail closed — close rather than guess). Each connection
 * gets its own accumulation buffer (EPP_MAX_FRAME-sized) on this thread's
 * stack; see accept_loop for why this runs one-thread-per-connection rather
 * than apid's serial accept-loop shape (EPP sessions are long-lived: a
 * registrar logs in once and issues many commands before logout, unlike
 * DoH/mgmt's one-shot request/response). */
static void handle_session(SSL *ssl) {
    X509 *peer = SSL_get_peer_certificate(ssl);
    char subject[256] = "(no client certificate)";
    if (peer) {
        X509_NAME_oneline(X509_get_subject_name(peer), subject, sizeof(subject));
        X509_free(peer);
    }
    dns_log(LOG_INFO, "[eppd] session from registrar cert: %s\n", subject);

    epp_session_t sess;
    memset(&sess, 0, sizeof(sess));

    static __thread uint8_t acc[4 + EPP_MAX_FRAME];
    int acclen = 0;
    static __thread char xmlbuf[EPP_MAX_FRAME + 1];
    static __thread char resp[8192];

    int greet_len = epp_build_greeting(resp, sizeof(resp));
    if (greet_len < 0 || greet_len >= (int) sizeof(resp) ||
        epp_write_frame(ssl, resp, greet_len) < 0) {
        dns_log(LOG_WARNING, "[eppd] failed to send greeting\n");
        return;
    }

    for (;;) {
        int xlen = epp_read_frame(ssl, acc, &acclen, (int) sizeof(acc), xmlbuf, sizeof(xmlbuf));
        if (xlen == 0)
            break; /* clean close, no partial frame pending */
        if (xlen < 0) {
            dns_log(LOG_WARNING, "[eppd] frame read/parse error from %s — closing\n", subject);
            break;
        }
        int should_close = 0;
        int rlen = epp_dispatch(&sess, xmlbuf, xlen, resp, sizeof(resp), &should_close);
        if (rlen < 0) {
            dns_log(LOG_WARNING, "[eppd] malformed/unrecognized EPP frame from %s — closing\n",
                    subject);
            break;
        }
        if (rlen >= (int) sizeof(resp) || epp_write_frame(ssl, resp, rlen) < 0) {
            dns_log(LOG_WARNING, "[eppd] failed to send response to %s\n", subject);
            break;
        }
        if (should_close)
            break;
    }
}

typedef struct {
    int cfd;
} conn_arg_t;

static void *conn_thread(void *arg) {
    conn_arg_t *ca = (conn_arg_t *) arg;
    int cfd = ca->cfd;
    free(ca);
    struct timeval tv = {.tv_sec = 300}; /* EPP sessions are long-lived but not infinite */
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    pthread_mutex_lock(&g_tls_mutex);
    SSL_CTX *ctx = g_eppd_ctx;
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    pthread_mutex_unlock(&g_tls_mutex);
    if (!ssl) {
        close(cfd);
        return NULL;
    }
    SSL_set_fd(ssl, cfd);
    /* SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT (set by
     * tls_server_ctx_from_pem when a CA is configured, which is always, per
     * tls_material_load) means a client that presents no cert or an
     * unverifiable one fails the handshake here — the session never reaches
     * handle_session without a registrar cert RFC 5734 requires. */
    if (SSL_accept(ssl) > 0)
        handle_session(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
    return NULL;
}

/* `srv` is already bound (main() does this synchronously, before
 * apply_eppd_sandbox() runs) — this thread only serves it. Deliberately NOT
 * doing the bind here: seccomp_load() (libsandbox, no SCMP_FLTATR_CTL_TSYNC)
 * only confines the CALLING thread, and a thread already running at that
 * point is never retroactively confined — so accept_loop (and every
 * per-connection thread it spawns) MUST be created after the sandbox is
 * applied, not before. A first version of this file bound and started this
 * thread before apply_eppd_sandbox(), which meant the seccomp filter never
 * covered any registrar-facing code at all; caught via a strace harvest,
 * not by inspection — see feature-work-progress.md. */
static void *accept_loop(void *arg) {
    int srv = *(int *) arg;
    dns_log(LOG_NOTICE, "[eppd] EPP (RFC 5734, mTLS) on :%d\n", g_eppd_port);
    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0)
            continue;
        conn_arg_t *ca = malloc(sizeof(*ca));
        if (!ca) {
            close(cfd);
            continue;
        }
        ca->cfd = cfd;
        pthread_t tid;
        if (pthread_create(&tid, NULL, conn_thread, ca) != 0) {
            free(ca);
            close(cfd);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}

/* ── Config + main ──────────────────────────────────────────────────────── */
static int load_config(void) {
    safe_strcpy(g_valkey_host, cfgenv("DNS_VALKEY_HOST", "127.0.0.1"), sizeof(g_valkey_host));
    g_valkey_port = atoi(cfgenv("DNS_VALKEY_PORT", "6379"));
    safe_strcpy(g_valkey_pass, cfgenv("DNS_VALKEY_PASSWORD", ""), sizeof(g_valkey_pass));
    char val[512];
    if (!vk_get("config:eppd_enabled", val, sizeof(val)) || atoi(val) != 1) {
        dns_log(LOG_NOTICE, "[eppd] config:eppd_enabled is not 1 — nothing to do\n");
        return -1;
    }
    g_eppd_enabled = 1;
    if (vk_get("config:eppd_port", val, sizeof(val)) && val[0])
        g_eppd_port = atoi(val);
    return 0;
}

#ifndef UNIT_TEST
static int schema_gate(void) {
    char sv[32] = "";
    vk_get("schema:version", sv, sizeof(sv));
    switch (schema_version_check(sv)) {
        case SCHEMA_OK:
        case SCHEMA_MINOR_DIFF:
        case SCHEMA_ABSENT:
            return 0;
        default:
            dns_log(LOG_ERR,
                    "[Schema] schema:version %s incompatible with compiled %s — refusing to "
                    "start\n",
                    sv[0] ? sv : "(unparseable)", SCHEMA_VERSION_STR);
            return -1;
    }
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    signal(SIGPIPE, SIG_IGN);
    if (load_config() < 0)
        return 1;
    if (schema_gate() != 0)
        return 1;
    tls_reload();
    if (!g_eppd_ctx) {
        dns_log(LOG_ERR, "[eppd] no usable TLS material at startup — exiting\n");
        return 1;
    }
    /* Bind the (privileged, RFC 5734 default 700) listener synchronously,
     * BEFORE the sandbox — same ordering resolverd uses for its DoT
     * listener/udp_workers_start. Root is still available here (if any) for
     * the bind; sandbox_apply() drops it right after. Doing the bind in a
     * separate thread (as an earlier version of this file did) would let
     * that thread — and everything it later spawns — run outside the
     * seccomp filter entirely, since the filter only covers the calling
     * thread going forward, never retroactively. */
    int srv = listen_on(g_eppd_port);
    if (srv < 0) {
        dns_log(LOG_ERR, "[eppd] failed to bind :%d — exiting\n", g_eppd_port);
        return 1;
    }
    apply_eppd_sandbox();

    pthread_t lt;
    if (pthread_create(&lt, NULL, accept_loop, &srv) != 0) {
        dns_log(LOG_ERR, "[eppd] failed to start listener thread\n");
        return 1;
    }

    keyspace_watch_config_t kcfg;
    memset(&kcfg, 0, sizeof(kcfg));
    kcfg.host = g_valkey_host;
    kcfg.port = g_valkey_port;
    kcfg.pass = g_valkey_pass;
    kcfg.db = 0;
    static const char *prefixes[] = {"cert:current", "config:eppd_tls_cert_pem",
                                     "config:eppd_tls_key_pem", "config:eppd_mtls_ca_pem", NULL};
    kcfg.prefixes = prefixes;
    kcfg.on_reconnect = keyspace_catchup;
    kcfg.on_key = keyspace_on_key;
    kcfg.log = dns_log;
    kcfg.tag = "eppd";
    pthread_t kt;
    if (pthread_create(&kt, NULL, keyspace_watch_loop, &kcfg) == 0)
        pthread_detach(kt);

    pthread_join(lt, NULL);
    return 0;
}
#endif /* UNIT_TEST */
