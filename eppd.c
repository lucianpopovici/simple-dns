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
#include <ctype.h>
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
#include <openssl/rand.h>

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

/* Retract a previously published key — used by delete/update to remove a
 * zone:* delegation record or purge an epp:* object outright. A missing key
 * is not an error (DEL is idempotent in Valkey); only a connection failure
 * is reported. */
static int vk_del(const char *key) {
    pthread_mutex_lock(&g_vk_mutex);
    if (vkc_ensure_to(&g_vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    vkc_reply_t r;
    int ok = vkc_cmd(&g_vk, &r, 2, "DEL", key) == 0;
    pthread_mutex_unlock(&g_vk_mutex);
    return ok;
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

/* Extracts the value of `attr` (e.g. "op") from the raw opening-tag text
 * xml[tag_start,tag_end) — i.e. `attr="value"` or `attr='value'` — into out
 * (empty if absent or malformed; never partially filled). Requires a
 * non-identifier character (or the tag start) immediately before the match
 * so "op=" doesn't false-positive inside some other attribute name that
 * merely ends in "op". This is deliberately narrower than xml_next_tag's own
 * attribute *skipping*: it is the one place (RFC 5730 <transfer op="...">)
 * this parser needs an attribute *value*, not just element content. */
static void epp_xml_attr_extract(const char *xml, int tag_start, int tag_end, const char *attr,
                                 char *out, int outcap) {
    out[0] = 0;
    int alen = (int) strlen(attr);
    for (int i = tag_start; i + alen < tag_end; i++) {
        if ((i > tag_start) &&
            (isalnum((unsigned char) xml[i - 1]) || xml[i - 1] == ':' || xml[i - 1] == '-'))
            continue; /* mid-identifier — not a real attribute-name start */
        if (memcmp(xml + i, attr, (size_t) alen) != 0)
            continue;
        int j = i + alen;
        while (j < tag_end && (xml[j] == ' ' || xml[j] == '\t'))
            j++;
        if (j >= tag_end || xml[j] != '=')
            continue;
        j++;
        while (j < tag_end && (xml[j] == ' ' || xml[j] == '\t'))
            j++;
        if (j >= tag_end || (xml[j] != '"' && xml[j] != '\''))
            continue;
        char q = xml[j++];
        int vs = j;
        while (j < tag_end && xml[j] != q)
            j++;
        if (j >= tag_end)
            return; /* unterminated attribute value — fail closed, leave out empty */
        int vlen = j - vs;
        if (vlen >= outcap)
            vlen = outcap - 1;
        memcpy(out, xml + vs, (size_t) vlen);
        out[vlen] = 0;
        return;
    }
}

/* Same traversal as xml_find_child, but additionally extracts one attribute
 * (`attr`) from the matched element's opening tag — needed only for
 * <transfer op="...">, the sole place in RFC 5730/5910 this parser cares
 * about an attribute value rather than element content. attr_out is set to
 * "" (not an error) if the tag has no such attribute. */
static int xml_find_child_attr(const char *xml, int start, int end, const char *tag,
                               const char *attr, char *attr_out, int attr_cap, int *content_start,
                               int *content_end, int *next_pos) {
    int pos = start;
    int tag_len = (int) strlen(tag);
    for (;;) {
        const char *tn;
        int tnl, tag_start;
        xml_tagkind_t k = xml_next_tag(xml, &pos, end, &tn, &tnl, &tag_start);
        int open_tag_end = pos; /* right after this tag's own '>' / '/>' */
        switch (k) {
            case XMLTAG_SKIP:
                continue;
            case XMLTAG_CLOSE:
            case XMLTAG_EOF:
                return 0;
            case XMLTAG_SELFCLOSE:
                if (tnl == tag_len && memcmp(tn, tag, (size_t) tag_len) == 0) {
                    epp_xml_attr_extract(xml, tag_start, open_tag_end, attr, attr_out, attr_cap);
                    *content_start = *content_end = pos;
                    *next_pos = pos;
                    return 1;
                }
                continue;
            case XMLTAG_OPEN: {
                int cstart = pos;
                int close_start;
                int np = xml_skip_to_close(xml, pos, end, tn, tnl, 1, &close_start);
                if (np < 0)
                    return -1;
                if (tnl == tag_len && memcmp(tn, tag, (size_t) tag_len) == 0) {
                    epp_xml_attr_extract(xml, tag_start, open_tag_end, attr, attr_out, attr_cap);
                    *content_start = cstart;
                    *content_end = close_start;
                    *next_pos = np;
                    return 1;
                }
                pos = np;
                continue;
            }
            case XMLTAG_ERROR:
            default:
                return -1;
        }
    }
}

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
/* Phase 2 additions (RFC 3915 RGP, RFC 5910 DS mapping, RFC 5731 §3.2.4
 * transfer, and object ownership — see CLAUDE-eppd.md). */
#define EPP_TAG_CLID 13         /* sponsoring registrar; domain/host/contact */
#define EPP_TAG_RGP_STATE 14    /* u8, domain only — epp_rgp_state_t */
#define EPP_TAG_RGP_UNTIL 15    /* u32 unix time, domain only */
#define EPP_TAG_DS 16           /* repeated, domain only: keytag(2 BE)|alg(1)|digtype(1)|digest */
#define EPP_TAG_TRANSFER_REID 17    /* domain only — gaining registrar of a pending/last transfer */
#define EPP_TAG_TRANSFER_REDATE 18  /* u32 unix time, domain only */
#define EPP_TAG_TRANSFER_STATUS 19  /* domain only — "", "pending", "clientApproved", ... */

#define EPP_MAX_ARR 16 /* status/ns/addr/ds entries per object — ample for Phase 1/2 */
#define EPP_DS_MAX_DIGEST 68 /* SHA-512 (64) + headroom; covers every registered digest type */

/* RFC 3915 RGP grace-period state a domain can be in. NONE covers ordinary
 * "ok" life; the others gate what a delete/renew does and what <rgp:*>
 * status domain:info reports. Deliberately collapses RFC 3915's two-stage
 * redemptionPeriod + "pendingDelete scheduled for release" into one
 * REDEMPTION window (config:eppd_redemption_secs) followed directly by
 * purge — a private/internal registry has no registrar-facing distinction
 * between the two, and this project has no billing/credit system for the
 * add/autorenew/transfer grace periods to protect either; they only gate
 * "does a delete during this window purge immediately or enter redemption". */
typedef enum {
    EPP_RGP_NONE = 0,
    EPP_RGP_ADD = 1,
    EPP_RGP_AUTORENEW = 2,
    EPP_RGP_TRANSFER = 3,
    EPP_RGP_REDEMPTION = 4,
} epp_rgp_state_t;

static atomic_uint g_roid_counter = 0;

static void epp_gen_roid(char *out, int cap, const char *suffix) {
    unsigned n = atomic_fetch_add(&g_roid_counter, 1u) + 1;
    snprintf(out, (size_t) cap, "%u-%s", n, suffix);
}

/* RFC 9154 "secure authInfo": a registrar-chosen authInfo pw is a weak,
 * often-reused shared secret — the whole reason 9154 exists. eppd never
 * trusts a client-supplied value (create/update silently discard one and
 * log a notice); every object's authInfo is always this server-generated
 * 128-bit random token, hex-encoded to 32 chars. Falls back to a PRNG-only
 * warning rather than failing the whole command if RAND_bytes reports an
 * entropy-pool failure — an authInfo that is merely weak (not attacker-
 * controlled) is still strictly better than refusing to create the object,
 * and OpenSSL's default RNG only fails this way in practice on a
 * mis-provisioned host that has bigger problems than this one token. */
static void epp_gen_authinfo(char *out, int cap) {
    uint8_t raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        dns_log(LOG_WARNING, "[eppd] RAND_bytes failed generating authInfo — host entropy pool "
                             "may be exhausted\n");
        for (size_t i = 0; i < sizeof(raw); i++)
            raw[i] = (uint8_t) (rand() ^ (i * 2654435761u));
    }
    hex_enc(raw, sizeof(raw), out);
    (void) cap; /* hex_enc's output is always 2*sizeof(raw)+1 = 33 bytes; every authinfo[] field
                 * this feeds is >= 256 bytes, so cap is always ample — kept for call-site clarity */
}

static uint32_t tlv_u32_of(const uint8_t *val, uint16_t vlen) {
    if (vlen != 4)
        return 0;
    return ((uint32_t) val[0] << 24) | ((uint32_t) val[1] << 16) | ((uint32_t) val[2] << 8) |
           (uint32_t) val[3];
}

/* One RFC 5910 dsData entry: DS rdata fields, pre-digest-decoded to bytes so
 * emit/publish never has to re-parse hex out of a TLV blob. */
typedef struct {
    uint16_t keytag;
    uint8_t alg;
    uint8_t digtype;
    uint8_t digest[EPP_DS_MAX_DIGEST];
    int digestlen;
} epp_ds_t;

typedef struct {
    char roid[32];
    char clid[64]; /* sponsoring registrar — authorization + transfer source of truth */
    char status[EPP_MAX_ARR][32];
    int nstatus;
    char authinfo[256];
    uint32_t crdate;
    uint32_t exdate;
    char registrant[64];
    char ns[EPP_MAX_ARR][256];
    int nns;
    epp_ds_t ds[EPP_MAX_ARR];
    int nds;
    epp_rgp_state_t rgp_state;
    uint32_t rgp_until; /* unix time the current rgp_state's grace/redemption window ends */
    char transfer_reid[64];    /* gaining registrar of the last/pending transfer */
    uint32_t transfer_redate;  /* when that transfer was requested */
    char transfer_status[24];  /* "" (never transferred), "pending", "clientApproved",
                                 * "clientRejected", "clientCancelled", "serverApproved" */
} epp_domain_t;

typedef struct {
    char roid[32];
    char clid[64];
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
    char clid[64];
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
    if (off >= 0 && d->clid[0])
        off =
            tlv_put(buf, cap, off, EPP_TAG_CLID, (const uint8_t *) d->clid, (int) strlen(d->clid));
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
    for (int i = 0; off >= 0 && i < d->nds; i++) {
        const epp_ds_t *e = &d->ds[i];
        uint8_t dsraw[4 + EPP_DS_MAX_DIGEST];
        dsraw[0] = (uint8_t) (e->keytag >> 8);
        dsraw[1] = (uint8_t) (e->keytag & 0xFF);
        dsraw[2] = e->alg;
        dsraw[3] = e->digtype;
        int dl = e->digestlen;
        if (dl < 0)
            dl = 0;
        if (dl > EPP_DS_MAX_DIGEST)
            dl = EPP_DS_MAX_DIGEST;
        memcpy(dsraw + 4, e->digest, (size_t) dl);
        off = tlv_put(buf, cap, off, EPP_TAG_DS, dsraw, 4 + dl);
    }
    if (off >= 0 && d->rgp_state != EPP_RGP_NONE)
        off = tlv_put_u8(buf, cap, off, EPP_TAG_RGP_STATE, (uint8_t) d->rgp_state);
    if (off >= 0 && d->rgp_until)
        off = tlv_put_u32(buf, cap, off, EPP_TAG_RGP_UNTIL, d->rgp_until);
    if (off >= 0 && d->transfer_reid[0])
        off = tlv_put(buf, cap, off, EPP_TAG_TRANSFER_REID, (const uint8_t *) d->transfer_reid,
                      (int) strlen(d->transfer_reid));
    if (off >= 0 && d->transfer_redate)
        off = tlv_put_u32(buf, cap, off, EPP_TAG_TRANSFER_REDATE, d->transfer_redate);
    if (off >= 0 && d->transfer_status[0])
        off = tlv_put(buf, cap, off, EPP_TAG_TRANSFER_STATUS,
                      (const uint8_t *) d->transfer_status, (int) strlen(d->transfer_status));
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
            case EPP_TAG_CLID:
                if (vlen < sizeof(d->clid)) {
                    memcpy(d->clid, val, vlen);
                    d->clid[vlen] = 0;
                }
                break;
            case EPP_TAG_DS:
                if (d->nds < EPP_MAX_ARR && vlen >= 4 && vlen - 4 <= EPP_DS_MAX_DIGEST) {
                    epp_ds_t *e = &d->ds[d->nds];
                    e->keytag = (uint16_t) ((val[0] << 8) | val[1]);
                    e->alg = val[2];
                    e->digtype = val[3];
                    e->digestlen = vlen - 4;
                    memcpy(e->digest, val + 4, (size_t) e->digestlen);
                    d->nds++;
                }
                break;
            case EPP_TAG_RGP_STATE:
                if (vlen == 1)
                    d->rgp_state = (epp_rgp_state_t) val[0];
                break;
            case EPP_TAG_RGP_UNTIL:
                d->rgp_until = tlv_u32_of(val, vlen);
                break;
            case EPP_TAG_TRANSFER_REID:
                if (vlen < sizeof(d->transfer_reid)) {
                    memcpy(d->transfer_reid, val, vlen);
                    d->transfer_reid[vlen] = 0;
                }
                break;
            case EPP_TAG_TRANSFER_REDATE:
                d->transfer_redate = tlv_u32_of(val, vlen);
                break;
            case EPP_TAG_TRANSFER_STATUS:
                if (vlen < sizeof(d->transfer_status)) {
                    memcpy(d->transfer_status, val, vlen);
                    d->transfer_status[vlen] = 0;
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
    if (off >= 0 && h->clid[0])
        off =
            tlv_put(buf, cap, off, EPP_TAG_CLID, (const uint8_t *) h->clid, (int) strlen(h->clid));
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
            case EPP_TAG_CLID:
                if (vlen < sizeof(h->clid)) {
                    memcpy(h->clid, val, vlen);
                    h->clid[vlen] = 0;
                }
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
    if (off >= 0 && c->clid[0])
        off =
            tlv_put(buf, cap, off, EPP_TAG_CLID, (const uint8_t *) c->clid, (int) strlen(c->clid));
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
            case EPP_TAG_CLID:
                if (vlen < sizeof(c->clid)) {
                    memcpy(c->clid, val, vlen);
                    c->clid[vlen] = 0;
                }
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
 * writes zone:<parent>:NS:<name> (multi-value, P0b) and zone:<parent>:DS:<name>
 * (RFC 5910, Phase 2 — "ttl|keytag,alg,digtype,hexdigest|..."; deleted rather
 * than written when nds==0, since a domain can legitimately go from secure to
 * insecure) and, for each in-bailiwick NS target, zone:<parent>:A/AAAA:<ns>
 * glue looked up from that host's own epp:host:* record, then bumps the
 * parent's serial. Called from create and from update whenever NS or DS
 * changed. */
static void epp_publish_domain(const char *name, const char ns[][256], int nns,
                               const epp_ds_t *ds, int nds) {
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

    snprintf(key, sizeof(key), "zone:%s:DS:%s", zone, name);
    if (nds > 0) {
        char dsval[4096];
        int doff = snprintf(dsval, sizeof(dsval), "%d", 3600);
        for (int i = 0; i < nds && doff < (int) sizeof(dsval) - 1; i++) {
            char hexdigest[2 * EPP_DS_MAX_DIGEST + 1];
            hex_enc(ds[i].digest, ds[i].digestlen, hexdigest);
            doff += snprintf(dsval + doff, sizeof(dsval) - doff, "|%u,%u,%u,%s", ds[i].keytag,
                             ds[i].alg, ds[i].digtype, hexdigest);
        }
        vk_set(key, dsval);
    } else {
        vk_del(key); /* domain went (or stayed) insecure — retract any stale DS */
    }

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
    dns_log(LOG_NOTICE, "[eppd] published %s NS delegation into zone %s (%d ns, %d ds)\n", name,
            zone, nns, nds);
}

/* Retract a domain's delegation from the parent zone (RFC 3915 delete):
 * removes zone:<parent>:NS/DS:<name> and bumps the parent's serial.
 * In-bailiwick glue A/AAAA for the host(s) is deliberately left in place —
 * it is keyed by hostname, not by this domain, and another delegation may
 * still reference the same host (host:delete's own association check is
 * what actually guards against a dangling glue record). */
static void epp_retract_domain(const char *name) {
    char zone[256];
    if (find_parent_zone(name, zone, sizeof(zone)) < 0)
        return;
    char key[900];
    snprintf(key, sizeof(key), "zone:%s:NS:%s", zone, name);
    vk_del(key);
    snprintf(key, sizeof(key), "zone:%s:DS:%s", zone, name);
    vk_del(key);
    epp_serial_bump_zone(zone);
    dns_log(LOG_NOTICE, "[eppd] retracted %s delegation from zone %s\n", name, zone);
}

/* Config knobs (seconds; day-scale defaults, see CLAUDE-eppd.md Phase 2) — a
 * plain vk_get per call rather than a cached global, since these are only
 * read on create/delete/transfer/the RGP tick, never on the query hot path.
 */
static long epp_cfg_secs(const char *key, long defval) {
    char v[32];
    if (vk_get(key, v, sizeof(v)) && v[0])
        return atol(v);
    return defval;
}
#define EPPD_ADD_GRACE_SECS() epp_cfg_secs("config:eppd_add_grace_secs", 5L * 86400)
#define EPPD_AUTORENEW_GRACE_SECS() epp_cfg_secs("config:eppd_autorenew_grace_secs", 45L * 86400)
#define EPPD_REDEMPTION_SECS() epp_cfg_secs("config:eppd_redemption_secs", 30L * 86400)
#define EPPD_TRANSFER_GRACE_SECS() epp_cfg_secs("config:eppd_transfer_grace_secs", 5L * 86400)
#define EPPD_TRANSFER_PENDING_SECS() epp_cfg_secs("config:eppd_transfer_pending_secs", 5L * 86400)
#define EPPD_RGP_TICK_SECS() epp_cfg_secs("config:eppd_rgp_tick_secs", 3600L)

/* Does d->status[] contain `name` (one of the client-settable prohibition/
 * hold flags — clientUpdateProhibited, clientDeleteProhibited,
 * clientTransferProhibited, clientHold)? Used to enforce RFC 5731 §2.3
 * status semantics on update/delete/transfer. */
static int epp_domain_status_has(const epp_domain_t *d, const char *name) {
    for (int i = 0; i < d->nstatus; i++)
        if (strcmp(d->status[i], name) == 0)
            return 1;
    return 0;
}

/* Renders the full <status> tag list for domain:info: computed states
 * (pendingDelete from RGP redemption, pendingTransfer from a pending
 * transfer) take precedence for registrar visibility, then any explicit
 * client-set flags, falling back to plain "ok" if none apply. Server-status
 * "ok"/pendingDelete/pendingTransfer are never stored in d->status[] itself
 * (single source of truth: rgp_state / transfer_status), only computed here. */
static int epp_domain_compute_status(const epp_domain_t *d, char *out, int cap) {
    int off = 0;
    int any = 0;
    if (d->rgp_state == EPP_RGP_REDEMPTION) {
        off += snprintf(out + off, (size_t) (cap - off), "<status s=\"pendingDelete\"/>");
        any = 1;
    }
    if (strcmp(d->transfer_status, "pending") == 0) {
        off += snprintf(out + off, (size_t) (cap - off), "<status s=\"pendingTransfer\"/>");
        any = 1;
    }
    for (int i = 0; i < d->nstatus && off < cap - 1; i++) {
        off += snprintf(out + off, (size_t) (cap - off), "<status s=\"%s\"/>", d->status[i]);
        any = 1;
    }
    if (!any)
        off += snprintf(out + off, (size_t) (cap - off), "<status s=\"ok\"/>");
    return off;
}

/* ── host:* command handlers (RFC 5732) ───────────────────────────────── */
static int epp_host_check(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                          int qe, const char *cltrid, char *resp, int rcap) {
    (void) sess;
    (void) cmd_s;
    (void) cmd_e;
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

static int epp_host_create(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                           int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
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
    safe_strcpy(h.clid, sess->clid, sizeof(h.clid));
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

static int epp_host_info(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                         int qe, const char *cltrid, char *resp, int rcap) {
    (void) sess;
    (void) cmd_s;
    (void) cmd_e;
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
static int epp_contact_check(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                             int qe, const char *cltrid, char *resp, int rcap) {
    (void) sess;
    (void) cmd_s;
    (void) cmd_e;
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

static int epp_contact_create(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                              int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
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
    safe_strcpy(c.clid, sess->clid, sizeof(c.clid));
    int ns, ne, nnp;
    if (xml_find_child(xml, qs, qe, "contact:name", &ns, &ne, &nnp) == 1)
        xml_text_decode(xml, ns, ne, c.name, sizeof(c.name));
    int es, ee, enp;
    if (xml_find_child(xml, qs, qe, "contact:email", &es, &ee, &enp) == 1)
        xml_text_decode(xml, es, ee, c.email, sizeof(c.email));
    int vs, ve, vnp;
    if (xml_find_child(xml, qs, qe, "contact:voice", &vs, &ve, &vnp) == 1)
        xml_text_decode(xml, vs, ve, c.voice, sizeof(c.voice));
    /* RFC 9154: never trust a client-supplied authInfo — always generate a
     * fresh server-side random token, silently discarding any <contact:pw>
     * the create carried (a client that supplies one is doing so per RFC
     * 5733's grammar, which still requires the element; noting it is not an
     * error, just not honored). */
    int aps, ape, apnp;
    if (xml_find_child(xml, qs, qe, "contact:authInfo", &aps, &ape, &apnp) == 1)
        dns_log(LOG_INFO,
                "[eppd] contact:create for %s supplied an authInfo pw — ignored, server-generates "
                "one (RFC 9154)\n",
                id);
    epp_gen_authinfo(c.authinfo, sizeof(c.authinfo));
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

static int epp_contact_info(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                            int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
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
    /* RFC 9154: authInfo is only ever disclosed to the sponsoring registrar's
     * own session — not to any other logged-in registrar querying the same
     * object (a different registrar wanting to prepare a transfer request
     * must obtain it from the sponsor out of band, then present it via
     * domain:transfer, not read it back from contact:info). */
    char authxml[320] = "";
    if (c.clid[0] && strcmp(c.clid, sess->clid) == 0 && c.authinfo[0])
        snprintf(authxml, sizeof(authxml), "<authInfo><pw>%s</pw></authInfo>", c.authinfo);
    char extra[1300];
    snprintf(extra, sizeof(extra),
             "<infData xmlns=\"urn:ietf:params:xml:ns:contact-1.0\">"
             "<id>%s</id><roid>%s</roid><status s=\"ok\"/>%s%s%s"
             "<crDate>%s</crDate>%s</infData>",
             id, c.roid, c.name[0] ? "<name>" : "", c.name[0] ? c.name : "",
             c.name[0] ? "</name>" : "", crdatestr, authxml);
    (void) c.email;
    (void) c.voice; /* Phase 1: not echoed in infData yet, stored for later use */
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* ── domain:* command handlers (RFC 5731) ─────────────────────────────── */
static int epp_domain_check(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                            int qe, const char *cltrid, char *resp, int rcap) {
    (void) sess;
    (void) cmd_s;
    (void) cmd_e;
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

/* ── RFC 5910 secDNS extension (DS mapping) ───────────────────────────────
 * RFC 5910's DS data always rides in <command>'s <extension> sibling, not
 * inside <create>/<update> itself, so these need the whole command range
 * (cmd_s/cmd_e), not just the domain:create/domain:update object range. */
static int epp_find_secdns_block(const char *xml, int cmd_s, int cmd_e, const char *secdns_tag,
                                 int *bs, int *be) {
    int es, ee, enp;
    if (xml_find_child(xml, cmd_s, cmd_e, "extension", &es, &ee, &enp) != 1)
        return 0;
    return xml_find_child(xml, es, ee, secdns_tag, bs, be, &enp);
}

/* Parses every <secDNS:dsData> child of [s,e) into ds_out[], up to max
 * entries. An entry with a missing field or an undecodable digest is
 * skipped (fail closed per-entry, not per-command — mirrors dnsd's
 * emit_ds_rrset on the read side). Returns the count actually parsed. */
static int epp_parse_ds_block(const char *xml, int s, int e, epp_ds_t *ds_out, int max) {
    int n = 0, pos = s;
    while (n < max) {
        int ds_s, ds_e, ds_np;
        if (xml_find_child(xml, pos, e, "secDNS:dsData", &ds_s, &ds_e, &ds_np) != 1)
            break;
        pos = ds_np;
        char keytag_s[16] = "", alg_s[16] = "", digtype_s[16] = "", digest_s[257] = "";
        int fs, fe, fnp;
        if (xml_find_child(xml, ds_s, ds_e, "secDNS:keyTag", &fs, &fe, &fnp) != 1 ||
            xml_text_decode(xml, fs, fe, keytag_s, sizeof(keytag_s)) < 0)
            continue;
        if (xml_find_child(xml, ds_s, ds_e, "secDNS:alg", &fs, &fe, &fnp) != 1 ||
            xml_text_decode(xml, fs, fe, alg_s, sizeof(alg_s)) < 0)
            continue;
        if (xml_find_child(xml, ds_s, ds_e, "secDNS:digestType", &fs, &fe, &fnp) != 1 ||
            xml_text_decode(xml, fs, fe, digtype_s, sizeof(digtype_s)) < 0)
            continue;
        if (xml_find_child(xml, ds_s, ds_e, "secDNS:digest", &fs, &fe, &fnp) != 1 ||
            xml_text_decode(xml, fs, fe, digest_s, sizeof(digest_s)) < 0)
            continue;
        uint8_t digest[EPP_DS_MAX_DIGEST];
        int dlen = hex_dec(digest_s, digest, sizeof(digest));
        if (dlen <= 0)
            continue;
        epp_ds_t *d = &ds_out[n];
        d->keytag = (uint16_t) atoi(keytag_s);
        d->alg = (uint8_t) atoi(alg_s);
        d->digtype = (uint8_t) atoi(digtype_s);
        d->digestlen = dlen;
        memcpy(d->digest, digest, (size_t) dlen);
        n++;
    }
    return n;
}

static int epp_domain_create(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                             int qe, const char *cltrid, char *resp, int rcap) {
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

    /* RFC 5910: DS data (if any) rides in <extension><secDNS:create>, a
     * sibling of <create>, not inside domain:create itself. */
    epp_ds_t dslist[EPP_MAX_ARR];
    int nds = 0;
    int sbs, sbe;
    if (epp_find_secdns_block(xml, cmd_s, cmd_e, "secDNS:create", &sbs, &sbe) == 1)
        nds = epp_parse_ds_block(xml, sbs, sbe, dslist, EPP_MAX_ARR);

    /* RFC 9154: never trust a client-supplied authInfo (see epp_gen_authinfo). */
    int aps, ape, apnp;
    if (xml_find_child(xml, qs, qe, "domain:authInfo", &aps, &ape, &apnp) == 1)
        dns_log(LOG_INFO,
                "[eppd] domain:create for %s supplied an authInfo pw — ignored, server-generates "
                "one (RFC 9154)\n",
                name);

    epp_domain_t d;
    memset(&d, 0, sizeof(d));
    safe_strcpy(d.clid, sess->clid, sizeof(d.clid));
    epp_gen_authinfo(d.authinfo, sizeof(d.authinfo));
    epp_gen_roid(d.roid, sizeof(d.roid), "EPPD-D");
    d.crdate = (uint32_t) time(NULL);
    d.exdate = d.crdate + 365u * 24u * 3600u; /* Phase 1: fixed 1y; <domain:period> parsing TODO */
    safe_strcpy(d.registrant, registrant, sizeof(d.registrant));
    d.nns = nns;
    for (int i = 0; i < nns; i++)
        safe_strcpy(d.ns[i], nslist[i], sizeof(d.ns[0]));
    d.nds = nds;
    for (int i = 0; i < nds; i++)
        d.ds[i] = dslist[i];
    safe_strcpy(d.status[0], "ok", sizeof(d.status[0]));
    d.nstatus = 1;
    /* RFC 3915 addGracePeriod starts at creation — a delete before it ends
     * purges immediately rather than entering redemption (see delete). */
    d.rgp_state = EPP_RGP_ADD;
    d.rgp_until = d.crdate + (uint32_t) EPPD_ADD_GRACE_SECS();

    uint8_t tlv[4096];
    int tlen = epp_domain_encode(&d, tlv, sizeof(tlv));
    if (tlen < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[8192];
    hex_enc(tlv, tlen, hexbuf);
    vk_set(key, hexbuf);

    if (nns > 0 || nds > 0)
        epp_publish_domain(name, nslist, nns, d.ds, nds);

    char crdatestr[32], exdatestr[32];
    epp_iso_date(d.crdate, crdatestr, sizeof(crdatestr));
    epp_iso_date(d.exdate, exdatestr, sizeof(exdatestr));
    char extra[512];
    snprintf(extra, sizeof(extra),
             "<creData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\">"
             "<name>%s</name><crDate>%s</crDate><exDate>%s</exDate></creData>",
             name, crdatestr, exdatestr);
    dns_log(LOG_NOTICE, "[eppd] domain created: %s (%d ns, %d ds)\n", name, nns, nds);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* Maps the domain's current RGP grace/redemption phase, if any, to its RFC
 * 3915 §3.1.1 <rgp:rgpStatus> value. Returns NULL for EPP_RGP_NONE (no rgp
 * extension emitted at all — the common case for a domain not near any
 * lifecycle edge). */
static const char *epp_rgp_status_str(epp_rgp_state_t s) {
    switch (s) {
        case EPP_RGP_ADD:
            return "addPeriod";
        case EPP_RGP_AUTORENEW:
            return "autoRenewPeriod";
        case EPP_RGP_TRANSFER:
            return "transferPeriod";
        case EPP_RGP_REDEMPTION:
            return "redemptionPeriod";
        default:
            return NULL;
    }
}

static int epp_domain_info(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                           int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
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
    char statusxml[600];
    epp_domain_compute_status(&d, statusxml, sizeof(statusxml));
    char crdatestr[32], exdatestr[32];
    epp_iso_date(d.crdate, crdatestr, sizeof(crdatestr));
    epp_iso_date(d.exdate, exdatestr, sizeof(exdatestr));
    /* RFC 9154: only the sponsoring registrar's own session sees authInfo. */
    char authxml[320] = "";
    if (d.clid[0] && strcmp(d.clid, sess->clid) == 0 && d.authinfo[0])
        snprintf(authxml, sizeof(authxml), "<authInfo><pw>%s</pw></authInfo>", d.authinfo);
    /* RFC 5910 secDNS + RFC 3915 rgp companion extensions — both optional,
     * both live in the single <extension> sibling of <infData>. */
    char extxml[3000] = "";
    int extoff = 0;
    if (d.nds > 0) {
        extoff += snprintf(extxml + extoff, sizeof(extxml) - (size_t) extoff,
                           "<secDNS:infData xmlns:secDNS=\"urn:ietf:params:xml:ns:secDNS-1.1\">");
        for (int i = 0; i < d.nds && extoff < (int) sizeof(extxml) - 1; i++) {
            char hexdigest[2 * EPP_DS_MAX_DIGEST + 1];
            hex_enc(d.ds[i].digest, d.ds[i].digestlen, hexdigest);
            extoff += snprintf(extxml + extoff, sizeof(extxml) - (size_t) extoff,
                               "<secDNS:dsData><secDNS:keyTag>%u</secDNS:keyTag>"
                               "<secDNS:alg>%u</secDNS:alg><secDNS:digestType>%u</secDNS:digestType>"
                               "<secDNS:digest>%s</secDNS:digest></secDNS:dsData>",
                               d.ds[i].keytag, d.ds[i].alg, d.ds[i].digtype, hexdigest);
        }
        extoff += snprintf(extxml + extoff, sizeof(extxml) - (size_t) extoff, "</secDNS:infData>");
    }
    const char *rgpstr = epp_rgp_status_str(d.rgp_state);
    if (rgpstr && extoff < (int) sizeof(extxml) - 1)
        extoff += snprintf(extxml + extoff, sizeof(extxml) - (size_t) extoff,
                           "<rgp:infData xmlns:rgp=\"urn:ietf:params:xml:ns:rgp-1.0\">"
                           "<rgp:rgpStatus s=\"%s\"/></rgp:infData>",
                           rgpstr);
    char extension[3100] = "";
    if (extoff > 0)
        snprintf(extension, sizeof(extension), "<extension>%s</extension>", extxml);
    char extra[8000];
    snprintf(extra, sizeof(extra),
             "<infData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\">"
             "<name>%s</name><roid>%s</roid>%s"
             "%s%s%s"
             "<ns>%s</ns>"
             "<clID>%s</clID>"
             "<crDate>%s</crDate><exDate>%s</exDate>%s</infData>%s",
             name, d.roid, statusxml, d.registrant[0] ? "<registrant>" : "",
             d.registrant[0] ? d.registrant : "", d.registrant[0] ? "</registrant>" : "", nsxml,
             d.clid, crdatestr, exdatestr, authxml, extension);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
}

/* Unreachable in practice now that Phase 2 registers all 15 (op, obj)
 * combinations in epp_handle_command's handlers[] table — kept as a fail-
 * closed default for any combination a future edit forgets to register,
 * rather than falling through to "unknown command" (2000), which would
 * misdescribe a recognized-but-unwired op/obj pair as unrecognized syntax. */
static int epp_handle_object_command_stub(const char *op, const char *obj, const char *cltrid,
                                          char *resp, int rcap) {
    char msg[128];
    snprintf(msg, sizeof(msg), "Command failed: %s %s not implemented", op, obj);
    return epp_build_result(resp, rcap, 2400, msg, NULL, cltrid);
}

/* Whitelist of client-settable status flags accepted by domain:update's
 * <domain:add>/<domain:rem><domain:status s="..."/> (and reused, loosely,
 * for host:update's <host:status> — RFC 5732's status set is a subset of
 * this one; a private/internal registry does not need to reject the few
 * domain-only values on a host, so one shared whitelist is kept rather than
 * two nearly-identical ones). Server-computed statuses (ok, pendingDelete,
 * pendingTransfer, ...) are never client-settable — see
 * epp_domain_compute_status. */
static int epp_status_settable(const char *s) {
    static const char *allowed[] = {
        "clientUpdateProhibited",
        "clientDeleteProhibited",
        "clientTransferProhibited",
        "clientRenewProhibited",
        "clientHold",
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (strcmp(s, allowed[i]) == 0)
            return 1;
    return 0;
}

/* Does any epp:domain:* object currently list `hostname` in its NS set?
 * Used by host:delete's RFC 5732 §3.2.2 "association exists" (2305) guard
 * and by host:update/epp_republish_host_glue to find which domains' glue
 * needs refreshing. Bounded KEYS scan (cap 512) — same convention as
 * find_parent_zone's zone_table:* scan; epp:domain:* is not expected to be
 * huge for a private/internal registry (ADR-002). used_by/cap may be
 * NULL/0 to just get the count (host:delete's use). */
static int epp_host_in_use(const char *hostname, char used_by[][256], int cap) {
    char keys[512][256];
    int n = vk_list_keys("epp:domain:*", keys, 512);
    int nu = 0;
    for (int i = 0; i < n; i++) {
        char blob[VKC_BUF];
        if (!vk_get(keys[i], blob, sizeof(blob)))
            continue;
        uint8_t tlv[4096];
        int tlen = hex_dec(blob, tlv, sizeof(tlv));
        epp_domain_t d;
        if (tlen < 0 || epp_domain_decode(tlv, tlen, &d) < 0)
            continue;
        for (int j = 0; j < d.nns; j++) {
            if (strcasecmp(d.ns[j], hostname) != 0)
                continue;
            if (used_by && nu < cap)
                safe_strcpy(used_by[nu], keys[i] + strlen("epp:domain:"), 256);
            nu++;
            break;
        }
    }
    return nu;
}

/* Does any epp:domain:* object have `contact_id` as its registrant? Guards
 * contact:delete's RFC 5733 §3.2.2 "association exists" (2305) check. */
static int epp_contact_in_use(const char *contact_id) {
    char keys[512][256];
    int n = vk_list_keys("epp:domain:*", keys, 512);
    for (int i = 0; i < n; i++) {
        char blob[VKC_BUF];
        if (!vk_get(keys[i], blob, sizeof(blob)))
            continue;
        uint8_t tlv[4096];
        int tlen = hex_dec(blob, tlv, sizeof(tlv));
        epp_domain_t d;
        if (tlen < 0 || epp_domain_decode(tlv, tlen, &d) < 0)
            continue;
        if (d.registrant[0] && strcasecmp(d.registrant, contact_id) == 0)
            return 1;
    }
    return 0;
}

/* host:update changed this host's addresses — any domain that already
 * published it as glue needs that glue refreshed. epp_publish_domain is
 * idempotent (re-derives NS/DS/glue from the domain's own stored state), so
 * simply re-running it for every referencing domain is correct, if heavier
 * than a targeted glue-only patch — acceptable given host updates are rare
 * compared to DNS query volume. */
static void epp_republish_host_glue(const char *hostname) {
    char used_by[512][256];
    int nu = epp_host_in_use(hostname, used_by, 512);
    for (int i = 0; i < nu; i++) {
        char key[300], blob[VKC_BUF];
        snprintf(key, sizeof(key), "epp:domain:%s", used_by[i]);
        if (!vk_get(key, blob, sizeof(blob)))
            continue;
        uint8_t tlv[4096];
        int tlen = hex_dec(blob, tlv, sizeof(tlv));
        epp_domain_t d;
        if (tlen < 0 || epp_domain_decode(tlv, tlen, &d) < 0)
            continue;
        epp_publish_domain(used_by[i], d.ns, d.nns, d.ds, d.nds);
    }
}

/* ── host:* update/delete (RFC 5732) ──────────────────────────────────── */
static int epp_host_update(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                           int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
    char name[256] = "";
    int ns_, ne_, np;
    if (xml_find_child(xml, qs, qe, "host:name", &ns_, &ne_, &np) != 1 ||
        xml_text_decode(xml, ns_, ne_, name, sizeof(name)) < 0 || !name[0])
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
    if (h.clid[0] && strcmp(h.clid, sess->clid) != 0)
        return epp_build_result(resp, rcap, 2201, "Authorization error: not the sponsoring registrar",
                                NULL, cltrid);
    for (int i = 0; i < h.nstatus; i++)
        if (strcmp(h.status[i], "clientUpdateProhibited") == 0)
            return epp_build_result(resp, rcap, 2304, "Object status prohibits operation", NULL,
                                    cltrid);

    int as, ae, anp;
    if (xml_find_child(xml, qs, qe, "add", &as, &ae, &anp) == 1) {
        int pos = as, xs, xe, xnp;
        while (h.nv4 + h.nv6 < EPP_MAX_ARR &&
               xml_find_child(xml, pos, ae, "host:addr", &xs, &xe, &xnp) == 1) {
            char addr[64] = "";
            xml_text_decode(xml, xs, xe, addr, sizeof(addr));
            if (strchr(addr, ':')) {
                if (h.nv6 < EPP_MAX_ARR)
                    safe_strcpy(h.v6[h.nv6++], addr, sizeof(h.v6[0]));
            } else if (addr[0] && h.nv4 < EPP_MAX_ARR)
                safe_strcpy(h.v4[h.nv4++], addr, sizeof(h.v4[0]));
            pos = xnp;
        }
        pos = as;
        char sval[32];
        while (h.nstatus < EPP_MAX_ARR &&
               xml_find_child_attr(xml, pos, ae, "host:status", "s", sval, sizeof(sval), &xs, &xe,
                                   &xnp) == 1) {
            if (sval[0] && epp_status_settable(sval)) {
                int dup = 0;
                for (int i = 0; i < h.nstatus; i++)
                    if (strcmp(h.status[i], sval) == 0) {
                        dup = 1;
                        break;
                    }
                if (!dup)
                    safe_strcpy(h.status[h.nstatus++], sval, sizeof(h.status[0]));
            }
            pos = xnp;
        }
    }
    int rs, re, rnp;
    if (xml_find_child(xml, qs, qe, "rem", &rs, &re, &rnp) == 1) {
        int pos = rs, xs, xe, xnp;
        while (xml_find_child(xml, pos, re, "host:addr", &xs, &xe, &xnp) == 1) {
            char addr[64] = "";
            xml_text_decode(xml, xs, xe, addr, sizeof(addr));
            for (int i = 0; i < h.nv4; i++)
                if (strcmp(h.v4[i], addr) == 0) {
                    memmove(&h.v4[i], &h.v4[i + 1], (size_t) (h.nv4 - i - 1) * sizeof(h.v4[0]));
                    h.nv4--;
                    i--;
                }
            for (int i = 0; i < h.nv6; i++)
                if (strcmp(h.v6[i], addr) == 0) {
                    memmove(&h.v6[i], &h.v6[i + 1], (size_t) (h.nv6 - i - 1) * sizeof(h.v6[0]));
                    h.nv6--;
                    i--;
                }
            pos = xnp;
        }
        pos = rs;
        char sval[32];
        while (xml_find_child_attr(xml, pos, re, "host:status", "s", sval, sizeof(sval), &xs, &xe,
                                   &xnp) == 1) {
            for (int i = 0; i < h.nstatus; i++)
                if (strcmp(h.status[i], sval) == 0) {
                    memmove(&h.status[i], &h.status[i + 1],
                           (size_t) (h.nstatus - i - 1) * sizeof(h.status[0]));
                    h.nstatus--;
                    i--;
                }
            pos = xnp;
        }
    }
    uint8_t tlv2[4096];
    int tlen2 = epp_host_encode(&h, tlv2, sizeof(tlv2));
    if (tlen2 < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[8192];
    hex_enc(tlv2, tlen2, hexbuf);
    vk_set(key, hexbuf);
    epp_republish_host_glue(name);
    dns_log(LOG_NOTICE, "[eppd] host updated: %s (%d v4, %d v6)\n", name, h.nv4, h.nv6);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
}

static int epp_host_delete(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                           int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
    char name[256] = "";
    int ns_, ne_, np;
    if (xml_find_child(xml, qs, qe, "host:name", &ns_, &ne_, &np) != 1 ||
        xml_text_decode(xml, ns_, ne_, name, sizeof(name)) < 0 || !name[0])
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
    if (h.clid[0] && strcmp(h.clid, sess->clid) != 0)
        return epp_build_result(resp, rcap, 2201, "Authorization error: not the sponsoring registrar",
                                NULL, cltrid);
    for (int i = 0; i < h.nstatus; i++)
        if (strcmp(h.status[i], "clientDeleteProhibited") == 0)
            return epp_build_result(resp, rcap, 2304, "Object status prohibits operation", NULL,
                                    cltrid);
    if (epp_host_in_use(name, NULL, 0) > 0)
        return epp_build_result(resp, rcap, 2305,
                                "Association prohibits operation: host is in use by a domain's NS set",
                                NULL, cltrid);
    vk_del(key);
    dns_log(LOG_NOTICE, "[eppd] host deleted: %s\n", name);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
}

/* ── contact:* update/delete (RFC 5733) ───────────────────────────────── */
static int epp_contact_update(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                              int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
    char id[64] = "";
    int is_, ie_, inp;
    if (xml_find_child(xml, qs, qe, "contact:id", &is_, &ie_, &inp) != 1 ||
        xml_text_decode(xml, is_, ie_, id, sizeof(id)) < 0 || !id[0])
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
    if (c.clid[0] && strcmp(c.clid, sess->clid) != 0)
        return epp_build_result(resp, rcap, 2201, "Authorization error: not the sponsoring registrar",
                                NULL, cltrid);

    int chs, che, chnp;
    if (xml_find_child(xml, qs, qe, "chg", &chs, &che, &chnp) == 1) {
        int ns2, ne2, nnp2;
        if (xml_find_child(xml, chs, che, "contact:name", &ns2, &ne2, &nnp2) == 1)
            xml_text_decode(xml, ns2, ne2, c.name, sizeof(c.name));
        int es2, ee2, enp2;
        if (xml_find_child(xml, chs, che, "contact:email", &es2, &ee2, &enp2) == 1)
            xml_text_decode(xml, es2, ee2, c.email, sizeof(c.email));
        int vs2, ve2, vnp2;
        if (xml_find_child(xml, chs, che, "contact:voice", &vs2, &ve2, &vnp2) == 1)
            xml_text_decode(xml, vs2, ve2, c.voice, sizeof(c.voice));
        int aps, ape, apnp;
        if (xml_find_child(xml, chs, che, "contact:authInfo", &aps, &ape, &apnp) == 1) {
            /* RFC 9154: regenerate server-side, never accept the client's value. */
            epp_gen_authinfo(c.authinfo, sizeof(c.authinfo));
            dns_log(LOG_INFO,
                    "[eppd] contact:update for %s requested authInfo change — regenerated "
                    "server-side (RFC 9154)\n",
                    id);
        }
    }
    uint8_t tlv2[2048];
    int tlen2 = epp_contact_encode(&c, tlv2, sizeof(tlv2));
    if (tlen2 < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[4096];
    hex_enc(tlv2, tlen2, hexbuf);
    vk_set(key, hexbuf);
    dns_log(LOG_NOTICE, "[eppd] contact updated: %s\n", id);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
}

static int epp_contact_delete(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                              int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
    char id[64] = "";
    int is_, ie_, inp;
    if (xml_find_child(xml, qs, qe, "contact:id", &is_, &ie_, &inp) != 1 ||
        xml_text_decode(xml, is_, ie_, id, sizeof(id)) < 0 || !id[0])
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
    if (c.clid[0] && strcmp(c.clid, sess->clid) != 0)
        return epp_build_result(resp, rcap, 2201, "Authorization error: not the sponsoring registrar",
                                NULL, cltrid);
    if (epp_contact_in_use(id))
        return epp_build_result(
            resp, rcap, 2305, "Association prohibits operation: contact is a domain's registrant",
            NULL, cltrid);
    vk_del(key);
    dns_log(LOG_NOTICE, "[eppd] contact deleted: %s\n", id);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
}

/* ── domain:* update/delete (RFC 5731) + RGP (RFC 3915) + secDNS (RFC 5910) ── */
static int epp_domain_update(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                             int qe, const char *cltrid, char *resp, int rcap) {
    char name[256] = "";
    int ns_, ne_, np;
    if (xml_find_child(xml, qs, qe, "domain:name", &ns_, &ne_, &np) != 1 ||
        xml_text_decode(xml, ns_, ne_, name, sizeof(name)) < 0 || !name[0])
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
    if (d.clid[0] && strcmp(d.clid, sess->clid) != 0)
        return epp_build_result(resp, rcap, 2201, "Authorization error: not the sponsoring registrar",
                                NULL, cltrid);
    if (epp_domain_status_has(&d, "clientUpdateProhibited"))
        return epp_build_result(resp, rcap, 2304, "Object status prohibits operation", NULL, cltrid);

    int changed_ns = 0, changed_ds = 0;

    int as, ae, anp;
    if (xml_find_child(xml, qs, qe, "add", &as, &ae, &anp) == 1) {
        int nss, nse, nsnp;
        if (xml_find_child(xml, as, ae, "domain:ns", &nss, &nse, &nsnp) == 1) {
            /* update only accepts hostObj referencing an already-existing host
             * — hostAttr's implicit host create/update is domain:create-only
             * (kept there, not duplicated here: a real update rarely needs it,
             * and the object model has no natural place to record "this host
             * was implicitly modified by an unrelated domain's update"). */
            int pos = nss, hos, hoe, honp;
            while (d.nns < EPP_MAX_ARR &&
                   xml_find_child(xml, pos, nse, "domain:hostObj", &hos, &hoe, &honp) == 1) {
                char hn[256] = "";
                xml_text_decode(xml, hos, hoe, hn, sizeof(hn));
                strlower(hn);
                char hkey[300], hblob[16];
                snprintf(hkey, sizeof(hkey), "epp:host:%s", hn);
                if (vk_get(hkey, hblob, sizeof(hblob))) {
                    int dup = 0;
                    for (int i = 0; i < d.nns; i++)
                        if (strcasecmp(d.ns[i], hn) == 0) {
                            dup = 1;
                            break;
                        }
                    if (!dup) {
                        safe_strcpy(d.ns[d.nns], hn, sizeof(d.ns[0]));
                        d.nns++;
                        changed_ns = 1;
                    }
                }
                pos = honp;
            }
        }
        int pos = as, xs, xe, xnp;
        char sval[32];
        while (d.nstatus < EPP_MAX_ARR &&
               xml_find_child_attr(xml, pos, ae, "domain:status", "s", sval, sizeof(sval), &xs, &xe,
                                   &xnp) == 1) {
            if (sval[0] && epp_status_settable(sval)) {
                int dup = 0;
                for (int i = 0; i < d.nstatus; i++)
                    if (strcmp(d.status[i], sval) == 0) {
                        dup = 1;
                        break;
                    }
                if (!dup)
                    safe_strcpy(d.status[d.nstatus++], sval, sizeof(d.status[0]));
            }
            pos = xnp;
        }
    }

    int rs, re, rnp;
    if (xml_find_child(xml, qs, qe, "rem", &rs, &re, &rnp) == 1) {
        int nss, nse, nsnp;
        if (xml_find_child(xml, rs, re, "domain:ns", &nss, &nse, &nsnp) == 1) {
            int pos = nss, hos, hoe, honp;
            while (xml_find_child(xml, pos, nse, "domain:hostObj", &hos, &hoe, &honp) == 1) {
                char hn[256] = "";
                xml_text_decode(xml, hos, hoe, hn, sizeof(hn));
                strlower(hn);
                for (int i = 0; i < d.nns; i++)
                    if (strcasecmp(d.ns[i], hn) == 0) {
                        memmove(&d.ns[i], &d.ns[i + 1], (size_t) (d.nns - i - 1) * sizeof(d.ns[0]));
                        d.nns--;
                        changed_ns = 1;
                        i--;
                    }
                pos = honp;
            }
        }
        int pos = rs, xs, xe, xnp;
        char sval[32];
        while (xml_find_child_attr(xml, pos, re, "domain:status", "s", sval, sizeof(sval), &xs, &xe,
                                   &xnp) == 1) {
            for (int i = 0; i < d.nstatus; i++)
                if (strcmp(d.status[i], sval) == 0) {
                    memmove(&d.status[i], &d.status[i + 1],
                           (size_t) (d.nstatus - i - 1) * sizeof(d.status[0]));
                    d.nstatus--;
                    i--;
                }
            pos = xnp;
        }
    }

    int chs, che, chnp;
    if (xml_find_child(xml, qs, qe, "chg", &chs, &che, &chnp) == 1) {
        int rgs, rge, rgnp;
        if (xml_find_child(xml, chs, che, "domain:registrant", &rgs, &rge, &rgnp) == 1)
            xml_text_decode(xml, rgs, rge, d.registrant, sizeof(d.registrant));
        int aps, ape, apnp;
        if (xml_find_child(xml, chs, che, "domain:authInfo", &aps, &ape, &apnp) == 1) {
            epp_gen_authinfo(d.authinfo, sizeof(d.authinfo));
            dns_log(LOG_INFO,
                    "[eppd] domain:update for %s requested authInfo change — regenerated "
                    "server-side (RFC 9154)\n",
                    name);
        }
    }

    /* RFC 5910 secDNS extension: <secDNS:chg> replaces the whole DS set;
     * otherwise <secDNS:add>/<secDNS:rem> are additive (rem matches on
     * keyTag+alg+digestType, ignoring the digest bytes — the identifying
     * triple per RFC 5910 §3.2). */
    int secs_, sece;
    if (epp_find_secdns_block(xml, cmd_s, cmd_e, "secDNS:update", &secs_, &sece) == 1) {
        int cs2, ce2, cnp2;
        if (xml_find_child(xml, secs_, sece, "secDNS:chg", &cs2, &ce2, &cnp2) == 1) {
            d.nds = epp_parse_ds_block(xml, cs2, ce2, d.ds, EPP_MAX_ARR);
            changed_ds = 1;
        } else {
            int ads, ade, adnp;
            if (xml_find_child(xml, secs_, sece, "secDNS:add", &ads, &ade, &adnp) == 1) {
                epp_ds_t toadd[EPP_MAX_ARR];
                int nadd = epp_parse_ds_block(xml, ads, ade, toadd, EPP_MAX_ARR);
                for (int i = 0; i < nadd && d.nds < EPP_MAX_ARR; i++) {
                    d.ds[d.nds++] = toadd[i];
                    changed_ds = 1;
                }
            }
            int rds, rde, rdnp;
            if (xml_find_child(xml, secs_, sece, "secDNS:rem", &rds, &rde, &rdnp) == 1) {
                epp_ds_t torem[EPP_MAX_ARR];
                int nrem = epp_parse_ds_block(xml, rds, rde, torem, EPP_MAX_ARR);
                for (int i = 0; i < nrem; i++)
                    for (int j = 0; j < d.nds; j++)
                        if (d.ds[j].keytag == torem[i].keytag && d.ds[j].alg == torem[i].alg &&
                            d.ds[j].digtype == torem[i].digtype) {
                            memmove(&d.ds[j], &d.ds[j + 1],
                                   (size_t) (d.nds - j - 1) * sizeof(d.ds[0]));
                            d.nds--;
                            changed_ds = 1;
                            j--;
                        }
            }
        }
    }

    /* RFC 3915 restore: <extension><rgp:update><rgp:restore op="request"/>
     * ...</rgp:update></extension>. Simplified from the full request+report
     * two-step (see CLAUDE-eppd.md) — a request alone restores the domain
     * to "ok" immediately, since a private/internal registry has no
     * registrar-facing report workflow to gate on. */
    int rgs2, rge2;
    if (epp_find_secdns_block(xml, cmd_s, cmd_e, "rgp:update", &rgs2, &rge2) == 1) {
        char restoreop[16] = "";
        int rrs, rre, rrnp;
        if (xml_find_child_attr(xml, rgs2, rge2, "rgp:restore", "op", restoreop, sizeof(restoreop),
                                &rrs, &rre, &rrnp) == 1 &&
            strcmp(restoreop, "request") == 0 && d.rgp_state == EPP_RGP_REDEMPTION) {
            d.rgp_state = EPP_RGP_NONE;
            d.rgp_until = 0;
            changed_ns = 1; /* force republish — the delegation was retracted on delete */
            dns_log(LOG_NOTICE, "[eppd] domain %s restored from redemptionPeriod\n", name);
        }
    }

    uint8_t tlv2[4096];
    int tlen2 = epp_domain_encode(&d, tlv2, sizeof(tlv2));
    if (tlen2 < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[8192];
    hex_enc(tlv2, tlen2, hexbuf);
    vk_set(key, hexbuf);

    if (changed_ns || changed_ds)
        epp_publish_domain(name, d.ns, d.nns, d.ds, d.nds);

    dns_log(LOG_NOTICE, "[eppd] domain updated: %s (ns=%d ds=%d)\n", name, d.nns, d.nds);
    return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
}

static int epp_domain_delete(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e, int qs,
                             int qe, const char *cltrid, char *resp, int rcap) {
    (void) cmd_s;
    (void) cmd_e;
    char name[256] = "";
    int ns_, ne_, np;
    if (xml_find_child(xml, qs, qe, "domain:name", &ns_, &ne_, &np) != 1 ||
        xml_text_decode(xml, ns_, ne_, name, sizeof(name)) < 0 || !name[0])
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
    if (d.clid[0] && strcmp(d.clid, sess->clid) != 0)
        return epp_build_result(resp, rcap, 2201, "Authorization error: not the sponsoring registrar",
                                NULL, cltrid);
    if (epp_domain_status_has(&d, "clientDeleteProhibited"))
        return epp_build_result(resp, rcap, 2304, "Object status prohibits operation", NULL, cltrid);
    if (strcmp(d.transfer_status, "pending") == 0)
        return epp_build_result(resp, rcap, 2304,
                                "Object status prohibits operation: transfer pending", NULL, cltrid);

    time_t now = time(NULL);
    /* RFC 3915 §3.2: a delete during the add, autoRenew, or transfer grace
     * window is a full (immediate) delete — no redemptionPeriod. Checked
     * directly against rgp_state/rgp_until (which the RGP tick keeps
     * current), not by re-deriving "how long ago was the triggering event"
     * from crDate — crDate must never change once set (an autorenew is not
     * a recreation), so it can't double as that reference point. */
    int in_grace =
        (d.rgp_state == EPP_RGP_ADD || d.rgp_state == EPP_RGP_AUTORENEW ||
         d.rgp_state == EPP_RGP_TRANSFER) &&
        now < (time_t) d.rgp_until;

    if (in_grace) {
        epp_retract_domain(name);
        vk_del(key);
        dns_log(LOG_NOTICE, "[eppd] domain deleted (grace period, immediate purge): %s\n", name);
        return epp_build_result(resp, rcap, 1000, "Command completed successfully", NULL, cltrid);
    }

    d.rgp_state = EPP_RGP_REDEMPTION;
    d.rgp_until = (uint32_t) now + (uint32_t) EPPD_REDEMPTION_SECS();
    uint8_t tlv2[4096];
    int tlen2 = epp_domain_encode(&d, tlv2, sizeof(tlv2));
    if (tlen2 < 0)
        return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
    char hexbuf[8192];
    hex_enc(tlv2, tlen2, hexbuf);
    vk_set(key, hexbuf);
    epp_retract_domain(name); /* stops resolving during redemption, like every real registry */
    dns_log(LOG_NOTICE, "[eppd] domain %s entered redemptionPeriod (purge in %lds unless restored)\n",
            name, (long) EPPD_REDEMPTION_SECS());
    return epp_build_result(resp, rcap, 1001, "Command completed successfully; action pending", NULL,
                            cltrid);
}

/* ── domain:transfer (RFC 5731 §3.2.4) ────────────────────────────────────
 * Not part of epp_obj_handler_fn's dispatch table (its <transfer op="...">
 * shape needs the op attribute the table's callers don't have), so
 * epp_handle_command calls this directly. */
static int epp_domain_transfer(epp_session_t *sess, const char *xml, int ts, int te, const char *op,
                               const char *cltrid, char *resp, int rcap) {
    /* The object-specific payload is <domain:transfer>, nested one level
     * inside <transfer op="...">'s content — mirroring how <domain:create>
     * nests inside <create> — not domain:name/domain:authInfo directly at
     * the <transfer> level. */
    int dts, dte, dtnp;
    if (xml_find_child(xml, ts, te, "domain:transfer", &dts, &dte, &dtnp) != 1)
        return epp_build_result(resp, rcap, 2003, "Required parameter missing: domain:transfer",
                                NULL, cltrid);
    int ds_, de_, dnp;
    char name[256] = "";
    if (xml_find_child(xml, dts, dte, "domain:name", &ds_, &de_, &dnp) != 1 ||
        xml_text_decode(xml, ds_, de_, name, sizeof(name)) < 0 || !name[0])
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
    int is_pending = strcmp(d.transfer_status, "pending") == 0;

    if (strcmp(op, "query") == 0) {
        if (!d.transfer_status[0])
            return epp_build_result(resp, rcap, 2303, "Object does not exist: no transfer history",
                                    NULL, cltrid);
        if (strcmp(sess->clid, d.clid) != 0 && strcmp(sess->clid, d.transfer_reid) != 0)
            return epp_build_result(resp, rcap, 2201,
                                    "Authorization error: not a party to this transfer", NULL,
                                    cltrid);
        char extra[700];
        snprintf(extra, sizeof(extra),
                "<trnData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\"><name>%s</name>"
                "<trStatus>%s</trStatus><reID>%s</reID><acID>%s</acID></trnData>",
                name, d.transfer_status, d.transfer_reid, d.clid);
        return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
    }

    if (strcmp(op, "request") == 0) {
        if (is_pending)
            return epp_build_result(resp, rcap, 2304,
                                    "Object status prohibits operation: transfer already pending",
                                    NULL, cltrid);
        if (epp_domain_status_has(&d, "clientTransferProhibited") ||
            epp_domain_status_has(&d, "serverTransferProhibited"))
            return epp_build_result(resp, rcap, 2304, "Object status prohibits operation", NULL,
                                    cltrid);
        if (d.clid[0] && strcmp(d.clid, sess->clid) == 0)
            return epp_build_result(resp, rcap, 2002,
                                    "Command use error: already the sponsoring registrar", NULL,
                                    cltrid);
        int as_, ae_, anp;
        char pw[256] = "";
        if (xml_find_child(xml, dts, dte, "domain:authInfo", &as_, &ae_, &anp) != 1)
            return epp_build_result(resp, rcap, 2003,
                                    "Required parameter missing: domain:authInfo", NULL, cltrid);
        int pws, pwe, pwnp;
        if (xml_find_child(xml, as_, ae_, "domain:pw", &pws, &pwe, &pwnp) != 1 ||
            xml_text_decode(xml, pws, pwe, pw, sizeof(pw)) < 0)
            return epp_build_result(resp, rcap, 2003,
                                    "Required parameter missing: domain:authInfo/pw", NULL, cltrid);
        if (!d.authinfo[0] || strcmp(d.authinfo, pw) != 0)
            return epp_build_result(resp, rcap, 2200, "Authentication error: authInfo mismatch",
                                    NULL, cltrid);

        safe_strcpy(d.transfer_reid, sess->clid, sizeof(d.transfer_reid));
        d.transfer_redate = (uint32_t) time(NULL);
        safe_strcpy(d.transfer_status, "pending", sizeof(d.transfer_status));
        uint8_t tlv2[4096];
        int tlen2 = epp_domain_encode(&d, tlv2, sizeof(tlv2));
        if (tlen2 < 0)
            return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
        char hexbuf[8192];
        hex_enc(tlv2, tlen2, hexbuf);
        vk_set(key, hexbuf);
        dns_log(LOG_NOTICE, "[eppd] transfer requested for %s: %s -> %s\n", name, d.clid,
                sess->clid);
        char extra[700];
        snprintf(extra, sizeof(extra),
                "<trnData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\"><name>%s</name>"
                "<trStatus>pending</trStatus><reID>%s</reID><acID>%s</acID></trnData>",
                name, d.transfer_reid, d.clid);
        return epp_build_result(resp, rcap, 1001, "Command completed successfully; action pending",
                                extra, cltrid);
    }

    if (strcmp(op, "cancel") == 0 || strcmp(op, "reject") == 0 || strcmp(op, "approve") == 0) {
        if (!is_pending)
            return epp_build_result(resp, rcap, 2304,
                                    "Object status prohibits operation: no pending transfer", NULL,
                                    cltrid);
        int is_gaining = strcmp(sess->clid, d.transfer_reid) == 0;
        int is_losing = d.clid[0] && strcmp(sess->clid, d.clid) == 0;
        if (strcmp(op, "cancel") == 0) {
            if (!is_gaining)
                return epp_build_result(resp, rcap, 2201,
                                        "Authorization error: not the requesting registrar", NULL,
                                        cltrid);
            safe_strcpy(d.transfer_status, "clientCancelled", sizeof(d.transfer_status));
        } else if (strcmp(op, "reject") == 0) {
            if (!is_losing)
                return epp_build_result(resp, rcap, 2201,
                                        "Authorization error: not the sponsoring registrar", NULL,
                                        cltrid);
            safe_strcpy(d.transfer_status, "clientRejected", sizeof(d.transfer_status));
        } else {
            if (!is_losing)
                return epp_build_result(resp, rcap, 2201,
                                        "Authorization error: not the sponsoring registrar", NULL,
                                        cltrid);
            safe_strcpy(d.transfer_status, "clientApproved", sizeof(d.transfer_status));
            safe_strcpy(d.clid, d.transfer_reid, sizeof(d.clid));
            d.exdate += 365u * 24u * 3600u; /* RFC 5731 §3.2.4: transfer extends by 1 registration
                                              * period */
            d.rgp_state = EPP_RGP_TRANSFER;
            d.rgp_until = (uint32_t) time(NULL) + (uint32_t) EPPD_TRANSFER_GRACE_SECS();
        }
        uint8_t tlv2[4096];
        int tlen2 = epp_domain_encode(&d, tlv2, sizeof(tlv2));
        if (tlen2 < 0)
            return epp_build_result(resp, rcap, 2400, "Command failed: encode error", NULL, cltrid);
        char hexbuf[8192];
        hex_enc(tlv2, tlen2, hexbuf);
        vk_set(key, hexbuf);
        dns_log(LOG_NOTICE, "[eppd] transfer %s for %s (now %s)\n", op, name, d.transfer_status);
        char extra[700];
        snprintf(extra, sizeof(extra),
                "<trnData xmlns=\"urn:ietf:params:xml:ns:domain-1.0\"><name>%s</name>"
                "<trStatus>%s</trStatus><reID>%s</reID><acID>%s</acID></trnData>",
                name, d.transfer_status, d.transfer_reid, d.clid);
        return epp_build_result(resp, rcap, 1000, "Command completed successfully", extra, cltrid);
    }

    return epp_build_result(resp, rcap, 2101, "Unimplemented option: transfer op", NULL, cltrid);
}

typedef int (*epp_obj_handler_fn)(epp_session_t *sess, const char *xml, int cmd_s, int cmd_e,
                                  int qs, int qe, const char *cltrid, char *resp, int rcap);

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

    if (!sess->logged_in) {
        int os, oe, onp;
        /* <transfer> is handled below (its own dispatch, own auth checks per
         * op= — a transfer request is inherently cross-registrar); every
         * other command requires an existing session. */
        if (xml_find_child(xml, cmd_s, cmd_e, "transfer", &os, &oe, &onp) != 1)
            return epp_build_result(resp, rcap, 2201, "Authorization error: not logged in", NULL,
                                    cltrid);
    }

    int ts, te, tnp;
    char transfer_op[16] = "";
    if (xml_find_child_attr(xml, cmd_s, cmd_e, "transfer", "op", transfer_op, sizeof(transfer_op),
                            &ts, &te, &tnp) == 1) {
        if (!sess->logged_in)
            return epp_build_result(resp, rcap, 2201, "Authorization error: not logged in", NULL,
                                    cltrid);
        return epp_domain_transfer(sess, xml, ts, te, transfer_op, cltrid, resp, rcap);
    }

    static const struct {
        const char *tag;
        const char *op;
    } objcmds[] = {
        {"check", "check"},   {"info", "info"},     {"create", "create"},
        {"update", "update"}, {"delete", "delete"},
    };
    static const struct {
        const char *op;
        const char *obj;
        epp_obj_handler_fn fn;
    } handlers[] = {
        {"check", "domain", epp_domain_check},     {"create", "domain", epp_domain_create},
        {"info", "domain", epp_domain_info},       {"update", "domain", epp_domain_update},
        {"delete", "domain", epp_domain_delete},   {"check", "host", epp_host_check},
        {"create", "host", epp_host_create},       {"info", "host", epp_host_info},
        {"update", "host", epp_host_update},       {"delete", "host", epp_host_delete},
        {"check", "contact", epp_contact_check},   {"create", "contact", epp_contact_create},
        {"info", "contact", epp_contact_info},     {"update", "contact", epp_contact_update},
        {"delete", "contact", epp_contact_delete},
    };
    for (size_t i = 0; i < sizeof(objcmds) / sizeof(objcmds[0]); i++) {
        int os, oe, onp;
        if (xml_find_child(xml, cmd_s, cmd_e, objcmds[i].tag, &os, &oe, &onp) != 1)
            continue;
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
                    return handlers[k].fn(sess, xml, cmd_s, cmd_e, qs, qe, cltrid, resp, rcap);
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

/* ── RFC 3915 RGP background sweep ─────────────────────────────────────────
 * The state transitions that don't happen synchronously inside a command
 * handler because nothing triggers them except the passage of time:
 * autoRenewPeriod (exdate reached), redemption purge (redemption window
 * elapsed with no restore), grace-window expiry (add/autorenew/transfer
 * revert to plain "ok"), and transfer auto-approval (RFC 5731 §3.2.4 — a
 * registry auto-approves a transfer request the losing registrar neither
 * approved nor rejected within the pending window). One domain at a time,
 * each independently encoded/stored — a crash or Valkey hiccup mid-sweep
 * loses at most the domains not yet reached this tick, not the whole batch.
 */
static void epp_rgp_tick_one(const char *domkey) {
    char blob[VKC_BUF];
    if (!vk_get(domkey, blob, sizeof(blob)))
        return;
    uint8_t tlv[4096];
    int tlen = hex_dec(blob, tlv, sizeof(tlv));
    epp_domain_t d;
    if (tlen < 0 || epp_domain_decode(tlv, tlen, &d) < 0)
        return;
    const char *name = domkey + strlen("epp:domain:");
    uint32_t now = (uint32_t) time(NULL);
    int changed = 0;
    int purge = 0;

    if (d.rgp_state == EPP_RGP_REDEMPTION && now >= d.rgp_until) {
        purge = 1;
    } else {
        if (d.rgp_state != EPP_RGP_REDEMPTION && now >= d.exdate) {
            /* RFC 3915 autoRenewPeriod: registration renews automatically;
             * a delete during the grace window that follows is immediate
             * (epp_domain_delete checks rgp_state/rgp_until directly, not
             * crDate — crDate must never change once set, an autorenew is
             * not a recreation). */
            d.exdate += 365u * 24u * 3600u;
            d.rgp_state = EPP_RGP_AUTORENEW;
            d.rgp_until = now + (uint32_t) EPPD_AUTORENEW_GRACE_SECS();
            changed = 1;
            dns_log(LOG_NOTICE, "[eppd] domain %s auto-renewed (new exdate)\n", name);
        } else if ((d.rgp_state == EPP_RGP_ADD || d.rgp_state == EPP_RGP_AUTORENEW ||
                   d.rgp_state == EPP_RGP_TRANSFER) &&
                  now >= d.rgp_until) {
            d.rgp_state = EPP_RGP_NONE;
            d.rgp_until = 0;
            changed = 1;
        }
        if (strcmp(d.transfer_status, "pending") == 0 &&
            now - d.transfer_redate > (uint32_t) EPPD_TRANSFER_PENDING_SECS()) {
            /* RFC 5731 §3.2.4: no response within the pending window ->
             * server auto-approves. */
            safe_strcpy(d.transfer_status, "serverApproved", sizeof(d.transfer_status));
            safe_strcpy(d.clid, d.transfer_reid, sizeof(d.clid));
            d.exdate += 365u * 24u * 3600u;
            d.rgp_state = EPP_RGP_TRANSFER;
            d.rgp_until = now + (uint32_t) EPPD_TRANSFER_GRACE_SECS();
            changed = 1;
            dns_log(LOG_NOTICE, "[eppd] domain %s transfer auto-approved (pending window elapsed)\n",
                    name);
        }
    }

    if (purge) {
        vk_del(domkey); /* delegation was already retracted when delete entered redemption */
        dns_log(LOG_NOTICE, "[eppd] domain %s purged (redemptionPeriod elapsed)\n", name);
        return;
    }
    if (!changed)
        return;
    uint8_t tlv2[4096];
    int tlen2 = epp_domain_encode(&d, tlv2, sizeof(tlv2));
    if (tlen2 < 0)
        return;
    char hexbuf[8192];
    hex_enc(tlv2, tlen2, hexbuf);
    vk_set(domkey, hexbuf);
}

static void epp_rgp_tick_scan(void) {
    char keys[512][256];
    int n = vk_list_keys("epp:domain:*", keys, 512);
    for (int i = 0; i < n; i++)
        epp_rgp_tick_one(keys[i]);
}

static void *epp_rgp_tick_loop(void *arg) {
    (void) arg;
    for (;;) {
        long secs = EPPD_RGP_TICK_SECS();
        if (secs < 1)
            secs = 1;
        sleep((unsigned int) secs);
        epp_rgp_tick_scan();
    }
    return NULL;
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

    /* RFC 3915 RGP background sweep — autorenew, redemption purge, grace-
     * window expiry, transfer auto-approval (see epp_rgp_tick_loop). */
    pthread_t rt;
    if (pthread_create(&rt, NULL, epp_rgp_tick_loop, NULL) == 0)
        pthread_detach(rt);

    pthread_join(lt, NULL);
    return 0;
}
#endif /* UNIT_TEST */
