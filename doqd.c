/* doqd.c — DNS-over-QUIC (RFC 9250) sidecar.
 *
 * Terminates QUIC/UDP 853 and relays the framed DNS message to dnsd's
 * loopback DNS port (UDP, TCP retry when dnsd's reply is truncated) — the
 * exact pattern apid already uses for DoH (apid.c dns_forward/handle_doh).
 * doqd never parses the DNS payload itself; it only understands RFC 9250's
 * stream framing (a 2-octet length prefix, identical to DoT/TCP framing).
 *
 * Why a separate sidecar, not inside dnsd: dnsd is the trusted core holding
 * DNSSEC signing keys and the TSIG secret (CLAUDE.md "the authoritative
 * daemon ... stays small"). A QUIC/TLS state machine is a large untrusted-
 * input surface; a bug in it must not be a bug in the signer. doqd only
 * forwards opaque bytes over loopback, so it can at worst DoS the DoQ
 * transport, never forge an answer or touch a key.
 *
 * OpenSSL version: doqd needs OpenSSL >= 3.5 for the *server-side* QUIC API
 * (SSL_new_listener/SSL_accept_connection/SSL_accept_stream). This raises
 * the floor for *this one binary only* — dnsd/apid/certd/resolverd still
 * build against OpenSSL 3.0+. See the doqd-ossl-sanity Makefile check.
 *
 * Config (Valkey, read-only — doqd writes nothing):
 *   config:doq_enabled          "1" to start (default 0 — never on by accident)
 *   config:doq_port             UDP listen port (default 8853 in dev; 853 in prod)
 *   config:doq_dns_port         dnsd's loopback DNS port (default 5353 in dev)
 *   config:doq_max_conns        in-flight connection cap (default 1024)
 * TLS material: cert:current (written by certd), falling back to
 * config:tls_cert_pem/config:tls_key_pem — same contract as dnsd/apid.
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
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/quic.h>

#include "dns_wire.h"

#define MAX_PEM 65536
#define RESP_BUF 65536
#define DOQ_MAX_MSG 65535 /* a DNS message's own 16-bit length ceiling */

/* RFC 9250 §4.3 application error codes — named once, no bare literals at
 * the close-stream/close-connection call sites (CLAUDE.md code-style rule). */
#define DOQ_NO_ERROR 0x0
#define DOQ_INTERNAL_ERROR 0x1
#define DOQ_PROTOCOL_ERROR 0x2
#define DOQ_REQUEST_CANCELLED 0x3
#define DOQ_EXCESSIVE_LOAD 0x4
#define DOQ_ERROR_UNSPECIFIED 0x5

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

/* ── Config / state ──────────────────────────────────────────────────────── */
static char g_valkey_host[256] = "127.0.0.1";
static int g_valkey_port = 6379;
static char g_valkey_pass[256] = "";
static int g_doq_enabled = 0;
static int g_doq_port = 8853;
static int g_dns_port = 5353; /* dnsd's UDP/TCP port on loopback */
static int g_doq_max_conns = 1024;
static char g_tls_cert_pem[MAX_PEM] = "";
static char g_tls_key_pem[MAX_PEM] = "";
static SSL_CTX *g_doq_ctx = NULL;
static pthread_mutex_t g_tls_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_conn_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_conn_count = 0;

static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

/* ── Valkey RESP client (same minimal client as certd.c/mdnsd.c/apid.c) ──── */
typedef struct {
    int fd;
    char rbuf[RESP_BUF];
    int rlen, rpos;
} resp_conn_t;
static resp_conn_t vk = {.fd = -1};
static pthread_mutex_t g_vk_mutex = PTHREAD_MUTEX_INITIALIZER;

static int resp_fill(resp_conn_t *c) {
    if (c->rpos > 0 && c->rlen > c->rpos) {
        memmove(c->rbuf, c->rbuf + c->rpos, c->rlen - c->rpos);
        c->rlen -= c->rpos;
        c->rpos = 0;
    } else if (c->rpos >= c->rlen) {
        c->rlen = c->rpos = 0;
    }
    int room = RESP_BUF - c->rlen - 1;
    if (room <= 0)
        return -1;
    int n = (int) recv(c->fd, c->rbuf + c->rlen, room, 0);
    if (n <= 0)
        return -1;
    c->rlen += n;
    c->rbuf[c->rlen] = 0;
    return n;
}
static int resp_readline(resp_conn_t *c, char *out, int olen) {
    for (;;) {
        char *p = (char *) memchr(c->rbuf + c->rpos, '\n', c->rlen - c->rpos);
        if (p) {
            int len = (int) (p - (c->rbuf + c->rpos));
            if (len > 0 && *(p - 1) == '\r')
                len--;
            if (len >= olen)
                len = olen - 1;
            memcpy(out, c->rbuf + c->rpos, len);
            out[len] = 0;
            c->rpos = (int) (p - c->rbuf) + 1;
            return len;
        }
        if (resp_fill(c) < 0)
            return -1;
    }
}
static int resp_readbytes(resp_conn_t *c, char *out, int n) {
    int got = 0;
    while (got < n) {
        int have = c->rlen - c->rpos;
        if (have <= 0) {
            if (resp_fill(c) < 0)
                return -1;
            continue;
        }
        int take = (n - got < have) ? (n - got) : have;
        memcpy(out + got, c->rbuf + c->rpos, take);
        c->rpos += take;
        got += take;
    }
    while (c->rlen - c->rpos < 2) {
        if (resp_fill(c) < 0)
            return -1;
    }
    c->rpos += 2;
    out[n] = 0;
    return n;
}
typedef struct {
    int type;
    long integer;
    char str[MAX_PEM];
    int count;
} resp_reply_t;
static int resp_parse(resp_conn_t *c, resp_reply_t *r) {
    char line[512];
    if (resp_readline(c, line, sizeof(line)) < 0)
        return -1;
    memset(r, 0, sizeof(*r));
    switch (line[0]) {
        case '+':
            r->type = 0;
            safe_strcpy(r->str, line + 1, sizeof(r->str));
            return 0;
        case '-':
            r->type = 1;
            safe_strcpy(r->str, line + 1, sizeof(r->str));
            return 0;
        case ':':
            r->type = 3;
            r->integer = atol(line + 1);
            return 0;
        case '$': {
            int bl = atoi(line + 1);
            if (bl < 0) {
                r->type = 4;
                return 0;
            }
            r->type = 2;
            int take = bl < (int) sizeof(r->str) - 1 ? bl : (int) sizeof(r->str) - 1;
            if (resp_readbytes(c, r->str, take) < 0)
                return -1;
            int excess = bl - take;
            while (excess > 0) {
                char drain[257];
                int d = excess > (int) (sizeof(drain) - 1) ? (int) (sizeof(drain) - 1) : excess;
                if (resp_readbytes(c, drain, d) < 0)
                    return -1;
                excess -= d;
            }
            r->str[take] = 0;
            return 0;
        }
        case '*':
            r->type = 5;
            r->count = atoi(line + 1);
            return 0;
        default:
            return -1;
    }
}
static int resp_send(resp_conn_t *c, const char *cmd, int len) {
    int sent = 0;
    while (sent < len) {
        int n = (int) send(c->fd, cmd + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return 0;
}
static int resp_cmd(resp_conn_t *c, resp_reply_t *r, int argc, ...) {
    char buf[8192];
    int pos = snprintf(buf, sizeof(buf), "*%d\r\n", argc);
    va_list ap;
    va_start(ap, argc);
    for (int i = 0; i < argc; i++) {
        const char *a = va_arg(ap, const char *);
        int al = (int) strlen(a);
        if (pos < 0 || pos >= (int) sizeof(buf)) {
            va_end(ap);
            return -1;
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "$%d\r\n%s\r\n", al, a);
    }
    va_end(ap);
    if (pos < 0 || pos >= (int) sizeof(buf))
        return -1;
    if (resp_send(c, buf, pos) < 0)
        return -1;
    return resp_parse(c, r);
}
static int resp_send_cmd(resp_conn_t *c, int argc, ...) {
    char buf[8192];
    int pos = snprintf(buf, sizeof(buf), "*%d\r\n", argc);
    va_list ap;
    va_start(ap, argc);
    for (int i = 0; i < argc; i++) {
        const char *a = va_arg(ap, const char *);
        int al = (int) strlen(a);
        if (pos < 0 || pos >= (int) sizeof(buf)) {
            va_end(ap);
            return -1;
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "$%d\r\n%s\r\n", al, a);
    }
    va_end(ap);
    if (pos < 0 || pos >= (int) sizeof(buf))
        return -1;
    return resp_send(c, buf, pos);
}
static int valkey_connect(resp_conn_t *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->rlen = c->rpos = 0;
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0)
        return -1;
    struct timeval tv = {.tv_sec = 4};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(g_valkey_port)};
    if (inet_pton(AF_INET, g_valkey_host, &sa.sin_addr) != 1) {
        struct addrinfo hints = {0}, *res;
        char ps[8];
        snprintf(ps, sizeof(ps), "%d", g_valkey_port);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(g_valkey_host, ps, &hints, &res) != 0) {
            close(c->fd);
            c->fd = -1;
            return -1;
        }
        memcpy(&sa, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
    }
    if (connect(c->fd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        close(c->fd);
        c->fd = -1;
        return -1;
    }
    resp_reply_t r;
    if (g_valkey_pass[0]) {
        if (resp_cmd(c, &r, 2, "AUTH", g_valkey_pass) < 0 || r.type == 1) {
            close(c->fd);
            c->fd = -1;
            return -1;
        }
    }
    resp_cmd(c, &r, 2, "SELECT", "0");
    return 0;
}
static int valkey_ensure(resp_conn_t *c) {
    if (c->fd < 0)
        return valkey_connect(c);
    resp_reply_t r;
    if (resp_cmd(c, &r, 1, "PING") < 0)
        return valkey_connect(c);
    return 0;
}
static int vk_get(const char *key, char *out, int olen) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "GET", key) < 0) {
        vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (r.type != 2)
        return 0;
    safe_strcpy(out, r.str, olen);
    return 1;
}

/* ── DNS forwarding to dnsd over loopback (lifted from apid.c dns_forward,
 * same contract: UDP first, TCP retry on TC, never parses the payload) ──── */
static int dns_forward(const uint8_t *q, int qlen, uint8_t *resp, int rmax) {
    if (qlen < 12)
        return -1;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t) g_dns_port)};
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct timeval tv = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int rlen = -1;
    if (sendto(fd, q, (size_t) qlen, 0, (struct sockaddr *) &sa, sizeof(sa)) == qlen) {
        ssize_t n = recv(fd, resp, (size_t) rmax, 0);
        if (n >= 12)
            rlen = (int) n;
    }
    close(fd);
    if (rlen < 12)
        return -1;
    if (!(resp[2] & 0x02))
        return rlen; /* no TC — done */
    int tfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tfd < 0)
        return rlen;
    setsockopt(tfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(tfd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        close(tfd);
        return rlen;
    }
    uint8_t lp[2] = {(uint8_t) (qlen >> 8), (uint8_t) (qlen & 0xFF)};
    if (send(tfd, lp, 2, MSG_NOSIGNAL) != 2 || send(tfd, q, (size_t) qlen, MSG_NOSIGNAL) != qlen) {
        close(tfd);
        return rlen;
    }
    uint8_t lr[2];
    int got = 0;
    while (got < 2) {
        ssize_t n = recv(tfd, lr + got, (size_t) (2 - got), 0);
        if (n <= 0) {
            close(tfd);
            return rlen;
        }
        got += (int) n;
    }
    int tlen = (lr[0] << 8) | lr[1];
    if (tlen < 12 || tlen > rmax) {
        close(tfd);
        return rlen;
    }
    got = 0;
    while (got < tlen) {
        ssize_t n = recv(tfd, resp + got, (size_t) (tlen - got), 0);
        if (n <= 0) {
            close(tfd);
            return rlen;
        }
        got += (int) n;
    }
    close(tfd);
    return tlen;
}

/* ── RFC 9250 §4.2 stream framing — a pure function, fuzzed without a live
 * QUIC socket (make fuzz-doq). A DoQ stream carries exactly one 2-octet-
 * length-prefixed DNS message, then the client concludes its send side.
 * Fails closed on anything else: a length that disagrees with what's
 * actually on the stream (too little OR extra trailing bytes — RFC 9250
 * §4.2 forbids a second message on the same stream), or a length too short
 * to be a real DNS header. Never returns a partial message. */
static int doq_frame_next(const uint8_t *buf, int len, const uint8_t **msg, int *msglen) {
    if (len < 2)
        return -1;
    int declared = (buf[0] << 8) | buf[1];
    if (declared < 12)
        return -1;
    if (2 + declared != len)
        return -1;
    *msg = buf + 2;
    *msglen = declared;
    return 0;
}

/* ── TLS: QUIC-method SSL_CTX from cert:current ───────────────────────────
 * Deliberately NOT shared with libdnswire's tls_server_ctx_from_pem: that
 * function is TLS_server_method()-only and is linked by every daemon,
 * including ones that must keep building against OpenSSL 3.0+. Making it
 * QUIC-aware would need an unconditional `#include <openssl/quic.h>` in
 * dns_wire.c, which doesn't exist before OpenSSL 3.2 — that would silently
 * break the OpenSSL-3.0/3.1 build for dnsd/apid/certd/resolverd to serve
 * this one QUIC-only sidecar. The X.509/EVP_PKEY loading logic below is
 * otherwise identical; the QUIC method and ALPN token are the only real
 * difference, so a small doqd-local duplicate is the correct boundary, not
 * a shortcut. */
static int doq_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                              const unsigned char *in, unsigned int inlen, void *arg) {
    (void) ssl;
    (void) arg;
    static const unsigned char doq_proto[] = {3, 'd', 'o', 'q'};
    if (SSL_select_next_proto((unsigned char **) out, outlen, doq_proto, sizeof(doq_proto), in,
                              inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

/* Create the QUIC server SSL_CTX's *fixed* configuration — ALPN callback and
 * concurrency-model domain flags — once, ever, at startup. Deliberately
 * carries no certificate yet; see quic_ctx_load_cert() below for why. */
static SSL_CTX *quic_ctx_new_base(void) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx)
        return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_alpn_select_cb(ctx, doq_alpn_select_cb, NULL);
    /* Contentive Concurrency Model + explicit reliable blocking I/O: every
     * worker thread here spends its idle time blocked in
     * SSL_accept_stream/SSL_read_ex, so a QUIC domain that allows different
     * stream/connection SSL objects to be safely used concurrently from
     * different threads is required (openssl-quic-concurrency(7)) — the
     * legacy default (no explicit domain flags) is documented as unreliable
     * for multi-threaded use. NOTE: SSL_DOMAIN_FLAG_THREAD_ASSISTED (which
     * implies MULTI_THREAD+BLOCKING and additionally runs a background
     * assist thread for QUIC timer events) was tried first per the man
     * page's own recommendation, but empirically made SSL_accept_connection
     * return NULL immediately instead of blocking, on this OpenSSL 3.5.7
     * build — verified via a minimal standalone repro before landing this.
     * The explicit MULTI_THREAD|BLOCKING combination (without the assist
     * thread) blocks correctly; our worker-per-connection architecture is
     * always blocked in a QUIC call when idle, so we don't need an assist
     * thread to service timers between calls the way a callback-driven
     * application would. */
    if (SSL_CTX_set_domain_flags(ctx, SSL_DOMAIN_FLAG_MULTI_THREAD | SSL_DOMAIN_FLAG_BLOCKING) !=
        1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* Load (or reload) certificate + key material onto an *existing* SSL_CTX.
 * Deliberately mutates ctx in place rather than building a fresh SSL_CTX and
 * swapping a global pointer, the way dnsd's/apid's TLS reload does: the QUIC
 * listener (SSL_new_listener) takes its own long-lived reference to the ctx
 * at creation time and is never recreated, so swapping which SSL_CTX* a
 * global variable happens to point to would not reach it — the already-
 * running listener would keep serving the stale certificate forever. In
 * place mutation of the one ctx the listener actually holds is how a cert
 * rotation reaches it. Returns 1 on success, 0 on any load/parse failure
 * (caller must treat that as "keep the previous certificate", not a crash —
 * an update that fails to parse must never take a working listener down). */
static int quic_ctx_load_cert(SSL_CTX *ctx, const char *cert_pem, const char *key_pem) {
    if (!cert_pem || !cert_pem[0] || !key_pem || !key_pem[0])
        return 0;
    BIO *bc = BIO_new_mem_buf(cert_pem, -1);
    X509 *cert = PEM_read_bio_X509_AUX(bc, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bc);
        return 0;
    }
    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        X509_free(cert);
        BIO_free(bc);
        return 0;
    }
    X509_free(cert);
    X509 *chain_ca;
    while ((chain_ca = PEM_read_bio_X509(bc, NULL, NULL, NULL)) != NULL)
        SSL_CTX_add_extra_chain_cert(ctx, chain_ca);
    BIO_free(bc);
    BIO *bk = BIO_new_mem_buf(key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL);
    BIO_free(bk);
    if (!pkey)
        return 0;
    int ok = SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
    EVP_PKEY_free(pkey);
    if (!ok || !SSL_CTX_check_private_key(ctx))
        return 0;
    return 1;
}

/* Load TLS material: cert:current preferred, config:tls_*_pem fallback —
 * same contract dnsd/apid use. */
static int tls_material_load(void) {
    char blob[MAX_PEM];
    if (vk_get("cert:current", blob, sizeof(blob)) && blob[0] &&
        cert_current_split(blob, g_tls_cert_pem, sizeof(g_tls_cert_pem), g_tls_key_pem,
                           sizeof(g_tls_key_pem)) == 0)
        return 1;
    char cert[MAX_PEM] = "", key[MAX_PEM] = "";
    int have_cert = vk_get("config:tls_cert_pem", cert, sizeof(cert)) && cert[0];
    int have_key = vk_get("config:tls_key_pem", key, sizeof(key)) && key[0];
    if (have_cert && have_key) {
        safe_strcpy(g_tls_cert_pem, cert, sizeof(g_tls_cert_pem));
        safe_strcpy(g_tls_key_pem, key, sizeof(g_tls_key_pem));
        return 1;
    }
    return 0;
}

/* Reload the certificate on the one persistent QUIC SSL_CTX (creating it
 * first, on the very first call). Safe to call from the keyspace-watch
 * thread at any time after startup — see quic_ctx_load_cert's contract. */
static void tls_reload(void) {
    if (!tls_material_load()) {
        dns_log(LOG_WARNING, "[TLS] cert:current / config:tls_*_pem unavailable — DoQ listener "
                             "stays down until a cert is published\n");
        return;
    }
    pthread_mutex_lock(&g_tls_mutex);
    if (!g_doq_ctx)
        g_doq_ctx = quic_ctx_new_base();
    int ok = g_doq_ctx && quic_ctx_load_cert(g_doq_ctx, g_tls_cert_pem, g_tls_key_pem);
    pthread_mutex_unlock(&g_tls_mutex);
    if (!ok) {
        dns_log(LOG_ERR, "[TLS] QUIC context cert load failed — keeping the previous "
                         "certificate (if any)\n");
        return;
    }
    dns_log(LOG_INFO, "[TLS] QUIC context cert (re)loaded\n");
}

/* Re-read the non-cert config:doq_* knobs that are safe to change without a
 * restart (no socket rebind involved): the connection cap and dnsd's
 * loopback forwarding port. config:doq_port is deliberately NOT reloaded
 * here — changing it would require rebinding the UDP listener socket, which
 * this simple accept-loop architecture does not support live. */
static void doq_config_reload(resp_conn_t *c) {
    resp_reply_t r;
    if (resp_cmd(c, &r, 2, "GET", "config:doq_max_conns") == 0 && r.type == 2 && r.str[0]) {
        int n = atoi(r.str);
        if (n > 0)
            g_doq_max_conns = n;
    }
    if (resp_cmd(c, &r, 2, "GET", "config:doq_dns_port") == 0 && r.type == 2 && r.str[0]) {
        int n = atoi(r.str);
        if (n > 0)
            g_dns_port = n;
    }
}

/* Live reload via Valkey keyspace notifications (migration Step 6), mirroring
 * apid's keyspace_watch_thread: a dedicated subscriber connection (separate
 * from the request/reply `vk`), capped-backoff reconnect, full catch-up
 * re-run after every reconnect so a Valkey restart never causes a missed
 * update. doqd only ever reads; it writes nothing to Valkey. */
#define KEYSPACE_DB 0
static void *keyspace_watch_thread(void *arg) {
    (void) arg;
    static resp_conn_t sub;
    int backoff = 1;
    for (;;) {
        memset(&sub, 0, sizeof(sub));
        sub.fd = -1;
        if (valkey_connect(&sub) < 0) {
            sleep(backoff);
            if (backoff < 30)
                backoff *= 2;
            continue;
        }
        struct timeval no_to = {0}; /* block for events; drop the 4s read timeout */
        setsockopt(sub.fd, SOL_SOCKET, SO_RCVTIMEO, &no_to, sizeof(no_to));
        resp_reply_t r;
        if (resp_cmd(&sub, &r, 4, "CONFIG", "SET", "notify-keyspace-events", "KEA") < 0 ||
            r.type == 1)
            dns_log(LOG_WARNING, "[Reload] could not enable keyspace notifications — "
                                 "boot/reconnect catch-up only\n");
        tls_reload();
        doq_config_reload(&sub);
        static const char *prefixes[] = {"cert:current", "config:tls_cert_pem",
                                         "config:tls_key_pem", "config:doq_max_conns",
                                         "config:doq_dns_port", NULL};
        int subok = 1;
        for (int i = 0; prefixes[i]; i++) {
            char pat[160];
            snprintf(pat, sizeof(pat), "__keyspace@%d__:%s", KEYSPACE_DB, prefixes[i]);
            if (resp_send_cmd(&sub, 2, "PSUBSCRIBE", pat) < 0) {
                subok = 0;
                break;
            }
        }
        if (!subok) {
            close(sub.fd);
            sub.fd = -1;
            sleep(backoff);
            if (backoff < 30)
                backoff *= 2;
            continue;
        }
        backoff = 1;
        dns_log(LOG_NOTICE, "[Reload] live reload active (keyspace notifications)\n");
        for (;;) {
            resp_reply_t hdr;
            if (resp_parse(&sub, &hdr) < 0)
                break;
            if (hdr.type != 5 || hdr.count < 1)
                continue;
            char kind[16] = "";
            char channel[160] = "";
            int rderr = 0;
            for (int i = 0; i < hdr.count; i++) {
                resp_reply_t el;
                if (resp_parse(&sub, &el) < 0) {
                    rderr = 1;
                    break;
                }
                if (i == 0)
                    safe_strcpy(kind, el.str, sizeof(kind));
                else if (i == 1)
                    safe_strcpy(channel, el.str, sizeof(channel));
            }
            if (rderr)
                break;
            if (strcmp(kind, "pmessage") != 0)
                continue;
            if (strstr(channel, "cert:current") || strstr(channel, "config:tls_"))
                tls_reload();
            else if (strstr(channel, "config:doq_max_conns") || strstr(channel, "config:doq_dns_port"))
                doq_config_reload(&sub);
        }
        dns_log(LOG_WARNING, "[Reload] keyspace connection lost — reconnecting\n");
        close(sub.fd);
        sub.fd = -1;
        sleep(backoff);
        if (backoff < 30)
            backoff *= 2;
    }
    return NULL;
}

/* ── Per-stream / per-connection handling ─────────────────────────────────
 * One DNS exchange per client-initiated bidirectional QUIC stream (RFC 9250
 * §4.2): read to the client's FIN, validate framing (doq_frame_next), fail
 * closed on anything malformed (reset the stream, never forward a partial/
 * extra message), otherwise forward to dnsd and relay the answer back. */
static void doq_handle_stream(SSL *stream) {
    int stype = SSL_get_stream_type(stream);
    if (stype != SSL_STREAM_TYPE_BIDI) {
        /* RFC 9250 §4.2: unidirectional streams are reserved. A peer that
         * sends DNS on one gets the whole connection closed, not just the
         * stream — treat it as a protocol violation, not a one-off. */
        SSL *conn = SSL_get0_connection(stream);
        SSL_SHUTDOWN_EX_ARGS args = {.quic_error_code = DOQ_PROTOCOL_ERROR,
                                     .quic_reason = "unidirectional stream not permitted"};
        if (conn)
            SSL_shutdown_ex(conn, SSL_SHUTDOWN_FLAG_RAPID, &args, sizeof(args));
        SSL_free(stream);
        return;
    }

    static const int max_buf = 2 + DOQ_MAX_MSG;
    uint8_t *buf = malloc((size_t) max_buf);
    if (!buf) {
        SSL_STREAM_RESET_ARGS rargs = {.quic_error_code = DOQ_INTERNAL_ERROR};
        SSL_stream_reset(stream, &rargs, sizeof(rargs));
        SSL_free(stream);
        return;
    }
    int total = 0;
    int proto_err = 0;
    for (;;) {
        size_t got = 0;
        int r = SSL_read_ex(stream, buf + total, (size_t) (max_buf - total), &got);
        if (r <= 0) {
            int err = SSL_get_error(stream, r);
            if (err != SSL_ERROR_ZERO_RETURN)
                proto_err = 1; /* anything but a clean FIN is fail-closed */
            break;
        }
        total += (int) got;
        if (total >= max_buf) {
            proto_err = 1; /* oversized — bigger than any real DNS message */
            break;
        }
    }

    const uint8_t *msg = NULL;
    int msglen = 0;
    if (!proto_err && doq_frame_next(buf, total, &msg, &msglen) < 0)
        proto_err = 1;

    if (proto_err) {
        SSL_STREAM_RESET_ARGS rargs = {.quic_error_code = DOQ_PROTOCOL_ERROR};
        SSL_stream_reset(stream, &rargs, sizeof(rargs));
        free(buf);
        SSL_free(stream);
        return;
    }

    uint8_t resp[DOQ_MAX_MSG];
    int rlen = dns_forward(msg, msglen, resp, (int) sizeof(resp));
    free(buf);
    if (rlen < 0) {
        SSL_STREAM_RESET_ARGS rargs = {.quic_error_code = DOQ_INTERNAL_ERROR};
        SSL_stream_reset(stream, &rargs, sizeof(rargs));
        SSL_free(stream);
        return;
    }

    uint8_t lp[2] = {(uint8_t) (rlen >> 8), (uint8_t) (rlen & 0xFF)};
    size_t wrote = 0;
    if (SSL_write_ex(stream, lp, 2, &wrote) == 1 && wrote == 2) {
        SSL_write_ex(stream, resp, (size_t) rlen, &wrote);
    }
    SSL_stream_conclude(stream, 0); /* FIN our send side */
    SSL_free(stream);
}

/* One detached thread per accepted connection (same model as dnsd's
 * dot_thread). Streams within a connection are handled sequentially —
 * simple and correct for an authoritative server; fanning out per-stream is
 * a later optimisation, not a correctness requirement (RFC 9250 doesn't
 * order streams, and OpenSSL's CCM/TACM concurrency model would allow it
 * without any protocol-level change). */
static void *doq_conn_thread(void *arg) {
    SSL *conn = arg;
    SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
    for (;;) {
        SSL *stream = SSL_accept_stream(conn, 0);
        if (!stream)
            break; /* connection closed/terminated */
        doq_handle_stream(stream);
    }
    SSL_free(conn);
    pthread_mutex_lock(&g_conn_count_mutex);
    g_conn_count--;
    pthread_mutex_unlock(&g_conn_count_mutex);
    return NULL;
}

static void *doq_listen_thread(void *arg) {
    (void) arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        dns_log(LOG_ERR, "[DoQ] socket failed: %s\n", strerror(errno));
        return NULL;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons((uint16_t) g_doq_port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        dns_log(LOG_ERR, "[DoQ] bind :%d/udp failed: %s\n", g_doq_port, strerror(errno));
        close(fd);
        return NULL;
    }

    pthread_mutex_lock(&g_tls_mutex);
    SSL_CTX *ctx = g_doq_ctx;
    if (ctx)
        SSL_CTX_up_ref(ctx);
    pthread_mutex_unlock(&g_tls_mutex);
    if (!ctx) {
        dns_log(LOG_ERR, "[DoQ] no TLS context yet — listener not started (waiting for a cert)\n");
        close(fd);
        return NULL;
    }
    SSL *listener = SSL_new_listener(ctx, 0);
    SSL_CTX_free(ctx); /* listener holds its own ref now */
    if (!listener) {
        dns_log(LOG_ERR, "[DoQ] SSL_new_listener failed\n");
        close(fd);
        return NULL;
    }
    if (!SSL_set_fd(listener, fd) || !SSL_listen(listener)) {
        dns_log(LOG_ERR, "[DoQ] listener setup failed\n");
        SSL_free(listener);
        close(fd);
        return NULL;
    }
    dns_log(LOG_NOTICE, "[DoQ] listening on :%d/udp (ALPN doq)\n", g_doq_port);

    for (;;) {
        ERR_clear_error();
        SSL *conn = SSL_accept_connection(listener, 0);
        if (!conn) {
            /* Expected occasionally (e.g. a QUIC Initial that never
             * completes address validation) and should be rare given this
             * listener is configured for reliable blocking accept — but a
             * brief pause here is deliberate insurance against a busy-loop
             * if some future OpenSSL/config combination ever makes
             * SSL_accept_connection return NULL immediately instead of
             * blocking (this exact failure mode was hit and root-caused
             * once already during development — see the domain-flags
             * comment on quic_server_ctx_from_pem). */
            dns_log(LOG_WARNING, "[DoQ] SSL_accept_connection failed; continuing\n");
            usleep(50000);
            continue;
        }
        pthread_mutex_lock(&g_conn_count_mutex);
        int over = g_conn_count >= g_doq_max_conns;
        if (!over)
            g_conn_count++;
        pthread_mutex_unlock(&g_conn_count_mutex);
        if (over) {
            SSL_SHUTDOWN_EX_ARGS args = {.quic_error_code = DOQ_EXCESSIVE_LOAD,
                                         .quic_reason = "connection cap reached"};
            SSL_shutdown_ex(conn, SSL_SHUTDOWN_FLAG_RAPID, &args, sizeof(args));
            SSL_free(conn);
            continue;
        }
        pthread_t tid;
        if (pthread_create(&tid, NULL, doq_conn_thread, conn) == 0) {
            pthread_detach(tid);
        } else {
            dns_log(LOG_ERR, "[DoQ] failed to start connection worker\n");
            SSL_free(conn);
            pthread_mutex_lock(&g_conn_count_mutex);
            g_conn_count--;
            pthread_mutex_unlock(&g_conn_count_mutex);
        }
    }
    return NULL;
}

/* ── Config + main ──────────────────────────────────────────────────────── */
static int load_config(void) {
    safe_strcpy(g_valkey_host, cfgenv("DNS_VALKEY_HOST", "127.0.0.1"), sizeof(g_valkey_host));
    g_valkey_port = atoi(cfgenv("DNS_VALKEY_PORT", "6379"));
    safe_strcpy(g_valkey_pass, cfgenv("DNS_VALKEY_PASSWORD", ""), sizeof(g_valkey_pass));
    char val[512];
    if (!vk_get("config:doq_enabled", val, sizeof(val)) || atoi(val) != 1) {
        dns_log(LOG_NOTICE, "[DoQ] config:doq_enabled is not 1 — nothing to do\n");
        return -1;
    }
    g_doq_enabled = 1;
    if (vk_get("config:doq_port", val, sizeof(val)) && val[0])
        g_doq_port = atoi(val);
    if (vk_get("config:doq_dns_port", val, sizeof(val)) && val[0])
        g_dns_port = atoi(val);
    if (vk_get("config:doq_max_conns", val, sizeof(val)) && val[0])
        g_doq_max_conns = atoi(val);
    if (g_doq_max_conns <= 0)
        g_doq_max_conns = 1024;
    return 0;
}

static int schema_gate(void) {
    char sv[32] = "";
    vk_get("schema:version", sv, sizeof(sv));
    switch (schema_version_check(sv)) {
        case SCHEMA_OK:
        case SCHEMA_MINOR_DIFF:
        case SCHEMA_ABSENT:
            return 0;
        default:
            dns_log(LOG_ERR, "[Schema] schema:version %s incompatible with compiled %s — "
                             "refusing to start\n",
                    sv[0] ? sv : "(unparseable)", SCHEMA_VERSION_STR);
            return -1;
    }
}

#ifndef UNIT_TEST
int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    if (load_config() < 0)
        return 1;
    if (schema_gate() != 0)
        return 1;
    tls_reload();
    if (!g_doq_ctx) {
        dns_log(LOG_ERR, "[DoQ] no usable TLS material at startup — exiting\n");
        return 1;
    }
    dns_log(LOG_NOTICE, "[doqd] Starting: DoQ :%d/udp, dnsd at 127.0.0.1:%d\n", g_doq_port,
            g_dns_port);
    pthread_t kt, lt;
    if (pthread_create(&kt, NULL, keyspace_watch_thread, NULL) == 0)
        pthread_detach(kt);
    if (pthread_create(&lt, NULL, doq_listen_thread, NULL) != 0) {
        dns_log(LOG_ERR, "[DoQ] failed to start listener thread\n");
        return 1;
    }
    pthread_join(lt, NULL);
    return 0;
}
#endif /* UNIT_TEST */
