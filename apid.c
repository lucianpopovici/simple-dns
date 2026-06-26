/* apid.c — HTTP/HTTPS front for DoH and management (migration Step 4).
 *
 * The in-house alternative to a reverse proxy (decision recorded in
 * CLAUDE-migration.md Step 4): one small daemon owns every HTTP surface that
 * used to be embedded in dns_server.c, so the authoritative core never parses
 * HTTP or terminates web TLS again.
 *
 *   - DoH (RFC 8484): GET/POST /dns-query. The DNS message is forwarded to
 *     dnsd over loopback UDP (TCP retry when the reply is truncated) — apid
 *     never interprets DNS payloads.
 *   - Management API (same endpoints the monolith served): list, update,
 *     delete, zone, config, zone/list, zone/add, zone/del. Every write
 *     goes to Valkey only — apid calls nothing inside dnsd. dnsd applies the
 *     in-memory state it derives from those keys (SOA serial, zone table,
 *     TLS PEMs) live via Valkey keyspace notifications (migration Step 6);
 *     zone records themselves are read live per query already.
 *   - /health (apid itself) and /metrics (proxied from dnsd's localhost-only
 *     read-only endpoint).
 *
 * Listeners (same ports the monolith used):
 *   config:http_port   (8053) plain HTTP  — is_mgmt=0: DoH, health, metrics,
 *                      list, DDNS update/delete gated by config:ddns_secret
 *   config:https_port  (8443) HTTPS       — is_mgmt=1 when mTLS verifies the
 *                      client against config:mtls_ca_pem (required for
 *                      config and zone-table management, exactly as before)
 *
 * TLS material: cert:current (written by certd), falling back to
 * config:tls_cert_pem / config:tls_key_pem; hot-reloaded live via Valkey
 * keyspace notifications (migration Step 6). Env: DNS_VALKEY_HOST/PORT/PASSWORD.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
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

#include "dns_wire.h"

#define HTTP_BUF 16384
#define RESP_BUF 65536
#define MAX_PEM 65536
#define DNS_BUF 65535
#define DEFAULT_TTL 60
#define MAX_ZONES_LIST 64 /* cap on zones scanned for longest-suffix resolution */

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
static int g_http_port = 8053;
static int g_https_port = 8443;
static int g_dns_port = 5353; /* dnsd's UDP/TCP port on loopback */
static char g_tls_cert_pem[MAX_PEM] = "";
static char g_tls_key_pem[MAX_PEM] = "";
static char g_mtls_ca_pem[MAX_PEM] = "";
static SSL_CTX *g_https_ctx = NULL;
static pthread_mutex_t g_tls_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

/* ── Valkey RESP client (same minimal client as certd.c / mdnsd.c) ───────── */
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
/* Send a command without reading a reply — for (P)SUBSCRIBE, whose replies and
 * subsequent messages are consumed by the subscriber read loop. */
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
static int vk_set(const char *key, const char *val, uint32_t ttl) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    int ok;
    if (ttl > 0) {
        char ts[32];
        snprintf(ts, sizeof(ts), "%u", ttl);
        ok = resp_cmd(&vk, &r, 5, "SET", key, val, "EX", ts);
    } else
        ok = resp_cmd(&vk, &r, 3, "SET", key, val);
    if (ok < 0) {
        vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return r.type == 0;
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
static int vk_del(const char *key) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "DEL", key) < 0) {
        vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return r.type == 3 ? (int) r.integer : 0;
}
static long vk_incr(const char *key) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "INCR", key) < 0) {
        vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return r.type == 3 ? r.integer : -1;
}

/* Resolve the most-specific configured zone (zone_table:<z>) that `name`
 * belongs to.  Falls back to config:zone_name.  This is how the management API
 * decides which zone's namespace (zone:<z>:* / ddns:<z>:*) a record is written
 * to, mirroring dnsd's longest-suffix zone selection. */
static void resolve_zone(const char *name, char *out, int outsz) {
    out[0] = 0;
    size_t best = 0, nl = strlen(name);
    char zns[MAX_ZONES_LIST][256];
    int nz = 0;
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) >= 0) {
        resp_reply_t r;
        resp_cmd(&vk, &r, 2, "KEYS", "zone_table:*");
        if (r.type == 5) {
            int cnt = r.count;
            for (int i = 0; i < cnt; i++) {
                resp_reply_t kr;
                if (resp_parse(&vk, &kr) < 0)
                    break;
                if (kr.type == 2 && nz < MAX_ZONES_LIST) {
                    safe_strcpy(zns[nz], kr.str + 11, sizeof(zns[nz])); /* skip "zone_table:" */
                    nz++;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    for (int i = 0; i < nz; i++) {
        const char *z = zns[i];
        size_t zl = strlen(z);
        if (zl == 0 || zl > nl)
            continue;
        int m = (zl == nl && strcasecmp(name, z) == 0) ||
                (nl > zl + 1 && name[nl - zl - 1] == '.' && strcasecmp(name + nl - zl, z) == 0);
        if (m && zl > best) {
            best = zl;
            safe_strcpy(out, z, outsz);
        }
    }
    if (!out[0])
        vk_get("config:zone_name", out, outsz);
}

/* SOA serial bump for a zone.  The primary zone (config:zone_name) keeps the
 * legacy config:zone_serial counter; other zones use config:zone:<z>:serial.
 * dnsd picks up the new serial live via keyspace notifications (Step 6). */
static void serial_bump_zone(const char *zn) {
    char primary[256] = "";
    vk_get("config:zone_name", primary, sizeof(primary));
    char ikey[320];
    if (!zn || !zn[0] || strcasecmp(zn, primary) == 0)
        safe_strcpy(ikey, "config:zone_serial", sizeof(ikey));
    else
        snprintf(ikey, sizeof(ikey), "config:zone:%s:serial", zn);
    if (vk_incr(ikey) < 0)
        dns_log(LOG_WARNING, "[apid] serial bump failed (Valkey down?)\n");
}

/* ── Record-type names (the types the management API provisions) ─────────── */
static const char *type2str(uint16_t t) {
    switch (t) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 5:
            return "CNAME";
        case 12:
            return "PTR";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 28:
            return "AAAA";
        case 29:
            return "LOC";
        case 33:
            return "SRV";
        case 39:
            return "DNAME";
        case 44:
            return "SSHFP";
        case 52:
            return "TLSA";
        case 257:
            return "CAA";
        default:
            return "?";
    }
}
static uint16_t str2type(const char *s) {
    if (!strcasecmp(s, "A"))
        return 1;
    if (!strcasecmp(s, "NS"))
        return 2;
    if (!strcasecmp(s, "CNAME"))
        return 5;
    if (!strcasecmp(s, "PTR"))
        return 12;
    if (!strcasecmp(s, "MX"))
        return 15;
    if (!strcasecmp(s, "TXT"))
        return 16;
    if (!strcasecmp(s, "AAAA"))
        return 28;
    if (!strcasecmp(s, "LOC"))
        return 29;
    if (!strcasecmp(s, "SRV"))
        return 33;
    if (!strcasecmp(s, "DNAME"))
        return 39;
    if (!strcasecmp(s, "SSHFP"))
        return 44;
    if (!strcasecmp(s, "TLSA"))
        return 52;
    if (!strcasecmp(s, "CAA"))
        return 257;
    return 0;
}

/* ── TLS context (server side; mTLS when CA provided) ────────────────────── */
static SSL_CTX *tls_ctx_from_pem(const char *cert_pem, const char *key_pem, const char *ca_pem,
                                 int verify_client) {
    if (!cert_pem || !cert_pem[0] || !key_pem || !key_pem[0]) {
        dns_log(LOG_ERR, "[TLS] No cert/key PEM\n");
        return NULL;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    BIO *bc = BIO_new_mem_buf(cert_pem, -1);
    X509 *cert = PEM_read_bio_X509_AUX(bc, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bc);
        SSL_CTX_free(ctx);
        dns_log(LOG_ERR, "[TLS] Bad cert PEM\n");
        return NULL;
    }
    SSL_CTX_use_certificate(ctx, cert);
    X509_free(cert);
    X509 *ca;
    while ((ca = PEM_read_bio_X509(bc, NULL, NULL, NULL)) != NULL)
        SSL_CTX_add_extra_chain_cert(ctx, ca);
    BIO_free(bc);
    BIO *bk = BIO_new_mem_buf(key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL);
    BIO_free(bk);
    if (!pkey) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (verify_client && ca_pem && ca_pem[0]) {
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        BIO *bca = BIO_new_mem_buf(ca_pem, -1);
        X509 *cax;
        while ((cax = PEM_read_bio_X509(bca, NULL, NULL, NULL)) != NULL) {
            X509_STORE_add_cert(store, cax);
            X509_free(cax);
        }
        BIO_free(bca);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    return ctx;
}

/* Split cert:current into chain + key (same contract as dnsd/certd). */
static int cert_current_split(const char *blob, char *cert_out, size_t cert_sz, char *key_out,
                              size_t key_sz) {
    static const char *kbegin_pat[] = {"-----BEGIN PRIVATE KEY-----",
                                       "-----BEGIN EC PRIVATE KEY-----",
                                       "-----BEGIN RSA PRIVATE KEY-----", NULL};
    const char *kb = NULL;
    for (int ki = 0; kbegin_pat[ki]; ki++) {
        kb = strstr(blob, kbegin_pat[ki]);
        if (kb)
            break;
    }
    if (!kb)
        return -1;
    const char *ke = strstr(kb, "-----END ");
    if (!ke)
        return -1;
    ke = strchr(ke, '\n');
    if (!ke)
        ke = kb + strlen(kb);
    else
        ke++;
    size_t klen = (size_t) (ke - kb);
    if (klen + 1 > key_sz)
        return -1;
    memcpy(key_out, kb, klen);
    key_out[klen] = 0;
    size_t pre = (size_t) (kb - blob), post = strlen(ke);
    if (pre + post + 1 > cert_sz)
        return -1;
    memcpy(cert_out, blob, pre);
    memcpy(cert_out + pre, ke, post);
    cert_out[pre + post] = 0;
    if (!strstr(cert_out, "-----BEGIN CERTIFICATE-----"))
        return -1;
    return 0;
}

static void tls_reload(void) {
    pthread_mutex_lock(&g_tls_mutex);
    if (g_https_ctx) {
        SSL_CTX_free(g_https_ctx);
        g_https_ctx = NULL;
    }
    g_https_ctx =
        tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, g_mtls_ca_pem, g_mtls_ca_pem[0] ? 1 : 0);
    if (g_https_ctx) {
        static const uint8_t h2_alpn[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        SSL_CTX_set_alpn_protos(g_https_ctx, h2_alpn, sizeof(h2_alpn));
    }
    pthread_mutex_unlock(&g_tls_mutex);
    dns_log(LOG_INFO, "[TLS] HTTPS context %s (mTLS %s)\n",
            g_https_ctx ? "loaded" : "unavailable (no cert yet)", g_mtls_ca_pem[0] ? "on" : "off");
}

/* Load TLS material: cert:current preferred, config:tls_*_pem fallback. */
static int tls_material_load(void) {
    static char blob[MAX_PEM], cert[MAX_PEM], key[MAX_PEM];
    blob[0] = 0;
    if (vk_get("cert:current", blob, sizeof(blob)) && blob[0] &&
        cert_current_split(blob, cert, sizeof(cert), key, sizeof(key)) == 0) {
        if (strcmp(cert, g_tls_cert_pem) || strcmp(key, g_tls_key_pem)) {
            safe_strcpy(g_tls_cert_pem, cert, sizeof(g_tls_cert_pem));
            safe_strcpy(g_tls_key_pem, key, sizeof(g_tls_key_pem));
            return 1;
        }
        return 0;
    }
    char c2[MAX_PEM] = "", k2[MAX_PEM] = "";
    vk_get("config:tls_cert_pem", c2, sizeof(c2));
    vk_get("config:tls_key_pem", k2, sizeof(k2));
    if (c2[0] && k2[0] && (strcmp(c2, g_tls_cert_pem) || strcmp(k2, g_tls_key_pem))) {
        safe_strcpy(g_tls_cert_pem, c2, sizeof(g_tls_cert_pem));
        safe_strcpy(g_tls_key_pem, k2, sizeof(g_tls_key_pem));
        return 1;
    }
    return 0;
}

/* Reload the HTTPS cert/key (cert:current or config:tls_*) and the mTLS CA,
 * rebuilding the TLS context if anything changed. Used for the boot/reconnect
 * catch-up and on a keyspace notification. */
static void tls_material_reload(void) {
    char ca2[MAX_PEM] = "";
    vk_get("config:mtls_ca_pem", ca2, sizeof(ca2));
    int changed = tls_material_load();
    if (strcmp(ca2, g_mtls_ca_pem)) {
        safe_strcpy(g_mtls_ca_pem, ca2, sizeof(g_mtls_ca_pem));
        changed = 1;
    }
    if (changed) {
        dns_log(LOG_NOTICE, "[TLS] Certificate material changed — reloading\n");
        tls_reload();
    }
}

/* Live reload via Valkey keyspace notifications (migration Step 6). apid owns
 * the HTTPS TLS material, so it watches cert:current plus the config tls_cert_pem,
 * tls_key_pem and mtls_ca_pem keys and hot-reloads — replacing the old 30s poll.
 * A dedicated subscriber connection (separate from the request/reply `vk`);
 * reconnects use capped backoff and re-run the catch-up so nothing is missed. */
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
        tls_material_reload(); /* catch up via the shared vk connection */
        static const char *prefixes[] = {"cert:current", "config:tls_cert_pem",
                                         "config:tls_key_pem", "config:mtls_ca_pem", NULL};
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
        dns_log(LOG_NOTICE, "[Reload] live TLS reload active (keyspace notifications)\n");
        for (;;) {
            resp_reply_t hdr;
            if (resp_parse(&sub, &hdr) < 0)
                break;
            if (hdr.type != 5 || hdr.count < 1)
                continue;
            char kind[16] = "";
            int rderr = 0;
            for (int i = 0; i < hdr.count; i++) {
                resp_reply_t el;
                if (resp_parse(&sub, &el) < 0) {
                    rderr = 1;
                    break;
                }
                if (i == 0)
                    safe_strcpy(kind, el.str, sizeof(kind));
            }
            if (rderr)
                break;
            if (strcmp(kind, "pmessage") == 0)
                tls_material_reload();
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

/* ── HTTP plumbing ───────────────────────────────────────────────────────── */
static void url_decode(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && isxdigit((unsigned char) r[1]) && isxdigit((unsigned char) r[2])) {
            char h[3] = {r[1], r[2], 0};
            *w++ = (char) strtol(h, NULL, 16);
            r += 3;
        } else if (*r == '+') {
            *w++ = ' ';
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = 0;
}
static int qs_get(const char *qs, const char *key, char *out, int olen) {
    char nd[128];
    snprintf(nd, sizeof(nd), "%s=", key);
    const char *p = strstr(qs, nd);
    if (!p)
        return 0;
    p += strlen(nd);
    int i = 0;
    while (p[i] && p[i] != '&' && i < olen - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = 0;
    url_decode(out);
    return 1;
}
static void api_send(int fd, SSL *ssl, int code, const char *body) {
    char resp[HTTP_BUF];
    const char *st = code == 200   ? "OK"
                     : code == 201 ? "Created"
                     : code == 400 ? "Bad Request"
                     : code == 403 ? "Forbidden"
                     : code == 404 ? "Not Found"
                     : code == 204 ? "No Content"
                     : code == 502 ? "Bad Gateway"
                     : code == 507 ? "Insufficient Storage"
                                   : "Internal Server Error";
    int n = snprintf(
        resp, sizeof(resp),
        "HTTP/1.0 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
        code, st, strlen(body), body);
    if (n > 0) {
        if (ssl)
            SSL_write(ssl, resp, n);
        else {
            ssize_t w = write(fd, resp, n);
            (void) w;
        }
    }
}

/* ── DNS forwarding to dnsd over loopback ────────────────────────────────── */
/* UDP first; if the response has TC set, retry over TCP (RFC 7766 framing).
 * Returns response length or -1. */
static int dns_forward(const uint8_t *q, int qlen, uint8_t *resp, int rmax) {
    if (qlen < 12)
        return -1;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(g_dns_port)};
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct timeval tv = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int rlen = -1;
    if (sendto(fd, q, qlen, 0, (struct sockaddr *) &sa, sizeof(sa)) == qlen) {
        ssize_t n = recv(fd, resp, rmax, 0);
        if (n >= 12)
            rlen = (int) n;
    }
    close(fd);
    if (rlen < 12)
        return -1;
    if (!(resp[2] & 0x02))
        return rlen; /* no TC — done */
    /* Truncated: retry over TCP */
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
    if (send(tfd, lp, 2, MSG_NOSIGNAL) != 2 || send(tfd, q, qlen, MSG_NOSIGNAL) != qlen) {
        close(tfd);
        return rlen;
    }
    uint8_t lr[2];
    int got = 0;
    while (got < 2) {
        ssize_t n = recv(tfd, lr + got, 2 - got, 0);
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
        ssize_t n = recv(tfd, resp + got, tlen - got, 0);
        if (n <= 0) {
            close(tfd);
            return rlen;
        }
        got += (int) n;
    }
    close(tfd);
    return tlen;
}

/* DoH response (RFC 8484): forward and answer as application/dns-message */
static void handle_doh(int fd, SSL *ssl, const uint8_t *pkt, int plen) {
    uint8_t resp[DNS_BUF];
    int rlen = dns_forward(pkt, plen, resp, sizeof(resp));
    if (rlen < 0) {
        api_send(fd, ssl, 400, "bad dns message\n");
        return;
    }
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.0 200 OK\r\nContent-Type: application/dns-message\r\n"
                      "Content-Length: %d\r\nConnection: close\r\n\r\n",
                      rlen);
    if (ssl) {
        SSL_write(ssl, hdr, hl);
        SSL_write(ssl, resp, rlen);
    } else {
        ssize_t w = write(fd, hdr, hl);
        w = write(fd, resp, rlen);
        (void) w;
    }
}

/* /metrics — proxied from dnsd's localhost-only read-only endpoint */
static void handle_metrics(int fd, SSL *ssl) {
    char dnsd_http[16];
    snprintf(dnsd_http, sizeof(dnsd_http), "%d", g_http_port);
    char port_s[64];
    int dport = 0;
    if (vk_get("config:metrics_port", port_s, sizeof(port_s)) && port_s[0])
        dport = atoi(port_s);
    if (dport <= 0)
        dport = g_http_port + 1; /* dnsd default: http_port+1 */
    int tfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tfd < 0) {
        api_send(fd, ssl, 502, "metrics unavailable\n");
        return;
    }
    struct timeval tv = {.tv_sec = 3};
    setsockopt(tfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(dport)};
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(tfd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        close(tfd);
        api_send(fd, ssl, 502, "metrics unavailable\n");
        return;
    }
    const char *req = "GET /metrics HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if (send(tfd, req, strlen(req), MSG_NOSIGNAL) < 0) {
        close(tfd);
        api_send(fd, ssl, 502, "metrics unavailable\n");
        return;
    }
    char buf[HTTP_BUF];
    int total = 0;
    for (;;) {
        ssize_t n = recv(tfd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0)
            break;
        total += (int) n;
        if (total >= (int) sizeof(buf) - 1)
            break;
    }
    close(tfd);
    buf[total] = 0;
    if (total <= 0) {
        api_send(fd, ssl, 502, "metrics unavailable\n");
        return;
    }
    /* relay dnsd's complete HTTP response as-is */
    if (ssl)
        SSL_write(ssl, buf, total);
    else {
        ssize_t w = write(fd, buf, total);
        (void) w;
    }
}

/* Read an HTTP request: loop until the CRLFCRLF header terminator, then until the
 * Content-Length body bytes are present — all bounded by `bufsz` and the socket's
 * SO_RCVTIMEO. A single recv() (the old behaviour) truncated any DoH POST body
 * split across TCP segments and had no body-size handling (CSA-DOS-001). Returns
 * total bytes read (NUL-terminated) or -1. */
static int http_read_request(int fd, SSL *ssl, char *buf, int bufsz) {
    int total = 0;
    int hdr_end = -1;
    long content_len = -1;
    while (total < bufsz - 1) {
        int n = ssl ? SSL_read(ssl, buf + total, bufsz - 1 - total)
                    : (int) recv(fd, buf + total, bufsz - 1 - total, 0);
        if (n <= 0)
            break; /* EOF / timeout / error */
        total += n;
        buf[total] = 0;
        if (hdr_end < 0) {
            char *e = strstr(buf, "\r\n\r\n");
            if (e) {
                hdr_end = (int) (e - buf) + 4;
                char *cl = strcasestr(buf, "content-length:");
                if (cl && cl < buf + hdr_end) {
                    content_len = strtol(cl + 15, NULL, 10);
                    if (content_len < 0)
                        content_len = 0;
                    if (content_len > bufsz - 1)
                        content_len = bufsz - 1; /* capped by the buffer */
                }
            }
        }
        if (hdr_end >= 0 && (content_len < 0 || total - hdr_end >= content_len))
            break; /* headers complete and full body (or no body) received */
    }
    return total > 0 ? total : -1;
}

/* ── Request handler (ported from the monolith's handle_api; every side
 *    effect is a Valkey write — nothing reaches into dnsd's memory) ──────── */
static void handle_api(int fd, SSL *ssl, int is_mgmt) {
    char buf[HTTP_BUF];
    int n = http_read_request(fd, ssl, buf, sizeof(buf));
    if (n <= 0)
        return;
    buf[n] = 0;
    char method[8], path[512];
    if (sscanf(buf, "%7s %511s", method, path) != 2) {
        api_send(fd, ssl, 400, "bad request\n");
        return;
    }
    char *qs = strchr(path, '?');
    if (qs) {
        *qs = 0;
        qs++;
    } else
        qs = "";

    /* DoH endpoint (RFC 8484) */
    if (!strcasecmp(path, "/dns-query")) {
        if (!strcasecmp(method, "POST")) {
            char *bdy = strstr(buf, "\r\n\r\n");
            if (!bdy) {
                api_send(fd, ssl, 400, "no body\n");
                return;
            }
            bdy += 4;
            int blen = n - (int) (bdy - buf);
            handle_doh(fd, ssl, (uint8_t *) bdy, blen);
        } else { /* GET with dns= parameter */
            char dns_b64[4096] = {0};
            qs_get(qs, "dns", dns_b64, sizeof(dns_b64));
            uint8_t pkt[DNS_BUF];
            int plen = b64url_dec(dns_b64, pkt, sizeof(pkt));
            if (plen < 12) {
                api_send(fd, ssl, 400, "bad dns parameter\n");
                return;
            }
            handle_doh(fd, ssl, pkt, plen);
        }
        return;
    }

    if (!strcmp(path, "/health")) {
        api_send(fd, ssl, 200, "ok\n");
        return;
    }
    if (!strcmp(path, "/metrics")) {
        handle_metrics(fd, ssl);
        return;
    }

    if (!strcmp(path, "/list")) {
        char body[HTTP_BUF];
        int bp = 0;
        char zn[256] = "", zs[32] = "";
        vk_get("config:zone_name", zn, sizeof(zn));
        vk_get("config:zone_serial", zs, sizeof(zs));
        bp += snprintf(body + bp, sizeof(body) - bp, "Zone: %s  Serial: %s\n\n", zn, zs);
        pthread_mutex_lock(&g_vk_mutex);
        if (valkey_ensure(&vk) >= 0) {
            const char *pfxs[] = {"ddns:*", "zone:*", NULL};
            for (int pi = 0; pfxs[pi]; pi++) {
                resp_reply_t r;
                resp_cmd(&vk, &r, 2, "KEYS", pfxs[pi]);
                if (r.type == 5) {
                    for (int i = 0; i < r.count && bp < (int) sizeof(body) - 256; i++) {
                        resp_reply_t kr;
                        resp_parse(&vk, &kr);
                        if (kr.type != 2)
                            continue;
                        resp_reply_t vr;
                        resp_cmd(&vk, &vr, 2, "GET", kr.str);
                        resp_reply_t tr;
                        resp_cmd(&vk, &tr, 2, "TTL", kr.str);
                        bp += snprintf(body + bp, sizeof(body) - bp, "  %-50s = %s  TTL=%ld\n",
                                       kr.str, vr.str, tr.type == 3 ? tr.integer : -1L);
                    }
                }
            }
        }
        pthread_mutex_unlock(&g_vk_mutex);
        api_send(fd, ssl, 200, body);
        return;
    }

    /* Auth for the write paths below: mTLS listener, or ?key=<ddns_secret> */
    char akey[128] = {0};
    qs_get(qs, "key", akey, sizeof(akey));
    if (!is_mgmt) {
        char secret[256] = "";
        vk_get("config:ddns_secret", secret, sizeof(secret));
        /* Constant-time compare (CSA-TIME-001): strcmp short-circuits on the
         * first differing byte, leaking a timing oracle on the DDNS secret. */
        size_t la = strlen(akey);
        size_t ls = strlen(secret);
        if (!secret[0] || la != ls || CRYPTO_memcmp(akey, secret, ls) != 0) {
            api_send(fd, ssl, 403, "forbidden\n");
            return;
        }
    }
    char hostname[256] = {0};
    qs_get(qs, "hostname", hostname, sizeof(hostname));
    if (hostname[0])
        strlower(hostname);

    /* DDNS update */
    if (!strcmp(path, "/update")) {
        char ip[64] = {0}, ip6[64] = {0}, ttls[16] = {0};
        qs_get(qs, "ip", ip, sizeof(ip));
        qs_get(qs, "ip6", ip6, sizeof(ip6));
        qs_get(qs, "ttl", ttls, sizeof(ttls));
        if (!hostname[0]) {
            api_send(fd, ssl, 400, "missing hostname\n");
            return;
        }
        uint32_t ttl = ttls[0] ? (uint32_t) atoi(ttls) : DEFAULT_TTL;
        if (ttl < 10)
            ttl = 10;
        char zn[256];
        resolve_zone(hostname, zn, sizeof(zn));
        if (!zn[0]) {
            api_send(fd, ssl, 400, "no authoritative zone for that hostname\n");
            return;
        }
        char vkey[600], rbody[700];
        if (ip[0]) {
            struct in_addr a4;
            if (inet_pton(AF_INET, ip, &a4) != 1) {
                api_send(fd, ssl, 400, "bad ip\n");
                return;
            }
            snprintf(vkey, sizeof(vkey), "ddns:%s:A:%s", zn, hostname);
            vk_set(vkey, ip, ttl);
            serial_bump_zone(zn);
            snprintf(rbody, sizeof(rbody), "ok: %s A %s TTL=%u\n", hostname, ip, ttl);
            api_send(fd, ssl, 200, rbody);
        } else if (ip6[0]) {
            struct in6_addr a6;
            if (inet_pton(AF_INET6, ip6, &a6) != 1) {
                api_send(fd, ssl, 400, "bad ip6\n");
                return;
            }
            snprintf(vkey, sizeof(vkey), "ddns:%s:AAAA:%s", zn, hostname);
            vk_set(vkey, ip6, ttl);
            serial_bump_zone(zn);
            snprintf(rbody, sizeof(rbody), "ok: %s AAAA %s TTL=%u\n", hostname, ip6, ttl);
            api_send(fd, ssl, 200, rbody);
        } else
            api_send(fd, ssl, 400, "missing ip or ip6\n");
        return;
    }
    if (!strcmp(path, "/delete")) {
        if (!hostname[0]) {
            api_send(fd, ssl, 400, "missing hostname\n");
            return;
        }
        char zn[256];
        resolve_zone(hostname, zn, sizeof(zn));
        if (!zn[0]) {
            api_send(fd, ssl, 400, "no authoritative zone for that hostname\n");
            return;
        }
        char typestr[16] = {0};
        qs_get(qs, "type", typestr, sizeof(typestr));
        char vk2[600];
        int d = 0;
        if (!typestr[0] || !strcasecmp(typestr, "A")) {
            snprintf(vk2, sizeof(vk2), "ddns:%s:A:%s", zn, hostname);
            d += vk_del(vk2);
        }
        if (!typestr[0] || !strcasecmp(typestr, "AAAA")) {
            snprintf(vk2, sizeof(vk2), "ddns:%s:AAAA:%s", zn, hostname);
            d += vk_del(vk2);
        }
        serial_bump_zone(zn);
        char rbody[128];
        snprintf(rbody, sizeof(rbody), "ok: deleted %d key(s)\n", d);
        api_send(fd, ssl, 200, rbody);
        return;
    }

    /* Zone record provisioning */
    if (!strcmp(path, "/zone") && (!strcasecmp(method, "POST") || !strcasecmp(method, "PUT"))) {
        char *bdy = strstr(buf, "\r\n\r\n");
        if (!bdy) {
            api_send(fd, ssl, 400, "no body\n");
            return;
        }
        bdy += 4;
        char name[256] = {0}, type[16] = {0}, value[512] = {0}, ttls[16] = {0}, pref[16] = {0};
        qs_get(bdy, "name", name, sizeof(name));
        strlower(name);
        qs_get(bdy, "type", type, sizeof(type));
        qs_get(bdy, "value", value, sizeof(value));
        qs_get(bdy, "ttl", ttls, sizeof(ttls));
        qs_get(bdy, "pref", pref, sizeof(pref));
        if (!name[0])
            qs_get(qs, "name", name, sizeof(name));
        if (!type[0])
            qs_get(qs, "type", type, sizeof(type));
        if (!value[0])
            qs_get(qs, "value", value, sizeof(value));
        if (!name[0] || !type[0] || !value[0]) {
            api_send(fd, ssl, 400, "missing name/type/value\n");
            return;
        }
        uint16_t rt = str2type(type);
        if (!rt) {
            api_send(fd, ssl, 400, "unknown type\n");
            return;
        }
        uint32_t ttl = ttls[0] ? (uint32_t) atoi(ttls) : 300;
        char zn[256];
        resolve_zone(name, zn, sizeof(zn));
        if (!zn[0]) {
            api_send(fd, ssl, 400, "no authoritative zone for that name\n");
            return;
        }
        char vkey[600], vval[1024];
        snprintf(vkey, sizeof(vkey), "zone:%s:%s:%s", zn, type2str(rt), name);
        if (rt == 15)
            snprintf(vval, sizeof(vval), "%u|%s|%s", ttl, pref[0] ? pref : "10", value);
        else
            snprintf(vval, sizeof(vval), "%u|%s", ttl, value);
        vk_set(vkey, vval, 0);
        serial_bump_zone(zn);
        dns_log(LOG_NOTICE, "[ZONE] %s %s:%s = %s\n", type2str(rt), zn, name, vval);
        char rb[640];
        snprintf(rb, sizeof(rb), "ok: %s\n", vkey);
        api_send(fd, ssl, 201, rb);
        return;
    }
    if (!strcmp(path, "/zone") && !strcasecmp(method, "DELETE")) {
        char name[256] = {0}, type[16] = {0};
        qs_get(qs, "name", name, sizeof(name));
        strlower(name);
        qs_get(qs, "type", type, sizeof(type));
        if (!name[0]) {
            api_send(fd, ssl, 400, "missing name\n");
            return;
        }
        char zn[256];
        resolve_zone(name, zn, sizeof(zn));
        if (!zn[0]) {
            api_send(fd, ssl, 400, "no authoritative zone for that name\n");
            return;
        }
        int d = 0;
        if (type[0]) {
            uint16_t rt = str2type(type);
            if (!rt) {
                api_send(fd, ssl, 400, "unknown type\n");
                return;
            }
            char vkey[600];
            snprintf(vkey, sizeof(vkey), "zone:%s:%s:%s", zn, type2str(rt), name);
            d = vk_del(vkey);
        } else {
            const char *ts[] = {"A",   "AAAA",  "CNAME", "MX",    "TXT", "NS", "SRV",
                                "CAA", "SSHFP", "TLSA",  "DNAME", "LOC", NULL};
            for (int i = 0; ts[i]; i++) {
                char vk2[600];
                snprintf(vk2, sizeof(vk2), "zone:%s:%s:%s", zn, ts[i], name);
                d += vk_del(vk2);
            }
        }
        serial_bump_zone(zn);
        char rb[128];
        snprintf(rb, sizeof(rb), "ok: deleted %d record(s)\n", d);
        api_send(fd, ssl, 200, rb);
        return;
    }

    /* Config management (mgmt only) */
    if (is_mgmt && !strcmp(path, "/config") && !strcasecmp(method, "POST")) {
        char *bdy = strstr(buf, "\r\n\r\n");
        if (!bdy) {
            api_send(fd, ssl, 400, "no body\n");
            return;
        }
        bdy += 4;
        char cfgkey[128] = {0}, cfgval[4096] = {0};
        qs_get(bdy, "key", cfgkey, sizeof(cfgkey));
        qs_get(bdy, "value", cfgval, sizeof(cfgval));
        if (!cfgkey[0]) {
            api_send(fd, ssl, 400, "missing key\n");
            return;
        }
        char fullkey[160];
        snprintf(fullkey, sizeof(fullkey), "config:%s", cfgkey);
        vk_set(fullkey, cfgval, 0);
        char rb[320];
        snprintf(rb, sizeof(rb), "ok: config:%s updated (dnsd applies it live)\n", cfgkey);
        api_send(fd, ssl, 200, rb);
        return;
    }

    /* Multi-zone management (zone_table:* — the format dnsd loads at boot) */
    if (is_mgmt && !strcasecmp(method, "GET") && !strcmp(path, "/zone/list")) {
        char body[HTTP_BUF];
        int bp = 0;
        pthread_mutex_lock(&g_vk_mutex);
        if (valkey_ensure(&vk) >= 0) {
            resp_reply_t r;
            resp_cmd(&vk, &r, 2, "KEYS", "zone_table:*");
            if (r.type == 5) {
                bp += snprintf(body + bp, sizeof(body) - bp, "zones: %d\n", r.count);
                for (int i = 0; i < r.count && bp < (int) sizeof(body) - 512; i++) {
                    resp_reply_t kr;
                    resp_parse(&vk, &kr);
                    if (kr.type != 2)
                        continue;
                    resp_reply_t vr;
                    resp_cmd(&vk, &vr, 2, "GET", kr.str);
                    bp += snprintf(body + bp, sizeof(body) - bp, "  %-40s = %s\n", kr.str + 11,
                                   vr.type == 2 ? vr.str : "?");
                }
            } else
                bp += snprintf(body + bp, sizeof(body) - bp, "zones: 0\n");
        } else
            bp += snprintf(body + bp, sizeof(body) - bp, "valkey unavailable\n");
        pthread_mutex_unlock(&g_vk_mutex);
        api_send(fd, ssl, 200, body);
        return;
    }
    if (is_mgmt && !strcasecmp(method, "POST") && !strcmp(path, "/zone/add")) {
        char *bdy = strstr(buf, "\r\n\r\n");
        if (!bdy) {
            api_send(fd, ssl, 400, "no body\n");
            return;
        }
        bdy += 4;
        char zn[256] = {0}, zmn[320] = {0}, zrn[320] = {0};
        qs_get(bdy, "name", zn, sizeof(zn));
        strlower(zn);
        qs_get(bdy, "mname", zmn, sizeof(zmn));
        qs_get(bdy, "rname", zrn, sizeof(zrn));
        if (!zn[0]) {
            api_send(fd, ssl, 400, "name required\n");
            return;
        }
        if (!zmn[0]) {
            snprintf(zmn, sizeof(zmn), "ns1.%s", zn);
        }
        if (!zrn[0]) {
            snprintf(zrn, sizeof(zrn), "hostmaster.%s", zn);
        }
        char zkey[300], zval[2048];
        snprintf(zkey, sizeof(zkey), "zone_table:%s", zn);
        /* mname|rname|serial|refresh|retry|expire|minimum|axfr_allow|notify_targets */
        snprintf(zval, sizeof(zval), "%s|%s|1|3600|900|604800|300|127.0.0.1|", zmn, zrn);
        vk_set(zkey, zval, 0);
        dns_log(LOG_NOTICE, "[Zone] Added %s (dnsd loads the zone table live)\n", zn);
        char rb[320];
        snprintf(rb, sizeof(rb), "ok: zone %s added\n", zn);
        api_send(fd, ssl, 201, rb);
        return;
    }
    if (is_mgmt && !strcasecmp(method, "POST") && !strcmp(path, "/zone/del")) {
        char *bdy = strstr(buf, "\r\n\r\n");
        if (!bdy) {
            api_send(fd, ssl, 400, "no body\n");
            return;
        }
        bdy += 4;
        char zn[256] = {0};
        qs_get(bdy, "name", zn, sizeof(zn));
        strlower(zn);
        if (!zn[0]) {
            api_send(fd, ssl, 400, "name required\n");
            return;
        }
        char zkey[300];
        snprintf(zkey, sizeof(zkey), "zone_table:%s", zn);
        if (!vk_del(zkey)) {
            api_send(fd, ssl, 404, "zone not found\n");
            return;
        }
        dns_log(LOG_NOTICE, "[Zone] Deleted %s\n", zn);
        api_send(fd, ssl, 200, "ok\n");
        return;
    }

    api_send(fd, ssl, 404, "unknown endpoint\n");
}

/* ── Listeners ───────────────────────────────────────────────────────────── */
static int listen_on(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons(port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        dns_log(LOG_ERR, "[apid] bind :%d failed: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *http_thread(void *arg) {
    (void) arg;
    int srv = listen_on(g_http_port);
    if (srv < 0)
        return NULL;
    dns_log(LOG_NOTICE, "[apid] HTTP (DoH + DDNS) on :%d\n", g_http_port);
    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0)
            continue;
        struct timeval tv = {.tv_sec = 10};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        handle_api(cfd, NULL, 0);
        close(cfd);
    }
    return NULL;
}

static void *https_thread(void *arg) {
    (void) arg;
    int srv = listen_on(g_https_port);
    if (srv < 0)
        return NULL;
    dns_log(LOG_NOTICE, "[apid] HTTPS (DoH + mgmt) on :%d\n", g_https_port);
    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0)
            continue;
        struct timeval tv = {.tv_sec = 10};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        pthread_mutex_lock(&g_tls_mutex);
        SSL_CTX *ctx = g_https_ctx;
        SSL *ssl = ctx ? SSL_new(ctx) : NULL;
        pthread_mutex_unlock(&g_tls_mutex);
        if (!ssl) {
            close(cfd);
            continue;
        }
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(cfd);
            continue;
        }
        /* Management status comes from mTLS: a verified client cert. When no
         * CA is configured the context does not request a cert and is_mgmt
         * stays 0 (DoH-only TLS). */
        X509 *peer = SSL_get_peer_certificate(ssl);
        int is_mgmt = 0;
        if (peer) {
            X509_free(peer);
            is_mgmt = (SSL_get_verify_result(ssl) == X509_V_OK);
        }
        handle_api(cfd, ssl, is_mgmt);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
    }
    return NULL;
}

/* ── Config + main ──────────────────────────────────────────────────────── */
static void load_config(void) {
    safe_strcpy(g_valkey_host, cfgenv("DNS_VALKEY_HOST", "127.0.0.1"), sizeof(g_valkey_host));
    g_valkey_port = atoi(cfgenv("DNS_VALKEY_PORT", "6379"));
    safe_strcpy(g_valkey_pass, cfgenv("DNS_VALKEY_PASSWORD", ""), sizeof(g_valkey_pass));
    char val[64];
    if (vk_get("config:http_port", val, sizeof(val)) && val[0])
        g_http_port = atoi(val);
    if (vk_get("config:https_port", val, sizeof(val)) && val[0])
        g_https_port = atoi(val);
    if (vk_get("config:dns_port", val, sizeof(val)) && val[0])
        g_dns_port = atoi(val);
    vk_get("config:mtls_ca_pem", g_mtls_ca_pem, sizeof(g_mtls_ca_pem));
    tls_material_load();
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    signal(SIGPIPE, SIG_IGN);
    load_config();
    tls_reload();
    dns_log(LOG_NOTICE, "[apid] Starting: HTTP :%d, HTTPS :%d, dnsd at 127.0.0.1:%d\n", g_http_port,
            g_https_port, g_dns_port);
    pthread_t t1, t2, t3;
    if (pthread_create(&t3, NULL, keyspace_watch_thread, NULL) == 0)
        pthread_detach(t3);
    if (pthread_create(&t2, NULL, https_thread, NULL) == 0)
        pthread_detach(t2);
    http_thread(NULL); /* plain-HTTP accept loop runs in main */
    (void) t1;
    return 0;
}
