/* certd.c — certificate manager sidecar (migration Step 2, CLAUDE.md).
 *
 * Owns the ACME (RFC 8555) directory/JWS/order flow with DNS-01 challenges,
 * EST (RFC 7030) mTLS enrollment, CSR generation and renewal scheduling —
 * everything that used to live inside dns_server.c. This is deliberately the
 * only network-facing parser code outside the resolver: it talks to the CA /
 * EST server so the authoritative daemon never has to.
 *
 * Integration is entirely through Valkey (the only contract):
 *   reads   config:acme_* / config:est_*       (written by the dashboard)
 *   reads   cert:current                        (to decide renewal)
 *   writes  acme:account_key, acme:account_url  (its own namespace)
 *   writes  zone:TXT:_acme-challenge.<domain>   (DNS-01; deleted afterwards)
 *   writes  cert:current                        (issued cert chain + key PEM)
 *
 * dnsd watches cert:current and hot-reloads TLS + publishes TLSA itself;
 * certd never reloads anything in-process and never writes config:* or
 * other zone:* records.
 *
 * Usage: certd [--once]
 *   --once   run a single renewal check and exit (for cron / testing)
 *
 * Env: DNS_VALKEY_HOST, DNS_VALKEY_PORT, DNS_VALKEY_PASSWORD.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include "dns_wire.h"

#define ACME_CA_PROD "https://acme-v02.api.letsencrypt.org/directory"
#define ACME_RENEW_DAYS 30
#define HTTP_BUF 16384
#define RESP_BUF 65536
#define MAX_PEM 65536
#define RENEW_CHECK_SECS 86400

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

static char g_acme_domain[256] = "";
static char g_acme_email[256] = "";
static char g_acme_ca[512] = ACME_CA_PROD;
static char g_acme_client_cert_pem[MAX_PEM] = "";
static char g_acme_client_key_pem[MAX_PEM] = "";
static char g_acme_ca_pem[MAX_PEM] = "";
static char g_est_server[512] = "";
static char g_est_domain[256] = "";
static char g_est_client_cert_pem[MAX_PEM] = "";
static char g_est_client_key_pem[MAX_PEM] = "";
static char g_est_ca_pem[MAX_PEM] = "";

/* Active certificate, mirrored from cert:current (read-only for decisions
 * and as fallback mTLS identity for EST re-enrollment). */
static char g_tls_cert_pem[MAX_PEM] = "";
static char g_tls_key_pem[MAX_PEM] = "";

static EVP_PKEY *g_acme_key = NULL;
static char g_acme_account_url[512] = "";
static char g_acme_dir_newnonce[512] = "";
static char g_acme_dir_newacct[512] = "";
static char g_acme_dir_neworder[512] = "";
static char g_acme_nonce[256] = "";

static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

static void sha256(const uint8_t *in, int n, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return;
    unsigned int dl = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, out, &dl);
    EVP_MD_CTX_free(ctx);
}

static int json_str(const char *j, const char *key, char *out, int olen) {
    char nd[256];
    snprintf(nd, sizeof(nd), "\"%s\"", key);
    const char *p = strstr(j, nd);
    if (!p)
        return 0;
    p += strlen(nd);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n')
        p++;
    if (*p != '"')
        return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < olen - 1) {
        if (*p == '\\' && p[1])
            p++;
        out[i++] = *p++;
    }
    out[i] = 0;
    return 1;
}

/* ── Valkey RESP client ──────────────────────────────────────────────────── */
/* Same implementation as dns_server.c minus the RFC 8767 stale-shadow keys:
 * certd does not own the stale:* namespace and has no cache to keep warm. */
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

/* ── EC helpers (P-256 JWK + ECDSA raw signatures for JWS) ───────────────── */
static int ec_pub_xy(EVP_PKEY *k, uint8_t xy[64]) {
    BIGNUM *x = NULL, *y = NULL;
    if (EVP_PKEY_get_bn_param(k, "qx", &x) != 1)
        return 0;
    if (EVP_PKEY_get_bn_param(k, "qy", &y) != 1) {
        BN_free(x);
        return 0;
    }
    BN_bn2binpad(x, xy, 32);
    BN_bn2binpad(y, xy + 32, 32);
    BN_free(x);
    BN_free(y);
    return 1;
}
static int ecdsa_der_to_raw(const uint8_t *der, int dl, uint8_t raw[64]) {
    const uint8_t *p = der;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long) dl);
    if (!s)
        return 0;
    const BIGNUM *r, *sg;
    ECDSA_SIG_get0(s, &r, &sg);
    BN_bn2binpad(r, raw, 32);
    BN_bn2binpad(sg, raw + 32, 32);
    ECDSA_SIG_free(s);
    return 1;
}

/* ── cert:current handling ───────────────────────────────────────────────── */
/* Split one PEM blob into cert chain + private key (same logic as dnsd's
 * watcher; the blob is the cert:current contract format). */
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

/* Refresh the local mirror of the active cert from cert:current. */
static void cert_current_load(void) {
    static char blob[MAX_PEM];
    blob[0] = 0;
    if (!vk_get("cert:current", blob, sizeof(blob)) || !blob[0])
        return;
    static char cert[MAX_PEM], key[MAX_PEM];
    if (cert_current_split(blob, cert, sizeof(cert), key, sizeof(key)) < 0)
        return;
    safe_strcpy(g_tls_cert_pem, cert, sizeof(g_tls_cert_pem));
    safe_strcpy(g_tls_key_pem, key, sizeof(g_tls_key_pem));
}

/* cert_post_issue — publish an issued certificate.
 * Writes cert chain + key as one blob to cert:current; dnsd watches that key,
 * hot-reloads TLS and publishes TLSA + NOTIFY itself. certd intentionally
 * writes nothing else (no config:*, no zone:* except the DNS-01 TXT). */
static void cert_post_issue(const char *domain, const char *cert_pem, const char *key_pem) {
    static char blob[2 * MAX_PEM];
    snprintf(blob, sizeof(blob), "%s%s%s", cert_pem,
             cert_pem[strlen(cert_pem) - 1] == '\n' ? "" : "\n", key_pem);
    if (!vk_set("cert:current", blob, 0)) {
        dns_log(LOG_ERR, "[PKI] Failed to write cert:current\n");
        return;
    }
    safe_strcpy(g_tls_cert_pem, cert_pem, sizeof(g_tls_cert_pem));
    safe_strcpy(g_tls_key_pem, key_pem, sizeof(g_tls_key_pem));
    dns_log(LOG_NOTICE, "[PKI] cert:current updated for %s\n", domain);
}

/* ── HTTPS client (optionally mTLS) ──────────────────────────────────────── */
/* Bind the expected peer identity so the handshake fails on a cert that does not
 * match `host` (CSA-TLS-002). SSL_set_tlsext_host_name() only sets SNI; identity
 * is checked via set1_host (DNS) or set1_ip (IP literal). */
static void tls_verify_peer_name(SSL *ssl, const char *host) {
    X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    unsigned char addr[16];
    if (inet_pton(AF_INET, host, addr) == 1 || inet_pton(AF_INET6, host, addr) == 1)
        X509_VERIFY_PARAM_set1_ip_asc(vp, host);
    else
        X509_VERIFY_PARAM_set1_host(vp, host, 0);
}

static char *https_req_mtls(const char *host, int port, const char *method, const char *path,
                            const char *body, const char *client_cert_pem,
                            const char *client_key_pem, const char *server_ca_pem,
                            const char *content_type, int *code, char *resp_hdrs, int hl) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return NULL;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return NULL;
    }
    struct timeval tv = {.tv_sec = 20};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx) {
        close(fd);
        return NULL;
    }
    if (server_ca_pem && server_ca_pem[0]) {
        X509_STORE *st = SSL_CTX_get_cert_store(cctx);
        BIO *bca = BIO_new_mem_buf(server_ca_pem, -1);
        X509 *cx;
        while ((cx = PEM_read_bio_X509(bca, NULL, NULL, NULL)) != NULL) {
            X509_STORE_add_cert(st, cx);
            X509_free(cx);
        }
        BIO_free(bca);
    } else {
        SSL_CTX_set_default_verify_paths(cctx);
    }
    /* Verify the CA chain on BOTH paths (CSA-TLS-001): previously SSL_VERIFY_PEER
     * was set only when an explicit CA PEM was configured, so the normal
     * system-trust path (public ACME CA) accepted ANY certificate. */
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    if (client_cert_pem && client_cert_pem[0] && client_key_pem && client_key_pem[0]) {
        BIO *bc = BIO_new_mem_buf(client_cert_pem, -1);
        X509 *cc = PEM_read_bio_X509_AUX(bc, NULL, NULL, NULL);
        if (cc) {
            SSL_CTX_use_certificate(cctx, cc);
            X509_free(cc);
        }
        X509 *ci;
        while ((ci = PEM_read_bio_X509(bc, NULL, NULL, NULL)) != NULL)
            SSL_CTX_add_extra_chain_cert(cctx, ci);
        BIO_free(bc);
        BIO *bk = BIO_new_mem_buf(client_key_pem, -1);
        EVP_PKEY *ck = PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL);
        BIO_free(bk);
        if (ck) {
            SSL_CTX_use_PrivateKey(cctx, ck);
            EVP_PKEY_free(ck);
        }
        if (!SSL_CTX_check_private_key(cctx)) {
            dns_log(LOG_ERR, "[PKI] mTLS cert/key mismatch\n");
            SSL_CTX_free(cctx);
            close(fd);
            return NULL;
        }
    }
    SSL *ssl = SSL_new(cctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    tls_verify_peer_name(ssl, host);
    if (SSL_connect(ssl) <= 0) {
        dns_log(LOG_ERR, "[PKI] TLS handshake/verify to %s:%d failed\n", host, port);
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        close(fd);
        return NULL;
    }
    char req[HTTP_BUF];
    int rp = 0;
    rp += snprintf(req + rp, sizeof(req) - rp,
                   "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: dns-server/2.0\r\nAccept: */*\r\n",
                   method, path, host);
    if (body) {
        const char *ct = content_type ? content_type : "application/jose+json";
        rp += snprintf(req + rp, sizeof(req) - rp,
                       "Content-Type: %s\r\nContent-Length: %zu\r\n\r\n%s", ct, strlen(body), body);
    } else {
        rp += snprintf(req + rp, sizeof(req) - rp, "Connection: close\r\n\r\n");
    }
    SSL_write(ssl, req, rp);
    char *rbuf = malloc(HTTP_BUF);
    if (!rbuf) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        close(fd);
        return NULL;
    }
    int rtotal = 0, cap = HTTP_BUF;
    for (;;) {
        if (rtotal >= cap - 1) {
            char *nbuf = realloc(rbuf, cap * 2);
            if (!nbuf) {
                break;
            }
            rbuf = nbuf;
            cap *= 2;
        }
        int n = SSL_read(ssl, rbuf + rtotal, cap - rtotal - 1);
        if (n <= 0)
            break;
        rtotal += n;
    }
    rbuf[rtotal] = 0;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    close(fd);
    *code = 0;
    sscanf(rbuf, "HTTP/1.%*c %d", code);
    char *sep = strstr(rbuf, "\r\n\r\n");
    if (!sep) {
        free(rbuf);
        return NULL;
    }
    if (resp_hdrs && hl > 0) {
        int nn = (int) (sep - rbuf);
        if (nn >= hl)
            nn = hl - 1;
        memcpy(resp_hdrs, rbuf, nn);
        resp_hdrs[nn] = 0;
    }
    char *ret = strdup(sep + 4);
    free(rbuf);
    if (!ret)
        return NULL;
    return ret;
}

static int hdr_val(const char *h, const char *k, char *out, int olen) {
    char nd[256];
    snprintf(nd, sizeof(nd), "%s:", k);
    const char *p = strcasestr(h, nd);
    if (!p)
        return 0;
    p += strlen(nd);
    while (*p == ' ')
        p++;
    int i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < olen - 1)
        out[i++] = *p++;
    out[i] = 0;
    return 1;
}
static void parse_url(const char *url, char *host, int *port, char *path, int plen) {
    *port = 443;
    strcpy(path, "/");
    const char *p = url;
    if (strncmp(p, "https://", 8) == 0)
        p += 8;
    else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *port = 80;
    }
    const char *sl = strchr(p, '/');
    int hl = sl ? (int) (sl - p) : (int) strlen(p);
    memcpy(host, p, hl);
    host[hl] = 0;
    if (sl)
        safe_strcpy(path, sl, plen);
    char *col = strchr(host, ':');
    if (col) {
        *port = atoi(col + 1);
        *col = 0;
    }
}

/* ── ACME client (RFC 8555) ──────────────────────────────────────────────── */
static void acme_jwk(EVP_PKEY *k, char *out, int olen) {
    uint8_t xy[64];
    if (!ec_pub_xy(k, xy)) {
        snprintf(out, olen, "{}");
        return;
    }
    char xb[64], yb[64];
    b64url_enc(xy, 32, xb, sizeof(xb));
    b64url_enc(xy + 32, 32, yb, sizeof(yb));
    snprintf(out, olen, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xb, yb);
}
static void acme_thumbprint(EVP_PKEY *k, char *out, int olen) {
    char jwk[512];
    acme_jwk(k, jwk, sizeof(jwk));
    uint8_t h32[32];
    sha256((uint8_t *) jwk, strlen(jwk), h32);
    b64url_enc(h32, 32, out, olen);
}
static char *acme_jws(EVP_PKEY *key, const char *url, const char *nonce, const char *payload) {
    char hj[1024];
    if (g_acme_account_url[0])
        snprintf(hj, sizeof(hj),
                 "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\",\"kid\":\"%s\"}", nonce, url,
                 g_acme_account_url);
    else {
        char jwk[512];
        acme_jwk(key, jwk, sizeof(jwk));
        snprintf(hj, sizeof(hj), "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\",\"jwk\":%s}",
                 nonce, url, jwk);
    }
    char hb[1024], pb[4096];
    b64url_enc((uint8_t *) hj, strlen(hj), hb, sizeof(hb));
    if (payload)
        b64url_enc((uint8_t *) payload, strlen(payload), pb, sizeof(pb));
    else
        strcpy(pb, "");
    char si[8192];
    snprintf(si, sizeof(si), "%s.%s", hb, pb);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    EVP_DigestSignInit(mc, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSignUpdate(mc, si, strlen(si));
    size_t sl = 0;
    EVP_DigestSignFinal(mc, NULL, &sl);
    if (sl == 0) {
        EVP_MD_CTX_free(mc);
        char *jws = malloc(16);
        if (jws)
            strcpy(jws, "{}");
        return jws;
    }
    uint8_t *der = malloc(sl);
    if (!der) {
        EVP_MD_CTX_free(mc);
        return NULL;
    }
    EVP_DigestSignFinal(mc, der, &sl);
    EVP_MD_CTX_free(mc);
    uint8_t raw[64];
    ecdsa_der_to_raw(der, sl, raw);
    free(der);
    char sb[256];
    b64url_enc(raw, 64, sb, sizeof(sb));
    char *jws = malloc(HTTP_BUF);
    if (!jws)
        return NULL;
    snprintf(jws, HTTP_BUF, "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}", hb,
             pb, sb);
    return jws;
}
static int acme_nonce_fetch(const char *host, int port) {
    char path[512];
    int p2;
    char h2[256];
    parse_url(g_acme_dir_newnonce, h2, &p2, path, sizeof(path));
    char hdrs[4096] = {0};
    int code = 0;
    char *b = https_req_mtls(h2, p2, "HEAD", path, NULL, NULL, NULL, NULL, NULL, &code, hdrs,
                             sizeof(hdrs));
    free(b);
    hdr_val(hdrs, "Replay-Nonce", g_acme_nonce, sizeof(g_acme_nonce));
    return g_acme_nonce[0] ? 0 : -1;
    (void) host;
    (void) port;
}
static char *acme_post(const char *url, const char *payload, const char *host, int port, int *code,
                       char *rh, int rhl) {
    acme_nonce_fetch(host, port);
    char *jws = acme_jws(g_acme_key, url, g_acme_nonce, payload);
    if (!jws)
        return NULL;
    char path[512];
    int p2;
    char h2[256];
    parse_url(url, h2, &p2, path, sizeof(path));
    char *body = https_req_mtls(h2, p2, "POST", path, jws,
                                g_acme_client_cert_pem[0] ? g_acme_client_cert_pem : NULL,
                                g_acme_client_key_pem[0] ? g_acme_client_key_pem : NULL,
                                g_acme_ca_pem[0] ? g_acme_ca_pem : NULL, NULL, code, rh, rhl);
    free(jws);
    hdr_val(rh, "Replay-Nonce", g_acme_nonce, sizeof(g_acme_nonce));
    return body;
}
static int acme_directory(const char *host, int port) {
    char path[512];
    int p2;
    char h2[256];
    parse_url(g_acme_ca, h2, &p2, path, sizeof(path));
    char hdrs[4096] = {0};
    int code = 0;
    char *body = https_req_mtls(
        h2, p2, "GET", path, NULL, g_acme_client_cert_pem[0] ? g_acme_client_cert_pem : NULL,
        g_acme_client_key_pem[0] ? g_acme_client_key_pem : NULL,
        g_acme_ca_pem[0] ? g_acme_ca_pem : NULL, NULL, &code, hdrs, sizeof(hdrs));
    if (!body || code != 200) {
        free(body);
        return -1;
    }
    json_str(body, "newNonce", g_acme_dir_newnonce, sizeof(g_acme_dir_newnonce));
    json_str(body, "newAccount", g_acme_dir_newacct, sizeof(g_acme_dir_newacct));
    json_str(body, "newOrder", g_acme_dir_neworder, sizeof(g_acme_dir_neworder));
    free(body);
    dns_log(LOG_NOTICE, "[ACME] Directory OK\n");
    (void) host;
    (void) port;
    return 0;
}

/* make_csr_der — PKCS#10 DER with CN=domain and DNS SAN. */
static uint8_t *make_csr_der(const char *domain, EVP_PKEY **dkout, int *derlen) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
    EVP_PKEY *dk = NULL;
    EVP_PKEY_keygen(kctx, &dk);
    EVP_PKEY_CTX_free(kctx);
    if (!dk) {
        *dkout = NULL;
        return NULL;
    }
    *dkout = dk;
    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_pubkey(req, dk);
    X509_NAME *nm = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (unsigned char *) domain, -1, -1, 0);
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    char san[512];
    snprintf(san, sizeof(san), "DNS:%s", domain);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if (ext)
        sk_X509_EXTENSION_push(exts, ext);
    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_sign(req, dk, EVP_sha256());
    int n = i2d_X509_REQ(req, NULL);
    if (n <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(dk);
        *dkout = NULL;
        return NULL;
    }
    uint8_t *der = malloc((size_t) n);
    if (!der) {
        X509_REQ_free(req);
        EVP_PKEY_free(dk);
        *dkout = NULL;
        return NULL;
    }
    uint8_t *p = der;
    i2d_X509_REQ(req, (unsigned char **) &p);
    X509_REQ_free(req);
    *derlen = n;
    return der;
}

static char *acme_gen_csr(const char *domain, EVP_PKEY **dkout) {
    int derlen = 0;
    uint8_t *der = make_csr_der(domain, dkout, &derlen);
    if (!der)
        return NULL;
    char *cb64 = malloc((size_t) derlen * 2 + 4);
    if (!cb64) {
        free(der);
        EVP_PKEY_free(*dkout);
        *dkout = NULL;
        return NULL;
    }
    b64url_enc(der, derlen, cb64, (int) ((size_t) derlen * 2 + 4));
    free(der);
    return cb64;
}

static int acme_issue(void) {
    if (!g_acme_domain[0])
        return 0;
    dns_log(LOG_NOTICE, "[ACME] Requesting cert for %s\n", g_acme_domain);
    char achost[256];
    int acport = 443;
    char acpath[512];
    parse_url(g_acme_ca, achost, &acport, acpath, sizeof(acpath));
    if (!g_acme_key) {
        char pem[MAX_PEM] = {0};
        if (vk_get("acme:account_key", pem, sizeof(pem)) && strlen(pem) > 10) {
            BIO *b = BIO_new_mem_buf(pem, -1);
            g_acme_key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
            BIO_free(b);
        }
        if (!g_acme_key) {
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            EVP_PKEY_keygen_init(kctx);
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
            EVP_PKEY_keygen(kctx, &g_acme_key);
            EVP_PKEY_CTX_free(kctx);
            BIO *b = BIO_new(BIO_s_mem());
            PEM_write_bio_PrivateKey(b, g_acme_key, NULL, NULL, 0, NULL, NULL);
            char *pp;
            long pl = BIO_get_mem_data(b, &pp);
            char p2[MAX_PEM];
            int nn = (int) (pl < MAX_PEM - 1 ? pl : MAX_PEM - 1);
            memcpy(p2, pp, nn);
            p2[nn] = 0;
            vk_set("acme:account_key", p2, 0);
            BIO_free(b);
        }
    }
    if (acme_directory(achost, acport) < 0) {
        dns_log(LOG_ERR, "[ACME] Directory failed\n");
        return -1;
    }
    if (!g_acme_account_url[0]) {
        char pay[512];
        snprintf(pay, sizeof(pay), "{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:%s\"]}",
                 g_acme_email[0] ? g_acme_email : "admin@example.com");
        char hdrs[4096] = {0};
        int code = 0;
        char *body = acme_post(g_acme_dir_newacct, pay, achost, acport, &code, hdrs, sizeof(hdrs));
        free(body);
        hdr_val(hdrs, "Location", g_acme_account_url, sizeof(g_acme_account_url));
        if (g_acme_account_url[0]) {
            vk_set("acme:account_url", g_acme_account_url, 0);
            dns_log(LOG_NOTICE, "[ACME] Account: %s\n", g_acme_account_url);
        }
    }
    char pay[512];
    snprintf(pay, sizeof(pay), "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}",
             g_acme_domain);
    char ord_hdrs[4096] = {0};
    int code = 0;
    char *ord_body =
        acme_post(g_acme_dir_neworder, pay, achost, acport, &code, ord_hdrs, sizeof(ord_hdrs));
    if (!ord_body || code < 200 || code >= 300) {
        dns_log(LOG_ERR, "[ACME] newOrder failed %d\n", code);
        free(ord_body);
        return -1;
    }
    char order_url[512] = {0};
    hdr_val(ord_hdrs, "Location", order_url, sizeof(order_url));
    char authz_url[512] = {0};
    {
        char *p = strstr(ord_body, "authorizations");
        if (p) {
            p = strchr(p, '[');
            if (p) {
                p = strchr(p, '"');
                if (p) {
                    p++;
                    int i = 0;
                    while (*p && *p != '"' && i < (int) sizeof(authz_url) - 1)
                        authz_url[i++] = *p++;
                    authz_url[i] = 0;
                }
            }
        }
    }
    char finalize_url[512] = {0};
    json_str(ord_body, "finalize", finalize_url, sizeof(finalize_url));
    free(ord_body);
    char ah[256];
    int ap = 443;
    char apath[512];
    parse_url(authz_url, ah, &ap, apath, sizeof(apath));
    char azh[4096] = {0};
    char *az_body = acme_post(authz_url, NULL, ah, ap, &code, azh, sizeof(azh));
    if (!az_body) {
        dns_log(LOG_ERR, "[ACME] authz failed\n");
        return -1;
    }
    char ch_tok[256] = {0}, ch_url[512] = {0};
    {
        char *p = az_body;
        while ((p = strstr(p, "\"dns-01\"")) != NULL) {
            char *obj = p - 300;
            if (obj < az_body)
                obj = az_body;
            char tok2[256] = {0}, uv[512] = {0};
            json_str(obj, "token", tok2, sizeof(tok2));
            json_str(obj, "url", uv, sizeof(uv));
            if (tok2[0] && uv[0]) {
                safe_strcpy(ch_tok, tok2, sizeof(ch_tok));
                safe_strcpy(ch_url, uv, sizeof(ch_url));
            }
            p += 8;
            break;
        }
    }
    free(az_body);
    if (!ch_tok[0]) {
        dns_log(LOG_ERR, "[ACME] No dns-01 challenge\n");
        return -1;
    }
    char thumb[256];
    acme_thumbprint(g_acme_key, thumb, sizeof(thumb));
    char kauth[512];
    snprintf(kauth, sizeof(kauth), "%s.%s", ch_tok, thumb);
    uint8_t h32[32];
    sha256((uint8_t *) kauth, strlen(kauth), h32);
    char dns01val[256];
    b64url_enc(h32, 32, dns01val, sizeof(dns01val));
    dns_log(LOG_NOTICE, "[ACME] DNS-01 TXT: %s\n", dns01val);
    char acme_name[512];
    snprintf(acme_name, sizeof(acme_name), "_acme-challenge.%s", g_acme_domain);
    strlower(acme_name);
    char acme_val[512];
    snprintf(acme_val, sizeof(acme_val), "120|%s", dns01val);
    char acme_vk[560];
    snprintf(acme_vk, sizeof(acme_vk), "zone:TXT:%s", acme_name);
    vk_set(acme_vk, acme_val, 0);
    dns_log(LOG_NOTICE, "[ACME] TXT %s set — waiting 5s\n", acme_name);
    sleep(5);
    char ch_hdrs[4096] = {0};
    char *ch_body = acme_post(ch_url, "{}", achost, acport, &code, ch_hdrs, sizeof(ch_hdrs));
    free(ch_body);
    if (code < 200 || code >= 300) {
        vk_del(acme_vk);
        return -1;
    }
    dns_log(LOG_NOTICE, "[ACME] Polling authz (up to 3min)\n");
    int validated = 0;
    for (int i = 0; i < 30; i++) {
        sleep(6);
        char ph[4096] = {0};
        char *pb = acme_post(authz_url, NULL, ah, ap, &code, ph, sizeof(ph));
        if (!pb) {
            dns_log(LOG_DEBUG, "[ACME] Polling authz...\n");
            continue;
        }
        char status[64] = {0};
        json_str(pb, "status", status, sizeof(status));
        free(pb);
        dns_log(LOG_INFO, "[ACME] authz status: %s\n", status);
        if (!strcmp(status, "valid")) {
            validated = 1;
            break;
        }
        if (!strcmp(status, "invalid"))
            break;
    }
    vk_del(acme_vk);
    dns_log(LOG_NOTICE, "[ACME] Polling done\n");
    if (!validated) {
        return -1;
    }
    EVP_PKEY *dkey = NULL;
    char *csr = acme_gen_csr(g_acme_domain, &dkey);
    if (!csr)
        return -1;
    char fin_pay[4096];
    snprintf(fin_pay, sizeof(fin_pay), "{\"csr\":\"%s\"}", csr);
    free(csr);
    char fh[256];
    int fp = 443;
    char fpath[512];
    parse_url(finalize_url, fh, &fp, fpath, sizeof(fpath));
    char fin_hdrs[4096] = {0};
    char *fb = acme_post(finalize_url, fin_pay, fh, fp, &code, fin_hdrs, sizeof(fin_hdrs));
    free(fb);
    char cert_url[512] = {0};
    dns_log(LOG_NOTICE, "[ACME] Polling order (up to 3min)\n");
    for (int i = 0; i < 30; i++) {
        sleep(6);
        char oh[4096] = {0};
        char *ob = acme_post(order_url, NULL, achost, acport, &code, oh, sizeof(oh));
        if (!ob) {
            dns_log(LOG_DEBUG, "[ACME] Polling order...\n");
            continue;
        }
        char status[64] = {0};
        json_str(ob, "status", status, sizeof(status));
        json_str(ob, "certificate", cert_url, sizeof(cert_url));
        free(ob);
        dns_log(LOG_INFO, "[ACME] order status: %s\n", status);
        if (!strcmp(status, "valid") && cert_url[0])
            break;
    }
    dns_log(LOG_NOTICE, "[ACME] Order poll done\n");
    if (!cert_url[0]) {
        EVP_PKEY_free(dkey);
        return -1;
    }
    char ch2[256];
    int cp = 443;
    char cpath[512];
    parse_url(cert_url, ch2, &cp, cpath, sizeof(cpath));
    char cdh[4096] = {0};
    char *cert_pem = acme_post(cert_url, NULL, ch2, cp, &code, cdh, sizeof(cdh));
    if (!cert_pem || code < 200 || code >= 300) {
        free(cert_pem);
        EVP_PKEY_free(dkey);
        return -1;
    }
    BIO *kb = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(kb, dkey, NULL, NULL, 0, NULL, NULL);
    char *kpp;
    long kpl = BIO_get_mem_data(kb, &kpp);
    char key_pem[MAX_PEM];
    int kn = (int) (kpl < MAX_PEM - 1 ? kpl : MAX_PEM - 1);
    memcpy(key_pem, kpp, kn);
    key_pem[kn] = 0;
    BIO_free(kb);
    EVP_PKEY_free(dkey);
    cert_post_issue(g_acme_domain, cert_pem, key_pem);
    free(cert_pem);
    return 0;
}

static int acme_needs_renewal(void) {
    if (!g_acme_domain[0])
        return 0;
    if (!g_tls_cert_pem[0])
        return 1;
    BIO *b = BIO_new_mem_buf(g_tls_cert_pem, -1);
    X509 *cert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!cert)
        return 1;
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert));
    X509_free(cert);
    dns_log(LOG_NOTICE, "[ACME] Cert expires in %d days\n", days);
    return days < ACME_RENEW_DAYS;
}

/* ── EST client (RFC 7030) ───────────────────────────────────────────────── */
static char *est_pkcs7_to_pem(const char *body, int blen) {
    PKCS7 *p7 = NULL;
    if (blen > 5 && body[0] == '-') {
        BIO *bp = BIO_new_mem_buf(body, blen);
        p7 = PEM_read_bio_PKCS7(bp, NULL, NULL, NULL);
        BIO_free(bp);
    }
    if (!p7) {
        char *stripped = malloc(blen + 1);
        if (!stripped)
            return NULL;
        int si = 0;
        for (int i = 0; i < blen; i++)
            if (body[i] != '\n' && body[i] != '\r' && body[i] != ' ')
                stripped[si++] = body[i];
        stripped[si] = 0;
        uint8_t *der = malloc(si + 4);
        int derlen = 0;
        if (der) {
            derlen = b64std_dec(stripped, (uint8_t *) der, si + 4);
        }
        free(stripped);
        if (der && derlen > 0) {
            const unsigned char *pp = (const unsigned char *) der;
            p7 = d2i_PKCS7(NULL, &pp, (long) derlen);
        }
        free(der);
    }
    if (!p7) {
        dns_log(LOG_ERR, "[EST] Failed to parse PKCS#7\n");
        return NULL;
    }
    STACK_OF(X509) *certs = NULL;
    if (PKCS7_type_is_signed(p7))
        certs = p7->d.sign->cert;
    else if (PKCS7_type_is_signedAndEnveloped(p7))
        certs = p7->d.signed_and_enveloped->cert;
    if (!certs || sk_X509_num(certs) == 0) {
        PKCS7_free(p7);
        dns_log(LOG_ERR, "[EST] No certificates in PKCS#7\n");
        return NULL;
    }
    BIO *pb = BIO_new(BIO_s_mem());
    for (int i = 0; i < sk_X509_num(certs); i++)
        PEM_write_bio_X509(pb, sk_X509_value(certs, i));
    PKCS7_free(p7);
    char *ptr;
    long plen = BIO_get_mem_data(pb, &ptr);
    char *result = NULL;
    if (plen > 0) {
        result = malloc(plen + 1);
        if (result) {
            memcpy(result, ptr, plen);
            result[plen] = 0;
        }
    }
    BIO_free(pb);
    return result;
}

static char *est_cacerts(const char *host, int port, const char *cc, const char *ck,
                         const char *ca) {
    int code = 0;
    char *body = https_req_mtls(host, port, "GET", "/.well-known/est/cacerts", NULL, cc, ck, ca,
                                NULL, &code, NULL, 0);
    if (!body || code != 200) {
        dns_log(LOG_ERR, "[EST] cacerts failed HTTP %d\n", code);
        free(body);
        return NULL;
    }
    char *pem = est_pkcs7_to_pem(body, (int) strlen(body));
    free(body);
    return pem;
}

static char *est_enroll(const char *host, int port, const char *domain, const char *op,
                        const char *cc, const char *ck, const char *ca, char **key_pem_out) {
    EVP_PKEY *dk = NULL;
    int derlen = 0;
    uint8_t *csr = make_csr_der(domain, &dk, &derlen);
    if (!csr) {
        dns_log(LOG_ERR, "[EST] CSR generation failed\n");
        return NULL;
    }
    /* Standard base64 (RFC 7030 requires non-URL-safe base64) */
    int b64sz = (derlen / 3 + 1) * 4 + 2;
    char *b64 = malloc(b64sz);
    if (!b64) {
        free(csr);
        EVP_PKEY_free(dk);
        return NULL;
    }
    b64url_enc(csr, derlen, b64, b64sz);
    free(csr);
    for (char *p = b64; *p; p++) {
        if (*p == '-')
            *p = '+';
        else if (*p == '_')
            *p = '/';
    }
    char path[128];
    snprintf(path, sizeof(path), "/.well-known/est/%s", op);
    int code = 0;
    char rhdrs[2048] = {0};
    dns_log(LOG_NOTICE, "[EST] Submitting CSR to %s:%d%s for %s\n", host, port, path, domain);
    char *body = https_req_mtls(host, port, "POST", path, b64, cc, ck, ca, "application/pkcs10",
                                &code, rhdrs, sizeof(rhdrs));
    free(b64);
    if (code == 202) {
        char ra[16] = {0};
        hdr_val(rhdrs, "Retry-After", ra, sizeof(ra));
        int delay = ra[0] ? atoi(ra) : 30;
        if (delay > 120)
            delay = 120;
        dns_log(LOG_NOTICE, "[EST] Deferred — retrying in %ds\n", delay);
        free(body);
        sleep(delay);
        int b64bsz = (derlen / 3 + 1) * 4 + 2;
        char *b64b = malloc(b64bsz);
        if (b64b) {
            uint8_t *csr2 = make_csr_der(domain, &dk, &derlen);
            if (csr2) {
                b64url_enc(csr2, derlen, b64b, b64bsz);
                free(csr2);
                for (char *p = b64b; *p; p++) {
                    if (*p == '-')
                        *p = '+';
                    else if (*p == '_')
                        *p = '/';
                }
                body = https_req_mtls(host, port, "POST", path, b64b, cc, ck, ca,
                                      "application/pkcs10", &code, NULL, 0);
            }
            free(b64b);
        }
    }
    if (!body || (code != 200 && code != 201)) {
        dns_log(LOG_ERR, "[EST] Enrollment failed HTTP %d\n", code);
        free(body);
        EVP_PKEY_free(dk);
        return NULL;
    }
    char *cert_pem = est_pkcs7_to_pem(body, (int) strlen(body));
    free(body);
    if (!cert_pem) {
        EVP_PKEY_free(dk);
        return NULL;
    }
    BIO *kb = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(kb, dk, NULL, NULL, 0, NULL, NULL);
    char *kptr;
    long klen = BIO_get_mem_data(kb, &kptr);
    char *key_pem = NULL;
    if (klen > 0) {
        key_pem = malloc(klen + 1);
        if (key_pem) {
            memcpy(key_pem, kptr, klen);
            key_pem[klen] = 0;
        }
    }
    BIO_free(kb);
    EVP_PKEY_free(dk);
    if (!key_pem) {
        free(cert_pem);
        return NULL;
    }
    *key_pem_out = key_pem;
    dns_log(LOG_NOTICE, "[EST] Certificate issued for %s\n", domain);
    return cert_pem;
}

static int est_issue(void) {
    if (!g_est_server[0])
        return -1;
    const char *domain = g_est_domain[0] ? g_est_domain : g_acme_domain;
    if (!domain[0]) {
        dns_log(LOG_ERR, "[EST] No domain configured\n");
        return -1;
    }
    char host[256] = "";
    int port = 443;
    char path[512];
    parse_url(g_est_server, host, &port, path, sizeof(path));
    const char *cc = g_est_client_cert_pem[0] ? g_est_client_cert_pem : NULL;
    const char *ck = g_est_client_key_pem[0] ? g_est_client_key_pem : NULL;
    const char *ca = g_est_ca_pem[0] ? g_est_ca_pem : NULL;
    const char *op = g_tls_cert_pem[0] ? "simplereenroll" : "simpleenroll";
    /* Re-enrollment: use existing server cert as mTLS identity if no EST client cert */
    if (!cc && g_tls_cert_pem[0] && g_tls_key_pem[0]) {
        cc = g_tls_cert_pem;
        ck = g_tls_key_pem;
        dns_log(LOG_NOTICE, "[EST] Using server cert as mTLS identity for re-enrollment\n");
    }
    char *key_pem = NULL;
    char *cert_pem = est_enroll(host, port, domain, op, cc, ck, ca, &key_pem);
    if (!cert_pem)
        return -1;
    cert_post_issue(domain, cert_pem, key_pem);
    free(cert_pem);
    free(key_pem);
    return 0;
}

static int est_needs_renewal(void) {
    if (!g_est_server[0])
        return 0;
    if (!g_tls_cert_pem[0])
        return 1;
    BIO *b = BIO_new_mem_buf(g_tls_cert_pem, -1);
    X509 *cert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!cert)
        return 1;
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert));
    X509_free(cert);
    return days < ACME_RENEW_DAYS;
}

/* ── Config + main loop ──────────────────────────────────────────────────── */
static void load_config(void) {
    safe_strcpy(g_valkey_host, cfgenv("DNS_VALKEY_HOST", "127.0.0.1"), sizeof(g_valkey_host));
    g_valkey_port = atoi(cfgenv("DNS_VALKEY_PORT", "6379"));
    safe_strcpy(g_valkey_pass, cfgenv("DNS_VALKEY_PASSWORD", ""), sizeof(g_valkey_pass));
    char val[512];
    if (vk_get("config:acme_domain", val, sizeof(val)) && val[0])
        safe_strcpy(g_acme_domain, val, sizeof(g_acme_domain));
    if (vk_get("config:acme_email", val, sizeof(val)) && val[0])
        safe_strcpy(g_acme_email, val, sizeof(g_acme_email));
    if (vk_get("config:acme_ca", val, sizeof(val)) && val[0])
        safe_strcpy(g_acme_ca, val, sizeof(g_acme_ca));
    vk_get("config:acme_client_cert_pem", g_acme_client_cert_pem, sizeof(g_acme_client_cert_pem));
    vk_get("config:acme_client_key_pem", g_acme_client_key_pem, sizeof(g_acme_client_key_pem));
    vk_get("config:acme_ca_pem", g_acme_ca_pem, sizeof(g_acme_ca_pem));
    if (vk_get("config:est_server", val, sizeof(val)) && val[0])
        safe_strcpy(g_est_server, val, sizeof(g_est_server));
    if (vk_get("config:est_domain", val, sizeof(val)) && val[0])
        safe_strcpy(g_est_domain, val, sizeof(g_est_domain));
    vk_get("config:est_client_cert_pem", g_est_client_cert_pem, sizeof(g_est_client_cert_pem));
    vk_get("config:est_client_key_pem", g_est_client_key_pem, sizeof(g_est_client_key_pem));
    vk_get("config:est_ca_pem", g_est_ca_pem, sizeof(g_est_ca_pem));
    vk_get("acme:account_url", g_acme_account_url, sizeof(g_acme_account_url));
}

static int renewal_check(void) {
    load_config();
    cert_current_load();
    if (!g_acme_domain[0] && !g_est_server[0]) {
        dns_log(LOG_INFO,
                "[PKI] Nothing configured (config:acme_domain / config:est_server empty)\n");
        return 0;
    }
    if (!est_needs_renewal() && !acme_needs_renewal())
        return 0;
    dns_log(LOG_WARNING, "[PKI] Certificate renewal needed\n");
    int ok = -1;
    if (g_est_server[0]) {
        dns_log(LOG_NOTICE, "[PKI] Trying EST renewal\n");
        ok = est_issue();
        if (ok < 0)
            dns_log(LOG_WARNING, "[PKI] EST failed, trying ACME\n");
    }
    if (ok < 0 && g_acme_domain[0]) {
        dns_log(LOG_NOTICE, "[PKI] Trying ACME renewal\n");
        ok = acme_issue();
    }
    if (ok < 0)
        dns_log(LOG_ERR, "[PKI] All renewal methods failed\n");
    return ok;
}

int main(int argc, char **argv) {
    int once = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--once"))
            once = 1;
        else {
            fprintf(stderr, "usage: %s [--once]\n", argv[0]);
            return 2;
        }
    }
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    dns_log(LOG_NOTICE, "[certd] Starting (renewal check every %ds%s)\n", RENEW_CHECK_SECS,
            once ? ", --once" : "");
    /* est_cacerts is exercised on demand only; reference it so a build with
     * the function unused still compiles clean under -Wall. */
    (void) est_cacerts;
    if (once)
        return renewal_check() < 0 ? 1 : 0;
    for (;;) {
        renewal_check();
        sleep(RENEW_CHECK_SECS);
    }
    return 0;
}
