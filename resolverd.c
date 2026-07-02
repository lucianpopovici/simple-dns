/*
 * resolverd.c — Caching/forwarding DNS resolver (the recursive role)
 *
 * The recursive/forwarding counterpart to the authoritative `dnsd`; kept a
 * distinct daemon because authoritative and recursive are different DNS roles
 * and must not share a process (CLAUDE.md). Owns upstream UDP/TCP/DoT/DoH, the
 * cache, and DNSSEC *validation*; reads/writes only its `cache:*` Valkey
 * namespace (never the authoritative zone). Formerly `dns_client.c`.
 *
 * A local caching resolver that:
 *   - Listens on a configurable local port (default 5354)
 *   - Forwards queries to the dns_server (UDP, TCP, or DoT)
 *   - Authenticates with TSIG (HMAC-SHA256) using the shared key
 *   - Sends EDNS(0) DNS Cookies (RFC 7873): stable per-upstream Client Cookie,
 *     learns + reuses the Server Cookie, retries once on BADCOOKIE (RCODE 23)
 *   - Caches all responses (positive + negative) with TTL accuracy
 *   - Stores cache in Valkey under  cache:<qname>:<qtype>  for persistence
 *   - In-memory fallback cache (LRU, configurable size) when Valkey is down
 *   - CNAME chain following (up to 8 hops)
 *   - Negative caching: NXDOMAIN + NODATA cached per SOA minimum TTL
 *   - RFC 8767 serve-stale: on upstream failure/SERVFAIL, serve a recently
 *     expired cache entry (bounded by SERVE_STALE_MAX) instead of failing
 *   - RFC 9520 failure caching: cache upstream SERVFAIL briefly
 *     (SERVFAIL_CACHE_TTL) to suppress repeated queries to a broken name
 *   - RFC 8198 aggressive NSEC/NSEC3 cache: a validated NXDOMAIN/NODATA's
 *     denial-of-existence span (AGGRESSIVE_NSEC) answers later queries that
 *     fall in the same gap without an upstream round trip
 *   - RFC 8914 Extended DNS Errors: an EDNS-speaking client that gets
 *     SERVFAIL learns why (DNSSEC Bogus / Network Error), reusing the
 *     libdnswire EDE emitter dnsd already uses
 *   - RFC 7858 DoT server (opt-in, DOT_SERVER_ENABLED) for resolverd's own
 *     stub clients, self-advertised via RFC 9462 DDR
 *     (_dns.resolver.arpa SVCB) — never advertised unless the listener
 *     itself is actually up
 *   - Thread-safe: per-bucket rwlock on memory cache
 *   - Prefetch: re-queries records when TTL < 10% of original
 *   - CLI: dig-like output + cache stats + cache flush/inspect commands
 *
 * Configuration (environment or resolverd.conf):
 *   UPSTREAM_HOST     Upstream dns_server IP/hostname  (default: 127.0.0.1)
 *   UPSTREAM_PORT     Upstream port                    (default: 5353)
 *   UPSTREAM_PROTO    udp | tcp | dot                  (default: udp)
 *   LISTEN_PORT       Local listen port                (default: 5354)
 *   TSIG_KEY_NAME     TSIG key name                    (default: "")
 *   TSIG_SECRET_B64   TSIG secret base64               (default: "")
 *   COOKIE_SECRET     16-byte hex cookie secret        (default: random)
 *   VALKEY_HOST       Valkey host for cache            (default: 127.0.0.1)
 *   VALKEY_PORT       Valkey port                      (default: 6379)
 *   VALKEY_PASS       Valkey password                  (default: "")
 *   CACHE_SIZE        Max in-memory cache entries      (default: 8192)
 *   CACHE_TTL_MAX     Max TTL to cache (seconds)       (default: 3600)
 *   CACHE_NEG_TTL     Max negative TTL (seconds)       (default: 300)
 *   SERVE_STALE_MAX   RFC 8767 stale-serve window (s)  (default: 3600, 0=off)
 *   SERVFAIL_CACHE_TTL RFC 9520 cached-SERVFAIL TTL (s) (default: 30, 0=off)
 *   AGGRESSIVE_NSEC   RFC 8198 aggressive NSEC/NSEC3   (default: 1)
 *   DOT_CA_PEM        Path to CA cert PEM for DoT      (default: system)
 *   DOT_SERVER_ENABLED RFC 7858 DoT server for stubs    (default: 0)
 *   DOT_SERVER_PORT   DoT server listen port           (default: 8854)
 *   DOT_SERVER_CERT_PEM / DOT_SERVER_KEY_PEM  Server cert/key PEM file paths
 *   DOT_SERVER_ADN    Authentication domain name (must match the cert;
 *                     also the RFC 9462 DDR TargetName)
 *
 * Sandbox (Valkey config:* keys, env override in parens; applied after the
 * listeners bind, before the proxy loop — no-op unless started as root):
 *   config:resolverd_chroot_dir      (RESOLVERD_CHROOT)    filesystem confinement
 *   config:resolverd_isolation_mode  (RESOLVERD_ISOLATION) chroot (default) | mountns
 *   config:resolverd_privdrop_user   (RESOLVERD_USER)      drop target (default nobody)
 *   config:resolverd_privdrop_group  (RESOLVERD_GROUP)     drop target group
 *   config:resolverd_seccomp_mode    (RESOLVERD_SECCOMP)   enforce (default) | audit | off
 *
 * Build (see the Makefile for the hardened production target):
 *   make resolverd        # optimised, hardened
 *   make resolverd_debug  # ASan/UBSan
 *
 * Usage (proxy mode — run as local resolver):
 *   ./resolverd
 *   # Then configure your system to use 127.0.0.1:5354
 *
 * Usage (CLI / one-shot query):
 *   ./resolverd <name> [type] [options]
 *   ./resolverd example.local A
 *   ./resolverd example.local MX --upstream 10.0.0.1:5353 --dot
 *   ./resolverd --stats          # show cache statistics
 *   ./resolverd --flush          # flush entire cache
 *   ./resolverd --flush example.local A   # flush specific entry
 *   ./resolverd --dump           # dump all cached records
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include "dns_wire.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "sandbox.h"

/* =========================================================================
 * Constants
 * ======================================================================= */
#define DNS_BUF 8192
/* Constants moved to dns_wire.h: DNS_TYPE_*, DNS_CLASS_IN, DNS_QR, DNS_RA,
 * DNS_RCODE_MASK, DNS_RCODE_BADCOOKIE, DNS_OPCODE_QUERY, TSIG_FUDGE,
 * EDNS_OPT_COOKIE (as EDNS_OPT_COOKIE), DNS_COOKIE_CLIENT_LEN. */
#define DNS_COOKIE_LEN DNS_COOKIE_CLIENT_LEN /* resolverd local alias */
#define DNS_COOKIE_SERVER_MAX 32
#define SOA_MINIMUM_OFF 16 /* offset to minimum within SOA rdata (past serials) */

#define CACHE_BUCKETS 4096 /* must be power of 2 */
#define CACHE_BUCKET_MASK (CACHE_BUCKETS - 1)
#define MAX_CNAME_HOPS 8
#define PREFETCH_RATIO 10 /* prefetch when TTL < original/10 */
#define RESP_BUF 65536
#define MAX_PEM_PATH 512

/* Valkey RESP types */
#define RESP_STR 0
#define RESP_ERR 1
#define RESP_BULK 2
#define RESP_INT 3
#define RESP_NIL 4
#define RESP_ARR 5

/* =========================================================================
 * Types
 * ======================================================================= */
typedef enum { PROTO_UDP = 0, PROTO_TCP, PROTO_DOT, PROTO_DOH } upstream_proto_t;

/* A single cached RR */
typedef struct cache_rr {
    uint16_t type;
    uint16_t rdlen;
    uint32_t ttl_original; /* TTL at insertion time */
    time_t inserted_at;    /* wall time of insertion */
    uint8_t *rdata;        /* heap-allocated */
} cache_rr_t;

/* Cache entry: one qname/qtype tuple → N RRs */
typedef struct cache_entry {
    char qname[256];
    uint16_t qtype;
    int nrr;
    cache_rr_t *rrs; /* heap array of nrr records */
    int negative;    /* 1 = NXDOMAIN/NODATA, 0 = positive */
    uint8_t rcode;
    uint32_t neg_ttl; /* for negative entries */
    time_t inserted_at;
    uint32_t prefetch_ttl; /* re-query when remaining TTL drops below this */
    int served_stale;      /* 1 = this entry has already expired, served stale */
    int dnssec_status;     /* dnssec_status_t */
    /* LRU chain */
    struct cache_entry *lru_prev, *lru_next;
    /* Hash chain */
    struct cache_entry *hash_next;
} cache_entry_t;

/* Per-bucket lock */
typedef struct {
    cache_entry_t *head;
    pthread_rwlock_t lock;
    int count;
} cache_bucket_t;

/* Valkey RESP connection */
typedef struct {
    int fd;
    char rbuf[RESP_BUF];
    int rlen, rpos;
} resp_conn_t;
typedef struct {
    int type;
    long integer;
    char str[RESP_BUF];
    int count;
} resp_reply_t;

/* Configuration */
typedef struct {
#define MAX_UPSTREAMS 4
    /* Primary upstream (index 0) + fallbacks */
    char upstream_host[MAX_UPSTREAMS][256];
    int upstream_port[MAX_UPSTREAMS];
    upstream_proto_t upstream_proto[MAX_UPSTREAMS];
    int upstream_count;     /* number of configured upstreams */
    upstream_proto_t proto; /* kept for compat — mirrors upstream_proto[0] */
    int listen_port;
    char tsig_key_name[256];
    uint8_t tsig_secret[64];
    int tsig_secret_len;
    uint8_t cookie_secret[16];
    char valkey_host[256];
    int valkey_port;
    char valkey_pass[256];
    int cache_size;
    uint32_t cache_ttl_max;
    uint32_t cache_neg_ttl;
    char dot_ca_pem[MAX_PEM_PATH];
    char doh_path[256]; /* URL path for DoH, default /dns-query */
    int doh_port;       /* DoH server port, default 443 */
    int listen_tcp;     /* 1 = also listen on TCP for the proxy */
    int valkey_enabled;
#define MAX_SEARCH_DOMAINS 6
    char search_domains[MAX_SEARCH_DOMAINS][256];
    int search_domain_count;
    uint32_t cache_neg_ttl_min; /* floor for negative cache TTL */
    /* RFC 8767: max seconds past expiry a cache entry may be served on
     * upstream failure/SERVFAIL (0 = serve-stale disabled). */
    uint32_t serve_stale_max;
    /* RFC 9520: TTL for a cached SERVFAIL, to suppress repeated queries to a
     * persistently failing name (0 = failure caching disabled). */
    uint32_t servfail_cache_ttl;
    /* RFC 5452 §2.2 0x20 case randomization (defense-in-depth alongside the
     * CSPRNG transaction ID + source port already in upstream_query_one). */
    int dns0x20_enabled;
    char dns0x20_disable[512]; /* comma-separated upstream hostnames to exempt */
    /* RFC 8198: synthesize NXDOMAIN/NODATA from a cached SECURE NSEC/NSEC3
     * denial span on a cache miss, instead of going upstream. */
    int aggressive_nsec_enabled;
    /* RFC 7858 DoT server for resolverd's own stub clients + RFC 9462 DDR
     * self-advertisement. Off by default — requires an operator-provisioned
     * cert; resolverd must never advertise an encrypted endpoint it doesn't
     * actually serve. */
    int dot_server_enabled;
    int dot_server_port;
    char dot_server_cert_pem[MAX_PEM_PATH];
    char dot_server_key_pem[MAX_PEM_PATH];
    char dot_server_adn[256]; /* authentication domain name — must match the cert */
} config_t;

/* =========================================================================
 * Per-domain upstream routing table
 *
 * Maps a DNS name suffix to a specific upstream index.
 * Lookup uses longest-suffix match, identical to dnsmasq semantics:
 *   route for "corp.local"     matches "host.corp.local", "corp.local"
 *   route for "."              matches everything (catch-all / default)
 *
 * Valkey key: domain_route:<suffix>  →  <upstream_idx>
 *
 * CLI:  --server /corp.local/10.0.0.1:5353[:proto]
 *       --server /./8.8.8.8:53             (catch-all)
 * Env:  DOMAIN_ROUTES=corp.local=10.0.0.1:5353:udp,./8.8.8.8:53
 * ======================================================================= */
#define MAX_ROUTES 32

typedef struct {
    char suffix[256]; /* DNS name suffix, e.g. "corp.local" or "." */
    int upstream_idx; /* index into g_cfg.upstream_host[] */
} route_entry_t;

static route_entry_t g_routes[MAX_ROUTES];
static int g_route_count = 0;
static pthread_mutex_t g_route_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * Globals
 * ======================================================================= */
static config_t g_cfg;
static cache_bucket_t g_cache[CACHE_BUCKETS];
static int g_cache_total = 0; /* total entries (approximate) */
static pthread_mutex_t g_cache_count_mutex = PTHREAD_MUTEX_INITIALIZER;
/* LRU list — head = most recently used, tail = eviction candidate */
static cache_entry_t *g_lru_head = NULL, *g_lru_tail = NULL;
static pthread_mutex_t g_lru_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Statistics */
static uint64_t g_stat_queries = 0;
static uint64_t g_stat_hits = 0;
static uint64_t g_stat_misses = 0;
static uint64_t g_stat_expired = 0;
static uint64_t g_stat_negcache = 0;
static uint64_t g_stat_stale = 0; /* stale-while-revalidate serves */
static pthread_mutex_t g_stat_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Valkey client (for persistent cache) */
static resp_conn_t g_vk;
static pthread_mutex_t g_vk_mutex = PTHREAD_MUTEX_INITIALIZER;
/* SSL context for DoT (client role — connecting to an upstream) */
static SSL_CTX *g_dot_ctx = NULL;
/* SSL context for DoT (server role — resolverd's own stub-facing listener,
 * RFC 7858 / RFC 9462 DDR). NULL unless DOT_SERVER_ENABLED and a valid
 * cert/key/ADN are configured. */
static SSL_CTX *g_dot_server_ctx = NULL;
/* Per-upstream EMA RTT in microseconds (exponential moving average, α=0.2) */
static long g_upstream_rtt_ema[MAX_UPSTREAMS] = {0};
static pthread_mutex_t g_upstream_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Prefetch queue */

/* =========================================================================
 * Utility: lowercase, hex, base64
 * ======================================================================= */

/* =========================================================================
 * SipHash-2-4 for DNS Cookies
 * ======================================================================= */
#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND(v0, v1, v2, v3)                                                                   \
    v0 += v1;                                                                                      \
    v1 = ROTL64(v1, 13);                                                                           \
    v1 ^= v0;                                                                                      \
    v0 = ROTL64(v0, 32);                                                                           \
    v2 += v3;                                                                                      \
    v3 = ROTL64(v3, 16);                                                                           \
    v3 ^= v2;                                                                                      \
    v0 += v3;                                                                                      \
    v3 = ROTL64(v3, 21);                                                                           \
    v3 ^= v0;                                                                                      \
    v2 += v1;                                                                                      \
    v1 = ROTL64(v1, 17);                                                                           \
    v1 ^= v2;                                                                                      \
    v2 = ROTL64(v2, 32);

static uint64_t siphash24(const uint8_t *in, int n, const uint8_t key[16]) {
    uint64_t k0 = 0, k1 = 0;
    for (int i = 0; i < 8; i++)
        k0 |= ((uint64_t) key[i]) << (i * 8);
    for (int i = 0; i < 8; i++)
        k1 |= ((uint64_t) key[8 + i]) << (i * 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL, v1 = k1 ^ 0x646f72616e646f6dULL,
             v2 = k0 ^ 0x6c7967656e657261ULL, v3 = k1 ^ 0x7465646279746573ULL;
    int i = 0;
    for (; i + 7 < n; i += 8) {
        uint64_t m = 0;
        for (int j = 0; j < 8; j++)
            m |= ((uint64_t) in[i + j]) << (j * 8);
        v3 ^= m;
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        v0 ^= m;
    }
    uint64_t last = (uint64_t) (n & 0xFF) << 56;
    int rem = n - i;
    switch (rem) { /* fall-through intentional */
        case 7:
            last |= ((uint64_t) in[i + 6] << 48);
        case 6:
            last |= ((uint64_t) in[i + 5] << 40);
        case 5:
            last |= ((uint64_t) in[i + 4] << 32);
        case 4:
            last |= ((uint64_t) in[i + 3] << 24);
        case 3:
            last |= ((uint64_t) in[i + 2] << 16);
        case 2:
            last |= ((uint64_t) in[i + 1] << 8);
        case 1:
            last |= ((uint64_t) in[i]);
        default:
            break;
    }
    v3 ^= last;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    v0 ^= last;
    v2 ^= 0xFF;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* =========================================================================
 * Valkey RESP client (minimal, same protocol as server)
 * ======================================================================= */
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
static int resp_parse(resp_conn_t *c, resp_reply_t *r) {
    char line[1024];
    if (resp_readline(c, line, sizeof(line)) < 0)
        return -1;
    memset(r, 0, sizeof(*r));
    switch (line[0]) {
        case '+':
            r->type = RESP_STR;
            safe_strcpy(r->str, line + 1, sizeof(r->str));
            return 0;
        case '-':
            r->type = RESP_ERR;
            safe_strcpy(r->str, line + 1, sizeof(r->str));
            return 0;
        case ':':
            r->type = RESP_INT;
            r->integer = atol(line + 1);
            return 0;
        case '$': {
            int bl = atoi(line + 1);
            if (bl < 0) {
                r->type = RESP_NIL;
                return 0;
            }
            r->type = RESP_BULK;
            int take = bl < RESP_BUF - 1 ? bl : RESP_BUF - 1;
            if (resp_readbytes(c, r->str, take) < 0)
                return -1;
            int excess = bl - take;
            while (excess > 0) {
                char d[256];
                int dk = excess > (int) sizeof(d) ? (int) sizeof(d) : excess;
                if (resp_readbytes(c, d, dk) < 0)
                    return -1;
                excess -= dk;
            }
            r->str[take] = 0;
            return 0;
        }
        case '*':
            r->type = RESP_ARR;
            r->count = atoi(line + 1);
            return 0;
        default:
            return -1;
    }
}
static int resp_send_cmd(resp_conn_t *c, resp_reply_t *r, int argc, ...) {
    char buf[8192];
    int pos = snprintf(buf, sizeof(buf), "*%d\r\n", argc);
    va_list ap;
    va_start(ap, argc);
    for (int i = 0; i < argc; i++) {
        const char *a = va_arg(ap, const char *);
        int al = (int) strlen(a);
        if (pos >= (int) sizeof(buf) - 4)
            break;
        pos += snprintf(buf + pos, sizeof(buf) - pos, "$%d\r\n%s\r\n", al, a);
    }
    va_end(ap);
    int sent = 0;
    while (sent < pos) {
        int n = (int) send(c->fd, buf + sent, pos - sent, MSG_NOSIGNAL);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return resp_parse(c, r);
}

static int vk_connect(resp_conn_t *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->rlen = c->rpos = 0;
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0)
        return -1;
    struct timeval tv = {.tv_sec = 3};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(g_cfg.valkey_port)};
    if (inet_pton(AF_INET, g_cfg.valkey_host, &sa.sin_addr) != 1) {
        struct addrinfo h = {0}, *res;
        char ps[8];
        snprintf(ps, sizeof(ps), "%d", g_cfg.valkey_port);
        h.ai_family = AF_INET;
        h.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(g_cfg.valkey_host, ps, &h, &res) != 0) {
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
    if (g_cfg.valkey_pass[0]) {
        resp_reply_t r;
        if (resp_send_cmd(c, &r, 2, "AUTH", g_cfg.valkey_pass) < 0 || r.type == RESP_ERR) {
            close(c->fd);
            c->fd = -1;
            return -1;
        }
    }
    return 0;
}
static int vk_ensure(resp_conn_t *c) {
    if (c->fd < 0)
        return vk_connect(c);
    resp_reply_t r;
    if (resp_send_cmd(c, &r, 1, "PING") < 0) {
        return vk_connect(c);
    }
    return 0;
}

static int vk_set(const char *key, const char *val, uint32_t ttl) {
    pthread_mutex_lock(&g_vk_mutex);
    if (!g_cfg.valkey_enabled || vk_ensure(&g_vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    int ok;
    if (ttl > 0) {
        char ts[16];
        snprintf(ts, sizeof(ts), "%u", ttl);
        ok = resp_send_cmd(&g_vk, &r, 5, "SET", key, val, "EX", ts);
    } else
        ok = resp_send_cmd(&g_vk, &r, 3, "SET", key, val);
    if (ok < 0) {
        g_vk.fd = -1;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return ok >= 0 && r.type == RESP_STR;
}
static int vk_get(const char *key, char *out, int olen) {
    pthread_mutex_lock(&g_vk_mutex);
    if (!g_cfg.valkey_enabled || vk_ensure(&g_vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    if (resp_send_cmd(&g_vk, &r, 2, "GET", key) < 0) {
        g_vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (r.type != RESP_BULK)
        return 0;
    safe_strcpy(out, r.str, olen);
    return 1;
}
static int vk_del(const char *key) {
    pthread_mutex_lock(&g_vk_mutex);
    if (!g_cfg.valkey_enabled || vk_ensure(&g_vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    resp_send_cmd(&g_vk, &r, 2, "DEL", key);
    if (r.type < 0)
        g_vk.fd = -1;
    pthread_mutex_unlock(&g_vk_mutex);
    return r.type == RESP_INT ? (int) r.integer : 0;
}
static int vk_keys_scan(const char *pattern, char keys[][512], int maxkeys) {
    pthread_mutex_lock(&g_vk_mutex);
    int n = 0;
    if (!g_cfg.valkey_enabled || vk_ensure(&g_vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    if (resp_send_cmd(&g_vk, &r, 2, "KEYS", pattern) < 0 || r.type != RESP_ARR) {
        g_vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    for (int i = 0; i < r.count && i < maxkeys; i++) {
        resp_reply_t kr;
        if (resp_parse(&g_vk, &kr) < 0)
            break;
        if (kr.type == RESP_BULK) {
            safe_strcpy(keys[n], kr.str, sizeof(keys[n]));
            n++;
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return n;
}

/* Format one rdata value as a human-readable string */
static void rdata_to_str(const uint8_t *pkt, int plen, int rdoff, uint16_t rdlen, uint16_t type,
                         char *out, int olen) {
    out[0] = 0;
    switch (type) {
        case DNS_TYPE_A:
            if (rdlen == 4)
                snprintf(out, olen, "%d.%d.%d.%d", pkt[rdoff], pkt[rdoff + 1], pkt[rdoff + 2],
                         pkt[rdoff + 3]);
            break;
        case DNS_TYPE_AAAA:
            if (rdlen == 16) {
                struct in6_addr a;
                memcpy(&a, pkt + rdoff, 16);
                inet_ntop(AF_INET6, &a, out, olen);
            }
            break;
        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:
            name_from_wire(pkt, plen, rdoff, out, olen);
            break;
        case DNS_TYPE_MX: {
            char mx[256] = "";
            name_from_wire(pkt, plen, rdoff + 2, mx, sizeof(mx));
            snprintf(out, olen, "%u %s", get16(pkt, rdoff), mx);
        } break;
        case DNS_TYPE_TXT: {
            int i = rdoff, end = rdoff + rdlen, o = 0;
            while (i < end) {
                int l = pkt[i++];
                if (i + l > end)
                    l = end - i;
                if (o + l + 3 < olen) {
                    out[o++] = '"';
                    memcpy(out + o, pkt + i, l);
                    o += l;
                    out[o++] = '"';
                    out[o++] = ' ';
                }
                i += l;
            }
            if (o > 0)
                out[o - 1] = 0;
            else
                out[0] = 0;
        } break;
        case DNS_TYPE_SOA: {
            char mname[256] = "", rname[256] = "";
            int p = name_from_wire(pkt, plen, rdoff, mname, sizeof(mname));
            if (p > 0)
                p = name_from_wire(pkt, plen, p, rname, sizeof(rname));
            if (p > 0 && p + 20 <= plen)
                snprintf(out, olen, "%s %s %u %u %u %u %u", mname, rname, get32(pkt, p),
                         get32(pkt, p + 4), get32(pkt, p + 8), get32(pkt, p + 12),
                         get32(pkt, p + 16));
        } break;
        case DNS_TYPE_SRV: {
            char tgt[256] = "";
            name_from_wire(pkt, plen, rdoff + 6, tgt, sizeof(tgt));
            snprintf(out, olen, "%u %u %u %s", get16(pkt, rdoff), get16(pkt, rdoff + 2),
                     get16(pkt, rdoff + 4), tgt);
        } break;
        default: { /* hex dump */
            int i = rdoff, o = 0;
            while (i < rdoff + (int) rdlen && o + 3 < olen) {
                snprintf(out + o, olen - o, "%02x", pkt[i++]);
                o += 2;
                if (i < rdoff + (int) rdlen && o + 1 < olen) {
                    out[o++] = ' ';
                }
            }
            out[o] = 0;
        }
    }
}

/* Forward declaration needed by DNSSEC validation */
static int upstream_query(const char *qname, uint16_t qtype, uint8_t *resp, int resp_sz,
                          long *rtt_us_out);

/* =========================================================================
 * DNSSEC validation — RFC 4035
 *
 * We verify that:
 *   1. Every RRset in the answer with a RRSIG is correctly signed.
 *   2. The signing DNSKEY is trusted (either explicitly configured, or
 *      fetched and verified against a DS record in the parent zone).
 *
 * Trust anchor: DNSSEC_TRUST_ANCHOR env var — hex-encoded SHA-256 of the
 *   trusted DNSKEY RDATA (the root KSK by default is pre-compiled in).
 *   For our server's internal zone, set the trust anchor to the ZSK SPKI
 *   hash printed by dns_server at startup.
 *
 * Implementation notes:
 *   - We use OpenSSL EVP to verify ECDSA P-256 (alg 13) and Ed25519 (alg 15).
 *   - RSA (alg 5, 7, 8) is recognised but returns "unsupported" — our server
 *     only generates ECDSA/Ed25519 keys so this is acceptable.
 *   - Validation result is stored in the cache entry so repeated hits don't
 *     re-verify.
 * ======================================================================= */

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

typedef enum {
    DNSSEC_UNCHECKED = 0, /* not yet verified */
    DNSSEC_SECURE = 1,    /* signatures verified against trusted key */
    DNSSEC_INSECURE = 2,  /* zone not signed or no DO bit */
    DNSSEC_BOGUS = 3,     /* signature present but invalid */
} dnssec_status_t;

/* Configured trust anchors: SHA-256 of DNSKEY rdata */
#define MAX_TRUST_ANCHORS 8
static uint8_t g_trust_anchors[MAX_TRUST_ANCHORS][32];
static int g_trust_anchor_count = 0;
static pthread_mutex_t g_ta_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Add a trust anchor from hex string */
static void dnssec_add_trust_anchor(const char *hex) {
    pthread_mutex_lock(&g_ta_mutex);
    if (g_trust_anchor_count < MAX_TRUST_ANCHORS) {
        int n = hex_dec(hex, g_trust_anchors[g_trust_anchor_count], 32);
        if (n == 32)
            g_trust_anchor_count++;
    }
    pthread_mutex_unlock(&g_ta_mutex);
}

/* SHA-256 wrapper */
static void sha256_buf(const uint8_t *in, int n, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dl = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, out, &dl);
    EVP_MD_CTX_free(ctx);
}

/* Check whether a DNSKEY rdata blob matches any configured trust anchor */
static int dnskey_is_trusted(const uint8_t *dkrd, int dklen) {
    uint8_t hash[32];
    sha256_buf(dkrd, dklen, hash);
    pthread_mutex_lock(&g_ta_mutex);
    for (int i = 0; i < g_trust_anchor_count; i++) {
        if (memcmp(hash, g_trust_anchors[i], 32) == 0) {
            pthread_mutex_unlock(&g_ta_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_ta_mutex);
    return 0;
}

/* Verify an ECDSA P-256 (alg 13) RRSIG.
 * sig_raw: 64-byte raw R||S (not DER).
 * data: the signing data (RRSIG header + canonical RR).
 * pubkey_xy: 64-byte X||Y from DNSKEY rdata (after 4-byte flags/proto/alg). */
static int verify_ecdsa_p256(const uint8_t *sig_raw, const uint8_t *data, int dlen,
                             const uint8_t pubkey_xy[64]) {
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    /* Convert 64-byte raw to DER ECDSA signature */
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig)
        return 0;
    BIGNUM *r = BN_bin2bn(sig_raw, 32, NULL);
    BIGNUM *s = BN_bin2bn(sig_raw + 32, 32, NULL);
    ECDSA_SIG_set0(sig, r, s);
    int derlen = i2d_ECDSA_SIG(sig, NULL);
    uint8_t *der = malloc(derlen);
    if (!der) {
        ECDSA_SIG_free(sig);
        return 0;
    }
    uint8_t *p = der;
    i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    /* Build EVP_PKEY from raw X||Y */
    uint8_t pub[65];
    pub[0] = 0x04;
    memcpy(pub + 1, pubkey_xy, 64);
    params[0] = OSSL_PARAM_construct_utf8_string("group", "P-256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("pub", pub, 65);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    int ok = 0;
    if (kctx && EVP_PKEY_fromdata_init(kctx) > 0 &&
        EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0 && pkey) {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) > 0 &&
            EVP_DigestVerifyUpdate(mctx, data, dlen) > 0 &&
            EVP_DigestVerifyFinal(mctx, der, derlen) == 1)
            ok = 1;
        EVP_MD_CTX_free(mctx);
    }
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    free(der);
    return ok;
}

/* Verify an Ed25519 (alg 15) RRSIG.
 * sig_raw: 64-byte Ed25519 signature.
 * pubkey: 32-byte raw Ed25519 public key. */
static int verify_ed25519(const uint8_t *sig_raw, const uint8_t *data, int dlen,
                          const uint8_t pubkey[32]) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32);
    if (!pkey)
        return 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int ok = (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey) > 0 &&
              EVP_DigestVerify(mctx, sig_raw, 64, data, dlen) == 1);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* =========================================================================
 * DNSSEC signing-input construction (RFC 4034 §3.1.8.1)
 *
 * The data a validator must verify is:
 *     RRSIG_RDATA (type covered .. signer name, i.e. without the signature)
 *  || canonical RRset (each RR: owner | type | class | original TTL |
 *                      rdlength | canonical rdata), sorted per §6.3.
 * ======================================================================= */

#define DNSSEC_MAX_RRS 16 /* max RRs in one verified RRset */
/* Number of labels in a dotted name ("" = root = 0). The leftmost "*" of an
 * already-wildcard owner does not count (RFC 4034 §3.1.3). */
static int name_label_count(const char *name) {
    if (name[0] == 0)
        return 0;
    int n = 1;
    for (const char *p = name; *p; p++) {
        if (*p == '.')
            n++;
    }
    if (name[0] == '*' && name[1] == '.')
        n--;
    return n;
}

/*
 * dnssec_verify_rrset — verify one RRset against its RRSIG.
 *
 * pkt, plen:   full response packet (for name decompression)
 * rr_offs:     packet offsets of each RR in the set (start of owner name)
 * rr_count:    number of RRs in the set (same owner+type+class)
 * rrsig_rdata: the RRSIG rdata bytes
 * rrsig_rdlen: length of rrsig_rdata
 * dnskey_rdata: the DNSKEY rdata of the signing key
 * dklen:       length of dnskey_rdata
 *
 * Returns 1 if valid, 0 if invalid, -1 if unsupported algorithm.
 */
static int dnssec_verify_rrset(const uint8_t *pkt, int plen, const int *rr_offs, int rr_count,
                               const uint8_t *rrsig_rdata, int rrsig_rdlen,
                               const uint8_t *dnskey_rdata, int dklen) {
    if (rrsig_rdlen < 18)
        return 0;
    if (rr_count < 1 || rr_count > DNSSEC_MAX_RRS)
        return 0;
    /* RRSIG RDATA layout (RFC 4034 §3.1): covered(2) alg(1) labels(1) ... */
    uint8_t alg = rrsig_rdata[2];
    if (alg != 13 && alg != 15)
        return -1; /* unsupported */
    uint16_t covered = get16(rrsig_rdata, 0);
    uint8_t sig_labels = rrsig_rdata[3];
    uint32_t orig_ttl = get32(rrsig_rdata, 4);
    /* Locate the end of the signer name inside the RRSIG rdata. */
    int snoff = 18; /* type(2)+alg(1)+labels(1)+orig_ttl(4)+sig_exp(4)+sig_inc(4)+key_tag(2) */
    if (snoff >= rrsig_rdlen)
        return 0;
    const uint8_t *sn = rrsig_rdata + snoff;
    int sn_end = 0;
    while (snoff + sn_end < rrsig_rdlen) {
        uint8_t l = sn[sn_end];
        if (l == 0) {
            sn_end++;
            break;
        }
        if ((l & 0xC0) == 0xC0)
            return 0; /* signer name must not be compressed (RFC 4034 §3.1.7) */
        sn_end += l + 1;
    }
    int hdr_len = snoff + sn_end;
    /* Signature bytes follow the header */
    if (hdr_len >= rrsig_rdlen)
        return 0;
    const uint8_t *sig = rrsig_rdata + hdr_len;
    int siglen = rrsig_rdlen - hdr_len;
    /* Public key is in DNSKEY rdata: flags(2)+proto(1)+alg(1)+pubkey */
    if (dklen < 4)
        return 0;
    const uint8_t *pubkey = dnskey_rdata + 4;
    int pklen = dklen - 4;
    if (alg == 13 && (siglen != 64 || pklen != 64))
        return 0;
    if (alg == 15 && (siglen != 64 || pklen != 32))
        return 0;
    /* Build the canonical form of every RR in the set. */
    canon_rr_t *rrs = calloc((size_t) rr_count, sizeof(canon_rr_t));
    if (!rrs)
        return 0;
    int ok = 0;
    for (int i = 0; i < rr_count; i++) {
        char oname[256];
        int a = name_from_wire(pkt, plen, rr_offs[i], oname, sizeof(oname));
        if (a < 0 || a + 10 > plen)
            goto out;
        uint16_t rtype = get16(pkt, a);
        uint16_t rclass = get16(pkt, a + 2);
        uint16_t rdlen = get16(pkt, a + 8);
        if (rtype != covered)
            goto out;
        if (a + 10 + (int) rdlen > plen)
            goto out;
        /* Wildcard expansion (RFC 4035 §5.3.2): if the owner has more labels
         * than the RRSIG labels field, the signed name was the wildcard —
         * reconstruct "*." + the rightmost <labels> labels. */
        const char *owner = oname;
        char wname[260];
        int olabels = name_label_count(oname);
        if (olabels < sig_labels)
            goto out;
        if (olabels > sig_labels) {
            const char *p = oname;
            for (int skip = olabels - (int) sig_labels; skip > 0; skip--) {
                p = strchr(p, '.');
                if (!p)
                    goto out;
                p++;
            }
            snprintf(wname, sizeof(wname), "*.%s", p);
            owner = wname;
        }
        /* owner | type | class | original TTL | rdlength | canonical rdata */
        int pos = name_to_wire(owner, rrs[i].buf, CANON_RR_MAX);
        if (pos < 0 || pos + 10 > CANON_RR_MAX)
            goto out;
        put16(rrs[i].buf, pos, rtype);
        put16(rrs[i].buf, pos + 2, rclass);
        put32(rrs[i].buf, pos + 4, orig_ttl);
        int clen = canon_rdata(pkt, plen, a + 10, rdlen, rtype, rrs[i].buf + pos + 10,
                               CANON_RR_MAX - pos - 10);
        if (clen < 0)
            goto out;
        put16(rrs[i].buf, pos + 8, (uint16_t) clen);
        rrs[i].len = pos + 10 + clen;
    }
    /* Sort into canonical order (insertion sort; the set is small). */
    for (int i = 1; i < rr_count; i++) {
        canon_rr_t tmp = rrs[i];
        int j = i - 1;
        while (j >= 0 && canon_rr_cmp(&rrs[j], &tmp) > 0) {
            rrs[j + 1] = rrs[j];
            j--;
        }
        rrs[j + 1] = tmp;
    }
    /* Assemble RRSIG header || canonical RRset and verify. */
    {
        size_t need = (size_t) hdr_len;
        for (int i = 0; i < rr_count; i++)
            need += (size_t) rrs[i].len;
        uint8_t *data = malloc(need);
        if (!data)
            goto out;
        memcpy(data, rrsig_rdata, (size_t) hdr_len);
        size_t off = (size_t) hdr_len;
        for (int i = 0; i < rr_count; i++) {
            memcpy(data + off, rrs[i].buf, (size_t) rrs[i].len);
            off += (size_t) rrs[i].len;
        }
        if (alg == 13)
            ok = verify_ecdsa_p256(sig, data, (int) need, pubkey);
        else
            ok = verify_ed25519(sig, data, (int) need, pubkey);
        free(data);
    }
out:
    free(rrs);
    return ok;
}

/* Query <name> for DNSKEY and copy the first DNSKEY rdata found into
 * dnskey_rd (capacity cap). Returns the rdata length, or 0 if none
 * found/unreachable. Shared by the positive- and negative-response
 * validators so the DNSKEY-fetch parse exists in exactly one place. */
static int dnssec_fetch_dnskey(const char *name, uint8_t *dnskey_rd, int cap) {
    uint8_t dkresp[DNS_BUF * 2];
    long rtt = 0;
    int dkrlen = upstream_query(name, 48 /*DNSKEY*/, dkresp, sizeof(dkresp), &rtt);
    if (dkrlen < 12)
        return 0;
    const dns_hdr_t *dkh = (const dns_hdr_t *) dkresp;
    int dkoff = 12;
    for (int i = 0; i < ntohs(dkh->qdcount) && dkoff < dkrlen; i++) {
        char tmp[256];
        dkoff = name_from_wire(dkresp, dkrlen, dkoff, tmp, sizeof(tmp));
        if (dkoff < 0)
            return 0;
        dkoff += 4;
    }
    for (int i = 0; i < ntohs(dkh->ancount) && dkoff < dkrlen; i++) {
        char rn[256];
        int a = name_from_wire(dkresp, dkrlen, dkoff, rn, sizeof(rn));
        if (a < 0 || a + 10 > dkrlen)
            break;
        uint16_t rt = get16(dkresp, a);
        uint16_t rdl = get16(dkresp, a + 8);
        if (rt == 48 && rdl > 0 && rdl <= (uint16_t) cap) {
            memcpy(dnskey_rd, dkresp + a + 10, rdl);
            return (int) rdl;
        }
        dkoff = a + 10 + (int) rdl;
    }
    return 0;
}

/*
 * dnssec_validate_response — validate RRSIG records in a DNS response.
 *
 * Fetches DNSKEY records if not present in the response.
 * Returns DNSSEC_SECURE, DNSSEC_INSECURE, or DNSSEC_BOGUS.
 */
static dnssec_status_t dnssec_validate_response(const uint8_t *resp, int rlen, const char *qname) {
    if (rlen < 12)
        return DNSSEC_INSECURE;
    const dns_hdr_t *h = (const dns_hdr_t *) resp;
    int ancount = ntohs(h->ancount);
    if (ancount == 0)
        return DNSSEC_INSECURE;
    /* Scan the answer section: record every RR's offset/owner/type, and grab
     * the RRSIG + DNSKEY rdata. */
    uint8_t rrsig_rd[512];
    int rrsig_rdlen = 0;
    char rrsig_owner[256] = {0};
    uint8_t dnskey_rd[128];
    int dnskey_rdlen = 0;
    int an_offs[DNSSEC_MAX_RRS];
    char an_names[DNSSEC_MAX_RRS][256];
    uint16_t an_types[DNSSEC_MAX_RRS];
    int an_n = 0;
    int off = 12;
    /* Skip question */
    for (int i = 0; i < ntohs(h->qdcount) && off < rlen; i++) {
        char tmp[256];
        off = name_from_wire(resp, rlen, off, tmp, sizeof(tmp));
        if (off < 0)
            return DNSSEC_INSECURE;
        off += 4;
    }
    for (int i = 0; i < ancount && off < rlen; i++) {
        char rname[256];
        int a = name_from_wire(resp, rlen, off, rname, sizeof(rname));
        if (a < 0 || a + 10 > rlen)
            break;
        uint16_t rtype = get16(resp, a);
        uint16_t rdlen = get16(resp, a + 8);
        if (a + 10 + (int) rdlen > rlen)
            break;
        if (rtype == DNS_TYPE_RRSIG && rrsig_rdlen == 0 && rdlen > 0 &&
            rdlen <= (int) sizeof(rrsig_rd)) {
            memcpy(rrsig_rd, resp + a + 10, rdlen);
            rrsig_rdlen = (int) rdlen;
            safe_strcpy(rrsig_owner, rname, sizeof(rrsig_owner));
        }
        if (rtype == DNS_TYPE_DNSKEY && rdlen > 0 && rdlen <= (int) sizeof(dnskey_rd)) {
            memcpy(dnskey_rd, resp + a + 10, rdlen);
            dnskey_rdlen = (int) rdlen;
        }
        if (an_n < DNSSEC_MAX_RRS) {
            an_offs[an_n] = off;
            an_types[an_n] = rtype;
            safe_strcpy(an_names[an_n], rname, sizeof(an_names[an_n]));
            an_names[an_n][sizeof(an_names[an_n]) - 1] = 0;
            an_n++;
        }
        off = a + 10 + (int) rdlen;
    }
    if (rrsig_rdlen == 0)
        return DNSSEC_INSECURE; /* no signature — zone not signed */
    if (rrsig_rdlen < 18)
        return DNSSEC_BOGUS;
    /* Select the RRset the RRSIG covers: same owner name + the covered type. */
    uint16_t covered = get16(rrsig_rd, 0);
    int rr_offs[DNSSEC_MAX_RRS];
    int rr_n = 0;
    for (int i = 0; i < an_n; i++) {
        if (an_types[i] == covered && strcmp(an_names[i], rrsig_owner) == 0)
            rr_offs[rr_n++] = an_offs[i];
    }
    if (rr_n == 0)
        return DNSSEC_BOGUS; /* signature over nothing present — fail closed */
    /* If no DNSKEY in response, fetch it */
    if (dnskey_rdlen == 0)
        dnskey_rdlen = dnssec_fetch_dnskey(qname, dnskey_rd, (int) sizeof(dnskey_rd));
    if (dnskey_rdlen == 0)
        return DNSSEC_INSECURE;
    /* Check trust anchor */
    if (!dnskey_is_trusted(dnskey_rd, dnskey_rdlen)) {
        /* Key not trusted — still validate signature, mark as insecure */
        int r = dnssec_verify_rrset(resp, rlen, rr_offs, rr_n, rrsig_rd, rrsig_rdlen, dnskey_rd,
                                    dnskey_rdlen);
        if (r == 0)
            return DNSSEC_BOGUS;
        return DNSSEC_INSECURE;
    }
    /* Key trusted — validate signature */
    int r = dnssec_verify_rrset(resp, rlen, rr_offs, rr_n, rrsig_rd, rrsig_rdlen, dnskey_rd,
                                dnskey_rdlen);
    if (r == 1)
        return DNSSEC_SECURE;
    if (r == 0)
        return DNSSEC_BOGUS;
    return DNSSEC_INSECURE; /* unsupported alg */
}

/* =========================================================================
 * RFC 8198 — aggressive use of the DNSSEC-validated negative cache
 *
 * A validated NXDOMAIN/NODATA response carries an NSEC or NSEC3 record that
 * proves a whole *range* of names doesn't exist (or that one name exists but
 * lacks a whole set of types). Once that proof is SECURE, later queries that
 * land in the same range can be answered from it without going upstream —
 * see aggressive_nsec_answer(), in the cache section below.
 * ======================================================================= */

/* One validated denial-of-existence span, extracted from a SECURE negative
 * response's authority section. */
typedef struct {
    int is_nsec3;
    char zone[256]; /* SOA owner name — a candidate qname must be inside this
                       zone before this span is even considered, so a proof
                       from one forwarded domain never leaks into another. */
    /* NSEC */
    char owner[256]; /* lowercased dotted */
    char next[256];  /* lowercased dotted; wraps to the zone apex at the end
                        of the chain (canon_name_cmp(next, owner) <= 0). */
    /* NSEC3 (RFC 5155) */
    uint8_t owner_hash[20];
    uint8_t next_hash[20];
    uint8_t nsec3_alg;
    uint16_t nsec3_iters;
    uint8_t nsec3_salt[64];
    int nsec3_saltlen;
    int optout; /* RFC 5155 §7.2.1 opt-out: never use this span to prove
                   non-existence — an unsigned delegation may live in the gap. */
    /* Type bitmap at the owner (NSEC or NSEC3), raw window-encoded bytes —
     * proves NODATA for the owner name itself when a queried type's bit is
     * clear. */
    uint8_t bitmap[128];
    int bitmap_len;
} nsec_proof_t;

#define MAX_NEG_PROOFS 4

/* RFC 4034 §4.1.2 windowed type bitmap: window(1) len(1) bits[len]. Returns
 * 1 if `type`'s bit is set, 0 if clear or the bitmap doesn't cover it. */
static int nsec_bitmap_has_type(const uint8_t *bm, int bmlen, uint16_t type) {
    int win = type / 256;
    int bit = type % 256;
    int off = 0;
    while (off + 2 <= bmlen) {
        int w = bm[off];
        int wl = bm[off + 1];
        if (off + 2 + wl > bmlen)
            break;
        if (w == win && bit / 8 < wl)
            return (bm[off + 2 + bit / 8] & (0x80 >> (bit % 8))) != 0;
        off += 2 + wl;
    }
    return 0;
}

/* Parse an NSEC or NSEC3 RR's rdata (at pkt+rdoff, length rdlen, owner name
 * already decoded) into *proof. Returns 1 on success, 0 on a malformed
 * record (fail closed — the caller must not use a partially-filled proof). */
static int nsec_parse_rdata(const uint8_t *pkt, int plen, const char *owner, uint16_t rtype,
                            int rdoff, int rdlen, nsec_proof_t *proof) {
    int rdend = rdoff + rdlen;
    if (rdend > plen || rdlen < 0)
        return 0;
    memset(proof, 0, sizeof(*proof));
    if (rtype == DNS_TYPE_NSEC) {
        char next[256];
        int after = name_from_wire(pkt, plen, rdoff, next, sizeof(next));
        if (after < 0 || after > rdend)
            return 0;
        proof->is_nsec3 = 0;
        safe_strcpy(proof->owner, owner, sizeof(proof->owner));
        safe_strcpy(proof->next, next, sizeof(proof->next));
        int bmlen = rdend - after;
        if (bmlen < 0)
            return 0;
        if (bmlen > (int) sizeof(proof->bitmap))
            bmlen = (int) sizeof(proof->bitmap);
        memcpy(proof->bitmap, pkt + after, bmlen);
        proof->bitmap_len = bmlen;
        return 1;
    }
    if (rtype == DNS_TYPE_NSEC3) {
        if (rdlen < 5)
            return 0;
        uint8_t alg = pkt[rdoff];
        uint8_t flags = pkt[rdoff + 1];
        uint16_t iters = get16(pkt, rdoff + 2);
        uint8_t saltlen = pkt[rdoff + 4];
        int p = rdoff + 5;
        if (saltlen > (int) sizeof(proof->nsec3_salt) || p + saltlen > rdend)
            return 0;
        uint8_t salt[64];
        memcpy(salt, pkt + p, saltlen);
        p += saltlen;
        if (p + 1 > rdend)
            return 0;
        uint8_t hashlen = pkt[p];
        p += 1;
        if (hashlen != 20 /* SHA-1 (alg 1) digest length */ || p + hashlen > rdend)
            return 0;
        if (alg != NSEC3_ALG_SHA1)
            return 0;
        proof->is_nsec3 = 1;
        proof->nsec3_alg = alg;
        proof->nsec3_iters = iters;
        proof->nsec3_saltlen = saltlen;
        memcpy(proof->nsec3_salt, salt, (size_t) saltlen);
        proof->optout = (flags & 0x01) != 0;
        memcpy(proof->next_hash, pkt + p, 20);
        p += 20;
        /* Owner hash is base32hex in the owner name's first label. */
        char label[64];
        const char *dot = strchr(owner, '.');
        size_t llen = dot ? (size_t) (dot - owner) : strlen(owner);
        if (llen == 0 || llen >= sizeof(label))
            return 0;
        memcpy(label, owner, llen);
        label[llen] = 0;
        if (base32hex_dec(label, proof->owner_hash, sizeof(proof->owner_hash)) != 20)
            return 0;
        int bmlen = rdend - p;
        if (bmlen < 0)
            return 0;
        if (bmlen > (int) sizeof(proof->bitmap))
            bmlen = (int) sizeof(proof->bitmap);
        memcpy(proof->bitmap, pkt + p, bmlen);
        proof->bitmap_len = bmlen;
        return 1;
    }
    return 0;
}

/*
 * dnssec_validate_negative — validate the denial-of-existence proof in a
 * NXDOMAIN/NODATA response's authority section (RFC 4035 §3.1.3, §5.4): the
 * SOA RRset and every NSEC/NSEC3 RRset present must each carry a signature
 * that verifies against a trusted key. On SECURE, every validated NSEC/NSEC3
 * span found is written to proofs[] (a real NXDOMAIN response can carry up to
 * three: closest-encloser, next-closer/covering, and wildcard denial — RFC
 * 5155 §7.2 — and aggressive lookup needs to try each independently, since
 * classifying which one is "the" covering span up front isn't reliable).
 */
static dnssec_status_t dnssec_validate_negative(const uint8_t *resp, int rlen, const char *qname,
                                                nsec_proof_t *proofs, int max_proofs,
                                                int *proof_count) {
    (void) qname;
    *proof_count = 0;
    if (rlen < 12)
        return DNSSEC_INSECURE;
    const dns_hdr_t *h = (const dns_hdr_t *) resp;
    int nscount = ntohs(h->nscount);
    if (nscount == 0)
        return DNSSEC_INSECURE;
    int off = 12;
    for (int i = 0; i < ntohs(h->qdcount) && off < rlen; i++) {
        char tmp[256];
        off = name_from_wire(resp, rlen, off, tmp, sizeof(tmp));
        if (off < 0)
            return DNSSEC_INSECURE;
        off += 4;
    }
    for (int i = 0; i < ntohs(h->ancount) && off < rlen; i++) {
        char tmp[256];
        int a = name_from_wire(resp, rlen, off, tmp, sizeof(tmp));
        if (a < 0 || a + 10 > rlen)
            return DNSSEC_INSECURE;
        off = a + 10 + (int) get16(resp, a + 8);
    }
    /* Scan the authority section once, recording every RR's owner-start
     * offset/owner/type/rdata (mirrors dnssec_validate_response's answer
     * scan). */
#define NEG_MAX_RRS 24
    int ns_start[NEG_MAX_RRS];
    int ns_rdoff[NEG_MAX_RRS];
    uint16_t ns_rdlen[NEG_MAX_RRS];
    char ns_names[NEG_MAX_RRS][256];
    uint16_t ns_types[NEG_MAX_RRS];
    int ns_n = 0;
    char zone[256] = {0};
    uint8_t dnskey_rd[128];
    int dnskey_rdlen = 0;
    for (int i = 0; i < nscount && off < rlen; i++) {
        int rr_start = off;
        char rname[256];
        int a = name_from_wire(resp, rlen, off, rname, sizeof(rname));
        if (a < 0 || a + 10 > rlen)
            break;
        uint16_t rtype = get16(resp, a);
        uint16_t rdlen = get16(resp, a + 8);
        if (a + 10 + (int) rdlen > rlen)
            break;
        if (rtype == DNS_TYPE_SOA && !zone[0])
            safe_strcpy(zone, rname, sizeof(zone));
        if (ns_n < NEG_MAX_RRS) {
            ns_start[ns_n] = rr_start;
            ns_rdoff[ns_n] = a + 10;
            ns_rdlen[ns_n] = rdlen;
            safe_strcpy(ns_names[ns_n], rname, sizeof(ns_names[ns_n]));
            ns_types[ns_n] = rtype;
            ns_n++;
        }
        off = a + 10 + (int) rdlen;
    }
    /* A negative response doesn't normally carry its zone's DNSKEY, but if
     * one happens to be glued into the additional section (mirrors the
     * in-band check dnssec_validate_response does on the answer section),
     * use it instead of an upstream round trip. */
    for (int i = 0; i < ntohs(h->arcount) && off < rlen; i++) {
        char rname[256];
        int a = name_from_wire(resp, rlen, off, rname, sizeof(rname));
        if (a < 0 || a + 10 > rlen)
            break;
        uint16_t rtype = get16(resp, a);
        uint16_t rdlen = get16(resp, a + 8);
        if (a + 10 + (int) rdlen > rlen)
            break;
        if (rtype == DNS_TYPE_DNSKEY && dnskey_rdlen == 0 && rdlen > 0 &&
            rdlen <= (int) sizeof(dnskey_rd)) {
            memcpy(dnskey_rd, resp + a + 10, rdlen);
            dnskey_rdlen = (int) rdlen;
        }
        off = a + 10 + (int) rdlen;
    }
    if (!zone[0])
        return DNSSEC_INSECURE; /* no SOA — not a well-formed denial proof */
    int soa_secure = 0, saw_bogus = 0;
    for (int i = 0; i < ns_n; i++) {
        if (ns_types[i] != DNS_TYPE_RRSIG)
            continue;
        const char *rname = ns_names[i];
        uint16_t rdlen = ns_rdlen[i];
        uint8_t rrsig_rd[512];
        if (rdlen < 18 || rdlen > (int) sizeof(rrsig_rd))
            continue;
        memcpy(rrsig_rd, resp + ns_rdoff[i], rdlen);
        uint16_t covered = get16(rrsig_rd, 0);
        if (covered != DNS_TYPE_SOA && covered != DNS_TYPE_NSEC && covered != DNS_TYPE_NSEC3)
            continue;
        int rr_offs[NEG_MAX_RRS];
        int rr_n = 0;
        int rdata_off = -1;
        uint16_t rdata_len = 0;
        for (int j = 0; j < ns_n; j++) {
            if (ns_types[j] == covered && strcmp(ns_names[j], rname) == 0) {
                rr_offs[rr_n++] = ns_start[j];
                if (rdata_off < 0) {
                    rdata_off = ns_rdoff[j];
                    rdata_len = ns_rdlen[j];
                }
            }
        }
        if (rr_n == 0)
            continue;
        if (dnskey_rdlen == 0)
            dnskey_rdlen = dnssec_fetch_dnskey(zone, dnskey_rd, (int) sizeof(dnskey_rd));
        if (dnskey_rdlen == 0)
            return DNSSEC_INSECURE;
        int r = dnssec_verify_rrset(resp, rlen, rr_offs, rr_n, rrsig_rd, rdlen, dnskey_rd,
                                    dnskey_rdlen);
        if (r == 0) {
            saw_bogus = 1;
            continue;
        }
        if (r == 1 && dnskey_is_trusted(dnskey_rd, dnskey_rdlen)) {
            if (covered == DNS_TYPE_SOA) {
                soa_secure = 1;
            } else if (*proof_count < max_proofs) {
                nsec_proof_t *pr = &proofs[*proof_count];
                if (nsec_parse_rdata(resp, rlen, rname, covered, rdata_off, rdata_len, pr)) {
                    safe_strcpy(pr->zone, zone, sizeof(pr->zone));
                    (*proof_count)++;
                }
            }
        }
        /* r == -1 (unsupported alg) or an untrusted key: neither bogus nor
         * securely proven — just doesn't contribute to SECURE. */
    }
    if (saw_bogus)
        return DNSSEC_BOGUS;
    if (soa_secure && *proof_count > 0)
        return DNSSEC_SECURE;
    return DNSSEC_INSECURE;
#undef NEG_MAX_RRS
}

/* =========================================================================
 * mDNS client — RFC 6762
 * For .local names: send multicast query to 224.0.0.251:5353 and collect
 * responses for 500 ms before returning.  Results are cached normally.
 * ======================================================================= */
#define MDNS_MCAST4_ADDR "224.0.0.251"
#define MDNS_MCAST6_ADDR "ff02::fb"
#define MDNS_CLIENT_PORT 5353
#define MDNS_COLLECT_MS 500 /* collect window in milliseconds */

/*
 * mdns_query — send a multicast DNS query and collect responses.
 * Returns the length of the last (or best) response in resp, or -1 on error.
 */
static int mdns_query(const char *qname, uint16_t qtype, uint8_t *resp, int resp_sz) {
    /* Build a plain mDNS query (no TSIG, no cookies, id=0) */
    uint8_t query[512];
    memset(query, 0, 12);
    dns_hdr_t *qh = (dns_hdr_t *) query;
    qh->id = 0;
    qh->flags = 0;
    qh->qdcount = htons(1);
    int off = 12;
    int n = name_to_wire(qname, query + off, sizeof(query) - off);
    if (n < 0)
        return -1;
    off += n;
    if (off + 4 > (int) sizeof(query))
        return -1;
    put16(query, off, qtype);
    off += 2;
    put16(query, off, DNS_CLASS_IN);
    off += 2;
    int qlen = off;

    /* Create IPv4 UDP socket */
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    /* Bind to mDNS port */
    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(MDNS_CLIENT_PORT);
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) < 0) {
        close(fd);
        return -1;
    }
    /* Set multicast TTL=255 */
    uint8_t ttl255 = 255;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl255, sizeof(ttl255));
    /* Join mDNS multicast group on all multicast-capable interfaces */
    struct ifaddrs *ifa = NULL;
    getifaddrs(&ifa);
    for (struct ifaddrs *i = ifa; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
            continue;
        if (!(i->ifa_flags & IFF_MULTICAST) || !(i->ifa_flags & IFF_UP))
            continue;
        struct ip_mreq mr = {0};
        inet_pton(AF_INET, MDNS_MCAST4_ADDR, &mr.imr_multiaddr);
        mr.imr_interface = ((struct sockaddr_in *) i->ifa_addr)->sin_addr;
        setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr));
    }
    if (ifa)
        freeifaddrs(ifa);
    /* Receive timeout: MDNS_COLLECT_MS */
    struct timeval tv;
    tv.tv_sec = MDNS_COLLECT_MS / 1000;
    tv.tv_usec = (MDNS_COLLECT_MS % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    /* Send to multicast group */
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MDNS_CLIENT_PORT);
    inet_pton(AF_INET, MDNS_MCAST4_ADDR, &dst.sin_addr);
    if (sendto(fd, query, qlen, 0, (struct sockaddr *) &dst, sizeof(dst)) < 0) {
        close(fd);
        return -1;
    }
    /* Collect responses until timeout */
    int best_rlen = -1;
    for (;;) {
        struct sockaddr_in src = {0};
        socklen_t srclen = sizeof(src);
        int rlen = (int) recvfrom(fd, resp, resp_sz, 0, (struct sockaddr *) &src, &srclen);
        if (rlen < 12)
            break;
        /* Accept if it's a response (QR=1) with at least one answer */
        uint16_t flags = get16(resp, 2);
        int ancount = get16(resp, 6);
        if ((flags & 0x8000) && ancount > 0) {
            best_rlen = rlen;
            break;
        }
    }
    close(fd);
    return best_rlen;
}

/* is_local_name — returns 1 if name ends with .local */
static int is_local_name(const char *name) {
    int n = (int) strlen(name);
    return n > 6 && strcasecmp(name + n - 6, ".local") == 0;
}

/* =========================================================================
 * TSIG: append a signed TSIG RR to a query
 * ======================================================================= */
static int tsig_sign_query(uint8_t *buf, int off, int blen, uint16_t orig_id) {
    if (g_cfg.tsig_secret_len == 0)
        return off;
    time_t now = time(NULL);
    /* TSIG variables */
    uint8_t vars[512];
    int vp = 0;
    /* key name in wire format */
    {
        char *sp2 = NULL;
        char tmp[256];
        safe_strcpy(tmp, g_cfg.tsig_key_name, sizeof(tmp));
        char *lbl = strtok_r(tmp, ".", &sp2);
        while (lbl) {
            int ll = (int) strlen(lbl);
            vars[vp++] = (uint8_t) ll;
            memcpy(vars + vp, lbl, ll);
            vp += ll;
            lbl = strtok_r(NULL, ".", &sp2);
        }
        vars[vp++] = 0;
    }
    vars[vp++] = 0;
    vars[vp++] = 255; /* class ANY */
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0; /* ttl=0 */
    const char *alg_wire = "\x0bhmac-sha256\x00";
    memcpy(vars + vp, alg_wire, 13);
    vp += 13;
    vars[vp++] = 0;
    vars[vp++] = 0; /* time high */
    vars[vp++] = (uint8_t) ((now >> 24) & 0xFF);
    vars[vp++] = (uint8_t) ((now >> 16) & 0xFF);
    vars[vp++] = (uint8_t) ((now >> 8) & 0xFF);
    vars[vp++] = (uint8_t) (now & 0xFF);
    vars[vp++] = TSIG_FUDGE >> 8;
    vars[vp++] = TSIG_FUDGE & 0xFF;
    vars[vp++] = 0;
    vars[vp++] = 0; /* error=0 */
    vars[vp++] = 0;
    vars[vp++] = 0; /* other len=0 */
    /* HMAC-SHA256 */
    uint8_t mac[32];
    size_t mlen = 32;
    EVP_MAC *evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(evp_mac);
    OSSL_PARAM params[2] = {OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                            OSSL_PARAM_construct_end()};
    EVP_MAC_init(mctx, g_cfg.tsig_secret, g_cfg.tsig_secret_len, params);
    EVP_MAC_update(mctx, buf, off);
    EVP_MAC_update(mctx, vars, vp);
    EVP_MAC_final(mctx, mac, &mlen, 32);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(evp_mac);
    if (off + 200 > blen)
        return off;
    /* key name */
    {
        char *sp3 = NULL;
        char tmp[256];
        safe_strcpy(tmp, g_cfg.tsig_key_name, sizeof(tmp));
        char *lbl = strtok_r(tmp, ".", &sp3);
        while (lbl) {
            int ll = (int) strlen(lbl);
            buf[off++] = (uint8_t) ll;
            memcpy(buf + off, lbl, ll);
            off += ll;
            lbl = strtok_r(NULL, ".", &sp3);
        }
        buf[off++] = 0;
    }
    buf[off++] = 0;
    buf[off++] = 250; /* TSIG */
    buf[off++] = 0;
    buf[off++] = 255; /* class ANY */
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0; /* ttl=0 */
    /* rdata */
    uint8_t rd[200];
    int rp = 0;
    memcpy(rd + rp, alg_wire, 13);
    rp += 13;
    rd[rp++] = 0;
    rd[rp++] = 0; /* time high */
    rd[rp++] = (uint8_t) ((now >> 24) & 0xFF);
    rd[rp++] = (uint8_t) ((now >> 16) & 0xFF);
    rd[rp++] = (uint8_t) ((now >> 8) & 0xFF);
    rd[rp++] = (uint8_t) (now & 0xFF);
    rd[rp++] = TSIG_FUDGE >> 8;
    rd[rp++] = TSIG_FUDGE & 0xFF;
    rd[rp++] = 0;
    rd[rp++] = (uint8_t) mlen;
    memcpy(rd + rp, mac, mlen);
    rp += mlen;
    rd[rp++] = orig_id >> 8;
    rd[rp++] = orig_id & 0xFF;
    rd[rp++] = 0;
    rd[rp++] = 0; /* error=0 */
    rd[rp++] = 0;
    rd[rp++] = 0; /* other=0 */
    buf[off++] = 0;
    buf[off++] = (uint8_t) rp;
    memcpy(buf + off, rd, rp);
    off += rp;
    dns_hdr_t *h = (dns_hdr_t *) buf;
    h->arcount = htons(ntohs(h->arcount) + 1);
    return off;
}

/* =========================================================================
 * DNS Cookies — client side (RFC 7873)
 *
 * Per upstream we keep a stable Client Cookie (so a cookie-enforcing server can
 * recognise us across queries) and the most recent Server Cookie it handed back.
 * On the first query to a server we have no Server Cookie, so it answers
 * BADCOOKIE (RCODE 23) and includes a fresh Server Cookie; we learn it and retry.
 * Subsequent queries carry the learned Server Cookie and are answered directly.
 * ======================================================================= */
static uint8_t g_client_cookie[MAX_UPSTREAMS][DNS_COOKIE_LEN];
static int g_client_cookie_set[MAX_UPSTREAMS];
static uint8_t g_server_cookie[MAX_UPSTREAMS][DNS_COOKIE_SERVER_MAX];
static int g_server_cookie_len[MAX_UPSTREAMS]; /* 0 = none learned yet */
static pthread_mutex_t g_cookie_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Stable Client Cookie for an upstream: SipHash(host, secret). RFC 7873 §4
 * recommends a Client Cookie that is constant per server but differs between
 * servers (avoids cross-server linkability). */
static void cookie_get_client(int idx, uint8_t out[DNS_COOKIE_LEN]) {
    pthread_mutex_lock(&g_cookie_mutex);
    if (!g_client_cookie_set[idx]) {
        const char *host = g_cfg.upstream_host[idx];
        uint64_t h = siphash24((const uint8_t *) host, strlen(host), g_cfg.cookie_secret);
        memcpy(g_client_cookie[idx], &h, DNS_COOKIE_LEN);
        g_client_cookie_set[idx] = 1;
    }
    memcpy(out, g_client_cookie[idx], DNS_COOKIE_LEN);
    pthread_mutex_unlock(&g_cookie_mutex);
}

/* Copy the learned Server Cookie for an upstream into out (max
 * DNS_COOKIE_SERVER_MAX). Returns its length, or 0 if none learned. */
static int cookie_get_server(int idx, uint8_t *out) {
    pthread_mutex_lock(&g_cookie_mutex);
    int len = g_server_cookie_len[idx];
    if (len > 0)
        memcpy(out, g_server_cookie[idx], (size_t) len);
    pthread_mutex_unlock(&g_cookie_mutex);
    return len;
}

static void cookie_store_server(int idx, const uint8_t *scookie, int slen) {
    if (slen <= 0 || slen > DNS_COOKIE_SERVER_MAX)
        return;
    pthread_mutex_lock(&g_cookie_mutex);
    memcpy(g_server_cookie[idx], scookie, (size_t) slen);
    g_server_cookie_len[idx] = slen;
    pthread_mutex_unlock(&g_cookie_mutex);
}

/* Walk a response's OPT RR. Returns the 12-bit extended RCODE (combining the
 * header's low nibble with the OPT TTL's high byte — needed because BADCOOKIE=23
 * does not fit the 4-bit header field), or the basic header RCODE if there is no
 * OPT. If a COOKIE option is present, the Server Cookie portion (the bytes after
 * the 8-byte Client Cookie, 8..32 bytes) is copied into the scookie/slen outs.
 * Bounds-checked throughout; fails toward "no cookie" on any malformed input. */
static int response_opt_parse(const uint8_t *pkt, int plen, uint8_t *scookie, int *slen) {
    *slen = 0;
    if (plen < 12)
        return -1;
    const dns_hdr_t *h = (const dns_hdr_t *) pkt;
    int rcode = ntohs(h->flags) & DNS_RCODE_MASK;
    int off = 12;
    char nm[256];
    /* Question section */
    for (int i = 0; i < ntohs(h->qdcount); i++) {
        off = name_from_wire(pkt, plen, off, nm, sizeof(nm));
        if (off < 0 || off + 4 > plen)
            return rcode;
        off += 4;
    }
    /* Answer + authority RRs — skip over rdata */
    int skip = ntohs(h->ancount) + ntohs(h->nscount);
    for (int i = 0; i < skip; i++) {
        off = name_from_wire(pkt, plen, off, nm, sizeof(nm));
        if (off < 0 || off + 10 > plen)
            return rcode;
        int rdl = get16(pkt, off + 8);
        off += 10 + rdl;
        if (off > plen)
            return rcode;
    }
    /* Additional RRs — look for OPT */
    for (int i = 0; i < ntohs(h->arcount); i++) {
        off = name_from_wire(pkt, plen, off, nm, sizeof(nm));
        if (off < 0 || off + 10 > plen)
            return rcode;
        uint16_t rtype = get16(pkt, off);
        int rdl = get16(pkt, off + 8);
        if (rtype == DNS_TYPE_OPT) {
            int ext_rcode = pkt[off + 4]; /* OPT TTL high byte = extended RCODE */
            rcode = (ext_rcode << 4) | (rcode & 0x0F);
            int rp = off + 10;
            int end = rp + rdl;
            while (rp + 4 <= end && rp + 4 <= plen) {
                uint16_t oc = get16(pkt, rp);
                uint16_t ol = get16(pkt, rp + 2);
                rp += 4;
                if (rp + ol > plen)
                    break;
                if (oc == EDNS_OPT_COOKIE && ol > DNS_COOKIE_LEN) {
                    int sl = ol - DNS_COOKIE_LEN;
                    if (sl > DNS_COOKIE_SERVER_MAX)
                        sl = DNS_COOKIE_SERVER_MAX;
                    memcpy(scookie, pkt + rp + DNS_COOKIE_LEN, (size_t) sl);
                    *slen = sl;
                }
                rp += ol;
            }
        }
        off += 10 + rdl;
        if (off > plen)
            return rcode;
    }
    return rcode;
}

/* CSPRNG 16-bit value for transaction IDs and source ports — the resolver's
 * primary anti-spoofing entropy (RFC 5452). rand()/srand(time()) is predictable;
 * fall back to it only if OpenSSL's RNG ever fails (it should not). */
static uint16_t csprng_u16(void) {
    uint16_t v;
    if (RAND_bytes((unsigned char *) &v, sizeof(v)) == 1)
        return v;
    return (uint16_t) rand();
}

/* Two DNS names equal ignoring case and a single trailing dot. */
static int names_equal_nocase(const char *a, const char *b) {
    size_t la = strlen(a);
    size_t lb = strlen(b);
    if (la && a[la - 1] == '.')
        la--;
    if (lb && b[lb - 1] == '.')
        lb--;
    return la == lb && strncasecmp(a, b, la) == 0;
}

/* RFC 5452 §2.2 0x20 case randomization: mix the outbound QNAME's letter case
 * so an off-path attacker must also guess this query's case pattern, not just
 * the ID and source port. Fresh randomness per call — case-flip decisions are
 * independent of any previous query, so replaying an old pattern doesn't help
 * a forger. Non-letters pass through unchanged. */
static void dns0x20_mix(const char *qname, char *out, size_t outsz) {
    size_t n = strlen(qname);
    if (n >= outsz)
        n = outsz - 1;
    uint8_t bits[32];
    if (RAND_bytes(bits, (int) sizeof(bits)) != 1)
        memset(bits, 0, sizeof(bits)); /* fail closed to "no mixing", never UB */
    int bi = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) qname[i];
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char) (c - 'A' + 'a');
        if (c >= 'a' && c <= 'z') {
            int byte = bi / 8, bit = bi % 8;
            if (byte < (int) sizeof(bits) && (bits[byte] & (1 << bit)))
                c = (unsigned char) (c - 'a' + 'A');
            bi++;
        }
        out[i] = (char) c;
    }
    out[n] = 0;
}

/* True if 0x20 is active for this upstream: globally enabled and not listed in
 * DNS0X20_DISABLE (RFC 5452 guardrail — some upstreams demonstrably break on
 * mixed-case QNAMEs; keep a per-upstream opt-out rather than an all-or-nothing
 * switch). */
static int dns0x20_active_for(int upstream_idx) {
    if (!g_cfg.dns0x20_enabled)
        return 0;
    if (!g_cfg.dns0x20_disable[0])
        return 1;
    char list[512];
    safe_strcpy(list, g_cfg.dns0x20_disable, sizeof(list));
    char *sp = NULL;
    for (char *tok = strtok_r(list, ",", &sp); tok; tok = strtok_r(NULL, ",", &sp)) {
        while (*tok == ' ')
            tok++;
        if (strcasecmp(tok, g_cfg.upstream_host[upstream_idx]) == 0)
            return 0;
    }
    return 1;
}

/* Read the question-section QNAME preserving case (name_from_wire in
 * libdnswire always lowercases — correct for cache keys/comparisons
 * everywhere else, but it destroys the very case information 0x20 needs to
 * verify). Rejects any compression pointer: the question section is the
 * first thing after the 12-byte header, so nothing earlier in the message is
 * a valid backward target — a conforming server never compresses it, and a
 * forger inserting a pointer here is exactly the case to reject, not follow. */
static int qname_from_wire_case_preserving(const uint8_t *pkt, int plen, char *out, int outsz) {
    int off = 12, oi = 0;
    while (off < plen) {
        int lablen = pkt[off];
        if (lablen & 0xC0)
            return -1;
        if (lablen == 0) {
            off++;
            break;
        }
        if (off + 1 + lablen > plen)
            return -1;
        if (oi > 0) {
            if (oi + 1 >= outsz)
                return -1;
            out[oi++] = '.';
        }
        if (oi + lablen >= outsz)
            return -1;
        memcpy(out + oi, pkt + off + 1, (size_t) lablen);
        oi += lablen;
        off += 1 + lablen;
    }
    out[oi] = 0;
    return off;
}

/* RFC 5452 response acceptance: a reply is trusted only if its transaction ID
 * matches the query, the QR bit is set, and the question section echoes the asked
 * QNAME (case-insensitive), QTYPE, and QCLASS. Without this an off-path spoofer
 * only has to guess the 16-bit source port; with it they must also guess the
 * 16-bit ID. When enforce_case is set (0x20 was applied to this query),
 * additionally require the echoed QNAME to match sent_qname byte-for-byte in
 * case — a forger who doesn't see the query never learns the exact pattern,
 * so any mismatch here is treated as a forged/stray packet and dropped. */
static int response_matches_query(const uint8_t *resp, int rlen, uint16_t id,
                                  const char *sent_qname, uint16_t qtype, int enforce_case) {
    if (rlen < 12)
        return 0;
    if (get16(resp, 0) != id)
        return 0;
    if (!(get16(resp, 2) & DNS_QR))
        return 0;
    if (get16(resp, 4) < 1)
        return 0; /* qdcount */
    char rqname[256];
    int off = name_from_wire(resp, rlen, 12, rqname, sizeof(rqname));
    if (off < 0 || off + 4 > rlen)
        return 0;
    if (get16(resp, off) != qtype)
        return 0;
    if (get16(resp, off + 2) != DNS_CLASS_IN) /* we only ever ask IN */
        return 0;
    if (!names_equal_nocase(rqname, sent_qname))
        return 0;
    if (enforce_case) {
        char rqname_cs[256];
        if (qname_from_wire_case_preserving(resp, rlen, rqname_cs, sizeof(rqname_cs)) < 0)
            return 0;
        /* Strip a single trailing dot from each side before comparing, same
         * convention as names_equal_nocase — sent_qname may or may not carry
         * one depending on the caller. */
        size_t rl = strlen(rqname_cs), sl = strlen(sent_qname);
        if (rl && rqname_cs[rl - 1] == '.')
            rl--;
        if (sl && sent_qname[sl - 1] == '.')
            sl--;
        if (rl != sl || strncmp(rqname_cs, sent_qname, rl) != 0)
            return 0;
    }
    return 1;
}

/* =========================================================================
 * EDNS(0) + DNS Cookie
 * ======================================================================= */
static int edns_append(uint8_t *buf, int off, int blen, int do_bit, int upstream_idx) {
    if (off + 11 > blen)
        return off;
    buf[off++] = 0; /* root name */
    buf[off++] = 0;
    buf[off++] = 41; /* OPT */
    uint16_t udp_sz = 1232;
    buf[off++] = udp_sz >> 8;
    buf[off++] = udp_sz & 0xFF;
    buf[off++] = 0;
    buf[off++] = 0; /* extended rcode+version */
    buf[off++] = do_bit ? 0x80 : 0x00;
    buf[off++] = 0; /* DO bit */
    /* RDATA: DNS Cookie option (RFC 7873) — stable Client Cookie for this
     * upstream, plus the learned Server Cookie (if any) so a cookie-enforcing
     * server answers directly instead of with BADCOOKIE. */
    int rdata_off = off + 2;
    int rdata_len = 0;
    uint8_t ccookie[DNS_COOKIE_LEN];
    cookie_get_client(upstream_idx, ccookie);
    uint8_t scookie[DNS_COOKIE_SERVER_MAX];
    int slen = cookie_get_server(upstream_idx, scookie);
    int cookie_opt_len = DNS_COOKIE_LEN + slen; /* 8 + 0..32 */
    if (rdata_off + 4 + cookie_opt_len < blen) {
        put16(buf, rdata_off, EDNS_OPT_COOKIE);
        put16(buf, rdata_off + 2, (uint16_t) cookie_opt_len);
        memcpy(buf + rdata_off + 4, ccookie, DNS_COOKIE_LEN);
        if (slen > 0)
            memcpy(buf + rdata_off + 4 + DNS_COOKIE_LEN, scookie, (size_t) slen);
        rdata_off += 4 + cookie_opt_len;
        rdata_len += 4 + cookie_opt_len;
    }
    put16(buf, off, (uint16_t) rdata_len);
    off = rdata_off;
    dns_hdr_t *h = (dns_hdr_t *) buf;
    h->arcount = htons(ntohs(h->arcount) + 1);
    return off;
}

/* =========================================================================
 * Transport: build query, send, receive response
 * ======================================================================= */
static int build_query(uint8_t *buf, int blen, const char *qname, uint16_t qtype, uint16_t id,
                       int do_bit, int upstream_idx) {
    if (blen < 12)
        return -1;
    memset(buf, 0, 12);
    dns_hdr_t *h = (dns_hdr_t *) buf;
    h->id = htons(id);
    h->flags = htons(DNS_RD); /* recursion desired */
    h->qdcount = htons(1);
    int off = 12;
    int n = name_to_wire(qname, buf + off, blen - off);
    if (n < 0)
        return -1;
    off += n;
    if (off + 4 > blen)
        return -1;
    put16(buf, off, qtype);
    off += 2;
    put16(buf, off, DNS_CLASS_IN);
    off += 2;
    off = edns_append(buf, off, blen, do_bit, upstream_idx);
    off = tsig_sign_query(buf, off, blen, id);
    return off;
}

/* Bind the expected peer identity to a client SSL so the handshake fails on a
 * certificate that does not match `host`. SSL_set_tlsext_host_name() only sets the
 * SNI extension — it does NOT verify the cert, which left DoT/DoH open to MITM by
 * any CA-valid cert (CSA-TLS-002). SSL_set1_host checks DNS names only, so an IP
 * literal upstream is verified via set1_ip against the cert's IP SANs instead. */
static void tls_verify_peer_name(SSL *ssl, const char *host) {
    X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    unsigned char addr[16];
    if (inet_pton(AF_INET, host, addr) == 1 || inet_pton(AF_INET6, host, addr) == 1)
        X509_VERIFY_PARAM_set1_ip_asc(vp, host);
    else
        X509_VERIFY_PARAM_set1_host(vp, host, 0);
}

/* Open a DoT connection to the upstream server */
static SSL *dot_connect(int *fd_out) {
    struct addrinfo hints = {0}, *res;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", g_cfg.upstream_port[0]);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_cfg.upstream_host[0], ps, &hints, &res) != 0)
        return NULL;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return NULL;
    }
    struct timeval tv = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);
    SSL *ssl = SSL_new(g_dot_ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, g_cfg.upstream_host[0]);
    tls_verify_peer_name(ssl, g_cfg.upstream_host[0]);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }
    *fd_out = fd;
    return ssl;
}

/* Send a query over TCP or DoT (with 2-byte length prefix) */
static int tcp_query(const uint8_t *query, int qlen, uint8_t *resp, int resp_sz, int use_dot) {
    int fd = -1;
    SSL *ssl = NULL;
    if (use_dot) {
        ssl = dot_connect(&fd);
        if (!ssl)
            return -1;
    } else {
        struct addrinfo hints = {0}, *res;
        char ps[8];
        snprintf(ps, sizeof(ps), "%d", g_cfg.upstream_port[0]);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(g_cfg.upstream_host[0], ps, &hints, &res) != 0)
            return -1;
        fd = socket(res->ai_family, res->ai_socktype, 0);
        if (fd < 0) {
            freeaddrinfo(res);
            return -1;
        }
        struct timeval tv = {.tv_sec = 5};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        freeaddrinfo(res);
    }
    /* send with 2-byte length prefix */
    uint8_t lb[2];
    lb[0] = qlen >> 8;
    lb[1] = qlen & 0xFF;
    int ok;
    if (ssl) {
        ok = (SSL_write(ssl, lb, 2) == 2 && SSL_write(ssl, query, qlen) == qlen);
    } else {
        ok = (send(fd, lb, 2, MSG_NOSIGNAL) == 2 && send(fd, query, qlen, MSG_NOSIGNAL) == qlen);
    }
    if (!ok) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(fd);
        return -1;
    }
    /* receive response */
    uint8_t rl[2];
    int got = 0;
    while (got < 2) {
        int n = ssl ? SSL_read(ssl, rl + got, 2 - got) : (int) recv(fd, rl + got, 2 - got, 0);
        if (n <= 0)
            goto fail;
        got += n;
    }
    int rlen = (rl[0] << 8) | rl[1];
    if (rlen < 12 || rlen > resp_sz)
        goto fail;
    got = 0;
    while (got < rlen) {
        int n =
            ssl ? SSL_read(ssl, resp + got, rlen - got) : (int) recv(fd, resp + got, rlen - got, 0);
        if (n <= 0)
            goto fail;
        got += n;
    }
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(fd);
    return rlen;
fail:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(fd);
    return -1;
}

/* =========================================================================
 * DNS-over-HTTPS client (RFC 8484)
 *
 * Sends a POST to /.well-known/dns-query (or g_cfg.doh_path) with:
 *   Content-Type: application/dns-message
 *   Body: raw DNS wire-format query
 *
 * Receives HTTP/1.1 response; body is raw DNS wire-format response.
 * Uses the same SSL context as DoT (g_dot_ctx).
 * No HTTP/2 or external library required.
 * ======================================================================= */
static int doh_query_on(const char *host, int port, const char *path, const uint8_t *query,
                        int qlen, uint8_t *resp, int resp_sz) {
    struct addrinfo hints = {0}, *res;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = {.tv_sec = 10};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    /* TLS handshake */
    if (!g_dot_ctx) {
        close(fd);
        return -1;
    }
    SSL *ssl = SSL_new(g_dot_ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    tls_verify_peer_name(ssl, host);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    /* Build HTTP/1.1 POST request */
    char req[1024];
    int rp = 0;
    rp += snprintf(req + rp, sizeof(req) - rp,
                   "POST %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Content-Type: application/dns-message\r\n"
                   "Accept: application/dns-message\r\n"
                   "Content-Length: %d\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   path, host, qlen);
    /* Send headers */
    int sent = 0;
    while (sent < rp) {
        int n = SSL_write(ssl, req + sent, rp - sent);
        if (n <= 0)
            goto fail;
    }
    /* Send DNS wire body */
    sent = 0;
    while (sent < qlen) {
        int n = SSL_write(ssl, (const char *) query + sent, qlen - sent);
        if (n <= 0)
            goto fail;
        sent += n;
    }
    /* Read HTTP response — collect everything */
    char *rbuf = malloc(resp_sz + 4096);
    int rtotal = 0;
    if (!rbuf)
        goto fail;
    for (;;) {
        int n = SSL_read(ssl, rbuf + rtotal, resp_sz + 4096 - rtotal - 1);
        if (n <= 0)
            break;
        rtotal += n;
    }
    rbuf[rtotal] = 0;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    /* Parse HTTP status line */
    int status = 0;
    sscanf(rbuf, "HTTP/1.%*c %d", &status);
    if (status != 200) {
        free(rbuf);
        return -1;
    }
    /* Find end of headers */
    char *body = strstr(rbuf, "\r\n\r\n");
    if (!body) {
        free(rbuf);
        return -1;
    }
    body += 4;
    /* Content-Length tells us the DNS response size */
    int clen = -1;
    char *cl = strcasestr(rbuf, "Content-Length:");
    if (cl)
        clen = atoi(cl + 15);
    int blen = (int) (rtotal - (int) (body - rbuf));
    if (clen > 0 && clen < blen)
        blen = clen;
    if (blen < 12 || blen > resp_sz) {
        free(rbuf);
        return -1;
    }
    memcpy(resp, body, blen);
    free(rbuf);
    return blen;
fail:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return -1;
}

/* =========================================================================
 * Route table helpers
 * ======================================================================= */

/*
 * route_find — longest-suffix match for qname.
 * Returns the upstream index to use, or -1 if no route matches
 * (caller falls back to EMA-sorted upstream selection).
 *
 * Matching rules (same as dnsmasq):
 *   suffix "."        matches any name (catch-all)
 *   suffix "corp.local"  matches "corp.local" and "*.corp.local"
 */
static int route_find(const char *qname) {
    int best_idx = -1;
    size_t best_len = 0;
    pthread_mutex_lock(&g_route_mutex);
    for (int i = 0; i < g_route_count; i++) {
        const char *sfx = g_routes[i].suffix;
        /* Catch-all "." matches everything */
        if (sfx[0] == '.' && sfx[1] == '\0') {
            if (best_len == 0) {
                best_idx = g_routes[i].upstream_idx;
                best_len = 1;
            }
            continue;
        }
        size_t sl = strlen(sfx), ql = strlen(qname);
        int match = 0;
        if (sl == ql && strcasecmp(qname, sfx) == 0)
            match = 1;
        else if (ql > sl + 1 && qname[ql - sl - 1] == '.' && strcasecmp(qname + ql - sl, sfx) == 0)
            match = 1;
        if (match && sl > best_len) {
            best_idx = g_routes[i].upstream_idx;
            best_len = sl;
        }
    }
    pthread_mutex_unlock(&g_route_mutex);
    return best_idx;
}

/*
 * route_add — add or replace a routing entry.
 * If host:port:proto is non-NULL and not already in the upstream table,
 * it is appended first.  Returns the upstream index used, or -1 on error.
 */
static int route_add(const char *suffix, const char *host, int port, upstream_proto_t proto) {
    /* Normalise suffix: strip leading/trailing dots except standalone "." */
    char sfx[256];
    safe_strcpy(sfx, suffix, sizeof(sfx));
    strlower(sfx);
    int slen = (int) strlen(sfx);
    while (slen > 1 && sfx[slen - 1] == '.') {
        sfx[--slen] = 0;
    }

    /* Find or add upstream */
    int uidx = -1;
    for (int i = 0; i < g_cfg.upstream_count; i++) {
        if (strcasecmp(g_cfg.upstream_host[i], host) == 0 && g_cfg.upstream_port[i] == port &&
            g_cfg.upstream_proto[i] == proto) {
            uidx = i;
            break;
        }
    }
    if (uidx < 0) {
        if (g_cfg.upstream_count >= MAX_UPSTREAMS)
            return -1;
        uidx = g_cfg.upstream_count;
        safe_strcpy(g_cfg.upstream_host[uidx], host, sizeof(g_cfg.upstream_host[uidx]));
        g_cfg.upstream_port[uidx] = port;
        g_cfg.upstream_proto[uidx] = proto;
        g_cfg.upstream_count++;
    }

    /* Find or add route */
    pthread_mutex_lock(&g_route_mutex);
    int ridx = -1;
    for (int i = 0; i < g_route_count; i++) {
        if (strcasecmp(g_routes[i].suffix, sfx) == 0) {
            ridx = i;
            break;
        }
    }
    if (ridx < 0) {
        if (g_route_count >= MAX_ROUTES) {
            pthread_mutex_unlock(&g_route_mutex);
            return -1;
        }
        ridx = g_route_count++;
    }
    safe_strcpy(g_routes[ridx].suffix, sfx, sizeof(g_routes[ridx].suffix));
    g_routes[ridx].upstream_idx = uidx;
    pthread_mutex_unlock(&g_route_mutex);
    return uidx;
}

/*
 * parse_server_arg — parse dnsmasq-style /suffix/host:port[:proto] string.
 * Also accepts "suffix=host:port[:proto]" (env-var style).
 * Returns 1 on success.
 */
static int parse_server_arg(const char *arg) {
    char buf[512];
    safe_strcpy(buf, arg, sizeof(buf));
    char *suffix = buf, *hostpart = NULL;

    if (buf[0] == '/') {
        /* /suffix/host:port[:proto] */
        suffix = buf + 1;
        char *sl = strchr(suffix, '/');
        if (!sl)
            return 0;
        *sl = 0;
        hostpart = sl + 1;
    } else {
        /* suffix=host:port[:proto] */
        char *eq = strchr(buf, '=');
        if (!eq)
            return 0;
        *eq = 0;
        hostpart = eq + 1;
    }
    /* Parse host:port[:proto] */
    char host[256] = "";
    int port = 53;
    upstream_proto_t proto = PROTO_UDP;
    char *col = strchr(hostpart, ':');
    if (col) {
        int hlen = (int) (col - hostpart);
        if (hlen > 255)
            hlen = 255;
        memcpy(host, hostpart, hlen);
        host[hlen] = 0; /* exact-length prefix copy */
        char *col2 = strchr(col + 1, ':');
        if (col2) {
            port = atoi(col + 1);
            if (!strcasecmp(col2 + 1, "dot"))
                proto = PROTO_DOT;
            else if (!strcasecmp(col2 + 1, "tcp"))
                proto = PROTO_TCP;
            else if (!strcasecmp(col2 + 1, "doh"))
                proto = PROTO_DOH;
        } else {
            port = atoi(col + 1);
        }
    } else {
        safe_strcpy(host, hostpart, sizeof(host));
    }
    if (!host[0])
        return 0;
    return route_add(suffix, host, port, proto) >= 0 ? 1 : 0;
}

/* Send one already-built query over the current upstream's transport (g_cfg.proto
 * + slot 0, set by the caller). Returns response length or -1. Factored out so
 * the RFC 7873 BADCOOKIE retry can resend without duplicating the transport
 * fan-out. */
static int upstream_dispatch(const uint8_t *query, int qlen, uint8_t *resp, int resp_sz) {
    int rlen = -1;
    if (g_cfg.proto == PROTO_DOT)
        rlen = tcp_query(query, qlen, resp, resp_sz, 1);
    else if (g_cfg.proto == PROTO_TCP)
        rlen = tcp_query(query, qlen, resp, resp_sz, 0);
    else if (g_cfg.proto == PROTO_DOH) {
        const char *doh_path = g_cfg.doh_path[0] ? g_cfg.doh_path : "/dns-query";
        rlen = doh_query_on(g_cfg.upstream_host[0], g_cfg.doh_port ? g_cfg.doh_port : 443, doh_path,
                            query, qlen, resp, resp_sz);
    } else {
        struct addrinfo hints = {0}, *res;
        char ps[8];
        snprintf(ps, sizeof(ps), "%d", g_cfg.upstream_port[0]);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(g_cfg.upstream_host[0], ps, &hints, &res) == 0) {
            int fd = socket(res->ai_family, res->ai_socktype, 0);
            if (fd >= 0) {
                /* Random source port */
                struct sockaddr_storage local = {0};
                local.ss_family = (sa_family_t) res->ai_family;
                for (int a = 0; a < 16; a++) {
                    uint16_t sp = (uint16_t) (1024 + (csprng_u16() % 64511));
                    if (local.ss_family == AF_INET)
                        ((struct sockaddr_in *) &local)->sin_port = htons(sp);
                    else
                        ((struct sockaddr_in6 *) &local)->sin6_port = htons(sp);
                    int o2 = 1;
                    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &o2, sizeof(o2));
                    if (bind(fd, (struct sockaddr *) &local,
                             (socklen_t) (local.ss_family == AF_INET
                                              ? sizeof(struct sockaddr_in)
                                              : sizeof(struct sockaddr_in6))) == 0)
                        break;
                }
                struct timeval tv2 = {.tv_sec = 3};
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
                if (connect(fd, res->ai_addr, res->ai_addrlen) == 0 &&
                    send(fd, query, qlen, 0) == qlen)
                    rlen = (int) recv(fd, resp, resp_sz, 0);
                close(fd);
                if (rlen >= 2 && (get16(resp, 2) & DNS_TC))
                    rlen = tcp_query(query, qlen, resp, resp_sz, 0);
            }
            freeaddrinfo(res);
        }
    }
    return rlen;
}

/* Send a query to one specific upstream (by index). Returns rlen or -1. */
static int upstream_query_one(const char *qname, uint16_t qtype, uint8_t *resp, int resp_sz,
                              int upstream_idx, long *rtt_us_out) {
    uint16_t id = csprng_u16();
    uint8_t query[DNS_BUF];
    /* Temporarily point g_cfg to this upstream for build_query/tcp_query */
    /* (they read g_cfg.upstream_host/port/proto) */
    char saved_host[256];
    int saved_port;
    upstream_proto_t saved_proto;
    safe_strcpy(saved_host, g_cfg.upstream_host[0], sizeof(saved_host));
    saved_port = g_cfg.upstream_port[0];
    saved_proto = g_cfg.proto;
    /* Point slot 0 at the chosen upstream. Skip the copy when it IS slot 0:
     * safe_strcpy() is strncpy-based, and strncpy with src==dst is undefined
     * behaviour (ASan: strncpy-param-overlap) — querying the primary upstream
     * would otherwise abort. */
    if (upstream_idx != 0)
        safe_strcpy(g_cfg.upstream_host[0], g_cfg.upstream_host[upstream_idx],
                    sizeof(g_cfg.upstream_host[0]));
    g_cfg.upstream_port[0] = g_cfg.upstream_port[upstream_idx];
    g_cfg.proto = g_cfg.upstream_proto[upstream_idx];
    /* RFC 5452 §2.2 0x20: wire-encode (and later verify) a case-mixed QNAME
     * instead of the plain one when this upstream hasn't opted out. qname
     * itself is left untouched — callers outside this function (cache keys,
     * logging) still see the original case. */
    int use_0x20 = dns0x20_active_for(upstream_idx);
    char qname_sent[256];
    if (use_0x20)
        dns0x20_mix(qname, qname_sent, sizeof(qname_sent));
    else
        safe_strcpy(qname_sent, qname, sizeof(qname_sent));
    int qlen = build_query(query, sizeof(query), qname_sent, qtype, id, 1, upstream_idx);
    int rlen = -1;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rlen = upstream_dispatch(query, qlen, resp, resp_sz);
    /* RFC 5452: drop any reply whose ID/question does not match what we asked —
     * fail closed so a spoofed or stray packet is never cached or trusted. */
    if (rlen >= 12 && !response_matches_query(resp, rlen, id, qname_sent, qtype, use_0x20))
        rlen = -1;
    /* RFC 7873: learn the Server Cookie from the (now validated) response; if the
     * upstream rejected us with BADCOOKIE (no/stale Server Cookie), retry once
     * carrying the fresh one (new ID). Subsequent queries reuse the stored cookie
     * via edns_append, so this round trip happens at most once per upstream. */
    if (rlen >= 12) {
        uint8_t scookie[DNS_COOKIE_SERVER_MAX];
        int slen = 0;
        int full_rcode = response_opt_parse(resp, rlen, scookie, &slen);
        if (slen > 0)
            cookie_store_server(upstream_idx, scookie, slen);
        if (full_rcode == DNS_RCODE_BADCOOKIE && slen > 0) {
            id = csprng_u16();
            if (use_0x20)
                dns0x20_mix(qname, qname_sent, sizeof(qname_sent));
            qlen = build_query(query, sizeof(query), qname_sent, qtype, id, 1, upstream_idx);
            rlen = upstream_dispatch(query, qlen, resp, resp_sz);
            if (rlen >= 12 && !response_matches_query(resp, rlen, id, qname_sent, qtype, use_0x20))
                rlen = -1;
            if (rlen >= 12) {
                int slen2 = 0;
                response_opt_parse(resp, rlen, scookie, &slen2);
                if (slen2 > 0)
                    cookie_store_server(upstream_idx, scookie, slen2);
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* Restore */
    safe_strcpy(g_cfg.upstream_host[0], saved_host, sizeof(g_cfg.upstream_host[0]));
    g_cfg.upstream_port[0] = saved_port;
    g_cfg.proto = saved_proto;
    long rtt = (long) ((t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000L);
    if (rtt_us_out)
        *rtt_us_out = rtt;
    /* Update EMA RTT for this upstream */
    if (rlen > 0) {
        pthread_mutex_lock(&g_upstream_mutex);
        if (g_upstream_rtt_ema[upstream_idx] == 0)
            g_upstream_rtt_ema[upstream_idx] = rtt;
        else
            g_upstream_rtt_ema[upstream_idx] =
                (long) (0.8 * g_upstream_rtt_ema[upstream_idx] + 0.2 * rtt);
        pthread_mutex_unlock(&g_upstream_mutex);
    }
    return rlen;
}

/*
 * upstream_query — try each configured upstream in order of EMA RTT.
 * Falls back to next upstream on failure after one retry.
 * Returns response length or -1.
 */
static int upstream_query(const char *qname, uint16_t qtype, uint8_t *resp, int resp_sz,
                          long *rtt_us_out) {
    /* Per-domain routing: check route table first (longest-suffix match) */
    {
        int routed = route_find(qname);
        if (routed >= 0 && routed < g_cfg.upstream_count) {
            long rtt = 0;
            int rlen = upstream_query_one(qname, qtype, resp, resp_sz, routed, &rtt);
            if (rtt_us_out)
                *rtt_us_out = rtt;
            return rlen; /* route matched — skip EMA fallback */
        }
    }

    /* No route match — sort upstreams by EMA RTT (fastest first) */
    int order[MAX_UPSTREAMS];
    int nc = g_cfg.upstream_count;
    for (int i = 0; i < nc; i++)
        order[i] = i;
    pthread_mutex_lock(&g_upstream_mutex);
    /* Simple insertion sort on EMA RTT */
    for (int i = 1; i < nc; i++) {
        int key = order[i];
        int j = i - 1;
        while (j >= 0 && (g_upstream_rtt_ema[order[j]] > g_upstream_rtt_ema[key] &&
                          g_upstream_rtt_ema[key] > 0)) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = key;
    }
    pthread_mutex_unlock(&g_upstream_mutex);
    int rlen = -1;
    if (rtt_us_out)
        *rtt_us_out = 0;
    for (int oi = 0; oi < nc; oi++) {
        int idx = order[oi];
        long rtt = 0;
        rlen = upstream_query_one(qname, qtype, resp, resp_sz, idx, &rtt);
        if (rlen > 0) {
            if (rtt_us_out)
                *rtt_us_out = rtt;
            break;
        }
        /* backoff before trying next upstream */
        if (oi + 1 < nc) {
            struct timespec sl = {0, .tv_nsec = 50000000L};
            nanosleep(&sl, NULL);
        }
    }
    /* UDP fallback handled inside upstream_query_one */
    return rlen;
}

/* =========================================================================
 * Cache: key, hash, insert, lookup, eviction
 * ======================================================================= */
static uint32_t cache_hash(const char *name, uint16_t qtype) {
    uint32_t h = 2166136261u;
    for (const char *p = name; *p; p++) {
        h ^= (uint8_t) *p;
        h *= 16777619u;
    }
    h ^= qtype;
    h *= 16777619u;
    return h & CACHE_BUCKET_MASK;
}

/* Remaining TTL of an entry (0 if expired) */
static uint32_t entry_remaining_ttl(const cache_entry_t *e) {
    if (e->negative) {
        uint32_t elapsed = (uint32_t) (time(NULL) - e->inserted_at);
        return elapsed < e->neg_ttl ? e->neg_ttl - elapsed : 0;
    }
    if (e->nrr == 0 || !e->rrs)
        return 0; /* no RRs (or not yet/partly built) — treat as expired */
    uint32_t min_remain = UINT32_MAX;
    for (int i = 0; i < e->nrr; i++) {
        uint32_t elapsed = (uint32_t) (time(NULL) - e->rrs[i].inserted_at);
        uint32_t remain = elapsed < e->rrs[i].ttl_original ? e->rrs[i].ttl_original - elapsed : 0;
        if (remain < min_remain)
            min_remain = remain;
    }
    return min_remain == UINT32_MAX ? 0 : min_remain;
}

/* How long ago an already-expired entry became expired (0 if still live or
 * has no RRs to judge from). Shared by the in-memory and Valkey-backed
 * stale-serve windows (RFC 8767). */
static uint32_t entry_expired_for(const cache_entry_t *e) {
    time_t now = time(NULL);
    if (e->negative) {
        uint32_t elapsed = (uint32_t) (now - e->inserted_at);
        return elapsed > e->neg_ttl ? elapsed - e->neg_ttl : 0;
    }
    if (e->nrr == 0 || !e->rrs)
        return 0;
    uint32_t max_age = 0, min_orig = UINT32_MAX;
    for (int i = 0; i < e->nrr; i++) {
        uint32_t age = (uint32_t) (now - e->rrs[i].inserted_at);
        if (age > max_age)
            max_age = age;
        if (e->rrs[i].ttl_original < min_orig)
            min_orig = e->rrs[i].ttl_original;
    }
    if (min_orig == UINT32_MAX)
        return 0;
    return max_age > min_orig ? max_age - min_orig : 0;
}

static void lru_touch(cache_entry_t *e) {
    pthread_mutex_lock(&g_lru_mutex);
    /* Remove from current position */
    if (e->lru_prev)
        e->lru_prev->lru_next = e->lru_next;
    else
        g_lru_head = e->lru_next;
    if (e->lru_next)
        e->lru_next->lru_prev = e->lru_prev;
    else
        g_lru_tail = e->lru_prev;
    /* Insert at head */
    e->lru_prev = NULL;
    e->lru_next = g_lru_head;
    if (g_lru_head)
        g_lru_head->lru_prev = e;
    g_lru_head = e;
    if (!g_lru_tail)
        g_lru_tail = e;
    pthread_mutex_unlock(&g_lru_mutex);
}

static void lru_insert(cache_entry_t *e) {
    pthread_mutex_lock(&g_lru_mutex);
    e->lru_prev = NULL;
    e->lru_next = g_lru_head;
    if (g_lru_head)
        g_lru_head->lru_prev = e;
    g_lru_head = e;
    if (!g_lru_tail)
        g_lru_tail = e;
    pthread_mutex_unlock(&g_lru_mutex);
}

static void cache_entry_free(cache_entry_t *e) {
    if (e->rrs)
        for (int i = 0; i < e->nrr; i++)
            free(e->rrs[i].rdata);
    free(e->rrs);
    free(e);
}

/* Evict the LRU entry */
static void cache_evict_one(void) {
    pthread_mutex_lock(&g_lru_mutex);
    cache_entry_t *victim = g_lru_tail;
    if (!victim) {
        pthread_mutex_unlock(&g_lru_mutex);
        return;
    }
    /* Remove from LRU list */
    if (victim->lru_prev)
        victim->lru_prev->lru_next = NULL;
    else
        g_lru_head = NULL;
    g_lru_tail = victim->lru_prev;
    pthread_mutex_unlock(&g_lru_mutex);
    /* Remove from hash bucket */
    uint32_t bkt = cache_hash(victim->qname, victim->qtype);
    pthread_rwlock_wrlock(&g_cache[bkt].lock);
    cache_entry_t **pp = &g_cache[bkt].head;
    while (*pp && *pp != victim)
        pp = &(*pp)->hash_next;
    if (*pp)
        *pp = victim->hash_next;
    g_cache[bkt].count--;
    pthread_rwlock_unlock(&g_cache[bkt].lock);
    cache_entry_free(victim);
    pthread_mutex_lock(&g_cache_count_mutex);
    g_cache_total--;
    pthread_mutex_unlock(&g_cache_count_mutex);
}

/*
 * cache_insert — add or replace an entry.
 * Caller provides pre-built cache_entry_t (we take ownership).
 */
static void cache_insert(cache_entry_t *e) {
    uint32_t bkt = cache_hash(e->qname, e->qtype);
    pthread_rwlock_wrlock(&g_cache[bkt].lock);
    /* Replace existing entry for same name+type */
    cache_entry_t **pp = &g_cache[bkt].head;
    while (*pp) {
        if ((*pp)->qtype == e->qtype && strcasecmp((*pp)->qname, e->qname) == 0) {
            cache_entry_t *old = *pp;
            *pp = old->hash_next;
            /* Remove from LRU */
            pthread_mutex_lock(&g_lru_mutex);
            if (old->lru_prev)
                old->lru_prev->lru_next = old->lru_next;
            else
                g_lru_head = old->lru_next;
            if (old->lru_next)
                old->lru_next->lru_prev = old->lru_prev;
            else
                g_lru_tail = old->lru_prev;
            pthread_mutex_unlock(&g_lru_mutex);
            cache_entry_free(old);
            g_cache[bkt].count--;
            pthread_mutex_lock(&g_cache_count_mutex);
            g_cache_total--;
            pthread_mutex_unlock(&g_cache_count_mutex);
            break;
        }
        pp = &(*pp)->hash_next;
    }
    e->hash_next = g_cache[bkt].head;
    g_cache[bkt].head = e;
    g_cache[bkt].count++;
    pthread_rwlock_unlock(&g_cache[bkt].lock);
    lru_insert(e);
    pthread_mutex_lock(&g_cache_count_mutex);
    g_cache_total++;
    pthread_mutex_unlock(&g_cache_count_mutex);
    /* Evict if over capacity */
    if (g_cache_total > g_cfg.cache_size)
        cache_evict_one();
}

/*
 * cache_lookup — find a cache entry. Returns a copy (caller frees).
 * With allow_stale=0 (the normal live-lookup path), returns NULL on miss or
 * expiry — a fresh answer or nothing, never opportunistically-stale data.
 * With allow_stale=1 (the RFC 8767 upstream-failure fallback), also returns
 * an already-expired entry if it's still within g_cfg.serve_stale_max,
 * marked served_stale=1.
 */
static cache_entry_t *cache_lookup(const char *qname, uint16_t qtype, int allow_stale) {
    uint32_t bkt = cache_hash(qname, qtype);
    pthread_rwlock_rdlock(&g_cache[bkt].lock);
    cache_entry_t *e = g_cache[bkt].head;
    while (e) {
        if (e->qtype == qtype && strcasecmp(e->qname, qname) == 0)
            break;
        e = e->hash_next;
    }
    if (!e) {
        pthread_rwlock_unlock(&g_cache[bkt].lock);
        return NULL;
    }
    int is_stale = 0;
    if (entry_remaining_ttl(e) == 0) {
        if (!allow_stale || entry_expired_for(e) > g_cfg.serve_stale_max) {
            pthread_rwlock_unlock(&g_cache[bkt].lock);
            if (allow_stale) {
                pthread_mutex_lock(&g_stat_mutex);
                g_stat_expired++;
                pthread_mutex_unlock(&g_stat_mutex);
            }
            return NULL;
        }
        is_stale = 1;
        pthread_mutex_lock(&g_stat_mutex);
        g_stat_expired++;
        pthread_mutex_unlock(&g_stat_mutex);
    }
    /* Deep copy */
    cache_entry_t *copy = malloc(sizeof(cache_entry_t));
    if (!copy) {
        pthread_rwlock_unlock(&g_cache[bkt].lock);
        return NULL;
    }
    memcpy(copy, e, sizeof(cache_entry_t));
    copy->lru_prev = copy->lru_next = copy->hash_next = NULL;
    if (e->nrr > 0) {
        copy->rrs = malloc(e->nrr * sizeof(cache_rr_t));
        if (!copy->rrs) {
            free(copy);
            pthread_rwlock_unlock(&g_cache[bkt].lock);
            return NULL;
        }
        memcpy(copy->rrs, e->rrs, e->nrr * sizeof(cache_rr_t));
        for (int i = 0; i < e->nrr; i++) {
            if (e->rrs[i].rdata && e->rrs[i].rdlen > 0) {
                copy->rrs[i].rdata = malloc(e->rrs[i].rdlen);
                if (copy->rrs[i].rdata)
                    memcpy(copy->rrs[i].rdata, e->rrs[i].rdata, e->rrs[i].rdlen);
            } else
                copy->rrs[i].rdata = NULL;
        }
    }
    copy->served_stale = is_stale;
    pthread_rwlock_unlock(&g_cache[bkt].lock);
    lru_touch(e);
    return copy;
}

static void cache_entry_copy_free(cache_entry_t *e) {
    if (!e)
        return;
    if (e->rrs) {
        for (int i = 0; i < e->nrr; i++)
            free(e->rrs[i].rdata);
        free(e->rrs);
    }
    free(e);
}

/* =========================================================================
 * RFC 8198 — aggressive NSEC/NSEC3 span store
 *
 * A bounded ring buffer of validated denial spans (see dnssec_validate_
 * negative() above). Ring/FIFO eviction rather than LRU or expiry-aware
 * bookkeeping: this is a best-effort accelerator layered on top of the real
 * cache/upstream path, never the only source of an answer's correctness, so
 * the O(1)-insert/O(n)-scan tradeoff is fine at this bound.
 * ======================================================================= */
#define MAX_AGG_NSEC 2048

typedef struct {
    nsec_proof_t proof;
    time_t expiry;
    int in_use;
} agg_nsec_slot_t;

static agg_nsec_slot_t g_agg_nsec[MAX_AGG_NSEC];
static int g_agg_nsec_next = 0;
static pthread_mutex_t g_agg_nsec_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ttl_secs is the entry's already-computed negative TTL (SOA minimum, capped
 * by g_cfg.cache_neg_ttl) — the span never outlives the record it came from,
 * satisfying the "do not exceed the original denial TTL" guardrail. */
static void aggressive_nsec_insert(const nsec_proof_t *proof, uint32_t ttl_secs) {
    if (ttl_secs == 0)
        return;
    pthread_mutex_lock(&g_agg_nsec_mutex);
    agg_nsec_slot_t *slot = &g_agg_nsec[g_agg_nsec_next];
    g_agg_nsec_next = (g_agg_nsec_next + 1) % MAX_AGG_NSEC;
    slot->proof = *proof;
    slot->expiry = time(NULL) + (time_t) ttl_secs;
    slot->in_use = 1;
    pthread_mutex_unlock(&g_agg_nsec_mutex);
}

/* True if `name` is inside (or equal to) `zone` (case-insensitive suffix
 * match on whole labels only). Bounds aggressive spans to the zone they were
 * proven in — a resolverd forwarding for many unrelated domains must never
 * let one zone's NSEC chain answer for another. */
static int name_in_zone(const char *name, const char *zone) {
    if (!zone[0])
        return 1; /* root zone covers everything */
    size_t nlen = strlen(name), zlen = strlen(zone);
    if (nlen < zlen)
        return 0;
    if (strcasecmp(name + (nlen - zlen), zone) != 0)
        return 0;
    return nlen == zlen || name[nlen - zlen - 1] == '.';
}

/*
 * aggressive_nsec_answer — consult validated denial spans for a name that
 * just missed the ordinary cache. On a match, populates *out and returns 1
 * (NXDOMAIN for a gap match, NODATA for an owner-name/type-bitmap match);
 * returns 0 if nothing covers it (caller falls through to upstream).
 */
typedef struct {
    int is_nxdomain; /* 1 = name doesn't exist; 0 = name exists, type doesn't (NODATA) */
} agg_nsec_result_t;

static int aggressive_nsec_answer(const char *qname, uint16_t qtype, agg_nsec_result_t *out) {
    if (!g_cfg.aggressive_nsec_enabled)
        return 0;
    time_t now = time(NULL);
    uint8_t qhash[20];
    int qhash_valid_for_iters = -1, qhash_valid_for_saltlen = -1;
    int found = 0;
    pthread_mutex_lock(&g_agg_nsec_mutex);
    for (int i = 0; i < MAX_AGG_NSEC && !found; i++) {
        agg_nsec_slot_t *slot = &g_agg_nsec[i];
        if (!slot->in_use || slot->expiry <= now)
            continue;
        nsec_proof_t *p = &slot->proof;
        if (!name_in_zone(qname, p->zone))
            continue;
        if (p->is_nsec3) {
            if (p->optout)
                continue; /* RFC 8198 §5 / RFC 5155 §7.2.1: never synthesize
                             across an opt-out span. */
            /* Hash the candidate once per distinct (iterations, saltlen)
             * pair seen — in practice every span in one zone shares params. */
            if (qhash_valid_for_iters != p->nsec3_iters ||
                qhash_valid_for_saltlen != p->nsec3_saltlen) {
                nsec3_hash_raw(qname, p->nsec3_salt, p->nsec3_saltlen, p->nsec3_iters, qhash);
                qhash_valid_for_iters = p->nsec3_iters;
                qhash_valid_for_saltlen = p->nsec3_saltlen;
            }
            int cmp_owner = memcmp(qhash, p->owner_hash, 20);
            int cmp_next = memcmp(qhash, p->next_hash, 20);
            int wraps = memcmp(p->owner_hash, p->next_hash, 20) >= 0;
            if (cmp_owner == 0) {
                if (nsec_bitmap_has_type(p->bitmap, p->bitmap_len, qtype))
                    continue; /* type actually exists here — can't help */
                out->is_nxdomain = 0;
                found = 1;
            } else if (wraps ? (cmp_owner > 0 || cmp_next < 0) : (cmp_owner > 0 && cmp_next < 0)) {
                out->is_nxdomain = 1;
                found = 1;
            }
        } else {
            int cmp_owner = canon_name_cmp(qname, p->owner);
            int cmp_next = canon_name_cmp(qname, p->next);
            int wraps = canon_name_cmp(p->owner, p->next) >= 0;
            if (cmp_owner == 0) {
                if (nsec_bitmap_has_type(p->bitmap, p->bitmap_len, qtype))
                    continue;
                out->is_nxdomain = 0;
                found = 1;
            } else if (wraps ? (cmp_owner > 0 || cmp_next < 0) : (cmp_owner > 0 && cmp_next < 0)) {
                out->is_nxdomain = 1;
                found = 1;
            }
        }
    }
    pthread_mutex_unlock(&g_agg_nsec_mutex);
    return found;
}

/* Flush one specific entry (or all entries if qname is NULL) */
static int cache_flush(const char *qname, uint16_t qtype) {
    int count = 0;
    if (!qname) {
        /* Flush all */
        for (int b = 0; b < CACHE_BUCKETS; b++) {
            pthread_rwlock_wrlock(&g_cache[b].lock);
            cache_entry_t *e = g_cache[b].head, *nx;
            while (e) {
                nx = e->hash_next;
                pthread_mutex_lock(&g_lru_mutex);
                if (e->lru_prev)
                    e->lru_prev->lru_next = e->lru_next;
                else
                    g_lru_head = e->lru_next;
                if (e->lru_next)
                    e->lru_next->lru_prev = e->lru_prev;
                else
                    g_lru_tail = e->lru_prev;
                pthread_mutex_unlock(&g_lru_mutex);
                cache_entry_free(e);
                count++;
                e = nx;
            }
            g_cache[b].head = NULL;
            g_cache[b].count = 0;
            pthread_rwlock_unlock(&g_cache[b].lock);
        }
        pthread_mutex_lock(&g_cache_count_mutex);
        g_cache_total = 0;
        pthread_mutex_unlock(&g_cache_count_mutex);
        /* Also flush Valkey cache namespace */
        if (g_cfg.valkey_enabled) {
            char keys[256][512];
            int n = vk_keys_scan("dnscache:*", keys, 256);
            for (int i = 0; i < n; i++)
                vk_del(keys[i]);
        }
        return count;
    }
    uint32_t bkt = cache_hash(qname, qtype);
    pthread_rwlock_wrlock(&g_cache[bkt].lock);
    cache_entry_t **pp = &g_cache[bkt].head;
    while (*pp) {
        cache_entry_t *e = *pp;
        if (e->qtype == qtype && strcasecmp(e->qname, qname) == 0) {
            *pp = e->hash_next;
            pthread_mutex_lock(&g_lru_mutex);
            if (e->lru_prev)
                e->lru_prev->lru_next = e->lru_next;
            else
                g_lru_head = e->lru_next;
            if (e->lru_next)
                e->lru_next->lru_prev = e->lru_prev;
            else
                g_lru_tail = e->lru_prev;
            pthread_mutex_unlock(&g_lru_mutex);
            cache_entry_free(e);
            g_cache[bkt].count--;
            pthread_mutex_lock(&g_cache_count_mutex);
            g_cache_total--;
            pthread_mutex_unlock(&g_cache_count_mutex);
            count++;
            break;
        }
        pp = &(*pp)->hash_next;
    }
    pthread_rwlock_unlock(&g_cache[bkt].lock);
    if (g_cfg.valkey_enabled) {
        char vk_key[600];
        snprintf(vk_key, sizeof(vk_key), "dnscache:%s:%s", qname, type2str(qtype));
        vk_del(vk_key);
    }
    return count;
}

/* =========================================================================
 * Valkey persistent cache: serialise/deserialise entries
 *
 * Format (plain text, pipe-separated):
 *   <nrr>|<rcode>|<negative>|<neg_ttl>|<inserted_at>|
 *   <type>:<ttl_orig>:<rdlen_hex>:<rdata_hex>|...
 * ======================================================================= */
static void cache_store_valkey(const cache_entry_t *e) {
    if (!g_cfg.valkey_enabled)
        return;
    char vk_key[600];
    snprintf(vk_key, sizeof(vk_key), "dnscache:%s:%s", e->qname, type2str(e->qtype));
    /* Compute longest TTL for Valkey expiry */
    uint32_t max_ttl = e->negative ? e->neg_ttl : 0;
    for (int i = 0; i < e->nrr; i++)
        if (e->rrs[i].ttl_original > max_ttl)
            max_ttl = e->rrs[i].ttl_original;
    if (max_ttl == 0) {
        vk_del(vk_key);
        return;
    }
    /* Serialise */
    char buf[RESP_BUF];
    int pos = 0;
    pos += snprintf(buf + pos, RESP_BUF - pos, "%d|%u|%d|%u|%ld|", e->nrr, (uint32_t) e->rcode,
                    e->negative, e->neg_ttl, (long) e->inserted_at);
    for (int i = 0; i < e->nrr && pos < RESP_BUF - 256; i++) {
        pos += snprintf(buf + pos, RESP_BUF - pos, "%u:%u:%u:", e->rrs[i].type,
                        e->rrs[i].ttl_original, e->rrs[i].rdlen);
        for (int j = 0; j < (int) e->rrs[i].rdlen && pos + 3 < RESP_BUF; j++)
            pos += snprintf(buf + pos, RESP_BUF - pos, "%02x", e->rrs[i].rdata[j]);
        if (pos < RESP_BUF - 1)
            buf[pos++] = '|';
    }
    buf[pos] = 0;
    vk_set(vk_key, buf, max_ttl);
}

static cache_entry_t *cache_load_valkey(const char *qname, uint16_t qtype, int allow_stale) {
    if (!g_cfg.valkey_enabled)
        return NULL;
    char vk_key[600];
    snprintf(vk_key, sizeof(vk_key), "dnscache:%s:%s", qname, type2str(qtype));
    char buf[RESP_BUF];
    if (!vk_get(vk_key, buf, sizeof(buf)))
        return NULL;
    cache_entry_t *e = calloc(1, sizeof(cache_entry_t));
    if (!e)
        return NULL;
    safe_strcpy(e->qname, qname, sizeof(e->qname));
    e->qtype = qtype;
    /* Parse header: nrr|rcode|negative|neg_ttl|inserted_at| */
    char *sp4 = NULL;
    char *tok = strtok_r(buf, "|", &sp4);
    if (!tok) {
        free(e);
        return NULL;
    }
    e->nrr = atoi(tok);
    tok = strtok_r(NULL, "|", &sp4);
    if (tok)
        e->rcode = (uint8_t) atoi(tok);
    tok = strtok_r(NULL, "|", &sp4);
    if (tok)
        e->negative = atoi(tok);
    tok = strtok_r(NULL, "|", &sp4);
    if (tok)
        e->neg_ttl = (uint32_t) atoi(tok);
    tok = strtok_r(NULL, "|", &sp4);
    if (tok)
        e->inserted_at = (time_t) atol(tok);
    if (e->nrr > 0) {
        e->rrs = calloc(e->nrr, sizeof(cache_rr_t));
        if (!e->rrs) {
            free(e);
            return NULL;
        }
        for (int i = 0; i < e->nrr; i++) {
            tok = strtok_r(NULL, "|", &sp4);
            if (!tok)
                break;
            /* format: type:ttl_orig:rdlen:hex */
            unsigned tp = 0, ttlo = 0, rdl = 0;
            char hexdata[2048] = "";
            sscanf(tok, "%u:%u:%u:%2047s", &tp, &ttlo, &rdl, hexdata);
            e->rrs[i].type = (uint16_t) tp;
            e->rrs[i].ttl_original = ttlo;
            e->rrs[i].rdlen = (uint16_t) rdl;
            e->rrs[i].inserted_at = e->inserted_at;
            if (rdl > 0 && hexdata[0]) {
                e->rrs[i].rdata = malloc(rdl);
                if (e->rrs[i].rdata)
                    hex_dec(hexdata, e->rrs[i].rdata, rdl);
            }
        }
    }
    /* Rebuild TTL against current time. Must run AFTER e->rrs is populated: the
     * positive-entry path of entry_remaining_ttl() reads each RR's
     * ttl_original/inserted_at, so calling it earlier (with nrr>0 but rrs not yet
     * allocated) dereferenced a NULL e->rrs and crashed on the first Valkey cache
     * hit after an in-memory miss (e.g. a freshly (re)started resolverd). */
    if (entry_remaining_ttl(e) == 0) {
        if (!allow_stale || entry_expired_for(e) > g_cfg.serve_stale_max) {
            cache_entry_free(e);
            return NULL;
        }
        e->served_stale = 1;
    }
    return e;
}

/* =========================================================================
 * Parse DNS response into a cache entry
 * ======================================================================= */
static cache_entry_t *parse_response_to_entry(const uint8_t *resp, int rlen, const char *qname,
                                              uint16_t qtype) {
    if (rlen < 12)
        return NULL;
    const dns_hdr_t *h = (const dns_hdr_t *) resp;
    uint8_t rcode = (uint8_t) (ntohs(h->flags) & DNS_RCODE_MASK);
    int ancount = ntohs(h->ancount);
    int nscount = ntohs(h->nscount);
    cache_entry_t *e = calloc(1, sizeof(cache_entry_t));
    if (!e)
        return NULL;
    safe_strcpy(e->qname, qname, sizeof(e->qname));
    e->qtype = qtype;
    e->rcode = rcode;
    e->inserted_at = time(NULL);
    /* Skip question section */
    int off = 12;
    for (int i = 0; i < ntohs(h->qdcount); i++) {
        char tmp[256];
        off = name_from_wire(resp, rlen, off, tmp, sizeof(tmp));
        if (off < 0)
            goto fail;
        off += 4;
        if (off > rlen)
            goto fail;
    }
    /* Handle NXDOMAIN / NODATA: extract SOA minimum TTL for negative cache TTL */
    if (rcode == 3 /*NXDOMAIN*/ || (rcode == 0 && ancount == 0)) {
        e->negative = 1;
        /* Scan authority section for SOA minimum TTL */
        uint32_t soa_min = g_cfg.cache_neg_ttl;
        int aoff = off;
        /* skip answer RRs (none for NXDOMAIN but be safe) */
        for (int i = 0; i < ancount && aoff < rlen; i++) {
            char nm[256];
            int a = name_from_wire(resp, rlen, aoff, nm, sizeof(nm));
            if (a < 0)
                break;
            if (a + 10 > rlen)
                break;
            uint16_t rdl = get16(resp, a + 8);
            aoff = a + 10 + (int) rdl;
        }
        for (int i = 0; i < nscount && aoff < rlen; i++) {
            char nm[256];
            int a = name_from_wire(resp, rlen, aoff, nm, sizeof(nm));
            if (a < 0)
                break;
            if (a + 10 > rlen)
                break;
            uint16_t rtype = get16(resp, a), rdl = get16(resp, a + 8);
            if (rtype == DNS_TYPE_SOA && a + 10 + (int) rdl <= rlen) {
                /* SOA rdata: mname(wire) rname(wire) serial(4) refresh(4) retry(4) expire(4)
                 * minimum(4) */
                int sp = a + 10;
                char mn[256], rn[256];
                sp = name_from_wire(resp, rlen, sp, mn, sizeof(mn));
                if (sp > 0)
                    sp = name_from_wire(resp, rlen, sp, rn, sizeof(rn));
                if (sp > 0 && sp + 20 <= rlen) {
                    uint32_t minimum = get32(resp, sp + 16);
                    if (minimum < soa_min)
                        soa_min = minimum;
                }
            }
            aoff = a + 10 + (int) rdl;
        }
        e->neg_ttl = (soa_min > g_cfg.cache_neg_ttl) ? g_cfg.cache_neg_ttl : soa_min;
        pthread_mutex_lock(&g_stat_mutex);
        g_stat_negcache++;
        pthread_mutex_unlock(&g_stat_mutex);
        return e;
    }
    /* Parse answer RRs */
    if (ancount > 0) {
        e->rrs = calloc(ancount, sizeof(cache_rr_t));
        if (!e->rrs)
            goto fail;
        for (int i = 0; i < ancount && off < rlen; i++) {
            char rname[256];
            int a = name_from_wire(resp, rlen, off, rname, sizeof(rname));
            if (a < 0 || a + 10 > rlen)
                break;
            uint16_t rtype = get16(resp, a), rclass = get16(resp, a + 2);
            uint32_t ttl = get32(resp, a + 4);
            uint16_t rdlen = get16(resp, a + 8);
            if (rclass != DNS_CLASS_IN || rtype == DNS_TYPE_OPT) {
                off = a + 10 + (int) rdlen;
                continue;
            }
            if (a + 10 + (int) rdlen > rlen)
                break;
            /* Clamp TTL */
            if (ttl > g_cfg.cache_ttl_max)
                ttl = g_cfg.cache_ttl_max;
            cache_rr_t *rr = &e->rrs[e->nrr];
            rr->type = rtype;
            rr->ttl_original = ttl;
            rr->rdlen = rdlen;
            rr->inserted_at = time(NULL);
            if (rdlen > 0) {
                rr->rdata = malloc(rdlen);
                if (rr->rdata)
                    memcpy(rr->rdata, resp + a + 10, rdlen);
            }
            e->nrr++;
            off = a + 10 + (int) rdlen;
        }
    }
    /* Set prefetch threshold: re-query when TTL < original/PREFETCH_RATIO */
    if (e->nrr > 0) {
        uint32_t min_ttl = UINT32_MAX;
        for (int i = 0; i < e->nrr; i++)
            if (e->rrs[i].ttl_original < min_ttl)
                min_ttl = e->rrs[i].ttl_original;
        e->prefetch_ttl = min_ttl / PREFETCH_RATIO;
    }
    return e;
fail:
    cache_entry_free(e);
    return NULL;
}

/*
 * RFC 9520 — cache a synthetic SERVFAIL briefly so a persistently failing
 * name doesn't retrigger an upstream query (and the query storm that invites)
 * on every subsequent lookup. Mirrors the NXDOMAIN/NODATA negative-entry
 * shape from parse_response_to_entry (nrr=0, negative=1).
 */
static void cache_servfail(const char *qname, uint16_t qtype) {
    if (g_cfg.servfail_cache_ttl == 0)
        return;
    cache_entry_t *e = calloc(1, sizeof(cache_entry_t));
    if (!e)
        return;
    safe_strcpy(e->qname, qname, sizeof(e->qname));
    e->qtype = qtype;
    e->rcode = 2 /* SERVFAIL */;
    e->negative = 1;
    e->neg_ttl = g_cfg.servfail_cache_ttl;
    e->inserted_at = time(NULL);
    cache_insert(e);
    cache_store_valkey(e);
}

/* =========================================================================
 * Prefetch thread
 * ======================================================================= */
typedef struct {
    char qname[256];
    uint16_t qtype;
} prefetch_job_t;

static void *prefetch_worker(void *arg) {
    prefetch_job_t *j = (prefetch_job_t *) arg;
    uint8_t resp[DNS_BUF];
    long rtt = 0;
    int rlen = upstream_query(j->qname, j->qtype, resp, sizeof(resp), &rtt);
    /* A failed refresh (no response, or upstream SERVFAIL) must not clobber
     * the entry it was meant to refresh — this fires right after a serve-
     * stale hit (RFC 8767), i.e. exactly when upstream is known to be down. */
    if (rlen >= 12 && (ntohs(((dns_hdr_t *) resp)->flags) & DNS_RCODE_MASK) != 2) {
        cache_entry_t *e = parse_response_to_entry(resp, rlen, j->qname, j->qtype);
        if (e) {
            cache_insert(e);
            cache_store_valkey(e);
        }
    }
    free(j);
    return NULL;
}

static void prefetch_async(const char *qname, uint16_t qtype) {
    prefetch_job_t *j = malloc(sizeof(prefetch_job_t));
    if (!j)
        return;
    safe_strcpy(j->qname, qname, sizeof(j->qname));
    j->qtype = qtype;
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, prefetch_worker, j);
    pthread_attr_destroy(&attr);
}

/* =========================================================================
 * Main resolve function: cache check → upstream → cache fill
 * ======================================================================= */
typedef struct {
    int from_cache;
    uint32_t cache_ttl_remaining;
    long rtt_us;
    int rcode;
    int ancount;
    int dnssec_status;     /* 0=unchecked 1=secure 2=insecure 3=bogus */
    char answers[32][512]; /* human-readable answer strings */
    char answer_names[32][256];
    uint16_t answer_types[32];
    uint32_t answer_ttls[32];
} resolve_result_t;

/*
 * Populate `result` from a cache entry obtained via cache_lookup/
 * cache_load_valkey (which have already applied the stale-window check) and
 * free it. Handles negative answers, prefetch triggering, and RFC 8767
 * stale-serve accounting. Returns what dns_resolve should return: 0 for a
 * positive answer (already filled in), or the cached rcode for a negative
 * one.
 */
static int serve_cached_entry(cache_entry_t *ce, const char *qname, resolve_result_t *result) {
    pthread_mutex_lock(&g_stat_mutex);
    g_stat_hits++;
    pthread_mutex_unlock(&g_stat_mutex);
    result->from_cache = 1;
    result->cache_ttl_remaining = entry_remaining_ttl(ce);
    result->rcode = ce->rcode;
    if (ce->served_stale) {
        prefetch_async(qname, ce->qtype);
        result->from_cache = 2;
        pthread_mutex_lock(&g_stat_mutex);
        g_stat_stale++;
        pthread_mutex_unlock(&g_stat_mutex);
    } else if (!ce->negative && ce->prefetch_ttl > 0 &&
               result->cache_ttl_remaining <= ce->prefetch_ttl) {
        prefetch_async(qname, ce->qtype);
    }
    if (ce->negative) {
        int rc = result->rcode;
        cache_entry_copy_free(ce);
        return rc;
    }
    int n = ce->nrr < 32 ? ce->nrr : 32;
    result->ancount = n;
    for (int i = 0; i < n; i++) {
        result->answer_types[i] = ce->rrs[i].type;
        result->answer_ttls[i] =
            (uint32_t) (time(NULL) - ce->rrs[i].inserted_at < ce->rrs[i].ttl_original
                            ? ce->rrs[i].ttl_original -
                                  (uint32_t) (time(NULL) - ce->rrs[i].inserted_at)
                            : 0);
        /* Re-encode rdata as string using a fake packet context */
        uint8_t fake[512];
        memset(fake, 0, sizeof(fake));
        if (ce->rrs[i].rdata && ce->rrs[i].rdlen > 0)
            memcpy(fake, ce->rrs[i].rdata,
                   ce->rrs[i].rdlen < (int) sizeof(fake) ? ce->rrs[i].rdlen : (int) sizeof(fake));
        rdata_to_str(fake, ce->rrs[i].rdlen, 0, ce->rrs[i].rdlen, ce->rrs[i].type,
                     result->answers[i], sizeof(result->answers[i]));
        safe_strcpy(result->answer_names[i], qname, sizeof(result->answer_names[i]));
    }
    cache_entry_copy_free(ce);
    return 0;
}

static int dns_resolve(const char *qname_in, uint16_t qtype, resolve_result_t *result) {
    memset(result, 0, sizeof(*result));
    char qname[256];
    safe_strcpy(qname, qname_in, sizeof(qname));
    strlower(qname);
    pthread_mutex_lock(&g_stat_mutex);
    g_stat_queries++;
    pthread_mutex_unlock(&g_stat_mutex);

    /* -1. mDNS for .local names (RFC 6762) — try multicast before unicast */
    if (is_local_name(qname)) {
        uint8_t mresp[DNS_BUF * 2];
        int mrlen = mdns_query(qname, qtype, mresp, sizeof(mresp));
        if (mrlen > 0) {
            /* Parse the mDNS response into the cache and result */
            cache_entry_t *mce = parse_response_to_entry(mresp, mrlen, qname, qtype);
            if (mce && mce->nrr > 0) {
                mce->dnssec_status = (int) DNSSEC_INSECURE; /* mDNS is not DNSSEC-signed */
                cache_insert(mce);
                cache_store_valkey(mce);
                pthread_mutex_lock(&g_stat_mutex);
                g_stat_hits++;
                pthread_mutex_unlock(&g_stat_mutex);
                result->from_cache = 0;
                result->rtt_us = MDNS_COLLECT_MS * 1000;
                result->dnssec_status = (int) DNSSEC_INSECURE;
                /* Populate result */
                int anc = ntohs(((dns_hdr_t *) mresp)->ancount);
                int mo = 12;
                for (int qi = 0; qi < ntohs(((dns_hdr_t *) mresp)->qdcount) && mo < mrlen; qi++) {
                    char tmp[256];
                    mo = name_from_wire(mresp, mrlen, mo, tmp, sizeof(tmp));
                    if (mo < 0)
                        break;
                    mo += 4;
                }
                int ridx2 = 0;
                for (int i = 0; i < anc && mo < mrlen && ridx2 < 32; i++) {
                    char rn[256];
                    int a = name_from_wire(mresp, mrlen, mo, rn, sizeof(rn));
                    if (a < 0 || a + 10 > mrlen)
                        break;
                    uint16_t rt = get16(mresp, a), rcl = get16(mresp, a + 2);
                    uint32_t ttl = get32(mresp, a + 4);
                    uint16_t rdl = get16(mresp, a + 8);
                    if (rcl == DNS_CLASS_IN && rt != DNS_TYPE_OPT) {
                        result->answer_types[ridx2] = rt;
                        result->answer_ttls[ridx2] = ttl;
                        safe_strcpy(result->answer_names[ridx2], rn,
                                    sizeof(result->answer_names[ridx2]));
                        rdata_to_str(mresp, mrlen, a + 10, rdl, rt, result->answers[ridx2], 512);
                        ridx2++;
                    }
                    mo = a + 10 + (int) rdl;
                }
                result->ancount = ridx2;
                if (ridx2 > 0)
                    return 0;
            }
            if (mce)
                cache_entry_free(mce);
        }
        /* mDNS failed or no answers — fall through to unicast */
    }

    /* 0. Search domain expansion for unqualified names (no dot in name) */
    if (g_cfg.search_domain_count > 0 && !strchr(qname, '.')) {
        /* Try each search domain in order until we get a non-NXDOMAIN response */
        for (int sdi = 0; sdi < g_cfg.search_domain_count; sdi++) {
            char expanded[256];
            snprintf(expanded, sizeof(expanded), "%s.%s", qname, g_cfg.search_domains[sdi]);
            resolve_result_t sub;
            memset(&sub, 0, sizeof(sub));
            if (dns_resolve(expanded, qtype, &sub) == 0 && sub.rcode != 3 /*NXDOMAIN*/) {
                *result = sub;
                return 0;
            }
        }
        /* All search domains exhausted — fall through to exact name */
    }

    /* 1. Memory cache lookup (fresh only — never opportunistically stale) */
    cache_entry_t *ce = cache_lookup(qname, qtype, 0);
    /* 2. Valkey persistent cache fallback */
    if (!ce)
        ce = cache_load_valkey(qname, qtype, 0);
    if (ce)
        return serve_cached_entry(ce, qname, result);

    /* 2.5 RFC 8198: a validated NSEC/NSEC3 denial span from an earlier query
     * may already prove this name/type doesn't exist — answer from it
     * without going upstream at all. */
    agg_nsec_result_t agg;
    if (aggressive_nsec_answer(qname, qtype, &agg)) {
        pthread_mutex_lock(&g_stat_mutex);
        g_stat_hits++;
        pthread_mutex_unlock(&g_stat_mutex);
        result->from_cache = 1;
        result->ancount = 0;
        result->dnssec_status = (int) DNSSEC_SECURE;
        result->rcode = agg.is_nxdomain ? 3 /* NXDOMAIN */ : 0 /* NOERROR/NODATA */;
        return result->rcode;
    }

    /* 3. Miss — query upstream */
    pthread_mutex_lock(&g_stat_mutex);
    g_stat_misses++;
    pthread_mutex_unlock(&g_stat_mutex);
    uint8_t resp[DNS_BUF * 2];
    int rlen = upstream_query(qname, qtype, resp, sizeof(resp), &result->rtt_us);
    int upstream_failed = (rlen < 12);
    if (!upstream_failed) {
        result->rcode = ntohs(((dns_hdr_t *) resp)->flags) & DNS_RCODE_MASK;
        /* RFC 8767 §3 / RFC 9520 treat an upstream SERVFAIL the same as no
         * response at all — it is a resolution failure, not an answer to
         * cache as one. */
        upstream_failed = (result->rcode == 2 /* SERVFAIL */);
    }
    if (upstream_failed) {
        /* RFC 8767: prefer a recently-expired cache entry over failing the
         * query outright. */
        cache_entry_t *sce = cache_lookup(qname, qtype, 1);
        if (!sce)
            sce = cache_load_valkey(qname, qtype, 1);
        if (sce)
            return serve_cached_entry(sce, qname, result);
        /* RFC 9520: nothing to serve — cache the failure briefly so repeated
         * queries for this name don't retrigger the same failing lookup. */
        cache_servfail(qname, qtype);
        return -1;
    }
    /* 4. Parse response + DNSSEC validation */
    ce = parse_response_to_entry(resp, rlen, qname, qtype);
    if (ce) {
        if (ce->negative) {
            nsec_proof_t proofs[MAX_NEG_PROOFS];
            int proof_n = 0;
            ce->dnssec_status =
                (int) dnssec_validate_negative(resp, rlen, qname, proofs, MAX_NEG_PROOFS, &proof_n);
            if (ce->dnssec_status == (int) DNSSEC_SECURE)
                for (int i = 0; i < proof_n; i++)
                    aggressive_nsec_insert(&proofs[i], ce->neg_ttl);
        } else {
            ce->dnssec_status = (int) dnssec_validate_response(resp, rlen, qname);
        }
        result->dnssec_status = ce->dnssec_status;
        if (ce->dnssec_status == 3 /*BOGUS*/) {
            fprintf(stderr, ";; DNSSEC BOGUS: signature verification FAILED for %s\n", qname);
            cache_entry_free(ce);
            return -2; /* caller gets SERVFAIL */
        }
        cache_insert(ce);
        cache_store_valkey(ce);
    }
    /* 5. Populate result from raw response */
    int ancount = ntohs(((dns_hdr_t *) resp)->ancount);
    int off = 12;
    for (int i = 0; i < ntohs(((dns_hdr_t *) resp)->qdcount) && off < rlen; i++) {
        char tmp[256];
        off = name_from_wire(resp, rlen, off, tmp, sizeof(tmp));
        if (off < 0)
            break;
        off += 4;
    }
    int ridx = 0;
    for (int i = 0; i < ancount && off < rlen && ridx < 32; i++) {
        char rname[256];
        int a = name_from_wire(resp, rlen, off, rname, sizeof(rname));
        if (a < 0 || a + 10 > rlen)
            break;
        uint16_t rtype = get16(resp, a), rclass = get16(resp, a + 2);
        uint32_t ttl = get32(resp, a + 4);
        uint16_t rdlen = get16(resp, a + 8);
        if (rclass == DNS_CLASS_IN && rtype != DNS_TYPE_OPT) {
            result->answer_types[ridx] = rtype;
            result->answer_ttls[ridx] = ttl;
            safe_strcpy(result->answer_names[ridx], rname, sizeof(result->answer_names[ridx]));
            rdata_to_str(resp, rlen, a + 10, rdlen, rtype, result->answers[ridx], 512);
            ridx++;
        }
        off = a + 10 + (int) rdlen;
    }
    result->ancount = ridx;
    /* CNAME chain following */
    if (ridx > 0 && result->answer_types[0] == DNS_TYPE_CNAME && qtype != DNS_TYPE_CNAME &&
        qtype != DNS_TYPE_ANY) {
        /* Follow CNAME target */
        char cname_target[256];
        safe_strcpy(cname_target, result->answers[0], sizeof(cname_target));
        for (int hop = 0; hop < MAX_CNAME_HOPS && cname_target[0]; hop++) {
            resolve_result_t sub;
            memset(&sub, 0, sizeof(sub));
            if (dns_resolve(cname_target, qtype, &sub) < 0)
                break;
            /* Append sub-results */
            for (int j = 0; j < sub.ancount && ridx < 32; j++) {
                result->answer_types[ridx] = sub.answer_types[j];
                result->answer_ttls[ridx] = sub.answer_ttls[j];
                safe_strcpy(result->answer_names[ridx], sub.answer_names[j],
                            sizeof(result->answer_names[ridx]));
                safe_strcpy(result->answers[ridx], sub.answers[j], sizeof(result->answers[ridx]));
                ridx++;
            }
            result->ancount = ridx;
            /* If the sub-result has a CNAME, keep chasing */
            if (sub.ancount > 0 && sub.answer_types[0] == DNS_TYPE_CNAME)
                safe_strcpy(cname_target, sub.answers[0], sizeof(cname_target));
            else
                break;
        }
    }
    return 0;
}

/*
 * Maps a dns_resolve() failure code to an RFC 8914 Extended DNS Error so a
 * stub client that sent EDNS learns *why* an answer is SERVFAIL, rather than
 * just that it is. Only meaningful for rc<0 (success codes never call this).
 */
static void ede_for_resolve_failure(int rc, int *ede_code, const char **ede_text) {
    if (rc == -2) {
        *ede_code = EDE_DNSSEC_BOGUS;
        *ede_text = "DNSSEC validation failed";
    } else {
        *ede_code = EDE_NETWORK_ERROR;
        *ede_text = "No response from upstream";
    }
}

/* =========================================================================
 * RFC 9462 DDR — Discovery of Designated Resolvers
 *
 * If resolverd's own DoT listener is configured (dot_server_init below), a
 * client already talking to us in the clear can ask this same resolver
 * "do you also offer encrypted transport?" by querying _dns.resolver.arpa
 * SVCB. Precomputed once at startup — see dot_server_init — reused by every
 * matching query, per RFC 9460 wire form (SvcPriority | TargetName |
 * SvcParams), built via libdnswire's svcb_present_to_tlv/svcb_tlv_to_wire
 * (the same encoder dnsd uses for zone SVCB records — no second copy).
 * ======================================================================= */
#define DDR_OWNER "_dns.resolver.arpa"
#define DDR_TTL 300u
static uint8_t g_ddr_svcb_rdata[512];
static int g_ddr_svcb_rdata_len = 0;

/*
 * build_dns_response — resolve the query in pkt[0..plen) and build a
 * complete response (header, question, answers, EDE) into resp[0..cap).
 * Shared by the plain-UDP, plain-TCP, and DoT response paths so the
 * per-type rdata encoding and EDE-attachment logic exists in exactly one
 * place. Returns the response length, or -1 if the query is malformed
 * enough that nothing should be sent back at all.
 */
static int build_dns_response(const uint8_t *pkt, int plen, int is_tcp, uint8_t *resp, int cap) {
    if (plen < 12)
        return -1;
    const dns_hdr_t *qh = (const dns_hdr_t *) pkt;
    if (ntohs(qh->flags) & DNS_QR)
        return -1; /* ignore responses */
    if (ntohs(qh->qdcount) != 1)
        return -1;
    char qname[256] = {0};
    int after = name_from_wire(pkt, plen, 12, qname, sizeof(qname));
    if (after < 0 || after + 3 >= plen)
        return -1;
    uint16_t qtype = get16(pkt, after);

    memset(resp, 0, 12);
    dns_hdr_t *rh = (dns_hdr_t *) resp;
    rh->id = qh->id;
    uint16_t flags = DNS_QR | DNS_RA | (ntohs(qh->flags) & DNS_RD);
    rh->qdcount = htons(1);
    int off = 12;
    int qsec = after - 12 + 4;
    if (off + qsec < cap) {
        memcpy(resp + off, pkt + 12, qsec);
        off += qsec;
    }
    int ancount = 0;

    if (g_ddr_svcb_rdata_len > 0 && qtype == DNS_TYPE_SVCB && !strcasecmp(qname, DDR_OWNER)) {
        /* Answer the discovery query directly — never touches dns_resolve,
         * the cache, or an upstream; this is data about resolverd itself. */
        rh->flags = htons(flags | 0 /* NOERROR */);
        int n = name_to_wire(qname, resp + off, cap - off);
        if (n > 0 && off + n + 10 + g_ddr_svcb_rdata_len <= cap) {
            off += n;
            put16(resp, off, DNS_TYPE_SVCB);
            off += 2;
            put16(resp, off, DNS_CLASS_IN);
            off += 2;
            put32(resp, off, DDR_TTL);
            off += 4;
            put16(resp, off, (uint16_t) g_ddr_svcb_rdata_len);
            off += 2;
            memcpy(resp + off, g_ddr_svcb_rdata, (size_t) g_ddr_svcb_rdata_len);
            off += g_ddr_svcb_rdata_len;
            ancount = 1;
        }
        rh->ancount = htons((uint16_t) ancount);
        rh->arcount = 0;
        return off;
    }

    resolve_result_t result;
    memset(&result, 0, sizeof(result));
    int rc = dns_resolve(qname, qtype, &result);
    rh->flags = htons(flags | (uint16_t) (rc < 0 ? 2 /* SERVFAIL */ : result.rcode));

    /* Append answer RRs */
    for (int i = 0; i < result.ancount && off + 32 < cap; i++) {
        uint8_t rdata[512];
        int rdlen = 0;
        uint16_t rtype = result.answer_types[i];
        /* Re-encode answer rdata into wire format */
        switch (rtype) {
            case DNS_TYPE_A: {
                struct in_addr a4;
                if (inet_pton(AF_INET, result.answers[i], &a4) == 1) {
                    memcpy(rdata, &a4, 4);
                    rdlen = 4;
                }
                break;
            }
            case DNS_TYPE_AAAA: {
                struct in6_addr a6;
                if (inet_pton(AF_INET6, result.answers[i], &a6) == 1) {
                    memcpy(rdata, &a6, 16);
                    rdlen = 16;
                }
                break;
            }
            case DNS_TYPE_CNAME:
            case DNS_TYPE_PTR:
            case DNS_TYPE_NS: {
                int n = name_to_wire(result.answers[i], rdata, sizeof(rdata));
                if (n > 0)
                    rdlen = n;
                break;
            }
            case DNS_TYPE_MX: {
                char mxname[256] = "";
                uint16_t pref = 0;
                sscanf(result.answers[i], "%hu %255s", &pref, mxname);
                rdata[0] = pref >> 8;
                rdata[1] = pref & 0xFF;
                int n = name_to_wire(mxname, rdata + 2, sizeof(rdata) - 2);
                if (n > 0)
                    rdlen = 2 + n;
                break;
            }
            case DNS_TYPE_TXT: { /* value is "text" quoted */
                const char *p = result.answers[i];
                if (*p == '"')
                    p++;
                int sl = (int) strlen(p);
                if (sl > 0 && p[sl - 1] == '"')
                    sl--;
                if (sl > 255)
                    sl = 255;
                rdata[0] = (uint8_t) sl;
                memcpy(rdata + 1, p, sl);
                rdlen = 1 + sl;
                break;
            }
            default:
                break;
        }
        if (rdlen > 0) {
            int n = name_to_wire(result.answer_names[i], resp + off, cap - off);
            if (n < 0)
                break;
            off += n;
            if (off + 10 + rdlen > cap)
                break;
            put16(resp, off, rtype);
            off += 2;
            put16(resp, off, DNS_CLASS_IN);
            off += 2;
            put32(resp, off, result.answer_ttls[i]);
            off += 4;
            put16(resp, off, (uint16_t) rdlen);
            off += 2;
            memcpy(resp + off, rdata, rdlen);
            off += rdlen;
            ancount++;
        }
    }
    rh->ancount = htons((uint16_t) ancount);
    /* RFC 8914: tell an EDNS-speaking client why a failed resolution is
     * SERVFAIL. Only attach an OPT record at all if the client sent one. */
    edns_info_t req_ei;
    edns_parse(pkt, plen, &req_ei);
    int arcount = 0;
    if (req_ei.present) {
        int ede_code = -1;
        const char *ede_text = NULL;
        if (rc < 0)
            ede_for_resolve_failure(rc, &ede_code, &ede_text);
        int new_off = edns_append_opt(resp, off, cap, is_tcp, req_ei.do_bit, 0, &req_ei, NULL, NULL,
                                      ede_code, ede_text, -1, 0, NULL);
        if (new_off > off) {
            off = new_off;
            arcount = 1;
        }
    }
    rh->arcount = htons((uint16_t) arcount);
    return off;
}

/* =========================================================================
 * Proxy mode: listen on local UDP, forward, respond from cache
 * ======================================================================= */
static void proxy_handle(int srv_fd, const uint8_t *pkt, int plen, const struct sockaddr *src,
                         socklen_t srclen) {
    uint8_t resp[DNS_BUF * 2];
    int off = build_dns_response(pkt, plen, 0 /* is_tcp */, resp, (int) sizeof(resp));
    if (off < 0)
        return;
    sendto(srv_fd, resp, off, 0, src, srclen);
}

/* proxy_handle_tcp — serve one DNS-over-TCP session (2-byte length-framing) */
static void proxy_handle_tcp(int cfd) {
    uint8_t lb[2];
    int got = 0;
    struct timeval tv = {.tv_sec = 5};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (got < 2) {
        int n = (int) recv(cfd, lb + got, 2 - got, 0);
        if (n <= 0)
            goto done;
        got += n;
    }
    int qlen = (lb[0] << 8) | lb[1];
    if (qlen < 12 || qlen > DNS_BUF)
        goto done;
    uint8_t pkt[DNS_BUF];
    got = 0;
    while (got < qlen) {
        int n = (int) recv(cfd, pkt + got, qlen - got, 0);
        if (n <= 0)
            goto done;
        got += n;
    }
    /* Resolve and send back over TCP */
    if (pkt[2] & 0x80)
        goto done; /* ignore responses */
    uint8_t resp[DNS_BUF * 2];
    int off = build_dns_response(pkt, qlen, 1 /* is_tcp */, resp, (int) sizeof(resp));
    if (off < 0)
        goto done;
    /* Send with 2-byte length prefix */
    uint8_t hdr[2];
    hdr[0] = off >> 8;
    hdr[1] = off & 0xFF;
    send(cfd, hdr, 2, MSG_NOSIGNAL);
    send(cfd, resp, off, MSG_NOSIGNAL);
done:
    close(cfd);
}

typedef struct {
    int cfd;
} tcp_client_arg_t;
static void *tcp_client_thread(void *arg) {
    tcp_client_arg_t *a = (tcp_client_arg_t *) arg;
    int cfd = a->cfd;
    free(a);
    proxy_handle_tcp(cfd);
    return NULL;
}

/* proxy_handle_dot — serve one DoT (RFC 7858) session: TLS handshake, then
 * the same 2-byte length-prefixed framing as plain DNS-over-TCP, just
 * inside the TLS record layer. One query per connection, matching
 * proxy_handle_tcp's existing simplification (no pipelining). */
static void proxy_handle_dot(int cfd) {
    struct timeval tv = {.tv_sec = 5};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    SSL *ssl = SSL_new(g_dot_server_ctx);
    if (!ssl) {
        close(cfd);
        return;
    }
    SSL_set_fd(ssl, cfd);
    if (SSL_accept(ssl) <= 0)
        goto done;
    {
        uint8_t lb[2];
        int got = 0;
        while (got < 2) {
            int n = SSL_read(ssl, lb + got, 2 - got);
            if (n <= 0)
                goto done;
            got += n;
        }
        int qlen = (lb[0] << 8) | lb[1];
        if (qlen < 12 || qlen > DNS_BUF)
            goto done;
        uint8_t pkt[DNS_BUF];
        got = 0;
        while (got < qlen) {
            int n = SSL_read(ssl, pkt + got, qlen - got);
            if (n <= 0)
                goto done;
            got += n;
        }
        if (pkt[2] & 0x80)
            goto done; /* ignore responses */
        uint8_t resp[DNS_BUF * 2];
        int off = build_dns_response(pkt, qlen, 1 /* is_tcp */, resp, (int) sizeof(resp));
        if (off < 0)
            goto done;
        uint8_t hdr[2] = {(uint8_t) (off >> 8), (uint8_t) (off & 0xFF)};
        SSL_write(ssl, hdr, 2);
        SSL_write(ssl, resp, off);
    }
done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
}

static void *dot_client_thread(void *arg) {
    tcp_client_arg_t *a = (tcp_client_arg_t *) arg;
    int cfd = a->cfd;
    free(a);
    proxy_handle_dot(cfd);
    return NULL;
}

static void apply_sandbox(void); /* defined below; drops privs + seccomp post-bind */

static void *proxy_run(void *arg) {
    (void) arg;
    int opt = 1;
    const char *proto_label = g_cfg.proto == PROTO_DOT   ? "DoT"
                              : g_cfg.proto == PROTO_DOH ? "DoH"
                              : g_cfg.proto == PROTO_TCP ? "TCP"
                                                         : "UDP";

    /* ── IPv4 UDP ─────────────────────────────────────────────────── */
    int fd4 = -1;
    fd4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd4 >= 0) {
        setsockopt(fd4, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in sa4 = {.sin_family = AF_INET,
                                  .sin_port = htons(g_cfg.listen_port),
                                  .sin_addr.s_addr = INADDR_ANY};
        if (bind(fd4, (struct sockaddr *) &sa4, sizeof(sa4)) < 0) {
            perror("proxy IPv4 UDP bind");
            close(fd4);
            fd4 = -1;
        }
    }

    /* ── IPv6 UDP ─────────────────────────────────────────────────── */
    int fd6 = -1;
    fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd6 >= 0) {
        setsockopt(fd6, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        int v6only = 1;
        setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        struct sockaddr_in6 sa6 = {.sin6_family = AF_INET6, .sin6_port = htons(g_cfg.listen_port)};
        if (bind(fd6, (struct sockaddr *) &sa6, sizeof(sa6)) < 0) {
            perror("proxy IPv6 UDP bind (non-fatal)");
            close(fd6);
            fd6 = -1;
        }
    }

    /* ── IPv4 TCP ─────────────────────────────────────────────────── */
    int tcp4 = -1;
    if (g_cfg.listen_tcp) {
        tcp4 = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp4 >= 0) {
            setsockopt(tcp4, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in sa4 = {.sin_family = AF_INET,
                                      .sin_port = htons(g_cfg.listen_port),
                                      .sin_addr.s_addr = INADDR_ANY};
            if (bind(tcp4, (struct sockaddr *) &sa4, sizeof(sa4)) < 0 || listen(tcp4, 32) < 0) {
                perror("proxy IPv4 TCP bind (non-fatal)");
                close(tcp4);
                tcp4 = -1;
            }
        }
    }

    /* ── IPv6 TCP ─────────────────────────────────────────────────── */
    int tcp6 = -1;
    if (g_cfg.listen_tcp) {
        tcp6 = socket(AF_INET6, SOCK_STREAM, 0);
        if (tcp6 >= 0) {
            setsockopt(tcp6, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            int v6only = 1;
            setsockopt(tcp6, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            struct sockaddr_in6 sa6 = {.sin6_family = AF_INET6,
                                       .sin6_port = htons(g_cfg.listen_port)};
            if (bind(tcp6, (struct sockaddr *) &sa6, sizeof(sa6)) < 0 || listen(tcp6, 32) < 0) {
                perror("proxy IPv6 TCP bind (non-fatal)");
                close(tcp6);
                tcp6 = -1;
            }
        }
    }

    /* ── DoT (RFC 7858) — resolverd's own stub-facing encrypted listener ──
     * Only bound when dot_server_init() (main()) built a context; a client
     * must never be pointed at an encrypted endpoint that doesn't exist. */
    int dotfd4 = -1, dotfd6 = -1;
    if (g_dot_server_ctx) {
        dotfd4 = socket(AF_INET, SOCK_STREAM, 0);
        if (dotfd4 >= 0) {
            setsockopt(dotfd4, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in sa4 = {.sin_family = AF_INET,
                                      .sin_port = htons(g_cfg.dot_server_port),
                                      .sin_addr.s_addr = INADDR_ANY};
            if (bind(dotfd4, (struct sockaddr *) &sa4, sizeof(sa4)) < 0 || listen(dotfd4, 32) < 0) {
                perror("proxy IPv4 DoT bind (non-fatal)");
                close(dotfd4);
                dotfd4 = -1;
            }
        }
        dotfd6 = socket(AF_INET6, SOCK_STREAM, 0);
        if (dotfd6 >= 0) {
            setsockopt(dotfd6, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            int v6only = 1;
            setsockopt(dotfd6, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            struct sockaddr_in6 sa6 = {.sin6_family = AF_INET6,
                                       .sin6_port = htons(g_cfg.dot_server_port)};
            if (bind(dotfd6, (struct sockaddr *) &sa6, sizeof(sa6)) < 0 || listen(dotfd6, 32) < 0) {
                perror("proxy IPv6 DoT bind (non-fatal)");
                close(dotfd6);
                dotfd6 = -1;
            }
        }
    }

    if (fd4 < 0 && fd6 < 0) {
        fprintf(stderr, "[proxy] No sockets available\n");
        return NULL;
    }

    printf("[proxy] Listening on :%d  IPv4-UDP=%s IPv6-UDP=%s IPv4-TCP=%s IPv6-TCP=%s\n"
           "        → %s:%d + %d upstream(s) (%s)\n",
           g_cfg.listen_port, fd4 >= 0 ? "up" : "n/a", fd6 >= 0 ? "up" : "n/a",
           tcp4 >= 0 ? "up" : "n/a", tcp6 >= 0 ? "up" : "n/a", g_cfg.upstream_host[0],
           g_cfg.upstream_port[0], g_cfg.upstream_count, proto_label);
    if (g_dot_server_ctx)
        printf("[proxy] DoT (RFC 7858) on :%d  IPv4=%s IPv6=%s  DDR adn=%s\n",
               g_cfg.dot_server_port, dotfd4 >= 0 ? "up" : "n/a", dotfd6 >= 0 ? "up" : "n/a",
               g_cfg.dot_server_adn);

    /* All listeners are bound. Drop root, confine the filesystem, and install the
     * syscall filter before the loop touches untrusted query/response bytes. */
    apply_sandbox();

    uint8_t buf[DNS_BUF];
    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        int maxfd = -1;
        if (fd4 >= 0) {
            FD_SET(fd4, &fds);
            if (fd4 > maxfd)
                maxfd = fd4;
        }
        if (fd6 >= 0) {
            FD_SET(fd6, &fds);
            if (fd6 > maxfd)
                maxfd = fd6;
        }
        if (tcp4 >= 0) {
            FD_SET(tcp4, &fds);
            if (tcp4 > maxfd)
                maxfd = tcp4;
        }
        if (tcp6 >= 0) {
            FD_SET(tcp6, &fds);
            if (tcp6 > maxfd)
                maxfd = tcp6;
        }
        if (dotfd4 >= 0) {
            FD_SET(dotfd4, &fds);
            if (dotfd4 > maxfd)
                maxfd = dotfd4;
        }
        if (dotfd6 >= 0) {
            FD_SET(dotfd6, &fds);
            if (dotfd6 > maxfd)
                maxfd = dotfd6;
        }
        if (maxfd < 0)
            break;
        struct timeval tv = {.tv_sec = 30};
        int r = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }
        if (r == 0)
            continue;

        /* IPv4 UDP */
        if (fd4 >= 0 && FD_ISSET(fd4, &fds)) {
            struct sockaddr_in src4;
            socklen_t sl = sizeof(src4);
            ssize_t n = recvfrom(fd4, buf, sizeof(buf), 0, (struct sockaddr *) &src4, &sl);
            if (n > 0)
                proxy_handle(fd4, buf, (int) n, (struct sockaddr *) &src4, sl);
        }

        /* IPv6 UDP */
        if (fd6 >= 0 && FD_ISSET(fd6, &fds)) {
            struct sockaddr_in6 src6;
            socklen_t sl = sizeof(src6);
            ssize_t n = recvfrom(fd6, buf, sizeof(buf), 0, (struct sockaddr *) &src6, &sl);
            if (n > 0)
                proxy_handle(fd6, buf, (int) n, (struct sockaddr *) &src6, sl);
        }

        /* IPv4 TCP — spawn thread per connection */
        if (tcp4 >= 0 && FD_ISSET(tcp4, &fds)) {
            int cfd = accept(tcp4, NULL, NULL);
            if (cfd >= 0) {
                tcp_client_arg_t *ta = malloc(sizeof(*ta));
                ta->cfd = cfd;
                pthread_t tid;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&tid, &attr, tcp_client_thread, ta);
                pthread_attr_destroy(&attr);
            }
        }

        /* IPv6 TCP — spawn thread per connection */
        if (tcp6 >= 0 && FD_ISSET(tcp6, &fds)) {
            int cfd = accept(tcp6, NULL, NULL);
            if (cfd >= 0) {
                tcp_client_arg_t *ta = malloc(sizeof(*ta));
                ta->cfd = cfd;
                pthread_t tid;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&tid, &attr, tcp_client_thread, ta);
                pthread_attr_destroy(&attr);
            }
        }

        /* IPv4 DoT — spawn thread per connection */
        if (dotfd4 >= 0 && FD_ISSET(dotfd4, &fds)) {
            int cfd = accept(dotfd4, NULL, NULL);
            if (cfd >= 0) {
                tcp_client_arg_t *ta = malloc(sizeof(*ta));
                ta->cfd = cfd;
                pthread_t tid;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&tid, &attr, dot_client_thread, ta);
                pthread_attr_destroy(&attr);
            }
        }

        /* IPv6 DoT — spawn thread per connection */
        if (dotfd6 >= 0 && FD_ISSET(dotfd6, &fds)) {
            int cfd = accept(dotfd6, NULL, NULL);
            if (cfd >= 0) {
                tcp_client_arg_t *ta = malloc(sizeof(*ta));
                ta->cfd = cfd;
                pthread_t tid;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&tid, &attr, dot_client_thread, ta);
                pthread_attr_destroy(&attr);
            }
        }
    }
    if (fd4 >= 0)
        close(fd4);
    if (fd6 >= 0)
        close(fd6);
    if (tcp4 >= 0)
        close(tcp4);
    if (tcp6 >= 0)
        close(tcp6);
    if (dotfd4 >= 0)
        close(dotfd4);
    if (dotfd6 >= 0)
        close(dotfd6);
    return NULL;
}

/* =========================================================================
 * Configuration loading
 * ======================================================================= */
static const char *getenv_or(const char *key, const char *def) {
    const char *v = getenv(key);
    return v && v[0] ? v : def;
}

static void config_load_env(void) {
    safe_strcpy(g_cfg.upstream_host[0], getenv_or("UPSTREAM_HOST", "127.0.0.1"),
                sizeof(g_cfg.upstream_host[0]));
    g_cfg.upstream_port[0] = atoi(getenv_or("UPSTREAM_PORT", "5353"));
    g_cfg.upstream_proto[0] = PROTO_UDP; /* overridden below by UPSTREAM_PROTO */
    g_cfg.upstream_count = 1;
    /* Parse UPSTREAM_FALLBACKS: comma-separated host:port[:proto] */
    const char *fallbacks = getenv_or("UPSTREAM_FALLBACKS", "");
    if (fallbacks[0]) {
        char fb[512];
        safe_strcpy(fb, fallbacks, sizeof(fb));
        char *sp5 = NULL;
        char *tok = strtok_r(fb, ",", &sp5);
        while (tok && g_cfg.upstream_count < MAX_UPSTREAMS) {
            int idx = g_cfg.upstream_count;
            /* format: host:port[:udp|tcp|dot] */
            char h[256] = "";
            int p = 5353;
            char pr[8] = "udp";
            char *col = strchr(tok, ':');
            if (col) {
                *col = 0;
                safe_strcpy(h, tok, sizeof(h));
                char *col2 = strchr(col + 1, ':');
                if (col2) {
                    *col2 = 0;
                    p = atoi(col + 1);
                    safe_strcpy(pr, col2 + 1, sizeof(pr));
                } else
                    p = atoi(col + 1);
            } else
                safe_strcpy(h, tok, sizeof(h));
            safe_strcpy(g_cfg.upstream_host[idx], h, sizeof(g_cfg.upstream_host[idx]));
            g_cfg.upstream_port[idx] = p;
            if (!strcasecmp(pr, "dot"))
                g_cfg.upstream_proto[idx] = PROTO_DOT;
            else if (!strcasecmp(pr, "tcp"))
                g_cfg.upstream_proto[idx] = PROTO_TCP;
            else if (!strcasecmp(pr, "doh"))
                g_cfg.upstream_proto[idx] = PROTO_DOH;
            else
                g_cfg.upstream_proto[idx] = PROTO_UDP;
            g_cfg.upstream_count++;
            tok = strtok_r(NULL, ",", &sp5);
        }
    }
    g_cfg.listen_port = atoi(getenv_or("LISTEN_PORT", "5354"));
    const char *proto = getenv_or("UPSTREAM_PROTO", "udp");
    if (!strcasecmp(proto, "dot")) {
        g_cfg.proto = PROTO_DOT;
        g_cfg.upstream_proto[0] = PROTO_DOT;
    } else if (!strcasecmp(proto, "tcp")) {
        g_cfg.proto = PROTO_TCP;
        g_cfg.upstream_proto[0] = PROTO_TCP;
    } else if (!strcasecmp(proto, "doh")) {
        g_cfg.proto = PROTO_DOH;
        g_cfg.upstream_proto[0] = PROTO_DOH;
    } else {
        g_cfg.proto = PROTO_UDP;
        g_cfg.upstream_proto[0] = PROTO_UDP;
    }
    safe_strcpy(g_cfg.tsig_key_name, getenv_or("TSIG_KEY_NAME", ""), sizeof(g_cfg.tsig_key_name));
    const char *tsig_b64 = getenv_or("TSIG_SECRET_B64", "");
    if (tsig_b64[0])
        g_cfg.tsig_secret_len = b64std_dec(tsig_b64, g_cfg.tsig_secret, sizeof(g_cfg.tsig_secret));
    const char *ckhex = getenv_or("COOKIE_SECRET", "");
    if (ckhex[0])
        hex_dec(ckhex, g_cfg.cookie_secret, 16);
    else
        RAND_bytes(g_cfg.cookie_secret, 16);
    safe_strcpy(g_cfg.valkey_host, getenv_or("VALKEY_HOST", "127.0.0.1"),
                sizeof(g_cfg.valkey_host));
    g_cfg.valkey_port = atoi(getenv_or("VALKEY_PORT", "6379"));
    safe_strcpy(g_cfg.valkey_pass, getenv_or("VALKEY_PASS", ""), sizeof(g_cfg.valkey_pass));
    g_cfg.cache_size = atoi(getenv_or("CACHE_SIZE", "8192"));
    g_cfg.cache_ttl_max = (uint32_t) atoi(getenv_or("CACHE_TTL_MAX", "3600"));
    g_cfg.cache_neg_ttl = (uint32_t) atoi(getenv_or("CACHE_NEG_TTL", "300"));
    safe_strcpy(g_cfg.dot_ca_pem, getenv_or("DOT_CA_PEM", ""), sizeof(g_cfg.dot_ca_pem));
    g_cfg.cache_neg_ttl_min = (uint32_t) atoi(getenv_or("CACHE_NEG_TTL_MIN", "1"));
    g_cfg.serve_stale_max = (uint32_t) atoi(getenv_or("SERVE_STALE_MAX", "3600"));
    g_cfg.servfail_cache_ttl = (uint32_t) atoi(getenv_or("SERVFAIL_CACHE_TTL", "30"));
    safe_strcpy(g_cfg.doh_path, getenv_or("DOH_PATH", "/dns-query"), sizeof(g_cfg.doh_path));
    g_cfg.doh_port = atoi(getenv_or("DOH_PORT", "443"));
    g_cfg.listen_tcp = atoi(getenv_or("LISTEN_TCP", "1"));
    g_cfg.dns0x20_enabled = atoi(getenv_or("DNS0X20_ENABLED", "1"));
    safe_strcpy(g_cfg.dns0x20_disable, getenv_or("DNS0X20_DISABLE", ""),
                sizeof(g_cfg.dns0x20_disable));
    g_cfg.aggressive_nsec_enabled = atoi(getenv_or("AGGRESSIVE_NSEC", "1"));
    g_cfg.dot_server_enabled = atoi(getenv_or("DOT_SERVER_ENABLED", "0"));
    g_cfg.dot_server_port = atoi(getenv_or("DOT_SERVER_PORT", "8854"));
    safe_strcpy(g_cfg.dot_server_cert_pem, getenv_or("DOT_SERVER_CERT_PEM", ""),
                sizeof(g_cfg.dot_server_cert_pem));
    safe_strcpy(g_cfg.dot_server_key_pem, getenv_or("DOT_SERVER_KEY_PEM", ""),
                sizeof(g_cfg.dot_server_key_pem));
    safe_strcpy(g_cfg.dot_server_adn, getenv_or("DOT_SERVER_ADN", ""),
                sizeof(g_cfg.dot_server_adn));
    /* Search domains: SEARCH_DOMAINS=domain1,domain2,... */
    g_cfg.search_domain_count = 0;
    const char *sdomains = getenv_or("SEARCH_DOMAINS", "");
    if (sdomains[0]) {
        char sd_buf[1024];
        safe_strcpy(sd_buf, sdomains, sizeof(sd_buf));
        char *sp6 = NULL;
        char *stok = strtok_r(sd_buf, ",", &sp6);
        while (stok && g_cfg.search_domain_count < MAX_SEARCH_DOMAINS) {
            safe_strcpy(g_cfg.search_domains[g_cfg.search_domain_count], stok,
                        sizeof(g_cfg.search_domains[g_cfg.search_domain_count]));
            g_cfg.search_domain_count++;
            stok = strtok_r(NULL, ",", &sp6);
        }
    }
    /* Per-domain routing: DOMAIN_ROUTES=suffix=host:port[:proto],... */
    const char *dr_env = getenv_or("DOMAIN_ROUTES", "");
    if (dr_env[0]) {
        char dr_buf[2048];
        safe_strcpy(dr_buf, dr_env, sizeof(dr_buf));
        char *sp7 = NULL;
        char *dr_tok = strtok_r(dr_buf, ",", &sp7);
        while (dr_tok) {
            parse_server_arg(dr_tok);
            dr_tok = strtok_r(NULL, ",", &sp7);
        }
    }
    /* DNSSEC trust anchors: DNSSEC_TRUST_ANCHORS=hex1,hex2,... */
    const char *ta_env = getenv_or("DNSSEC_TRUST_ANCHORS", "");
    if (ta_env[0]) {
        char ta_buf[2048];
        safe_strcpy(ta_buf, ta_env, sizeof(ta_buf));
        char *sp8 = NULL;
        char *ta_tok = strtok_r(ta_buf, ",", &sp8);
        while (ta_tok) {
            dnssec_add_trust_anchor(ta_tok);
            ta_tok = strtok_r(NULL, ",", &sp8);
        }
    }
    /* Load persisted routes from Valkey: domain_route:<suffix> → host:port:proto */
    /* (called after vk is connected — deferred to first use in dns_resolve) */
    /* Try Valkey if reachable */
    g_cfg.valkey_enabled = 1;
    memset(&g_vk, 0, sizeof(g_vk));
    g_vk.fd = -1;
}

static void config_load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0] || line[0] == '#')
            continue;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        while (*v == ' ')
            v++;
        setenv(k, v, 1);
    }
    fclose(f);
    config_load_env();
}

/* =========================================================================
 * DoT SSL context initialisation
 * ======================================================================= */
static void dot_init(void) {
    g_dot_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_dot_ctx)
        return;
    SSL_CTX_set_min_proto_version(g_dot_ctx, TLS1_2_VERSION);
    if (g_cfg.dot_ca_pem[0]) {
        /* Explicit PEM file: loaded eagerly into the in-memory store here. */
        if (SSL_CTX_load_verify_locations(g_dot_ctx, g_cfg.dot_ca_pem, NULL) != 1)
            fprintf(stderr,
                    "[dot] warning: could not load CA bundle '%s' — upstream TLS "
                    "verification will fail\n",
                    g_cfg.dot_ca_pem);
    } else {
        /* Default system trust store. SSL_CTX_set_default_verify_paths only
         * records the path and resolves it lazily at handshake time — which,
         * under the sandbox, happens after chroot/pivot_root has removed
         * /etc/ssl. Eagerly load the default CA *file* now (pre-sandbox) so peer
         * verification still works once confined; keep set_default_verify_paths
         * as the (lazy) hashed-dir fallback. */
        const char *cafile = X509_get_default_cert_file();
        if (!cafile || SSL_CTX_load_verify_locations(g_dot_ctx, cafile, NULL) != 1)
            fprintf(stderr,
                    "[dot] warning: could not eagerly load default CA file '%s' — "
                    "upstream TLS verification may fail under chroot\n",
                    cafile ? cafile : "(null)");
        SSL_CTX_set_default_verify_paths(g_dot_ctx);
    }
    SSL_CTX_set_verify(g_dot_ctx, SSL_VERIFY_PEER, NULL);
}

/* Read a whole file into buf (NUL-terminated). Returns the length, or -1 on
 * any I/O error or if it doesn't fit. */
static int read_pem_file(const char *path, char *buf, int bufsz) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int n = (int) fread(buf, 1, (size_t) (bufsz - 1), f);
    int had_more = !feof(f);
    fclose(f);
    if (n <= 0 || had_more)
        return -1;
    buf[n] = 0;
    return n;
}

#define DOT_SERVER_PEM_MAX 16384

/*
 * dot_server_init — RFC 7858 DoT server for resolverd's own stub clients,
 * plus the RFC 9462 DDR record that advertises it. Both are opt-in and only
 * activate together: a client must never be told about an encrypted
 * endpoint resolverd doesn't actually serve, so the DDR SVCB record
 * (g_ddr_svcb_rdata) is only populated when the DoT context itself loaded
 * successfully. Cert/key are read into memory HERE, before apply_sandbox()
 * confines the filesystem — same reasoning as dot_init's eager CA load
 * above (the chroot may not carry these files).
 */
static void dot_server_init(void) {
    if (!g_cfg.dot_server_enabled)
        return;
    if (!g_cfg.dot_server_cert_pem[0] || !g_cfg.dot_server_key_pem[0] || !g_cfg.dot_server_adn[0]) {
        fprintf(stderr, "[dot-server] DOT_SERVER_ENABLED=1 but cert/key/ADN is not fully "
                        "configured — DoT listener and DDR advertisement stay OFF\n");
        return;
    }
    static char cert_pem[DOT_SERVER_PEM_MAX];
    static char key_pem[DOT_SERVER_PEM_MAX];
    if (read_pem_file(g_cfg.dot_server_cert_pem, cert_pem, sizeof(cert_pem)) < 0) {
        fprintf(stderr, "[dot-server] could not read cert PEM '%s' — DoT listener stays OFF\n",
                g_cfg.dot_server_cert_pem);
        return;
    }
    if (read_pem_file(g_cfg.dot_server_key_pem, key_pem, sizeof(key_pem)) < 0) {
        fprintf(stderr, "[dot-server] could not read key PEM '%s' — DoT listener stays OFF\n",
                g_cfg.dot_server_key_pem);
        return;
    }
    g_dot_server_ctx = tls_server_ctx_from_pem(cert_pem, key_pem, NULL, 0);
    if (!g_dot_server_ctx) {
        fprintf(stderr, "[dot-server] cert/key failed to load — DoT listener stays OFF\n");
        return;
    }
    /* RFC 7858 §3.2: select "dot" ALPN (shared with dnsd — see dns_wire.c). */
    SSL_CTX_set_alpn_select_cb(g_dot_server_ctx, dot_alpn_select_cb, NULL);

    /* RFC 9462 DDR: precompute the SVCB record advertising this listener,
     * via the same presentation-format encoder dnsd uses for zone SVCB
     * records (svcb_present_to_tlv + svcb_tlv_to_wire) — no second encoder. */
    char present[512];
    snprintf(present, sizeof(present), "1 %s alpn=dot port=%d", g_cfg.dot_server_adn,
             g_cfg.dot_server_port);
    uint8_t tlv[512];
    int tlvlen = svcb_present_to_tlv(present, tlv, sizeof(tlv));
    if (tlvlen > 0)
        g_ddr_svcb_rdata_len =
            svcb_tlv_to_wire(tlv, tlvlen, g_ddr_svcb_rdata, sizeof(g_ddr_svcb_rdata));
    if (g_ddr_svcb_rdata_len <= 0) {
        fprintf(stderr, "[dot-server] failed to build the DDR SVCB record for ADN '%s'\n",
                g_cfg.dot_server_adn);
        g_ddr_svcb_rdata_len = 0;
    }
}

/* =========================================================================
 * Cache initialisation
 * ======================================================================= */
static void cache_init(void) {
    for (int i = 0; i < CACHE_BUCKETS; i++) {
        g_cache[i].head = NULL;
        g_cache[i].count = 0;
        pthread_rwlock_init(&g_cache[i].lock, NULL);
    }
}

/* =========================================================================
 * CLI output helpers
 * ======================================================================= */
static void print_result(const char *qname, uint16_t qtype, const resolve_result_t *r,
                         long rtt_us) {
    const char *proto_str = g_cfg.proto == PROTO_DOT   ? "DoT"
                            : g_cfg.proto == PROTO_DOH ? "DoH"
                            : g_cfg.proto == PROTO_TCP ? "TCP"
                                                       : "UDP";
    printf("\n;; Query: %s %s  via %s %s:%d\n", qname, type2str(qtype), proto_str,
           g_cfg.upstream_host[0], g_cfg.upstream_port[0]);
    if (g_cfg.tsig_key_name[0])
        printf(";; TSIG:  %s\n", g_cfg.tsig_key_name);
    const char *sec_str[] = {"UNCHECKED", "SECURE", "INSECURE", "BOGUS"};
    int ds = r->dnssec_status;
    if (ds >= 0 && ds <= 3)
        printf(";; DNSSEC: %s%s\n", sec_str[ds], ds == 1 ? " ✓" : ds == 3 ? " ✗" : "");
    printf(";; Status: %s%s  ",
           r->rcode == 0   ? "NOERROR"
           : r->rcode == 1 ? "FORMERR"
           : r->rcode == 2 ? "SERVFAIL"
           : r->rcode == 3 ? "NXDOMAIN"
           : r->rcode == 5 ? "REFUSED"
                           : "?",
           r->rcode == 3     ? " (NXDOMAIN)"
           : r->ancount == 0 ? " (NODATA)"
                             : "");
    if (r->from_cache == 2)
        printf("(STALE, revalidating in background)\n");
    else if (r->from_cache == 1)
        printf("(CACHED, TTL=%us remaining)\n", r->cache_ttl_remaining);
    else if (rtt_us > 0)
        printf("(UPSTREAM, RTT=%ldµs)\n", rtt_us);
    else
        printf("\n");
    if (r->ancount == 0) {
        printf(";; No answers\n");
        return;
    }
    printf(";; ANSWER SECTION:\n");
    printf("%-40s %-6s %-8s %s\n", "NAME", "TTL", "TYPE", "RDATA");
    printf("%-40s %-6s %-8s %s\n", "----", "---", "----", "-----");
    for (int i = 0; i < r->ancount; i++)
        printf("%-40s %-6u %-8s %s\n", r->answer_names[i], r->answer_ttls[i],
               type2str(r->answer_types[i]), r->answers[i]);
}

static void print_stats(void) {
    printf("\n── Cache Statistics ─────────────────────────────\n");
    printf("  Entries (in-memory):  %d / %d\n", g_cache_total, g_cfg.cache_size);
    printf("  Queries:              %llu\n", (unsigned long long) g_stat_queries);
    printf("  Cache hits:           %llu\n", (unsigned long long) g_stat_hits);
    printf("  Cache misses:         %llu\n", (unsigned long long) g_stat_misses);
    printf("  Expired entries:      %llu\n", (unsigned long long) g_stat_expired);
    printf("  Negative cached:      %llu\n", (unsigned long long) g_stat_negcache);
    printf("  Stale served:         %llu\n", (unsigned long long) g_stat_stale);
    if (g_stat_queries > 0)
        printf("  Hit rate:             %.1f%%\n", 100.0 * g_stat_hits / g_stat_queries);
    for (int ui = 0; ui < g_cfg.upstream_count; ui++) {
        const char *pstr = g_cfg.upstream_proto[ui] == PROTO_DOT   ? "DoT"
                           : g_cfg.upstream_proto[ui] == PROTO_DOH ? "DoH"
                           : g_cfg.upstream_proto[ui] == PROTO_TCP ? "TCP"
                                                                   : "UDP";
        printf("  Upstream[%d]:          %s:%d (%s) RTT≈%ldµs\n", ui, g_cfg.upstream_host[ui],
               g_cfg.upstream_port[ui], pstr, g_upstream_rtt_ema[ui]);
    }
    printf("  TSIG:                 %s\n",
           g_cfg.tsig_key_name[0] ? g_cfg.tsig_key_name : "disabled");
    printf("  Valkey cache:         %s\n", g_cfg.valkey_enabled ? "enabled" : "disabled");
    if (g_route_count > 0) {
        printf("\n── Domain Routes ────────────────────────────────\n");
        printf("  %-40s → %s\n", "Suffix", "Upstream");
        pthread_mutex_lock(&g_route_mutex);
        for (int i = 0; i < g_route_count; i++) {
            int ui = g_routes[i].upstream_idx;
            const char *ps = g_cfg.upstream_proto[ui] == PROTO_DOT   ? "DoT"
                             : g_cfg.upstream_proto[ui] == PROTO_DOH ? "DoH"
                             : g_cfg.upstream_proto[ui] == PROTO_TCP ? "TCP"
                                                                     : "UDP";
            printf("  %-40s → %s:%d (%s)\n",
                   g_routes[i].suffix[0] == "."[0] && !g_routes[i].suffix[1] ? ".(catch-all)"
                                                                             : g_routes[i].suffix,
                   g_cfg.upstream_host[ui], g_cfg.upstream_port[ui], ps);
        }
        pthread_mutex_unlock(&g_route_mutex);
    }
}

static void dump_cache(void) {
    printf("\n── Cache Dump ───────────────────────────────────\n");
    printf("%-40s %-8s %-8s %s\n", "NAME", "TYPE", "TTL", "RDATA");
    int total = 0;
    for (int b = 0; b < CACHE_BUCKETS; b++) {
        pthread_rwlock_rdlock(&g_cache[b].lock);
        cache_entry_t *e = g_cache[b].head;
        while (e) {
            uint32_t rem = entry_remaining_ttl(e);
            if (rem > 0) {
                if (e->negative) {
                    printf("%-40s %-8s %-8s %s\n", e->qname, type2str(e->qtype), "", "NEGATIVE");
                    total++;
                } else
                    for (int i = 0; i < e->nrr; i++) {
                        char rdata_s[256] = "";
                        if (e->rrs[i].rdata && e->rrs[i].rdlen > 0)
                            rdata_to_str(e->rrs[i].rdata, e->rrs[i].rdlen, 0, e->rrs[i].rdlen,
                                         e->rrs[i].type, rdata_s, sizeof(rdata_s));
                        printf("%-40s %-8s %-8u %s\n", e->qname, type2str(e->rrs[i].type), rem,
                               rdata_s);
                        total++;
                    }
            }
            e = e->hash_next;
        }
        pthread_rwlock_unlock(&g_cache[b].lock);
    }
    printf("── %d live records ──────────────────────────────\n", total);
}

/* =========================================================================
 * main
 * ======================================================================= */
static void usage(const char *prog) {
    printf("Usage:\n"
           "  %s                         Start caching proxy on LISTEN_PORT\n"
           "  %s <name> [type]           One-shot query (default type: A)\n"
           "  %s --stats                 Show cache statistics\n"
           "  %s --flush                 Flush entire cache\n"
           "  %s --flush <name> [type]   Flush specific entry\n"
           "  %s --dump                  Dump all cached records\n"
           "\nOptions (can also be set via environment variables):\n"
           "  --upstream <host:port>     Upstream dns_server  [UPSTREAM_HOST/PORT]\n"
           "  --proto <udp|tcp|dot|doh>  Transport            [UPSTREAM_PROTO]\n"
           "  --listen <port>            Local proxy port     [LISTEN_PORT]\n"
           "  --tsig-key <name:b64>      TSIG key name:secret [TSIG_KEY_NAME/SECRET_B64]\n"
           "  --cookie-secret <hex>      16-byte cookie secret[COOKIE_SECRET]\n"
           "  --valkey <host:port>       Valkey cache server  [VALKEY_HOST/PORT]\n"
           "  --no-valkey                Disable Valkey cache\n"
           "  --cache-size <n>           Max in-memory entries[CACHE_SIZE]\n"
           "  --fallback <host:port[:proto]> Add fallback upstream [UPSTREAM_FALLBACKS]\n"
           "  --search <domain>          Append search domain   [SEARCH_DOMAINS]\n"
           "  --trust-anchor <hex>       SHA-256 of trusted DNSKEY RDATA [DNSSEC_TRUST_ANCHORS]\n"
           "  --doh-path <path>          DoH URL path         [DOH_PATH=/dns-query]\n"
           "  --doh-port <port>          DoH server port      [DOH_PORT=443]\n"
           "  --server /suffix/host:port[:proto]  Route suffix to upstream (dnsmasq syntax)\n"
           "  --route  suffix=host:port[:proto]   Same, alternate syntax    [DOMAIN_ROUTES]\n"
           "  --no-tcp-proxy             Disable TCP proxy listener\n"
           "  --no-dnssec                Disable DNSSEC validation\n"
           "  --no-mdns                  Disable mDNS for .local names\n"
           "  --conf <path>              Load config from file\n"
           "\nExamples:\n"
           "  %s example.local A\n"
           "  %s _http._tcp.local SRV --upstream 10.0.0.1:5353\n"
           "  %s example.local MX --proto dot --upstream 10.0.0.1:8853\n"
           "  UPSTREAM_HOST=10.0.0.1 TSIG_SECRET_B64=abc== %s --stats\n",
           prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

/* ==========================================================================
 * Sandbox glue — delegates to libsandbox (sandbox.c/h), shared with dnsd.
 *
 * resolverd is internet-facing on two sides: it parses untrusted *upstream*
 * responses and serves untrusted *downstream* queries, so it gets the same
 * defence-in-depth as dnsd. The hardening logic lives once in sandbox.c; this
 * glue only resolves resolverd-scoped config and hands it over.
 *
 * Config is resolverd-scoped (NOT shared with dnsd's keys) because the two
 * daemons need different filesystem views and syscall sets: resolverd makes
 * outbound connections and resolves upstream hostnames, so its chroot must carry
 * resolver files + a CA bundle. All config is read HERE, before sandbox_apply()
 * chroots, so a chroot that hides the config source cannot silently weaken the
 * filter. seccomp defaults to enforce: the whitelist was strace-harvested across
 * every upstream transport (UDP/TCP/DoT-TLS/DoH, IP + hostname/getaddrinfo
 * upstreams, cache miss/hit, DNSSEC validation) on glibc/Fedora and confirmed to
 * issue no syscall outside sandbox.c's base[]+getaddrinfo group (zero gaps, no
 * EPERM under enforce). Override to "audit" per-deployment to re-harvest on a
 * different libc/kernel before trusting enforce there. */
static void resolverd_log(int level, const char *fmt, ...) {
    (void) level;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void apply_sandbox(void) {
    sandbox_config_t sb;
    memset(&sb, 0, sizeof(sb));
    vk_get("config:resolverd_chroot_dir", sb.chroot_dir, sizeof(sb.chroot_dir));
    sandbox_env_override(sb.chroot_dir, sizeof(sb.chroot_dir), "RESOLVERD_CHROOT");
    vk_get("config:resolverd_isolation_mode", sb.isolation_mode, sizeof(sb.isolation_mode));
    sandbox_env_override(sb.isolation_mode, sizeof(sb.isolation_mode), "RESOLVERD_ISOLATION");
    vk_get("config:resolverd_privdrop_user", sb.privdrop_user, sizeof(sb.privdrop_user));
    sandbox_env_override(sb.privdrop_user, sizeof(sb.privdrop_user), "RESOLVERD_USER");
    vk_get("config:resolverd_privdrop_group", sb.privdrop_group, sizeof(sb.privdrop_group));
    sandbox_env_override(sb.privdrop_group, sizeof(sb.privdrop_group), "RESOLVERD_GROUP");
    vk_get("config:resolverd_seccomp_mode", sb.seccomp_mode, sizeof(sb.seccomp_mode));
    sandbox_env_override(sb.seccomp_mode, sizeof(sb.seccomp_mode), "RESOLVERD_SECCOMP");
    /* enforce by default — whitelist harvest-validated across all transports (see above) */
    sb.seccomp_default = SANDBOX_SECCOMP_ENFORCE;
    sb.extra_syscall_groups = SANDBOX_SYS_GETADDRINFO; /* glibc resolver for upstream hostnames */
    sb.log = resolverd_log;
    sb.tag = "resolverd";
    sandbox_apply(&sb);
}

#ifndef UNIT_TEST
/* ADR-003 schema-version gate (serving/proxy path only — one-shot CLI queries do
 * not participate in the long-running bus contract). resolverd is NOT the seeder;
 * dnsd writes schema:version. Absent or Valkey-down is treated as "assume current"
 * and never blocks; only an explicit incompatible major (or unparseable value)
 * refuses. Returns 0 to proceed, -1 to refuse. */
static int schema_gate(void) {
    char sv[32] = "";
    vk_get("schema:version", sv, sizeof(sv));
    switch (schema_version_check(sv)) {
        case SCHEMA_OK:
            return 0;
        case SCHEMA_MINOR_DIFF:
            fprintf(stderr,
                    "[Schema] schema:version %s differs in minor from compiled %s — continuing\n",
                    sv, SCHEMA_VERSION_STR);
            return 0;
        case SCHEMA_ABSENT:
            fprintf(stderr, "[Schema] schema:version absent — assuming compiled %s\n",
                    SCHEMA_VERSION_STR);
            return 0;
        default: /* SCHEMA_MAJOR_DIFF or SCHEMA_MALFORMED */
            fprintf(
                stderr,
                "[Schema] schema:version %s incompatible with compiled %s — refusing to start\n",
                sv[0] ? sv : "(unparseable)", SCHEMA_VERSION_STR);
            return -1;
    }
}

int main(int argc, char **argv) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));
    /* Load defaults */
    config_load_env();
    /* Parse arguments */
    int mode_proxy = 0, mode_stats = 0, mode_flush = 0, mode_dump = 0;
    char query_name[256] = "", query_type_s[32] = "A";
    char flush_name[256] = "", flush_type_s[32] = "A";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--stats")) {
            mode_stats = 1;
        } else if (!strcmp(argv[i], "--dump")) {
            mode_dump = 1;
        } else if (!strcmp(argv[i], "--flush")) {
            mode_flush = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                safe_strcpy(flush_name, argv[++i], sizeof(flush_name));
                if (i + 1 < argc && argv[i + 1][0] != '-')
                    safe_strcpy(flush_type_s, argv[++i], sizeof(flush_type_s));
            }
        } else if (!strcmp(argv[i], "--upstream") && i + 1 < argc) {
            char *col = strchr(argv[i + 1], ':');
            if (col) {
                *col = 0;
                safe_strcpy(g_cfg.upstream_host[0], argv[i + 1], sizeof(g_cfg.upstream_host[0]));
                g_cfg.upstream_port[0] = atoi(col + 1);
                *col = ':';
            } else
                safe_strcpy(g_cfg.upstream_host[0], argv[++i], sizeof(g_cfg.upstream_host[0]));
            i++;
        } else if (!strcmp(argv[i], "--proto") && i + 1 < argc) {
            i++;
            if (!strcasecmp(argv[i], "dot"))
                g_cfg.proto = PROTO_DOT;
            else if (!strcasecmp(argv[i], "tcp"))
                g_cfg.proto = PROTO_TCP;
            else if (!strcasecmp(argv[i], "doh"))
                g_cfg.proto = PROTO_DOH;
            else
                g_cfg.proto = PROTO_UDP;
            /* The query path dispatches on the per-upstream transport
             * (upstream_proto[0]), not g_cfg.proto. Keep them in sync — as the
             * env UPSTREAM_PROTO path does — so --proto dot/tcp/doh is honoured
             * instead of silently falling back to plaintext UDP. */
            g_cfg.upstream_proto[0] = g_cfg.proto;
        } else if (!strcmp(argv[i], "--listen") && i + 1 < argc) {
            g_cfg.listen_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--tsig-key") && i + 1 < argc) {
            i++;
            char *col = strchr(argv[i], ':');
            if (col) {
                *col = 0;
                safe_strcpy(g_cfg.tsig_key_name, argv[i], sizeof(g_cfg.tsig_key_name));
                g_cfg.tsig_secret_len =
                    b64std_dec(col + 1, g_cfg.tsig_secret, sizeof(g_cfg.tsig_secret));
                *col = ':';
            } else
                safe_strcpy(g_cfg.tsig_key_name, argv[i], sizeof(g_cfg.tsig_key_name));
        } else if (!strcmp(argv[i], "--cookie-secret") && i + 1 < argc)
            hex_dec(argv[++i], g_cfg.cookie_secret, 16);
        else if (!strcmp(argv[i], "--valkey") && i + 1 < argc) {
            i++;
            char *col = strchr(argv[i], ':');
            if (col) {
                *col = 0;
                safe_strcpy(g_cfg.valkey_host, argv[i], sizeof(g_cfg.valkey_host));
                g_cfg.valkey_port = atoi(col + 1);
            } else
                safe_strcpy(g_cfg.valkey_host, argv[i], sizeof(g_cfg.valkey_host));
        } else if (!strcmp(argv[i], "--no-valkey")) {
            g_cfg.valkey_enabled = 0;
        } else if (!strcmp(argv[i], "--cache-size") && i + 1 < argc) {
            g_cfg.cache_size = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--fallback") && i + 1 < argc) {
            i++;
            if (g_cfg.upstream_count < MAX_UPSTREAMS) {
                int idx = g_cfg.upstream_count;
                char *col = strchr(argv[i], ':');
                if (col) {
                    *col = 0;
                    safe_strcpy(g_cfg.upstream_host[idx], argv[i],
                                sizeof(g_cfg.upstream_host[idx]));
                    char *col2 = strchr(col + 1, ':');
                    if (col2) {
                        *col2 = 0;
                        g_cfg.upstream_port[idx] = atoi(col + 1);
                        if (!strcasecmp(col2 + 1, "dot"))
                            g_cfg.upstream_proto[idx] = PROTO_DOT;
                        else if (!strcasecmp(col2 + 1, "tcp"))
                            g_cfg.upstream_proto[idx] = PROTO_TCP;
                        else
                            g_cfg.upstream_proto[idx] = PROTO_UDP;
                    } else {
                        g_cfg.upstream_port[idx] = atoi(col + 1);
                        g_cfg.upstream_proto[idx] = PROTO_UDP;
                    }
                } else
                    safe_strcpy(g_cfg.upstream_host[idx], argv[i],
                                sizeof(g_cfg.upstream_host[idx]));
                g_cfg.upstream_count++;
            }
        } else if (!strcmp(argv[i], "--search") && i + 1 < argc) {
            if (g_cfg.search_domain_count < MAX_SEARCH_DOMAINS) {
                safe_strcpy(g_cfg.search_domains[g_cfg.search_domain_count], argv[++i],
                            sizeof(g_cfg.search_domains[g_cfg.search_domain_count]));
                g_cfg.search_domain_count++;
            } else
                i++;
        } else if (!strcmp(argv[i], "--trust-anchor") && i + 1 < argc) {
            dnssec_add_trust_anchor(argv[++i]);
        } else if (!strcmp(argv[i], "--doh-path") && i + 1 < argc)
            safe_strcpy(g_cfg.doh_path, argv[++i], sizeof(g_cfg.doh_path));
        else if (!strcmp(argv[i], "--doh-port") && i + 1 < argc)
            g_cfg.doh_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-tcp-proxy"))
            g_cfg.listen_tcp = 0;
        else if (!strcmp(argv[i], "--server") && i + 1 < argc) {
            /* dnsmasq-compatible: --server /suffix/host:port[:proto] */
            if (!parse_server_arg(argv[++i]))
                fprintf(stderr, "[warn] --server: bad format: %s\n", argv[i]);
        } else if (!strcmp(argv[i], "--route") && i + 1 < argc) {
            /* alternative: --route suffix=host:port[:proto] */
            if (!parse_server_arg(argv[++i]))
                fprintf(stderr, "[warn] --route: bad format: %s\n", argv[i]);
        } else if (!strcmp(argv[i], "--no-dnssec")) { /* future flag */
        } else if (!strcmp(argv[i], "--no-mdns")) {   /* future flag */
        } else if (!strcmp(argv[i], "--conf") && i + 1 < argc) {
            config_load_file(argv[++i]);
        } else if (argv[i][0] != '-' && !query_name[0]) {
            safe_strcpy(query_name, argv[i], sizeof(query_name));
        } else if (argv[i][0] != '-' && !query_type_s[0]) {
            safe_strcpy(query_type_s, argv[i], sizeof(query_type_s));
        }
    }
    cache_init();
    if (g_cfg.proto == PROTO_DOT || g_cfg.proto == PROTO_DOH)
        dot_init();
    dot_server_init(); /* no-op unless DOT_SERVER_ENABLED=1; must run before apply_sandbox() */
    /* One-shot modes that don't need proxy */
    if (mode_stats) {
        print_stats();
        return 0;
    }
    if (mode_flush) {
        int n = cache_flush(flush_name[0] ? flush_name : NULL,
                            flush_name[0] ? str2type(flush_type_s) : 0);
        printf("Flushed %d entr%s\n", n, n == 1 ? "y" : "ies");
        return 0;
    }
    if (mode_dump) {
        dump_cache();
        return 0;
    }
    if (query_name[0]) {
        /* One-shot query */
        uint16_t qtype = str2type(query_type_s);
        if (!qtype) {
            fprintf(stderr, "Unknown type: %s\n", query_type_s);
            return 1;
        }
        resolve_result_t result;
        int rc = dns_resolve(query_name, qtype, &result);
        if (rc < 0) {
            fprintf(stderr, "Query failed\n");
            return 1;
        }
        print_result(query_name, qtype, &result, result.rtt_us);
        print_stats();
        return result.rcode;
    }
    /* Default: proxy mode */
    if (schema_gate() != 0)
        return 1;
    mode_proxy = 1;
    if (mode_proxy) {
        /* Start proxy in main thread (blocking) */
        proxy_run(NULL);
    }
    if (g_dot_ctx)
        SSL_CTX_free(g_dot_ctx);
    if (g_dot_server_ctx)
        SSL_CTX_free(g_dot_server_ctx);
    return 0;
}
#endif /* UNIT_TEST */
