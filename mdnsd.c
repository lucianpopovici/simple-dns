/* mdnsd.c — mDNS / DNS-SD responder (migration Step 3, CLAUDE.md).
 *
 * The link-local responder that used to live inside dns_server.c: answers
 * .local queries (RFC 6762) and _services._dns-sd._udp.local browse requests
 * (RFC 6763), probes and announces on startup. Link-local, low trust —
 * deliberately a separate process from the authoritative daemon.
 *
 * Integration is entirely through Valkey:
 *   reads  mdns:<TYPE>:<name>    mDNS-only records (not served by unicast DNS)
 *   reads  zone:<TYPE>:<name>    shared records (read-only; dnsd owns writes)
 *   reads  config:mdns_*         enabled flag, hostname, interfaces
 * It writes nothing.
 *
 * Interfaces are explicit (CLAUDE.md: never implicitly all-interfaces):
 *   config:mdns_interfaces   comma-separated interface names to join the
 *                            multicast groups on, or "all" to opt in to
 *                            every multicast-capable interface.
 *                            Unset/empty -> mdnsd refuses to start.
 *
 * Other config: config:mdns_enabled ("1" to run), config:mdns_hostname,
 * config:zone_name (hostname default). Env: DNS_VALKEY_HOST/PORT/PASSWORD.
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
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "dns_wire.h"

#define MDNS_PORT 5353
#define MDNS_MCAST4 "224.0.0.251"
#define MDNS_MCAST6 "ff02::fb"
#define MDNS_TTL_HOST 120       /* recommended for host records (RFC 6762 §11.3) */
#define MDNS_TTL_SERVICE 4500   /* recommended for service records */
#define MDNS_TTL_OTHER 4500     /* other records */
#define MDNS_PROBE_WAIT 250000  /* 250 ms in µs between probes */
#define MDNS_PROBE_COUNT 3      /* RFC 6762 §8.1 */
#define MDNS_QU_BIT 0x8000      /* QU (unicast-response) bit in QTYPE */
#define MDNS_CACHE_FLUSH 0x8000 /* Cache-flush bit in RRCLASS */
#define MDNS_MAX_MSG 8192       /* max mDNS message size */
#define DNSSD_SERVICES "_services._dns-sd._udp.local"

#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_PTR 12
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_SRV 33
#define DNS_TYPE_ANY 255
#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255
#define DNS_QR 0x8000
#define DNS_AA 0x0400

#define RESP_BUF 65536
#define MAX_IFACES 16

typedef struct {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((packed)) dns_hdr_t;

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
static char g_mdns_hostname[256] = "";
static char g_ifaces[MAX_IFACES][64];
static int g_iface_count = 0; /* -1 = "all" */
static int g_mdns4_sock = -1;
static int g_mdns6_sock = -1;

static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

/* ── Valkey RESP client (same minimal client as certd.c) ─────────────────── */
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
    char str[4096];
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

/* Look up a shared authoritative record by name across all zones.
 * Records are keyed zone:<zone>:<TYPE>:<name> (multi-zone, Step 7); mDNS shares
 * the unicast zone's records, so we glob the zone segment.  qname is fully
 * qualified, so at most one key matches. */
static int zone_glob_get(const char *tname, const char *qname, char *out, int olen) {
    char pat[600], key[600] = "";
    snprintf(pat, sizeof(pat), "zone:*:%s:%s", tname, qname);
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) >= 0) {
        resp_reply_t r;
        if (resp_cmd(&vk, &r, 2, "KEYS", pat) >= 0 && r.type == 5) {
            for (int i = 0; i < r.count; i++) {
                resp_reply_t kr;
                if (resp_parse(&vk, &kr) < 0)
                    break;
                if (kr.type == 2 && !key[0])
                    safe_strcpy(key, kr.str, sizeof(key));
            }
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (!key[0])
        return 0;
    return vk_get(key, out, olen);
}

/* ── Type name mapping (the record types mDNS serves) ────────────────────── */
static const char *type2str(uint16_t t) {
    switch (t) {
        case DNS_TYPE_A:
            return "A";
        case DNS_TYPE_AAAA:
            return "AAAA";
        case DNS_TYPE_PTR:
            return "PTR";
        case DNS_TYPE_SRV:
            return "SRV";
        case DNS_TYPE_TXT:
            return "TXT";
        case DNS_TYPE_CNAME:
            return "CNAME";
        default:
            return "?";
    }
}
static uint16_t str2type(const char *s) {
    if (!strcasecmp(s, "A"))
        return DNS_TYPE_A;
    if (!strcasecmp(s, "AAAA"))
        return DNS_TYPE_AAAA;
    if (!strcasecmp(s, "PTR"))
        return DNS_TYPE_PTR;
    if (!strcasecmp(s, "SRV"))
        return DNS_TYPE_SRV;
    if (!strcasecmp(s, "TXT"))
        return DNS_TYPE_TXT;
    if (!strcasecmp(s, "CNAME"))
        return DNS_TYPE_CNAME;
    return 0;
}

/* ── Wire-format helpers specific to mDNS ────────────────────────────────── */

/* Append a name in DNS wire format to buf[off].  Returns new offset, -1 on overflow. */
static int mdns_put_name(uint8_t *buf, int off, int blen, const char *name) {
    char tmp[256];
    safe_strcpy(tmp, name, sizeof(tmp));
    /* strip trailing dot */
    int tl = (int) strlen(tmp);
    if (tl > 0 && tmp[tl - 1] == '.')
        tmp[--tl] = 0;
    char *sp = NULL;
    char *lbl = strtok_r(tmp, ".", &sp);
    while (lbl) {
        int ll = (int) strlen(lbl);
        if (off + ll + 1 >= blen)
            return -1;
        buf[off++] = (uint8_t) ll;
        memcpy(buf + off, lbl, ll);
        off += ll;
        lbl = strtok_r(NULL, ".", &sp);
    }
    if (off >= blen)
        return -1;
    buf[off++] = 0;
    return off;
}

/* Append a complete RR (no compression).  Returns new offset, -1 on overflow. */
static int mdns_put_rr(uint8_t *buf, int off, int blen, const char *name, uint16_t rtype,
                       uint16_t rclass_flags, /* MDNS_CACHE_FLUSH|DNS_CLASS_IN */
                       uint32_t ttl, const uint8_t *rdata, uint16_t rdlen) {
    off = mdns_put_name(buf, off, blen, name);
    if (off < 0 || off + 10 + (int) rdlen > blen)
        return -1;
    buf[off++] = rtype >> 8;
    buf[off++] = rtype & 0xFF;
    buf[off++] = rclass_flags >> 8;
    buf[off++] = rclass_flags & 0xFF;
    buf[off++] = ttl >> 24;
    buf[off++] = (ttl >> 16) & 0xFF;
    buf[off++] = (ttl >> 8) & 0xFF;
    buf[off++] = ttl & 0xFF;
    buf[off++] = rdlen >> 8;
    buf[off++] = rdlen & 0xFF;
    if (rdlen)
        memcpy(buf + off, rdata, rdlen);
    return off + (int) rdlen;
}

/* Send a raw mDNS message to the multicast group on both IPv4 and IPv6 */
static void mdns_send(const uint8_t *msg, int len) {
    if (g_mdns4_sock >= 0) {
        struct sockaddr_in dst4 = {0};
        dst4.sin_family = AF_INET;
        dst4.sin_port = htons(MDNS_PORT);
        inet_pton(AF_INET, MDNS_MCAST4, &dst4.sin_addr);
        sendto(g_mdns4_sock, msg, len, 0, (struct sockaddr *) &dst4, sizeof(dst4));
    }
    if (g_mdns6_sock >= 0) {
        struct sockaddr_in6 dst6 = {0};
        dst6.sin6_family = AF_INET6;
        dst6.sin6_port = htons(MDNS_PORT);
        inet_pton(AF_INET6, MDNS_MCAST6, &dst6.sin6_addr);
        sendto(g_mdns6_sock, msg, len, 0, (struct sockaddr *) &dst6, sizeof(dst6));
    }
}

/* ── DNS-SD service enumeration ─────────────────────────────────────────── */

/*
 * mdns_append_sd_browse — append PTR records for _services._dns-sd._udp.local.
 * Scans Valkey for mdns:PTR:_*._*._*.local keys and returns the unique
 * service types as PTR records.
 */
static int mdns_append_sd_browse(uint8_t *buf, int off, int blen, int *ancount) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return off;
    }
    resp_reply_t r;
    resp_cmd(&vk, &r, 2, "KEYS", "mdns:PTR:_*");
    if (r.type == 5) {
        for (int i = 0; i < r.count; i++) {
            resp_reply_t kr;
            resp_parse(&vk, &kr);
            if (kr.type != 2)
                continue;
            /* key = "mdns:PTR:<service-instance-or-type>" */
            const char *svcname = kr.str + 9; /* skip "mdns:PTR:" */
            /* only include pure service type PTRs like "_http._tcp.local" */
            if (svcname[0] != '_')
                continue;
            /* rdata = service type name in wire format */
            uint8_t rd[256];
            int roff = 0;
            roff = name_to_wire(svcname, rd, sizeof(rd));
            if (roff < 0)
                continue;
            off = mdns_put_rr(buf, off, blen, DNSSD_SERVICES, DNS_TYPE_PTR, DNS_CLASS_IN,
                              MDNS_TTL_SERVICE, rd, (uint16_t) roff);
            if (off < 0) {
                off = 0;
                break;
            }
            (*ancount)++;
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return off;
}

/* ── Core query answerer ─────────────────────────────────────────────────── */

/*
 * mdns_lookup_records — find records for qname/qtype in both
 * mdns:TYPE:name and zone:TYPE:name Valkey keys.
 * Appends matching RRs to buf and increments *ancount.
 * Returns new offset, or original off on failure.
 */
static int mdns_lookup_records(uint8_t *buf, int off, int blen, const char *qname, uint16_t qtype,
                               int *ancount, int legacy) {
    /* RFC 6762 §6.7: legacy unicast responses must not set the cache-flush
     * bit (the querier reads it as class 0x8001) and should cap TTLs at 10s. */
    const uint16_t cls = legacy ? DNS_CLASS_IN : (DNS_CLASS_IN | MDNS_CACHE_FLUSH);
    uint16_t types_to_check[16];
    int ntypes = 0;
    if (qtype == DNS_TYPE_ANY) {
        uint16_t all[] = {
            DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_PTR, DNS_TYPE_SRV, DNS_TYPE_TXT, DNS_TYPE_CNAME, 0};
        for (int i = 0; all[i]; i++)
            types_to_check[ntypes++] = all[i];
    } else {
        types_to_check[ntypes++] = qtype;
    }
    for (int ti = 0; ti < ntypes; ti++) {
        uint16_t qt = types_to_check[ti];
        const char *tname = type2str(qt);
        /* Try mdns:TYPE:name first, then the shared zone:<zone>:TYPE:name */
        for (int pi = 0; pi < 2; pi++) {
            char val[512];
            if (pi == 0) {
                char vkey[600];
                snprintf(vkey, sizeof(vkey), "mdns:%s:%s", tname, qname);
                if (!vk_get(vkey, val, sizeof(val)))
                    continue;
            } else {
                if (!zone_glob_get(tname, qname, val, sizeof(val)))
                    continue;
            }
            /* Parse ttl|value */
            uint32_t ttl = MDNS_TTL_OTHER;
            char *pipe = strchr(val, '|');
            char *vptr = val;
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                vptr = pipe + 1;
            }
            if (legacy && ttl > 10)
                ttl = 10;
            uint8_t rd[512];
            uint16_t rdlen = 0;
            switch (qt) {
                case DNS_TYPE_A: {
                    struct in_addr a4;
                    char *sp = NULL;
                    char *ip = strtok_r(vptr, "|", &sp);
                    while (ip) {
                        if (inet_pton(AF_INET, ip, &a4) == 1) {
                            memcpy(rd, &a4, 4);
                            rdlen = 4;
                            off =
                                mdns_put_rr(buf, off, blen, qname, DNS_TYPE_A, cls, ttl, rd, rdlen);
                            if (off < 0)
                                goto done;
                            (*ancount)++;
                        }
                        ip = strtok_r(NULL, "|", &sp);
                    }
                    rdlen = 0; /* already appended per-IP */
                    break;
                }
                case DNS_TYPE_AAAA: {
                    struct in6_addr a6;
                    char *sp = NULL;
                    char *ip = strtok_r(vptr, "|", &sp);
                    while (ip) {
                        if (inet_pton(AF_INET6, ip, &a6) == 1) {
                            memcpy(rd, &a6, 16);
                            rdlen = 16;
                            off = mdns_put_rr(buf, off, blen, qname, DNS_TYPE_AAAA, cls, ttl, rd,
                                              rdlen);
                            if (off < 0)
                                goto done;
                            (*ancount)++;
                        }
                        ip = strtok_r(NULL, "|", &sp);
                    }
                    rdlen = 0;
                    break;
                }
                case DNS_TYPE_PTR: {
                    /* PTR: rdata = target name in wire format */
                    int n = name_to_wire(vptr, rd, sizeof(rd));
                    if (n < 0)
                        continue;
                    rdlen = (uint16_t) n;
                    break;
                }
                case DNS_TYPE_SRV: {
                    /* ttl|priority|weight|port|target */
                    uint16_t prio = 0, weight = 0, port = 0;
                    char target[256] = "";
                    char *sp = NULL;
                    char *tok = strtok_r(vptr, "|", &sp);
                    if (tok)
                        prio = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp);
                    if (tok)
                        weight = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp);
                    if (tok)
                        port = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp);
                    if (tok)
                        safe_strcpy(target, tok, sizeof(target));
                    rd[0] = prio >> 8;
                    rd[1] = prio & 0xFF;
                    rd[2] = weight >> 8;
                    rd[3] = weight & 0xFF;
                    rd[4] = port >> 8;
                    rd[5] = port & 0xFF;
                    int n = name_to_wire(target, rd + 6, sizeof(rd) - 6);
                    if (n < 0)
                        continue;
                    rdlen = (uint16_t) (6 + n);
                    break;
                }
                case DNS_TYPE_TXT: {
                    int tl = txt_encode(vptr, rd, (int) sizeof(rd));
                    if (tl < 0)
                        continue;
                    rdlen = (uint16_t) tl;
                    break;
                }
                case DNS_TYPE_CNAME: {
                    int n = name_to_wire(vptr, rd, sizeof(rd));
                    if (n < 0)
                        continue;
                    rdlen = (uint16_t) n;
                    break;
                }
                default:
                    continue;
            }
            if (rdlen > 0) {
                off = mdns_put_rr(buf, off, blen, qname, qt, cls, ttl, rd, rdlen);
                if (off < 0)
                    goto done;
                (*ancount)++;
            }
        }
    }
done:
    if (off < 0) {
        dns_log(LOG_DEBUG, "[mDNS] Response truncated for %s\n", qname);
        off = 0;
    }
    return off;
}

/*
 * mdns_build_response — build a mDNS response packet for an incoming query.
 * Only answers questions about .local names we are authoritative for.
 * Returns response length (0 = no answer, nothing to send).
 */
static int mdns_build_response(const uint8_t *query, int qlen, uint8_t *resp, int resp_len,
                               int is_legacy_unicast) {
    if (qlen < 12)
        return 0;
    const dns_hdr_t *qh = (const dns_hdr_t *) query;
    /* Ignore non-query or responses */
    if (ntohs(qh->flags) & DNS_QR)
        return 0;
    int qdcount = ntohs(qh->qdcount);
    if (qdcount == 0 || qdcount > 10)
        return 0;

    memset(resp, 0, 12);
    dns_hdr_t *rh = (dns_hdr_t *) resp;
    /* RFC 6762 §18: QR=1, AA=1, opcode=0 */
    rh->flags = htons(DNS_QR | DNS_AA);
    rh->id = is_legacy_unicast ? qh->id : 0; /* mDNS responses have id=0 */

    /* Pass 1 — parse all questions. (The pre-split responder reused one
     * offset to parse the query AND write answers, leaving garbage between
     * the header and the first answer; every query response was malformed.)
     * For legacy unicast the question section is echoed verbatim
     * (RFC 6762 §6.7); multicast responses carry no questions (§6). */
    char qnames[10][256];
    uint16_t qtypes[10], qclasses[10];
    int nq = 0, qoff = 12;
    for (int qi = 0; qi < qdcount; qi++) {
        int after = name_from_wire(query, qlen, qoff, qnames[nq], sizeof(qnames[nq]));
        if (after < 0 || after + 3 >= qlen)
            break;
        qtypes[nq] = get16(query, after);
        qclasses[nq] = get16(query, after + 2) & 0x7FFF; /* mask QU bit */
        qoff = after + 4;
        nq++;
    }
    if (nq == 0)
        return 0;

    int off = 12;
    if (is_legacy_unicast) {
        /* Copy the question bytes verbatim; offsets are preserved (both
         * sections start at 12), so any compression pointers stay valid. */
        if (qoff > resp_len)
            return 0;
        memcpy(resp + 12, query + 12, qoff - 12);
        off = qoff;
        rh->qdcount = htons((uint16_t) nq);
    }

    /* Pass 2 — append answers */
    int ancount = 0;
    for (int qi = 0; qi < nq; qi++) {
        const char *qname = qnames[qi];
        /* Only answer IN class queries */
        if (qclasses[qi] != DNS_CLASS_IN && qclasses[qi] != DNS_CLASS_ANY)
            continue;
        /* Only answer .local questions */
        int nl = (int) strlen(qname);
        int is_local = (nl >= 6 && strcasecmp(qname + nl - 6, ".local") == 0) ||
                       (nl == 5 && strcasecmp(qname, "local") == 0);
        if (!is_local)
            continue;

        /* Special: _services._dns-sd._udp.local (RFC 6763 §9) */
        if (strcasecmp(qname, DNSSD_SERVICES) == 0) {
            int new_off = mdns_append_sd_browse(resp, off, resp_len, &ancount);
            if (new_off > 0)
                off = new_off;
            continue;
        }

        /* Regular record lookup */
        int new_off = mdns_lookup_records(resp, off, resp_len, qname, qtypes[qi], &ancount,
                                          is_legacy_unicast);
        if (new_off > 0)
            off = new_off;
    }

    if (ancount == 0)
        return 0;
    rh->ancount = htons((uint16_t) ancount);
    return off;
}

/* ── Probe & Announce ───────────────────────────────────────────────────── */

/*
 * mdns_probe — RFC 6762 §8.1
 * Send 3 probe queries for our hostname before claiming it.
 */
static void mdns_probe(void) {
    if (!g_mdns_hostname[0])
        return;
    dns_log(LOG_NOTICE, "[mDNS] Probing for %s\n", g_mdns_hostname);
    for (int i = 0; i < MDNS_PROBE_COUNT; i++) {
        uint8_t pkt[256];
        int off = 12;
        memset(pkt, 0, 12);
        dns_hdr_t *h = (dns_hdr_t *) pkt;
        h->id = 0;
        h->qdcount = htons(1);
        /* question: <hostname> ANY IN */
        off = mdns_put_name(pkt, off, sizeof(pkt), g_mdns_hostname);
        if (off > 0) {
            put16(pkt, off, DNS_TYPE_ANY);
            off += 2;
            put16(pkt, off, DNS_CLASS_IN);
            off += 2;
            mdns_send(pkt, off);
        }
        usleep(MDNS_PROBE_WAIT);
    }
    dns_log(LOG_NOTICE, "[mDNS] Probe complete — claiming %s\n", g_mdns_hostname);
}

/*
 * mdns_announce — RFC 6762 §8.3
 * Send unsolicited (gratuitous) mDNS responses for all our records.
 */
static void mdns_announce(void) {
    uint8_t pkt[MDNS_MAX_MSG];
    int off = 12;
    int ancount = 0;
    memset(pkt, 0, 12);
    dns_hdr_t *h = (dns_hdr_t *) pkt;
    h->id = 0;
    h->flags = htons(DNS_QR | DNS_AA);

    /* Announce all mdns:* and shared zone:*:A:* records.  Keys are
     * mdns:<TYPE>:<name> (3 parts) and zone:<zone>:<TYPE>:<name> (4 parts). */
    const char *patterns[2] = {"mdns:*", "zone:*:A:*"};
    for (int pi = 0; pi < 2; pi++) {
        pthread_mutex_lock(&g_vk_mutex);
        if (valkey_ensure(&vk) < 0) {
            pthread_mutex_unlock(&g_vk_mutex);
            continue;
        }
        resp_reply_t r;
        resp_cmd(&vk, &r, 2, "KEYS", patterns[pi]);
        if (r.type == 5) {
            for (int i = 0; i < r.count; i++) {
                resp_reply_t kr;
                resp_parse(&vk, &kr);
                if (kr.type != 2)
                    continue;
                /* parse key: mdns:TYPE:name OR zone:<zone>:TYPE:name */
                char kbuf[512];
                safe_strcpy(kbuf, kr.str, sizeof(kbuf));
                char *p1 = strchr(kbuf, ':');
                if (!p1)
                    continue;
                *p1++ = 0;
                int is_zone = (strcmp(kbuf, "zone") == 0);
                if (is_zone) {
                    /* skip the <zone> segment */
                    char *zsep = strchr(p1, ':');
                    if (!zsep)
                        continue;
                    p1 = zsep + 1;
                }
                char *p2 = strchr(p1, ':');
                if (!p2)
                    continue;
                *p2++ = 0;
                char *tname = p1, *rname = p2;
                uint16_t rt = str2type(tname);
                if (!rt)
                    continue;
                resp_reply_t vr;
                resp_cmd(&vk, &vr, 2, "GET", kr.str);
                if (vr.type != 2)
                    continue;
                char *vptr = vr.str;
                uint32_t ttl = MDNS_TTL_OTHER;
                char *pipe = strchr(vptr, '|');
                if (pipe) {
                    ttl = (uint32_t) atoi(vptr);
                    vptr = pipe + 1;
                }
                uint8_t rd[256];
                uint16_t rdlen = 0;
                switch (rt) {
                    case DNS_TYPE_A: {
                        struct in_addr a4;
                        if (inet_pton(AF_INET, vptr, &a4) == 1) {
                            memcpy(rd, &a4, 4);
                            rdlen = 4;
                        }
                        break;
                    }
                    case DNS_TYPE_AAAA: {
                        struct in6_addr a6;
                        if (inet_pton(AF_INET6, vptr, &a6) == 1) {
                            memcpy(rd, &a6, 16);
                            rdlen = 16;
                        }
                        break;
                    }
                    case DNS_TYPE_PTR: {
                        int n = name_to_wire(vptr, rd, sizeof(rd));
                        if (n > 0)
                            rdlen = (uint16_t) n;
                        break;
                    }
                    case DNS_TYPE_SRV: {
                        uint16_t pr = 0, wt = 0, po = 0;
                        char tg[256] = "";
                        char *sp = NULL;
                        char *tok = strtok_r(vptr, "|", &sp);
                        if (tok)
                            pr = (uint16_t) atoi(tok);
                        tok = strtok_r(NULL, "|", &sp);
                        if (tok)
                            wt = (uint16_t) atoi(tok);
                        tok = strtok_r(NULL, "|", &sp);
                        if (tok)
                            po = (uint16_t) atoi(tok);
                        tok = strtok_r(NULL, "|", &sp);
                        if (tok)
                            safe_strcpy(tg, tok, sizeof(tg));
                        rd[0] = pr >> 8;
                        rd[1] = pr & 0xFF;
                        rd[2] = wt >> 8;
                        rd[3] = wt & 0xFF;
                        rd[4] = po >> 8;
                        rd[5] = po & 0xFF;
                        int n = name_to_wire(tg, rd + 6, sizeof(rd) - 6);
                        if (n > 0)
                            rdlen = (uint16_t) (6 + n);
                        break;
                    }
                    case DNS_TYPE_TXT: {
                        int tl = txt_encode(vptr, rd, (int) sizeof(rd));
                        if (tl < 0)
                            break;
                        rdlen = (uint16_t) tl;
                        break;
                    }
                    default:
                        break;
                }
                if (rdlen) {
                    int no = mdns_put_rr(pkt, off, sizeof(pkt), rname, rt,
                                         DNS_CLASS_IN | MDNS_CACHE_FLUSH, ttl, rd, rdlen);
                    if (no > 0) {
                        off = no;
                        ancount++;
                    }
                }
            }
        }
        pthread_mutex_unlock(&g_vk_mutex);
    }
    if (ancount > 0) {
        h->ancount = htons((uint16_t) ancount);
        mdns_send(pkt, off);
        dns_log(LOG_NOTICE, "[mDNS] Announced %d records for %s\n", ancount, g_mdns_hostname);
    }
}

/* ── Socket setup ───────────────────────────────────────────────────────── */

/* Is this interface in the configured allowlist? */
static int iface_allowed(const char *name) {
    if (g_iface_count < 0)
        return 1; /* "all" explicitly configured */
    for (int i = 0; i < g_iface_count; i++)
        if (strcmp(g_ifaces[i], name) == 0)
            return 1;
    return 0;
}

/*
 * mdns_open_socket — create a UDP socket for mDNS on the given AF and join
 * the multicast group on the explicitly configured interfaces only
 * (config:mdns_interfaces; "all" opts in to every multicast-capable one).
 */
static int mdns_open_socket(int af) {
    int fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        dns_log(LOG_ERR, "[mDNS] socket(%d) failed: %s\n", af, strerror(errno));
        return -1;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    int joined = 0;
    if (af == AF_INET) {
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(MDNS_PORT);
        sa.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            dns_log(LOG_ERR, "[mDNS] bind IPv4 failed: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        /* Set multicast TTL=255 (RFC 6762 §11) */
        uint8_t ttl = 255;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        /* Loopback for local testing */
        uint8_t loop = 1;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
        struct ifaddrs *ifa = NULL;
        getifaddrs(&ifa);
        for (struct ifaddrs *i = ifa; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
                continue;
            if (!(i->ifa_flags & IFF_MULTICAST))
                continue;
            if (!iface_allowed(i->ifa_name))
                continue;
            struct ip_mreq mr = {0};
            inet_pton(AF_INET, MDNS_MCAST4, &mr.imr_multiaddr);
            mr.imr_interface = ((struct sockaddr_in *) i->ifa_addr)->sin_addr;
            if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) == 0) {
                dns_log(LOG_NOTICE, "[mDNS] Joined %s on %s\n", MDNS_MCAST4, i->ifa_name);
                joined++;
            }
        }
        if (ifa)
            freeifaddrs(ifa);
    } else {
        struct sockaddr_in6 sa6 = {0};
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(MDNS_PORT);
        if (bind(fd, (struct sockaddr *) &sa6, sizeof(sa6)) < 0) {
            dns_log(LOG_ERR, "[mDNS] bind IPv6 failed: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        int ttl = 255;
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
        int loop = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));
        struct ifaddrs *ifa = NULL;
        getifaddrs(&ifa);
        for (struct ifaddrs *i = ifa; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET6)
                continue;
            if (!(i->ifa_flags & IFF_MULTICAST))
                continue;
            if (!iface_allowed(i->ifa_name))
                continue;
            struct ipv6_mreq mr6 = {0};
            inet_pton(AF_INET6, MDNS_MCAST6, &mr6.ipv6mr_multiaddr);
            mr6.ipv6mr_interface = if_nametoindex(i->ifa_name);
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mr6, sizeof(mr6)) == 0) {
                dns_log(LOG_NOTICE, "[mDNS] Joined %s on %s\n", MDNS_MCAST6, i->ifa_name);
                joined++;
            }
        }
        if (ifa)
            freeifaddrs(ifa);
    }
    if (!joined) {
        dns_log(LOG_WARNING, "[mDNS] No %s multicast group joined (interface filter)\n",
                af == AF_INET ? "IPv4" : "IPv6");
        close(fd);
        return -1;
    }
    return fd;
}

/* ── Live reload via Valkey keyspace notifications (migration Step 6) ───────
 *
 * mdnsd serves mdns: and zone: records live per query already, so the value here
 * is re-announcing (RFC 6762 §8.3 gratuitous responses) when a record changes
 * so the link learns it without waiting for the next query. A dedicated
 * subscriber connection watches mdns:* and config:mdns_*; record/hostname
 * edits trigger a re-announce, while interface/enable changes need a restart
 * (the multicast sockets are bound at startup). Reconnects use capped backoff. */
#define KEYSPACE_DB 0
static void mdns_keyspace_apply(const char *key) {
    if (strncmp(key, "mdns:", 5) == 0) {
        mdns_announce();
    } else if (strcmp(key, "config:mdns_hostname") == 0) {
        char v[256] = "";
        if (vk_get("config:mdns_hostname", v, sizeof(v)) && v[0])
            safe_strcpy(g_mdns_hostname, v, sizeof(g_mdns_hostname));
        mdns_announce();
    } else if (strcmp(key, "config:mdns_interfaces") == 0 ||
               strcmp(key, "config:mdns_enabled") == 0) {
        dns_log(LOG_WARNING,
                "[Reload] %s changed — restart mdnsd to apply "
                "(multicast sockets are bound at startup)\n",
                key);
    } else if (strncmp(key, "config:mdns_", 12) == 0) {
        mdns_announce();
    }
}

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
                                 "announce-on-change disabled\n");
        static const char *prefixes[] = {"mdns:*", "config:mdns_*", NULL};
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
            char kind[16] = "", channel[512] = "";
            int rderr = 0;
            for (int i = 0; i < hdr.count; i++) {
                resp_reply_t el;
                if (resp_parse(&sub, &el) < 0) {
                    rderr = 1;
                    break;
                }
                if (i == 0)
                    safe_strcpy(kind, el.str, sizeof(kind));
                else if (i == 2)
                    safe_strcpy(channel, el.str, sizeof(channel));
            }
            if (rderr)
                break;
            if (strcmp(kind, "pmessage") != 0)
                continue;
            const char *sep = strstr(channel, "__:");
            if (sep)
                mdns_keyspace_apply(sep + 3);
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

/* ── Receive loop ───────────────────────────────────────────────────────── */

static void mdns_recv_loop(int fd4, int fd6) {
    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        if (fd4 >= 0)
            FD_SET(fd4, &fds);
        if (fd6 >= 0)
            FD_SET(fd6, &fds);
        int maxfd = (fd4 > fd6 ? fd4 : fd6);
        struct timeval tv = {.tv_sec = 5};
        int r = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (r <= 0)
            continue;

        int socks[2] = {fd4, fd6};
        int afs[2] = {AF_INET, AF_INET6};
        for (int si = 0; si < 2; si++) {
            int fd = socks[si];
            int af = afs[si];
            if (fd < 0 || !FD_ISSET(fd, &fds))
                continue;

            uint8_t pkt[MDNS_MAX_MSG];
            union {
                struct sockaddr_in v4;
                struct sockaddr_in6 v6;
            } src;
            socklen_t srclen = sizeof(src);
            ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0, (struct sockaddr *) &src, &srclen);
            if (n < 12)
                continue;

            /* Determine if this is a legacy unicast query (not from port 5353) */
            int is_legacy = 0;
            if (af == AF_INET)
                is_legacy = (ntohs(src.v4.sin_port) != MDNS_PORT);
            else
                is_legacy = (ntohs(src.v6.sin6_port) != MDNS_PORT);

            uint8_t resp[MDNS_MAX_MSG];
            int rlen = mdns_build_response(pkt, (int) n, resp, sizeof(resp), is_legacy);
            if (rlen <= 0)
                continue;

            char src_str[64] = "?";
            if (af == AF_INET)
                inet_ntop(AF_INET, &src.v4.sin_addr, src_str, sizeof(src_str));
            else
                inet_ntop(AF_INET6, &src.v6.sin6_addr, src_str, sizeof(src_str));
            dns_log(LOG_DEBUG, "[mDNS] Query from %s → %d-byte response\n", src_str, rlen);

            if (is_legacy) {
                /* Legacy unicast: respond directly to querier */
                sendto(fd, resp, rlen, 0, (struct sockaddr *) &src, srclen);
            } else {
                /* Standard mDNS: multicast the response (RFC 6762 §6) */
                /* Small random delay 20-120ms to reduce collisions */
                usleep(20000 + (rand() % 100000));
                mdns_send(resp, rlen);
            }
        }
    }
}

/* ── Config + main ──────────────────────────────────────────────────────── */

static int load_config(void) {
    safe_strcpy(g_valkey_host, cfgenv("DNS_VALKEY_HOST", "127.0.0.1"), sizeof(g_valkey_host));
    g_valkey_port = atoi(cfgenv("DNS_VALKEY_PORT", "6379"));
    safe_strcpy(g_valkey_pass, cfgenv("DNS_VALKEY_PASSWORD", ""), sizeof(g_valkey_pass));
    char val[512];
    if (!vk_get("config:mdns_enabled", val, sizeof(val)) || atoi(val) != 1) {
        dns_log(LOG_NOTICE, "[mDNS] config:mdns_enabled is not 1 — nothing to do\n");
        return -1;
    }
    if (vk_get("config:mdns_hostname", val, sizeof(val)) && val[0])
        safe_strcpy(g_mdns_hostname, val, sizeof(g_mdns_hostname));
    /* Default mdns_hostname to <zone_name>.local if not set */
    if (!g_mdns_hostname[0] && vk_get("config:zone_name", val, sizeof(val)) && val[0]) {
        int zl = (int) strlen(val);
        if (zl > 0 && val[zl - 1] == '.')
            val[zl - 1] = 0;
        safe_strcpy(g_mdns_hostname, val, sizeof(g_mdns_hostname));
        if (!strstr(g_mdns_hostname, ".local"))
            strncat(g_mdns_hostname, ".local",
                    sizeof(g_mdns_hostname) - strlen(g_mdns_hostname) - 1);
    }
    /* Explicit interface allowlist — never implicitly all interfaces */
    if (!vk_get("config:mdns_interfaces", val, sizeof(val)) || !val[0]) {
        dns_log(LOG_ERR, "[mDNS] config:mdns_interfaces is not set.\n");
        dns_log(LOG_ERR, "[mDNS] Set it to a comma-separated interface list "
                         "(e.g. \"eth0\" or \"eth0,wlan0\"), or \"all\" to opt "
                         "in to every multicast-capable interface.\n");
        return -1;
    }
    if (!strcasecmp(val, "all")) {
        g_iface_count = -1;
    } else {
        char *sp = NULL;
        for (char *tok = strtok_r(val, ", ", &sp); tok && g_iface_count < MAX_IFACES;
             tok = strtok_r(NULL, ", ", &sp))
            safe_strcpy(g_ifaces[g_iface_count++], tok, sizeof(g_ifaces[0]));
        if (g_iface_count == 0) {
            dns_log(LOG_ERR, "[mDNS] config:mdns_interfaces parsed to nothing\n");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    srand((unsigned) time(NULL) ^ (unsigned) getpid());
    if (load_config() < 0)
        return 1;
    g_mdns4_sock = mdns_open_socket(AF_INET);
    g_mdns6_sock = mdns_open_socket(AF_INET6);
    if (g_mdns4_sock < 0 && g_mdns6_sock < 0) {
        dns_log(LOG_ERR, "[mDNS] No multicast sockets — exiting\n");
        return 1;
    }
    dns_log(LOG_NOTICE, "[mDNS] Responder up: %s (IPv4 %s, IPv6 %s)\n", g_mdns_hostname,
            g_mdns4_sock >= 0 ? "up" : "down", g_mdns6_sock >= 0 ? "up" : "down");
    mdns_probe();
    mdns_announce();
    /* Live reload: re-announce when mdns: or config:mdns_ records change
     * (migration Step 6). */
    {
        pthread_t kt;
        if (pthread_create(&kt, NULL, keyspace_watch_thread, NULL) == 0)
            pthread_detach(kt);
        else
            dns_log(LOG_ERR, "[Reload] Failed to start keyspace watcher\n");
    }
    mdns_recv_loop(g_mdns4_sock, g_mdns6_sock);
    return 0;
}
