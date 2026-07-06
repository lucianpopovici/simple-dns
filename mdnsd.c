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
 *
 * RFC 8766 Discovery Proxy (opt-in): bridges unicast DNS-SD queries under a
 * configured subdomain to link-local mDNS, so services that only advertise
 * on-link become reachable from other subnets. config:dp_enabled +
 * config:dp_subdomains (comma-separated, e.g. "lab.example.com" — queries
 * for <name>.lab.example.com map to <name>.local on the mDNS side) —
 * unconfigured subdomains are REFUSED, never forwarded. config:dp_port
 * (default 8530), config:dp_ttl_cap (default 30s — RFC 8766 §5.3, the
 * source mDNS TTL is never reused unchanged). Never proxies a link-scoped
 * (fe80::/10) AAAA to the unicast side.
 *
 * RFC 8490 DSO + RFC 8765 DNS Push Notifications (opt-in, requires the
 * Discovery Proxy above): config:dso_enabled + config:dso_port (default
 * 8531) run a DoT (TLS-only, cert:current-sourced) listener where clients
 * SUBSCRIBE to a (name,type) under a proxied subdomain and get PUSHed the
 * current answer set, then a PUSH whenever it changes (detected by polling
 * every config:dso_poll_interval_secs, default 5). config:dso_max_subscriptions
 * caps subscriptions per session; config:dso_inactivity_ms /
 * config:dso_keepalive_ms tune the RFC 8490 session timers (defaults 15000
 * each, matching the RFC's own defaults).
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

#define MAX_IFACES 16

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

/* RFC 8766 Discovery Proxy (Add 1) — off by default; requires an explicit
 * proxied subdomain list, same "never implicitly on" posture as the
 * interface allowlist above. */
#define DP_MAX_SUBDOMAINS 8
static int g_dp_enabled = 0;
static char g_dp_subdomains[DP_MAX_SUBDOMAINS][256];
static int g_dp_subdomain_count = 0;
static int g_dp_port = 8530;
static uint32_t g_dp_ttl_cap = 30;

/* RFC 8490 DSO + RFC 8765 DNS Push Notifications (Add 2) — the live-update
 * companion to the Discovery Proxy above: a client SUBSCRIBEs to a
 * (name,type) under a proxied subdomain over a long-lived DoT session and
 * gets PUSHed the current answer set, then a PUSH whenever it changes.
 * Off by default; RFC 8765 mandates TLS (the Strict Privacy DoT profile,
 * RFC 8310 — no plaintext option), so the listener only comes up once
 * cert:current has a usable certificate, same hot-reload contract as
 * dnsd/apid. SUBSCRIBE only accepts names under a configured Discovery
 * Proxy subdomain — Push rides on Add 1's existing trust boundary, it is
 * not a general update channel. */
#define DSO_MAX_SESSIONS 32
#define DSO_MAX_SUBS_PER_SESSION 8
#define DSO_MAX_MSG 16384 /* RFC 8765 §5.4: max PUSH message is 16382+2 bytes */
/* RFC 8490 §7 generic TLV types */
#define DSO_TLV_KEEPALIVE 1
#define DSO_TLV_RETRY_DELAY 2
#define DSO_TLV_ENCRYPTION_PADDING 3
/* RFC 8765 §5 Push TLV types */
#define DSO_TLV_SUBSCRIBE 0x40
#define DSO_TLV_PUSH 0x41
#define DSO_TLV_UNSUBSCRIBE 0x42
#define DSO_TLV_RECONFIRM 0x43
static int g_dso_enabled = 0;
static int g_dso_port = 8531;
static uint32_t g_dso_inactivity_ms = 15000; /* RFC 8490 §6.1 default */
static uint32_t g_dso_keepalive_ms = 15000;  /* RFC 8490 §6.2 default */
static int g_dso_max_subs = DSO_MAX_SUBS_PER_SESSION;
static int g_dso_poll_secs = 5;

static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

/* ── Valkey — thin wrappers over the shared libdnswire RESP client (see
 * dns_wire.h: vkc_connect_to/vkc_ensure_to/vkc_cmd/vkc_parse). mdnsd used to
 * carry its own copy (same shape as certd's) whose reply buffer was sized
 * 4096 bytes instead of the 65536 every other copy used — large enough to
 * silently truncate a multi-intermediate-CA cert:current chain read through
 * vk_get. Repointing at the shared client (which eppd already used) fixes
 * that as a side effect of using one implementation instead of a diverged
 * copy. ──────────────────────────────────────────────────────────────────── */
static vkc_conn_t vk = {.fd = -1};
static pthread_mutex_t g_vk_mutex = PTHREAD_MUTEX_INITIALIZER;

static int vk_get(const char *key, char *out, int olen) {
    pthread_mutex_lock(&g_vk_mutex);
    if (vkc_ensure_to(&vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    vkc_reply_t r;
    if (vkc_cmd(&vk, &r, 2, "GET", key) < 0) {
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
    if (vkc_ensure_to(&vk, g_valkey_host, g_valkey_port, g_valkey_pass) >= 0) {
        vkc_reply_t r;
        if (vkc_cmd(&vk, &r, 2, "KEYS", pat) >= 0 && r.type == 5) {
            for (int i = 0; i < r.count; i++) {
                vkc_reply_t kr;
                if (vkc_parse(&vk, &kr) < 0)
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
    if (vkc_ensure_to(&vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return off;
    }
    vkc_reply_t r;
    vkc_cmd(&vk, &r, 2, "KEYS", "mdns:PTR:_*");
    if (r.type == 5) {
        for (int i = 0; i < r.count; i++) {
            vkc_reply_t kr;
            vkc_parse(&vk, &kr);
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
        if (vkc_ensure_to(&vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
            pthread_mutex_unlock(&g_vk_mutex);
            continue;
        }
        vkc_reply_t r;
        vkc_cmd(&vk, &r, 2, "KEYS", patterns[pi]);
        if (r.type == 5) {
            for (int i = 0; i < r.count; i++) {
                vkc_reply_t kr;
                vkc_parse(&vk, &kr);
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
                vkc_reply_t vr;
                vkc_cmd(&vk, &vr, 2, "GET", kr.str);
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

/* ==========================================================================
 * RFC 8766 Discovery Proxy — bridges unicast DNS-SD queries to link-local
 * mDNS, so services that only advertise on-link become reachable from other
 * subnets. Runs as its own thread + UDP listener (config:dp_port), separate
 * from the multicast responder's port 5353. Its multicast query/collect
 * step (dp_mdns_collect below) sends via, and buffers responses observed
 * by, the SAME socket mdns_recv_loop already reads (g_mdns4_sock) rather
 * than opening a second one — see the comment on dp_maybe_collect for why.
 * dp_listen_thread itself is a single serial loop (one request handled
 * start-to-finish, including its collection window, before the next); the
 * shared g_dp_collected buffer's mutex protects it against mdns_recv_loop
 * (a different thread) but assumes only one Discovery Proxy request is ever
 * in flight at a time, which that serial loop guarantees. This is a
 * first-milestone, one-shot-discovery feature per CLAUDE-mdnsd.md, not
 * meant to sustain high QPS.
 * ======================================================================= */
#define DP_COLLECT_MS 600
#define DP_MAX_RESPONSES 16
#define DP_MAX_ANSWERS 32

/* True if name ends with suffix on a whole-label boundary (mdnsd has no
 * shared translation unit with resolverd's identical name_in_zone). */
static int dp_suffix_match(const char *name, const char *suffix) {
    size_t nlen = strlen(name), slen = strlen(suffix);
    if (nlen < slen)
        return 0;
    if (strcasecmp(name + (nlen - slen), suffix) != 0)
        return 0;
    return nlen == slen || name[nlen - slen - 1] == '.';
}

/* unicast <prefix>.<suffix> -> mDNS <prefix>.local (bare "local" if prefix
 * is empty, i.e. the query was for the proxied subdomain's apex itself). */
static int dp_to_mdns_name(const char *qname, const char *suffix, char *out, int outsz) {
    size_t nlen = strlen(qname), slen = strlen(suffix);
    if (nlen == slen)
        return snprintf(out, (size_t) outsz, "local") < outsz ? 0 : -1;
    if (nlen < slen + 1)
        return -1;
    size_t plen = nlen - slen - 1; /* also drop the separating dot */
    return snprintf(out, (size_t) outsz, "%.*s.local", (int) plen, qname) < outsz ? 0 : -1;
}

/* Inverse: mDNS <prefix>.local (or bare "local") -> unicast <prefix>.<suffix>.
 * Returns -1 if mdns_name isn't actually under .local (defensive — the
 * caller should leave such a name untouched, not proxy it). */
static int dp_from_mdns_name(const char *mdns_name, const char *suffix, char *out, int outsz) {
    if (!strcasecmp(mdns_name, "local"))
        return snprintf(out, (size_t) outsz, "%s", suffix) < outsz ? 0 : -1;
    static const char LOCAL[] = ".local";
    size_t nlen = strlen(mdns_name), llen = sizeof(LOCAL) - 1;
    if (nlen <= llen || strcasecmp(mdns_name + nlen - llen, LOCAL) != 0)
        return -1;
    size_t plen = nlen - llen;
    return snprintf(out, (size_t) outsz, "%.*s.%s", (int) plen, mdns_name, suffix) < outsz ? 0 : -1;
}

/*
 * Discovery Proxy response collection — deliberately reuses mdnsd's single
 * existing port-5353 socket (g_mdns4_sock, via mdns_send/mdns_recv_loop)
 * rather than opening a second socket bound to the same port. A second
 * SO_REUSEPORT socket sharing that port was the first implementation here,
 * and it silently missed most responses: Linux hash-routes each incoming
 * UDP datagram to exactly ONE socket among a REUSEPORT group sharing a
 * port, not to all of them — so the query (and its multicast replies) would
 * land on whichever of the two sockets won the hash, which in practice was
 * almost always the pre-existing g_mdns4_sock, starving the query socket.
 * Routing every inbound packet through the one socket mdnsd already reads
 * sidesteps the whole class of problem.
 */
static pthread_mutex_t g_dp_collect_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Serializes whole collection rounds (arm -> send -> sleep -> read) against
 * each other. dp_mdns_collect's collection window is process-wide (one
 * armed/collected state shared via g_dp_collect_mutex above) and was
 * originally only ever invoked serially from the single-threaded
 * dp_listen_thread. DSO/Push (Add 2) added concurrent callers — a
 * SUBSCRIBE handler on each session's own thread, plus a periodic poll
 * thread — so without this, two overlapping collections would each see a
 * mix of both callers' responses. This mutex is coarser than
 * g_dp_collect_mutex on purpose: it must be held for the full round
 * (including the DP_COLLECT_MS sleep), not just the bookkeeping updates. */
static pthread_mutex_t g_dp_query_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_dp_armed = 0;
static uint8_t g_dp_collected[DP_MAX_RESPONSES][MDNS_MAX_MSG];
static int g_dp_collected_lens[DP_MAX_RESPONSES];
static int g_dp_collected_count = 0;

/* Called from mdns_recv_loop for every packet it receives, before/alongside
 * its normal query-answering logic — buffers a response packet only while a
 * Discovery Proxy collection window is open. */
static void dp_maybe_collect(const uint8_t *pkt, int plen) {
    if (plen < 12)
        return;
    uint16_t flags = get16(pkt, 2);
    int ancount = get16(pkt, 6);
    if (!(flags & 0x8000) || ancount == 0)
        return; /* not a response, or an empty one */
    pthread_mutex_lock(&g_dp_collect_mutex);
    if (g_dp_armed && g_dp_collected_count < DP_MAX_RESPONSES) {
        int len = plen < MDNS_MAX_MSG ? plen : MDNS_MAX_MSG;
        memcpy(g_dp_collected[g_dp_collected_count], pkt, (size_t) len);
        g_dp_collected_lens[g_dp_collected_count] = len;
        g_dp_collected_count++;
    }
    pthread_mutex_unlock(&g_dp_collect_mutex);
}

/*
 * dp_mdns_collect — send a multicast mDNS query for (qname,qtype) via the
 * shared responder socket and collect EVERY response seen within
 * DP_COLLECT_MS (not just the first, per resolverd's client-side
 * mdns_query — a browse-style PTR query can get separate packets from
 * multiple responders on the link, each advertising a different service
 * instance; a lookup proxy has to gather them all). Returns the number of
 * packets collected into out[]/out_lens[] (capped at max_out).
 */
static int dp_mdns_collect(const char *qname, uint16_t qtype, uint8_t out[][MDNS_MAX_MSG],
                           int *out_lens, int max_out) {
    pthread_mutex_lock(&g_dp_query_mutex);
    uint8_t query[512];
    memset(query, 0, 12);
    put16(query, 4, 1); /* qdcount = 1 — a well-formed responder (and this
                         * codebase's own DNS-SD stub tests) reject qdcount
                         * != 1 outright, silently */
    int off = mdns_put_name(query, 12, sizeof(query), qname);
    if (off < 0 || off + 4 > (int) sizeof(query)) {
        pthread_mutex_unlock(&g_dp_query_mutex);
        return 0;
    }
    put16(query, off, qtype);
    off += 2;
    put16(query, off, DNS_CLASS_IN);
    off += 2;
    int qlen = off;

    pthread_mutex_lock(&g_dp_collect_mutex);
    g_dp_collected_count = 0;
    g_dp_armed = 1;
    pthread_mutex_unlock(&g_dp_collect_mutex);

    mdns_send(query, qlen);
    usleep(DP_COLLECT_MS * 1000);

    pthread_mutex_lock(&g_dp_collect_mutex);
    g_dp_armed = 0;
    int n = g_dp_collected_count < max_out ? g_dp_collected_count : max_out;
    for (int i = 0; i < n; i++) {
        memcpy(out[i], g_dp_collected[i], (size_t) g_dp_collected_lens[i]);
        out_lens[i] = g_dp_collected_lens[i];
    }
    pthread_mutex_unlock(&g_dp_collect_mutex);
    pthread_mutex_unlock(&g_dp_query_mutex);
    return n;
}

typedef struct {
    char name[256];
    uint16_t type;
    uint32_t ttl;
    uint8_t rdata[512];
    int rdlen;
} dp_answer_t;

static int dp_answer_dup(const dp_answer_t *arr, int n, const dp_answer_t *cand) {
    for (int i = 0; i < n; i++) {
        if (arr[i].type == cand->type && strcasecmp(arr[i].name, cand->name) == 0 &&
            arr[i].rdlen == cand->rdlen &&
            memcmp(arr[i].rdata, cand->rdata, (size_t) cand->rdlen) == 0)
            return 1;
    }
    return 0;
}

/*
 * dp_collect_answers — parse every RR in one mDNS response packet's answer
 * section (matching qtype, or a CNAME) and additional section (glue:
 * A/AAAA/TXT/SRV, per RFC 6763 §12 regardless of qtype — bridging a
 * browse->resolve chain in one shot is the whole point), translate names
 * from .local back to the proxied unicast subdomain, and append
 * (deduplicated) to answers[], incrementing *n. Two guardrails enforced here, not
 * optionally: never emit a link-scoped (fe80::/10) AAAA — a remote client
 * can never route to it — and never reuse the source TTL unchanged (RFC
 * 8766 §5.3) — cap it, since a one-shot proxy has no way to push an update
 * when the service later disappears.
 */
static void dp_collect_answers(const uint8_t *pkt, int plen, uint16_t qtype, const char *suffix,
                               uint32_t ttl_cap, dp_answer_t *answers, int *n, int max_n) {
    if (plen < 12)
        return;
    int qdcount = get16(pkt, 4);
    int ancount = get16(pkt, 6), nscount = get16(pkt, 8), arcount = get16(pkt, 10);
    int off = 12;
    for (int i = 0; i < qdcount && off < plen; i++) {
        char tmp[256];
        off = name_from_wire(pkt, plen, off, tmp, sizeof(tmp));
        if (off < 0)
            return;
        off += 4;
    }
    int total = ancount + nscount + arcount;
    for (int i = 0; i < total && off < plen && *n < max_n; i++) {
        char rname[256];
        int a = name_from_wire(pkt, plen, off, rname, sizeof(rname));
        if (a < 0 || a + 10 > plen)
            return;
        uint16_t rtype = get16(pkt, a);
        uint16_t rclass = get16(pkt, a + 2) & 0x7FFF; /* mask the mDNS cache-flush bit */
        uint32_t ttl = get32(pkt, a + 4);
        uint16_t rdlen = get16(pkt, a + 8);
        int rdoff = a + 10;
        if (rdoff + rdlen > plen)
            return;
        off = rdoff + rdlen;
        if (rclass != DNS_CLASS_IN)
            continue;
        if (i < ancount) {
            if (rtype != qtype && rtype != DNS_TYPE_CNAME)
                continue;
        } else if (i < ancount + nscount) {
            continue; /* authority section: not meaningful for an mDNS answer here */
        } else {
            if (rtype != DNS_TYPE_A && rtype != DNS_TYPE_AAAA && rtype != DNS_TYPE_TXT &&
                rtype != DNS_TYPE_SRV)
                continue;
        }
        dp_answer_t cand;
        memset(&cand, 0, sizeof(cand));
        if (dp_from_mdns_name(rname, suffix, cand.name, sizeof(cand.name)) < 0)
            continue; /* not actually under .local — ignore defensively */
        cand.type = rtype;
        cand.ttl = ttl < ttl_cap ? ttl : ttl_cap;
        switch (rtype) {
            case DNS_TYPE_A:
                if (rdlen != 4)
                    continue;
                memcpy(cand.rdata, pkt + rdoff, 4);
                cand.rdlen = 4;
                break;
            case DNS_TYPE_AAAA:
                if (rdlen != 16)
                    continue;
                if (pkt[rdoff] == 0xfe && (pkt[rdoff + 1] & 0xc0) == 0x80)
                    continue; /* fe80::/10 link-local — never leak off-link */
                memcpy(cand.rdata, pkt + rdoff, 16);
                cand.rdlen = 16;
                break;
            case DNS_TYPE_TXT:
                if (rdlen > (uint16_t) sizeof(cand.rdata))
                    continue;
                memcpy(cand.rdata, pkt + rdoff, rdlen);
                cand.rdlen = rdlen;
                break;
            case DNS_TYPE_PTR:
            case DNS_TYPE_CNAME: {
                char tgt[256], rewritten[256];
                if (name_from_wire(pkt, plen, rdoff, tgt, sizeof(tgt)) < 0)
                    continue;
                if (dp_from_mdns_name(tgt, suffix, rewritten, sizeof(rewritten)) < 0)
                    safe_strcpy(rewritten, tgt, sizeof(rewritten)); /* not .local; pass through */
                int n2 = mdns_put_name(cand.rdata, 0, sizeof(cand.rdata), rewritten);
                if (n2 < 0)
                    continue;
                cand.rdlen = n2;
                break;
            }
            case DNS_TYPE_SRV: {
                if (rdlen < 7)
                    continue;
                char tgt[256], rewritten[256];
                if (name_from_wire(pkt, plen, rdoff + 6, tgt, sizeof(tgt)) < 0)
                    continue;
                if (dp_from_mdns_name(tgt, suffix, rewritten, sizeof(rewritten)) < 0)
                    safe_strcpy(rewritten, tgt, sizeof(rewritten));
                memcpy(cand.rdata, pkt + rdoff, 6);
                int n2 = mdns_put_name(cand.rdata, 6, sizeof(cand.rdata), rewritten);
                if (n2 < 0)
                    continue;
                cand.rdlen = n2;
                break;
            }
            default:
                continue; /* unsupported rdata shape — skip rather than guess */
        }
        if (!dp_answer_dup(answers, *n, &cand))
            answers[(*n)++] = cand;
    }
}

/* Find the configured proxied subdomain qname falls under, or NULL if none —
 * shared by the Discovery Proxy query path and the DSO/Push SUBSCRIBE path
 * (Add 2) below, since both gate on the exact same "never proxy/subscribe a
 * subdomain we aren't explicitly configured for" guardrail. */
static const char *dp_find_suffix(const char *qname) {
    for (int i = 0; i < g_dp_subdomain_count; i++)
        if (dp_suffix_match(qname, g_dp_subdomains[i]))
            return g_dp_subdomains[i];
    return NULL;
}

/* dp_handle_query — one Discovery Proxy request, start to finish: validate,
 * translate the qname, run the multicast collection window, translate the
 * answers back, and reply unicast. REFUSED for any name outside the
 * configured proxied subdomains (CLAUDE-mdnsd.md guardrail: never proxy a
 * subdomain we aren't explicitly configured for). */
static void dp_handle_query(int srv_fd, const uint8_t *pkt, int plen, const struct sockaddr *src,
                            socklen_t srclen) {
    if (plen < 12)
        return;
    compress_reset(); /* per-message compression context — see append_rr below */
    uint16_t qflags = get16(pkt, 2);
    if (qflags & 0x8000)
        return; /* ignore responses */
    if (get16(pkt, 4) != 1)
        return; /* qdcount != 1 */
    char qname[256];
    int after = name_from_wire(pkt, plen, 12, qname, sizeof(qname));
    if (after < 0 || after + 4 > plen)
        return;
    uint16_t qtype = get16(pkt, after);
    uint16_t qclass = get16(pkt, after + 2);

    uint8_t resp[MDNS_MAX_MSG];
    memset(resp, 0, 12);
    put16(resp, 0, get16(pkt, 0)); /* echo the query id */
    int qsec = after - 12 + 4;
    int off = 12;
    if (qsec >= 0 && off + qsec < (int) sizeof(resp)) {
        memcpy(resp + off, pkt + 12, qsec);
        off += qsec;
    }
    put16(resp, 4, 1); /* qdcount */

    const char *suffix = dp_find_suffix(qname);
    if (!suffix || qclass != DNS_CLASS_IN) {
        put16(resp, 2, 0x8000 | 5 /* REFUSED */);
        sendto(srv_fd, resp, off, 0, src, srclen);
        return;
    }

    char mdns_qname[256];
    if (dp_to_mdns_name(qname, suffix, mdns_qname, sizeof(mdns_qname)) < 0) {
        put16(resp, 2, 0x8000 | 2 /* SERVFAIL */);
        sendto(srv_fd, resp, off, 0, src, srclen);
        return;
    }

    /* See the module-level comment above: these are static (not stack) both
     * because they're too large to put on the stack repeatedly and because
     * the listener processes one query at a time, serially. */
    static uint8_t collected[DP_MAX_RESPONSES][MDNS_MAX_MSG];
    static int collected_lens[DP_MAX_RESPONSES];
    int nresp = dp_mdns_collect(mdns_qname, qtype, collected, collected_lens, DP_MAX_RESPONSES);

    static dp_answer_t answers[DP_MAX_ANSWERS];
    int nans = 0;
    for (int i = 0; i < nresp; i++)
        dp_collect_answers(collected[i], collected_lens[i], qtype, suffix, g_dp_ttl_cap, answers,
                           &nans, DP_MAX_ANSWERS);

    int ancount = 0;
    for (int i = 0; i < nans; i++) {
        /* append_rr (libdnswire) compresses the owner name against the
         * names already written in this message — plain unicast clients
         * (unlike mDNS's own uncompressed convention) expect this, and the
         * repeated long owner names here (the same instance name for
         * SRV+TXT, the proxied subdomain itself for PTR) compress well. */
        int n2 = append_rr(resp, off, sizeof(resp), answers[i].name, answers[i].type, DNS_CLASS_IN,
                           answers[i].ttl, answers[i].rdata, (uint16_t) answers[i].rdlen);
        if (n2 < 0)
            break;
        off = n2;
        ancount++;
    }
    put16(resp, 6, (uint16_t) ancount);
    put16(resp, 2, 0x8400); /* QR|AA, rcode NOERROR */
    sendto(srv_fd, resp, off, 0, src, srclen);
    dns_log(LOG_INFO, "[DP] %s %s -> %d answer(s) (via mdns %s, %d response(s) collected)\n",
            type2str(qtype), qname, ancount, mdns_qname, nresp);
}

static void *dp_listen_thread(void *arg) {
    (void) arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        dns_log(LOG_ERR, "[DP] socket failed: %s\n", strerror(errno));
        return NULL;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons((uint16_t) g_dp_port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        dns_log(LOG_ERR, "[DP] bind :%d failed: %s\n", g_dp_port, strerror(errno));
        close(fd);
        return NULL;
    }
    dns_log(LOG_NOTICE, "[DP] Discovery Proxy listening on :%d for %d subdomain(s)\n", g_dp_port,
            g_dp_subdomain_count);
    uint8_t buf[MDNS_MAX_MSG];
    for (;;) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        int n = (int) recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &src, &srclen);
        if (n > 0)
            dp_handle_query(fd, buf, n, (struct sockaddr *) &src, srclen);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * RFC 8490 DSO + RFC 8765 DNS Push Notifications (Add 2)
 *
 * "Change" detection is a bounded poll, not a passive full-link mDNS cache:
 * every g_dso_poll_secs, every actively-subscribed (name,type) pair re-runs
 * the same dp_mdns_collect() the Discovery Proxy uses for a one-shot lookup
 * (de-duplicated across sessions — N sessions subscribed to the same name
 * cost one collection round, not N) and diffs the result against what was
 * last pushed to each session. This was chosen over building a continuous
 * shadow cache of every advertisement seen on the link (a materially bigger,
 * riskier piece of state to keep leak-free) because it reuses the
 * already-audited Add 1 collection path and gives subscribers changes
 * within one poll interval, which is adequate for the bounded subscription
 * counts this daemon is designed for.
 *
 * dp_mdns_collect's collection window is process-wide (it arms/reads
 * g_dp_collected under g_dp_collect_mutex and shares mdnsd's single
 * link-local socket) and was previously only ever called from the
 * single-threaded dp_listen_thread. DSO adds concurrent callers — SUBSCRIBE
 * handlers on each session's own thread, plus this poll thread — so
 * dp_mdns_collect itself now serializes whole collection rounds against
 * each other via g_dp_query_mutex (see its definition), not just the
 * bookkeeping variables.
 * ══════════════════════════════════════════════════════════════════════ */

typedef struct {
    char name[256];
    uint16_t type;
    uint16_t msg_id; /* the SUBSCRIBE request's Message ID — what UNSUBSCRIBE references */
    int nans;
    dp_answer_t last[DP_MAX_ANSWERS]; /* last answer set pushed to this subscription */
} dso_sub_t;

typedef struct {
    int fd;
    SSL *ssl;
    int active;
    pthread_mutex_t mutex;  /* protects active/subs/nsubs/last[] below */
    pthread_mutex_t wmutex; /* protects ssl/fd and serializes writes to them.
                             * Lock order: mutex may be held while acquiring
                             * wmutex (dso_poll_one); never the reverse. */
    dso_sub_t subs[DSO_MAX_SUBS_PER_SESSION];
    int nsubs;
} dso_session_t;

static dso_session_t g_dso_sessions[DSO_MAX_SESSIONS];
static SSL_CTX *g_dso_ctx = NULL;
static pthread_mutex_t g_dso_tls_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Build (or rebuild, on cert:current hot-reload) the Push listener's TLS
 * context. Builds the replacement before swapping so a transient bad/absent
 * blob never tears down an already-working listener. Fails closed: leaves
 * g_dso_ctx NULL (listener refuses every connection) until a valid cert
 * exists — RFC 8765 has no plaintext fallback. */
static void dso_tls_reload(void) {
    if (!g_dso_enabled)
        return;
    char blob[24576], cert[16384], key[8192];
    if (!vk_get("cert:current", blob, sizeof(blob)) || !blob[0] ||
        cert_current_split(blob, cert, sizeof(cert), key, sizeof(key)) < 0) {
        dns_log(LOG_WARNING, "[DSO] cert:current unavailable/unparseable — Push listener stays "
                             "down until a cert is published (RFC 8765 requires TLS, never "
                             "plaintext)\n");
        return;
    }
    SSL_CTX *newctx = tls_server_ctx_from_pem(cert, key, NULL, 0);
    if (!newctx) {
        dns_log(LOG_ERR, "[DSO] TLS context build failed from cert:current\n");
        return;
    }
    pthread_mutex_lock(&g_dso_tls_mutex);
    SSL_CTX *old = g_dso_ctx;
    g_dso_ctx = newctx;
    pthread_mutex_unlock(&g_dso_tls_mutex);
    if (old)
        SSL_CTX_free(old);
    dns_log(LOG_INFO, "[DSO] TLS context loaded\n");
}

/* Find a free session slot and claim it (active=1, subs cleared). Returns
 * NULL if all DSO_MAX_SESSIONS slots are in use — a deliberate resource cap,
 * not a soft limit. */
static dso_session_t *dso_alloc_session(void) {
    for (int i = 0; i < DSO_MAX_SESSIONS; i++) {
        dso_session_t *s = &g_dso_sessions[i];
        pthread_mutex_lock(&s->mutex);
        if (!s->active) {
            memset(s->subs, 0, sizeof(s->subs));
            s->nsubs = 0;
            s->active = 1;
            pthread_mutex_unlock(&s->mutex);
            return s;
        }
        pthread_mutex_unlock(&s->mutex);
    }
    return NULL;
}

/* Tear down a session: mark inactive first (so the poll thread's next
 * active-check skips it), then close the TLS/socket under wmutex so a
 * concurrent dso_send_raw() either completes before or safely no-ops after
 * (it re-checks s->ssl != NULL under the same lock). */
static void dso_teardown_session(dso_session_t *s) {
    pthread_mutex_lock(&s->mutex);
    s->active = 0;
    s->nsubs = 0;
    pthread_mutex_unlock(&s->mutex);
    pthread_mutex_lock(&s->wmutex);
    if (s->ssl) {
        SSL_shutdown(s->ssl);
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
    if (s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
    pthread_mutex_unlock(&s->wmutex);
}

/* Length-prefixed (RFC 1035 TCP framing, reused unchanged by RFC 8490 §5)
 * send of one already-built DSO message. No-ops safely if the session's TLS
 * has already been torn down. */
static int dso_send_raw(dso_session_t *s, const uint8_t *msg, int len) {
    pthread_mutex_lock(&s->wmutex);
    int ok = -1;
    if (s->ssl) {
        uint8_t lb[2] = {(uint8_t) (len >> 8), (uint8_t) (len & 0xFF)};
        if (SSL_write(s->ssl, lb, 2) == 2 && SSL_write(s->ssl, msg, len) == len)
            ok = 0;
    }
    pthread_mutex_unlock(&s->wmutex);
    return ok;
}

typedef struct {
    uint16_t type;
    int off;      /* absolute offset of DSO-DATA */
    uint16_t len; /* DSO-DATA length */
} dso_tlv_t;

/* Read one TLV at pkt+off. Returns the offset just past it, or -1 on
 * truncation — the caller must abort the session on -1 (fail closed), not
 * skip bytes and guess. */
static int dso_read_tlv(const uint8_t *pkt, int plen, int off, dso_tlv_t *out) {
    if (off + 4 > plen)
        return -1;
    out->type = get16(pkt, off);
    out->len = get16(pkt, off + 2);
    out->off = off + 4;
    if (out->off + (int) out->len > plen)
        return -1;
    return out->off + out->len;
}

/* A DSO response carrying only the 12-byte header (SUBSCRIBE success/failure,
 * and generic error responses — FORMERR/DSOTYPENI/etc). */
static int dso_build_simple_response(uint16_t msg_id, uint16_t rcode, uint8_t *out, int outsz) {
    if (outsz < 12)
        return -1;
    memset(out, 0, 12);
    put16(out, 0, msg_id);
    put16(out, 2, DNS_QR | DNS_OPCODE_DSO | (rcode & DNS_RCODE_MASK));
    return 12;
}

static int dso_build_keepalive_response(uint16_t msg_id, uint8_t *out, int outsz) {
    if (outsz < 12 + 4 + 8)
        return -1;
    memset(out, 0, 12);
    put16(out, 0, msg_id);
    put16(out, 2, DNS_QR | DNS_OPCODE_DSO | DNS_RCODE_NOERROR);
    int off = 12;
    put16(out, off, DSO_TLV_KEEPALIVE);
    off += 2;
    put16(out, off, 8);
    off += 2;
    put32(out, off, g_dso_inactivity_ms);
    off += 4;
    put32(out, off, g_dso_keepalive_ms);
    off += 4;
    return off;
}

/* Build a unidirectional (Message ID 0) PUSH message: a single Push TLV
 * (RFC 8765 §5.4) whose DATA is a sequence of RRs — TTL as collected for an
 * add, TTL 0xFFFFFFFF (removes exactly this NAME/TYPE/CLASS/RDATA) for a
 * removal. Names are uncompressed (append_rr_plain): the Push TLV's DATA is
 * not the message's absolute offset 0, and libdnswire's compression context
 * (name_to_wire_c) assumes owner names compress against the *whole
 * message's* offsets — using it here would need the TLV's data offset
 * threaded through, which isn't worth it for what are typically a handful
 * of small RRs. Returns the message length, or -1 if nothing fit/was given. */
static int dso_build_push(const dp_answer_t *adds, int nadds, const dp_answer_t *removes,
                          int nremoves, uint8_t *out, int outsz) {
    if (outsz < 16)
        return -1;
    memset(out, 0, 12);
    put16(out, 2, DNS_OPCODE_DSO); /* ID=0, QR=0 -> unidirectional */
    int tlv_hdr = 12;
    int off = tlv_hdr + 4;
    int data_start = off;
    for (int i = 0; i < nadds; i++) {
        int n = append_rr_plain(out, off, outsz, adds[i].name, adds[i].type, DNS_CLASS_IN,
                                adds[i].ttl, adds[i].rdata, (uint16_t) adds[i].rdlen);
        if (n < 0)
            break; /* best-effort: stop rather than overflow the buffer */
        off = n;
    }
    for (int i = 0; i < nremoves; i++) {
        int n = append_rr_plain(out, off, outsz, removes[i].name, removes[i].type, DNS_CLASS_IN,
                                0xFFFFFFFFu, removes[i].rdata, (uint16_t) removes[i].rdlen);
        if (n < 0)
            break;
        off = n;
    }
    int data_len = off - data_start;
    if (data_len == 0)
        return -1;
    put16(out, tlv_hdr, DSO_TLV_PUSH);
    put16(out, tlv_hdr + 2, (uint16_t) data_len);
    return off;
}

static void dso_push_answers(dso_session_t *s, const dp_answer_t *adds, int nadds,
                             const dp_answer_t *removes, int nremoves) {
    if (nadds == 0 && nremoves == 0)
        return;
    uint8_t msg[DSO_MAX_MSG];
    int len = dso_build_push(adds, nadds, removes, nremoves, msg, sizeof(msg));
    if (len < 0)
        return;
    dso_send_raw(s, msg, len);
}

/* Run the Add-1 collection path for (name,type) under suffix and return the
 * translated answer set. Uses stack (not static) buffers because — unlike
 * dp_handle_query, which is only ever called serially from the one
 * dp_listen_thread — this is called concurrently from SUBSCRIBE handlers,
 * the poll thread, and RECONFIRM handling, each on its own thread stack. */
static int dso_collect_current(const char *name, uint16_t type, const char *suffix,
                               dp_answer_t *out, int max_out) {
    char mdns_qname[256];
    if (dp_to_mdns_name(name, suffix, mdns_qname, sizeof(mdns_qname)) < 0)
        return 0;
    uint8_t collected[DP_MAX_RESPONSES][MDNS_MAX_MSG];
    int collected_lens[DP_MAX_RESPONSES];
    int nresp = dp_mdns_collect(mdns_qname, type, collected, collected_lens, DP_MAX_RESPONSES);
    int n = 0;
    for (int r = 0; r < nresp; r++)
        dp_collect_answers(collected[r], collected_lens[r], type, suffix, g_dp_ttl_cap, out, &n,
                           max_out);
    return n;
}

/* Diff a freshly-collected answer set against every session subscribed to
 * (name,type) and PUSH each session only what changed for it. Called both
 * by the periodic poller (below) and by RECONFIRM (an on-demand re-check of
 * one name/type). */
static void dso_poll_one(const char *name, uint16_t type, const dp_answer_t *cur, int ncur) {
    for (int i = 0; i < DSO_MAX_SESSIONS; i++) {
        dso_session_t *s = &g_dso_sessions[i];
        for (int j = 0; j < DSO_MAX_SUBS_PER_SESSION; j++) {
            pthread_mutex_lock(&s->mutex);
            if (!s->active || j >= s->nsubs) {
                pthread_mutex_unlock(&s->mutex);
                break;
            }
            dso_sub_t *sub = &s->subs[j];
            if (sub->type != type || strcasecmp(sub->name, name) != 0) {
                pthread_mutex_unlock(&s->mutex);
                continue;
            }
            dp_answer_t adds[DP_MAX_ANSWERS], removes[DP_MAX_ANSWERS];
            int nadds = 0, nremoves = 0;
            for (int c = 0; c < ncur; c++)
                if (!dp_answer_dup(sub->last, sub->nans, &cur[c]))
                    adds[nadds++] = cur[c];
            for (int p = 0; p < sub->nans; p++)
                if (!dp_answer_dup(cur, ncur, &sub->last[p]))
                    removes[nremoves++] = sub->last[p];
            sub->nans = ncur;
            memcpy(sub->last, cur, sizeof(dp_answer_t) * (size_t) ncur);
            pthread_mutex_unlock(&s->mutex);
            if (nadds || nremoves)
                dso_push_answers(s, adds, nadds, removes, nremoves);
        }
    }
}

static void dso_handle_subscribe(dso_session_t *sess, uint16_t msg_id, const uint8_t *pkt, int mlen,
                                 const dso_tlv_t *tlv) {
    if (msg_id == 0) /* SUBSCRIBE must be a request, never unidirectional */
        return;
    char qname[256];
    int a = name_from_wire(pkt, mlen, tlv->off, qname, sizeof(qname));
    /* RFC 8765 §5.1: DSO-DATA MUST contain exactly one NAME, TYPE, CLASS —
     * reject anything trailing or short as malformed, not "ignore the rest". */
    if (a < 0 || a + 4 != tlv->off + (int) tlv->len) {
        uint8_t resp[12];
        int rl = dso_build_simple_response(msg_id, DNS_RCODE_FORMERR, resp, sizeof(resp));
        dso_send_raw(sess, resp, rl);
        return;
    }
    uint16_t qtype = get16(pkt, a);
    uint16_t qclass = get16(pkt, a + 2);
    const char *suffix = (qclass == DNS_CLASS_IN) ? dp_find_suffix(qname) : NULL;
    if (!suffix) {
        /* Guardrail: never subscribe a name we aren't explicitly configured
         * to proxy — same posture as Add 1's REFUSED-on-unconfigured-subdomain. */
        uint8_t resp[12];
        int rl = dso_build_simple_response(msg_id, DNS_RCODE_REFUSED, resp, sizeof(resp));
        dso_send_raw(sess, resp, rl);
        return;
    }

    pthread_mutex_lock(&sess->mutex);
    dso_sub_t *slot = NULL;
    for (int i = 0; i < sess->nsubs; i++)
        if (sess->subs[i].type == qtype && strcasecmp(sess->subs[i].name, qname) == 0) {
            slot = &sess->subs[i];
            break;
        }
    if (!slot && sess->nsubs >= g_dso_max_subs) {
        pthread_mutex_unlock(&sess->mutex);
        uint8_t resp[12]; /* per-session subscription cap guardrail */
        int rl = dso_build_simple_response(msg_id, DNS_RCODE_REFUSED, resp, sizeof(resp));
        dso_send_raw(sess, resp, rl);
        return;
    }
    if (!slot)
        slot = &sess->subs[sess->nsubs++];
    memset(slot, 0, sizeof(*slot));
    safe_strcpy(slot->name, qname, sizeof(slot->name));
    slot->type = qtype;
    slot->msg_id = msg_id;
    pthread_mutex_unlock(&sess->mutex);

    uint8_t resp[12];
    int rl = dso_build_simple_response(msg_id, DNS_RCODE_NOERROR, resp, sizeof(resp));
    dso_send_raw(sess, resp, rl);

    /* RFC 8765 §5.1: "In the case that the answer set was already non-empty
     * ... an initial PUSH message will be sent immediately following the
     * SUBSCRIBE Response." */
    dp_answer_t cur[DP_MAX_ANSWERS];
    int ncur = dso_collect_current(qname, qtype, suffix, cur, DP_MAX_ANSWERS);
    pthread_mutex_lock(&sess->mutex);
    for (int i = 0; i < sess->nsubs; i++)
        if (sess->subs[i].type == qtype && strcasecmp(sess->subs[i].name, qname) == 0) {
            sess->subs[i].nans = ncur;
            memcpy(sess->subs[i].last, cur, sizeof(dp_answer_t) * (size_t) ncur);
            break;
        }
    pthread_mutex_unlock(&sess->mutex);
    if (ncur > 0)
        dso_push_answers(sess, cur, ncur, NULL, 0);
    dns_log(LOG_INFO, "[DSO] SUBSCRIBE %s %s from session (id %u) -> %d initial answer(s)\n",
            type2str(qtype), qname, msg_id, ncur);
}

static void dso_handle_unsubscribe(dso_session_t *sess, uint16_t sub_msg_id) {
    pthread_mutex_lock(&sess->mutex);
    for (int i = 0; i < sess->nsubs; i++) {
        if (sess->subs[i].msg_id == sub_msg_id) {
            sess->subs[i] = sess->subs[sess->nsubs - 1];
            sess->nsubs--;
            break;
        }
    }
    pthread_mutex_unlock(&sess->mutex);
}

/* RFC 8765 §5.6: client asks the server to re-verify data it suspects is
 * stale. DSO-DATA is one full RR (NAME/TYPE/CLASS/TTL/RDATA); we only need
 * NAME+TYPE to decide what to re-check — re-running the collection early
 * and pushing any resulting diff to whichever sessions are subscribed is a
 * faithful implementation of "re-verify," just without a bespoke
 * revalidation mechanism beyond what SUBSCRIBE already uses. */
static void dso_handle_reconfirm(const uint8_t *pkt, int mlen, const dso_tlv_t *tlv) {
    char qname[256];
    int a = name_from_wire(pkt, mlen, tlv->off, qname, sizeof(qname));
    if (a < 0 || a + 4 > tlv->off + (int) tlv->len)
        return; /* malformed — unidirectional, nothing to error back */
    uint16_t qtype = get16(pkt, a);
    uint16_t qclass = get16(pkt, a + 2);
    if (qclass == DNS_CLASS_ANY || qtype == DNS_TYPE_ANY)
        return;
    const char *suffix = dp_find_suffix(qname);
    if (!suffix)
        return;
    dp_answer_t cur[DP_MAX_ANSWERS];
    int ncur = dso_collect_current(qname, qtype, suffix, cur, DP_MAX_ANSWERS);
    dso_poll_one(qname, qtype, cur, ncur);
}

/* Dispatch one parsed DSO message. Returns 0 to keep the session open, -1 to
 * abort it (fail closed on anything that doesn't parse as a well-formed DSO
 * message — this listener speaks DSO exclusively, there is no plaintext/
 * classic-query fallback to degrade to). */
static int dso_handle_message(dso_session_t *sess, const uint8_t *pkt, int mlen) {
    if (mlen < 12)
        return -1;
    uint16_t msg_id = get16(pkt, 0);
    uint16_t flags = get16(pkt, 2);
    if ((flags & DNS_OPCODE_MASK) != DNS_OPCODE_DSO) {
        if (msg_id != 0) {
            uint8_t resp[12];
            int rl = dso_build_simple_response(msg_id, DNS_RCODE_NOTIMP, resp, sizeof(resp));
            dso_send_raw(sess, resp, rl);
        }
        return -1;
    }
    if (get16(pkt, 4) || get16(pkt, 6) || get16(pkt, 8) || get16(pkt, 10)) {
        /* RFC 8490 §5.1: QD/AN/NS/ARCOUNT MUST be zero in a DSO message */
        if (msg_id != 0) {
            uint8_t resp[12];
            int rl = dso_build_simple_response(msg_id, DNS_RCODE_FORMERR, resp, sizeof(resp));
            dso_send_raw(sess, resp, rl);
        }
        return -1;
    }
    dso_tlv_t tlv;
    if (dso_read_tlv(pkt, mlen, 12, &tlv) < 0) {
        if (msg_id != 0) {
            uint8_t resp[12];
            int rl = dso_build_simple_response(msg_id, DNS_RCODE_FORMERR, resp, sizeof(resp));
            dso_send_raw(sess, resp, rl);
        }
        return -1;
    }
    switch (tlv.type) {
        case DSO_TLV_KEEPALIVE:
            if (msg_id == 0 || tlv.len != 8)
                return 0; /* malformed/unidirectional keepalive — silently ignore, not fatal */
            {
                uint8_t resp[24];
                int rl = dso_build_keepalive_response(msg_id, resp, sizeof(resp));
                dso_send_raw(sess, resp, rl);
            }
            return 0;
        case DSO_TLV_SUBSCRIBE:
            dso_handle_subscribe(sess, msg_id, pkt, mlen, &tlv);
            return 0;
        case DSO_TLV_UNSUBSCRIBE:
            if (msg_id != 0 || tlv.len != 2)
                return 0; /* UNSUBSCRIBE is unidirectional; malformed -> ignore */
            dso_handle_unsubscribe(sess, get16(pkt, tlv.off));
            return 0;
        case DSO_TLV_RECONFIRM:
            if (msg_id != 0)
                return 0; /* RECONFIRM is unidirectional */
            dso_handle_reconfirm(pkt, mlen, &tlv);
            return 0;
        default:
            /* Unimplemented Primary TLV type. RFC 8490 §5.2: only a request
             * gets a response; a unidirectional message with an unknown type
             * is just ignored. */
            if (msg_id != 0) {
                uint8_t resp[12];
                int rl = dso_build_simple_response(msg_id, DNS_RCODE_DSOTYPENI, resp, sizeof(resp));
                dso_send_raw(sess, resp, rl);
            }
            return 0;
    }
}

static void *dso_session_thread(void *arg) {
    dso_session_t *sess = arg;
    /* RFC 8490 §6.1/6.3: a session with no traffic for the inactivity
     * timeout must be closed; the server side allows "5 seconds or twice
     * the inactivity value, whichever is greater" beyond that before it
     * forcibly aborts. Modeled here as one rolling SO_RCVTIMEO — any
     * received message (not just Keepalive; that only resets the
     * *keepalive* timer, not the inactivity timer per spec, but we don't
     * distinguish the two clocks) restarts the wait by virtue of looping
     * back into a fresh recv. */
    uint32_t grace = g_dso_inactivity_ms * 2 > 5000 ? g_dso_inactivity_ms * 2 : 5000;
    uint32_t total_ms = g_dso_inactivity_ms + grace;
    struct timeval tv = {.tv_sec = total_ms / 1000, .tv_usec = (long) (total_ms % 1000) * 1000};
    setsockopt(sess->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        uint8_t lb[2];
        int got = 0;
        while (got < 2) {
            int n = SSL_read(sess->ssl, lb + got, 2 - got);
            if (n <= 0)
                goto done;
            got += n;
        }
        int mlen = (lb[0] << 8) | lb[1];
        if (mlen < 12 || mlen > DSO_MAX_MSG)
            break;
        uint8_t pkt[DSO_MAX_MSG];
        got = 0;
        while (got < mlen) {
            int n = SSL_read(sess->ssl, pkt + got, mlen - got);
            if (n <= 0)
                goto done;
            got += n;
        }
        if (dso_handle_message(sess, pkt, mlen) < 0)
            break;
    }
done:
    dso_teardown_session(sess);
    return NULL;
}

static void *dso_listen_thread(void *arg) {
    (void) arg;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        dns_log(LOG_ERR, "[DSO] socket failed: %s\n", strerror(errno));
        return NULL;
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons((uint16_t) g_dso_port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        dns_log(LOG_ERR, "[DSO] bind :%d failed: %s\n", g_dso_port, strerror(errno));
        close(fd);
        return NULL;
    }
    if (listen(fd, 16) < 0) {
        dns_log(LOG_ERR, "[DSO] listen failed: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }
    dns_log(LOG_NOTICE, "[DSO] Push listener on :%d (TLS)\n", g_dso_port);
    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(fd, (struct sockaddr *) &caddr, &clen);
        if (cfd < 0)
            continue;
        pthread_mutex_lock(&g_dso_tls_mutex);
        SSL_CTX *ctx = g_dso_ctx;
        SSL *ssl = ctx ? SSL_new(ctx) : NULL;
        if (ssl)
            SSL_set_fd(ssl, cfd);
        pthread_mutex_unlock(&g_dso_tls_mutex);
        if (!ssl) { /* no cert yet — fail closed, never plaintext */
            close(cfd);
            continue;
        }
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(cfd);
            continue;
        }
        dso_session_t *sess = dso_alloc_session();
        if (!sess) {
            dns_log(LOG_WARNING, "[DSO] session cap (%d) reached — rejecting connection\n",
                    DSO_MAX_SESSIONS);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(cfd);
            continue;
        }
        pthread_mutex_lock(&sess->wmutex);
        sess->fd = cfd;
        sess->ssl = ssl;
        pthread_mutex_unlock(&sess->wmutex);
        pthread_t st;
        if (pthread_create(&st, NULL, dso_session_thread, sess) == 0)
            pthread_detach(st);
        else
            dso_teardown_session(sess);
    }
    return NULL;
}

static void *dso_poll_thread(void *arg) {
    (void) arg;
    for (;;) {
        sleep(g_dso_poll_secs > 0 ? g_dso_poll_secs : 5);
        if (!g_dso_enabled)
            continue;
        /* De-duplicate (name,type) across every session's subscriptions —
         * dp_mdns_collect blocks for DP_COLLECT_MS per unique pair and only
         * one collection round runs at a time (g_dp_query_mutex), so this
         * keeps one poll cycle's cost proportional to unique subscriptions,
         * not total sessions. static: dso_poll_thread has exactly one
         * instance, so this isn't shared across concurrent callers. */
        typedef struct {
            char name[256];
            uint16_t type;
        } dso_key_t;
        static dso_key_t keys[DSO_MAX_SESSIONS * DSO_MAX_SUBS_PER_SESSION];
        int nkeys = 0;
        for (int i = 0; i < DSO_MAX_SESSIONS; i++) {
            dso_session_t *s = &g_dso_sessions[i];
            pthread_mutex_lock(&s->mutex);
            if (s->active) {
                for (int j = 0; j < s->nsubs; j++) {
                    int dup = 0;
                    for (int k = 0; k < nkeys; k++)
                        if (keys[k].type == s->subs[j].type &&
                            strcasecmp(keys[k].name, s->subs[j].name) == 0) {
                            dup = 1;
                            break;
                        }
                    if (!dup && nkeys < (int) (sizeof(keys) / sizeof(keys[0]))) {
                        safe_strcpy(keys[nkeys].name, s->subs[j].name, sizeof(keys[nkeys].name));
                        keys[nkeys].type = s->subs[j].type;
                        nkeys++;
                    }
                }
            }
            pthread_mutex_unlock(&s->mutex);
        }
        for (int k = 0; k < nkeys; k++) {
            const char *suffix = dp_find_suffix(keys[k].name);
            if (!suffix)
                continue; /* config changed underneath an existing subscription */
            dp_answer_t cur[DP_MAX_ANSWERS];
            int ncur = dso_collect_current(keys[k].name, keys[k].type, suffix, cur, DP_MAX_ANSWERS);
            dso_poll_one(keys[k].name, keys[k].type, cur, ncur);
        }
    }
    return NULL;
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

/* config:dso_inactivity_ms / dso_keepalive_ms / dso_max_subscriptions /
 * dso_poll_interval_secs are plain variables read fresh by each new
 * SUBSCRIBE/poll cycle — no bound resource to rebind, so they reload live.
 * dso_enabled/dso_port instead need a restart (listener socket is bound at
 * startup), same posture as mdns_interfaces/mdns_enabled above. */
static void dso_soft_config_reload(void) {
    char val[512];
    if (vk_get("config:dso_inactivity_ms", val, sizeof(val)) && val[0])
        g_dso_inactivity_ms = (uint32_t) atoi(val);
    if (vk_get("config:dso_keepalive_ms", val, sizeof(val)) && val[0])
        g_dso_keepalive_ms = (uint32_t) atoi(val);
    if (vk_get("config:dso_max_subscriptions", val, sizeof(val)) && val[0]) {
        int v = atoi(val);
        g_dso_max_subs = (v > 0 && v <= DSO_MAX_SUBS_PER_SESSION) ? v : DSO_MAX_SUBS_PER_SESSION;
    }
    if (vk_get("config:dso_poll_interval_secs", val, sizeof(val)) && val[0]) {
        int v = atoi(val);
        g_dso_poll_secs = (v >= 2) ? v : 2;
    }
}

static void mdns_keyspace_apply(const char *key, void *ctx) {
    (void) ctx;
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
    } else if (strcmp(key, "cert:current") == 0) {
        dso_tls_reload();
    } else if (strcmp(key, "config:dso_enabled") == 0 || strcmp(key, "config:dso_port") == 0) {
        dns_log(LOG_WARNING,
                "[Reload] %s changed — restart mdnsd to apply (DSO listener socket is bound at "
                "startup)\n",
                key);
    } else if (strncmp(key, "config:dso_", 11) == 0) {
        dso_soft_config_reload();
    } else if (strncmp(key, "config:mdns_", 12) == 0) {
        mdns_announce();
    }
}

/* No catch-up pass on (re)connect: this mirrors mdnsd's pre-existing
 * behavior exactly (the hand-rolled loop this replaces never re-applied
 * current config after a reconnect either, only reacted to pmessages seen
 * from that point forward) — repointing at the shared watcher intentionally
 * doesn't change that. A future improvement could re-run mdns_announce() +
 * dso_tls_reload() here, matching eppd/apid/doqd's own catch-up callbacks,
 * but that's new behavior, not part of this repoint. */
static void mdns_keyspace_catchup(void *ctx) {
    (void) ctx;
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

            /* RFC 8766 Discovery Proxy: buffer this packet if it's a
             * response and a collection window is open (dp_mdns_collect). */
            dp_maybe_collect(pkt, (int) n);

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
    /* RFC 8766 Discovery Proxy — opt-in, and only with an explicit proxied
     * subdomain list (never implicitly proxy the whole link). */
    g_dp_enabled = (vk_get("config:dp_enabled", val, sizeof(val)) && atoi(val) == 1);
    if (g_dp_enabled) {
        if (vk_get("config:dp_subdomains", val, sizeof(val)) && val[0]) {
            char *sp = NULL;
            for (char *tok = strtok_r(val, ",", &sp);
                 tok && g_dp_subdomain_count < DP_MAX_SUBDOMAINS; tok = strtok_r(NULL, ",", &sp))
                safe_strcpy(g_dp_subdomains[g_dp_subdomain_count++], tok,
                            sizeof(g_dp_subdomains[0]));
        }
        if (g_dp_subdomain_count == 0) {
            dns_log(LOG_ERR,
                    "[DP] config:dp_enabled=1 but config:dp_subdomains is empty — Discovery "
                    "Proxy stays OFF\n");
            g_dp_enabled = 0;
        }
        if (vk_get("config:dp_port", val, sizeof(val)) && val[0])
            g_dp_port = atoi(val);
        if (vk_get("config:dp_ttl_cap", val, sizeof(val)) && val[0])
            g_dp_ttl_cap = (uint32_t) atoi(val);
    }
    /* RFC 8490 DSO + RFC 8765 Push (Add 2) — opt-in, and only meaningful on
     * top of an active Discovery Proxy (Push has nothing to subscribe to
     * otherwise: SUBSCRIBE is gated on the same proxied-subdomain list). */
    g_dso_enabled = (vk_get("config:dso_enabled", val, sizeof(val)) && atoi(val) == 1);
    if (g_dso_enabled && !g_dp_enabled) {
        dns_log(LOG_ERR, "[DSO] config:dso_enabled=1 but Discovery Proxy (config:dp_enabled) is "
                         "off — Push has no subdomains to subscribe under. DSO stays OFF\n");
        g_dso_enabled = 0;
    }
    if (g_dso_enabled) {
        if (vk_get("config:dso_port", val, sizeof(val)) && val[0])
            g_dso_port = atoi(val);
        if (vk_get("config:dso_inactivity_ms", val, sizeof(val)) && val[0])
            g_dso_inactivity_ms = (uint32_t) atoi(val);
        if (vk_get("config:dso_keepalive_ms", val, sizeof(val)) && val[0])
            g_dso_keepalive_ms = (uint32_t) atoi(val);
        if (vk_get("config:dso_max_subscriptions", val, sizeof(val)) && val[0]) {
            int v = atoi(val);
            g_dso_max_subs =
                (v > 0 && v <= DSO_MAX_SUBS_PER_SESSION) ? v : DSO_MAX_SUBS_PER_SESSION;
        }
        if (vk_get("config:dso_poll_interval_secs", val, sizeof(val)) && val[0]) {
            int v = atoi(val);
            /* Floor at 2s: DP_COLLECT_MS=600ms per unique subscribed name
             * means a too-small interval just piles up backlogged cycles. */
            g_dso_poll_secs = (v >= 2) ? v : 2;
        }
    }
    return 0;
}

/* ADR-003 schema-version gate. mdnsd is NOT the seeder (dnsd writes
 * schema:version) and is read-only on the bus; it only checks. Absent/Valkey-down
 * is "assume current" and never blocks; an incompatible major (or unparseable
 * value) refuses. Returns 0 to proceed, -1 to refuse. */
static int schema_gate(void) {
    char sv[32] = "";
    vk_get("schema:version", sv, sizeof(sv));
    switch (schema_version_check(sv)) {
        case SCHEMA_OK:
            return 0;
        case SCHEMA_MINOR_DIFF:
            dns_log(LOG_WARNING,
                    "[Schema] schema:version %s differs in minor from compiled %s — continuing\n",
                    sv, SCHEMA_VERSION_STR);
            return 0;
        case SCHEMA_ABSENT:
            dns_log(LOG_INFO, "[Schema] schema:version absent — assuming compiled %s\n",
                    SCHEMA_VERSION_STR);
            return 0;
        default: /* SCHEMA_MAJOR_DIFF or SCHEMA_MALFORMED */
            dns_log(
                LOG_ERR,
                "[Schema] schema:version %s incompatible with compiled %s — refusing to start\n",
                sv[0] ? sv : "(unparseable)", SCHEMA_VERSION_STR);
            return -1;
    }
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    srand((unsigned) time(NULL) ^ (unsigned) getpid());
    if (load_config() < 0)
        return 1;
    if (schema_gate() != 0)
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
     * (migration Step 6), via the shared keyspace_watch_loop (dns_wire.h). */
    {
        static keyspace_watch_config_t kcfg;
        memset(&kcfg, 0, sizeof(kcfg));
        kcfg.host = g_valkey_host;
        kcfg.port = g_valkey_port;
        kcfg.pass = g_valkey_pass;
        kcfg.db = KEYSPACE_DB;
        static const char *prefixes[] = {"mdns:*", "config:mdns_*", "cert:current",
                                         "config:dso_*", NULL};
        kcfg.prefixes = prefixes;
        kcfg.on_reconnect = mdns_keyspace_catchup;
        kcfg.on_key = mdns_keyspace_apply;
        kcfg.log = dns_log;
        kcfg.tag = "mdnsd";
        pthread_t kt;
        if (pthread_create(&kt, NULL, keyspace_watch_loop, &kcfg) == 0)
            pthread_detach(kt);
        else
            dns_log(LOG_ERR, "[Reload] Failed to start keyspace watcher\n");
    }
    if (g_dp_enabled) {
        pthread_t dpt;
        if (pthread_create(&dpt, NULL, dp_listen_thread, NULL) == 0)
            pthread_detach(dpt);
        else
            dns_log(LOG_ERR, "[DP] Failed to start Discovery Proxy listener\n");
    }
    if (g_dso_enabled) {
        for (int i = 0; i < DSO_MAX_SESSIONS; i++) {
            pthread_mutex_init(&g_dso_sessions[i].mutex, NULL);
            pthread_mutex_init(&g_dso_sessions[i].wmutex, NULL);
            g_dso_sessions[i].fd = -1;
            g_dso_sessions[i].ssl = NULL;
            g_dso_sessions[i].active = 0;
        }
        dso_tls_reload();
        pthread_t dsolt, dsopt;
        if (pthread_create(&dsolt, NULL, dso_listen_thread, NULL) == 0)
            pthread_detach(dsolt);
        else
            dns_log(LOG_ERR, "[DSO] Failed to start Push listener\n");
        if (pthread_create(&dsopt, NULL, dso_poll_thread, NULL) == 0)
            pthread_detach(dsopt);
        else
            dns_log(LOG_ERR, "[DSO] Failed to start Push poll thread\n");
    }
    mdns_recv_loop(g_mdns4_sock, g_mdns6_sock);
    return 0;
}
