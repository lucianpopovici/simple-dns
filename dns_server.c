/*
 * dns_server.c — Production authoritative DNS server
 *
 * Implemented RFCs:
 *   1034/1035  Core DNS – query/response, wire format, record types
 *   1876       LOC records (geographic location)
 *   1995       IXFR – Incremental Zone Transfer (real diff + AXFR fallback)
 *   1996       DNS NOTIFY – prompt zone-change notification
 *   2136       DNS UPDATE – dynamic record management (zone verification)
 *   2181       Clarifications (QDCOUNT=1 enforced, TTL clamped to 2^31-1)
 *   2308       Negative caching – SOA in authority on NXDOMAIN/NODATA
 *   2782       SRV records
 *   2931       SIG(0) transaction signatures (stub – reject unsigned updates)
 *   3007       Secure DNS Dynamic Update (TSIG prerequisite)
 *   3596       AAAA records
 *   3597       Unknown RR type pass-through (zone:TYPE:name keys are served as-is;
 *              the \# presentation-format parser is not implemented)
 *   4033-4035  DNSSEC – ZSK, DNSKEY, RRSIG, NSEC, Algorithm 13
 *   6781       DNSSEC operational practices – automated ZSK rollover (§4.1.1.1 Pre-Publish)
 *   4255/6594  SSHFP records
 *   4592       Wildcard records (*.label synthesis)
 *   6303       Locally served DNS zones (RFC 6303)
 *   7344/8078  CDS/CDNSKEY – child signals for DNSSEC delegation
 *   7553       URI records
 *   9250 stub  NAPTR records (query/serve)
 *   5001       NSID – Name Server Identifier EDNS option
 *   5155       NSEC3 – hashed authenticated denial of existence
 *   5936       AXFR – Full Zone Transfer over TCP
 *   6672       DNAME – whole-subtree redirection
 *   6698/7671  DANE/TLSA records
 *   6891       EDNS(0) – full OPT RR in responses, payload size negotiation
 *   7828       edns-tcp-keepalive EDNS option (DoT)
 *   7830/8467  EDNS Padding
 *   7858       DNS-over-TLS (DoT)
 *   8080       EdDSA/Ed25519 DNSSEC algorithm 15 (alongside Alg 13)
 *   8482       Minimal responses to QTYPE=ANY
 *   8484       DNS-over-HTTPS (DoH) – /dns-query endpoint on HTTPS port
 *   8659       CAA records
 *   8914       Extended DNS Errors (EDE) EDNS option
 *   8945       TSIG – per-message HMAC authentication for UPDATE/AXFR/NOTIFY
 *   9018       DNS Cookies – SipHash-2-4 anti-spoofing/amplification
 *   9364       DNSSEC (consolidation RFC)
 *   9619       QDCOUNT=1 enforcement for QUERY
 *   6762       mDNS RFC 6762 (Multicast DNS, dual-stack IPv4+IPv6)
 *   6763       DNS-SD RFC 6763 (Service Discovery / Bonjour browsing)
 *   7030       EST  RFC 7030 (Enrollment over Secure Transport, mTLS)
 *   8555       ACME RFC 8555 (DNS-01 challenge, cert auto-renewal, mTLS)
 *
 * New Valkey key schema additions:
 *   config:soa_mname           SOA primary nameserver  (default: ns1.<domain>)
 *   config:soa_rname           SOA responsible mailbox (default: hostmaster.<domain>)
 *   config:soa_refresh         SOA refresh interval    (default: 3600)
 *   config:soa_retry           SOA retry interval      (default: 900)
 *   config:soa_expire          SOA expire interval     (default: 604800)
 *   config:soa_minimum         SOA minimum/negative TTL(default: 300)
 *   config:zone_serial         SOA serial (auto-incremented on changes)
 *   config:tsig_key_name       TSIG key name           (default: tsig-key)
 *   config:tsig_secret_b64     TSIG HMAC-SHA256 secret (base64)
 *   config:nsid                NSID string             (default: hostname)
 *   config:cookie_secret       16-byte hex cookie secret
 *   config:axfr_allow          Comma-separated IPs/CIDRs allowed to do AXFR
 *   config:notify_targets      Comma-separated IP:port targets for NOTIFY
 *   config:privdrop_user       Unprivileged user dnsd setuids to after binding
 *                              sockets (env DNS_USER overrides; default "nobody")
 *   config:privdrop_group      Unprivileged group (env DNS_GROUP; default = the
 *                              user's primary group). Only acts when run as root.
 *   config:seccomp_mode        Syscall sandbox: "audit" (default, log-only),
 *                              "enforce" (EPERM), or "off". Needs -DHAVE_SECCOMP.
 *
 * Multi-zone key schema (migration Step 7) — records carry the owning zone:
 *   zone_table:<zone>          Zone SOA + transfer settings
 *                              (mname|rname|serial|refresh|retry|expire|minimum
 *                               |axfr_allow|notify_targets)
 *   zone:<zone>:<TYPE>:<name>  Authoritative record, e.g. zone:example.com:A:www.example.com
 *                              (SRV ttl|prio|weight|port|target; CAA ttl|flags|tag|value;
 *                               SSHFP ttl|alg|fptype|fp_hex; TLSA ttl|usage|sel|mtype|hex;
 *                               DNAME ttl|target; LOC ttl|loc_wire_hex; …)
 *   ddns:<zone>:<TYPE>:<name>  Dynamic record (RFC 2136 / HTTP /update)
 *   config:zone:<zone>:serial  Per-zone SOA serial counter (primary keeps config:zone_serial)
 *   config:zone:<zone>:nsec3_iters / :nsec3_salt / :dnssec_nsec_mode
 *                              Per-zone denial config (defaults from the global config:* values)
 *   dnssec:<zone>:{zsk,zsk_ed25519,ksk,ksk_ed25519}
 *                              Per-zone DNSSEC keys (primary adopts the legacy dnssec:* keys)
 *   The legacy single-zone keys (zone:<TYPE>:<name>, dnssec:zsk, …) are migrated
 *   with tools/migrate-multizone.sh.
 *
 * Per-zone ZSK rollover schema (RFC 6781 Pre-Publish; written by dnsd):
 *   dnssec:<zone>:zsk_created  Epoch the active ZSK set was created
 *   dnssec:<zone>:zsk_rollover "publish|<epoch>" or "commit|<epoch>" (absent = idle)
 *   dnssec:<zone>:zsk_next / :zsk_ed25519_next
 *                              Incoming ZSK set, present only during a rollover
 *   dnssec:<zone>:zsk_rollover_seen
 *                              Last manual-trigger value dnsd has acted on (edge-trigger)
 *   config:[zone:<zone>:]zsk_validity            ZSK lifetime (s); 0/unset = no auto-roll
 *   config:[zone:<zone>:]rollover_publish_hold   Publish-phase hold (s, default 3600)
 *   config:[zone:<zone>:]rollover_commit_hold    Commit-phase hold (s, default 3600)
 *   config:zone:<zone>:zsk_rollover_request      Manual trigger (set a fresh value to roll now)
 *   config:rollover_tick_secs                    Rollover engine poll interval (s, default 30)
 *
 * Build:
 *   gcc -O2 -Wall -I<openssl-inc> -o dns_server dns_server.c \
 *       -L<openssl-lib> -lssl -lcrypto -lpthread -Wl,-rpath,<openssl-lib>
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
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include "dns_wire.h"

/* ==========================================================================
 * Compile-time defaults
 * ======================================================================= */
#define BOOT_FILE "dns_server.boot"
#define METRICS_PORT_DEFAULT 8054 /* localhost /metrics+/health */
#define DNS_PORT_DEFAULT 5353
#define DOT_PORT_DEFAULT 8853
#define HTTP_PORT_DEFAULT 8053
#define HTTPS_PORT_DEFAULT 8443
#define DEFAULT_TTL 60
#define DEFAULT_NEG_TTL 300
#define DNSSEC_SIG_VALIDITY (7 * 86400)
#define MAX_PEM 65536
#define BUF_SIZE 4096 /* enlarged for EDNS/AXFR */
#define HTTP_BUF 16384
#define RESP_BUF 65536
#define EDNS_MAX_UDP 1232 /* current BCP 2020 recommendation */
#define MAX_AXFR_THREADS 8
#define TSIG_ALG_HMAC_SHA256 "hmac-sha256."
/* TSIG time window in seconds (RFC 8945 §5.2.3 recommends 300). Emitted as
 * two big-endian bytes in BOTH the digest input and the TSIG RDATA — keep
 * every emit site on this constant so the two cannot drift apart. */
#define TSIG_FUDGE 300
#define DNS_COOKIE_CLIENT_LEN 8
#define DNS_COOKIE_SERVER_LEN 16 /* RFC 9018 §4.2: version|reserved|timestamp|hash */
#define DNS_COOKIE_VALIDITY 3600 /* seconds */

/* ==========================================================================
 * DNS type / class / opcode constants
 * ======================================================================= */
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_PTR 12 /* RFC 1035 — pointer for reverse DNS */
#define DNS_TYPE_SOA 6
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_LOC 29
#define DNS_TYPE_SRV 33
#define DNS_TYPE_NAPTR 35
#define DNS_TYPE_DNAME 39
#define DNS_TYPE_OPT 41
#define DNS_TYPE_SSHFP 44
#define DNS_TYPE_RRSIG 46
#define DNS_TYPE_NSEC 47
#define DNS_TYPE_DNSKEY 48
#define DNS_TYPE_NSEC3 50
#define DNS_TYPE_NSEC3PARAM 51
#define DNS_TYPE_TLSA 52
#define DNS_TYPE_DS 43      /* RFC 4034 §5 — delegation signer */
#define DNS_TYPE_CDS 59     /* RFC 7344 — child DS */
#define DNS_TYPE_CDNSKEY 60 /* RFC 7344 — child DNSKEY */
#define DNS_TYPE_URI 256    /* RFC 7553 */
#define DNS_TYPE_CAA 257
#define DNS_TYPE_IXFR 251 /* RFC 1995 — incremental zone transfer */
#define DNS_TYPE_AXFR 252 /* RFC 5936 — full zone transfer */
#define DNS_TYPE_ANY 255
#define DNS_TTL_MAX 2147483647u /* RFC 2181 §8 — 2^31-1 */

#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255
#define DNS_CLASS_NONE 254

#define DNS_QR 0x8000
#define DNS_AA 0x0400
#define DNS_TC 0x0200
#define DNS_RD 0x0100
#define DNS_AD 0x0020 /* RFC 4035 §3.1.6 — Authenticated Data */
#define DNS_OPCODE_QUERY 0x0000
#define DNS_OPCODE_NOTIFY 0x2000
#define DNS_OPCODE_UPDATE 0x2800
#define DNS_OPCODE_MASK 0x7800

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YXDOMAIN 6
#define DNS_RCODE_YXRRSET 7 /* RFC 2136: RRset should not exist but does */
#define DNS_RCODE_NXRRSET 8 /* RFC 2136: RRset should exist but does not */
#define DNS_RCODE_NOTZONE 10
#define DNS_RCODE_BADVERS 16
#define DNS_RCODE_BADSIG 17
#define DNS_RCODE_BADCOOKIE 23

/* EDNS option codes */
#define EDNS_OPT_NSID 3
#define EDNS_OPT_COOKIE 10
#define EDNS_OPT_KEEPALIVE 11
#define EDNS_OPT_PADDING 12
#define EDNS_OPT_EDE 15

/* Extended DNS Error info codes (RFC 8914) */
#define EDE_OTHER 0
#define EDE_DNSKEY_MISSING 1
#define EDE_RRSIG_MISSING 3
#define EDE_SIG_EXPIRED 5
#define EDE_SIG_NOT_YET 6
#define EDE_DNSKEY_MISSING2 7
#define EDE_SIG_INVALID 8
#define EDE_NXDOMAIN_NXZONE 12
#define EDE_BLOCKED 15
#define EDE_FILTERED 17
#define EDE_NOT_AUTH 18
#define EDE_NOT_SUPPORTED 19
#define EDE_NXDOMAIN 20
#define EDE_NO_REACHABLE 22

/* DNSSEC algorithm numbers */
#define DNS_ALG_ECDSAP256SHA256 13
#define DNS_ALG_ED25519 15
#define DNS_DNSKEY_FLAG_ZSK 256
#define DNS_DNSKEY_FLAG_KSK 257 /* Secure Entry Point — RFC 3757 */

/* DNSSEC signing keys are now per-zone (see zone_entry_t): ZSK signs RRsets,
 * KSK signs the DNSKEY RRset.  Loaded from dnssec:<zone>:* at startup. */

/* Forward declarations for helpers used before their definitions */
static void ixfr_journal_append(uint32_t, uint32_t, char, const char *, const char *);
static void notify_send(void);
/* Wire + Valkey helpers used by early code (multi-zone, NSEC) */
static int vk_set(const char *, const char *, uint32_t);
static int vk_get(const char *, char *, int);
static int emit_rr(uint8_t *, int, int, const char *, uint16_t, uint32_t, const uint8_t *, uint16_t,
                   int, int *);

/* NSEC3 hash algorithm */
#define NSEC3_ALG_SHA1 1

typedef struct {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((packed)) dns_hdr_t;

typedef struct {
    char name[256];
    uint16_t type;
    uint32_t ttl;
    char rdata_str[512];
    uint8_t rdata_a[4];
    uint16_t rdata_pref;
} dns_rec_t;

/* ==========================================================================
 * Multi-zone table (up to MAX_ZONES authoritative zones)
 *
 * Zone records remain keyed zone:TYPE:qname — the zone is selected by
 * longest-suffix match on qname against the zone table.
 *
 * Valkey key: zone_table:<zone_name>
 * Value:      mname|rname|serial|refresh|retry|expire|minimum|axfr_allow|notify_targets
 * ======================================================================= */
#define MAX_ZONES 16

typedef struct {
    char name[256];
    char soa_mname[256];
    char soa_rname[256];
    uint32_t soa_serial;
    uint32_t soa_refresh, soa_retry, soa_expire, soa_minimum;
    char axfr_allow[1024];
    char notify_targets[1024];
    /* Per-zone DNSSEC denial parameters (config:zone:<name>:*) */
    int nsec3_iters;
    char nsec3_salt[64];
    int dnssec_use_nsec3; /* 1 = NSEC3 (default), 0 = NSEC (plain) */
    /* Per-zone DNSSEC signing keys (dnssec:<name>:*). Guarded by g_zsk_mutex. */
    EVP_PKEY *zsk; /* ZSK P-256 */
    uint16_t zsk_tag;
    EVP_PKEY *zsk_ed; /* ZSK Ed25519 */
    uint16_t zsk_ed_tag;
    EVP_PKEY *ksk; /* KSK P-256 */
    uint16_t ksk_tag;
    EVP_PKEY *ksk_ed; /* KSK Ed25519 */
    uint16_t ksk_ed_tag;
    /* Per-zone ZSK rollover (RFC 6781 Pre-Publish). During a rollover the
     * incoming ZSK set is pre-published in the DNSKEY RRset; the signer switches
     * from the current to the incoming set only after the old DNSKEY has had
     * time to propagate, and the old key is removed only after old RRSIGs have
     * expired from caches — so a validator always has the key it needs. */
    EVP_PKEY *zsk_next; /* incoming ZSK P-256 (rollover only) */
    uint16_t zsk_next_tag;
    EVP_PKEY *zsk_ed_next; /* incoming ZSK Ed25519 (rollover only) */
    uint16_t zsk_ed_next_tag;
    int roll_phase;     /* ROLL_NONE / ROLL_PUBLISH / ROLL_COMMIT */
    time_t roll_since;  /* epoch the current phase was entered */
    time_t zsk_created; /* epoch the current ZSK set was created */
} zone_entry_t;

/* ZSK rollover phases (RFC 6781 §4.1.1.1 Pre-Publish). */
#define ROLL_NONE 0
#define ROLL_PUBLISH 1 /* publish current+next; keep signing with current */
#define ROLL_COMMIT 2  /* publish current+next; sign with next */

static zone_entry_t g_zones[MAX_ZONES];
static int g_zone_count = 0;
static pthread_mutex_t g_zones_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The authoritative zone selected for the request currently being handled by
 * this worker thread.  Set by the query / UPDATE / AXFR entry points before any
 * record emission, and read by the SOA / NSEC / signing helpers so they operate
 * on the matched zone's data and keys instead of a single global zone. */
static __thread zone_entry_t *t_zone = NULL;

/* Longest-suffix match of qname against the configured zones.
 * Returns the most specific zone that is equal to, or a parent of, qname. */
static zone_entry_t *zone_for_qname(const char *qname) {
    zone_entry_t *best = NULL;
    size_t best_len = 0;
    size_t ql = strlen(qname);
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count; i++) {
        zone_entry_t *z = &g_zones[i];
        size_t zl = strlen(z->name);
        if (zl == 0 || zl > ql)
            continue;
        int match = 0;
        if (zl == ql && strcasecmp(qname, z->name) == 0)
            match = 1;
        else if (ql > zl + 1 && qname[ql - zl - 1] == '.' &&
                 strcasecmp(qname + ql - zl, z->name) == 0)
            match = 1;
        if (match && zl > best_len) {
            best = z;
            best_len = zl;
        }
    }
    pthread_mutex_unlock(&g_zones_mutex);
    return best;
}

/* Build "zone:<zone>:<type>:<name>" for the current request's zone. */
static int zkey(char *buf, size_t sz, const char *type, const char *name) {
    const char *zn = t_zone ? t_zone->name : "";
    return snprintf(buf, sz, "zone:%s:%s:%s", zn, type, name);
}
/* Build "ddns:<zone>:<type>:<name>" for the current request's zone. */
static int dkey(char *buf, size_t sz, const char *type, const char *name) {
    const char *zn = t_zone ? t_zone->name : "";
    return snprintf(buf, sz, "ddns:%s:%s:%s", zn, type, name);
}

/* Add or update a zone. Returns its index or -1 on error. */
static int zone_upsert(const char *name, const char *mname, const char *rname, uint32_t serial,
                       uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum,
                       const char *axfr_allow, const char *notify_targets) {
    pthread_mutex_lock(&g_zones_mutex);
    int idx = -1;
    for (int i = 0; i < g_zone_count; i++)
        if (strcasecmp(g_zones[i].name, name) == 0) {
            idx = i;
            break;
        }
    if (idx < 0) {
        if (g_zone_count >= MAX_ZONES) {
            pthread_mutex_unlock(&g_zones_mutex);
            return -1;
        }
        idx = g_zone_count++;
    }
    zone_entry_t *z = &g_zones[idx];
    safe_strcpy(z->name, name, sizeof(z->name));
    safe_strcpy(z->soa_mname, mname && mname[0] ? mname : "", sizeof(z->soa_mname));
    safe_strcpy(z->soa_rname, rname && rname[0] ? rname : "", sizeof(z->soa_rname));
    z->soa_serial = serial;
    z->soa_refresh = refresh;
    z->soa_retry = retry;
    z->soa_expire = expire;
    z->soa_minimum = minimum;
    safe_strcpy(z->axfr_allow, axfr_allow ? axfr_allow : "127.0.0.1", sizeof(z->axfr_allow));
    safe_strcpy(z->notify_targets, notify_targets ? notify_targets : "", sizeof(z->notify_targets));
    pthread_mutex_unlock(&g_zones_mutex);
    return idx;
}

/* Load all zone_table:* keys from Valkey into the zone table */
/* zones_load_from_valkey — defined below after Valkey types */
static void zones_load_from_valkey(void);
/* Apply per-zone config (config:zone:<z>:*) and load DNSSEC keys for every zone
 * that does not yet have them.  Idempotent; safe to re-run on live reload. */
static void zones_post_load(void);
/* Seed/refresh the primary zone from the legacy global config:* values. */
static void seed_primary_zone(void);
/* Load per-zone ZSK rollover state (RFC 6781 Pre-Publish) from Valkey. */
static void zone_rollover_load(zone_entry_t *z);
/* Reload a zone's full DNSSEC key state live (current + rollover/next set). */
static void zone_dnssec_reload(zone_entry_t *z);

/* ==========================================================================
 * Runtime configuration
 * ======================================================================= */
static char g_valkey_host[256] = "127.0.0.1";
static int g_valkey_port = 6379;
static char g_valkey_pass[256] = "";
static int g_metrics_port = METRICS_PORT_DEFAULT;
static int g_dns_port = DNS_PORT_DEFAULT;
static int g_dot_port = DOT_PORT_DEFAULT;
static int g_http_port = HTTP_PORT_DEFAULT;
static int g_https_port = HTTPS_PORT_DEFAULT;
static char g_ddns_secret[256] = "changeme";
/* RRL configuration (rate limiting) */
static int g_rrl_enabled = 0;
static int g_rrl_rate = 5;   /* max responses/window */
static int g_rrl_window = 1; /* window in seconds */
static int g_rrl_slip = 2;   /* send TC every slip-th excess response */

/* Structured query log */
static char g_query_log_path[512] = ""; /* "" = disabled */
static FILE *g_query_log_fp = NULL;
static pthread_mutex_t g_qlog_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Write one JSON-line query log entry.
 * Format: {"ts":<unix>,"client":"<ip>","qname":"<n>","qtype":"<t>",
 *           "rcode":<r>,"answers":<n>,"rtt_us":<t>,"transport":"<udp|tcp|dot|doh>"}
 */
static const char *type2str(uint16_t t); /* forward decl for qlog_write */
static void qlog_write(const char *client_ip, const char *qname, uint16_t qtype, uint8_t rcode,
                       int answers, long rtt_us, const char *transport) {
    if (!g_query_log_fp && !g_query_log_path[0])
        return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char line[512];
    snprintf(line, sizeof(line),
             "{\"ts\":%ld,\"client\":\"%s\",\"qname\":\"%s\",\"qtype\":\"%s\""
             ",\"rcode\":%u,\"answers\":%d,\"rtt_us\":%ld,\"transport\":\"%s\"}\n",
             (long) ts.tv_sec, client_ip, qname, type2str(qtype), (unsigned) rcode, answers, rtt_us,
             transport);
    pthread_mutex_lock(&g_qlog_mutex);
    FILE *fp = g_query_log_fp ? g_query_log_fp : stderr;
    fputs(line, fp);
    fflush(fp);
    pthread_mutex_unlock(&g_qlog_mutex);
}

static void qlog_open(void) {
    pthread_mutex_lock(&g_qlog_mutex);
    if (g_query_log_fp) {
        fclose(g_query_log_fp);
        g_query_log_fp = NULL;
    }
    if (g_query_log_path[0] && strcmp(g_query_log_path, "stderr") != 0)
        g_query_log_fp = fopen(g_query_log_path, "a");
    pthread_mutex_unlock(&g_qlog_mutex);
}

/* mDNS state */

static char g_tls_cert_pem[MAX_PEM] = "";
static char g_tls_key_pem[MAX_PEM] = "";
static char g_mtls_ca_pem[MAX_PEM] = "";

/* SOA parameters */
static char g_soa_mname[256] = "ns1.example.local";
static char g_soa_rname[256] = "hostmaster.example.local";
static uint32_t g_soa_refresh = 3600;
static uint32_t g_soa_retry = 900;
static uint32_t g_soa_expire = 604800;
static uint32_t g_soa_minimum = 300;
static uint32_t g_soa_serial = 1;
static char g_zone_name[256] = "example.local";

/* TSIG */
static char g_tsig_key_name[256] = "tsig-key";
static uint8_t g_tsig_secret[64] = {0};
static int g_tsig_secret_len = 0;

/* NSID */
static char g_nsid[256] = "";

/* ==========================================================================
 * Syslog configuration
 * Syslog configuration — all keys under config:syslog_*
 *
 * Local syslog (system logger):
 *   config:syslog_enabled    "1" / "0"                       (default: 0)
 *   config:syslog_facility   "daemon","local0".."local7",...  (default: daemon)
 *   config:syslog_level      "debug","info","notice","warning","err","crit"
 *                             Messages at this level AND MORE SEVERE are sent.
 *                             (default: info)
 *   config:syslog_ident      Program identity string          (default: dns_server)
 *
 * Remote syslog (direct TCP/UDP/TLS to a remote server):
 *   config:syslog_remote_host     IP or hostname of remote syslog server
 *   config:syslog_remote_port     Port (default: 514 UDP/TCP, 6514 TLS)
 *   config:syslog_remote_proto    "udp" | "tcp" | "tls"      (default: udp)
 *   config:syslog_remote_level    Same scale as syslog_level  (default: info)
 *   config:syslog_remote_tls_verify  "1" to verify server cert (default: 1)
 *   config:syslog_remote_format   "rfc5424" | "rfc3164"       (default: rfc5424)
 *
 * Wire formats:
 *   RFC 5424 (default): <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID - - MSG
 *   RFC 3164 (legacy) : <PRI>TIMESTAMP HOSTNAME APP-NAME[PID]: MSG
 *
 * TCP framing (RFC 6587): octet-count framing — "<len> <message>"
 * TLS framing: same as TCP, over OpenSSL connection.
 * UDP framing: one datagram per message, no framing prefix.
 *
 * Auto-reconnect: TCP/TLS connections are re-established transparently on
 * failure. UDP is connectionless and re-creates the socket as needed.
 * All remote sends are non-blocking (SO_SNDTIMEO = 2s) so a dead syslog
 * server never stalls DNS query processing.
 * ======================================================================= */

/* ── Local syslog state ─────────────────────────────────────────────────── */
static int g_syslog_enabled = 0;
static int g_syslog_facility = LOG_DAEMON;
static int g_syslog_level = LOG_INFO;
static char g_syslog_ident[64] = "dns_server";

/* ── Remote syslog state ────────────────────────────────────────────────── */
typedef enum { RSYSLOG_UDP = 0, RSYSLOG_TCP, RSYSLOG_TLS } rsyslog_proto_t;
typedef enum { RFMT_RFC5424 = 0, RFMT_RFC3164 } rsyslog_fmt_t;

static char g_rsyslog_host[256] = "";
static int g_rsyslog_port = 0; /* 0 = disabled */
static rsyslog_proto_t g_rsyslog_proto = RSYSLOG_UDP;
static rsyslog_fmt_t g_rsyslog_fmt = RFMT_RFC5424;
static int g_rsyslog_level = LOG_INFO;
static int g_rsyslog_tls_verify = 1;
static int g_rsyslog_fd = -1; /* socket or -1 */
static SSL *g_rsyslog_ssl = NULL;
static SSL_CTX *g_rsyslog_ssl_ctx = NULL;
static char g_rsyslog_hostname[256] = ""; /* local hostname */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pid_t g_log_pid = 0;

/* ── Level / facility helpers ───────────────────────────────────────────── */
static int syslog_facility_from_str(const char *s) {
    if (!strcasecmp(s, "kern"))
        return LOG_KERN;
    if (!strcasecmp(s, "user"))
        return LOG_USER;
    if (!strcasecmp(s, "mail"))
        return LOG_MAIL;
    if (!strcasecmp(s, "daemon"))
        return LOG_DAEMON;
    if (!strcasecmp(s, "auth"))
        return LOG_AUTH;
    if (!strcasecmp(s, "lpr"))
        return LOG_LPR;
    if (!strcasecmp(s, "news"))
        return LOG_NEWS;
    if (!strcasecmp(s, "uucp"))
        return LOG_UUCP;
    if (!strcasecmp(s, "cron"))
        return LOG_CRON;
    if (!strcasecmp(s, "local0"))
        return LOG_LOCAL0;
    if (!strcasecmp(s, "local1"))
        return LOG_LOCAL1;
    if (!strcasecmp(s, "local2"))
        return LOG_LOCAL2;
    if (!strcasecmp(s, "local3"))
        return LOG_LOCAL3;
    if (!strcasecmp(s, "local4"))
        return LOG_LOCAL4;
    if (!strcasecmp(s, "local5"))
        return LOG_LOCAL5;
    if (!strcasecmp(s, "local6"))
        return LOG_LOCAL6;
    if (!strcasecmp(s, "local7"))
        return LOG_LOCAL7;
    return LOG_DAEMON;
}
static int syslog_level_from_str(const char *s) {
    if (!strcasecmp(s, "debug"))
        return LOG_DEBUG;
    if (!strcasecmp(s, "info"))
        return LOG_INFO;
    if (!strcasecmp(s, "notice"))
        return LOG_NOTICE;
    if (!strcasecmp(s, "warning") || !strcasecmp(s, "warn"))
        return LOG_WARNING;
    if (!strcasecmp(s, "err") || !strcasecmp(s, "error"))
        return LOG_ERR;
    if (!strcasecmp(s, "crit"))
        return LOG_CRIT;
    return LOG_INFO;
}
static const char *syslog_level_str(int level) {
    switch (level) {
        case LOG_DEBUG:
            return "DEBUG";
        case LOG_INFO:
            return "INFO";
        case LOG_NOTICE:
            return "NOTICE";
        case LOG_WARNING:
            return "WARN";
        case LOG_ERR:
            return "ERROR";
        case LOG_CRIT:
            return "CRIT";
        default:
            return "INFO";
    }
}
/* RFC 5424 severity integer (0–7) */
static int pri_severity(int level) {
    switch (level) {
        case LOG_EMERG:
            return 0;
        case LOG_ALERT:
            return 1;
        case LOG_CRIT:
            return 2;
        case LOG_ERR:
            return 3;
        case LOG_WARNING:
            return 4;
        case LOG_NOTICE:
            return 5;
        case LOG_INFO:
            return 6;
        case LOG_DEBUG:
            return 7;
        default:
            return 6;
    }
}

/* ── Remote syslog: connect / disconnect ────────────────────────────────── */

/* Close any existing remote connection */
static void rsyslog_disconnect(void) {
    if (g_rsyslog_ssl) {
        SSL_shutdown(g_rsyslog_ssl);
        SSL_free(g_rsyslog_ssl);
        g_rsyslog_ssl = NULL;
    }
    if (g_rsyslog_ssl_ctx) {
        SSL_CTX_free(g_rsyslog_ssl_ctx);
        g_rsyslog_ssl_ctx = NULL;
    }
    if (g_rsyslog_fd >= 0) {
        close(g_rsyslog_fd);
        g_rsyslog_fd = -1;
    }
}

/*
 * Establish connection to remote syslog server.
 * Called with g_log_mutex HELD.
 * Returns 0 on success, -1 on failure.
 */
static int rsyslog_connect(void) {
    rsyslog_disconnect();
    if (!g_rsyslog_host[0] || g_rsyslog_port <= 0)
        return -1;

    /* Resolve host */
    struct addrinfo hints = {0}, *res = NULL;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", g_rsyslog_port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = (g_rsyslog_proto == RSYSLOG_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    if (getaddrinfo(g_rsyslog_host, portstr, &hints, &res) != 0 || !res)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* Non-blocking send timeout: 2 seconds */
    struct timeval tv = {.tv_sec = 2};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (g_rsyslog_proto == RSYSLOG_UDP) {
        /* UDP: connect() so we can use send() instead of sendto() */
        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        g_rsyslog_fd = fd;
        freeaddrinfo(res);
        return 0;
    }

    /* TCP / TLS: connect */
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    if (g_rsyslog_proto == RSYSLOG_TCP) {
        g_rsyslog_fd = fd;
        return 0;
    }

    /* TLS */
    g_rsyslog_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_rsyslog_ssl_ctx) {
        close(fd);
        return -1;
    }
    SSL_CTX_set_min_proto_version(g_rsyslog_ssl_ctx, TLS1_2_VERSION);
    if (g_rsyslog_tls_verify) {
        SSL_CTX_set_verify(g_rsyslog_ssl_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(g_rsyslog_ssl_ctx);
    } else {
        SSL_CTX_set_verify(g_rsyslog_ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    g_rsyslog_ssl = SSL_new(g_rsyslog_ssl_ctx);
    if (!g_rsyslog_ssl) {
        SSL_CTX_free(g_rsyslog_ssl_ctx);
        g_rsyslog_ssl_ctx = NULL;
        close(fd);
        return -1;
    }
    SSL_set_fd(g_rsyslog_ssl, fd);
    SSL_set_tlsext_host_name(g_rsyslog_ssl, g_rsyslog_host);

    if (SSL_connect(g_rsyslog_ssl) <= 0) {
        SSL_free(g_rsyslog_ssl);
        g_rsyslog_ssl = NULL;
        SSL_CTX_free(g_rsyslog_ssl_ctx);
        g_rsyslog_ssl_ctx = NULL;
        close(fd);
        return -1;
    }
    g_rsyslog_fd = fd;
    return 0;
}

/*
 * Build an RFC 5424 or RFC 3164 syslog message into buf.
 * Returns the message length (not NUL-terminated beyond that).
 */
static int rsyslog_format(char *buf, int bufsz, int priority, const char *msg) {
    int pri = (g_syslog_facility & ~7) | pri_severity(priority);
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);

    if (g_rsyslog_fmt == RFMT_RFC5424) {
        /* <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG */
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        return snprintf(buf, bufsz, "<%d>1 %s %s %s %d - - %s", pri, ts,
                        g_rsyslog_hostname[0] ? g_rsyslog_hostname : "-", g_syslog_ident,
                        (int) g_log_pid, msg);
    } else {
        /* RFC 3164: <PRI>Mmm DD HH:MM:SS HOSTNAME APP-NAME[PID]: MSG */
        char ts[20];
        strftime(ts, sizeof(ts), "%b %e %H:%M:%S", &tm_buf);
        return snprintf(buf, bufsz, "<%d>%s %s %s[%d]: %s", pri, ts,
                        g_rsyslog_hostname[0] ? g_rsyslog_hostname : "localhost", g_syslog_ident,
                        (int) g_log_pid, msg);
    }
}

/*
 * Send one pre-formatted message to the remote syslog server.
 * Called with g_log_mutex HELD.
 * Attempts one reconnect on failure.
 */
static void rsyslog_send_raw(const char *msg, int msglen) {
    if (msglen <= 0)
        return;
    if (g_rsyslog_fd < 0) {
        if (rsyslog_connect() < 0)
            return;
    }

    int ok = 0;
    if (g_rsyslog_proto == RSYSLOG_UDP) {
        ok = (send(g_rsyslog_fd, msg, msglen, MSG_NOSIGNAL) == msglen);
    } else {
        /* RFC 6587 octet-counting: "<len> <message>" */
        char frame[8192 + 16];
        int flen = snprintf(frame, sizeof(frame), "%d ", msglen);
        if (flen + msglen < (int) sizeof(frame)) {
            memcpy(frame + flen, msg, msglen);
            flen += msglen;
            if (g_rsyslog_ssl)
                ok = (SSL_write(g_rsyslog_ssl, frame, flen) == flen);
            else
                ok = (send(g_rsyslog_fd, frame, flen, MSG_NOSIGNAL) == flen);
        }
    }

    if (!ok) {
        /* Connection broken — close and try once to reconnect */
        rsyslog_disconnect();
        if (rsyslog_connect() < 0)
            return;
        /* Retry send after reconnect */
        if (g_rsyslog_proto == RSYSLOG_UDP) {
            send(g_rsyslog_fd, msg, msglen, MSG_NOSIGNAL);
        } else {
            char frame[8192 + 16];
            int flen = snprintf(frame, sizeof(frame), "%d ", msglen);
            if (flen + msglen < (int) sizeof(frame)) {
                memcpy(frame + flen, msg, msglen);
                flen += msglen;
                if (g_rsyslog_ssl)
                    SSL_write(g_rsyslog_ssl, frame, flen);
                else
                    send(g_rsyslog_fd, frame, flen, MSG_NOSIGNAL);
            }
        }
    }
}

/* ── Central log function ───────────────────────────────────────────────── */

/*
 * dns_log() — unified logging.
 *
 * Destinations (each independently filtered by their configured level):
 *   1. stdout/stderr — always, with ISO-8601 timestamp + level tag
 *   2. Local syslog  — when config:syslog_enabled = 1
 *   3. Remote syslog — when config:syslog_remote_host is set
 *
 * Priority values are standard LOG_* constants (syslog.h).
 * Lower numeric value = more severe (LOG_ERR=3 < LOG_INFO=6).
 * A message is sent to a destination when:  priority <= configured_level
 *
 * Usage:
 *   dns_log(LOG_INFO,    "[DNS ] %s  %s %s\n", cip, type2str(qt), qn);
 *   dns_log(LOG_WARNING, "[TSIG] verify failed from %s\n", cip);
 *   dns_log(LOG_ERR,     "[TLS] SSL_accept error %d\n", err);
 */
static void dns_log(int priority, const char *fmt, ...) {
    va_list ap;
    char msg[4096];

    /* Format the message body once */
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Strip trailing newline for syslog (we add it back for stdout) */
    int mlen = (int) strlen(msg);
    if (mlen > 0 && msg[mlen - 1] == '\n')
        msg[mlen - 1] = '\0';

    pthread_mutex_lock(&g_log_mutex);

    /* ── 1. stdout / stderr with ISO-8601 timestamp ── */
    {
        time_t now = time(NULL);
        struct tm tm_buf;
        char ts[32];
        localtime_r(&now, &tm_buf);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);
        FILE *out = (priority <= LOG_WARNING) ? stderr : stdout;
        fprintf(out, "%s [%-6s] %s\n", ts, syslog_level_str(priority), msg);
        fflush(out);
    }

    /* ── 2. Local syslog ── */
    if (g_syslog_enabled && priority <= g_syslog_level)
        syslog(priority, "%s", msg);

    /* ── 3. Remote syslog ── */
    if (g_rsyslog_port > 0 && priority <= g_rsyslog_level) {
        char pkt[4096];
        int plen = rsyslog_format(pkt, sizeof(pkt), priority, msg);
        if (plen > 0 && plen < (int) sizeof(pkt))
            rsyslog_send_raw(pkt, plen);
    }

    pthread_mutex_unlock(&g_log_mutex);
}

/* ── (Re-)initialise local and remote syslog ────────────────────────────── */
static void syslog_init(void) {
    /* Local syslog */
    closelog();
    if (g_syslog_enabled) {
        openlog(g_syslog_ident, LOG_PID | LOG_NDELAY, g_syslog_facility);
    }

    /* Remote syslog: reconnect whenever settings change */
    /* Hold the mutex to safely touch g_rsyslog_fd / g_rsyslog_ssl */
    pthread_mutex_lock(&g_log_mutex);
    rsyslog_disconnect();
    if (g_rsyslog_port > 0 && g_rsyslog_host[0]) {
        const char *proto_str = g_rsyslog_proto == RSYSLOG_TLS   ? "tls"
                                : g_rsyslog_proto == RSYSLOG_TCP ? "tcp"
                                                                 : "udp";
        /* Connect outside the lock would deadlock via dns_log; use direct fprintf */
        fprintf(stdout, "[Log ] Remote syslog: %s://%s:%d  level=%s  fmt=%s\n", proto_str,
                g_rsyslog_host, g_rsyslog_port, syslog_level_str(g_rsyslog_level),
                g_rsyslog_fmt == RFMT_RFC5424 ? "RFC5424" : "RFC3164");
        rsyslog_connect(); /* best-effort; retried on first log message */
    }
    pthread_mutex_unlock(&g_log_mutex);

    dns_log(LOG_NOTICE, "[Log ] Logging initialised: local_syslog=%s remote=%s:%d\n",
            g_syslog_enabled ? "on" : "off", g_rsyslog_host[0] ? g_rsyslog_host : "(disabled)",
            g_rsyslog_port);
}

/* DNS Cookies */
static uint8_t g_cookie_secret[16] = {0};

/* AXFR / NOTIFY */
static char g_axfr_allow[1024] = "127.0.0.1";
static char g_notify_targets[1024] = "";

/* NSEC3 params */
static int g_nsec3_iters = 1;
static char g_nsec3_salt[64] = "";
static int g_dnssec_use_nsec3 = 1; /* 1=NSEC3 (default), 0=NSEC (plain) */

/* TLS contexts */
static SSL_CTX *g_dot_ctx = NULL;

/* DNSSEC signing keys live per-zone in zone_entry_t (loaded from dnssec:<zone>:*). */

/* ACME state */

/* Mutexes */
static pthread_mutex_t g_vk_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_zsk_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_tls_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_soa_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Query statistics (Prometheus) */
static uint64_t g_stat_queries = 0;  /* total queries received */
static uint64_t g_stat_noerror = 0;  /* NOERROR responses */
static uint64_t g_stat_nxdomain = 0; /* NXDOMAIN responses */
static uint64_t g_stat_refused = 0;  /* REFUSED (out-of-zone) */
static uint64_t g_stat_servfail = 0; /* SERVFAIL responses */
static uint64_t g_stat_rrl_drop = 0; /* RRL: dropped */
static uint64_t g_stat_rrl_tc = 0;   /* RRL: truncated */
static uint64_t g_stat_axfr = 0;     /* AXFR transfers completed */
static uint64_t g_stat_ddns = 0;     /* DDNS updates accepted */
static uint64_t g_stat_signed = 0;   /* RRSIGs generated */
static pthread_mutex_t g_stat_mutex = PTHREAD_MUTEX_INITIALIZER;
#define STAT_INC(c)                                                                                \
    do {                                                                                           \
        pthread_mutex_lock(&g_stat_mutex);                                                         \
        (c)++;                                                                                     \
        pthread_mutex_unlock(&g_stat_mutex);                                                       \
    } while (0)

/* ==========================================================================
 * Static zone (compiled-in)
 * ======================================================================= */
static dns_rec_t static_zone[] = {
    {"example.local", DNS_TYPE_A, 300, "", {192, 168, 1, 10}},
    {"www.example.local", DNS_TYPE_A, 300, "", {192, 168, 1, 10}},
    {"mail.example.local", DNS_TYPE_A, 300, "", {192, 168, 1, 20}},
    {"example.local", DNS_TYPE_AAAA, 300, "2001:db8::1"},
    {"example.local", DNS_TYPE_MX, 300, "mail.example.local", {0}, 10},
    {"example.local", DNS_TYPE_NS, 300, "ns1.example.local"},
    {"example.local", DNS_TYPE_TXT, 300, "v=spf1 mx ~all"},
};
static const int static_zone_sz = (int) (sizeof(static_zone) / sizeof(static_zone[0]));

/* ==========================================================================
 * RFC 6303 — Locally Served DNS Zones
 * For these zones the server answers authoritatively with SOA+NS rather
 * than forwarding.  PTR queries that fall inside these prefixes get a
 * synthesised NXDOMAIN with SOA so resolvers cache the negative answer.
 * ======================================================================= */
static const char *g_local_zones[] = {
    "localhost",
    "127.in-addr.arpa",
    "0.in-addr.arpa",
    "255.in-addr.arpa",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", /* ::1 */
    "d.f.ip6.arpa",                                                             /* fc00::/7  ULA  */
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa", /* fe80::/10 LL   */
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
    "home.arpa",
    NULL};

/* Returns 1 if qname is exactly one of the locally served zones or
 * is a subdomain of one (e.g. "1.0.0.127.in-addr.arpa"). */
static int is_local_zone(const char *qname) {
    char lq[256];
    safe_strcpy(lq, qname, sizeof(lq));
    strlower(lq);
    for (int i = 0; g_local_zones[i]; i++) {
        const char *z = g_local_zones[i];
        size_t zl = strlen(z), ql = strlen(lq);
        if (ql == zl && strcmp(lq, z) == 0)
            return 1;
        if (ql > zl + 1 && lq[ql - zl - 1] == '.' && strcmp(lq + ql - zl, z) == 0)
            return 1;
    }
    return 0;
}

/* ==========================================================================
 * Utility helpers
 * ======================================================================= */
static int streq_ci(const char *a, const char *b) {
    return strcasecmp(a, b) == 0;
}
static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}
/* RFC 2181 §8: TTL values MUST be clamped to [0, 2^31-1]. */
static uint32_t ttl_clamp(uint32_t ttl) {
    return ttl > DNS_TTL_MAX ? DNS_TTL_MAX : ttl;
}

/* hex encode/decode */

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
static void sha1(const uint8_t *in, int n, uint8_t out[20]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return;
    unsigned int dl = 20;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, out, &dl);
    EVP_MD_CTX_free(ctx);
}

/* ==========================================================================
 * SipHash-2-4 for DNS Cookies (RFC 9018)
 * ======================================================================= */
#define SIPHASH_ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIPHASH_SIPROUND(v0, v1, v2, v3)                                                           \
    v0 += v1;                                                                                      \
    v1 = SIPHASH_ROTL(v1, 13);                                                                     \
    v1 ^= v0;                                                                                      \
    v0 = SIPHASH_ROTL(v0, 32);                                                                     \
    v2 += v3;                                                                                      \
    v3 = SIPHASH_ROTL(v3, 16);                                                                     \
    v3 ^= v2;                                                                                      \
    v0 += v3;                                                                                      \
    v3 = SIPHASH_ROTL(v3, 21);                                                                     \
    v3 ^= v0;                                                                                      \
    v2 += v1;                                                                                      \
    v1 = SIPHASH_ROTL(v1, 17);                                                                     \
    v1 ^= v2;                                                                                      \
    v2 = SIPHASH_ROTL(v2, 32);

static uint64_t siphash24(const uint8_t *in, int inlen, const uint8_t key[16]) {
    uint64_t k0 = ((uint64_t) key[0]) | ((uint64_t) key[1] << 8) | ((uint64_t) key[2] << 16) |
                  ((uint64_t) key[3] << 24) | ((uint64_t) key[4] << 32) |
                  ((uint64_t) key[5] << 40) | ((uint64_t) key[6] << 48) | ((uint64_t) key[7] << 56);
    uint64_t k1 = ((uint64_t) key[8]) | ((uint64_t) key[9] << 8) | ((uint64_t) key[10] << 16) |
                  ((uint64_t) key[11] << 24) | ((uint64_t) key[12] << 32) |
                  ((uint64_t) key[13] << 40) | ((uint64_t) key[14] << 48) |
                  ((uint64_t) key[15] << 56);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL, v1 = k1 ^ 0x646f72616e646f6dULL,
             v2 = k0 ^ 0x6c7967656e657261ULL, v3 = k1 ^ 0x7465646279746573ULL;
    int i;
    for (i = 0; i + 7 < inlen; i += 8) {
        uint64_t m = ((uint64_t) in[i]) | ((uint64_t) in[i + 1] << 8) |
                     ((uint64_t) in[i + 2] << 16) | ((uint64_t) in[i + 3] << 24) |
                     ((uint64_t) in[i + 4] << 32) | ((uint64_t) in[i + 5] << 40) |
                     ((uint64_t) in[i + 6] << 48) | ((uint64_t) in[i + 7] << 56);
        v3 ^= m;
        SIPHASH_SIPROUND(v0, v1, v2, v3);
        SIPHASH_SIPROUND(v0, v1, v2, v3);
        v0 ^= m;
    }
    uint64_t last = (uint64_t) (inlen & 0xFF) << 56;
    int rem = inlen - i;
    switch (rem) {
        case 7:
            last |= ((uint64_t) in[i + 6] << 48); /* fall */
        case 6:
            last |= ((uint64_t) in[i + 5] << 40); /* fall */
        case 5:
            last |= ((uint64_t) in[i + 4] << 32); /* fall */
        case 4:
            last |= ((uint64_t) in[i + 3] << 24); /* fall */
        case 3:
            last |= ((uint64_t) in[i + 2] << 16); /* fall */
        case 2:
            last |= ((uint64_t) in[i + 1] << 8); /* fall */
        case 1:
            last |= ((uint64_t) in[i]);
            break;
        default:
            break;
    }
    v3 ^= last;
    SIPHASH_SIPROUND(v0, v1, v2, v3);
    SIPHASH_SIPROUND(v0, v1, v2, v3);
    v0 ^= last;
    v2 ^= 0xFF;
    SIPHASH_SIPROUND(v0, v1, v2, v3);
    SIPHASH_SIPROUND(v0, v1, v2, v3);
    SIPHASH_SIPROUND(v0, v1, v2, v3);
    SIPHASH_SIPROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* RFC 9018 §4.2: 16-byte server cookie = version(1) | reserved(3) |
 * timestamp(4) | hash(8). The hash is SipHash-2-4 over
 *   client_cookie(8) || version+reserved+timestamp(8) || client_ip(4)
 * keyed with the server's secret. Timestamp = Unix seconds; cookies are
 * accepted up to DNS_COOKIE_VALIDITY seconds old. */
static void compute_server_cookie(const uint8_t *ccookie, const struct in_addr *cip,
                                  uint32_t timestamp, uint8_t out[DNS_COOKIE_SERVER_LEN]) {
    out[0] = 1;                   /* version */
    out[1] = out[2] = out[3] = 0; /* reserved */
    out[4] = (timestamp >> 24) & 0xFF;
    out[5] = (timestamp >> 16) & 0xFF;
    out[6] = (timestamp >> 8) & 0xFF;
    out[7] = timestamp & 0xFF;
    uint8_t hin[8 + 8 + 4];
    memcpy(hin, ccookie, 8);
    memcpy(hin + 8, out, 8);
    memcpy(hin + 16, &cip->s_addr, 4);
    uint64_t h = siphash24(hin, sizeof(hin), g_cookie_secret);
    memcpy(out + 8, &h, 8);
}

/* ==========================================================================
 * RESP / Valkey client (RFC 1459 RESP)
 * ======================================================================= */
typedef struct {
    int fd;
    char rbuf[RESP_BUF];
    int rlen, rpos;
} resp_conn_t;
static resp_conn_t vk;

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
            /* clamp bl so we never write past r->str */
            int take = bl < (int) sizeof(r->str) - 1 ? bl : (int) sizeof(r->str) - 1;
            if (resp_readbytes(c, r->str, take) < 0)
                return -1;
            /* if the server sent more bytes than we want, drain the remainder */
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
/* Send a command but do NOT read a reply — for (P)SUBSCRIBE, whose multi-bulk
 * replies and subsequent messages are consumed by the subscriber read loop
 * (resp_cmd would read only the array header and desync the stream). */
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

static int valkey_connect_to(resp_conn_t *c, const char *host, int port, const char *pass) {
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
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        struct addrinfo hints = {0}, *res;
        char ps[8];
        snprintf(ps, sizeof(ps), "%d", port);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, ps, &hints, &res) != 0) {
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
    if (pass && pass[0]) {
        if (resp_cmd(c, &r, 2, "AUTH", pass) < 0 || r.type == 1) {
            close(c->fd);
            c->fd = -1;
            return -1;
        }
    }
    resp_cmd(c, &r, 2, "SELECT", "0");
    return 0;
}
static int valkey_connect(resp_conn_t *c) {
    return valkey_connect_to(c, g_valkey_host, g_valkey_port, g_valkey_pass);
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
    int connected = (valkey_ensure(&vk) >= 0);
    if (!connected) {
        /* Valkey unreachable — try RFC 8767 stale shadow key */
        pthread_mutex_unlock(&g_vk_mutex);
        char skey[640];
        snprintf(skey, sizeof(skey), "stale:%s", key);
        pthread_mutex_lock(&g_vk_mutex);
        if (valkey_ensure(&vk) >= 0) {
            resp_reply_t rs;
            if (resp_cmd(&vk, &rs, 2, "GET", skey) >= 0 && rs.type == 2) {
                safe_strcpy(out, rs.str, olen);
                pthread_mutex_unlock(&g_vk_mutex);
                dns_log(LOG_DEBUG, "[RFC8767] Serving stale data for %s\n", key);
                return 1;
            }
        }
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
    /* Write stale shadow key: 7-day TTL — used when Valkey is unreachable */
    {
        char skey[640];
        snprintf(skey, sizeof(skey), "stale:%s", key);
        pthread_mutex_lock(&g_vk_mutex);
        if (valkey_ensure(&vk) >= 0) {
            char ts[16];
            snprintf(ts, sizeof(ts), "%u", 7u * 86400);
            resp_reply_t sw;
            resp_cmd(&vk, &sw, 5, "SET", skey, out, "EX", ts);
        }
        pthread_mutex_unlock(&g_vk_mutex);
    }
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
static long vk_ttl(const char *key) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "TTL", key) < 0) {
        vk.fd = -1;
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return r.type == 3 ? r.integer : -1;
}

/* Load all zone_table:* keys from Valkey into the zone table.
 * Uses inline KEYS scan (no vk_keys_scan wrapper needed). */
static void zones_load_from_valkey(void) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return;
    }
    resp_reply_t r;
    resp_cmd(&vk, &r, 2, "KEYS", "zone_table:*");
    if (r.type != 5) {
        pthread_mutex_unlock(&g_vk_mutex);
        return;
    }
    int count = r.count;
    /* Collect key names first (KEYS returns an array) */
    char zkeys[MAX_ZONES][512];
    int nk = 0;
    for (int i = 0; i < count; i++) {
        resp_reply_t kr;
        if (resp_parse(&vk, &kr) < 0)
            break;
        if (kr.type == 2 && nk < MAX_ZONES) {
            safe_strcpy(zkeys[nk], kr.str, sizeof(zkeys[nk]));
            nk++;
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    /* Now fetch each zone entry */
    for (int i = 0; i < nk; i++) {
        const char *zname = zkeys[i] + 11; /* skip "zone_table:" */
        char val[2048] = "";
        if (!vk_get(zkeys[i], val, sizeof(val)))
            continue;
        char buf[2048];
        safe_strcpy(buf, val, sizeof(buf));
        char *f[9] = {0};
        char *p = buf;
        int fi = 0;
        while (fi < 9) {
            f[fi++] = p;
            char *n = strchr(p, '|');
            if (!n)
                break;
            *n = 0;
            p = n + 1;
        }
        zone_upsert(zname, f[0] ? f[0] : "", f[1] ? f[1] : "", f[2] ? (uint32_t) atoi(f[2]) : 1,
                    f[3] ? (uint32_t) atoi(f[3]) : 3600, f[4] ? (uint32_t) atoi(f[4]) : 900,
                    f[5] ? (uint32_t) atoi(f[5]) : 604800, f[6] ? (uint32_t) atoi(f[6]) : 300,
                    f[7] ? f[7] : NULL, f[8] ? f[8] : NULL);
    }
}
/* Atomically increment and return new integer value */
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

/* ==========================================================================
 * Boot file
 * ======================================================================= */
static void boot_load(void) {
    safe_strcpy(g_valkey_host, cfgenv("DNS_VALKEY_HOST", "127.0.0.1"), sizeof(g_valkey_host));
    g_valkey_port = atoi(cfgenv("DNS_VALKEY_PORT", "6379"));
    safe_strcpy(g_valkey_pass, cfgenv("DNS_VALKEY_PASSWORD", ""), sizeof(g_valkey_pass));
    g_metrics_port = atoi(cfgenv("METRICS_PORT", "8054"));
    FILE *f = fopen(BOOT_FILE, "r");
    if (!f)
        return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        if (!strcmp(k, "VALKEY_HOST"))
            safe_strcpy(g_valkey_host, v, sizeof(g_valkey_host));
        else if (!strcmp(k, "VALKEY_PORT"))
            g_valkey_port = atoi(v);
        else if (!strcmp(k, "VALKEY_PASSWORD"))
            safe_strcpy(g_valkey_pass, v, sizeof(g_valkey_pass));
    }
    fclose(f);
}

/* ==========================================================================
 * Config: load all settings from Valkey
 * ======================================================================= */
static void config_load_from_valkey(void) {
    char val[MAX_PEM];
#define G(k, d)                                                                                    \
    do {                                                                                           \
        if (vk_get("config:" k, val, sizeof(val)) && val[0])                                       \
            safe_strcpy(d, val, sizeof(d));                                                        \
    } while (0)
#define GI(k, d)                                                                                   \
    do {                                                                                           \
        if (vk_get("config:" k, val, sizeof(val)) && val[0])                                       \
            d = atoi(val);                                                                         \
    } while (0)
#define GU(k, d)                                                                                   \
    do {                                                                                           \
        if (vk_get("config:" k, val, sizeof(val)) && val[0])                                       \
            d = (uint32_t) atol(val);                                                              \
    } while (0)
    G("ddns_secret", g_ddns_secret);
    GI("dns_port", g_dns_port);
    GI("dot_port", g_dot_port);
    GI("http_port", g_http_port);
    GI("https_port", g_https_port);
    GI("metrics_port", g_metrics_port);
    G("soa_mname", g_soa_mname);
    G("soa_rname", g_soa_rname);
    GU("soa_refresh", g_soa_refresh);
    GU("soa_retry", g_soa_retry);
    GU("soa_expire", g_soa_expire);
    GU("soa_minimum", g_soa_minimum);
    GU("zone_serial", g_soa_serial);
    G("tsig_key_name", g_tsig_key_name);
    G("nsid", g_nsid);
    G("axfr_allow", g_axfr_allow);
    G("notify_targets", g_notify_targets);
    G("zone_name", g_zone_name);
    /* Query log */
    {
        char qlpath[512];
        if (vk_get("config:query_log_path", qlpath, sizeof(qlpath)) && qlpath[0]) {
            safe_strcpy(g_query_log_path, qlpath, sizeof(g_query_log_path));
            qlog_open();
        }
    }
    /* RRL */
    {
        char rrl_val[16];
        if (vk_get("config:rrl_enabled", rrl_val, sizeof(rrl_val)))
            g_rrl_enabled = atoi(rrl_val);
        if (vk_get("config:rrl_rate", rrl_val, sizeof(rrl_val)))
            g_rrl_rate = atoi(rrl_val);
        if (vk_get("config:rrl_window", rrl_val, sizeof(rrl_val)))
            g_rrl_window = atoi(rrl_val);
        if (vk_get("config:rrl_slip", rrl_val, sizeof(rrl_val)))
            g_rrl_slip = atoi(rrl_val);
    }
    /* TSIG secret (base64) */
    if (vk_get("config:tsig_secret_b64", val, sizeof(val)) && val[0])
        g_tsig_secret_len = b64std_dec(val, g_tsig_secret, sizeof(g_tsig_secret));
    /* Cookie secret (32 hex chars = 16 bytes) */
    if (vk_get("config:cookie_secret", val, sizeof(val)) && val[0])
        hex_dec(val, g_cookie_secret, 16);
    else
        RAND_bytes(g_cookie_secret, 16);
    /* NSEC3 params */
    if (vk_get("config:nsec3_iters", val, sizeof(val)) && val[0])
        g_nsec3_iters = atoi(val);
    if (vk_get("config:nsec3_salt", val, sizeof(val)) && val[0])
        safe_strcpy(g_nsec3_salt, val, sizeof(g_nsec3_salt));
    {
        char nmode[16];
        if (vk_get("config:dnssec_nsec_mode", nmode, sizeof(nmode)))
            g_dnssec_use_nsec3 = (strcasecmp(nmode, "nsec") == 0) ? 0 : 1;
    }
    /* If NSID empty, use hostname */
    if (!g_nsid[0])
        gethostname(g_nsid, sizeof(g_nsid) - 1);
    /* PEM blobs */
    vk_get("config:tls_cert_pem", g_tls_cert_pem, sizeof(g_tls_cert_pem));
    vk_get("config:tls_key_pem", g_tls_key_pem, sizeof(g_tls_key_pem));
    vk_get("config:mtls_ca_pem", g_mtls_ca_pem, sizeof(g_mtls_ca_pem));
    /* Local syslog config */
    if (vk_get("config:syslog_enabled", val, sizeof(val)) && val[0])
        g_syslog_enabled = atoi(val);
    if (vk_get("config:syslog_facility", val, sizeof(val)) && val[0])
        g_syslog_facility = syslog_facility_from_str(val);
    if (vk_get("config:syslog_level", val, sizeof(val)) && val[0])
        g_syslog_level = syslog_level_from_str(val);
    if (vk_get("config:syslog_ident", val, sizeof(val)) && val[0])
        safe_strcpy(g_syslog_ident, val, sizeof(g_syslog_ident));
    /* Remote syslog config */
    if (vk_get("config:syslog_remote_host", val, sizeof(val)) && val[0])
        safe_strcpy(g_rsyslog_host, val, sizeof(g_rsyslog_host));
    if (vk_get("config:syslog_remote_port", val, sizeof(val)) && val[0])
        g_rsyslog_port = atoi(val);
    else if (g_rsyslog_host[0] && g_rsyslog_port == 0)
        g_rsyslog_port = (g_rsyslog_proto == RSYSLOG_TLS) ? 6514 : 514;
    if (vk_get("config:syslog_remote_proto", val, sizeof(val)) && val[0]) {
        if (!strcasecmp(val, "tcp"))
            g_rsyslog_proto = RSYSLOG_TCP;
        else if (!strcasecmp(val, "tls"))
            g_rsyslog_proto = RSYSLOG_TLS;
        else
            g_rsyslog_proto = RSYSLOG_UDP;
    }
    if (vk_get("config:syslog_remote_level", val, sizeof(val)) && val[0])
        g_rsyslog_level = syslog_level_from_str(val);
    if (vk_get("config:syslog_remote_tls_verify", val, sizeof(val)) && val[0])
        g_rsyslog_tls_verify = atoi(val);
    if (vk_get("config:syslog_remote_format", val, sizeof(val)) && val[0])
        g_rsyslog_fmt = strcasecmp(val, "rfc3164") == 0 ? RFMT_RFC3164 : RFMT_RFC5424;
    /* Populate local hostname for syslog messages */
    if (!g_rsyslog_hostname[0])
        gethostname(g_rsyslog_hostname, sizeof(g_rsyslog_hostname) - 1);
    /* Record PID */
    g_log_pid = getpid();
    syslog_init();
#undef G
#undef GI
#undef GU
    dns_log(LOG_INFO, "[Config] dns:%d dot:%d http:%d https:%d zone:%s serial:%u\n", g_dns_port,
            g_dot_port, g_http_port, g_https_port, g_zone_name, g_soa_serial);
}
/* Bump a zone's SOA serial.  The persistent counter lives at
 * config:zone:<zone>:serial; the primary zone keeps the legacy
 * config:zone_serial key for backward compatibility. */
static uint32_t serial_bump(zone_entry_t *z) {
    char ikey[320];
    int primary = (!z || strcasecmp(z->name, g_zone_name) == 0);
    if (primary)
        safe_strcpy(ikey, "config:zone_serial", sizeof(ikey));
    else
        snprintf(ikey, sizeof(ikey), "config:zone:%s:serial", z->name);
    long ns = vk_incr(ikey);
    if (ns > 0) {
        pthread_mutex_lock(&g_soa_mutex);
        if (z)
            z->soa_serial = (uint32_t) ns;
        if (primary)
            g_soa_serial = (uint32_t) ns;
        pthread_mutex_unlock(&g_soa_mutex);
        return (uint32_t) ns;
    }
    pthread_mutex_lock(&g_soa_mutex);
    uint32_t nv;
    if (z)
        nv = ++z->soa_serial;
    else
        nv = ++g_soa_serial;
    if (primary)
        g_soa_serial = nv;
    pthread_mutex_unlock(&g_soa_mutex);
    char buf[32];
    snprintf(buf, sizeof(buf), "%u", nv);
    vk_set(ikey, buf, 0);
    return nv;
}

/* ==========================================================================
 * TLS contexts from in-memory PEM
 * ======================================================================= */
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
static void tls_reload(void) {
    pthread_mutex_lock(&g_tls_mutex);
    if (g_dot_ctx) {
        SSL_CTX_free(g_dot_ctx);
        g_dot_ctx = NULL;
    }
    g_dot_ctx = tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, NULL, 0);
    /* RFC 7858 §3.2: advertise "dot" ALPN on the DoT listener */
    if (g_dot_ctx) {
        static const uint8_t dot_alpn[] = {3, 'd', 'o', 't'};
        SSL_CTX_set_alpn_protos(g_dot_ctx, dot_alpn, sizeof(dot_alpn));
        /* TLS session resumption — reduces reconnect latency for DoT clients.
         * Server-side session cache: stores session state keyed by session ID.
         * Session tickets: allows stateless resumption (client stores ticket). */
        SSL_CTX_set_session_cache_mode(g_dot_ctx,
                                       SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);
        SSL_CTX_sess_set_cache_size(g_dot_ctx, 1024);
        SSL_CTX_set_timeout(g_dot_ctx, 3600); /* 1h session lifetime */
        /* Session ticket: generate a random key so tickets work across
         * reloads within the same process lifetime.  On cert hot-reload,
         * the existing key is retained so in-flight tickets remain valid. */
        static uint8_t s_ticket_key[48] = {0};
        static int s_ticket_key_init = 0;
        if (!s_ticket_key_init) {
            RAND_bytes(s_ticket_key, sizeof(s_ticket_key));
            s_ticket_key_init = 1;
        }
        SSL_CTX_set_tlsext_ticket_keys(g_dot_ctx, s_ticket_key, sizeof(s_ticket_key));
    }
    pthread_mutex_unlock(&g_tls_mutex);
    dns_log(LOG_INFO, "[TLS] Contexts %s\n", g_dot_ctx ? "loaded" : "unavailable (no cert yet)");
}

/* cert:current handling (migration Step 2, CLAUDE.md Valkey contract).
 *
 * `cert:current` is written by certd as one PEM blob: certificate chain plus
 * private key, concatenated in either order. dnsd only reads it: on change it
 * splits the blob, swaps the in-memory cert/key and hot-reloads the TLS
 * contexts. dnsd never writes cert:* and does not speak ACME/EST.
 *
 * Step 6 drives this from Valkey keyspace notifications (see
 * keyspace_watch_thread) instead of polling. */
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
    /* cert = blob minus the key block (chain may precede and/or follow it) */
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
/* Publish TLSA 3 1 1 for _443._tcp.<name> and _853._tcp.<name>, bump the
 * SOA serial and NOTIFY secondaries. This is dnsd's half of issuance: certd
 * writes cert:current only; the zone is dnsd's to write (ownership table).
 * The name comes from the certificate itself (first SAN dNSName, else CN),
 * so dnsd needs no knowledge of the ACME/EST configuration. */
static int pki_spki_sha256(X509 *cert, uint8_t out[32]);
static uint32_t serial_bump(zone_entry_t *z);
static void cert_publish_tlsa(const char *cert_pem) {
    BIO *b = BIO_new_mem_buf(cert_pem, -1);
    X509 *cert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!cert)
        return;
    char domain[256] = "";
    GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (gn->type == GEN_DNS) {
                const unsigned char *dn = ASN1_STRING_get0_data(gn->d.dNSName);
                int dl = ASN1_STRING_length(gn->d.dNSName);
                if (dl > 0 && dl < (int) sizeof(domain)) {
                    memcpy(domain, dn, dl);
                    domain[dl] = 0;
                    break;
                }
            }
        }
        GENERAL_NAMES_free(sans);
    }
    if (!domain[0])
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, domain,
                                  sizeof(domain));
    uint8_t h[32];
    if (domain[0] && pki_spki_sha256(cert, h)) {
        /* Lowercase only the owner name. The old cert_post_issue lowercased
         * the whole key ("zone:tlsa:…"), which the lookup path — keyed
         * "zone:TLSA:<qname>" via type2str — could never match. */
        strlower(domain);
        char hex[65];
        hex_enc(h, 32, hex);
        char owner[300];
        snprintf(owner, sizeof(owner), "_443._tcp.%s", domain);
        zone_entry_t *z = zone_for_qname(owner);
        const char *zn = z ? z->name : g_zone_name;
        char tkey[700], tval[128];
        snprintf(tval, sizeof(tval), "3600|3|1|1|%s", hex);
        snprintf(tkey, sizeof(tkey), "zone:%s:TLSA:_443._tcp.%s", zn, domain);
        vk_set(tkey, tval, 0);
        snprintf(tkey, sizeof(tkey), "zone:%s:TLSA:_853._tcp.%s", zn, domain);
        vk_set(tkey, tval, 0);
        dns_log(LOG_NOTICE, "[PKI] TLSA 3 1 1 published for %s (zone %s)\n", domain, zn);
        serial_bump(z);
        notify_send();
    }
    X509_free(cert);
}
/* Apply cert:current if it has changed since the last apply. Used for the
 * boot/reconnect catch-up and on a cert:current keyspace notification. */
static char g_cert_last[MAX_PEM];
static void cert_current_reload(void) {
    static char cur[MAX_PEM], cert[MAX_PEM], key[MAX_PEM];
    cur[0] = 0;
    if (!vk_get("cert:current", cur, sizeof(cur)) || !cur[0])
        return;
    if (strcmp(cur, g_cert_last) == 0)
        return;
    if (cert_current_split(cur, cert, sizeof(cert), key, sizeof(key)) < 0) {
        dns_log(LOG_ERR, "[TLS] cert:current malformed — ignoring\n");
        safe_strcpy(g_cert_last, cur, sizeof(g_cert_last)); /* don't re-parse */
        return;
    }
    safe_strcpy(g_tls_cert_pem, cert, sizeof(g_tls_cert_pem));
    safe_strcpy(g_tls_key_pem, key, sizeof(g_tls_key_pem));
    safe_strcpy(g_cert_last, cur, sizeof(g_cert_last));
    dns_log(LOG_NOTICE, "[TLS] cert:current changed — hot-reloading\n");
    tls_reload();
    cert_publish_tlsa(cert);
}

/* ── Live reload via Valkey keyspace notifications (migration Step 6) ───────
 *
 * A dedicated subscriber connection (separate from the request/reply `vk`,
 * which a subscribed connection cannot share) enables keyspace events and
 * PSUBSCRIBEs to the namespaces dnsd owns, so dashboard/certd edits take
 * effect without a restart or SIGHUP. zone:* and ddns:* RECORDS are already
 * read live per query, so only these need action on change:
 *   config:*       reload runtime config (SOA, RRL, NSID, TSIG, TLS paths…)
 *   cert:current   hot-reload TLS + publish TLSA (replaces the old 30s poll)
 *   zone_table:*   rebuild the in-memory multi-zone list
 *   dnssec:*       reload that zone's keys live (current + rollover/next set)
 *
 * The thread re-runs a full catch-up after every (re)connect, so changes made
 * while it was disconnected are not missed; reconnects use capped backoff so a
 * Valkey restart cannot cause a reconnect storm. */
#define KEYSPACE_DB 0
static void keyspace_apply(const char *key) {
    if (strncmp(key, "cert:current", 12) == 0) {
        cert_current_reload();
    } else if (strncmp(key, "config:", 7) == 0) {
        config_load_from_valkey();
        seed_primary_zone(); /* propagate SOA/zone config edits to the primary zone */
        zones_post_load();   /* re-apply per-zone NSEC3 config; load keys for new zones */
        if (strstr(key, "tls_") || strstr(key, "mtls_"))
            tls_reload();
        dns_log(LOG_INFO, "[Reload] config applied after %s change\n", key);
    } else if (strncmp(key, "zone_table:", 11) == 0) {
        zones_load_from_valkey();
        zones_post_load(); /* apply per-zone config + load keys for any new zone */
        dns_log(LOG_INFO, "[Reload] zone table reloaded after %s change\n", key);
    } else if (strncmp(key, "dnssec:", 7) == 0) {
        /* dnssec:<zone>:... — reload that zone's key state live (current set +
         * rollover/next set). Legacy un-prefixed keys (dnssec:zsk) belong to the
         * primary zone. */
        char zn[256] = "";
        const char *p = key + 7;
        const char *colon = strchr(p, ':');
        if (colon && (size_t) (colon - p) < sizeof(zn)) {
            memcpy(zn, p, (size_t) (colon - p));
            zn[colon - p] = 0;
        }
        zone_entry_t *z = NULL;
        pthread_mutex_lock(&g_zones_mutex);
        for (int i = 0; i < g_zone_count; i++) {
            if (strcasecmp(g_zones[i].name, zn) == 0 ||
                (!colon && strcasecmp(g_zones[i].name, g_zone_name) == 0)) {
                z = &g_zones[i];
                break;
            }
        }
        pthread_mutex_unlock(&g_zones_mutex);
        if (z) {
            zone_dnssec_reload(z);
            dns_log(LOG_INFO, "[Reload] DNSSEC keys reloaded for zone %s after %s change\n",
                    z->name, key);
        }
    }
}

static void *keyspace_watch_thread(void *arg) {
    (void) arg;
    static resp_conn_t sub;
    int backoff = 1;
    for (;;) {
        memset(&sub, 0, sizeof(sub));
        sub.fd = -1;
        if (valkey_connect_to(&sub, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
            sleep(backoff);
            if (backoff < 30)
                backoff *= 2;
            continue;
        }
        /* A subscriber blocks waiting for events, so drop the 4s read timeout
         * valkey_connect_to set (else recv would time out and look like a
         * disconnect — a reconnect storm). */
        struct timeval no_to = {0};
        setsockopt(sub.fd, SOL_SOCKET, SO_RCVTIMEO, &no_to, sizeof(no_to));

        /* Enable keyspace notifications (idempotent). KEA = keyspace + keyevent
         * channels, all event classes — covers SET/DEL/EXPIRE on watched keys. */
        resp_reply_t r;
        if (resp_cmd(&sub, &r, 4, "CONFIG", "SET", "notify-keyspace-events", "KEA") < 0 ||
            r.type == 1)
            dns_log(LOG_WARNING, "[Reload] could not enable keyspace notifications "
                                 "(CONFIG SET denied?) — boot/reconnect catch-up only\n");

        /* Catch up on anything changed before (re)subscribing, then subscribe.
         * Catch-up uses the shared `vk` connection, not `sub`. */
        config_load_from_valkey();
        zones_load_from_valkey();
        cert_current_reload();

        static const char *prefixes[] = {"config:*", "cert:current", "zone_table:*", "dnssec:*",
                                         NULL};
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
        backoff = 1; /* connected + subscribed cleanly */
        dns_log(LOG_NOTICE, "[Reload] live reload active (keyspace notifications)\n");

        /* Each notification is a multi-bulk: ["pmessage", pattern, channel,
         * payload]; channel is "__keyspace@<db>__:<key>", payload the event.
         * PSUBSCRIBE acks ("psubscribe", …) flow through here too and are
         * skipped. */
        for (;;) {
            resp_reply_t hdr;
            if (resp_parse(&sub, &hdr) < 0)
                break; /* disconnect */
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
                keyspace_apply(sep + 3);
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

/* ==========================================================================
 * DNSSEC helpers
 * ======================================================================= */
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
static int dnskey_rdata_ecdsa(EVP_PKEY *k, uint8_t *rd, int rdlen) {
    if (rdlen < 68)
        return -1;
    rd[0] = DNS_DNSKEY_FLAG_ZSK >> 8;
    rd[1] = DNS_DNSKEY_FLAG_ZSK & 0xFF;
    rd[2] = 3;
    rd[3] = DNS_ALG_ECDSAP256SHA256;
    if (!ec_pub_xy(k, rd + 4))
        return -1;
    return 68;
}
static int dnskey_rdata_ed25519(EVP_PKEY *k, uint8_t *rd, int rdlen) {
    if (rdlen < 36)
        return -1;
    rd[0] = DNS_DNSKEY_FLAG_ZSK >> 8;
    rd[1] = DNS_DNSKEY_FLAG_ZSK & 0xFF;
    rd[2] = 3;
    rd[3] = DNS_ALG_ED25519;
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(k, rd + 4, &pub_len) != 1)
        return -1;
    return 36;
}
/* KSK variants — flag 257 */
static int dnskey_rdata_ksk_ecdsa(EVP_PKEY *k, uint8_t *rd, int rdlen) {
    if (rdlen < 68)
        return -1;
    rd[0] = DNS_DNSKEY_FLAG_KSK >> 8;
    rd[1] = DNS_DNSKEY_FLAG_KSK & 0xFF;
    rd[2] = 3;
    rd[3] = DNS_ALG_ECDSAP256SHA256;
    if (!ec_pub_xy(k, rd + 4))
        return -1;
    return 68;
}
static int dnskey_rdata_ksk_ed25519(EVP_PKEY *k, uint8_t *rd, int rdlen) {
    if (rdlen < 36)
        return -1;
    rd[0] = DNS_DNSKEY_FLAG_KSK >> 8;
    rd[1] = DNS_DNSKEY_FLAG_KSK & 0xFF;
    rd[2] = 3;
    rd[3] = DNS_ALG_ED25519;
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(k, rd + 4, &pub_len) != 1)
        return -1;
    return 36;
}

static uint16_t keytag(const uint8_t *rd, int rdlen) {
    uint32_t ac = 0;
    for (int i = 0; i < rdlen; i++)
        ac += (i & 1) ? rd[i] : (uint32_t) rd[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return (uint16_t) (ac & 0xFFFF);
}
static int label_count(const char *n) {
    if (!n || !*n)
        return 0;
    const char *start = n;
    int c = 1;
    for (; *n; n++)
        if (*n == '.')
            c++;
    if (n > start && n[-1] == '.')
        c--;
    return c;
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

/* Build RRSIG rdata for one RR, using given ZSK key + algorithm */
static int make_rrsig(const char *owner, uint16_t rrtype, uint32_t ttl, const uint8_t *rrdata,
                      uint16_t rrdata_len, EVP_PKEY *zsk, uint8_t alg, uint16_t tag,
                      uint8_t *outbuf) {
    if (!zsk)
        return -1;
    uint8_t hdr[512];
    int hp = 0;
    time_t now = time(NULL);
    uint32_t t_inc = (uint32_t) (now - 300), t_exp = (uint32_t) (now + DNSSEC_SIG_VALIDITY);
    hdr[hp++] = rrtype >> 8;
    hdr[hp++] = rrtype & 0xFF;
    hdr[hp++] = alg;
    hdr[hp++] = (uint8_t) label_count(owner);
    hdr[hp++] = ttl >> 24;
    hdr[hp++] = (ttl >> 16) & 0xFF;
    hdr[hp++] = (ttl >> 8) & 0xFF;
    hdr[hp++] = ttl & 0xFF;
    hdr[hp++] = t_exp >> 24;
    hdr[hp++] = (t_exp >> 16) & 0xFF;
    hdr[hp++] = (t_exp >> 8) & 0xFF;
    hdr[hp++] = t_exp & 0xFF;
    hdr[hp++] = t_inc >> 24;
    hdr[hp++] = (t_inc >> 16) & 0xFF;
    hdr[hp++] = (t_inc >> 8) & 0xFF;
    hdr[hp++] = t_inc & 0xFF;
    hdr[hp++] = tag >> 8;
    hdr[hp++] = tag & 0xFF;
    /* Signer name wire */
    char sn[256];
    safe_strcpy(sn, owner, sizeof(sn));
    strlower(sn);
    {
        char *sp1 = NULL;
        char tmp[256];
        safe_strcpy(tmp, sn, sizeof(tmp));
        char *lbl = strtok_r(tmp, ".", &sp1);
        while (lbl) {
            int ll = (int) strlen(lbl);
            if (hp + ll + 2 > (int) sizeof(hdr)) {
                return -1;
            }
            hdr[hp++] = (uint8_t) ll;
            memcpy(hdr + hp, lbl, ll);
            hp += ll;
            lbl = strtok_r(NULL, ".", &sp1);
        }
        hdr[hp++] = 0;
    }
    /* Canonical RR */
    uint8_t own_w[256];
    int ow = 0;
    {
        char *sp2 = NULL;
        char tmp[256];
        safe_strcpy(tmp, sn, sizeof(tmp));
        char *lbl = strtok_r(tmp, ".", &sp2);
        while (lbl) {
            int ll = (int) strlen(lbl);
            own_w[ow++] = (uint8_t) ll;
            memcpy(own_w + ow, lbl, ll);
            ow += ll;
            lbl = strtok_r(NULL, ".", &sp2);
        }
        own_w[ow++] = 0;
    }
    int rr_need = ow + 10 + rrdata_len;
    uint8_t *rr = malloc(rr_need);
    if (!rr)
        return -1;
    int rp = 0;
    memcpy(rr, own_w, ow);
    rp += ow;
    rr[rp++] = rrtype >> 8;
    rr[rp++] = rrtype & 0xFF;
    rr[rp++] = 0;
    rr[rp++] = DNS_CLASS_IN;
    rr[rp++] = ttl >> 24;
    rr[rp++] = (ttl >> 16) & 0xFF;
    rr[rp++] = (ttl >> 8) & 0xFF;
    rr[rp++] = ttl & 0xFF;
    rr[rp++] = rrdata_len >> 8;
    rr[rp++] = rrdata_len & 0xFF;
    memcpy(rr + rp, rrdata, rrdata_len);
    rp += rrdata_len;
    /* Sign */
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    if (!mc) {
        free(rr);
        return -1;
    }
    const EVP_MD *md = (alg == DNS_ALG_ED25519) ? NULL : EVP_sha256();
    EVP_DigestSignInit(mc, NULL, md, NULL, zsk);
    EVP_DigestSignUpdate(mc, hdr, hp);
    EVP_DigestSignUpdate(mc, rr, rp);
    free(rr);
    size_t sl = 0;
    EVP_DigestSignFinal(mc, NULL, &sl);
    if (sl == 0) {
        EVP_MD_CTX_free(mc);
        return -1;
    }
    uint8_t *der = malloc(sl);
    if (!der) {
        EVP_MD_CTX_free(mc);
        return -1;
    }
    EVP_DigestSignFinal(mc, der, &sl);
    EVP_MD_CTX_free(mc);
    memcpy(outbuf, hdr, hp);
    if (alg == DNS_ALG_ED25519) {
        memcpy(outbuf + hp, der, sl);
        free(der);
        return hp + (int) sl;
    }
    uint8_t raw[64];
    if (!ecdsa_der_to_raw(der, sl, raw)) {
        free(der);
        return -1;
    }
    free(der);
    memcpy(outbuf + hp, raw, 64);
    return hp + 64;
}

/* Load or generate a DNSSEC key from Valkey.
 * Reads vk_key first; if absent and legacy_key is given, adopts the legacy
 * key under vk_key (eases migration of pre-multi-zone single-zone keys);
 * only generates + stores a fresh key when neither exists. */
static void dnssec_init_key(const char *vk_key, const char *legacy_key, EVP_PKEY **out,
                            uint16_t *tag, int alg, const char *label) {
    char pem[MAX_PEM] = {0};
    int have = (vk_get(vk_key, pem, sizeof(pem)) && strlen(pem) > 10);
    if (!have && legacy_key && vk_get(legacy_key, pem, sizeof(pem)) && strlen(pem) > 10) {
        have = 1;
        vk_set(vk_key, pem, 0); /* adopt the legacy key under the per-zone path */
    }
    if (have) {
        BIO *b = BIO_new_mem_buf(pem, -1);
        pthread_mutex_lock(&g_zsk_mutex);
        *out = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
        pthread_mutex_unlock(&g_zsk_mutex);
        BIO_free(b);
    }
    if (!*out) {
        dns_log(LOG_INFO, "[DNSSEC] Generating %s...\n", label);
        EVP_PKEY_CTX *kctx;
        if (alg == DNS_ALG_ED25519) {
            kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
            EVP_PKEY_keygen_init(kctx);
        } else {
            kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            EVP_PKEY_keygen_init(kctx);
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
        }
        pthread_mutex_lock(&g_zsk_mutex);
        EVP_PKEY_keygen(kctx, out);
        pthread_mutex_unlock(&g_zsk_mutex);
        EVP_PKEY_CTX_free(kctx);
        BIO *b = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(b, *out, NULL, NULL, 0, NULL, NULL);
        char *pp;
        long pl = BIO_get_mem_data(b, &pp);
        char pem2[MAX_PEM];
        int n = (int) (pl < MAX_PEM - 1 ? pl : MAX_PEM - 1);
        memcpy(pem2, pp, n);
        pem2[n] = 0;
        vk_set(vk_key, pem2, 0);
        BIO_free(b);
        dns_log(LOG_INFO, "[DNSSEC] %s generated and stored\n", label);
    }
    uint8_t dkrd[68];
    int dklen = (alg == DNS_ALG_ED25519) ? dnskey_rdata_ed25519(*out, dkrd, sizeof(dkrd))
                                         : dnskey_rdata_ecdsa(*out, dkrd, sizeof(dkrd));
    if (dklen > 0)
        *tag = keytag(dkrd, dklen);
    dns_log(LOG_INFO, "[DNSSEC] %s key tag: %u\n", label, *tag);
}
/* Load (or generate) the four DNSSEC keys for one zone.  The primary zone
 * (== g_zone_name) falls back to the legacy un-prefixed dnssec:* keys so an
 * existing single-zone deployment keeps its established DS/keytags. */
static void zone_dnssec_init(zone_entry_t *z) {
    int primary = (strcasecmp(z->name, g_zone_name) == 0);
    char k[320];
    char lbl[300];
    snprintf(k, sizeof(k), "dnssec:%s:zsk", z->name);
    snprintf(lbl, sizeof(lbl), "%s ZSK-P256", z->name);
    dnssec_init_key(k, primary ? "dnssec:zsk" : NULL, &z->zsk, &z->zsk_tag, DNS_ALG_ECDSAP256SHA256,
                    lbl);
    snprintf(k, sizeof(k), "dnssec:%s:zsk_ed25519", z->name);
    snprintf(lbl, sizeof(lbl), "%s ZSK-Ed25519", z->name);
    dnssec_init_key(k, primary ? "dnssec:zsk_ed25519" : NULL, &z->zsk_ed, &z->zsk_ed_tag,
                    DNS_ALG_ED25519, lbl);
    snprintf(k, sizeof(k), "dnssec:%s:ksk", z->name);
    snprintf(lbl, sizeof(lbl), "%s KSK-P256", z->name);
    dnssec_init_key(k, primary ? "dnssec:ksk" : NULL, &z->ksk, &z->ksk_tag, DNS_ALG_ECDSAP256SHA256,
                    lbl);
    snprintf(k, sizeof(k), "dnssec:%s:ksk_ed25519", z->name);
    snprintf(lbl, sizeof(lbl), "%s KSK-Ed25519", z->name);
    dnssec_init_key(k, primary ? "dnssec:ksk_ed25519" : NULL, &z->ksk_ed, &z->ksk_ed_tag,
                    DNS_ALG_ED25519, lbl);
    zone_rollover_load(z);
}

/* Load an existing private key from Valkey without generating one.  Used for
 * the incoming ("next") ZSK set during a rollover, which is absent outside a
 * rollover.  Returns 1 on success. */
static int dnssec_load_existing(const char *vk_key, EVP_PKEY **out, uint16_t *tag, int alg) {
    char pem[MAX_PEM] = {0};
    if (!(vk_get(vk_key, pem, sizeof(pem)) && strlen(pem) > 10))
        return 0;
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!k)
        return 0;
    *out = k;
    uint8_t dkrd[68];
    int dklen = (alg == DNS_ALG_ED25519) ? dnskey_rdata_ed25519(k, dkrd, sizeof(dkrd))
                                         : dnskey_rdata_ecdsa(k, dkrd, sizeof(dkrd));
    if (dklen > 0)
        *tag = keytag(dkrd, dklen);
    return 1;
}

/* Load the ZSK-rollover state for a zone from Valkey:
 *   dnssec:<zone>:zsk_created   epoch the current ZSK set was created
 *   dnssec:<zone>:zsk_rollover  "publish|<epoch>" or "commit|<epoch>" (absent = none)
 *   dnssec:<zone>:zsk_next, :zsk_ed25519_next   incoming key set (rollover only)
 * Loads the incoming keys into locals, then installs them under a single
 * g_zsk_mutex hold, so a concurrent query/reload never sees a half-applied
 * state (no transient missing key in the published DNSKEY RRset). */
static void zone_rollover_load(zone_entry_t *z) {
    char k[360], v[64];
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_created", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0]) {
        z->zsk_created = (time_t) atoll(v);
    } else {
        z->zsk_created = time(NULL);
        char b[32];
        snprintf(b, sizeof(b), "%lld", (long long) z->zsk_created);
        vk_set(k, b, 0);
    }
    int phase = ROLL_NONE;
    time_t since = 0;
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_rollover", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0]) {
        char ph[16] = "";
        long long si = 0;
        sscanf(v, "%15[^|]|%lld", ph, &si);
        if (strcmp(ph, "publish") == 0)
            phase = ROLL_PUBLISH;
        else if (strcmp(ph, "commit") == 0)
            phase = ROLL_COMMIT;
        since = (time_t) si;
    }
    EVP_PKEY *nk1 = NULL, *nk2 = NULL;
    uint16_t t1 = 0, t2 = 0;
    if (phase != ROLL_NONE) {
        char nk[360];
        snprintf(nk, sizeof(nk), "dnssec:%.255s:zsk_next", z->name);
        dnssec_load_existing(nk, &nk1, &t1, DNS_ALG_ECDSAP256SHA256);
        snprintf(nk, sizeof(nk), "dnssec:%.255s:zsk_ed25519_next", z->name);
        dnssec_load_existing(nk, &nk2, &t2, DNS_ALG_ED25519);
        if (!nk1 || !nk2) {
            dns_log(LOG_WARNING, "[Rollover] %s: incoming keys missing — aborting rollover\n",
                    z->name);
            if (nk1)
                EVP_PKEY_free(nk1);
            if (nk2)
                EVP_PKEY_free(nk2);
            nk1 = nk2 = NULL;
            phase = ROLL_NONE;
        }
    }
    pthread_mutex_lock(&g_zsk_mutex);
    EVP_PKEY *old1 = z->zsk_next, *old2 = z->zsk_ed_next;
    z->zsk_next = nk1;
    z->zsk_ed_next = nk2;
    z->zsk_next_tag = t1;
    z->zsk_ed_next_tag = t2;
    z->roll_phase = phase;
    z->roll_since = since;
    pthread_mutex_unlock(&g_zsk_mutex);
    if (old1)
        EVP_PKEY_free(old1);
    if (old2)
        EVP_PKEY_free(old2);
}

/* Reload a zone's full DNSSEC key state live (current set + rollover/next set),
 * e.g. on a dnssec:<zone>:* keyspace notification or after a rollover step. */
static void zone_dnssec_reload(zone_entry_t *z) {
    pthread_mutex_lock(&g_zsk_mutex);
    EVP_PKEY *old[4] = {z->zsk, z->zsk_ed, z->ksk, z->ksk_ed};
    z->zsk = z->zsk_ed = z->ksk = z->ksk_ed = NULL;
    pthread_mutex_unlock(&g_zsk_mutex);
    for (int i = 0; i < 4; i++)
        if (old[i])
            EVP_PKEY_free(old[i]);
    zone_dnssec_init(z); /* reloads current keys (present in Valkey) + rollover state */
}

/* ==========================================================================
 * ZSK rollover engine (RFC 6781 §4.1.1.1 Pre-Publish)
 *
 * publish:  DNSKEY = {current, next}, RRSIGs by current.  Held long enough for
 *           the old DNSKEY RRset to expire from caches (rollover_publish_hold,
 *           ~ DNSKEY TTL) so every validator sees `next` before it is used.
 * commit:   DNSKEY = {current, next}, RRSIGs by next.  Held long enough for
 *           RRSIGs made by `current` to expire from caches (rollover_commit_hold
 *           ~ max record TTL) so no validator still needs `current`.
 * finish:   promote next -> current, drop the old key, rollover over.
 * At no point is an in-use key absent from the published DNSKEY RRset.
 * ======================================================================= */
static uint32_t serial_bump(zone_entry_t *z);

/* Generate a fresh private key (alg 13 or 15) as PEM.  Returns 0 on success. */
static int dnssec_generate_pem(int alg, char *pem_out, int sz) {
    EVP_PKEY_CTX *kctx;
    if (alg == DNS_ALG_ED25519) {
        kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0) {
            if (kctx)
                EVP_PKEY_CTX_free(kctx);
            return -1;
        }
    } else {
        kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0) {
            if (kctx)
                EVP_PKEY_CTX_free(kctx);
            return -1;
        }
    }
    EVP_PKEY *k = NULL;
    if (EVP_PKEY_keygen(kctx, &k) <= 0 || !k) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }
    EVP_PKEY_CTX_free(kctx);
    BIO *b = BIO_new(BIO_s_mem());
    if (!b || PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL) != 1) {
        if (b)
            BIO_free(b);
        EVP_PKEY_free(k);
        return -1;
    }
    char *pp;
    long pl = BIO_get_mem_data(b, &pp);
    int n = (int) (pl < sz - 1 ? pl : sz - 1);
    memcpy(pem_out, pp, n);
    pem_out[n] = 0;
    BIO_free(b);
    EVP_PKEY_free(k);
    return 0;
}

/* Read a rollover timing knob: per-zone config:zone:<z>:<suffix> overrides the
 * global config:<suffix>, else the default. */
static long roll_cfg(const char *zone, const char *suffix, long def) {
    char k[360], v[64];
    snprintf(k, sizeof(k), "config:zone:%s:%s", zone, suffix);
    if (vk_get(k, v, sizeof(v)) && v[0])
        return atol(v);
    snprintf(k, sizeof(k), "config:%s", suffix);
    if (vk_get(k, v, sizeof(v)) && v[0])
        return atol(v);
    return def;
}

/* Begin a rollover: generate + store the incoming ZSK set, enter `publish`. */
static void rollover_start(zone_entry_t *z) {
    char pem[MAX_PEM], k[360];
    if (dnssec_generate_pem(DNS_ALG_ECDSAP256SHA256, pem, sizeof(pem)) != 0) {
        dns_log(LOG_ERR, "[Rollover] %s: P-256 keygen failed\n", z->name);
        return;
    }
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_next", z->name);
    vk_set(k, pem, 0);
    if (dnssec_generate_pem(DNS_ALG_ED25519, pem, sizeof(pem)) != 0) {
        dns_log(LOG_ERR, "[Rollover] %s: Ed25519 keygen failed\n", z->name);
        return;
    }
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_ed25519_next", z->name);
    vk_set(k, pem, 0);
    char st[64];
    snprintf(st, sizeof(st), "publish|%lld", (long long) time(NULL));
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_rollover", z->name);
    vk_set(k, st, 0);
    zone_rollover_load(z); /* bring the next keys + phase into memory */
    serial_bump(z);        /* DNSKEY RRset changed */
    notify_send();
    dns_log(LOG_NOTICE, "[Rollover] %s: started — publish (new ZSK tags %u/%u)\n", z->name,
            z->zsk_next_tag, z->zsk_ed_next_tag);
}

/* publish -> commit: keep both keys published, switch the signer to `next`. */
static void rollover_to_commit(zone_entry_t *z) {
    char k[360], st[64];
    snprintf(st, sizeof(st), "commit|%lld", (long long) time(NULL));
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_rollover", z->name);
    vk_set(k, st, 0);
    zone_rollover_load(z);
    serial_bump(z);
    notify_send();
    dns_log(LOG_NOTICE, "[Rollover] %s: commit — now signing with ZSK tags %u/%u\n", z->name,
            z->zsk_next_tag, z->zsk_ed_next_tag);
}

/* commit -> done: promote `next` to current, drop the retired key. */
static void rollover_finish(zone_entry_t *z) {
    char k[360], pem[MAX_PEM];
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_next", z->name);
    if (vk_get(k, pem, sizeof(pem)) && pem[0]) {
        char ck[360];
        snprintf(ck, sizeof(ck), "dnssec:%.255s:zsk", z->name);
        vk_set(ck, pem, 0);
    }
    vk_del(k);
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_ed25519_next", z->name);
    if (vk_get(k, pem, sizeof(pem)) && pem[0]) {
        char ck[360];
        snprintf(ck, sizeof(ck), "dnssec:%.255s:zsk_ed25519", z->name);
        vk_set(ck, pem, 0);
    }
    vk_del(k);
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_rollover", z->name);
    vk_del(k);
    char now_s[32];
    snprintf(now_s, sizeof(now_s), "%lld", (long long) time(NULL));
    snprintf(k, sizeof(k), "dnssec:%.255s:zsk_created", z->name);
    vk_set(k, now_s, 0);
    zone_dnssec_reload(z); /* current = promoted key; next/phase cleared */
    serial_bump(z);
    notify_send();
    dns_log(LOG_NOTICE, "[Rollover] %s: complete — active ZSK tags %u/%u\n", z->name, z->zsk_tag,
            z->zsk_ed_tag);
}

/* Drive each zone's rollover state machine one step (time- and request-based). */
static void rollover_tick(void) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_zones_mutex);
    int n = g_zone_count;
    pthread_mutex_unlock(&g_zones_mutex);
    for (int i = 0; i < n; i++) {
        zone_entry_t *z = &g_zones[i];
        pthread_mutex_lock(&g_zsk_mutex);
        int phase = z->roll_phase;
        time_t since = z->roll_since, created = z->zsk_created;
        pthread_mutex_unlock(&g_zsk_mutex);
        if (phase == ROLL_NONE) {
            /* Manual request: control plane sets a new value at
             * config:zone:<z>:zsk_rollover_request; dnsd records the last value
             * it handled in its own namespace (dnssec:*), so it is edge-triggered
             * without dnsd writing config:*. */
            long req = roll_cfg(z->name, "zsk_rollover_request", 0);
            char sk[360], sv[64] = "";
            snprintf(sk, sizeof(sk), "dnssec:%.255s:zsk_rollover_seen", z->name);
            vk_get(sk, sv, sizeof(sv));
            long seen = sv[0] ? atol(sv) : 0;
            int manual = (req > 0 && req != seen);
            long validity = roll_cfg(z->name, "zsk_validity", 0); /* 0 = no auto-roll */
            int age_due = (validity > 0 && (now - created) >= validity);
            if (manual || age_due) {
                rollover_start(z);
                if (manual) {
                    char b[32];
                    snprintf(b, sizeof(b), "%ld", req);
                    vk_set(sk, b, 0);
                }
            }
        } else if (phase == ROLL_PUBLISH) {
            if ((now - since) >= roll_cfg(z->name, "rollover_publish_hold", 3600))
                rollover_to_commit(z);
        } else if (phase == ROLL_COMMIT) {
            if ((now - since) >= roll_cfg(z->name, "rollover_commit_hold", 3600))
                rollover_finish(z);
        }
    }
}

static void *rollover_thread(void *arg) {
    (void) arg;
    for (;;) {
        long tick = roll_cfg("", "rollover_tick_secs", 30);
        if (tick < 1)
            tick = 1;
        sleep((unsigned) tick);
        rollover_tick();
    }
    return NULL;
}
/* Per-zone NSEC3 / denial config (config:zone:<z>:*), defaulting to the legacy
 * global config:* values which seed the primary zone. */
static void zone_apply_config(zone_entry_t *z) {
    z->nsec3_iters = g_nsec3_iters;
    safe_strcpy(z->nsec3_salt, g_nsec3_salt, sizeof(z->nsec3_salt));
    z->dnssec_use_nsec3 = g_dnssec_use_nsec3;
    if (strcasecmp(z->name, g_zone_name) == 0)
        return; /* primary zone uses the global config as-is */
    char k[320], v[128];
    snprintf(k, sizeof(k), "config:zone:%s:nsec3_iters", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0])
        z->nsec3_iters = atoi(v);
    snprintf(k, sizeof(k), "config:zone:%s:nsec3_salt", z->name);
    if (vk_get(k, v, sizeof(v)))
        safe_strcpy(z->nsec3_salt, v, sizeof(z->nsec3_salt));
    snprintf(k, sizeof(k), "config:zone:%s:dnssec_nsec_mode", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0])
        z->dnssec_use_nsec3 = (strcasecmp(v, "nsec") == 0) ? 0 : 1;
}
/* Seed/refresh the primary zone (config:zone_name) from the legacy global
 * config:* values, so a single-zone deployment with no zone_table:* entry still
 * has one fully-populated zone, and live config:* edits propagate to it. */
static void seed_primary_zone(void) {
    if (!g_zone_name[0])
        return;
    char mname[300], rname[300];
    snprintf(mname, sizeof(mname), "ns1.%s", g_zone_name);
    snprintf(rname, sizeof(rname), "hostmaster.%s", g_zone_name);
    zone_upsert(g_zone_name, g_soa_mname[0] ? g_soa_mname : mname,
                g_soa_rname[0] ? g_soa_rname : rname, g_soa_serial, g_soa_refresh, g_soa_retry,
                g_soa_expire, g_soa_minimum, g_axfr_allow, g_notify_targets);
}
static void zones_post_load(void) {
    pthread_mutex_lock(&g_zones_mutex);
    int n = g_zone_count;
    pthread_mutex_unlock(&g_zones_mutex);
    for (int i = 0; i < n; i++) {
        zone_apply_config(&g_zones[i]);
        if (!g_zones[i].zsk && !g_zones[i].zsk_ed && !g_zones[i].ksk && !g_zones[i].ksk_ed)
            zone_dnssec_init(&g_zones[i]);
    }
}
static void dnssec_init(void) {
    zones_post_load();
}

/* ==========================================================================
 * NSEC3 helpers (RFC 5155) — hashed denial of existence
 * ======================================================================= */

/* RFC 5155 Sec 5: base32hex encoding */

/* Compute NSEC3 owner name for a given qname */
static void nsec3_hash_name(const char *name, const uint8_t *salt, int saltlen, int iters,
                            char *out_b32hex, int out_len) {
    /* Wire-encode the name (lowercase); RFC 1035 max wire length = 255 bytes */
    char lname[256];
    safe_strcpy(lname, name, sizeof(lname));
    strlower(lname);
    uint8_t wire[257];
    int wlen = 0; /* 257 = 255 payload + 1 root + guard */
    char tmp[256];
    safe_strcpy(tmp, lname, sizeof(tmp));
    char *sp3 = NULL;
    char *lbl = strtok_r(tmp, ".", &sp3);
    while (lbl) {
        int ll = (int) strlen(lbl);
        if (ll > 63 || wlen + ll + 1 > 255)
            break; /* enforce label and total limits */
        wire[wlen++] = (uint8_t) ll;
        memcpy(wire + wlen, lbl, ll);
        wlen += ll;
        lbl = strtok_r(NULL, ".", &sp3);
    }
    if (wlen < 256)
        wire[wlen++] = 0; /* root label */
    /* Iterative SHA-1: H(x) = SHA-1(x || salt), repeated iters+1 times */
    uint8_t h[20];
    uint8_t ibuf[256 + 64];
    int iblen = wlen;
    memcpy(ibuf, wire, wlen);
    memcpy(ibuf + wlen, salt, saltlen);
    iblen += saltlen;
    sha1(ibuf, iblen, h);
    for (int i = 0; i < iters; i++) {
        memcpy(ibuf, h, 20);
        memcpy(ibuf + 20, salt, saltlen);
        sha1(ibuf, 20 + saltlen, h);
    }
    base32hex_enc(h, 20, out_b32hex, out_len);
}

/* Build NSEC3 RDATA for a name, covering given type bitmap */
static int nsec3_rdata(const char *name, uint16_t covered_type, uint8_t *out, int outlen) {
    const char *zsalt = t_zone ? t_zone->nsec3_salt : g_nsec3_salt;
    int ziters = t_zone ? t_zone->nsec3_iters : g_nsec3_iters;
    const char *zname = t_zone ? t_zone->name : g_zone_name;
    uint8_t salt[16];
    int saltlen = 0;
    if (zsalt[0])
        saltlen = hex_dec(zsalt, salt, sizeof(salt));
    /* Compute next-closer hash (we use the same name hash as next for simplicity) */
    char hash[64];
    nsec3_hash_name(name, salt, saltlen, ziters, hash, sizeof(hash));
    /* Build RDATA: alg(1)|flags(1)|iters(2)|saltlen(1)|salt|hashlen(1)|nexthash|bitmap */
    uint8_t nexthash[20];
    /* Next hash = hash of the zone apex (simplified — in production use sorted order) */
    uint8_t zone_wire[257];
    int zw = 0;
    {
        char *sp4 = NULL;
        char ztmp[256];
        safe_strcpy(ztmp, zname, sizeof(ztmp));
        char *zl = strtok_r(ztmp, ".", &sp4);
        while (zl) {
            int ll = (int) strlen(zl);
            if (ll > 63 || zw + ll + 1 > 255)
                break;
            zone_wire[zw++] = (uint8_t) ll;
            memcpy(zone_wire + zw, zl, ll);
            zw += ll;
            zl = strtok_r(NULL, ".", &sp4);
        }
        if (zw < 256)
            zone_wire[zw++] = 0;
    }
    {
        uint8_t ib[256 + 64];
        int ib_len = zw;
        memcpy(ib, zone_wire, zw);
        if (saltlen) {
            memcpy(ib + zw, salt, saltlen);
            ib_len += saltlen;
        }
        sha1(ib, ib_len, nexthash);
        for (int i = 0; i < ziters; i++) {
            uint8_t ib2[256 + 64];
            memcpy(ib2, nexthash, 20);
            if (saltlen) {
                memcpy(ib2 + 20, salt, saltlen);
            }
            sha1(ib2, 20 + saltlen, nexthash);
        }
    }
    if (outlen < 25)
        return -1;
    int op = 0;
    out[op++] = NSEC3_ALG_SHA1;
    out[op++] = 0; /* flags: opt-out=0 */
    out[op++] = (uint16_t) ziters >> 8;
    out[op++] = (uint16_t) ziters & 0xFF;
    out[op++] = (uint8_t) saltlen;
    memcpy(out + op, salt, saltlen);
    op += saltlen;
    out[op++] = 20;
    memcpy(out + op, nexthash, 20);
    op += 20;
    /* Type bitmap: Window 0, block covering covered_type */
    if (covered_type < 256 && op + 4 < outlen) {
        uint8_t bmap[32] = {0};
        bmap[covered_type / 8] |= (0x80 >> (covered_type % 8));
        int blen = covered_type / 8 + 1;
        out[op++] = 0;
        out[op++] = (uint8_t) blen;
        memcpy(out + op, bmap, blen);
        op += blen;
    }
    return op;
}

/* ==========================================================================
 * TSIG authentication (RFC 8945)
 * ======================================================================= */
typedef struct {
    char key_name[256];
    char alg_name[64]; /* e.g. "hmac-sha256." — for algorithm negotiation */
    uint8_t mac[64];   /* enlarged for SHA-512 (64 bytes) */
    int mac_len;
    uint32_t time_high;
    uint64_t time_low;
    uint16_t fudge;
    uint16_t orig_id;
    uint16_t error;
} tsig_rr_t;

/* RFC 8945 §5.4.2: a response's MAC input is prepended with the request's MAC
 * (length-prefixed).  tsig_verify stashes the request MAC here on success;
 * tsig_append consumes (and clears) it when computing the response MAC.
 * Per-thread because each request runs on its own worker. */
static __thread uint8_t g_tsig_req_mac[64];
static __thread int g_tsig_req_mac_len;

/* Find and parse a TSIG RR from the additional section.
   Returns pointer to start of TSIG record in pkt, fills t, or NULL if absent. */
static const uint8_t *tsig_find(const uint8_t *pkt, int plen, tsig_rr_t *t) {
    if (plen < 12)
        return NULL;
    const dns_hdr_t *h = (const dns_hdr_t *) pkt;
    int ar = ntohs(h->arcount);
    if (ar == 0)
        return NULL;
    /* Skip header, questions, answers, authority */
    int off = 12;
    int skip = ntohs(h->qdcount) + ntohs(h->ancount) + ntohs(h->nscount);
    for (int i = 0; i < skip; i++) {
        int a = /* name_from_wire inline: */ off;
        /* skip name */
        for (;;) {
            if (a >= plen)
                return NULL;
            uint8_t c = pkt[a];
            if ((c & 0xC0) == 0xC0) {
                a += 2;
                break;
            }
            if (c == 0) {
                a++;
                break;
            }
            a += c + 1;
        }
        if (a + 4 > plen)
            return NULL;
        a += 4; /* type+class */
        /* skip rdlen if RR (not question) */
        if (i >= ntohs(h->qdcount)) {
            if (a + 6 > plen)
                return NULL;
            uint16_t rdlen = ((uint16_t) pkt[a + 4] << 8) | pkt[a + 5];
            a += 6 + rdlen;
        }
        off = a;
    }
    /* Scan additional RRs for TSIG */
    for (int i = 0; i < ar; i++) {
        int a = off;
        int orig_off = a;
        /* skip name */
        for (;;) {
            if (a >= plen)
                return NULL;
            uint8_t c = pkt[a];
            if ((c & 0xC0) == 0xC0) {
                a += 2;
                break;
            }
            if (c == 0) {
                a++;
                break;
            }
            a += c + 1;
        }
        if (a + 10 > plen)
            return NULL;
        uint16_t rtype = ((uint16_t) pkt[a] << 8) | pkt[a + 1];
        uint16_t rdlen = ((uint16_t) pkt[a + 8] << 8) | pkt[a + 9];
        if (rtype == 250 /*TSIG*/) {
            /* Parse TSIG RDATA */
            int rd_off = a + 10;
            if (rd_off + rdlen > plen)
                return NULL;
            /* key name already in name[] – re-parse */
            {
                const uint8_t *p2 = pkt + orig_off;
                int opos = 0;
                for (;;) {
                    uint8_t c2 = *p2;
                    if (c2 == 0) {
                        break;
                    }
                    if ((c2 & 0xC0) == 0xC0) {
                        /* compression pointer: the name ends here */
                        break;
                    }
                    /* bounds: dot + label (c2 bytes) must fit in 255 chars */
                    int dot = (opos > 0) ? 1 : 0;
                    if (opos + dot + c2 >= (int) sizeof(t->key_name) - 1) {
                        opos = 0;
                        break;
                    }
                    if (dot)
                        t->key_name[opos++] = '.';
                    memcpy(t->key_name + opos, p2 + 1, c2);
                    opos += c2;
                    p2 += c2 + 1;
                }
                t->key_name[opos] = 0;
                strlower(t->key_name);
            }
            /* capture alg name */
            int rp = rd_off;
            {
                int apos = 0;
                for (;;) {
                    if (rp >= plen)
                        return NULL;
                    uint8_t c = pkt[rp];
                    if (c == 0) {
                        rp++;
                        break;
                    }
                    int dot = (apos > 0) ? 1 : 0;
                    if (apos + dot + (int) c < (int) sizeof(t->alg_name) - 1) {
                        if (dot)
                            t->alg_name[apos++] = '.';
                        memcpy(t->alg_name + apos, pkt + rp + 1, c);
                        apos += c;
                    }
                    rp += c + 1;
                }
                if (apos < (int) sizeof(t->alg_name))
                    t->alg_name[apos] = '.';
                t->alg_name[sizeof(t->alg_name) - 1] = 0;
                strlower(t->alg_name);
            }
            if (rp + 10 > plen)
                return NULL;
            t->time_high = ((uint32_t) pkt[rp] << 8) | pkt[rp + 1];
            rp += 2;
            t->time_low = ((uint64_t) pkt[rp] << 24) | ((uint64_t) pkt[rp + 1] << 16) |
                          ((uint64_t) pkt[rp + 2] << 8) | pkt[rp + 3];
            rp += 4;
            t->fudge = ((uint16_t) pkt[rp] << 8) | pkt[rp + 1];
            rp += 2;
            t->mac_len = ((uint16_t) pkt[rp] << 8) | pkt[rp + 1];
            rp += 2;
            if (t->mac_len > 64 || rp + t->mac_len > plen)
                return NULL;
            memcpy(t->mac, pkt + rp, t->mac_len);
            rp += t->mac_len;
            if (rp + 6 > plen)
                return NULL;
            t->orig_id = ((uint16_t) pkt[rp] << 8) | pkt[rp + 1];
            rp += 2;
            t->error = ((uint16_t) pkt[rp] << 8) | pkt[rp + 1];
            return pkt + orig_off;
        }
        off = a + 10 + rdlen;
    }
    return NULL;
}

/* Verify TSIG MAC.  Returns 1 if valid (or TSIG absent+no secret), 0 if invalid. */
/* Map TSIG algorithm wire name to OpenSSL digest name.
 * RFC 8945 §6: mandatory algorithms are hmac-sha256 and hmac-sha512.
 * We also accept hmac-sha1 and hmac-sha384 for interoperability. */
static const char *tsig_alg_to_digest(const char *alg_name) {
    if (!alg_name)
        return "SHA256";
    if (strcasestr(alg_name, "sha512"))
        return "SHA512";
    if (strcasestr(alg_name, "sha384"))
        return "SHA384";
    if (strcasestr(alg_name, "sha256"))
        return "SHA256";
    if (strcasestr(alg_name, "sha1"))
        return "SHA1";
    if (strcasestr(alg_name, "md5"))
        return "MD5";
    return "SHA256"; /* safe default */
}

static int tsig_verify(const uint8_t *pkt, int plen) {
    g_tsig_req_mac_len = 0; /* clear any stale state */
    if (g_tsig_secret_len == 0)
        return 1; /* TSIG not configured: accept all */
    tsig_rr_t t;
    memset(&t, 0, sizeof(t));
    const uint8_t *tsig_rr = tsig_find(pkt, plen, &t);
    if (!tsig_rr)
        return 0; /* required but absent */
    /* Build signing data: (pkt minus TSIG) + TSIG variables */
    int pkt_minus_tsig_len = (int) (tsig_rr - pkt);
    if (pkt_minus_tsig_len <= 0)
        return 0;
    /* Patch arcount -= 1 */
    uint8_t *tmp = malloc((size_t) pkt_minus_tsig_len);
    if (!tmp)
        return 0;
    memcpy(tmp, pkt, pkt_minus_tsig_len);
    uint16_t ar = ((uint16_t) tmp[10] << 8) | tmp[11];
    ar--;
    tmp[10] = ar >> 8;
    tmp[11] = ar & 0xFF;
    /* TSIG variables */
    uint8_t vars[512];
    int vp = 0;
    /* key name wire */
    {
        char *sp5 = NULL;
        char tmp2[256];
        safe_strcpy(tmp2, t.key_name, sizeof(tmp2));
        char *lbl = strtok_r(tmp2, ".", &sp5);
        while (lbl) {
            int ll = (int) strlen(lbl);
            vars[vp++] = (uint8_t) ll;
            memcpy(vars + vp, lbl, ll);
            vp += ll;
            lbl = strtok_r(NULL, ".", &sp5);
        }
        vars[vp++] = 0;
    }
    /* class=ANY, ttl=0 */
    vars[vp++] = 0;
    vars[vp++] = 255;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0;
    /* alg name: hmac-sha256. */
    const char *alg_wire = "\x0bhmac-sha256\x00";
    memcpy(vars + vp, alg_wire, 13);
    vp += 13;
    /* time signed */
    vars[vp++] = (uint8_t) (t.time_high >> 8);
    vars[vp++] = (uint8_t) (t.time_high & 0xFF);
    vars[vp++] = (uint8_t) ((t.time_low >> 24) & 0xFF);
    vars[vp++] = (uint8_t) ((t.time_low >> 16) & 0xFF);
    vars[vp++] = (uint8_t) ((t.time_low >> 8) & 0xFF);
    vars[vp++] = (uint8_t) (t.time_low & 0xFF);
    vars[vp++] = t.fudge >> 8;
    vars[vp++] = t.fudge & 0xFF;
    vars[vp++] = t.error >> 8;
    vars[vp++] = t.error & 0xFF;
    vars[vp++] = 0;
    vars[vp++] = 0; /* other len = 0 */
    /* Compute HMAC */
    unsigned int mlen = 0;
    uint8_t mac[64];
    EVP_MAC *evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!evp_mac) {
        free(tmp);
        return 0;
    }
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(evp_mac);
    if (!mctx) {
        EVP_MAC_free(evp_mac);
        free(tmp);
        return 0;
    }
    OSSL_PARAM params[2];
    const char *digest = tsig_alg_to_digest(t.alg_name);
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *) digest, 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_init(mctx, g_tsig_secret, g_tsig_secret_len, params);
    EVP_MAC_update(mctx, tmp, pkt_minus_tsig_len);
    EVP_MAC_update(mctx, vars, vp);
    free(tmp);
    size_t ml2 = 64;
    EVP_MAC_final(mctx, mac, &ml2, sizeof(mac));
    mlen = (unsigned) ml2;
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(evp_mac);
    int ok = (mlen == (unsigned) t.mac_len) && (memcmp(mac, t.mac, mlen) == 0);
    if (ok && t.mac_len > 0 && t.mac_len <= (int) sizeof(g_tsig_req_mac)) {
        memcpy(g_tsig_req_mac, t.mac, t.mac_len);
        g_tsig_req_mac_len = t.mac_len;
    }
    return ok;
}

/* Append TSIG RR to a response */
static int tsig_append(uint8_t *buf, int off, int blen, uint16_t orig_id, uint16_t error) {
    if (g_tsig_secret_len == 0)
        return off;
    /* Build TSIG variables for signing */
    time_t now = time(NULL);
    uint8_t vars[512];
    int vp = 0;
    /* key name wire */
    {
        char *sp6 = NULL;
        char tmp[256];
        safe_strcpy(tmp, g_tsig_key_name, sizeof(tmp));
        char *lbl = strtok_r(tmp, ".", &sp6);
        while (lbl) {
            int ll = (int) strlen(lbl);
            vars[vp++] = (uint8_t) ll;
            memcpy(vars + vp, lbl, ll);
            vp += ll;
            lbl = strtok_r(NULL, ".", &sp6);
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
    vars[vp++] = error >> 8;
    vars[vp++] = error & 0xFF;
    vars[vp++] = 0;
    vars[vp++] = 0;
    unsigned int mlen = 64;
    uint8_t mac[64];
    {
        EVP_MAC *evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(evp_mac);
        OSSL_PARAM params[2];
        const char *digest = tsig_alg_to_digest(g_tsig_key_name);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *) digest, 0);
        params[1] = OSSL_PARAM_construct_end();
        EVP_MAC_init(mctx, g_tsig_secret, g_tsig_secret_len, params);
        /* RFC 8945 §5.4.2: response MACs prepend the request's MAC (length-prefixed). */
        if (g_tsig_req_mac_len > 0) {
            uint8_t pre[2] = {(uint8_t) (g_tsig_req_mac_len >> 8),
                              (uint8_t) (g_tsig_req_mac_len & 0xFF)};
            EVP_MAC_update(mctx, pre, 2);
            EVP_MAC_update(mctx, g_tsig_req_mac, g_tsig_req_mac_len);
        }
        EVP_MAC_update(mctx, buf, off);
        EVP_MAC_update(mctx, vars, vp);
        size_t ml2 = 64;
        EVP_MAC_final(mctx, mac, &ml2, sizeof(mac));
        mlen = (unsigned) ml2;
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(evp_mac);
        g_tsig_req_mac_len = 0; /* consumed — clear so a stray future call won't reuse it */
    }
    /* Encode TSIG RR */
    if (off + 200 > blen)
        return off;
    /* key name */
    {
        char *sp7 = NULL;
        char tmp[256];
        safe_strcpy(tmp, g_tsig_key_name, sizeof(tmp));
        char *lbl = strtok_r(tmp, ".", &sp7);
        while (lbl) {
            int ll = (int) strlen(lbl);
            buf[off++] = (uint8_t) ll;
            memcpy(buf + off, lbl, ll);
            off += ll;
            lbl = strtok_r(NULL, ".", &sp7);
        }
        buf[off++] = 0;
    }
    buf[off++] = 0;
    buf[off++] = 250; /* type TSIG=250 */
    buf[off++] = 0;
    buf[off++] = 255; /* class ANY */
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0; /* ttl=0 */
    /* RDATA: alg name + time + fudge + mac len + mac + orig_id + error + other */
    uint8_t rdata[200];
    int rp = 0;
    memcpy(rdata + rp, alg_wire, 13);
    rp += 13;
    rdata[rp++] = 0;
    rdata[rp++] = 0; /* time high */
    rdata[rp++] = (uint8_t) ((now >> 24) & 0xFF);
    rdata[rp++] = (uint8_t) ((now >> 16) & 0xFF);
    rdata[rp++] = (uint8_t) ((now >> 8) & 0xFF);
    rdata[rp++] = (uint8_t) (now & 0xFF);
    rdata[rp++] = TSIG_FUDGE >> 8;
    rdata[rp++] = TSIG_FUDGE & 0xFF;
    rdata[rp++] = (uint8_t) (mlen >> 8);
    rdata[rp++] = (uint8_t) (mlen & 0xFF);
    memcpy(rdata + rp, mac, mlen);
    rp += mlen;
    rdata[rp++] = orig_id >> 8;
    rdata[rp++] = orig_id & 0xFF;
    rdata[rp++] = error >> 8;
    rdata[rp++] = error & 0xFF;
    rdata[rp++] = 0;
    rdata[rp++] = 0; /* other len=0 */
    buf[off++] = 0;
    buf[off++] = (uint8_t) rp;
    memcpy(buf + off, rdata, rp);
    off += rp;
    /* Increment arcount */
    dns_hdr_t *rh = (dns_hdr_t *) buf;
    rh->arcount = htons(ntohs(rh->arcount) + 1);
    return off;
}

/* ==========================================================================
 * TSIG AXFR multi-message MAC chaining (RFC 8945 §5.3.1)
 * ======================================================================= */

/* Init HMAC context keyed with g_tsig_secret.  Caller frees ctx + em. */
static EVP_MAC_CTX *tsig_hmac_new(EVP_MAC **em_out) {
    EVP_MAC *em = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!em)
        return NULL;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(em);
    if (!ctx) {
        EVP_MAC_free(em);
        return NULL;
    }
    OSSL_PARAM p[2];
    const char *dg = tsig_alg_to_digest(g_tsig_key_name);
    p[0] = OSSL_PARAM_construct_utf8_string("digest", (char *) dg, 0);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, g_tsig_secret, g_tsig_secret_len, p) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(em);
        return NULL;
    }
    *em_out = em;
    return ctx;
}

/* Feed [2-byte mac_len || mac] into ctx for RFC 8945 MAC chaining. */
static void tsig_hmac_prepend(EVP_MAC_CTX *ctx, const uint8_t *mac, int mlen) {
    if (mlen <= 0)
        return;
    uint8_t pre[2] = {(uint8_t) (mlen >> 8), (uint8_t) (mlen & 0xFF)};
    EVP_MAC_update(ctx, pre, 2);
    EVP_MAC_update(ctx, mac, mlen);
}

/* Encode TSIG signing variables into vars[512].  Returns byte count. */
static int tsig_vars_build(uint8_t vars[512], time_t now, uint16_t error) {
    int vp = 0;
    {
        char *sp8 = NULL;
        char tmp[256];
        safe_strcpy(tmp, g_tsig_key_name, sizeof(tmp));
        char *l = strtok_r(tmp, ".", &sp8);
        while (l) {
            int ll = (int) strlen(l);
            vars[vp++] = (uint8_t) ll;
            memcpy(vars + vp, l, ll);
            vp += ll;
            l = strtok_r(NULL, ".", &sp8);
        }
        vars[vp++] = 0;
    }
    vars[vp++] = 0;
    vars[vp++] = 255;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0;
    const char *aw = "\x0bhmac-sha256\x00";
    memcpy(vars + vp, aw, 13);
    vp += 13;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = (uint8_t) ((now >> 24) & 0xFF);
    vars[vp++] = (uint8_t) ((now >> 16) & 0xFF);
    vars[vp++] = (uint8_t) ((now >> 8) & 0xFF);
    vars[vp++] = (uint8_t) (now & 0xFF);
    vars[vp++] = 0;
    vars[vp++] = 5;
    vars[vp++] = error >> 8;
    vars[vp++] = error & 0xFF;
    vars[vp++] = 0;
    vars[vp++] = 0;
    return vp;
}

/* Write a TSIG RR into buf at off; increments arcount.  Returns updated off. */
static int tsig_rr_write(uint8_t *buf, int off, int blen, uint16_t orig_id, uint16_t error,
                         time_t now, const uint8_t *mac, int mlen) {
    if (off + 200 > blen)
        return off;
    const char *aw = "\x0bhmac-sha256\x00";
    {
        char *sp9 = NULL;
        char tmp[256];
        safe_strcpy(tmp, g_tsig_key_name, sizeof(tmp));
        char *l = strtok_r(tmp, ".", &sp9);
        while (l) {
            int ll = (int) strlen(l);
            buf[off++] = (uint8_t) ll;
            memcpy(buf + off, l, ll);
            off += ll;
            l = strtok_r(NULL, ".", &sp9);
        }
        buf[off++] = 0;
    }
    buf[off++] = 0;
    buf[off++] = 250;
    buf[off++] = 0;
    buf[off++] = 255;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    uint8_t rd[200];
    int rp = 0;
    memcpy(rd + rp, aw, 13);
    rp += 13;
    rd[rp++] = 0;
    rd[rp++] = 0;
    rd[rp++] = (uint8_t) ((now >> 24) & 0xFF);
    rd[rp++] = (uint8_t) ((now >> 16) & 0xFF);
    rd[rp++] = (uint8_t) ((now >> 8) & 0xFF);
    rd[rp++] = (uint8_t) (now & 0xFF);
    rd[rp++] = 0;
    rd[rp++] = 5;
    rd[rp++] = (uint8_t) (mlen >> 8);
    rd[rp++] = (uint8_t) (mlen & 0xFF);
    memcpy(rd + rp, mac, mlen);
    rp += mlen;
    rd[rp++] = orig_id >> 8;
    rd[rp++] = orig_id & 0xFF;
    rd[rp++] = error >> 8;
    rd[rp++] = error & 0xFF;
    rd[rp++] = 0;
    rd[rp++] = 0;
    buf[off++] = 0;
    buf[off++] = (uint8_t) rp;
    memcpy(buf + off, rd, rp);
    off += rp;
    ((dns_hdr_t *) buf)->arcount = htons(ntohs(((dns_hdr_t *) buf)->arcount) + 1);
    return off;
}

/* Sign and append TSIG to the first AXFR/IXFR response message.
 * Prepends the verified request MAC (g_tsig_req_mac) per §5.4.2.
 * Stores the computed MAC in out_mac[]/out_mac_len for subsequent chaining.
 * No-op (returns off unchanged) if TSIG not configured or request had no TSIG. */
static int tsig_axfr_first(uint8_t *buf, int off, int blen, uint16_t qid, uint8_t out_mac[64],
                           int *out_mac_len) {
    *out_mac_len = 0;
    if (g_tsig_secret_len == 0 || g_tsig_req_mac_len == 0)
        return off;
    time_t now = time(NULL);
    uint8_t vars[512];
    int vp = tsig_vars_build(vars, now, 0);
    EVP_MAC *em;
    EVP_MAC_CTX *ctx = tsig_hmac_new(&em);
    if (!ctx)
        return off;
    tsig_hmac_prepend(ctx, g_tsig_req_mac, g_tsig_req_mac_len);
    EVP_MAC_update(ctx, buf, off);
    EVP_MAC_update(ctx, vars, vp);
    size_t ml = 64;
    EVP_MAC_final(ctx, out_mac, &ml, 64);
    *out_mac_len = (int) ml;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(em);
    g_tsig_req_mac_len = 0;
    return tsig_rr_write(buf, off, blen, qid, 0, now, out_mac, *out_mac_len);
}

/* Update MAC chain for an intermediate AXFR/IXFR message (no TSIG RR emitted).
 * Computes HMAC([prior_mac_len||prior_mac||msg_bytes]) and updates prior_mac.
 * No-op if chaining not active (out_mac_len==0). */
static void tsig_axfr_mid(const uint8_t *msg, int msg_len, uint8_t prior_mac[64],
                          int *prior_mac_len) {
    if (g_tsig_secret_len == 0 || *prior_mac_len == 0)
        return;
    EVP_MAC *em;
    EVP_MAC_CTX *ctx = tsig_hmac_new(&em);
    if (!ctx)
        return;
    tsig_hmac_prepend(ctx, prior_mac, *prior_mac_len);
    EVP_MAC_update(ctx, msg, msg_len);
    size_t ml = 64;
    uint8_t mac[64];
    EVP_MAC_final(ctx, mac, &ml, 64);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(em);
    memcpy(prior_mac, mac, (size_t) ml);
    *prior_mac_len = (int) ml;
}

/* Sign and append TSIG to the final AXFR/IXFR message using the chained MAC.
 * No-op if chaining not active (prior_mac_len==0). Returns updated off. */
static int tsig_axfr_last(uint8_t *buf, int off, int blen, uint16_t qid, const uint8_t *prior_mac,
                          int prior_mac_len) {
    if (g_tsig_secret_len == 0 || prior_mac_len == 0)
        return off;
    time_t now = time(NULL);
    uint8_t vars[512];
    int vp = tsig_vars_build(vars, now, 0);
    EVP_MAC *em;
    EVP_MAC_CTX *ctx = tsig_hmac_new(&em);
    if (!ctx)
        return off;
    tsig_hmac_prepend(ctx, prior_mac, prior_mac_len);
    EVP_MAC_update(ctx, buf, off);
    EVP_MAC_update(ctx, vars, vp);
    size_t ml = 64;
    uint8_t mac[64];
    EVP_MAC_final(ctx, mac, &ml, 64);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(em);
    return tsig_rr_write(buf, off, blen, qid, 0, now, mac, (int) ml);
}

/* ==========================================================================
 * DNS wire helpers
 * ======================================================================= */

static const char *type2str(uint16_t t) {
    switch (t) {
        case DNS_TYPE_A:
            return "A";
        case DNS_TYPE_NS:
            return "NS";
        case DNS_TYPE_CNAME:
            return "CNAME";
        case DNS_TYPE_SOA:
            return "SOA";
        case DNS_TYPE_MX:
            return "MX";
        case DNS_TYPE_TXT:
            return "TXT";
        case DNS_TYPE_AAAA:
            return "AAAA";
        case DNS_TYPE_LOC:
            return "LOC";
        case DNS_TYPE_SRV:
            return "SRV";
        case DNS_TYPE_DNAME:
            return "DNAME";
        case DNS_TYPE_SSHFP:
            return "SSHFP";
        case DNS_TYPE_RRSIG:
            return "RRSIG";
        case DNS_TYPE_NSEC:
            return "NSEC";
        case DNS_TYPE_DNSKEY:
            return "DNSKEY";
        case DNS_TYPE_NSEC3:
            return "NSEC3";
        case DNS_TYPE_TLSA:
            return "TLSA";
        case DNS_TYPE_DS:
            return "DS";
        case DNS_TYPE_CAA:
            return "CAA";
        case DNS_TYPE_CDS:
            return "CDS";
        case DNS_TYPE_CDNSKEY:
            return "CDNSKEY";
        case DNS_TYPE_URI:
            return "URI";
        case DNS_TYPE_IXFR:
            return "IXFR";
        case DNS_TYPE_AXFR:
            return "AXFR";
        case DNS_TYPE_ANY:
            return "ANY";
        default:
            return "?";
    }
}

/* ==========================================================================
 * Response Rate Limiting (RRL)
 *
 * Protects against DNS amplification attacks by rate-limiting identical
 * (or similar) responses sent to the same client subnet (/24).
 *
 * Algorithm: token-bucket, refilled once per rrl_window seconds.
 *   - Key: (client /24 network address) XOR (qname hash)
 *   - Each key gets rrl_rate tokens per window.
 *   - When tokens reach 0: either drop the response (slip=1) or send a
 *     truncated (TC) response every rrl_slip-th request so legitimate
 *     TCP-capable clients can retry over TCP.
 *
 * config:rrl_enabled   "1" to enable (default: 0)
 * config:rrl_rate      max responses per window per source/name (default: 5)
 * config:rrl_window    token refill interval in seconds (default: 1)
 * config:rrl_slip      1 = always drop; N>1 = send TC every N-th (default: 2)
 *
 * Table size: 4096 buckets (power-of-two for cheap masking).
 * ======================================================================= */
#define RRL_BUCKETS 4096
#define RRL_BUCKET_MASK (RRL_BUCKETS - 1)

typedef struct {
    uint32_t key;          /* (src /24 addr) ^ (qname hash) */
    int32_t tokens;        /* current token count */
    time_t last_refill;    /* last refill timestamp */
    uint32_t slip_counter; /* counts drops to implement slip */
} rrl_entry_t;

static rrl_entry_t g_rrl[RRL_BUCKETS];
static pthread_mutex_t g_rrl_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * rrl_check — returns 0 if the packet should be sent normally,
 *             1 if it should be dropped,
 *             2 if it should be sent as TC-only (truncated, no answers).
 */
static int rrl_check(const struct in_addr *cip, const char *qname) {
    if (!g_rrl_enabled)
        return 0;
    /* Key: hash of /24 address XOR djb2 hash of qname */
    uint32_t addr24 = ntohl(cip->s_addr) & 0xFFFFFF00u;
    uint32_t qhash = 5381u;
    for (const char *p = qname; *p; p++)
        qhash = ((qhash << 5) + qhash) + (uint8_t) *p;
    uint32_t key = addr24 ^ qhash;
    uint32_t idx = (key ^ (key >> 16)) & RRL_BUCKET_MASK;
    pthread_mutex_lock(&g_rrl_mutex);
    rrl_entry_t *e = &g_rrl[idx];
    time_t now = time(NULL);
    /* Collision: different key resets the bucket */
    if (e->key != key) {
        e->key = key;
        e->tokens = g_rrl_rate;
        e->last_refill = now;
        e->slip_counter = 0;
    }
    /* Refill tokens if window has passed */
    if (now - e->last_refill >= g_rrl_window) {
        e->tokens = g_rrl_rate;
        e->last_refill = now;
    }
    int result = 0;
    if (e->tokens > 0) {
        e->tokens--;
    } else {
        e->slip_counter++;
        if (g_rrl_slip > 1 && (e->slip_counter % (uint32_t) g_rrl_slip) == 0)
            result = 2; /* send TC */
        else
            result = 1; /* drop */
    }
    pthread_mutex_unlock(&g_rrl_mutex);
    return result;
}

/* ==========================================================================
 * SOA record builder
 * ======================================================================= */
static int build_soa_rdata(uint8_t *rd, int rdlen) {
    /* Emit SOA for the current request's zone (t_zone), falling back to the
     * legacy single-zone globals when no zone has been selected. */
    const char *mname = (t_zone && t_zone->soa_mname[0]) ? t_zone->soa_mname : g_soa_mname;
    const char *rname = (t_zone && t_zone->soa_rname[0]) ? t_zone->soa_rname : g_soa_rname;
    int pos = 0;
    int n = name_to_wire(mname, rd, rdlen);
    if (n < 0)
        return -1;
    pos += n;
    n = name_to_wire(rname, rd + pos, rdlen - pos);
    if (n < 0)
        return -1;
    pos += n;
    if (pos + 20 > rdlen)
        return -1;
    pthread_mutex_lock(&g_soa_mutex);
    put32(rd, pos, t_zone ? t_zone->soa_serial : g_soa_serial);
    pos += 4;
    put32(rd, pos, t_zone ? t_zone->soa_refresh : g_soa_refresh);
    pos += 4;
    put32(rd, pos, t_zone ? t_zone->soa_retry : g_soa_retry);
    pos += 4;
    put32(rd, pos, t_zone ? t_zone->soa_expire : g_soa_expire);
    pos += 4;
    put32(rd, pos, t_zone ? t_zone->soa_minimum : g_soa_minimum);
    pos += 4;
    pthread_mutex_unlock(&g_soa_mutex);
    return pos;
}

/* SOA minimum TTL for the current zone (used for negative-cache TTLs). */
static uint32_t zone_soa_minimum(void) {
    return t_zone ? t_zone->soa_minimum : g_soa_minimum;
}

/* ==========================================================================
 * EDNS(0) parsing and response building
 * ======================================================================= */
typedef struct {
    int present;
    uint16_t max_udp;
    uint8_t version;
    int do_bit;
    uint8_t client_cookie[8];
    int has_client_cookie;
    uint8_t server_cookie[16]; /* RFC 9018: up to 16 bytes */
    int server_cookie_len;
    int has_server_cookie;
    char nsid_req; /* 1 if client requested NSID */
    int has_padding;
    uint16_t padding_req;
    int keepalive_req;
} edns_info_t;

static void edns_parse(const uint8_t *pkt, int plen, edns_info_t *ei) {
    memset(ei, 0, sizeof(*ei));
    ei->max_udp = 512;
    const dns_hdr_t *h = (const dns_hdr_t *) pkt;
    if (ntohs(h->arcount) == 0)
        return;
    /* Scan additional section for OPT */
    int off = 12;
    int skip = ntohs(h->qdcount) + ntohs(h->ancount) + ntohs(h->nscount) + ntohs(h->arcount);
    (void) skip;
    /* Quick scan: skip q/an/ns sections */
    for (int s = 0; s < 3; s++) {
        int cnt = s == 0 ? ntohs(h->qdcount) : (s == 1 ? ntohs(h->ancount) : ntohs(h->nscount));
        for (int i = 0; i < cnt; i++) {
            for (;;) {
                if (off >= plen)
                    return;
                uint8_t c = pkt[off];
                if ((c & 0xC0) == 0xC0) {
                    off += 2;
                    break;
                }
                if (c == 0) {
                    off++;
                    break;
                }
                off += c + 1;
            }
            if (s == 0) {
                off += 4;
            } else {
                if (off + 10 > plen)
                    return;
                uint16_t rdl = get16(pkt, off + 8);
                off += 10 + rdl;
            }
        }
    }
    for (int i = 0; i < ntohs(h->arcount); i++) {
        if (off >= plen)
            break;
        int name_start = off;
        (void) name_start;
        for (;;) {
            if (off >= plen)
                return;
            uint8_t c = pkt[off];
            if ((c & 0xC0) == 0xC0) {
                off += 2;
                break;
            }
            if (c == 0) {
                off++;
                break;
            }
            off += c + 1;
        }
        if (off + 10 > plen)
            break;
        uint16_t rtype = get16(pkt, off);
        if (rtype == DNS_TYPE_OPT) {
            ei->present = 1;
            ei->max_udp = get16(pkt, off + 2);
            ei->version = pkt[off + 5];
            ei->do_bit = (pkt[off + 4] & 0x80) ? 1 : 0;
            uint16_t rdlen = get16(pkt, off + 8);
            int rp = off + 10;
            while (rp + 4 <= off + 10 + rdlen && rp + 4 <= plen) {
                uint16_t oc = get16(pkt, rp), ol = get16(pkt, rp + 2);
                rp += 4;
                if (oc == EDNS_OPT_NSID) {
                    ei->nsid_req = 1;
                } else if (oc == EDNS_OPT_COOKIE && ol >= 8) {
                    if (rp + ol <= plen) {
                        memcpy(ei->client_cookie, pkt + rp, 8);
                        ei->has_client_cookie = 1;
                        /* RFC 9018: server cookie is the bytes after the 8-byte
                         * client cookie, length 8..32.  Capture for verification. */
                        if (ol > 8 && ol <= 8 + (int) sizeof(ei->server_cookie)) {
                            int slen = ol - 8;
                            memcpy(ei->server_cookie, pkt + rp + 8, slen);
                            ei->server_cookie_len = slen;
                            ei->has_server_cookie = 1;
                        }
                    }
                } else if (oc == EDNS_OPT_KEEPALIVE) {
                    ei->keepalive_req = 1;
                } else if (oc == EDNS_OPT_PADDING) {
                    ei->has_padding = 1;
                    ei->padding_req = ol;
                }
                rp += ol;
            }
            break;
        }
        uint16_t rdlen = get16(pkt, off + 8);
        off += 10 + rdlen;
    }
}

/* Append an EDNS OPT RR to the response */
static int edns_append_opt(uint8_t *buf, int off, int blen, int is_tcp, int do_bit,
                           uint16_t rcode_ext, const edns_info_t *req_ei, const struct in_addr *cip,
                           int ede_code, const char *ede_text) {
    if (off + 11 > blen)
        return off;
    /* Name = root (1 byte 0) */
    buf[off++] = 0;
    /* type = OPT */
    buf[off++] = 0;
    buf[off++] = 41;
    /* class = max UDP payload */
    uint16_t maxudp = is_tcp ? 65535 : EDNS_MAX_UDP;
    buf[off++] = maxudp >> 8;
    buf[off++] = maxudp & 0xFF;
    /* Extended RCODE (top 8 bits) | version=0 | DO bit | Z */
    buf[off++] = rcode_ext & 0xFF;
    buf[off++] = 0;
    buf[off++] = do_bit ? 0x80 : 0x00;
    buf[off++] = 0;
    /* RDATA: options */
    int rdata_off = off + 2;
    int rdata_len = 0;
    if (off + 2 > blen)
        return off;
    /* NSID option */
    if (req_ei && req_ei->nsid_req && g_nsid[0]) {
        int nsid_len = (int) strlen(g_nsid);
        if (rdata_off + 4 + nsid_len < blen) {
            put16(buf, rdata_off, EDNS_OPT_NSID);
            put16(buf, rdata_off + 2, (uint16_t) nsid_len);
            memcpy(buf + rdata_off + 4, g_nsid, nsid_len);
            rdata_off += 4 + nsid_len;
            rdata_len += 4 + nsid_len;
        }
    }
    /* Cookie option */
    if (req_ei && req_ei->has_client_cookie) {
        if (rdata_off + 4 + DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN < blen) {
            uint8_t scookie[DNS_COOKIE_SERVER_LEN];
            struct in_addr zero = {0};
            const struct in_addr *use_ip = cip ? cip : &zero;
            compute_server_cookie(req_ei->client_cookie, use_ip, (uint32_t) time(NULL), scookie);
            put16(buf, rdata_off, EDNS_OPT_COOKIE);
            put16(buf, rdata_off + 2, DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN);
            memcpy(buf + rdata_off + 4, req_ei->client_cookie, DNS_COOKIE_CLIENT_LEN);
            memcpy(buf + rdata_off + 4 + DNS_COOKIE_CLIENT_LEN, scookie, DNS_COOKIE_SERVER_LEN);
            int total = 4 + DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN;
            rdata_off += total;
            rdata_len += total;
        }
    }
    /* TCP keepalive: suggest 30s */
    if (is_tcp && req_ei && req_ei->keepalive_req) {
        if (rdata_off + 6 < blen) {
            put16(buf, rdata_off, EDNS_OPT_KEEPALIVE);
            put16(buf, rdata_off + 2, 2);
            put16(buf, rdata_off + 4, 300); /* 30s in units of 100ms */
            rdata_off += 6;
            rdata_len += 6;
        }
    }
    /* EDE option */
    if (ede_code >= 0) {
        int tlen = ede_text ? (int) strlen(ede_text) : 0;
        if (rdata_off + 4 + 2 + tlen < blen) {
            put16(buf, rdata_off, EDNS_OPT_EDE);
            put16(buf, rdata_off + 2, (uint16_t) (2 + tlen));
            put16(buf, rdata_off + 4, (uint16_t) ede_code);
            if (tlen)
                memcpy(buf + rdata_off + 6, ede_text, tlen);
            rdata_off += 4 + 2 + tlen;
            rdata_len += 4 + 2 + tlen;
        }
    }
    /* RFC 7830 / RFC 8467: pad encrypted-transport (DoT/DoH) responses.
     *   - If client requested padding (has_padding): honour with 128-byte blocks
     *     (common DNS-over-TLS client convention).
     *   - Always pad on is_tcp to a multiple of 468 bytes (RFC 8467 §4
     *     recommended block size), which hides response size from observers
     *     even when the client did not explicitly request padding. */
    if (is_tcp) {
        /* Choose block size: honour client request (128) or use RFC 8467 default (468) */
        int block = (req_ei && req_ei->has_padding) ? 128 : 468;
        /* Current total wire size of the response if we wrote the OPT RR now */
        int cur = off + 2 + rdata_len + 4; /* +4 = OPT RR owner+type+class+ttl prefix */
        int pad = block - ((cur) % block);
        if (pad == block)
            pad = 0; /* already on a block boundary */
        if (pad > 0 && rdata_off + 4 + pad < blen) {
            put16(buf, rdata_off, EDNS_OPT_PADDING);
            put16(buf, rdata_off + 2, (uint16_t) pad);
            memset(buf + rdata_off + 4, 0, pad);
            rdata_off += 4 + pad;
            rdata_len += 4 + pad;
        }
    }
    /* Write RDLEN */
    put16(buf, off, (uint16_t) rdata_len);
    off = rdata_off;
    /* Increment arcount */
    dns_hdr_t *rh = (dns_hdr_t *) buf;
    rh->arcount = htons(ntohs(rh->arcount) + 1);
    return off;
}

/* ==========================================================================
 * DNS Cookie verification (RFC 9018)
 *   Returns 1  = cookie ok (or no cookie present — unenforced).
 *           0  = BADCOOKIE; caller must respond with rcode 23 plus a fresh
 *                server cookie so the client can retry.
 *
 * Policy: clients that opt into cookies are required to complete the
 * handshake. A client sending only the client cookie triggers BADCOOKIE so
 * the server can return a freshly minted server cookie; the client then
 * replays with both halves and the server validates the MAC + timestamp.
 * Clients that don't send any cookie are unaffected.
 * ======================================================================= */
static int cookie_verify(const edns_info_t *ei, const struct in_addr *cip) {
    if (!ei->has_client_cookie)
        return 1; /* no cookie, no requirement */
    if (!ei->has_server_cookie)
        return 0; /* client must echo our server cookie */
    if (ei->server_cookie_len != DNS_COOKIE_SERVER_LEN)
        return 0;
    uint32_t ts = ((uint32_t) ei->server_cookie[4] << 24) |
                  ((uint32_t) ei->server_cookie[5] << 16) | ((uint32_t) ei->server_cookie[6] << 8) |
                  ei->server_cookie[7];
    uint32_t now = (uint32_t) time(NULL);
    if (ts > now || now - ts > DNS_COOKIE_VALIDITY)
        return 0; /* stale or future-dated */
    uint8_t expected[DNS_COOKIE_SERVER_LEN];
    compute_server_cookie(ei->client_cookie, cip, ts, expected);
    return memcmp(expected, ei->server_cookie, DNS_COOKIE_SERVER_LEN) == 0;
}

/* Forward declaration needed by NSEC functions */
static int emit_rr(uint8_t *resp, int off, int resp_len, const char *name, uint16_t type,
                   uint32_t ttl, const uint8_t *rdata, uint16_t rdlen, int dnssec_ok, int *answers);

/* ==========================================================================
 * NSEC plain denial (RFC 4034) — alternative to NSEC3
 *
 * Simple NSEC: owner name = qname, next name = next label in zone (we use
 * zone apex as a simplification for a single-zone server).
 * Bitmap covers the types we actually serve.
 * ======================================================================= */
static int nsec_rdata(const char *qname, uint8_t *rd, int rdlen) {
    (void) qname;
    /* Next owner name = zone apex */
    int pos = name_to_wire(t_zone ? t_zone->name : g_zone_name, rd, rdlen);
    if (pos < 0)
        return -1;
    /* Type bitmap window 0: build bitmap for common types */
    uint8_t bitmap[32] = {0};
    uint16_t types[] = {DNS_TYPE_A,      DNS_TYPE_NS,   DNS_TYPE_CNAME, DNS_TYPE_SOA,
                        DNS_TYPE_MX,     DNS_TYPE_TXT,  DNS_TYPE_AAAA,  DNS_TYPE_SRV,
                        DNS_TYPE_DNSKEY, DNS_TYPE_NSEC, DNS_TYPE_RRSIG, 0};
    int max_bit = 0;
    for (int i = 0; types[i]; i++) {
        int b = types[i] & 0xFF;
        bitmap[b / 8] |= (1 << (7 - (b % 8)));
        if (b > max_bit)
            max_bit = b;
    }
    int blen = (max_bit / 8) + 1;
    if (pos + 2 + blen > rdlen)
        return -1;
    rd[pos++] = 0; /* window block 0 */
    rd[pos++] = (uint8_t) blen;
    memcpy(rd + pos, bitmap, blen);
    pos += blen;
    return pos;
}

static int add_nsec_denial(uint8_t *resp, int off, int resp_len, const char *qname, int dnssec_ok,
                           int *auth_count) {
    uint8_t rd[512];
    int rdlen = nsec_rdata(qname, rd, sizeof(rd));
    if (rdlen < 0)
        return off;
    off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_NSEC, zone_soa_minimum(), rd,
                  (uint16_t) rdlen, dnssec_ok, auth_count);
    return off;
}

/* ==========================================================================
 * Query response builder
 * ======================================================================= */
static int emit_rr(uint8_t *resp, int off, int resp_len, const char *name, uint16_t type,
                   uint32_t ttl, const uint8_t *rdata, uint16_t rdlen, int dnssec_ok,
                   int *answers) {
    ttl = ttl_clamp(ttl); /* RFC 2181 §8 */
    int noff = append_rr(resp, off, resp_len, name, type, DNS_CLASS_IN, ttl, rdata, rdlen);
    if (noff < 0)
        return off;
    (*answers)++;
    off = noff;
    if (!dnssec_ok || !t_zone || !t_zone->zsk)
        return off;
    /* During a rollover's commit phase the incoming ("next") ZSK set is the
     * active signer (RFC 6781 Pre-Publish); otherwise the current set signs. */
    int use_next = (t_zone->roll_phase == ROLL_COMMIT && t_zone->zsk_next);
    /* Add RRSIG for ECDSA P-256 (Alg 13) */
    STAT_INC(g_stat_signed);
    {
        pthread_mutex_lock(&g_zsk_mutex);
        EVP_PKEY *zsk = use_next ? t_zone->zsk_next : t_zone->zsk;
        uint16_t tag = use_next ? t_zone->zsk_next_tag : t_zone->zsk_tag;
        pthread_mutex_unlock(&g_zsk_mutex);
        if (zsk) {
            uint8_t sig[512];
            int sl =
                make_rrsig(name, type, ttl, rdata, rdlen, zsk, DNS_ALG_ECDSAP256SHA256, tag, sig);
            if (sl > 0) {
                int so = append_rr(resp, off, resp_len, name, DNS_TYPE_RRSIG, DNS_CLASS_IN, ttl,
                                   sig, (uint16_t) sl);
                if (so > 0) {
                    off = so;
                    (*answers)++;
                }
            }
        }
    }
    /* Add RRSIG for Ed25519 (Alg 15) */
    {
        pthread_mutex_lock(&g_zsk_mutex);
        EVP_PKEY *zsk = use_next ? t_zone->zsk_ed_next : t_zone->zsk_ed;
        uint16_t tag = use_next ? t_zone->zsk_ed_next_tag : t_zone->zsk_ed_tag;
        pthread_mutex_unlock(&g_zsk_mutex);
        if (zsk) {
            uint8_t sig[512];
            int sl = make_rrsig(name, type, ttl, rdata, rdlen, zsk, DNS_ALG_ED25519, tag, sig);
            if (sl > 0) {
                int so = append_rr(resp, off, resp_len, name, DNS_TYPE_RRSIG, DNS_CLASS_IN, ttl,
                                   sig, (uint16_t) sl);
                if (so > 0) {
                    off = so;
                    (*answers)++;
                }
            }
        }
    }
    return off;
}

/* Add SOA to authority section (RFC 2308 negative caching) */
static int add_soa_authority(uint8_t *resp, int off, int resp_len, int dnssec_ok, int *auth_count) {
    uint8_t soa_rd[512];
    int soa_len = build_soa_rdata(soa_rd, sizeof(soa_rd));
    if (soa_len < 0)
        return off;
    off = emit_rr(resp, off, resp_len, t_zone ? t_zone->name : g_zone_name, DNS_TYPE_SOA,
                  zone_soa_minimum(), soa_rd, (uint16_t) soa_len, dnssec_ok, auth_count);
    return off;
}

/* Add NSEC3 to authority for authenticated denial */
static int add_nsec3_denial(uint8_t *resp, int off, int resp_len, const char *qname, uint16_t qtype,
                            int dnssec_ok, int *auth_count) {
    uint8_t n3rd[256];
    int n3len = nsec3_rdata(qname, qtype, n3rd, sizeof(n3rd));
    if (n3len > 0) {
        /* NSEC3 owner name = base32hex_hash.zone */
        const char *zsalt = t_zone ? t_zone->nsec3_salt : g_nsec3_salt;
        int ziters = t_zone ? t_zone->nsec3_iters : g_nsec3_iters;
        uint8_t salt[16];
        int saltlen = 0;
        if (zsalt[0])
            saltlen = hex_dec(zsalt, salt, sizeof(salt));
        char hash[64];
        nsec3_hash_name(qname, salt, saltlen, ziters, hash, sizeof(hash));
        char nsec3_owner[512];
        snprintf(nsec3_owner, sizeof(nsec3_owner), "%s.%s", hash,
                 t_zone ? t_zone->name : g_zone_name);
        strlower(nsec3_owner);
        off = emit_rr(resp, off, resp_len, nsec3_owner, DNS_TYPE_NSEC3, zone_soa_minimum(), n3rd,
                      (uint16_t) n3len, dnssec_ok, auth_count);
    }
    return off;
}

static int build_query_resp(const uint8_t *query, int qlen, uint8_t *resp, int resp_len, int is_tcp,
                            const struct in_addr *cip) {
    if (qlen < 12)
        return -1;
    compress_reset();
    t_zone = NULL; /* selected after the qname is parsed (see below) */
    const dns_hdr_t *qh = (const dns_hdr_t *) query;
    dns_hdr_t *rh = (dns_hdr_t *) resp;
    /* RFC 9619 / 2181: QDCOUNT must be 1 for QUERY */
    if (ntohs(qh->qdcount) != 1) {
        rh->id = qh->id;
        rh->flags = htons(DNS_QR | DNS_RCODE_FORMERR);
        rh->qdcount = rh->ancount = rh->nscount = rh->arcount = 0;
        return 12;
    }
    STAT_INC(g_stat_queries);
    rh->id = qh->id;
    rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_NOERROR);
    rh->qdcount = htons(1);
    rh->ancount = rh->nscount = rh->arcount = 0;
    int off = 12;
    char qname[256] = {0};
    int after = name_from_wire(query, qlen, off, qname, sizeof(qname));
    if (after < 0 || after + 3 >= qlen)
        return -1;
    int qsec = after - off + 4;
    if (off + qsec > resp_len)
        return -1;
    memcpy(resp + off, query + off, qsec);
    uint16_t qtype = get16(query, after);
    off += qsec;
    edns_info_t ei;
    edns_parse(query, qlen, &ei);
    /* RFC 6891 §6.1.3: respond with BADVERS for any EDNS version != 0.
     * Extended rcode = 1 (value 16, low nibble 0 in header, high byte 1 in OPT). */
    if (ei.present && ei.version != 0) {
        rh->flags = htons(DNS_QR | DNS_AA | (DNS_RCODE_BADVERS & 0xF));
        rh->ancount = rh->nscount = htons(0);
        off = edns_append_opt(resp, off, resp_len, is_tcp, 0,
                              (uint16_t) ((DNS_RCODE_BADVERS >> 4) & 0xFF), &ei, cip, -1, NULL);
        return off;
    }
    if (!cookie_verify(&ei, cip)) {
        /* RFC 9018: emit BADCOOKIE with a fresh server cookie so the client
         * can retry.  Header rcode = low 4 bits of 23; OPT TTL carries the
         * high 8 bits per RFC 6891 §6.1.3. */
        rh->flags = htons(DNS_QR | DNS_AA | (DNS_RCODE_BADCOOKIE & 0xF));
        rh->ancount = rh->nscount = htons(0);
        off = edns_append_opt(resp, off, resp_len, is_tcp, 0,
                              (uint16_t) ((DNS_RCODE_BADCOOKIE >> 4) & 0xFF), &ei, cip, -1, NULL);
        dns_log(LOG_DEBUG, "[COOKIE] BADCOOKIE %s %s\n", type2str(qtype), qname);
        return off;
    }
    int dnssec_ok = ei.do_bit;
    /* RFC 1035 §4.3.1: return REFUSED for names outside our zone.
     * This prevents systemd-resolved (and other validators) from
     * caching false NXDOMAIN when they accidentally route public
     * names to us.  Locally-served zones (RFC 6303) are exempt. */
    {
        /* Multi-zone: pick the most specific configured zone for this qname.
         * t_zone drives SOA, NSEC/NSEC3 and DNSSEC signing for the whole
         * response below. */
        t_zone = zone_for_qname(qname);
        int in_zone = (t_zone != NULL);
        if (!in_zone && !is_local_zone(qname)) {
            rh->flags = htons(DNS_QR | DNS_RCODE_REFUSED);
            rh->qdcount = htons(1);
            /* Copy question section so the client knows which query was refused */
            int qsec2 = after - 12 + 4;
            if (12 + qsec2 <= resp_len) {
                memcpy(resp + 12, query + 12, qsec2);
                off = 12 + qsec2;
            } else
                off = 12;
            off = edns_append_opt(resp, off, resp_len, is_tcp, 0, 0, &ei, cip, EDE_NOT_AUTH,
                                  "Not authoritative for this zone");
            dns_log(LOG_DEBUG, "[REFUSED] %s %s\n", type2str(qtype), qname);
            STAT_INC(g_stat_refused);
            return off;
        }
    }
    int answers = 0, auth_count = 0, found = 0;
    int any_minimal = 0; /* RFC 8482: limit ANY responses */
    if (qtype == DNS_TYPE_ANY)
        any_minimal = 1;
    /* RFC 6303: locally served zones — answer authoritatively with NXDOMAIN+SOA */
    if (is_local_zone(qname) && qtype != DNS_TYPE_SOA && qtype != DNS_TYPE_NS) {
        /* These zones are authoritative here: return SOA for them, NXDOMAIN for children */
        rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_NXDOMAIN);
        off = add_soa_authority(resp, off, resp_len, dnssec_ok, &auth_count);
        rh->nscount = htons((uint16_t) auth_count);
        if (dnssec_ok) {
            int ac2 = 0;
            if (t_zone ? t_zone->dnssec_use_nsec3 : g_dnssec_use_nsec3)
                off = add_nsec3_denial(resp, off, resp_len, qname, qtype, dnssec_ok, &ac2);
            else
                off = add_nsec_denial(resp, off, resp_len, qname, dnssec_ok, &ac2);
            rh->nscount = htons(ntohs(rh->nscount) + (uint16_t) ac2);
        }
        off = edns_append_opt(resp, off, resp_len, is_tcp, dnssec_ok, 0, &ei, cip, EDE_NXDOMAIN,
                              "Locally served zone");
        return off;
    }
    /* DNSSEC signing keys for the matched zone (NULL for locally-served zones). */
    EVP_PKEY *g_zsk = t_zone ? t_zone->zsk : NULL;
    EVP_PKEY *g_zsk_ed = t_zone ? t_zone->zsk_ed : NULL;
    EVP_PKEY *g_ksk = t_zone ? t_zone->ksk : NULL;
    EVP_PKEY *g_ksk_ed = t_zone ? t_zone->ksk_ed : NULL;
    uint16_t g_ksk_tag = t_zone ? t_zone->ksk_tag : 0;
    uint16_t g_ksk_ed_tag = t_zone ? t_zone->ksk_ed_tag : 0;
    /* Incoming ZSK set published during a rollover (NULL otherwise). */
    int roll_active = (t_zone && t_zone->roll_phase != ROLL_NONE);
    EVP_PKEY *g_zsk_next = roll_active ? t_zone->zsk_next : NULL;
    EVP_PKEY *g_zsk_ed_next = roll_active ? t_zone->zsk_ed_next : NULL;
    /* DNSKEY — serve ZSK (flag 256) + KSK (flag 257), KSK signs DNSKEY RRset */
    if ((qtype == DNS_TYPE_DNSKEY || qtype == DNS_TYPE_ANY)) {
        uint8_t dkrd[68];
        /* ZSK P-256 — emit without RRSIG (ZSK signs other RRsets) */
        if (g_zsk && dnskey_rdata_ecdsa(g_zsk, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 68);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
        }
        /* ZSK Ed25519 */
        if (g_zsk_ed && dnskey_rdata_ed25519(g_zsk_ed, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 36);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
        }
        /* Rollover (RFC 6781 Pre-Publish): publish the incoming ZSK set
         * alongside the current one for the whole rollover, so a validator that
         * cached the old DNSKEY still sees it and a validator fetching the new
         * one already has the key the RRSIG keytag points at. */
        if (g_zsk_next && dnskey_rdata_ecdsa(g_zsk_next, dkrd, sizeof(dkrd)) > 0) {
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 68);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
        }
        if (g_zsk_ed_next && dnskey_rdata_ed25519(g_zsk_ed_next, dkrd, sizeof(dkrd)) > 0) {
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 36);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
        }
        /* KSK P-256 — emit then sign DNSKEY RRset with KSK */
        if (g_ksk && dnskey_rdata_ksk_ecdsa(g_ksk, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 68);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
            /* Sign DNSKEY with KSK */
            if (dnssec_ok) {
                uint8_t sig[512];
                int sl = make_rrsig(qname, DNS_TYPE_DNSKEY, 3600, dkrd, 68, g_ksk,
                                    DNS_ALG_ECDSAP256SHA256, g_ksk_tag, sig);
                if (sl > 0) {
                    int so = append_rr(resp, off, resp_len, qname, DNS_TYPE_RRSIG, DNS_CLASS_IN,
                                       3600, sig, (uint16_t) sl);
                    if (so > 0) {
                        off = so;
                        answers++;
                    }
                }
            }
        }
        /* KSK Ed25519 */
        if (g_ksk_ed && dnskey_rdata_ksk_ed25519(g_ksk_ed, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 36);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
            if (dnssec_ok) {
                uint8_t sig[512];
                int sl = make_rrsig(qname, DNS_TYPE_DNSKEY, 3600, dkrd, 36, g_ksk_ed,
                                    DNS_ALG_ED25519, g_ksk_ed_tag, sig);
                if (sl > 0) {
                    int so = append_rr(resp, off, resp_len, qname, DNS_TYPE_RRSIG, DNS_CLASS_IN,
                                       3600, sig, (uint16_t) sl);
                    if (so > 0) {
                        off = so;
                        answers++;
                    }
                }
            }
        }
        if (any_minimal && answers > 0)
            goto finish_answer;
    }
    /* RFC 7344: CDS (child DS) — same content as DNSKEY but type=CDS */
    if (qtype == DNS_TYPE_CDS || qtype == DNS_TYPE_ANY) {
        uint8_t dkrd[68];
        if (g_zsk && dnskey_rdata_ecdsa(g_zsk, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_CDS, 3600, dkrd, 68, dnssec_ok,
                          &answers);
        }
        if (g_zsk_ed && dnskey_rdata_ed25519(g_zsk_ed, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_CDNSKEY, 3600, dkrd, 36, dnssec_ok,
                          &answers);
        }
    }
    /* RFC 7344: CDNSKEY — same as DNSKEY but type=CDNSKEY */
    if (qtype == DNS_TYPE_CDNSKEY || qtype == DNS_TYPE_ANY) {
        uint8_t dkrd[68];
        if (g_zsk && dnskey_rdata_ecdsa(g_zsk, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_CDNSKEY, 3600, dkrd, 68, dnssec_ok,
                          &answers);
        }
        if (g_zsk_ed && dnskey_rdata_ed25519(g_zsk_ed, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_CDNSKEY, 3600, dkrd, 36, dnssec_ok,
                          &answers);
        }
    }
    /* RFC 4034 §5: DS — Delegation Signer over the zone's KSKs.
     * DS rdata = keytag(2) | alg(1) | digest_type=2(SHA-256)(1) |
     * sha256(owner_wire||dnskey_rdata)(32) Only emitted at the zone apex where our KSKs live. */
    if (qtype == DNS_TYPE_DS || qtype == DNS_TYPE_ANY) {
        uint8_t dkrd[68];
        /* P-256 KSK */
        if (g_ksk && dnskey_rdata_ksk_ecdsa(g_ksk, dkrd, sizeof(dkrd)) > 0) {
            uint8_t dsrd[4 + 32];
            dsrd[0] = g_ksk_tag >> 8;
            dsrd[1] = g_ksk_tag & 0xFF;
            dsrd[2] = DNS_ALG_ECDSAP256SHA256;
            dsrd[3] = 2; /* SHA-256 */
            uint8_t hin[512];
            int hp = name_to_wire(qname, hin, sizeof(hin));
            if (hp > 0 && hp + 68 <= (int) sizeof(hin)) {
                memcpy(hin + hp, dkrd, 68);
                sha256(hin, hp + 68, dsrd + 4);
                int n2 = emit_rr(resp, off, resp_len, qname, DNS_TYPE_DS, 3600, dsrd, 4 + 32,
                                 dnssec_ok, &answers);
                if (n2 > 0) {
                    off = n2;
                    found = 1;
                }
            }
        }
        /* Ed25519 KSK */
        if (g_ksk_ed && dnskey_rdata_ksk_ed25519(g_ksk_ed, dkrd, sizeof(dkrd)) > 0) {
            uint8_t dsrd[4 + 32];
            dsrd[0] = g_ksk_ed_tag >> 8;
            dsrd[1] = g_ksk_ed_tag & 0xFF;
            dsrd[2] = DNS_ALG_ED25519;
            dsrd[3] = 2; /* SHA-256 */
            uint8_t hin[512];
            int hp = name_to_wire(qname, hin, sizeof(hin));
            if (hp > 0 && hp + 36 <= (int) sizeof(hin)) {
                memcpy(hin + hp, dkrd, 36);
                sha256(hin, hp + 36, dsrd + 4);
                int n2 = emit_rr(resp, off, resp_len, qname, DNS_TYPE_DS, 3600, dsrd, 4 + 32,
                                 dnssec_ok, &answers);
                if (n2 > 0) {
                    off = n2;
                    found = 1;
                }
            }
        }
    }
    /* SOA at the zone apex (RFC 1035) — answer authoritatively from the
     * selected zone's SOA parameters. */
    if ((qtype == DNS_TYPE_SOA || qtype == DNS_TYPE_ANY) && t_zone &&
        streq_ci(qname, t_zone->name)) {
        uint8_t soa_rd[512];
        int soa_len = build_soa_rdata(soa_rd, sizeof(soa_rd));
        if (soa_len > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_SOA, zone_soa_minimum(), soa_rd,
                          (uint16_t) soa_len, dnssec_ok, &answers);
            if (any_minimal && answers > 0)
                goto finish_answer;
        }
    }
    /* Static zone */
    for (int i = 0; i < static_zone_sz; i++) {
        dns_rec_t *r = &static_zone[i];
        if (!streq_ci(r->name, qname))
            continue;
        found = 1;
        if (r->type != qtype && qtype != DNS_TYPE_ANY)
            continue;
        uint8_t rd[256];
        uint16_t rdlen = 0;
        switch (r->type) {
            case DNS_TYPE_A:
                memcpy(rd, r->rdata_a, 4);
                rdlen = 4;
                break;
            case DNS_TYPE_AAAA: {
                struct in6_addr a6;
                if (inet_pton(AF_INET6, r->rdata_str, &a6) != 1)
                    continue;
                memcpy(rd, &a6, 16);
                rdlen = 16;
                break;
            }
            case DNS_TYPE_CNAME:
            case DNS_TYPE_NS:
            case DNS_TYPE_DNAME: {
                int n = name_to_wire(r->rdata_str, rd, sizeof(rd));
                if (n < 0)
                    continue;
                rdlen = (uint16_t) n;
                break;
            }
            case DNS_TYPE_MX: {
                rd[0] = r->rdata_pref >> 8;
                rd[1] = r->rdata_pref & 0xFF;
                int n = name_to_wire(r->rdata_str, rd + 2, sizeof(rd) - 2);
                if (n < 0)
                    continue;
                rdlen = (uint16_t) (2 + n);
                break;
            }
            case DNS_TYPE_TXT: {
                int tl = txt_encode(r->rdata_str, rd, (int) sizeof(rd));
                if (tl < 0)
                    continue;
                rdlen = (uint16_t) tl;
                break;
            }
            default:
                continue;
        }
        off =
            emit_rr(resp, off, resp_len, r->name, r->type, r->ttl, rd, rdlen, dnssec_ok, &answers);
        if (any_minimal && answers > 0)
            goto finish_answer;
    }
    /* Dynamic A */
    if (qtype == DNS_TYPE_A || qtype == DNS_TYPE_ANY) {
        char val[128], k[768];
        dkey(k, sizeof(k), "A", qname);
        if (vk_get(k, val, sizeof(val))) {
            found = 1;
            struct in_addr a4;
            if (inet_pton(AF_INET, val, &a4) == 1) {
                uint8_t rd[4];
                memcpy(rd, &a4, 4);
                long tl = vk_ttl(k);
                if (tl < 1)
                    tl = 1;
                off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_A, (uint32_t) tl, rd, 4,
                              dnssec_ok, &answers);
            }
        }
        zkey(k, sizeof(k), "A", qname);
        if (vk_get(k, val, sizeof(val))) {
            found = 1;
            uint32_t ttl = DEFAULT_TTL;
            char *pipe = strchr(val, '|');
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                pipe++;
            } else
                pipe = val;
            char *sp12 = NULL;
            char *ip = strtok_r(pipe, "|", &sp12);
            while (ip) {
                struct in_addr a4;
                if (inet_pton(AF_INET, ip, &a4) == 1) {
                    uint8_t rd[4];
                    memcpy(rd, &a4, 4);
                    off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_A, ttl, rd, 4, dnssec_ok,
                                  &answers);
                }
                ip = strtok_r(NULL, "|", &sp12);
            }
        }
    }
    /* Dynamic AAAA */
    if (qtype == DNS_TYPE_AAAA || qtype == DNS_TYPE_ANY) {
        char val[256], k[768];
        dkey(k, sizeof(k), "AAAA", qname);
        if (vk_get(k, val, sizeof(val))) {
            found = 1;
            struct in6_addr a6;
            if (inet_pton(AF_INET6, val, &a6) == 1) {
                uint8_t rd[16];
                memcpy(rd, &a6, 16);
                long tl = vk_ttl(k);
                if (tl < 1)
                    tl = 1;
                off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_AAAA, (uint32_t) tl, rd, 16,
                              dnssec_ok, &answers);
            }
        }
        zkey(k, sizeof(k), "AAAA", qname);
        if (vk_get(k, val, sizeof(val))) {
            found = 1;
            uint32_t ttl = DEFAULT_TTL;
            char *pipe = strchr(val, '|');
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                pipe++;
            } else
                pipe = val;
            char *sp13 = NULL;
            char *ip = strtok_r(pipe, "|", &sp13);
            while (ip) {
                struct in6_addr a6;
                if (inet_pton(AF_INET6, ip, &a6) == 1) {
                    uint8_t rd[16];
                    memcpy(rd, &a6, 16);
                    off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_AAAA, ttl, rd, 16, dnssec_ok,
                                  &answers);
                }
                ip = strtok_r(NULL, "|", &sp13);
            }
        }
    }
    /* Provisioned record types from Valkey */
    {
        uint16_t pts[] = {DNS_TYPE_CNAME,
                          DNS_TYPE_MX,
                          DNS_TYPE_TXT,
                          DNS_TYPE_NS,
                          DNS_TYPE_SRV,
                          DNS_TYPE_CAA,
                          DNS_TYPE_SSHFP,
                          DNS_TYPE_TLSA,
                          DNS_TYPE_DNAME,
                          DNS_TYPE_LOC,
                          DNS_TYPE_URI,
                          DNS_TYPE_NAPTR,
                          0};
        for (int pi = 0; pts[pi]; pi++) {
            uint16_t pt = pts[pi];
            if (qtype != pt && qtype != DNS_TYPE_ANY)
                continue;
            char k[768];
            zkey(k, sizeof(k), type2str(pt), qname);
            char val[512];
            if (!vk_get(k, val, sizeof(val)))
                continue;
            found = 1;
            uint32_t ttl = DEFAULT_TTL;
            char *pipe = strchr(val, '|');
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                pipe++;
            } else
                pipe = val;
            uint8_t rd[512];
            uint16_t rdlen = 0;
            switch (pt) {
                case DNS_TYPE_CNAME:
                case DNS_TYPE_NS:
                case DNS_TYPE_DNAME: {
                    int n = name_to_wire(pipe, rd, sizeof(rd));
                    if (n < 0)
                        continue;
                    rdlen = (uint16_t) n;
                    break;
                }
                case DNS_TYPE_MX: {
                    char *sp = strchr(pipe, '|');
                    uint16_t pref = 10;
                    if (sp) {
                        pref = (uint16_t) atoi(pipe);
                        pipe = sp + 1;
                    }
                    rd[0] = pref >> 8;
                    rd[1] = pref & 0xFF;
                    int n = name_to_wire(pipe, rd + 2, sizeof(rd) - 2);
                    if (n < 0)
                        continue;
                    rdlen = (uint16_t) (2 + n);
                    break;
                }
                case DNS_TYPE_TXT: {
                    int tl = txt_encode(pipe, rd, (int) sizeof(rd));
                    if (tl < 0)
                        continue;
                    rdlen = (uint16_t) tl;
                    break;
                }
                case DNS_TYPE_SRV: { /* ttl|prio|weight|port|target */
                    uint16_t prio = 0, weight = 0, port = 0;
                    char target[256] = "";
                    char *p2 = pipe;
                    char *sp14 = NULL;
                    char *tok = strtok_r(p2, "|", &sp14);
                    if (tok) {
                        prio = (uint16_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp14);
                    if (tok) {
                        weight = (uint16_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp14);
                    if (tok) {
                        port = (uint16_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp14);
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
                case DNS_TYPE_CAA: { /* ttl|flags|tag|value */
                    uint8_t flags = 0;
                    char tag[64] = "", caaval[256] = "";
                    char *p2 = pipe;
                    char *sp15 = NULL;
                    char *tok = strtok_r(p2, "|", &sp15);
                    if (tok) {
                        flags = (uint8_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp15);
                    if (tok)
                        safe_strcpy(tag, tok, sizeof(tag));
                    tok = strtok_r(NULL, "|", &sp15);
                    if (tok)
                        safe_strcpy(caaval, tok, sizeof(caaval));
                    rd[0] = flags;
                    rd[1] = (uint8_t) strlen(tag);
                    memcpy(rd + 2, tag, strlen(tag));
                    int tl = (int) strlen(tag);
                    memcpy(rd + 2 + tl, caaval, strlen(caaval));
                    rdlen = (uint16_t) (2 + tl + (int) strlen(caaval));
                    break;
                }
                case DNS_TYPE_SSHFP: { /* ttl|alg|fptype|fingerprint_hex */
                    uint8_t alg = 0, fptype = 0;
                    uint8_t fp[64] = {0};
                    int fplen = 0;
                    char *p2 = pipe;
                    char *sp16 = NULL;
                    char *tok = strtok_r(p2, "|", &sp16);
                    if (tok)
                        alg = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp16);
                    if (tok)
                        fptype = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp16);
                    if (tok)
                        fplen = hex_dec(tok, fp, sizeof(fp));
                    rd[0] = alg;
                    rd[1] = fptype;
                    memcpy(rd + 2, fp, fplen);
                    rdlen = (uint16_t) (2 + fplen);
                    break;
                }
                case DNS_TYPE_TLSA: { /* ttl|usage|selector|mtype|data_hex */
                    uint8_t usage = 0, sel = 0, mtype = 0;
                    uint8_t data[512] = {0};
                    int dlen = 0;
                    char *p2 = pipe;
                    char *sp17 = NULL;
                    char *tok = strtok_r(p2, "|", &sp17);
                    if (tok)
                        usage = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp17);
                    if (tok)
                        sel = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp17);
                    if (tok)
                        mtype = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp17);
                    if (tok)
                        dlen = hex_dec(tok, data, sizeof(data));
                    rd[0] = usage;
                    rd[1] = sel;
                    rd[2] = mtype;
                    memcpy(rd + 3, data, dlen);
                    rdlen = (uint16_t) (3 + dlen);
                    break;
                }
                case DNS_TYPE_LOC: { /* stored as raw hex of wire rdata */
                    int lo = hex_dec(pipe, rd, sizeof(rd));
                    rdlen = (uint16_t) lo;
                    break;
                }
                case DNS_TYPE_URI: { /* ttl|priority|weight|target */
                    uint16_t prio = 0, weight = 0;
                    char *p2 = pipe;
                    char *sp18 = NULL;
                    char *tok = strtok_r(p2, "|", &sp18);
                    if (tok)
                        prio = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp18);
                    if (tok)
                        weight = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp18);
                    if (!tok)
                        tok = "";
                    /* RFC 7553: priority(2)+weight(2)+target(variable, no length prefix) */
                    int tlen = (int) strlen(tok);
                    if (tlen > 255)
                        tlen = 255;
                    rd[0] = prio >> 8;
                    rd[1] = prio & 0xFF;
                    rd[2] = weight >> 8;
                    rd[3] = weight & 0xFF;
                    memcpy(rd + 4, tok, tlen);
                    rdlen = (uint16_t) (4 + tlen);
                    break;
                }
                case DNS_TYPE_NAPTR: { /* ttl|order|pref|flags|service|regexp|replacement */
                    /* stored as raw packed value: order|pref|flags|service|regexp|replacement */
                    uint16_t order2 = 0, pref2 = 0;
                    char flags2[64] = "", svc2[64] = "", re2[256] = "", repl2[256] = "";
                    char *p2 = pipe;
                    char *sp19 = NULL;
                    char *tok = strtok_r(p2, "|", &sp19);
                    if (tok)
                        order2 = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp19);
                    if (tok)
                        pref2 = (uint16_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp19);
                    if (tok)
                        safe_strcpy(flags2, tok, sizeof(flags2));
                    tok = strtok_r(NULL, "|", &sp19);
                    if (tok)
                        safe_strcpy(svc2, tok, sizeof(svc2));
                    tok = strtok_r(NULL, "|", &sp19);
                    if (tok)
                        safe_strcpy(re2, tok, sizeof(re2));
                    tok = strtok_r(NULL, "|", &sp19);
                    if (tok)
                        safe_strcpy(repl2, tok, sizeof(repl2));
                    int rp2 = 0;
                    rd[rp2++] = order2 >> 8;
                    rd[rp2++] = order2 & 0xFF;
                    rd[rp2++] = pref2 >> 8;
                    rd[rp2++] = pref2 & 0xFF;
                    /* flags length-prefixed string */
                    int fl = (int) strlen(flags2);
                    rd[rp2++] = (uint8_t) fl;
                    memcpy(rd + rp2, flags2, fl);
                    rp2 += fl;
                    int sl2 = (int) strlen(svc2);
                    rd[rp2++] = (uint8_t) sl2;
                    memcpy(rd + rp2, svc2, sl2);
                    rp2 += sl2;
                    int rl = (int) strlen(re2);
                    rd[rp2++] = (uint8_t) rl;
                    memcpy(rd + rp2, re2, rl);
                    rp2 += rl;
                    int nn2 = name_to_wire(repl2[0] ? repl2 : ".", rd + rp2, sizeof(rd) - rp2);
                    if (nn2 > 0)
                        rp2 += nn2;
                    rdlen = (uint16_t) rp2;
                    break;
                }
                default:
                    continue;
            }
            off = emit_rr(resp, off, resp_len, qname, pt, ttl, rd, rdlen, dnssec_ok, &answers);
            if (any_minimal && answers > 0)
                goto finish_answer;
        }
    }
    /* RFC 1034 §3.6.2 — CNAME synthesis for non-CNAME queries */
    if (!found && answers == 0 && qtype != DNS_TYPE_CNAME && qtype != DNS_TYPE_ANY) {
        char cname_key[768];
        zkey(cname_key, sizeof(cname_key), "CNAME", qname);
        char cname_val[512];
        if (vk_get(cname_key, cname_val, sizeof(cname_val))) {
            found = 1;
            uint32_t cname_ttl = DEFAULT_TTL;
            char *cpipe = strchr(cname_val, '|');
            const char *cname_target = cpipe ? cpipe + 1 : cname_val;
            if (cpipe)
                cname_ttl = (uint32_t) atoi(cname_val);
            uint8_t crd[256];
            int crlen = name_to_wire(cname_target, crd, sizeof(crd));
            if (crlen > 0) {
                off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_CNAME, cname_ttl, crd,
                              (uint16_t) crlen, dnssec_ok, &answers);
                /* Follow chain within zone — up to 8 hops */
                char cur[256];
                safe_strcpy(cur, cname_target, sizeof(cur));
                for (int hop = 0; hop < 8 && cur[0]; hop++) {
                    const char *zn = t_zone ? t_zone->name : g_zone_name;
                    size_t zl = strlen(zn), nl = strlen(cur);
                    int in_zone = (nl == zl && strcasecmp(cur, zn) == 0) ||
                                  (nl > zl + 1 && cur[nl - zl - 1] == '.' &&
                                   strcasecmp(cur + nl - zl, zn) == 0);
                    if (!in_zone)
                        break;
                    /* A records at this hop */
                    if (qtype == DNS_TYPE_A || qtype == DNS_TYPE_ANY) {
                        char ck[768];
                        zkey(ck, sizeof(ck), "A", cur);
                        char cv[256];
                        if (vk_get(ck, cv, sizeof(cv))) {
                            uint32_t t2 = DEFAULT_TTL;
                            char *pp = strchr(cv, '|');
                            char *ip = pp ? pp + 1 : cv;
                            if (pp)
                                t2 = (uint32_t) atoi(cv);
                            char cbuf[256];
                            safe_strcpy(cbuf, ip, sizeof(cbuf));
                            char *sp20 = NULL;
                            char *tok = strtok_r(cbuf, "|", &sp20);
                            while (tok) {
                                struct in_addr a4;
                                if (inet_pton(AF_INET, tok, &a4) == 1) {
                                    uint8_t rd4[4];
                                    memcpy(rd4, &a4, 4);
                                    off = emit_rr(resp, off, resp_len, cur, DNS_TYPE_A, t2, rd4, 4,
                                                  dnssec_ok, &answers);
                                }
                                tok = strtok_r(NULL, "|", &sp20);
                            }
                        }
                    }
                    /* AAAA records */
                    if (qtype == DNS_TYPE_AAAA || qtype == DNS_TYPE_ANY) {
                        char ck[768];
                        zkey(ck, sizeof(ck), "AAAA", cur);
                        char cv[256];
                        if (vk_get(ck, cv, sizeof(cv))) {
                            uint32_t t2 = DEFAULT_TTL;
                            char *pp = strchr(cv, '|');
                            char *ip = pp ? pp + 1 : cv;
                            if (pp)
                                t2 = (uint32_t) atoi(cv);
                            char cbuf[256];
                            safe_strcpy(cbuf, ip, sizeof(cbuf));
                            char *sp21 = NULL;
                            char *tok = strtok_r(cbuf, "|", &sp21);
                            while (tok) {
                                struct in6_addr a6;
                                if (inet_pton(AF_INET6, tok, &a6) == 1) {
                                    uint8_t rd6[16];
                                    memcpy(rd6, &a6, 16);
                                    off = emit_rr(resp, off, resp_len, cur, DNS_TYPE_AAAA, t2, rd6,
                                                  16, dnssec_ok, &answers);
                                }
                                tok = strtok_r(NULL, "|", &sp21);
                            }
                        }
                    }
                    /* Next CNAME hop? */
                    zkey(cname_key, sizeof(cname_key), "CNAME", cur);
                    if (answers == 0 && vk_get(cname_key, cname_val, sizeof(cname_val))) {
                        cpipe = strchr(cname_val, '|');
                        cname_target = cpipe ? cpipe + 1 : cname_val;
                        uint32_t t_hop = cpipe ? (uint32_t) atoi(cname_val) : DEFAULT_TTL;
                        crlen = name_to_wire(cname_target, crd, sizeof(crd));
                        if (crlen > 0)
                            off = emit_rr(resp, off, resp_len, cur, DNS_TYPE_CNAME, t_hop, crd,
                                          (uint16_t) crlen, dnssec_ok, &answers);
                        safe_strcpy(cur, cname_target, sizeof(cur));
                    } else
                        break;
                }
            }
        }
    }

    /* RFC 4592: wildcard lookup — if no exact match, try *.<parent> */
    if (!found) {
        /* Build wildcard name: *.one-label-up */
        char *dot = strchr(qname, '.');
        if (dot) {
            char wname[256];
            snprintf(wname, sizeof(wname), "*%s", dot); /* e.g. "*.example.local" */
            /* Search static zone for wildcard */
            for (int i = 0; i < static_zone_sz && !found; i++) {
                dns_rec_t *r = &static_zone[i];
                if (!streq_ci(r->name, wname))
                    continue;
                found = 1; /* wildcard owner exists */
                if (r->type != qtype && qtype != DNS_TYPE_ANY)
                    continue;
                uint8_t rd[256];
                uint16_t rdlen = 0;
                switch (r->type) {
                    case DNS_TYPE_A:
                        memcpy(rd, r->rdata_a, 4);
                        rdlen = 4;
                        break;
                    case DNS_TYPE_AAAA: {
                        struct in6_addr a6w;
                        if (inet_pton(AF_INET6, r->rdata_str, &a6w) != 1)
                            continue;
                        memcpy(rd, &a6w, 16);
                        rdlen = 16;
                        break;
                    }
                    case DNS_TYPE_CNAME:
                    case DNS_TYPE_NS:
                    case DNS_TYPE_DNAME: {
                        int nw = name_to_wire(r->rdata_str, rd, sizeof(rd));
                        if (nw < 0)
                            continue;
                        rdlen = (uint16_t) nw;
                        break;
                    }
                    case DNS_TYPE_MX: {
                        rd[0] = r->rdata_pref >> 8;
                        rd[1] = r->rdata_pref & 0xFF;
                        int nw = name_to_wire(r->rdata_str, rd + 2, sizeof(rd) - 2);
                        if (nw < 0)
                            continue;
                        rdlen = (uint16_t) (2 + nw);
                        break;
                    }
                    case DNS_TYPE_TXT: {
                        int tl = txt_encode(r->rdata_str, rd, (int) sizeof(rd));
                        if (tl < 0)
                            continue;
                        rdlen = (uint16_t) tl;
                        break;
                    }
                    default:
                        continue;
                }
                /* Emit with synthesised owner name (qname, not wildcard) */
                off = emit_rr(resp, off, resp_len, qname, r->type, r->ttl, rd, rdlen, dnssec_ok,
                              &answers);
            }
            /* Also check Valkey wildcard */
            if (!found) {
                char wk[768];
                if (qtype == DNS_TYPE_A || qtype == DNS_TYPE_ANY) {
                    zkey(wk, sizeof(wk), "A", wname);
                    char wv[128];
                    if (vk_get(wk, wv, sizeof(wv))) {
                        found = 1;
                        uint32_t wttl = DEFAULT_TTL;
                        char *wp = strchr(wv, '|');
                        if (wp) {
                            wttl = (uint32_t) atoi(wv);
                            wp++;
                        } else
                            wp = wv;
                        struct in_addr wa4;
                        if (inet_pton(AF_INET, wp, &wa4) == 1) {
                            uint8_t rd[4];
                            memcpy(rd, &wa4, 4);
                            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_A, wttl, rd, 4,
                                          dnssec_ok, &answers);
                        }
                    }
                }
                if (qtype == DNS_TYPE_AAAA || qtype == DNS_TYPE_ANY) {
                    zkey(wk, sizeof(wk), "AAAA", wname);
                    char wv[256];
                    if (vk_get(wk, wv, sizeof(wv))) {
                        found = 1;
                        uint32_t wttl = DEFAULT_TTL;
                        char *wp = strchr(wv, '|');
                        if (wp) {
                            wttl = (uint32_t) atoi(wv);
                            wp++;
                        } else
                            wp = wv;
                        struct in6_addr wa6;
                        if (inet_pton(AF_INET6, wp, &wa6) == 1) {
                            uint8_t rd[16];
                            memcpy(rd, &wa6, 16);
                            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_AAAA, wttl, rd, 16,
                                          dnssec_ok, &answers);
                        }
                    }
                }
            }
        }
    }

finish_answer:
    rh->ancount = htons((uint16_t) answers);
    /* RFC 4035 §3.1.6: set AD bit when DO=1 and we returned signed answers */
    if (dnssec_ok && answers > 0 && g_zsk)
        rh->flags = htons(ntohs(rh->flags) | DNS_AD);
    /* RRL: rate-limit before returning response to caller */
    if (!is_tcp && g_rrl_enabled) {
        int rrl_action = rrl_check(cip, qname);
        if (rrl_action == 1) {
            dns_log(LOG_DEBUG, "[RRL] DROP %s %s\n", type2str(qtype), qname);
            STAT_INC(g_stat_rrl_drop);
            return -1; /* caller discards — no response sent */
        }
        if (rrl_action == 2) {
            /* Send truncated response — client should retry over TCP */
            dns_log(LOG_DEBUG, "[RRL] TC %s %s\n", type2str(qtype), qname);
            STAT_INC(g_stat_rrl_tc);
            rh->flags = htons(ntohs(rh->flags) | DNS_TC);
            rh->ancount = rh->nscount = rh->arcount = 0;
            off = 12 + (after - 12) + 4; /* header + question only */
        }
    }
    int ede_code = -1;
    const char *ede_text = NULL;
    if (answers == 0) {
        /* RFC 2308: add SOA in authority for NXDOMAIN / NODATA */
        if (!found) {
            rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_NXDOMAIN);
            ede_code = EDE_NXDOMAIN;
            ede_text = "Name does not exist in zone";
            STAT_INC(g_stat_nxdomain);
        } else { /* NODATA — name exists, type doesn't */
            rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_NOERROR);
            ede_code = EDE_NOT_AUTH;
            STAT_INC(g_stat_noerror);
        }
        off = add_soa_authority(resp, off, resp_len, dnssec_ok, &auth_count);
        if (dnssec_ok) {
            if (t_zone ? t_zone->dnssec_use_nsec3 : g_dnssec_use_nsec3)
                off = add_nsec3_denial(resp, off, resp_len, qname, qtype, dnssec_ok, &auth_count);
            else
                off = add_nsec_denial(resp, off, resp_len, qname, dnssec_ok, &auth_count);
        }
        rh->nscount = htons((uint16_t) auth_count);
    }
    /* RFC 8482: set HINFO hint for ANY minimal responses */
    if (any_minimal && answers > 0) {
        /* Add HINFO record as hint per RFC 8482 */
        const uint8_t hinfo_rd[] = {3, 'R', 'F', 'C', 1, '1'};
        append_rr(resp, off, resp_len, qname, 13 /*HINFO*/, DNS_CLASS_IN, 3600, hinfo_rd,
                  sizeof(hinfo_rd));
    /* We don't count this in answers to avoid recursion */ }
    /* RFC 1035 §4.2.1: set TC bit if response exceeds negotiated UDP size */
    if (!is_tcp) {
        uint16_t max_udp = ei.present ? ei.max_udp : 512;
        if (max_udp < 512)
            max_udp = 512;
        if ((uint16_t) off > max_udp) {
            /* Truncate: keep header + question, set TC, drop answers */
            int qend = 12 + (after - 12) + 4; /* header + question section */
            rh->flags = htons(ntohs(rh->flags) | DNS_TC);
            rh->ancount = rh->nscount = rh->arcount = 0;
            off = qend;
        }
    }
    /* EDNS OPT in response */
    off = edns_append_opt(resp, off, resp_len, is_tcp, dnssec_ok, 0, &ei, cip, ede_code, ede_text);
    return off;
}

/* ==========================================================================
 * RFC 2136 §2.4 prerequisite helpers
 * ======================================================================= */
/* Returns 1 if at least one RR exists for `name` (any type, any namespace). */
static int prereq_name_exists(const char *name) {
    char vk[768];
    char tmp[8];
    const char *types[] = {"A",   "AAAA",  "CNAME", "MX",    "TXT", "NS", "SRV",
                           "CAA", "SSHFP", "TLSA",  "DNAME", "LOC", NULL};
    for (int ti = 0; types[ti]; ti++) {
        dkey(vk, sizeof(vk), types[ti], name);
        if (vk_get(vk, tmp, sizeof(tmp)))
            return 1;
        zkey(vk, sizeof(vk), types[ti], name);
        if (vk_get(vk, tmp, sizeof(tmp)))
            return 1;
    }
    for (int i = 0; i < static_zone_sz; i++)
        if (streq_ci(static_zone[i].name, name))
            return 1;
    return 0;
}
/* Returns 1 if at least one RR of type `rtype` exists for `name`. */
static int prereq_rrset_exists(const char *name, uint16_t rtype) {
    char vk[768];
    char tmp[8];
    const char *ts = type2str(rtype);
    if (!ts)
        return 0;
    dkey(vk, sizeof(vk), ts, name);
    if (vk_get(vk, tmp, sizeof(tmp)))
        return 1;
    zkey(vk, sizeof(vk), ts, name);
    if (vk_get(vk, tmp, sizeof(tmp)))
        return 1;
    for (int i = 0; i < static_zone_sz; i++)
        if (streq_ci(static_zone[i].name, name) && static_zone[i].type == rtype)
            return 1;
    return 0;
}

/* ==========================================================================
 * RFC 2136 DNS UPDATE
 * ======================================================================= */
static int handle_update(const uint8_t *pkt, int plen, uint8_t *resp) {
    if (plen < 12)
        return -1;
    const dns_hdr_t *h = (const dns_hdr_t *) pkt;
    dns_hdr_t *rh = (dns_hdr_t *) resp;
    rh->id = h->id;
    rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | DNS_RCODE_NOERROR);
    rh->qdcount = rh->ancount = rh->nscount = rh->arcount = 0;
    /* TSIG verification */
    if (g_tsig_secret_len > 0 && !tsig_verify(pkt, plen)) {
        rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | DNS_RCODE_BADSIG);
        return 12;
    }
    int off = 12;
    t_zone = NULL;
    for (int i = 0; i < ntohs(h->qdcount); i++) {
        char zn[256];
        int za = name_from_wire(pkt, plen, off, zn, sizeof(zn));
        if (za < 0)
            goto formerr;
        /* RFC 2136 §3.1: the zone section names one authoritative zone; select
         * it so all reads/writes below are scoped to it.  Reject if we are not
         * authoritative for that zone. */
        if (i == 0) {
            t_zone = zone_for_qname(zn);
            if (!t_zone || strcasecmp(t_zone->name, zn) != 0) {
                dns_log(LOG_WARNING, "[UPDATE] Rejected: zone '%s' not authoritative here\n", zn);
                rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | DNS_RCODE_NOTZONE);
                return 12;
            }
        }
        off = za + 4;
        if (off > plen)
            goto formerr;
    }
    /* RFC 2136 §2.4 prerequisites */
    for (int i = 0; i < ntohs(h->ancount); i++) {
        char nm[256];
        int a = name_from_wire(pkt, plen, off, nm, sizeof(nm));
        if (a < 0 || a + 9 > plen)
            goto formerr;
        uint16_t rtype = get16(pkt, a), rclass = get16(pkt, a + 2);
        uint16_t rdlen = get16(pkt, a + 8);
        off = a + 10 + rdlen;
        if (off > plen)
            goto formerr;
        uint16_t prereq_fail = 0;
        if (rclass == DNS_CLASS_ANY && rtype == DNS_TYPE_ANY && rdlen == 0) {
            if (!prereq_name_exists(nm))
                prereq_fail = DNS_RCODE_NXDOMAIN;
        } else if (rclass == DNS_CLASS_ANY && rtype != DNS_TYPE_ANY && rdlen == 0) {
            if (!prereq_rrset_exists(nm, rtype))
                prereq_fail = DNS_RCODE_NXRRSET;
        } else if (rclass == DNS_CLASS_NONE && rtype == DNS_TYPE_ANY && rdlen == 0) {
            if (prereq_name_exists(nm))
                prereq_fail = DNS_RCODE_YXDOMAIN;
        } else if (rclass == DNS_CLASS_NONE && rtype != DNS_TYPE_ANY && rdlen == 0) {
            if (prereq_rrset_exists(nm, rtype))
                prereq_fail = DNS_RCODE_YXRRSET;
        }
        /* class=IN rdata = exact RRset match — not implemented (RFC 2136 §3.2.5) */
        if (prereq_fail) {
            rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | prereq_fail);
            {
                int o2 = tsig_append(resp, 12, BUF_SIZE, ntohs(h->id), 0);
                return o2;
            }
        }
    }
    for (int i = 0; i < ntohs(h->nscount); i++) {
        char un[256];
        int a = name_from_wire(pkt, plen, off, un, sizeof(un));
        if (a < 0 || a + 9 > plen)
            goto formerr;
        uint16_t ut = get16(pkt, a), uc = get16(pkt, a + 2);
        uint32_t uttl = get32(pkt, a + 4);
        uint16_t rdlen = get16(pkt, a + 8);
        off = a + 10;
        if (off + rdlen > plen)
            goto formerr;
        const uint8_t *rd = pkt + off;
        off += rdlen;
        char k[768];
        if (uc == DNS_CLASS_IN && rdlen > 0) {
            if (ut == DNS_TYPE_A && rdlen == 4) {
                char ip[32];
                snprintf(ip, sizeof(ip), "%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3]);
                dkey(k, sizeof(k), "A", un);
                vk_set(k, ip, uttl ? uttl : DEFAULT_TTL);
                {
                    uint32_t prev = t_zone ? t_zone->soa_serial : g_soa_serial;
                    uint32_t next = serial_bump(t_zone);
                    ixfr_journal_append(prev, next, 'A', un, ip);
                }
                dns_log(LOG_NOTICE, "[DDNS] A %s->%s\n", un, ip);
                STAT_INC(g_stat_ddns);
            } else if (ut == DNS_TYPE_AAAA && rdlen == 16) {
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rd, ip6, sizeof(ip6));
                dkey(k, sizeof(k), "AAAA", un);
                vk_set(k, ip6, uttl ? uttl : DEFAULT_TTL);
                {
                    uint32_t prev = t_zone ? t_zone->soa_serial : g_soa_serial;
                    uint32_t next = serial_bump(t_zone);
                    ixfr_journal_append(prev, next, 'A', un, ip6);
                }
                dns_log(LOG_NOTICE, "[DDNS] AAAA %s->%s\n", un, ip6);
            } else if (ut == DNS_TYPE_TXT && rdlen >= 1) {
                uint8_t sl = rd[0];
                /* sl is uint8_t (<= 255), so only the rdlen bound matters */
                if (sl > rdlen - 1)
                    goto formerr;
                char txt[256];
                memcpy(txt, rd + 1, sl);
                txt[sl] = 0;
                char val[320];
                snprintf(val, sizeof(val), "%u|%s", uttl ? uttl : DEFAULT_TTL, txt);
                zkey(k, sizeof(k), "TXT", un);
                vk_set(k, val, 0);
                serial_bump(t_zone);
                dns_log(LOG_NOTICE, "[UPDATE] TXT %s = %.60s%s\n", un, txt, sl > 60 ? "..." : "");
            } else if (ut == DNS_TYPE_CNAME && rdlen >= 1) {
                char target[256];
                int consumed = name_from_wire(pkt, plen, (int) (rd - pkt), target, sizeof(target));
                if (consumed < 0)
                    goto formerr;
                char val[320];
                snprintf(val, sizeof(val), "%u|%s", uttl ? uttl : DEFAULT_TTL, target);
                zkey(k, sizeof(k), "CNAME", un);
                vk_set(k, val, 0);
                serial_bump(t_zone);
                dns_log(LOG_NOTICE, "[UPDATE] CNAME %s -> %s\n", un, target);
            } else if (ut == DNS_TYPE_MX && rdlen >= 3) {
                uint16_t pref = (rd[0] << 8) | rd[1];
                char target[256];
                int consumed =
                    name_from_wire(pkt, plen, (int) (rd - pkt) + 2, target, sizeof(target));
                if (consumed < 0)
                    goto formerr;
                char val[384];
                snprintf(val, sizeof(val), "%u|%u|%s", uttl ? uttl : DEFAULT_TTL, pref, target);
                zkey(k, sizeof(k), "MX", un);
                vk_set(k, val, 0);
                serial_bump(t_zone);
                dns_log(LOG_NOTICE, "[UPDATE] MX %s -> %u %s\n", un, pref, target);
            } else if (ut == DNS_TYPE_SRV && rdlen >= 7) {
                uint16_t prio = (rd[0] << 8) | rd[1];
                uint16_t weight = (rd[2] << 8) | rd[3];
                uint16_t port = (rd[4] << 8) | rd[5];
                char target[256];
                int consumed =
                    name_from_wire(pkt, plen, (int) (rd - pkt) + 6, target, sizeof(target));
                if (consumed < 0)
                    goto formerr;
                char val[384];
                snprintf(val, sizeof(val), "%u|%u|%u|%u|%s", uttl ? uttl : DEFAULT_TTL, prio,
                         weight, port, target);
                zkey(k, sizeof(k), "SRV", un);
                vk_set(k, val, 0);
                serial_bump(t_zone);
                dns_log(LOG_NOTICE, "[UPDATE] SRV %s -> %u %u %u %s\n", un, prio, weight, port,
                        target);
            }
        } else if ((uc == DNS_CLASS_ANY || uc == DNS_CLASS_NONE) && rdlen == 0) {
            if (ut == DNS_TYPE_A || ut == DNS_TYPE_ANY) {
                dkey(k, sizeof(k), "A", un);
                vk_del(k);
            }
            if (ut == DNS_TYPE_AAAA || ut == DNS_TYPE_ANY) {
                dkey(k, sizeof(k), "AAAA", un);
                vk_del(k);
            }
            if (ut == DNS_TYPE_TXT || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "TXT", un);
                vk_del(k);
            }
            if (ut == DNS_TYPE_CNAME || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "CNAME", un);
                vk_del(k);
            }
            if (ut == DNS_TYPE_MX || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "MX", un);
                vk_del(k);
            }
            if (ut == DNS_TYPE_SRV || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "SRV", un);
                vk_del(k);
            }
            serial_bump(t_zone);
        }
    }
    /* Append TSIG to response */
    {
        int off2 = tsig_append(resp, 12, BUF_SIZE, ntohs(h->id), 0);
        return off2;
    }
formerr:
    rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | DNS_RCODE_FORMERR);
    return 12;
}

/* ==========================================================================
 * RFC 1995 IXFR — Incremental Zone Transfer
 *
 * Journal stored in Valkey as a list:
 *   ixfr:journal  — RPUSH entries of the form:
 *       "<from_serial>|<to_serial>|A|<name>|<value>"   (add)
 *       "<from_serial>|<to_serial>|D|<name>|<value>"   (delete)
 * Capped at IXFR_JOURNAL_MAX entries; older entries are dropped.
 * When IXFR is requested the server:
 *   1. Reads all journal entries from the requested serial onward.
 *   2. If the full diff is available: sends SOA + diff + SOA.
 *   3. Otherwise: falls back to AXFR.
 * ======================================================================= */
#define IXFR_JOURNAL_MAX 4096
#define IXFR_JOURNAL_KEY "ixfr:journal"

/* Append one change record to the IXFR journal */
static void ixfr_journal_append(uint32_t from_serial, uint32_t to_serial, char op, const char *name,
                                const char *value) {
    char entry[1024];
    snprintf(entry, sizeof(entry), "%u|%u|%c|%s|%s", from_serial, to_serial, op, name, value);
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) >= 0) {
        resp_reply_t r;
        resp_cmd(&vk, &r, 3, "RPUSH", IXFR_JOURNAL_KEY, entry);
        /* Trim to max size */
        if (r.type == 3 && r.integer > IXFR_JOURNAL_MAX) {
            char trim[32];
            snprintf(trim, sizeof(trim), "%d", IXFR_JOURNAL_MAX);
            resp_reply_t r2;
            char ltrim_idx[32];
            snprintf(ltrim_idx, sizeof(ltrim_idx), "%d", -IXFR_JOURNAL_MAX);
            resp_cmd(&vk, &r2, 4, "LTRIM", IXFR_JOURNAL_KEY, ltrim_idx, "-1");
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
}

/* Retrieve journal entries from from_serial onward.
 * Returns count of entries placed in out_entries (caller frees each).
 * Returns -1 if serial not in journal (fall back to AXFR). */
static int ixfr_journal_fetch(uint32_t from_serial, char **out_entries, int max_entries) {
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    resp_reply_t r;
    resp_cmd(&vk, &r, 4, "LRANGE", IXFR_JOURNAL_KEY, "0", "-1");
    if (r.type != 5) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    int count = r.count, found = -1, n = 0;
    for (int i = 0; i < count; i++) {
        resp_reply_t er;
        resp_parse(&vk, &er);
        if (er.type != 2)
            continue;
        uint32_t fs = 0;
        sscanf(er.str, "%u|", &fs);
        if (fs == from_serial)
            found = i;
        if (found >= 0) {
            if (n < max_entries) {
                char *dup = strdup(er.str);
                if (!dup) {
                    pthread_mutex_unlock(&g_vk_mutex);
                    for (int j = 0; j < n; j++)
                        free(out_entries[j]);
                    return -1;
                }
                out_entries[n++] = dup;
            }
            /* else: entry beyond max_entries is intentionally skipped */
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    return (found >= 0) ? n : -1;
}

/* ==========================================================================
 * AXFR / IXFR zone transfer (RFC 5936 / 1995)
 * ======================================================================= */
typedef struct {
    int fd;
    SSL *ssl;
    struct sockaddr_in addr;
    int ixfr;
    uint32_t ixfr_serial;
    uint16_t query_id;
    char zone[256]; /* requested zone (AXFR/IXFR question name) */
} axfr_conn_t;

static int axfr_ip_allowed(const struct in_addr *cip, const char *allow_list) {
    char allow[1024];
    safe_strcpy(allow, allow_list, sizeof(allow));
    char *sp22 = NULL;
    char *tok = strtok_r(allow, ",", &sp22);
    while (tok) {
        while (*tok == ' ')
            tok++;
        /* Simple exact match or /8-/32 CIDR */
        char *slash = strchr(tok, '/');
        if (slash) {
            int bits = atoi(slash + 1);
            *slash = 0;
            if (bits < 0)
                bits = 0;
            if (bits > 32)
                bits = 32;
            struct in_addr net;
            inet_pton(AF_INET, tok, &net);
            uint32_t mask = bits ? htonl(~((1u << (32 - bits)) - 1)) : 0u;
            if (bits == 32)
                mask = 0xFFFFFFFFu;
            if ((cip->s_addr & mask) == (net.s_addr & mask))
                return 1;
        } else {
            struct in_addr a;
            if (inet_pton(AF_INET, tok, &a) == 1 && a.s_addr == cip->s_addr)
                return 1;
        }
        tok = strtok_r(NULL, ",", &sp22);
    }
    return 0;
}

/* Send one DNS message over TCP (2-byte length prefix) */
static int tcp_send_msg(int fd, SSL *ssl, const uint8_t *msg, int len) {
    uint8_t lb[2];
    lb[0] = len >> 8;
    lb[1] = len & 0xFF;
    if (ssl) {
        if (SSL_write(ssl, lb, 2) <= 0 || SSL_write(ssl, msg, len) <= 0)
            return -1;
    } else {
        if (send(fd, lb, 2, 0) != 2 || send(fd, msg, len, 0) != len)
            return -1;
    }
    return 0;
}

static void *axfr_thread(void *arg) {
    axfr_conn_t c;
    memcpy(&c, arg, sizeof(c));
    free(arg);
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c.addr.sin_addr, cip, sizeof(cip));
    dns_log(LOG_NOTICE, "[%s] Transfer of %s to %s\n", c.ixfr ? "IXFR" : "AXFR", c.zone, cip);

    /* Select the requested zone; all SOA/keys/static records below are scoped
     * to t_zone.  Refuse if we are not authoritative for it. */
    t_zone = zone_for_qname(c.zone);
    const char *allow = (t_zone && t_zone->axfr_allow[0]) ? t_zone->axfr_allow : g_axfr_allow;
    if (!t_zone || !axfr_ip_allowed(&c.addr.sin_addr, allow)) {
        dns_log(LOG_ERR, "[AXFR] REFUSED %s for %s\n", cip, c.zone);
        /* Send REFUSED response */
        uint8_t ref[12] = {0};
        dns_hdr_t *rh = (dns_hdr_t *) ref;
        rh->id = 0;
        rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_REFUSED);
        tcp_send_msg(c.fd, c.ssl, ref, 12);
        goto done;
    }
    const char *zname = t_zone->name;

    uint8_t soa_rd[512];
    int soa_len = build_soa_rdata(soa_rd, sizeof(soa_rd));

    /* ── IXFR path (RFC 1995) ── */
    if (c.ixfr && c.ixfr_serial > 0 && c.ixfr_serial < t_zone->soa_serial) {
        char *entries[IXFR_JOURNAL_MAX];
        int ne = 0;
        ne = ixfr_journal_fetch(c.ixfr_serial, entries, IXFR_JOURNAL_MAX);
        if (ne > 0) {
            /* Send: current SOA, del-SOA(old), adds, new-SOA */
            uint8_t mb[BUF_SIZE];
            int mo;
            uint8_t ixfr_mac[64];
            int ixfr_mac_len = 0;
            /* Opening SOA */
            compress_reset();
            memset(mb, 0, 12);
            dns_hdr_t *mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            mo = 12;
            if (soa_len > 0)
                mo = append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_SOA, DNS_CLASS_IN,
                               t_zone->soa_minimum, soa_rd, (uint16_t) soa_len);
            mo = tsig_axfr_first(mb, mo, sizeof(mb), c.query_id, ixfr_mac, &ixfr_mac_len);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
            /* Old SOA (the one being replaced) */
            uint8_t old_soa[512];
            int old_soa_len = 0;
            { /* build SOA with from_serial */
                pthread_mutex_lock(&g_soa_mutex);
                uint32_t saved = t_zone->soa_serial;
                t_zone->soa_serial = c.ixfr_serial;
                pthread_mutex_unlock(&g_soa_mutex);
                old_soa_len = build_soa_rdata(old_soa, sizeof(old_soa));
                pthread_mutex_lock(&g_soa_mutex);
                t_zone->soa_serial = saved;
                pthread_mutex_unlock(&g_soa_mutex);
            }
            compress_reset();
            memset(mb, 0, 12);
            mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            mo = 12;
            if (old_soa_len > 0)
                mo = append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_SOA, DNS_CLASS_IN,
                               t_zone->soa_minimum, old_soa, (uint16_t) old_soa_len);
            tsig_axfr_mid(mb, mo, ixfr_mac, &ixfr_mac_len);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
            /* Changes */
            for (int ei = 0; ei < ne; ei++) {
                char *e = entries[ei];
                if (!e)
                    continue;
                uint32_t fs = 0, ts = 0;
                char op = 'A';
                char ename[256] = "";
                char eval[256] = "";
                sscanf(e, "%u|%u|%c|%255[^|]|%255[^\n]", &fs, &ts, &op, ename, eval);
                /* only A/AAAA for now; emit as ADD record */
                struct in_addr a4;
                struct in6_addr a6;
                compress_reset();
                memset(mb, 0, 12);
                mh = (dns_hdr_t *) mb;
                mh->flags = htons(DNS_QR | DNS_AA);
                mh->ancount = htons(1);
                mo = 12;
                if (inet_pton(AF_INET, eval, &a4) == 1) {
                    uint8_t rd[4];
                    memcpy(rd, &a4, 4);
                    mo = append_rr(mb, mo, sizeof(mb), ename, DNS_TYPE_A, DNS_CLASS_IN, DEFAULT_TTL,
                                   rd, 4);
                } else if (inet_pton(AF_INET6, eval, &a6) == 1) {
                    uint8_t rd[16];
                    memcpy(rd, &a6, 16);
                    mo = append_rr(mb, mo, sizeof(mb), ename, DNS_TYPE_AAAA, DNS_CLASS_IN,
                                   DEFAULT_TTL, rd, 16);
                } else {
                    free(e);
                    continue;
                }
                tsig_axfr_mid(mb, mo, ixfr_mac, &ixfr_mac_len);
                tcp_send_msg(c.fd, c.ssl, mb, mo);
                free(e);
            }
            /* Closing new SOA */
            compress_reset();
            memset(mb, 0, 12);
            mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            mo = 12;
            if (soa_len > 0)
                mo = append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_SOA, DNS_CLASS_IN,
                               t_zone->soa_minimum, soa_rd, (uint16_t) soa_len);
            mo = tsig_axfr_last(mb, mo, sizeof(mb), c.query_id, ixfr_mac, ixfr_mac_len);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
            dns_log(LOG_NOTICE, "[IXFR] Sent %d changes serial %u->%u to %s\n", ne, c.ixfr_serial,
                    t_zone->soa_serial, cip);
            goto done;
        }
        dns_log(LOG_NOTICE, "[IXFR] Serial %u not in journal, falling back to AXFR\n",
                c.ixfr_serial);
    } else if (c.ixfr && c.ixfr_serial == t_zone->soa_serial) {
        /* Already up to date — send just the current SOA */
        uint8_t mb[BUF_SIZE];
        compress_reset();
        memset(mb, 0, 12);
        dns_hdr_t *mh = (dns_hdr_t *) mb;
        mh->flags = htons(DNS_QR | DNS_AA);
        mh->ancount = htons(1);
        int mo = 12;
        if (soa_len > 0)
            mo = append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_SOA, DNS_CLASS_IN,
                           t_zone->soa_minimum, soa_rd, (uint16_t) soa_len);
        mo = tsig_append(mb, mo, sizeof(mb), c.query_id, 0);
        tcp_send_msg(c.fd, c.ssl, mb, mo);
        dns_log(LOG_NOTICE, "[IXFR] Already current serial %u for %s\n", t_zone->soa_serial, cip);
        goto done;
    }

    /* ── AXFR full transfer ── */
    uint8_t buf[BUF_SIZE];
    uint8_t axfr_mac[64];
    int axfr_mac_len = 0; /* TSIG chaining state (RFC 8945 §5.3.1) */
    /* First SOA */
    compress_reset();
    memset(buf, 0, 12);
    dns_hdr_t *rh = (dns_hdr_t *) buf;
    rh->flags = htons(DNS_QR | DNS_AA);
    rh->ancount = htons(1);
    int off = 12;
    /* Question section: zone name, type AXFR */
    int n = name_to_wire(zname, buf + off, sizeof(buf) - off);
    if (n > 0) {
        off += n;
        put16(buf, off, 252);
        off += 2;
        put16(buf, off, DNS_CLASS_IN);
        off += 2;
    }
    rh->qdcount = htons(1);
    if (soa_len > 0)
        off = append_rr(buf, off, sizeof(buf), zname, DNS_TYPE_SOA, DNS_CLASS_IN,
                        t_zone->soa_minimum, soa_rd, (uint16_t) soa_len);
    off = tsig_axfr_first(buf, off, sizeof(buf), c.query_id, axfr_mac, &axfr_mac_len);
    tcp_send_msg(c.fd, c.ssl, buf, off);

    /* Send all static zone records that belong to this zone */
    size_t znl = strlen(zname);
    for (int i = 0; i < static_zone_sz; i++) {
        dns_rec_t *r = &static_zone[i];
        size_t rnl = strlen(r->name);
        int in_zone = (rnl == znl && strcasecmp(r->name, zname) == 0) ||
                      (rnl > znl + 1 && r->name[rnl - znl - 1] == '.' &&
                       strcasecmp(r->name + rnl - znl, zname) == 0);
        if (!in_zone)
            continue;
        uint8_t rd[256];
        uint16_t rdlen = 0;
        switch (r->type) {
            case DNS_TYPE_A:
                memcpy(rd, r->rdata_a, 4);
                rdlen = 4;
                break;
            case DNS_TYPE_AAAA: {
                struct in6_addr a6;
                if (inet_pton(AF_INET6, r->rdata_str, &a6) != 1)
                    continue;
                memcpy(rd, &a6, 16);
                rdlen = 16;
                break;
            }
            case DNS_TYPE_CNAME:
            case DNS_TYPE_NS: {
                int nn = name_to_wire(r->rdata_str, rd, sizeof(rd));
                if (nn < 0)
                    continue;
                rdlen = (uint16_t) nn;
                break;
            }
            case DNS_TYPE_MX: {
                rd[0] = r->rdata_pref >> 8;
                rd[1] = r->rdata_pref & 0xFF;
                int nn = name_to_wire(r->rdata_str, rd + 2, sizeof(rd) - 2);
                if (nn < 0)
                    continue;
                rdlen = (uint16_t) (2 + nn);
                break;
            }
            case DNS_TYPE_TXT: {
                int tl = txt_encode(r->rdata_str, rd, (int) sizeof(rd));
                if (tl < 0)
                    continue;
                rdlen = (uint16_t) tl;
                break;
            }
            default:
                continue;
        }
        uint8_t mb[BUF_SIZE];
        compress_reset();
        memset(mb, 0, 12);
        dns_hdr_t *mh = (dns_hdr_t *) mb;
        mh->flags = htons(DNS_QR | DNS_AA);
        mh->ancount = htons(1);
        int mo = 12;
        mo = append_rr(mb, mo, sizeof(mb), r->name, r->type, DNS_CLASS_IN, r->ttl, rd, rdlen);
        tsig_axfr_mid(mb, mo, axfr_mac, &axfr_mac_len);
        tcp_send_msg(c.fd, c.ssl, mb, mo);
    }

    /* Send DNSKEY records */
    {
        uint8_t dkrd[68];
        EVP_PKEY *g_zsk = t_zone->zsk;
        EVP_PKEY *g_zsk_ed = t_zone->zsk_ed;
        if (g_zsk && dnskey_rdata_ecdsa(g_zsk, dkrd, sizeof(dkrd)) > 0) {
            uint8_t mb[BUF_SIZE];
            compress_reset();
            memset(mb, 0, 12);
            dns_hdr_t *mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            int mo = 12;
            mo =
                append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600, dkrd, 68);
            tsig_axfr_mid(mb, mo, axfr_mac, &axfr_mac_len);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
        }
        if (g_zsk_ed && dnskey_rdata_ed25519(g_zsk_ed, dkrd, sizeof(dkrd)) > 0) {
            uint8_t mb[BUF_SIZE];
            compress_reset();
            memset(mb, 0, 12);
            dns_hdr_t *mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            int mo = 12;
            mo =
                append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600, dkrd, 36);
            tsig_axfr_mid(mb, mo, axfr_mac, &axfr_mac_len);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
        }
    }

    /* Closing SOA */
    {
        uint8_t mb[BUF_SIZE];
        compress_reset();
        memset(mb, 0, 12);
        dns_hdr_t *mh = (dns_hdr_t *) mb;
        mh->flags = htons(DNS_QR | DNS_AA);
        mh->ancount = htons(1);
        int mo = 12;
        mo = append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_SOA, DNS_CLASS_IN, t_zone->soa_minimum,
                       soa_rd, (uint16_t) soa_len);
        mo = tsig_axfr_last(mb, mo, sizeof(mb), c.query_id, axfr_mac, axfr_mac_len);
        tcp_send_msg(c.fd, c.ssl, mb, mo);
    }
    dns_log(LOG_NOTICE, "[AXFR] Complete to %s\n", cip);
    STAT_INC(g_stat_axfr);
done:
    if (c.ssl) {
        SSL_shutdown(c.ssl);
        SSL_free(c.ssl);
    }
    close(c.fd);
    return NULL;
}

/* ==========================================================================
 * DNS NOTIFY sender (RFC 1996)
 * ======================================================================= */
/* Send a NOTIFY for one zone to a comma-separated target list. */
static void notify_zone(const char *zname, const char *targets_csv) {
    if (!zname[0] || !targets_csv[0])
        return;
    char targets[1024];
    safe_strcpy(targets, targets_csv, sizeof(targets));
    char *sp23 = NULL;
    char *tok = strtok_r(targets, ",", &sp23);
    while (tok) {
        while (*tok == ' ')
            tok++;
        char host[256] = "";
        int port = 53;
        char *col = strchr(tok, ':');
        if (col) {
            *col = 0;
            port = atoi(col + 1);
        }
        safe_strcpy(host, tok, sizeof(host));
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            tok = strtok_r(NULL, ",", &sp23);
            continue;
        }
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
        if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
            close(fd);
            tok = strtok_r(NULL, ",", &sp23);
            continue;
        }
        uint8_t pkt[64] = {0};
        dns_hdr_t *h = (dns_hdr_t *) pkt;
        h->id = htons((uint16_t) rand());
        h->flags = htons(DNS_QR & 0 ? 0 : 0 | DNS_OPCODE_NOTIFY | DNS_AA);
        h->qdcount = htons(1);
        int off = 12;
        int n = name_to_wire(zname, pkt + off, sizeof(pkt) - off);
        if (n > 0) {
            off += n;
            put16(pkt, off, DNS_TYPE_SOA);
            off += 2;
            put16(pkt, off, DNS_CLASS_IN);
            off += 2;
        }
        sendto(fd, pkt, off, 0, (struct sockaddr *) &sa, sizeof(sa));
        dns_log(LOG_NOTICE, "[NOTIFY] %s sent to %s:%d\n", zname, host, port);
        close(fd);
        tok = strtok_r(NULL, ",", &sp23);
    }
}

/* NOTIFY every configured zone's secondaries (RFC 1996). */
static void notify_send(void) {
    pthread_mutex_lock(&g_zones_mutex);
    int n = g_zone_count;
    pthread_mutex_unlock(&g_zones_mutex);
    for (int i = 0; i < n; i++) {
        if (g_zones[i].notify_targets[0])
            notify_zone(g_zones[i].name, g_zones[i].notify_targets);
    }
    /* Fallback: legacy single-zone notify config if no per-zone targets set. */
    if (n == 0 && g_notify_targets[0])
        notify_zone(g_zone_name, g_notify_targets);
}

/* ==========================================================================
 * DNS packet dispatch (shared by UDP / DoT / DoH)
 * ======================================================================= */
static int dns_process(const uint8_t *pkt, int plen, uint8_t *resp, int resp_len, int is_tcp,
                       const struct in_addr *cip) {
    if (plen < 12)
        return -1;
    const dns_hdr_t *h = (const dns_hdr_t *) pkt;
    uint16_t op = ntohs(h->flags) & DNS_OPCODE_MASK;
    if (op == DNS_OPCODE_QUERY)
        return build_query_resp(pkt, plen, resp, resp_len, is_tcp, cip);
    if (op == DNS_OPCODE_UPDATE)
        return handle_update(pkt, plen, resp);
    if (op == DNS_OPCODE_NOTIFY) {
        /* Accept and acknowledge NOTIFY */
        dns_hdr_t *rh = (dns_hdr_t *) resp;
        rh->id = h->id;
        rh->flags = htons(DNS_QR | DNS_OPCODE_NOTIFY | DNS_RCODE_NOERROR);
        rh->qdcount = rh->ancount = rh->nscount = rh->arcount = 0;
        dns_log(LOG_NOTICE, "[NOTIFY] Received NOTIFY\n");
        return 12;
    }
    dns_hdr_t *rh = (dns_hdr_t *) resp;
    rh->id = h->id;
    rh->flags = htons(DNS_QR | DNS_RCODE_NOTIMP);
    rh->qdcount = rh->ancount = rh->nscount = rh->arcount = 0;
    return 12;
}

/* ==========================================================================
 * DNS-over-TLS thread (RFC 7858) — handles AXFR too
 * ======================================================================= */
typedef struct {
    int fd;
    struct sockaddr_in addr;
} dot_conn_t;
static void *dot_thread(void *arg) {
    dot_conn_t c;
    memcpy(&c, arg, sizeof(c));
    free(arg);
    SSL *ssl = NULL;
    pthread_mutex_lock(&g_tls_mutex);
    SSL_CTX *ctx = g_dot_ctx;
    if (ctx) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, c.fd);
    }
    pthread_mutex_unlock(&g_tls_mutex);
    if (ssl && SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(c.fd);
        return NULL;
    }
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c.addr.sin_addr, cip, sizeof(cip));
    struct timeval tv = {.tv_sec = 30};
    setsockopt(c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        uint8_t lb[2];
        int got = 0;
        while (got < 2) {
            int n = ssl ? SSL_read(ssl, lb + got, 2 - got) : (int) recv(c.fd, lb + got, 2 - got, 0);
            if (n <= 0)
                goto dot_done;
            got += n;
        }
        uint16_t ml = (uint16_t) ((lb[0] << 8) | lb[1]);
        if (ml < 12 || ml > BUF_SIZE)
            break;
        uint8_t pkt[BUF_SIZE];
        got = 0;
        while (got < ml) {
            int n =
                ssl ? SSL_read(ssl, pkt + got, ml - got) : (int) recv(c.fd, pkt + got, ml - got, 0);
            if (n <= 0)
                goto dot_done;
            got += n;
        }
        /* Check for AXFR */
        uint16_t qtype = 0;
        char axfr_qn[256] = "";
        {
            int a = name_from_wire(pkt, ml, 12, axfr_qn, sizeof(axfr_qn));
            if (a >= 0 && a + 1 < ml)
                qtype = get16(pkt, a);
        }
        if (qtype == 252 /*AXFR*/ || qtype == 251 /*IXFR*/) {
            axfr_conn_t *ac = malloc(sizeof(axfr_conn_t));
            if (!ac) {
                if (ssl) {
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                }
                close(c.fd);
                return NULL;
            }
            ac->fd = c.fd;
            ac->ssl = ssl;
            ac->addr = c.addr;
            safe_strcpy(ac->zone, axfr_qn, sizeof(ac->zone));
            ac->ixfr = (qtype == 251); /* flag for IXFR vs AXFR */
            /* parse requested SOA serial from authority section of IXFR request */
            ac->ixfr_serial = 0;
            if (qtype == 251 && ml > 12) {
                /* authority section starts after question; scan for SOA */
                int sc = 12;
                char sn2[256];
                sc = name_from_wire(pkt, ml, sc, sn2, sizeof(sn2));
                if (sc > 0)
                    sc += 4; /* skip qtype+qclass */
                /* skip answer section (ancount=0 for IXFR requests) */
                /* scan authority for SOA */
                int ns_count = (ml >= 6) ? ((pkt[8] << 8) | pkt[9]) : 0;
                for (int i = 0; i < ns_count && sc + 10 < ml; i++) {
                    char rn2[256];
                    int ra = name_from_wire(pkt, ml, sc, rn2, sizeof(rn2));
                    if (ra < 0)
                        break;
                    uint16_t rt2 = get16(pkt, ra);
                    uint16_t rdl2 = get16(pkt, ra + 8);
                    if (rt2 == DNS_TYPE_SOA && rdl2 >= 20) {
                        /* serial is after mname+rname wire names */
                        int sp = ra + 10;
                        char mn2[256];
                        sp = name_from_wire(pkt, ml, sp, mn2, sizeof(mn2));
                        if (sp > 0) {
                            char rn3[256];
                            sp = name_from_wire(pkt, ml, sp, rn3, sizeof(rn3));
                        }
                        if (sp > 0 && sp + 4 <= ml)
                            ac->ixfr_serial = get32(pkt, sp);
                        break;
                    }
                    sc = ra + 10 + rdl2;
                }
            }
            ac->query_id = ntohs(((dns_hdr_t *) pkt)->id);
            tsig_verify(pkt, ml); /* stash request MAC into g_tsig_req_mac for response signing */
            axfr_thread(ac);
            return NULL;
        }
        char qn[256] = "?";
        uint16_t qt = 0;
        {
            int a = name_from_wire(pkt, ml, 12, qn, sizeof(qn));
            if (a >= 0 && a + 1 < ml)
                qt = get16(pkt, a);
        }
        dns_log(LOG_DEBUG, "[DoT ] %s %s %s\n", cip, type2str(qt), qn);
        struct timespec _dt0, _dt1;
        clock_gettime(CLOCK_MONOTONIC, &_dt0);
        uint8_t resp[BUF_SIZE];
        int rlen = dns_process(pkt, ml, resp, sizeof(resp), 1, &c.addr.sin_addr);
        clock_gettime(CLOCK_MONOTONIC, &_dt1);
        long _drtt =
            (long) ((_dt1.tv_sec - _dt0.tv_sec) * 1000000L + (_dt1.tv_nsec - _dt0.tv_nsec) / 1000L);
        if (rlen < 0)
            break;
        if (rlen >= 4) {
            uint8_t _rc = ntohs(get16(resp, 2)) & 0xF;
            int _an = rlen >= 8 ? ntohs(get16(resp, 6)) : 0;
            qlog_write(cip, qn, qt, _rc, _an, _drtt, "dot");
        }
        uint8_t rlb[2];
        rlb[0] = rlen >> 8;
        rlb[1] = rlen & 0xFF;
        if (ssl) {
            SSL_write(ssl, rlb, 2);
            SSL_write(ssl, resp, rlen);
        } else {
            send(c.fd, rlb, 2, 0);
            send(c.fd, resp, rlen, 0);
        }
    }
dot_done:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(c.fd);
    return NULL;
}

/* pki_spki_sha256 — SHA-256 of SubjectPublicKeyInfo (for TLSA 3 1 1) */
static int pki_spki_sha256(X509 *cert, uint8_t out[32]) {
    unsigned char *spki = NULL;
    int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki);
    if (n <= 0)
        return 0;
    SHA256(spki, (size_t) n, out);
    OPENSSL_free(spki);
    return 1;
}

/* ==========================================================================
 * HTTP(S) API + DoH handler
 * ======================================================================= */
/* ==========================================================================
 * Localhost-only observability endpoint (migration Step 4)
 *
 * dnsd's entire HTTP surface is now read-only /health + /metrics bound to
 * 127.0.0.1. Management writes and DoH go through the apid front (which talks
 * to Valkey and forwards DoH to dnsd's DNS port). dnsd no longer parses
 * management HTTP, terminates web TLS, or serves a first-boot config portal.
 * ======================================================================= */
static void metrics_send(int fd, int code, const char *ctype, const char *body) {
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                      "Connection: close\r\n\r\n",
                      code,
                      code == 200   ? "OK"
                      : code == 404 ? "Not Found"
                                    : "Bad Request",
                      ctype, strlen(body));
    if (hl > 0) {
        ssize_t w = write(fd, hdr, hl);
        (void) w;
    }
    if (body[0]) {
        ssize_t w = write(fd, body, strlen(body));
        (void) w;
    }
}

static void handle_metrics(int fd) {
    char buf[2048];
    int n = (int) recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
        return;
    buf[n] = 0;
    char method[8], path[256];
    if (sscanf(buf, "%7s %255s", method, path) != 2) {
        metrics_send(fd, 400, "text/plain", "bad request\n");
        return;
    }
    if (strcasecmp(method, "GET") != 0) {
        metrics_send(fd, 404, "text/plain", "not found\n");
        return;
    }
    if (!strcmp(path, "/health")) {
        metrics_send(fd, 200, "text/plain", "ok\n");
        return;
    }
    if (strcmp(path, "/metrics") != 0) {
        metrics_send(fd, 404, "text/plain", "not found\n");
        return;
    }
    /* Prometheus text format (RFC-like, de-facto standard) */
    char body[HTTP_BUF];
    pthread_mutex_lock(&g_stat_mutex);
    uint64_t sq = g_stat_queries, sn = g_stat_noerror, snx = g_stat_nxdomain, sr = g_stat_refused,
             ss = g_stat_servfail, rd = g_stat_rrl_drop, rt = g_stat_rrl_tc, ax = g_stat_axfr,
             dd = g_stat_ddns, si = g_stat_signed;
    pthread_mutex_unlock(&g_stat_mutex);
    snprintf(body, sizeof(body),
             "# HELP dns_queries_total Total DNS queries received\n"
             "# TYPE dns_queries_total counter\n"
             "dns_queries_total %llu\n"
             "# HELP dns_responses_total DNS responses by rcode\n"
             "# TYPE dns_responses_total counter\n"
             "dns_responses_total{rcode=\"NOERROR\"} %llu\n"
             "dns_responses_total{rcode=\"NXDOMAIN\"} %llu\n"
             "dns_responses_total{rcode=\"REFUSED\"} %llu\n"
             "dns_responses_total{rcode=\"SERVFAIL\"} %llu\n"
             "# HELP dns_rrl_total RRL actions\n"
             "# TYPE dns_rrl_total counter\n"
             "dns_rrl_total{action=\"drop\"} %llu\n"
             "dns_rrl_total{action=\"tc\"}   %llu\n"
             "# HELP dns_axfr_total AXFR transfers completed\n"
             "# TYPE dns_axfr_total counter\n"
             "dns_axfr_total %llu\n"
             "# HELP dns_ddns_total DDNS updates accepted\n"
             "# TYPE dns_ddns_total counter\n"
             "dns_ddns_total %llu\n"
             "# HELP dns_dnssec_signatures_total DNSSEC RRSIGs generated\n"
             "# TYPE dns_dnssec_signatures_total counter\n"
             "dns_dnssec_signatures_total %llu\n"
             "# HELP dns_zone_serial Current SOA serial\n"
             "# TYPE dns_zone_serial gauge\n"
             "dns_zone_serial %u\n"
             "# HELP dns_rrl_enabled Whether RRL is active\n"
             "# TYPE dns_rrl_enabled gauge\n"
             "dns_rrl_enabled %d\n",
             (unsigned long long) sq, (unsigned long long) sn, (unsigned long long) snx,
             (unsigned long long) sr, (unsigned long long) ss, (unsigned long long) rd,
             (unsigned long long) rt, (unsigned long long) ax, (unsigned long long) dd,
             (unsigned long long) si, g_soa_serial, g_rrl_enabled);
    metrics_send(fd, 200, "text/plain; version=0.0.4", body);
}

/* ==========================================================================
 * main
 * ======================================================================= */
/* Volatile flag set by SIGHUP handler; checked in the select() loop */
static volatile int g_reload_flag = 0;
static void sighup_handler(int sig) {
    (void) sig;
    g_reload_flag = 1;
}

/* ==========================================================================
 * Privilege drop (least privilege — CLAUDE.md design principle #4)
 *
 * Privileged resources (ports 53/853 need CAP_NET_BIND_SERVICE) are bound while
 * still root in Phase 6; we then *irreversibly* drop to an unprivileged service
 * account before entering the request loop, so a bug in the wire/crypto path
 * never runs with root. The persistent Valkey fd and the listening sockets stay
 * open across the uid change; later Valkey reconnects still work (no seccomp
 * yet). The query log degrades to stderr if it can no longer be reopened.
 *
 * Target account: config:privdrop_user / :privdrop_group, overridable by env
 * DNS_USER / DNS_GROUP, defaulting to "nobody". When the group is unset the
 * account's primary group is used.
 *
 * No-op when not started as root (development run on the high default ports).
 * Fail-closed: if started as root and the drop cannot be completed, exit rather
 * than keep serving untrusted input with full privilege.
 * ======================================================================= */
static void drop_privileges(void) {
    if (geteuid() != 0) {
        dns_log(LOG_INFO, "[Priv] Not running as root — privilege drop skipped\n");
        return;
    }

    char user[64] = "";
    char group[64] = "";
    vk_get("config:privdrop_user", user, sizeof(user));
    vk_get("config:privdrop_group", group, sizeof(group));
    const char *env_user = getenv("DNS_USER");
    const char *env_group = getenv("DNS_GROUP");
    if (env_user && env_user[0])
        safe_strcpy(user, env_user, sizeof(user));
    if (env_group && env_group[0])
        safe_strcpy(group, env_group, sizeof(group));
    if (!user[0])
        safe_strcpy(user, "nobody", sizeof(user));

    errno = 0;
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        dns_log(LOG_ERR,
                "[Priv] FATAL: privdrop user '%s' not found%s — set config:privdrop_user "
                "to a valid account\n",
                user, errno ? " (getpwnam failed)" : "");
        exit(1);
    }
    uid_t target_uid = pw->pw_uid;
    gid_t target_gid = pw->pw_gid;
    if (group[0]) {
        errno = 0;
        struct group *gr = getgrnam(group);
        if (!gr) {
            dns_log(LOG_ERR, "[Priv] FATAL: privdrop group '%s' not found%s\n", group,
                    errno ? " (getgrnam failed)" : "");
            exit(1);
        }
        target_gid = gr->gr_gid;
    }
    if (target_uid == 0) {
        dns_log(LOG_ERR, "[Priv] FATAL: privdrop user '%s' is root (uid 0) — refusing\n", user);
        exit(1);
    }

    /* Order matters: shed supplementary groups, then gid, then uid. Doing uid
     * first would forfeit the privilege needed for the group calls. */
    if (setgroups(0, NULL) != 0) {
        dns_log(LOG_ERR, "[Priv] FATAL: setgroups failed: %s\n", strerror(errno));
        exit(1);
    }
    if (setgid(target_gid) != 0) {
        dns_log(LOG_ERR, "[Priv] FATAL: setgid(%u) failed: %s\n", (unsigned) target_gid,
                strerror(errno));
        exit(1);
    }
    if (setuid(target_uid) != 0) {
        dns_log(LOG_ERR, "[Priv] FATAL: setuid(%u) failed: %s\n", (unsigned) target_uid,
                strerror(errno));
        exit(1);
    }
    /* Verify the drop is irreversible: regaining root must fail. */
    if (setuid(0) == 0 || setgid(0) == 0) {
        dns_log(LOG_ERR, "[Priv] FATAL: privileges not fully dropped (could regain root)\n");
        exit(1);
    }
    /* Belt-and-suspenders: keep the DNSSEC/TSIG key material out of core dumps
     * and ptrace by another process running as the same unprivileged user. */
    if (prctl(PR_SET_DUMPABLE, 0) != 0)
        dns_log(LOG_WARNING, "[Priv] PR_SET_DUMPABLE failed: %s\n", strerror(errno));

    dns_log(LOG_NOTICE, "[Priv] Dropped privileges to user '%s' (uid=%u gid=%u)\n", user,
            (unsigned) target_uid, (unsigned) target_gid);
}

/* ==========================================================================
 * seccomp syscall filter (sandbox layer 2 — CLAUDE.md design principle #4)
 *
 * After privileges are dropped, confine the process to the syscalls it
 * actually needs. The filter is whitelist-based and applied to *all* threads
 * (libseccomp loads with TSYNC), so the already-running keyspace/rollover
 * threads and every future per-connection worker are covered.
 *
 * Mode (config:seccomp_mode):
 *   audit   (default) — default action SCMP_ACT_LOG: a non-whitelisted syscall
 *                       is LOGGED (audit log / dmesg) but still permitted, so we
 *                       can observe the real syscall set without risking a crash.
 *   enforce           — default action EPERM: non-whitelisted syscalls fail.
 *   off               — no filter.
 *
 * Audit-first is deliberate: the whitelist below is a starting baseline; run in
 * audit mode, harvest what the kernel logs, then widen the list before any
 * deployment flips to enforce.
 *
 * Built only when libseccomp is available at compile time (-DHAVE_SECCOMP);
 * otherwise this is a no-op stub and dnsd runs unconfined.
 * ======================================================================= */
#ifdef HAVE_SECCOMP
static void seccomp_install(void) {
    char mode[16] = "";
    vk_get("config:seccomp_mode", mode, sizeof(mode));
    if (!mode[0])
        safe_strcpy(mode, "audit", sizeof(mode));
    if (strcmp(mode, "off") == 0) {
        dns_log(LOG_NOTICE, "[Seccomp] disabled (config:seccomp_mode=off)\n");
        return;
    }
    int enforce = (strcmp(mode, "enforce") == 0);
    uint32_t def_act = enforce ? SCMP_ACT_ERRNO(EPERM) : SCMP_ACT_LOG;

    scmp_filter_ctx ctx = seccomp_init(def_act);
    if (!ctx) {
        dns_log(LOG_ERR, "[Seccomp] seccomp_init failed — running unconfined\n");
        if (enforce)
            exit(1); /* fail closed in enforce mode */
        return;
    }

    /* Baseline whitelist. Grouped by purpose; in audit mode anything missing is
     * logged rather than blocked, so this is a starting point, not the final
     * set. SCMP_SYS() resolves names to this architecture's syscall numbers. */
    const int allow[] = {
        /* socket I/O — UDP/TCP serving + Valkey client (incl. reconnect) */
        SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(readv), SCMP_SYS(writev),
        SCMP_SYS(pread64), SCMP_SYS(pwrite64),
        SCMP_SYS(recvfrom), SCMP_SYS(sendto), SCMP_SYS(recvmsg), SCMP_SYS(sendmsg),
        SCMP_SYS(accept), SCMP_SYS(accept4), SCMP_SYS(socket), SCMP_SYS(connect),
        SCMP_SYS(bind), SCMP_SYS(listen), SCMP_SYS(shutdown),
        SCMP_SYS(setsockopt), SCMP_SYS(getsockopt),
        SCMP_SYS(getsockname), SCMP_SYS(getpeername),
        SCMP_SYS(select), SCMP_SYS(pselect6), SCMP_SYS(poll), SCMP_SYS(ppoll),
        SCMP_SYS(fcntl), SCMP_SYS(ioctl), SCMP_SYS(close),
        /* filesystem — qlog reopen, /dev/urandom, CA certs, /etc/resolv.conf */
        SCMP_SYS(openat), SCMP_SYS(open), SCMP_SYS(lseek),
        SCMP_SYS(fstat), SCMP_SYS(stat), SCMP_SYS(lstat), SCMP_SYS(newfstatat),
        SCMP_SYS(statx), SCMP_SYS(readlink), SCMP_SYS(readlinkat),
        SCMP_SYS(getdents64), SCMP_SYS(access), SCMP_SYS(faccessat),
        SCMP_SYS(faccessat2),
        /* memory */
        SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mremap), SCMP_SYS(mprotect),
        SCMP_SYS(brk), SCMP_SYS(madvise),
        /* threads, signals, process lifecycle */
        SCMP_SYS(clone), SCMP_SYS(clone3), SCMP_SYS(futex),
        SCMP_SYS(set_robust_list), SCMP_SYS(get_robust_list),
        SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(rt_sigreturn),
        SCMP_SYS(sigaltstack), SCMP_SYS(set_tid_address),
        SCMP_SYS(gettid), SCMP_SYS(getpid), SCMP_SYS(tgkill),
        SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(restart_syscall),
        /* time + randomness */
        SCMP_SYS(clock_gettime), SCMP_SYS(clock_nanosleep), SCMP_SYS(nanosleep),
        SCMP_SYS(gettimeofday), SCMP_SYS(time), SCMP_SYS(getrandom),
        /* process/runtime info used by glibc/OpenSSL */
        SCMP_SYS(uname), SCMP_SYS(arch_prctl), SCMP_SYS(rseq),
        SCMP_SYS(getuid), SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid),
        SCMP_SYS(getrlimit), SCMP_SYS(prlimit64), SCMP_SYS(sysinfo),
        SCMP_SYS(sched_getaffinity), SCMP_SYS(sched_yield), SCMP_SYS(getcpu),
        SCMP_SYS(membarrier), SCMP_SYS(prctl),
    };
    int total = (int) (sizeof(allow) / sizeof(allow[0]));
    int skipped = 0;
    for (int i = 0; i < total; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0) != 0)
            skipped++; /* syscall not known on this arch — fine, just skip */
    }

    if (seccomp_load(ctx) != 0) {
        dns_log(LOG_ERR, "[Seccomp] seccomp_load failed: %s%s\n", strerror(errno),
                enforce ? " — refusing to serve without the filter" : " — running unconfined");
        seccomp_release(ctx);
        if (enforce)
            exit(1); /* fail closed */
        return;
    }
    seccomp_release(ctx);

    dns_log(LOG_NOTICE,
            "[Seccomp] filter active: mode=%s, %d syscalls allowed (%d skipped). %s\n", mode,
            total - skipped, skipped,
            enforce ? "Disallowed syscalls return EPERM."
                    : "Audit mode — violations are logged, not blocked "
                      "(check the audit log / dmesg, then widen the whitelist).");
}
#else
static void seccomp_install(void) {
    dns_log(LOG_INFO, "[Seccomp] not built in (libseccomp unavailable at build time)\n");
}
#endif

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, sighup_handler); /* SIGHUP → reload config from Valkey */
    srand(time(NULL));
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    /* Phase 1: Bootstrap Valkey */
    memset(&vk, 0, sizeof(vk));
    vk.fd = -1;
    boot_load();
    dns_log(LOG_INFO, "[Boot] Connecting to Valkey %s:%d...\n", g_valkey_host, g_valkey_port);
    for (int btry = 0; valkey_connect(&vk) != 0; btry++) {
        if (btry >= 30) {
            dns_log(LOG_ERR, "[Boot] FATAL: Valkey unreachable at %s:%d\n", g_valkey_host,
                    g_valkey_port);
            return 1;
        }
        dns_log(LOG_WARNING,
                "[Boot] Valkey unreachable — retrying in 2s (provision connection via env or %s)\n",
                BOOT_FILE);
        sleep(2);
    }
    dns_log(LOG_INFO, "[Boot] Valkey connected.\n");

    /* Phase 2: Load config */
    config_load_from_valkey();

    /* Phase 2b: Populate multi-zone table (primary seed + zone_table:*) */
    seed_primary_zone();
    zones_load_from_valkey();
    dns_log(LOG_INFO, "[Zones] %d zone(s) loaded\n", g_zone_count);

    /* Phase 3: DNSSEC (both algorithms) */
    dnssec_init();

    /* Phase 4: Load cert if already in Valkey; ACME initial issuance is handled
     * by pki_renewal_thread after DNS sockets are open (DNS-01 requires the
     * server to be listening before Let's Encrypt can validate the challenge). */
    tls_reload();

    /* Phase 5: live-reload subscriber — applies config:*, cert:current,
     * zone_table:* edits via Valkey keyspace notifications, no restart needed
     * (migration Step 6). Also does the boot catch-up for cert:current, so it
     * subsumes the old polling cert watcher. ACME/EST live in certd. */
    {
        pthread_t ctid;
        if (pthread_create(&ctid, NULL, keyspace_watch_thread, NULL) == 0)
            pthread_detach(ctid);
        else
            dns_log(LOG_ERR, "[Reload] Failed to start keyspace watcher\n");
    }

    /* Per-zone ZSK rollover engine (RFC 6781 Pre-Publish). */
    {
        pthread_t rtid;
        if (pthread_create(&rtid, NULL, rollover_thread, NULL) == 0)
            pthread_detach(rtid);
        else
            dns_log(LOG_ERR, "[Rollover] Failed to start rollover engine\n");
    }

    /* (mDNS moved to the mdnsd daemon — migration Step 3.) */

    /* Phase 6: Open unicast DNS sockets — dual-stack IPv4 + IPv6 */
    int opt = 1;
    /* IPv6 dual-stack */
    int dns6_sock = -1, dot6_sock = -1, tcp_dns_sock = -1;
    /* Plain TCP DNS on dns_port (RFC 1035 §4.2.2 — TC retry) */
    {
        int ts = socket(AF_INET, SOCK_STREAM, 0);
        if (ts >= 0) {
            setsockopt(ts, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in sa4t = {.sin_family = AF_INET,
                                       .sin_port = htons(g_dns_port),
                                       .sin_addr.s_addr = INADDR_ANY};
            if (bind(ts, (struct sockaddr *) &sa4t, sizeof(sa4t)) < 0 || listen(ts, 32) < 0) {
                perror("[TCP-DNS] bind (non-fatal)");
                close(ts);
            } else {
                tcp_dns_sock = ts;
                dns_log(LOG_INFO, "[TCP ] Plain DNS TCP :%d\n", g_dns_port);
            }
        }
    }
    /* IPv6 UDP */
    {
        int v6s = socket(AF_INET6, SOCK_DGRAM, 0);
        if (v6s >= 0) {
            setsockopt(v6s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            int v6o = 1;
            setsockopt(v6s, IPPROTO_IPV6, IPV6_V6ONLY, &v6o, sizeof(v6o));
            struct sockaddr_in6 sa6u = {.sin6_family = AF_INET6, .sin6_port = htons(g_dns_port)};
            if (bind(v6s, (struct sockaddr *) &sa6u, sizeof(sa6u)) < 0) {
                perror("[IPv6] DNS UDP bind (non-fatal)");
                close(v6s);
            } else {
                dns6_sock = v6s;
                dns_log(LOG_INFO, "[IPv6] DNS UDP :[]::%d\n", g_dns_port);
            }
        }
    }
    /* IPv6 DoT TCP */
    {
        int v6t = socket(AF_INET6, SOCK_STREAM, 0);
        if (v6t >= 0) {
            setsockopt(v6t, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            int v6o = 1;
            setsockopt(v6t, IPPROTO_IPV6, IPV6_V6ONLY, &v6o, sizeof(v6o));
            struct sockaddr_in6 sa6t = {.sin6_family = AF_INET6, .sin6_port = htons(g_dot_port)};
            if (bind(v6t, (struct sockaddr *) &sa6t, sizeof(sa6t)) < 0 || listen(v6t, 32) < 0) {
                perror("[IPv6] DoT TCP bind (non-fatal)");
                close(v6t);
            } else {
                dot6_sock = v6t;
                dns_log(LOG_INFO, "[IPv6] DoT TCP :[]::%d\n", g_dot_port);
            }
        }
    }
    int dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_sock < 0) {
        perror("dns socket");
        return 1;
    }
    setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    {
        struct sockaddr_in sa = {.sin_family = AF_INET,
                                 .sin_port = htons(g_dns_port),
                                 .sin_addr.s_addr = INADDR_ANY};
        if (bind(dns_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("dns bind");
            return 1;
        }
    }
    int dot_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (dot_sock < 0) {
        perror("dot socket");
        return 1;
    }
    setsockopt(dot_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    {
        struct sockaddr_in sa = {.sin_family = AF_INET,
                                 .sin_port = htons(g_dot_port),
                                 .sin_addr.s_addr = INADDR_ANY};
        if (bind(dot_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("dot bind");
            return 1;
        }
        listen(dot_sock, 32);
    }
    /* Localhost-only observability listener (migration Step 4). DoH and the
     * management API are served by apid now, not dnsd. */
    int metrics_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (metrics_sock < 0) {
        perror("metrics socket");
        return 1;
    }
    setsockopt(metrics_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    {
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(g_metrics_port)};
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(metrics_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("metrics bind");
            return 1;
        }
        listen(metrics_sock, 8);
    }
    /* IPv6 sockets already created above */

    dns_log(LOG_INFO, "\n╔═══════════════════════════════════════════════════════════════════╗\n");
    dns_log(LOG_INFO, "║  DNS  UDP plain + RFC2136 UPDATE + NOTIFY  :%d                   ║\n",
            g_dns_port);
    dns_log(LOG_INFO, "║  DoT  TCP DNS-over-TLS + AXFR              :%d  %s           ║\n",
            g_dot_port, g_dot_ctx ? "TLS " : "----");
    dns_log(LOG_INFO, "║  metrics/health (localhost, read-only)     :%d                   ║\n",
            g_metrics_port);
    dns_log(LOG_INFO, "║  DoH + management API now served by apid                          ║\n");
    dns_log(LOG_INFO, "║  Valkey                                     %s:%d          ║\n",
            g_valkey_host, g_valkey_port);
    zone_entry_t *pz = zone_for_qname(g_zone_name);
    uint16_t b_zsk = pz ? pz->zsk_tag : 0, b_zsk_ed = pz ? pz->zsk_ed_tag : 0;
    uint16_t b_ksk = pz ? pz->ksk_tag : 0, b_ksk_ed = pz ? pz->ksk_ed_tag : 0;
    dns_log(LOG_INFO, "║  Zones configured                           %-6d                 ║\n",
            g_zone_count);
    dns_log(LOG_INFO, "║  Primary zone                               %-20s       ║\n", g_zone_name);
    dns_log(LOG_INFO, "║  DNSSEC ZSK P-256   tag                     %-6u (signs records)  ║\n",
            b_zsk);
    dns_log(LOG_INFO, "║  DNSSEC ZSK Ed25519 tag                     %-6u (signs records)  ║\n",
            b_zsk_ed);
    dns_log(LOG_INFO, "║  DNSSEC KSK P-256   tag                     %-6u (signs DNSKEY)   ║\n",
            b_ksk);
    dns_log(LOG_INFO, "║  DNSSEC KSK Ed25519 tag                     %-6u (signs DNSKEY)   ║\n",
            b_ksk_ed);
    dns_log(LOG_INFO, "║  TSIG                                       %s                ║\n",
            g_tsig_secret_len ? "enabled" : "disabled");
    dns_log(LOG_INFO, "║  RRL                                        %s (rate=%d/win=%ds)  ║\n",
            g_rrl_enabled ? "enabled" : "disabled", g_rrl_rate, g_rrl_window);
    dns_log(LOG_INFO, "║  DNS Cookies                                enabled               ║\n");
    dns_log(LOG_INFO, "║  NSID                                       %-20s       ║\n", g_nsid);
    dns_log(LOG_INFO, "║  Authenticated denial                       %s                ║\n",
            g_dnssec_use_nsec3 ? "NSEC3" : "NSEC (plain)");
    dns_log(LOG_INFO, "╚═══════════════════════════════════════════════════════════════════╝\n\n");
    dns_log(LOG_INFO, "Local endpoints (127.0.0.1 only, read-only):\n");
    dns_log(LOG_INFO, "  GET  /health   GET /metrics  (Prometheus)\n");
    dns_log(LOG_INFO, "DoH and the management API are served by apid;\n");
    dns_log(LOG_INFO, "ACME/EST by certd; mDNS by mdnsd.\n");
    dns_log(LOG_INFO, "\n");

    /* All privileged resources are now bound. Irreversibly drop root before
     * serving any untrusted input (least privilege — CLAUDE.md principle #4). */
    drop_privileges();

    /* Confine the process to the syscalls it needs (sandbox layer 2). Default
     * mode is audit (log-only) so the whitelist can be refined before enforce. */
    seccomp_install();

    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(dns_sock, &fds);
        FD_SET(dot_sock, &fds);
        FD_SET(metrics_sock, &fds);
        if (tcp_dns_sock >= 0)
            FD_SET(tcp_dns_sock, &fds);
        if (dns6_sock >= 0)
            FD_SET(dns6_sock, &fds);
        if (dot6_sock >= 0)
            FD_SET(dot6_sock, &fds);
        int maxfd = dns_sock;
        if (dot_sock > maxfd)
            maxfd = dot_sock;
        if (metrics_sock > maxfd)
            maxfd = metrics_sock;
        if (tcp_dns_sock > maxfd)
            maxfd = tcp_dns_sock;
        if (dns6_sock > maxfd)
            maxfd = dns6_sock;
        if (dot6_sock > maxfd)
            maxfd = dot6_sock;
        struct timeval tv = {.tv_sec = 30};
        int ready = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                /* EINTR from SIGHUP — check reload flag */
                if (g_reload_flag) {
                    g_reload_flag = 0;
                    dns_log(LOG_NOTICE, "[SIGHUP] Reloading configuration from Valkey\n");
                    config_load_from_valkey();
                    tls_reload();
                    dns_log(LOG_NOTICE, "[SIGHUP] Reload complete\n");
                }
                continue;
            }
            perror("select");
            break;
        }
        /* Also check outside EINTR (Linux delivers signal without error) */
        if (g_reload_flag) {
            g_reload_flag = 0;
            dns_log(LOG_NOTICE, "[SIGHUP] Reloading configuration from Valkey\n");
            config_load_from_valkey();
            tls_reload();
            dns_log(LOG_NOTICE, "[SIGHUP] Reload complete\n");
        }

        if (FD_ISSET(dns_sock, &fds)) {
            uint8_t pkt[BUF_SIZE], resp[BUF_SIZE];
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            ssize_t nn = recvfrom(dns_sock, pkt, sizeof(pkt), 0, (struct sockaddr *) &cli, &clen);
            if (nn > 0) {
                char cip2[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli.sin_addr, cip2, sizeof(cip2));
                char qn[256] = "?";
                uint16_t qt = 0;
                int a = name_from_wire(pkt, nn, 12, qn, sizeof(qn));
                if (a >= 0 && a + 1 < nn)
                    qt = get16(pkt, a);
                dns_log(LOG_DEBUG, "[DNS ] %s  %s %s\n", cip2, type2str(qt), qn);
                struct timespec _qt0, _qt1;
                clock_gettime(CLOCK_MONOTONIC, &_qt0);
                int rlen = dns_process(pkt, (int) nn, resp, sizeof(resp), 0, &cli.sin_addr);
                clock_gettime(CLOCK_MONOTONIC, &_qt1);
                long _rtt = (long) ((_qt1.tv_sec - _qt0.tv_sec) * 1000000L +
                                    (_qt1.tv_nsec - _qt0.tv_nsec) / 1000L);
                if (rlen > 0) {
                    sendto(dns_sock, resp, rlen, 0, (struct sockaddr *) &cli, clen);
                    uint8_t _rc = rlen >= 4 ? (ntohs(get16(resp, 2)) & 0xF) : 2;
                    int _an = rlen >= 8 ? ntohs(get16(resp, 6)) : 0;
                    qlog_write(cip2, qn, qt, _rc, _an, _rtt, "udp");
                }
            }
        }

        /* IPv6 UDP queries */
        if (dns6_sock >= 0 && FD_ISSET(dns6_sock, &fds)) {
            uint8_t pkt6[BUF_SIZE], resp6[BUF_SIZE];
            struct sockaddr_in6 cli6;
            socklen_t cl6 = sizeof(cli6);
            ssize_t nn6 =
                recvfrom(dns6_sock, pkt6, sizeof(pkt6), 0, (struct sockaddr *) &cli6, &cl6);
            if (nn6 > 0) {
                char cip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &cli6.sin6_addr, cip6, sizeof(cip6));
                char qn6[256] = "?";
                uint16_t qt6 = 0;
                int a6 = name_from_wire(pkt6, nn6, 12, qn6, sizeof(qn6));
                if (a6 >= 0 && a6 + 1 < (int) nn6)
                    qt6 = get16(pkt6, a6);
                dns_log(LOG_DEBUG, "[DNS6] %s  %s %s\n", cip6, type2str(qt6), qn6);
                /* Map IPv4-mapped addresses for cookie/logging */
                struct in_addr dummy4 = {.s_addr = 0};
                if (IN6_IS_ADDR_V4MAPPED(&cli6.sin6_addr))
                    memcpy(&dummy4, ((uint8_t *) &cli6.sin6_addr) + 12, 4);
                struct timespec _t0, _t1;
                clock_gettime(CLOCK_MONOTONIC, &_t0);
                int rlen6 = dns_process(pkt6, (int) nn6, resp6, sizeof(resp6), 0, &dummy4);
                clock_gettime(CLOCK_MONOTONIC, &_t1);
                long _rtt6 = (long) ((_t1.tv_sec - _t0.tv_sec) * 1000000L +
                                     (_t1.tv_nsec - _t0.tv_nsec) / 1000L);
                if (rlen6 > 0) {
                    sendto(dns6_sock, resp6, rlen6, 0, (struct sockaddr *) &cli6, cl6);
                    uint8_t _rc6 = rlen6 >= 4 ? (ntohs(get16(resp6, 2)) & 0xF) : 2;
                    int _an6 = rlen6 >= 8 ? ntohs(get16(resp6, 6)) : 0;
                    qlog_write(cip6, qn6, qt6, _rc6, _an6, _rtt6, "udp6");
                }
            }
        }

        /* Plain TCP DNS (TC retry, RFC 1035 §4.2.2) — no TLS */
        if (tcp_dns_sock >= 0 && FD_ISSET(tcp_dns_sock, &fds)) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(tcp_dns_sock, (struct sockaddr *) &cli, &clen);
            if (cfd >= 0) {
                dot_conn_t *c = malloc(sizeof(dot_conn_t));
                if (!c) {
                    close(cfd);
                } else {
                    c->fd = cfd;
                    c->addr = cli;
                    /* dot_thread handles ssl==NULL via plain send/recv */
                    pthread_t tid;
                    pthread_attr_t attr;
                    pthread_attr_init(&attr);
                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                    pthread_create(&tid, &attr, dot_thread, c);
                    pthread_attr_destroy(&attr);
                }
            }
        }

        /* IPv4 DoT */
        if (FD_ISSET(dot_sock, &fds)) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(dot_sock, (struct sockaddr *) &cli, &clen);
            if (cfd >= 0) {
                dot_conn_t *c = malloc(sizeof(dot_conn_t));
                if (!c) {
                    close(cfd);
                } else {
                    c->fd = cfd;
                    c->addr = cli;
                    pthread_t tid;
                    pthread_attr_t attr;
                    pthread_attr_init(&attr);
                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                    pthread_create(&tid, &attr, dot_thread, c);
                    pthread_attr_destroy(&attr);
                }
            }
        }

        /* IPv6 DoT */
        if (dot6_sock >= 0 && FD_ISSET(dot6_sock, &fds)) {
            struct sockaddr_in6 cli6;
            socklen_t cl6 = sizeof(cli6);
            int cfd6 = accept(dot6_sock, (struct sockaddr *) &cli6, &cl6);
            if (cfd6 >= 0) {
                dot_conn_t *c6 = malloc(sizeof(dot_conn_t));
                if (!c6) {
                    close(cfd6);
                } else {
                    c6->fd = cfd6;
                    memset(&c6->addr, 0, sizeof(c6->addr));
                    c6->addr.sin_family = AF_INET;
                    if (IN6_IS_ADDR_V4MAPPED(&cli6.sin6_addr))
                        memcpy(&c6->addr.sin_addr, ((uint8_t *) &cli6.sin6_addr) + 12, 4);
                    c6->addr.sin_port = cli6.sin6_port;
                    pthread_t tid6;
                    pthread_attr_t attr6;
                    pthread_attr_init(&attr6);
                    pthread_attr_setdetachstate(&attr6, PTHREAD_CREATE_DETACHED);
                    pthread_create(&tid6, &attr6, dot_thread, c6);
                    pthread_attr_destroy(&attr6);
                }
            }
        }

        if (FD_ISSET(metrics_sock, &fds)) {
            int cfd = accept(metrics_sock, NULL, NULL);
            if (cfd >= 0) {
                handle_metrics(cfd);
                close(cfd);
            }
        }
    }

    close(dns_sock);
    close(dot_sock);
    close(metrics_sock);
    if (tcp_dns_sock >= 0)
        close(tcp_dns_sock);
    if (dns6_sock >= 0)
        close(dns6_sock);
    if (dot6_sock >= 0)
        close(dot6_sock);
    if (vk.fd >= 0)
        close(vk.fd);
    if (g_dot_ctx)
        SSL_CTX_free(g_dot_ctx);
    for (int zi = 0; zi < g_zone_count; zi++) {
        zone_entry_t *z = &g_zones[zi];
        if (z->zsk)
            EVP_PKEY_free(z->zsk);
        if (z->zsk_ed)
            EVP_PKEY_free(z->zsk_ed);
        if (z->ksk)
            EVP_PKEY_free(z->ksk);
        if (z->ksk_ed)
            EVP_PKEY_free(z->ksk_ed);
        if (z->zsk_next)
            EVP_PKEY_free(z->zsk_next);
        if (z->zsk_ed_next)
            EVP_PKEY_free(z->zsk_ed_next);
    }
    if (g_syslog_enabled)
        closelog();
    pthread_mutex_lock(&g_log_mutex);
    rsyslog_disconnect();
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}
