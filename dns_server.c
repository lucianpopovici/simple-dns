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
 *   7477       CSYNC – child-to-parent synchronisation record (type 62);
 *              stored as serial|flags|NS,A,AAAA; query + AXFR serve, DNSSEC-signed
 *   7553       URI records
 *   9460       SVCB / HTTPS service-binding records (SvcParams stored as TLV;
 *              query + AXFR serve, DNSSEC-signed)
 *   8976       ZONEMD – whole-zone message digest (SIMPLE scheme, SHA-384);
 *              server-computed over the AXFR RRset, recomputed on every serial
 *              bump, opt-in via config:[zone:<z>:]zonemd (default off)
 *   1035 PTR   Reverse DNS — serve in-addr.arpa / ip6.arpa zones (query/AXFR);
 *              optional auto-PTR for DDNS A/AAAA (config:ddns_auto_ptr)
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
 *   9432       Catalog Zones – bulk provisioning of member zones (consumer side)
 *   9619       QDCOUNT=1 enforcement for QUERY
 *   5452       Forwarder upstream-reply validation (source addr/port + ID +
 *              question match; random ephemeral source port) — anti-spoofing
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
 *   config:soa_ttl             TTL the SOA RR is served with; negative-response
 *                              NSEC/NSEC3 + authority SOA are capped at
 *                              min(soa_ttl, soa_minimum) per RFC 9077.
 *                              (default: unset → soa_minimum)
 *   config:zone:<z>:soa_ttl    Per-zone override of the above.
 *   config:zone_serial         SOA serial (auto-incremented on changes)
 *   config:tsig_key_name       TSIG key name           (default: tsig-key)
 *   config:tsig_secret_b64     TSIG HMAC-SHA256 secret (base64)
 *   config:nsid                NSID string             (default: hostname)
 *   config:cookie_secret       16-byte hex cookie secret
 *   config:axfr_allow          Comma-separated IPs/CIDRs allowed to do AXFR
 *   config:notify_targets      Comma-separated IP:port targets for NOTIFY
 *   config:forward_enabled     "1" to forward out-of-zone queries (default: 0).
 *                              OFF + ACL-gated: an open resolver is an abuse
 *                              target. Empty config:forward_allow disables it
 *                              regardless (fail closed). Internal use only.
 *   config:forwarders          Upstream resolvers "ip[:port],..." (default :53),
 *                              tried in order until one answers.
 *   config:forward_allow       IPs/CIDRs allowed recursion (empty = disabled).
 *   config:forward_timeout_ms  Per-upstream wait in ms (default 1500).
 *   config:lb_mode             A/AAAA RRset rotation: none (default) | rr
 *                              (round-robin) | random. Local serving policy
 *                              only — not zone data, never travels in AXFR/IXFR.
 *   config:lb_health_enabled   "1" to TCP-probe load-balanced A/AAAA addresses
 *                              and drop down ones from answers (fail-open when
 *                              all are down). Local serving policy only.
 *   config:lb_health_targets   "name[:port],..." — names whose A/AAAA addresses
 *                              are probed (port default 80).
 *   config:lb_health_interval  Seconds between probe rounds (default 10).
 *   config:lb_health_timeout_ms  Per-probe TCP connect timeout (default 1000).
 *   config:dot_require_client_cert  "1" to require a verified client cert (mTLS)
 *                              on the DoT/transfer listener (needs
 *                              config:mtls_ca_pem). Default 0 — keep OFF on
 *                              public instances; ON on a hidden master to gate
 *                              AXFR/IXFR to the secondaries only.
 *   config:ddns_allow_suffix   When set (e.g. ".dyn.corp.local"), RFC 2136
 *                              UPDATE may only touch names at/under this suffix;
 *                              everything else is REFUSED. Empty = unrestricted.
 *   config:ddns_auto_ptr       When set, a forward A/AAAA DDNS registration also
 *                              maintains the matching reverse PTR lease in the
 *                              in-addr.arpa / ip6.arpa zone configured locally
 *                              (ddns:<revzone>:PTR:*). Off = no auto-PTR.
 *   config:ddns_sweep_secs     Interval (s) of the primary's DDNS lease-expiry
 *                              sweeper (default 30, 0 = off): replays a silently
 *                              expired ddns:* lease as a serial bump + IXFR 'D' +
 *                              NOTIFY so secondaries converge.
 *   config:zone_role           "primary" (default) or "secondary". A secondary
 *                              is a read-only replica: UPDATE → NOTAUTH and it
 *                              never generates DNSSEC keys (load-only).
 *   config:primary_host        Master a secondary pulls each zone from at start.
 *   config:primary_port        Master port (default 53).
 *   config:primary_tls         "1" to pull over TLS (DoT); verify the master
 *                              against config:xfr_ca_pem and present
 *                              config:xfr_client_cert_pem/xfr_client_key_pem
 *                              (mTLS) if set. Use TLS until transfer TSIG lands.
 *   config:privdrop_user       Unprivileged user dnsd setuids to after binding
 *                              sockets (env DNS_USER overrides; default "nobody")
 *   config:privdrop_group      Unprivileged group (env DNS_GROUP; default = the
 *                              user's primary group). Only acts when run as root.
 *   config:seccomp_mode        Syscall sandbox: "enforce" (default, EPERM),
 *                              "audit" (log-only), or "off". Needs -DHAVE_SECCOMP.
 *   config:chroot_dir          If set (env DNS_CHROOT overrides), confine the
 *                              filesystem here after binding sockets, before the
 *                              privilege drop. Only acts when run as root.
 *   config:isolation_mode      How chroot_dir is applied (env DNS_ISOLATION
 *                              overrides): "chroot" (default, chroot(2)) or
 *                              "mountns" (private mount namespace + pivot_root(2)).
 *
 * Multi-zone key schema (migration Step 7) — records carry the owning zone:
 *   zone_table:<zone>          Zone SOA + transfer settings
 *                              (mname|rname|serial|refresh|retry|expire|minimum
 *                               |axfr_allow|notify_targets[|soa_ttl])
 *                              soa_ttl is an optional additive trailing field
 *                              (ADR-003); absent → soa_minimum (RFC 9077).
 *   schema:version             ADR-003 inter-daemon schema contract "major.minor"
 *                              (current 1.0; dnsd seeds it, every daemon checks it
 *                              at startup — major mismatch is fatal, minor warns).
 *                              Simple values stay pipe-delimited; complex/extensible
 *                              values (SVCB, NAPTR, ZONEMD, ENUM, EPP) use the
 *                              versioned TLV codec (tlv_* in libdnswire). See the
 *                              format registry in CLAUDE.md.
 *   zone:<zone>:<TYPE>:<name>  Authoritative record, e.g. zone:example.com:A:www.example.com
 *                              (SRV ttl|prio|weight|port|target; CAA ttl|flags|tag|value;
 *                               SSHFP ttl|alg|fptype|fp_hex; TLSA ttl|usage|sel|mtype|hex;
 *                               DNAME ttl|target; LOC ttl|loc_wire_hex; …)
 *   ddns:<zone>:<TYPE>:<name>  Dynamic record (RFC 2136 / HTTP /update)
 *   ixfr:<zone>:journal        RFC 1995 IXFR journal (RPUSH list, capped at
 *                              IXFR_JOURNAL_MAX): "<from>|<to>|<A|D>|<name>|<value>"
 *                              per A/AAAA change; a gap forces AXFR fallback.
 *   config:zone:<zone>:serial  Per-zone SOA serial counter (primary keeps config:zone_serial)
 *   config:zone:<zone>:nsec3_iters / :nsec3_salt / :dnssec_nsec_mode
 *                              Per-zone denial config (defaults from the global config:* values)
 *   config:[zone:<zone>:]zonemd  RFC 8976 opt-in (1 = publish apex ZONEMD; default off).
 *                              dnsd writes the digest to zone:<zone>:ZONEMD:<apex> as
 *                              ttl|hex(TLV) — server-generated, recomputed on each serial bump.
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
 * Per-zone KSK rollover schema (RFC 6781 §4.1.2 Double-Signature; written by dnsd):
 *   dnssec:<zone>:ksk_created  Epoch the active KSK set was created
 *   dnssec:<zone>:ksk_rollover "double|<epoch>" or "retire|<epoch>" (absent = idle)
 *   dnssec:<zone>:ksk_next / :ksk_ed25519_next
 *                              Incoming KSK set, present only during a rollover
 *   dnssec:<zone>:ksk_rollover_seen              Last manual-trigger value acted on (edge-trigger)
 *   config:[zone:<zone>:]ksk_validity            KSK lifetime (s); 0/unset = no auto-roll
 *   config:[zone:<zone>:]ksk_publish_hold        Double-phase hold (s, default 3600; parent adds
 * DS) config:[zone:<zone>:]ksk_commit_hold         Retire-phase hold (s, default 3600; old DS
 * expires) config:zone:<zone>:ksk_rollover_request      Manual trigger (set a fresh value to roll
 * now)
 *
 * Catalog zones schema (RFC 9432; dnsd CONSUMES, the control plane WRITES):
 *   A catalog is an ordinary zone (it has zone_table:<cat>) carrying:
 *     zone:<cat>:TXT:version.<cat>          "2"  — RFC 9432 §4.1 schema version
 *     zone:<cat>:PTR:<id>.zones.<cat>       <member-zone>  — one per member
 *   dnsd provisions each member into its in-memory zone table (deriving SOA
 *   names from the member, inheriting the catalog's SOA timers / AXFR ACL /
 *   NOTIFY targets, generating dnssec:<member>:* keys), and deactivates members
 *   the catalog stops listing. It never writes zone_table:* — provisioning is
 *   in-memory, re-derived on each scan (boot, a config: or zone_table: change,
 *   and the rollover tick). config:zone:<member>:serial persists a member serial.
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
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <net/if.h>
#include <ifaddrs.h>
#include "sandbox.h" /* shared privilege-drop / chroot / seccomp sandbox */
#include <openssl/crypto.h>
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
#define MAX_AXFR_THREADS 8
#define TSIG_ALG_HMAC_SHA256 "hmac-sha256."

/* DNSSEC signing keys are now per-zone (see zone_entry_t): ZSK signs RRsets,
 * KSK signs the DNSKEY RRset.  Loaded from dnssec:<zone>:* at startup. */

/* Forward declarations for helpers used before their definitions */
static void ixfr_journal_append(const char *, uint32_t, uint32_t, char, const char *, const char *);
static void notify_send(void);
/* Wire + Valkey helpers used by early code (multi-zone, NSEC) */
static int vk_set(const char *, const char *, uint32_t);
static int vk_get(const char *, char *, int);
static int emit_rr(uint8_t *, int, int, const char *, uint16_t, uint32_t, const uint8_t *, uint16_t,
                   int, int *);

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
 * Value:      mname|rname|serial|refresh|retry|expire|minimum|axfr_allow|notify_targets[|soa_ttl]
 * ======================================================================= */
#define MAX_ZONES 16

typedef struct {
    char name[256];
    char soa_mname[256];
    char soa_rname[256];
    uint32_t soa_serial;
    uint32_t soa_refresh, soa_retry, soa_expire, soa_minimum;
    /* TTL the SOA RR is served with (RFC 9077 "the SOA's TTL"). 0 = unset →
     * falls back to soa_minimum (the legacy behavior). The negative-response
     * NSEC/NSEC3 + authority SOA are capped at min(this, soa_minimum). */
    uint32_t soa_ttl;
    /* Secondary zone-maintenance state (hidden-master plan Gap 6). xfr_last_ok =
     * epoch of the last successful contact with the master (resets the expire
     * timer); xfr_next_check = epoch the refresh thread should next pull. */
    time_t xfr_last_ok;
    time_t xfr_next_check;
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
    /* Per-zone KSK rollover (RFC 6781 §4.1.2 Double-Signature). The incoming KSK
     * set is published alongside the current one and the DNSKEY RRset is signed
     * by BOTH KSKs for the whole rollover; CDS/CDNSKEY advertises both DS so the
     * parent can swap, then only the new one, before the old KSK is retired — so
     * the parent's DS always matches a KSK that signs the published DNSKEY. */
    EVP_PKEY *ksk_next; /* incoming KSK P-256 (rollover only) */
    uint16_t ksk_next_tag;
    EVP_PKEY *ksk_ed_next; /* incoming KSK Ed25519 (rollover only) */
    uint16_t ksk_ed_next_tag;
    int ksk_roll_phase;    /* KROLL_NONE / KROLL_DOUBLE / KROLL_RETIRE */
    time_t ksk_roll_since; /* epoch the current KSK phase was entered */
    time_t ksk_created;    /* epoch the current KSK set was created */
    /* Catalog zones (RFC 9432). A zone provisioned from a catalog records the
     * catalog's name here (empty = operator-defined via zone_table). When the
     * catalog stops listing the member, dnsd deactivates the slot rather than
     * compacting the array, so a request thread that already holds a zone
     * pointer never dereferences freed memory. zone_for_qname skips inactive
     * slots; a member that reappears reuses its slot by name and reactivates. */
    int active;               /* 1 = served; 0 = deprovisioned (slot retained) */
    char catalog_origin[256]; /* owning catalog zone, or "" if operator-defined */
} zone_entry_t;

/* ZSK rollover phases (RFC 6781 §4.1.1.1 Pre-Publish). */
#define ROLL_NONE 0
#define ROLL_PUBLISH 1 /* publish current+next; keep signing with current */
#define ROLL_COMMIT 2  /* publish current+next; sign with next */

/* KSK rollover phases (RFC 6781 §4.1.2 Double-Signature). Both KSKs are in the
 * DNSKEY RRset and both sign it throughout; only the advertised CDS/CDNSKEY (and
 * thus the DS the parent should hold) changes between phases. */
#define KROLL_NONE 0
#define KROLL_DOUBLE 1 /* publish old+new KSK; CDS/CDNSKEY = {old, new} */
#define KROLL_RETIRE 2 /* publish old+new KSK; CDS/CDNSKEY = {new} only */

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
        if (!z->active)
            continue; /* deprovisioned catalog member — not served */
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
                       uint32_t soa_ttl, const char *axfr_allow, const char *notify_targets) {
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
    z->soa_ttl = soa_ttl;
    safe_strcpy(z->axfr_allow, axfr_allow ? axfr_allow : "127.0.0.1", sizeof(z->axfr_allow));
    safe_strcpy(z->notify_targets, notify_targets ? notify_targets : "", sizeof(z->notify_targets));
    z->active = 1; /* (re)affirm the slot; catalog_origin is preserved across upserts */
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
/* Reconcile catalog-zone (RFC 9432) membership: provision/deprovision members. */
static void catalog_scan_all(void);
/* RFC 8976: recompute the apex ZONEMD only if the stored digest is absent or
 * stale (its serial != the zone's current serial). Idempotent — safe to call on
 * boot and on every config/zone_table reload without churning a static zone. */
static void zonemd_seed_if_stale(zone_entry_t *z);
/* Serializes catalog scans so the boot / keyspace / rollover callers cannot
 * interleave a provision against a deprovision for the same slot. */
static pthread_mutex_t g_catalog_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ==========================================================================
 * Runtime configuration
 * ======================================================================= */
static char g_valkey_host[256] = "127.0.0.1";
static int g_valkey_port = 6379;
static char g_valkey_pass[256] = "";
static int g_metrics_port = METRICS_PORT_DEFAULT;
static int g_dns_port = DNS_PORT_DEFAULT;
static int g_dot_port = DOT_PORT_DEFAULT;
/* SO_REUSEPORT UDP worker threads for IPv4 (config:udp_workers / env UDP_WORKERS).
 * 1 = legacy single-threaded select() loop (default, unchanged behavior). >1 =
 * N kernel-load-balanced worker threads, each with its own UDP socket and its
 * own (lock-free) Valkey connection. */
static int g_udp_workers = 1;
/* recvmmsg/sendmmsg batch size for the worker path (config:udp_rx_batch / env
 * UDP_RX_BATCH). 1 = per-packet recvfrom/sendto (default). >1 amortizes the
 * per-packet syscall cost by draining up to N datagrams per recvmmsg and
 * replying with one sendmmsg. Uses MSG_WAITFORONE so latency is unaffected at
 * low load (returns as soon as ≥1 datagram is ready). Worker path only. */
static int g_udp_rx_batch = 1;
#define UDP_BATCH_MAX 64
static int g_http_port = HTTP_PORT_DEFAULT;
static int g_https_port = HTTPS_PORT_DEFAULT;
static char g_ddns_secret[256] = "changeme";
/* config:ddns_allow_suffix — when non-empty, RFC 2136 UPDATE may only touch
 * names at or under this suffix (e.g. ".dyn.corp.local"). One shared TSIG key
 * otherwise lets any registrant overwrite any name (apex, www, …); the suffix
 * confines dynamic registrants to a sub-domain so static/infra names are immune
 * (CLAUDE-discovery.md Gap 3). Empty = no restriction (legacy behaviour). */
static char g_ddns_allow_suffix[256] = "";
/* config:ddns_auto_ptr — when set, a forward A/AAAA DDNS registration also
 * maintains the matching reverse PTR lease in whichever in-addr.arpa / ip6.arpa
 * zone is configured locally (CLAUDE-discovery.md Gap 4). Off = no auto-PTR. */
static int g_ddns_auto_ptr = 0;
/* config:ddns_sweep_secs — interval of the DDNS lease-expiry sweeper (primary
 * only). A ddns:* lease expiring in Valkey is otherwise a SILENT delete (no
 * serial bump, no IXFR journal, no NOTIFY), so secondaries would keep serving a
 * dead workload's name until some unrelated change advanced the serial. The
 * sweeper detects vanished leases and emits the missing replication events
 * (CLAUDE-discovery.md Gap 2). 0 disables it. */
static int g_ddns_sweep_secs = 30;
/* config:zone_role — "primary" (default) or "secondary". A secondary is a
 * read-only replica: it pulls the zone from a master and must refuse all local
 * writes (UPDATE → NOTAUTH) and never mint its own DNSSEC keys (it would publish
 * a trust anchor that diverges from the master's). Hidden-master plan Gap 2/7/8. */
static int g_zone_secondary = 0;
/* RRL configuration (rate limiting) */
static int g_rrl_enabled = 0;
static int g_rrl_rate = 5;   /* max responses/window */
static int g_rrl_window = 1; /* window in seconds */
static int g_rrl_slip = 2;   /* send TC every slip-th excess response */

/* Out-of-zone forwarding (CLAUDE-forwarder.md). OFF by default and gated by a
 * client ACL: an empty g_forward_allow disables forwarding regardless of
 * g_forward_enabled (fail closed — a public instance must never become an open
 * resolver). dnsd normally reaches nothing but Valkey; this is the one opt-in
 * outbound path, for internal-only deployments. */
static int g_forward_enabled = 0;       /* config:forward_enabled */
static char g_forwarders[1024] = "";    /* config:forwarders — ip[:port],... (port 53 default) */
static char g_forward_allow[1024] = ""; /* config:forward_allow — IPs/CIDRs allowed recursion */
static int g_forward_timeout_ms = 1500; /* config:forward_timeout_ms — per-upstream wait */
/* Cap concurrent forward worker threads so a dead/slow upstream cannot
 * accumulate threads under load; over the cap we answer SERVFAIL immediately. */
#define FWD_MAX_INFLIGHT 256
static int g_fwd_inflight = 0;
static pthread_mutex_t g_fwd_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Server-side load balancing for A/AAAA RRsets (CLAUDE-loadbalance.md Gap 1).
 * Local serving policy only — not zone data, so it does not travel in AXFR/IXFR
 * and may differ per instance. Rotation never invalidates DNSSEC: emit_rr signs
 * each address RR independently, so reordering the RRset is signature-neutral. */
typedef enum { LB_NONE = 0, LB_RR, LB_RANDOM } lb_mode_t;
static lb_mode_t g_lb_mode = LB_NONE; /* config:lb_mode: none|rr|random */
/* One shared round-robin cursor across all names still yields a uniform
 * per-name distribution; atomic so concurrent workers stay race-free. */
static _Atomic uint32_t g_lb_counter = 0;
#define LB_MAX_ADDRS 32 /* cap addresses rotated per RRset (values are <=256 B) */

/* Load-balancing health checks (CLAUDE-loadbalance.md Gap 2). When enabled, a
 * background thread TCP-probes the addresses behind configured names and the
 * query path drops addresses marked down — unless ALL are down, in which case it
 * emits everything (a degraded answer beats an empty NOERROR resolvers would
 * negative-cache). Health state is local serving policy, never written back to
 * the zone, so it must never feed a secondary's store (CLAUDE.md Gap 7). */
static int g_lb_health_enabled = 0;         /* config:lb_health_enabled */
static char g_lb_health_targets[1024] = ""; /* config:lb_health_targets: name[:port],... */
static int g_lb_health_interval = 10;       /* config:lb_health_interval (s) */
static int g_lb_health_timeout_ms = 1000;   /* config:lb_health_timeout_ms */
#define LB_HEALTH_DEFAULT_PORT 80
#define LB_HEALTH_MAX 256 /* cap distinct probed addresses */
typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int up;
} lb_health_entry_t;
/* Current health table, rebuilt each probe round and swapped under the mutex.
 * The query path reads it only when health checking is enabled. */
static lb_health_entry_t *g_lb_health = NULL;
static int g_lb_health_count = 0;
static pthread_mutex_t g_lb_health_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Structured query log */
static char g_query_log_path[512] = ""; /* "" = disabled */
static FILE *g_query_log_fp = NULL;
static pthread_mutex_t g_qlog_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Write one JSON-line query log entry.
 * Format: {"ts":<unix>,"client":"<ip>","qname":"<n>","qtype":"<t>",
 *           "rcode":<r>,"answers":<n>,"rtt_us":<t>,"transport":"<udp|tcp|dot|doh>"}
 */
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
/* config:dot_require_client_cert — when 1 (and config:mtls_ca_pem is set), the
 * DoT/transfer listener requires a verified client cert (mTLS). OFF by default:
 * a public-facing instance shares the DoT port with ordinary RFC 7858 clients
 * that present no cert. On a hidden master (only secondaries connect) it can be
 * switched on globally to lock down AXFR/IXFR (hidden-master plan Gap 1). */
static int g_dot_require_client_cert = 0;

/* Secondary transfer-client config (hidden-master plan Gap 3). A secondary
 * (config:zone_role=secondary) pulls each zone from this master at startup. */
static char g_primary_host[256] = "";            /* config:primary_host */
static int g_primary_port = 53;                  /* config:primary_port */
static int g_primary_tls = 0;                    /* config:primary_tls (DoT) */
static char g_xfr_ca_pem[MAX_PEM] = "";          /* config:xfr_ca_pem — verify master */
static char g_xfr_client_cert_pem[MAX_PEM] = ""; /* config:xfr_client_cert_pem — our mTLS id */
static char g_xfr_client_key_pem[MAX_PEM] = "";  /* config:xfr_client_key_pem */
/* Refresh engine (Gap 6): a NOTIFY (Gap 5) sets g_xfr_wake + signals the cond so
 * the refresh thread re-checks immediately instead of waiting for the timer. */
static pthread_mutex_t g_xfr_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_xfr_cond = PTHREAD_COND_INITIALIZER;
static int g_xfr_wake = 0;

/* SOA parameters */
static char g_soa_mname[256] = "ns1.example.local";
static char g_soa_rname[256] = "hostmaster.example.local";
static uint32_t g_soa_refresh = 3600;
static uint32_t g_soa_retry = 900;
static uint32_t g_soa_expire = 604800;
static uint32_t g_soa_minimum = 300;
static uint32_t g_soa_ttl = 0; /* 0 = unset → use g_soa_minimum (RFC 9077) */
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
 * Console (stdout/stderr) output:
 *   config:console_level     "debug","info","notice","warning","err","crit"
 *                             Messages at this level AND MORE SEVERE are printed
 *                             to stdout/stderr. Per-query "[DNS ]" logging is at
 *                             DEBUG, so the default (info) keeps it off the hot
 *                             path. Env override: CONSOLE_LEVEL.   (default: info)
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

/* ── Console (stdout/stderr) state ──────────────────────────────────────── */
/* Gates the stdout/stderr log block in dns_log(). Default LOG_INFO so the
 * per-query "[DNS ]" DEBUG log does not force a serialized fprintf+fflush on the
 * hot path. Configurable via config:console_level / env CONSOLE_LEVEL. */
static int g_console_level = LOG_INFO;

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
/* CSPRNG 16-bit value for outbound transaction IDs (CSA-RAND-002). rand() is
 * predictable; the recipient authenticates NOTIFY via TSIG/SOA so this is mostly
 * for consistency, but a CSPRNG is the right default. */
static uint16_t csprng_u16(void) {
    uint16_t v;
    if (RAND_bytes((unsigned char *) &v, sizeof(v)) == 1)
        return v;
    return (uint16_t) rand();
}

/* Bind the expected peer identity so the TLS handshake fails on a cert that does
 * not match `host` (CSA-TLS-002/003). SSL_set_tlsext_host_name() only sets SNI;
 * identity is checked via set1_host (DNS) or set1_ip (IP literal). Only meaningful
 * when peer verification is enabled on the SSL/CTX. */
static void tls_verify_peer_name(SSL *ssl, const char *host) {
    X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    unsigned char addr[16];
    if (inet_pton(AF_INET, host, addr) == 1 || inet_pton(AF_INET6, host, addr) == 1)
        X509_VERIFY_PARAM_set1_ip_asc(vp, host);
    else
        X509_VERIFY_PARAM_set1_host(vp, host, 0);
}

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
    if (g_rsyslog_tls_verify)
        tls_verify_peer_name(g_rsyslog_ssl, g_rsyslog_host);

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

    /* Hot-path short-circuit: if this message is below every enabled sink's
     * level, do no formatting, take no lock, do no I/O. Per-query "[DNS ]" logs
     * are DEBUG, so at the default console level (info) this returns immediately
     * instead of forcing a serialized fprintf+fflush under g_log_mutex. */
    int to_console = (priority <= g_console_level);
    int to_syslog = (g_syslog_enabled && priority <= g_syslog_level);
    int to_remote = (g_rsyslog_port > 0 && priority <= g_rsyslog_level);
    if (!to_console && !to_syslog && !to_remote)
        return;

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
    if (to_console) {
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
    if (to_syslog)
        syslog(priority, "%s", msg);

    /* ── 3. Remote syslog ── */
    if (to_remote) {
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
static uint64_t g_stat_queries = 0;       /* total queries received */
static uint64_t g_stat_noerror = 0;       /* NOERROR responses */
static uint64_t g_stat_nxdomain = 0;      /* NXDOMAIN responses */
static uint64_t g_stat_refused = 0;       /* REFUSED (out-of-zone) */
static uint64_t g_stat_servfail = 0;      /* SERVFAIL responses */
static uint64_t g_stat_rrl_drop = 0;      /* RRL: dropped */
static uint64_t g_stat_rrl_tc = 0;        /* RRL: truncated */
static uint64_t g_stat_axfr = 0;          /* AXFR transfers completed */
static uint64_t g_stat_ddns = 0;          /* DDNS updates accepted */
static uint64_t g_stat_signed = 0;        /* RRSIGs generated */
static uint64_t g_stat_forwarded = 0;     /* queries answered via an upstream forwarder */
static uint64_t g_stat_forward_fail = 0;  /* forward attempts that failed (all upstreams) */
static uint64_t g_stat_lb_down_skips = 0; /* A/AAAA addresses suppressed as unhealthy (LB) */
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

/* Returns 1 if IPv4 address `ip` matches any entry in a comma-separated list of
 * IPs and /8-/32 CIDRs (e.g. "10.0.0.0/8, 192.168.1.5"). Shared by the AXFR ACL
 * and the forwarder client ACL (CLAUDE-forwarder.md Gap 1). An empty/blank list
 * matches nothing (fail closed). */
static int ip_list_allowed(const char *list, const struct in_addr *ip) {
    if (!list || !list[0])
        return 0;
    char allow[1024];
    safe_strcpy(allow, list, sizeof(allow));
    char *sp = NULL;
    for (char *tok = strtok_r(allow, ",", &sp); tok; tok = strtok_r(NULL, ",", &sp)) {
        while (*tok == ' ')
            tok++;
        char *slash = strchr(tok, '/');
        if (slash) {
            int bits = atoi(slash + 1);
            *slash = 0;
            if (bits < 0)
                bits = 0;
            if (bits > 32)
                bits = 32;
            struct in_addr net;
            if (inet_pton(AF_INET, tok, &net) != 1)
                continue;
            uint32_t mask = bits ? htonl(~((1u << (32 - bits)) - 1)) : 0u;
            if (bits == 32)
                mask = 0xFFFFFFFFu;
            if ((ip->s_addr & mask) == (net.s_addr & mask))
                return 1;
        } else {
            struct in_addr a;
            if (inet_pton(AF_INET, tok, &a) == 1 && a.s_addr == ip->s_addr)
                return 1;
        }
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
/* When non-NULL, vk_get() uses this thread-private connection instead of the
 * shared `vk` + g_vk_mutex, so a UDP worker's per-query GET (+ stale SET) runs
 * lock-free and overlaps with other workers. Set by udp_worker_thread(). */
static __thread resp_conn_t *t_vk_conn = NULL;

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

/* ==========================================================================
 * In-process record cache  (config:record_cache_ttl > 0 to enable)
 *
 * The baseline profile showed that, after SO_REUSEPORT removed the single-thread
 * serialization, the ceiling moved onto the shared Valkey, which a query hits
 * ~5x (zone select, record, SOA/DNSSEC config, the stale-shadow SET). This caches
 * per-query zone:/ddns: GET results — hits AND misses — in a shared, sharded,
 * direct-mapped table so warm queries skip those round-trips entirely.
 *
 * Correctness: entries expire after record_cache_ttl seconds (bounds staleness),
 * AND the keyspace subscriber calls rcache_invalidate() on every zone:/ddns:
 * change (dynamic UPDATE, dashboard/apid edits), so an edit takes effect at once
 * — not only after the TTL. Disabled by default (ttl 0 → vk_get is unchanged);
 * the table is allocated at startup only when enabled. Values larger than
 * RCACHE_VALLEN are simply not cached (fall through to Valkey).
 * ======================================================================= */
#define RCACHE_KEYLEN 640
#define RCACHE_VALLEN 512
#define RCACHE_LOCKS 64
#define RCACHE_WAYS                                                                                \
    4 /* set-associative: WAYS entries per bucket so colliding                                     \
       * keys coexist instead of evicting each other (a query                                      \
       * caches both ddns: and zone: per name → ~2x entries, which                               \
       * thrashed a direct-mapped table). */
typedef struct {
    char key[RCACHE_KEYLEN];
    char val[RCACHE_VALLEN];
    int hit; /* 1 = positive (val valid); 0 = negative (key absent) */
    int used;
    uint64_t expiry_ms;
} rcache_entry_t;
static rcache_entry_t *g_rcache = NULL;
static int g_rcache_cap = 0;      /* total entries (buckets * RCACHE_WAYS) */
static int g_rcache_buckets = 0;  /* number of sets */
static int g_rcache_ttl = 0;      /* seconds; 0 = disabled */
static int g_rcache_size = 16384; /* requested entries when enabled */
static pthread_mutex_t g_rcache_locks[RCACHE_LOCKS];

/* RFC 8767 stale-shadow write throttle. The shadow (stale:<key>, 7-day TTL) only
 * needs to be recent-ish for outage survival, but it was rewritten on EVERY
 * successful GET — a Valkey write per read. Write it on ~1/N reads instead.
 * 1 = write every GET (legacy), 0 = never write shadows. Per-thread counter, so
 * each worker refreshes independently. */
static int g_stale_sample = 16;
static __thread unsigned t_stale_ctr = 0;

static uint64_t rcache_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}
static uint64_t rcache_hash(const char *s) {
    uint64_t h = 1469598103934665603ULL; /* FNV-1a 64-bit */
    for (; *s; s++) {
        h ^= (uint8_t) *s;
        h *= 1099511628211ULL;
    }
    return h;
}
static void rcache_init(int cap) {
    if (cap < RCACHE_WAYS)
        return;
    int buckets = cap / RCACHE_WAYS;
    int total = buckets * RCACHE_WAYS;
    g_rcache = calloc((size_t) total, sizeof(rcache_entry_t));
    if (!g_rcache) {
        dns_log(LOG_WARNING, "[rcache] alloc of %d entries failed — cache disabled\n", total);
        return;
    }
    g_rcache_cap = total;
    g_rcache_buckets = buckets;
    for (int i = 0; i < RCACHE_LOCKS; i++)
        pthread_mutex_init(&g_rcache_locks[i], NULL);
    dns_log(LOG_NOTICE, "[rcache] enabled: %d entries (%d sets x %d ways), ttl %ds (~%zu MB)\n",
            total, buckets, RCACHE_WAYS, g_rcache_ttl,
            ((size_t) total * sizeof(rcache_entry_t)) >> 20);
}
/* 1 if a fresh entry was found (sets *hit; copies val for a positive); else 0. */
static int rcache_lookup(const char *key, char *out, int olen, int *hit) {
    if (!g_rcache || g_rcache_ttl <= 0)
        return 0;
    int bucket = (int) (rcache_hash(key) % (uint64_t) g_rcache_buckets);
    rcache_entry_t *set = &g_rcache[(size_t) bucket * RCACHE_WAYS];
    pthread_mutex_t *lk = &g_rcache_locks[bucket % RCACHE_LOCKS];
    int found = 0;
    pthread_mutex_lock(lk);
    for (int w = 0; w < RCACHE_WAYS; w++) {
        rcache_entry_t *e = &set[w];
        if (e->used && e->expiry_ms > rcache_now_ms() && strcmp(e->key, key) == 0) {
            *hit = e->hit;
            if (e->hit)
                safe_strcpy(out, e->val, olen);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(lk);
    return found;
}
static void rcache_store(const char *key, const char *val, int hit) {
    if (!g_rcache || g_rcache_ttl <= 0)
        return;
    if (strlen(key) >= RCACHE_KEYLEN)
        return;
    if (hit && val && strlen(val) >= RCACHE_VALLEN)
        return; /* value too large to cache — fall through to Valkey next time */
    int bucket = (int) (rcache_hash(key) % (uint64_t) g_rcache_buckets);
    rcache_entry_t *set = &g_rcache[(size_t) bucket * RCACHE_WAYS];
    pthread_mutex_t *lk = &g_rcache_locks[bucket % RCACHE_LOCKS];
    uint64_t now = rcache_now_ms();
    pthread_mutex_lock(lk);
    /* Pick a way: an existing entry for this key, else a free/expired slot, else
     * the one expiring soonest (approx-LRU eviction within the set). */
    rcache_entry_t *victim = &set[0];
    for (int w = 0; w < RCACHE_WAYS; w++) {
        rcache_entry_t *e = &set[w];
        if ((e->used && strcmp(e->key, key) == 0) || !e->used || e->expiry_ms <= now) {
            victim = e;
            break;
        }
        if (e->expiry_ms < victim->expiry_ms)
            victim = e;
    }
    safe_strcpy(victim->key, key, sizeof(victim->key));
    if (hit && val)
        safe_strcpy(victim->val, val, sizeof(victim->val));
    else
        victim->val[0] = 0;
    victim->hit = hit ? 1 : 0;
    victim->used = 1;
    victim->expiry_ms = now + (uint64_t) g_rcache_ttl * 1000;
    pthread_mutex_unlock(lk);
}
/* Invalidate one key — called by the keyspace subscriber on zone:/ddns: writes. */
static void rcache_invalidate(const char *key) {
    if (!g_rcache)
        return;
    int bucket = (int) (rcache_hash(key) % (uint64_t) g_rcache_buckets);
    rcache_entry_t *set = &g_rcache[(size_t) bucket * RCACHE_WAYS];
    pthread_mutex_t *lk = &g_rcache_locks[bucket % RCACHE_LOCKS];
    pthread_mutex_lock(lk);
    for (int w = 0; w < RCACHE_WAYS; w++) {
        if (set[w].used && strcmp(set[w].key, key) == 0) {
            set[w].used = 0;
            break;
        }
    }
    pthread_mutex_unlock(lk);
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
/* Core GET on a specific connection — does NO locking. The caller supplies
 * either the shared `vk` (while holding g_vk_mutex) or a thread-private
 * connection (no lock needed). Behavior is identical to the historical vk_get:
 * GET, RFC 8767 stale-shadow read on Valkey-unreachable, stale-shadow write on
 * hit. */
static int vk_get_conn(resp_conn_t *c, const char *key, char *out, int olen) {
    if (valkey_ensure(c) < 0) {
        /* Valkey unreachable — try RFC 8767 stale shadow key */
        char skey[640];
        snprintf(skey, sizeof(skey), "stale:%s", key);
        if (valkey_ensure(c) >= 0) {
            resp_reply_t rs;
            if (resp_cmd(c, &rs, 2, "GET", skey) >= 0 && rs.type == 2) {
                safe_strcpy(out, rs.str, olen);
                dns_log(LOG_DEBUG, "[RFC8767] Serving stale data for %s\n", key);
                return 1;
            }
        }
        return 0;
    }
    resp_reply_t r;
    if (resp_cmd(c, &r, 2, "GET", key) < 0) {
        c->fd = -1;
        return 0;
    }
    if (r.type != 2)
        return 0;
    safe_strcpy(out, r.str, olen);
    /* Refresh the RFC 8767 stale shadow (7-day TTL) on ~1/g_stale_sample reads to
     * avoid a Valkey write per read. The shadow only needs to be recent enough to
     * serve during a Valkey outage; the read-side serve-stale path is unchanged. */
    if (g_stale_sample > 0 && (++t_stale_ctr % (unsigned) g_stale_sample) == 0) {
        char skey[640];
        snprintf(skey, sizeof(skey), "stale:%s", key);
        char ts[16];
        snprintf(ts, sizeof(ts), "%u", 7u * 86400);
        resp_reply_t sw;
        resp_cmd(c, &sw, 5, "SET", skey, out, "EX", ts);
    }
    return 1;
}
static int vk_get(const char *key, char *out, int olen) {
    /* In-process cache for the hot per-query record reads (zone:/ddns:). Config
     * reads (config:/cert:/dnssec:/acme:) are not cached — they are not on the
     * hot path and must stay strictly live. */
    int cacheable = (g_rcache && g_rcache_ttl > 0 &&
                     (strncmp(key, "zone:", 5) == 0 || strncmp(key, "ddns:", 5) == 0));
    if (cacheable) {
        int hit = 0;
        if (rcache_lookup(key, out, olen, &hit))
            return hit;
    }
    int rc;
    /* Worker threads carry a private connection → lock-free, overlapping GETs. */
    if (t_vk_conn) {
        rc = vk_get_conn(t_vk_conn, key, out, olen);
    } else {
        pthread_mutex_lock(&g_vk_mutex);
        rc = vk_get_conn(&vk, key, out, olen);
        pthread_mutex_unlock(&g_vk_mutex);
    }
    if (cacheable)
        rcache_store(key, rc ? out : NULL, rc);
    return rc;
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
        /* mname|rname|serial|refresh|retry|expire|minimum|axfr_allow|notify_targets
         * |soa_ttl(optional, RFC 9077). soa_ttl is an additive trailing field
         * (ADR-003): absent → 0 → falls back to minimum. */
        char *f[10] = {0};
        char *p = buf;
        int fi = 0;
        while (fi < 10) {
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
                    f[9] ? (uint32_t) atoi(f[9]) : 0, f[7] ? f[7] : NULL, f[8] ? f[8] : NULL);
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
    g_ddns_allow_suffix[0] = 0;
    G("ddns_allow_suffix", g_ddns_allow_suffix);
    g_ddns_auto_ptr = 0;
    GI("ddns_auto_ptr", g_ddns_auto_ptr);
    GI("ddns_sweep_secs", g_ddns_sweep_secs);
    /* Role: a "secondary" is a read-only replica (hidden-master plan Gap 2). */
    g_zone_secondary = 0;
    {
        char role[64] = "";
        if (vk_get("config:zone_role", role, sizeof(role)) && strcasecmp(role, "secondary") == 0)
            g_zone_secondary = 1;
    }
    /* Secondary transfer-client config (hidden-master plan Gap 3). */
    g_primary_host[0] = 0;
    g_primary_port = 53;
    g_primary_tls = 0;
    g_xfr_ca_pem[0] = g_xfr_client_cert_pem[0] = g_xfr_client_key_pem[0] = 0;
    G("primary_host", g_primary_host);
    GI("primary_port", g_primary_port);
    GI("primary_tls", g_primary_tls);
    vk_get("config:xfr_ca_pem", g_xfr_ca_pem, sizeof(g_xfr_ca_pem));
    vk_get("config:xfr_client_cert_pem", g_xfr_client_cert_pem, sizeof(g_xfr_client_cert_pem));
    vk_get("config:xfr_client_key_pem", g_xfr_client_key_pem, sizeof(g_xfr_client_key_pem));
    GI("dns_port", g_dns_port);
    GI("dot_port", g_dot_port);
    GI("http_port", g_http_port);
    GI("https_port", g_https_port);
    GI("metrics_port", g_metrics_port);
    /* LISTEN_PORT env overrides config:dns_port (per-launch DNS port; documented
     * in CLAUDE.md). Lets the test harness run dnsd off the mDNS port 5353 — which
     * collides with a desktop avahi-daemon — without touching Valkey config. */
    {
        const char *lp = getenv("LISTEN_PORT");
        if (lp && *lp) {
            int p = atoi(lp);
            if (p > 0 && p <= 65535)
                g_dns_port = p;
        }
    }
    GI("udp_workers", g_udp_workers);
    {
        const char *uw = getenv("UDP_WORKERS");
        if (uw && uw[0])
            g_udp_workers = atoi(uw);
    }
    if (g_udp_workers < 1)
        g_udp_workers = 1;
    if (g_udp_workers > 64)
        g_udp_workers = 64;
    GI("udp_rx_batch", g_udp_rx_batch);
    {
        const char *rb = getenv("UDP_RX_BATCH");
        if (rb && rb[0])
            g_udp_rx_batch = atoi(rb);
    }
    if (g_udp_rx_batch < 1)
        g_udp_rx_batch = 1;
    if (g_udp_rx_batch > UDP_BATCH_MAX)
        g_udp_rx_batch = UDP_BATCH_MAX;
    /* In-process record cache (rcache). TTL/size re-read live; the table is
     * allocated once at startup (main) when enabled — toggling on requires a
     * restart, the TTL value itself can change live. */
    GI("record_cache_ttl", g_rcache_ttl);
    GI("record_cache_size", g_rcache_size);
    {
        const char *e = getenv("RECORD_CACHE_TTL");
        if (e && e[0])
            g_rcache_ttl = atoi(e);
        e = getenv("RECORD_CACHE_SIZE");
        if (e && e[0])
            g_rcache_size = atoi(e);
    }
    if (g_rcache_ttl < 0)
        g_rcache_ttl = 0;
    if (g_rcache_size < 0)
        g_rcache_size = 0;
    /* Stale-shadow write throttle (1 = every GET, N = ~1/N, 0 = off). */
    GI("stale_refresh_sample", g_stale_sample);
    {
        const char *e = getenv("STALE_REFRESH_SAMPLE");
        if (e && e[0])
            g_stale_sample = atoi(e);
    }
    if (g_stale_sample < 0)
        g_stale_sample = 0;
    G("soa_mname", g_soa_mname);
    G("soa_rname", g_soa_rname);
    GU("soa_refresh", g_soa_refresh);
    GU("soa_retry", g_soa_retry);
    GU("soa_expire", g_soa_expire);
    GU("soa_minimum", g_soa_minimum);
    GU("soa_ttl", g_soa_ttl);
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
    /* Out-of-zone forwarding (CLAUDE-forwarder.md). */
    g_forward_enabled = 0;
    g_forwarders[0] = 0;
    g_forward_allow[0] = 0;
    g_forward_timeout_ms = 1500;
    GI("forward_enabled", g_forward_enabled);
    G("forwarders", g_forwarders);
    G("forward_allow", g_forward_allow);
    GI("forward_timeout_ms", g_forward_timeout_ms);
    if (g_forward_timeout_ms < 100)
        g_forward_timeout_ms = 100;
    if (g_forward_timeout_ms > 30000)
        g_forward_timeout_ms = 30000;
    /* Guard rails (CLAUDE-forwarder.md Gap 3): make an open-resolver
     * misconfiguration impossible to enable silently. */
    if (g_forward_enabled && g_forward_allow[0]) {
        dns_log(LOG_WARNING,
                "[FORWARD] *** RECURSION ENABLED *** out-of-zone queries are forwarded to "
                "[%s] for clients in [%s] (timeout %dms). Keep this OFF on any public-facing "
                "instance — an open resolver is an amplification/abuse target.\n",
                g_forwarders[0] ? g_forwarders : "(none configured!)", g_forward_allow,
                g_forward_timeout_ms);
        if (g_zone_secondary)
            dns_log(LOG_WARNING,
                    "[FORWARD] zone_role=secondary (public-facing) AND forwarding is enabled — "
                    "ensure this secondary is internal-only.\n");
    } else if (g_forward_enabled && !g_forward_allow[0]) {
        dns_log(LOG_WARNING, "[FORWARD] forward_enabled=1 but forward_allow is empty — "
                             "forwarding stays DISABLED (fail closed).\n");
    }
    /* Load-balancing rotation for A/AAAA RRsets (CLAUDE-loadbalance.md Gap 1). */
    g_lb_mode = LB_NONE;
    {
        char lb[32] = "";
        if (vk_get("config:lb_mode", lb, sizeof(lb)) && lb[0]) {
            if (strcasecmp(lb, "rr") == 0)
                g_lb_mode = LB_RR;
            else if (strcasecmp(lb, "random") == 0)
                g_lb_mode = LB_RANDOM;
            else if (strcasecmp(lb, "none") != 0)
                dns_log(LOG_WARNING, "[LB] unknown lb_mode '%s' — rotation disabled\n", lb);
        }
    }
    /* Load-balancing health checks (CLAUDE-loadbalance.md Gap 2). */
    g_lb_health_enabled = 0;
    GI("lb_health_enabled", g_lb_health_enabled);
    g_lb_health_targets[0] = 0;
    G("lb_health_targets", g_lb_health_targets);
    g_lb_health_interval = 10;
    GI("lb_health_interval", g_lb_health_interval);
    g_lb_health_timeout_ms = 1000;
    GI("lb_health_timeout_ms", g_lb_health_timeout_ms);
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
    g_dot_require_client_cert = 0;
    GI("dot_require_client_cert", g_dot_require_client_cert);
    /* Console (stdout/stderr) level — env CONSOLE_LEVEL overrides config. */
    if (vk_get("config:console_level", val, sizeof(val)) && val[0])
        g_console_level = syslog_level_from_str(val);
    {
        const char *cl = getenv("CONSOLE_LEVEL");
        if (cl && cl[0])
            g_console_level = syslog_level_from_str(cl);
    }
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
/* RFC 8976 ZONEMD recompute hook — defined later (needs the record encoders +
 * SOA/DNSKEY builders). Called at the end of serial_bump so the apex ZONEMD
 * digest always reflects the just-committed zone content (§3 — recompute on
 * change, never per query). */
static void zonemd_update(zone_entry_t *z, uint32_t new_serial);

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
        zonemd_update(z, (uint32_t) ns);
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
    zonemd_update(z, nv);
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
    /* mTLS on the DoT/transfer listener (hidden-master plan Gap 1): require a
     * verified client cert only when explicitly enabled AND a CA is configured —
     * otherwise stay open for ordinary RFC 7858 clients (fail safe: a missing CA
     * never silently locks out clients). */
    int dot_mtls = (g_dot_require_client_cert && g_mtls_ca_pem[0]);
    g_dot_ctx =
        tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, dot_mtls ? g_mtls_ca_pem : NULL, dot_mtls);
    if (g_dot_require_client_cert && !g_mtls_ca_pem[0])
        dns_log(LOG_WARNING, "[DoT] dot_require_client_cert=1 but config:mtls_ca_pem is empty — "
                             "client-cert verification NOT enforced (no CA to verify against)\n");
    else if (dot_mtls)
        dns_log(LOG_NOTICE,
                "[DoT] client-cert verification REQUIRED (mTLS) on the DoT/transfer listener\n");
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
        catalog_scan_all();  /* per-zone catalog config may have changed (RFC 9432) */
        if (strstr(key, "tls_") || strstr(key, "mtls_") || strstr(key, "dot_require_client_cert"))
            tls_reload();
        dns_log(LOG_INFO, "[Reload] config applied after %s change\n", key);
    } else if (strncmp(key, "zone_table:", 11) == 0) {
        zones_load_from_valkey();
        zones_post_load();  /* apply per-zone config + load keys for any new zone */
        catalog_scan_all(); /* a new/removed zone_table entry may be a catalog */
        dns_log(LOG_INFO, "[Reload] zone table reloaded after %s change\n", key);
    } else if (strncmp(key, "zone:", 5) == 0 || strncmp(key, "ddns:", 5) == 0) {
        /* Record cache invalidation: a dynamic UPDATE or dashboard/apid edit to a
         * record must take effect at once, not only after the cache TTL. Exact-key
         * eviction (the event carries the precise key). No-op if cache disabled.
         * Note: "zone_table:" does not match "zone:" (5th char differs). */
        rcache_invalidate(key);
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

        /* zone:* / ddns:* are watched only to invalidate the record cache, so
         * subscribe to them only when it is active (else they add no value). */
        static const char *prefixes[] = {
            "config:*", "cert:current", "zone_table:*", "dnssec:*", NULL, NULL, NULL};
        if (g_rcache && g_rcache_ttl > 0) {
            int n = 4;
            prefixes[n++] = "zone:*";
            prefixes[n++] = "ddns:*";
        }
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

/* Build DS-format rdata (RFC 4034 §5.1.1) for a KSK: keytag(2) | alg(1) |
 * digest_type=2 (SHA-256)(1) | SHA-256(owner_wire || dnskey_rdata)(32). This is
 * the rdata of both a DS record and an RFC 7344 CDS record (identical formats),
 * so the DS and CDS answers share one implementation and cannot diverge.
 * `dkrd`/`dklen` is the KSK DNSKEY rdata. Writes 36 bytes; returns 36 or -1. */
static int ds_rdata_from_dnskey(const char *owner, const uint8_t *dkrd, int dklen, uint16_t tag,
                                int alg, uint8_t *ds_out) {
    uint8_t hin[512];
    int hp = name_to_wire(owner, hin, sizeof(hin));
    if (hp <= 0 || hp + dklen > (int) sizeof(hin))
        return -1;
    ds_out[0] = (uint8_t) (tag >> 8);
    ds_out[1] = (uint8_t) (tag & 0xFF);
    ds_out[2] = (uint8_t) alg;
    ds_out[3] = 2; /* SHA-256 */
    memcpy(hin + hp, dkrd, (size_t) dklen);
    sha256(hin, hp + dklen, ds_out + 4);
    return 4 + 32;
}

/* Emit a DS or CDS record (identical DS-format rdata) for one KSK. `rrtype` is
 * DNS_TYPE_DS or DNS_TYPE_CDS. No-op (returns off unchanged) when ksk is NULL. */
static int emit_ds_like(uint8_t *resp, int off, int resp_len, const char *qname, uint16_t rrtype,
                        EVP_PKEY *ksk, int alg, uint16_t tag, int dnssec_ok, int *answers) {
    if (!ksk)
        return off;
    uint8_t dkrd[68], dsrd[4 + 32];
    int dklen = (alg == DNS_ALG_ED25519) ? dnskey_rdata_ksk_ed25519(ksk, dkrd, sizeof(dkrd))
                                         : dnskey_rdata_ksk_ecdsa(ksk, dkrd, sizeof(dkrd));
    if (dklen <= 0 || ds_rdata_from_dnskey(qname, dkrd, dklen, tag, alg, dsrd) <= 0)
        return off;
    return emit_rr(resp, off, resp_len, qname, rrtype, 3600, dsrd, 4 + 32, dnssec_ok, answers);
}

/* Emit a CDNSKEY record (KSK DNSKEY rdata) for one KSK. No-op when ksk is NULL. */
static int emit_cdnskey(uint8_t *resp, int off, int resp_len, const char *qname, EVP_PKEY *ksk,
                        int alg, int dnssec_ok, int *answers) {
    if (!ksk)
        return off;
    uint8_t dkrd[68];
    int dklen = (alg == DNS_ALG_ED25519) ? dnskey_rdata_ksk_ed25519(ksk, dkrd, sizeof(dkrd))
                                         : dnskey_rdata_ksk_ecdsa(ksk, dkrd, sizeof(dkrd));
    if (dklen <= 0)
        return off;
    return emit_rr(resp, off, resp_len, qname, DNS_TYPE_CDNSKEY, 3600, dkrd, dklen, dnssec_ok,
                   answers);
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
    /* Canonicalize the rdata via the shared libdnswire codec (RFC 4034 §6.2)
     * so the signer's bytes match what a validator (resolverd) reconstructs:
     * name-bearing rdata (NS/MX/SOA/SRV/CNAME/PTR/DNAME) must be lowercased and
     * decompressed identically on both sides or the signature fails to verify
     * across the daemon boundary. canon_rdata copies all other rdata verbatim,
     * so A/AAAA/TXT/DNSKEY/NSEC output is unchanged. rrdata is a standalone,
     * already-uncompressed buffer, so it is its own "packet" (off 0, plen =
     * rrdata_len); the canonical length never exceeds rrdata_len here, so the
     * rr buffer (sized ow+10+rrdata_len) always has room. */
    int rdlen_pos = rp; /* RDLENGTH (2 bytes), back-patched after canon */
    rp += 2;
    int clen = canon_rdata(rrdata, rrdata_len, 0, rrdata_len, rrtype, rr + rp, rr_need - rp);
    if (clen < 0) {
        free(rr);
        return -1;
    }
    rr[rdlen_pos] = (uint8_t) (clen >> 8);
    rr[rdlen_pos + 1] = (uint8_t) (clen & 0xFF);
    rp += clen;
    /* Sign. All OpenSSL return values are checked — fail closed on any error
     * rather than emit a bogus signature. */
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    if (!mc) {
        free(rr);
        return -1;
    }
    size_t sl = 0;
    uint8_t *der = NULL;
    if (alg == DNS_ALG_ED25519) {
        /* Ed25519 (RFC 8080) is a one-shot algorithm: it does NOT support the
         * streaming EVP_DigestSignUpdate/Final API — that misuse returns an
         * error on some OpenSSL builds and crashes inside libcrypto on others.
         * Assemble the full signed message and use the one-shot EVP_DigestSign. */
        int msglen = hp + rp;
        uint8_t *msg = malloc((size_t) msglen);
        if (!msg) {
            EVP_MD_CTX_free(mc);
            free(rr);
            return -1;
        }
        memcpy(msg, hdr, (size_t) hp);
        memcpy(msg + hp, rr, (size_t) rp);
        free(rr);
        if (EVP_DigestSignInit(mc, NULL, NULL, NULL, zsk) != 1 ||
            EVP_DigestSign(mc, NULL, &sl, msg, (size_t) msglen) != 1 || sl == 0 ||
            (der = malloc(sl)) == NULL || EVP_DigestSign(mc, der, &sl, msg, (size_t) msglen) != 1) {
            EVP_MD_CTX_free(mc);
            free(msg);
            free(der);
            return -1;
        }
        free(msg);
    } else {
        /* ECDSA-P256 (alg 13): SHA-256 digest, streaming API is fine. */
        if (EVP_DigestSignInit(mc, NULL, EVP_sha256(), NULL, zsk) != 1 ||
            EVP_DigestSignUpdate(mc, hdr, (size_t) hp) != 1 ||
            EVP_DigestSignUpdate(mc, rr, (size_t) rp) != 1) {
            EVP_MD_CTX_free(mc);
            free(rr);
            return -1;
        }
        free(rr);
        if (EVP_DigestSignFinal(mc, NULL, &sl) != 1 || sl == 0 || (der = malloc(sl)) == NULL ||
            EVP_DigestSignFinal(mc, der, &sl) != 1) {
            EVP_MD_CTX_free(mc);
            free(der);
            return -1;
        }
    }
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
    /* A secondary must LOAD keys (replicated from the master out of band) but
     * never GENERATE them: a freshly minted key would publish a DNSKEY/DS that
     * diverges from the parent's DS, breaking validation for clients hitting
     * this replica. Serve unsigned instead, loudly. Hidden-master plan Gap 8. */
    if (!*out && g_zone_secondary) {
        dns_log(LOG_WARNING,
                "[DNSSEC] %s ABSENT on a secondary — NOT generating (would fork the trust "
                "anchor). Replicate the master's dnssec:* keys before start; serving unsigned.\n",
                label);
        return;
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
static int dnssec_load_existing(const char *vk_key, EVP_PKEY **out, uint16_t *tag, int alg,
                                int is_ksk) {
    char pem[MAX_PEM] = {0};
    if (!(vk_get(vk_key, pem, sizeof(pem)) && strlen(pem) > 10))
        return 0;
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!k)
        return 0;
    *out = k;
    /* Key tag must be computed over the rdata as published — KSK rdata carries
     * the SEP flag (257), ZSK carries 256 — so pick the matching encoder. */
    uint8_t dkrd[68];
    int ed = (alg == DNS_ALG_ED25519);
    int dklen;
    if (is_ksk)
        dklen = ed ? dnskey_rdata_ksk_ed25519(k, dkrd, sizeof(dkrd))
                   : dnskey_rdata_ksk_ecdsa(k, dkrd, sizeof(dkrd));
    else
        dklen = ed ? dnskey_rdata_ed25519(k, dkrd, sizeof(dkrd))
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
        dnssec_load_existing(nk, &nk1, &t1, DNS_ALG_ECDSAP256SHA256, 0);
        snprintf(nk, sizeof(nk), "dnssec:%.255s:zsk_ed25519_next", z->name);
        dnssec_load_existing(nk, &nk2, &t2, DNS_ALG_ED25519, 0);
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

    /* --- KSK rollover state (RFC 6781 §4.1.2 Double-Signature) ---
     *   dnssec:<zone>:ksk_created   epoch the current KSK set was created
     *   dnssec:<zone>:ksk_rollover  "double|<epoch>" or "retire|<epoch>" (absent = none)
     *   dnssec:<zone>:ksk_next, :ksk_ed25519_next   incoming KSK set (rollover only) */
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_created", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0]) {
        z->ksk_created = (time_t) atoll(v);
    } else {
        z->ksk_created = time(NULL);
        char b[32];
        snprintf(b, sizeof(b), "%lld", (long long) z->ksk_created);
        vk_set(k, b, 0);
    }
    int kphase = KROLL_NONE;
    time_t ksince = 0;
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_rollover", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0]) {
        char ph[16] = "";
        long long si = 0;
        sscanf(v, "%15[^|]|%lld", ph, &si);
        if (strcmp(ph, "double") == 0)
            kphase = KROLL_DOUBLE;
        else if (strcmp(ph, "retire") == 0)
            kphase = KROLL_RETIRE;
        ksince = (time_t) si;
    }
    EVP_PKEY *kk1 = NULL, *kk2 = NULL;
    uint16_t kt1 = 0, kt2 = 0;
    if (kphase != KROLL_NONE) {
        char nk[360];
        snprintf(nk, sizeof(nk), "dnssec:%.255s:ksk_next", z->name);
        dnssec_load_existing(nk, &kk1, &kt1, DNS_ALG_ECDSAP256SHA256, 1);
        snprintf(nk, sizeof(nk), "dnssec:%.255s:ksk_ed25519_next", z->name);
        dnssec_load_existing(nk, &kk2, &kt2, DNS_ALG_ED25519, 1);
        if (!kk1 || !kk2) {
            dns_log(LOG_WARNING, "[Rollover] %s: incoming KSK missing — aborting KSK rollover\n",
                    z->name);
            if (kk1)
                EVP_PKEY_free(kk1);
            if (kk2)
                EVP_PKEY_free(kk2);
            kk1 = kk2 = NULL;
            kphase = KROLL_NONE;
        }
    }
    pthread_mutex_lock(&g_zsk_mutex);
    EVP_PKEY *kold1 = z->ksk_next, *kold2 = z->ksk_ed_next;
    z->ksk_next = kk1;
    z->ksk_ed_next = kk2;
    z->ksk_next_tag = kt1;
    z->ksk_ed_next_tag = kt2;
    z->ksk_roll_phase = kphase;
    z->ksk_roll_since = ksince;
    pthread_mutex_unlock(&g_zsk_mutex);
    if (kold1)
        EVP_PKEY_free(kold1);
    if (kold2)
        EVP_PKEY_free(kold2);
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

/* ==========================================================================
 * KSK rollover engine (RFC 6781 §4.1.2 Double-Signature)
 *
 * double:  DNSKEY = {ZSK.., old KSK, new KSK}, the DNSKEY RRset signed by BOTH
 *          KSKs; CDS/CDNSKEY advertises {old, new} so the parent publishes both
 *          DS. Held (ksk_publish_hold) long enough for the parent to add DS(new)
 *          and for it to propagate; an operator who has confirmed the parent has
 *          DS(new) can advance immediately via the manual request.
 * retire:  same double-signed DNSKEY, but CDS/CDNSKEY now advertises {new} only,
 *          telling the parent to drop DS(old). Held (ksk_commit_hold) until
 *          DS(old) has expired from caches.
 * finish:  promote new KSK -> current, drop the old one; rollover over.
 * Both KSKs sign the DNSKEY RRset throughout, so whichever DS the parent serves
 * (old, new, or both) always points at a KSK that signed it — no validation gap.
 * ======================================================================= */

/* Begin a KSK rollover: generate + store the incoming KSK set, enter `double`. */
static void ksk_rollover_start(zone_entry_t *z) {
    char pem[MAX_PEM], k[360];
    if (dnssec_generate_pem(DNS_ALG_ECDSAP256SHA256, pem, sizeof(pem)) != 0) {
        dns_log(LOG_ERR, "[Rollover] %s: KSK P-256 keygen failed\n", z->name);
        return;
    }
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_next", z->name);
    vk_set(k, pem, 0);
    if (dnssec_generate_pem(DNS_ALG_ED25519, pem, sizeof(pem)) != 0) {
        dns_log(LOG_ERR, "[Rollover] %s: KSK Ed25519 keygen failed\n", z->name);
        return;
    }
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_ed25519_next", z->name);
    vk_set(k, pem, 0);
    char st[64];
    snprintf(st, sizeof(st), "double|%lld", (long long) time(NULL));
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_rollover", z->name);
    vk_set(k, st, 0);
    zone_rollover_load(z); /* bring the next KSK set + phase into memory */
    serial_bump(z);        /* DNSKEY + CDS/CDNSKEY RRsets changed */
    notify_send();
    dns_log(LOG_NOTICE,
            "[Rollover] %s: KSK started — double (new KSK tags %u/%u); CDS/CDNSKEY = {old, new}\n",
            z->name, z->ksk_next_tag, z->ksk_ed_next_tag);
}

/* double -> retire: keep both KSKs published and double-signing, but advertise
 * only the new KSK in CDS/CDNSKEY so the parent drops DS(old). */
static void ksk_rollover_to_retire(zone_entry_t *z) {
    char k[360], st[64];
    snprintf(st, sizeof(st), "retire|%lld", (long long) time(NULL));
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_rollover", z->name);
    vk_set(k, st, 0);
    zone_rollover_load(z);
    serial_bump(z);
    notify_send();
    dns_log(LOG_NOTICE, "[Rollover] %s: KSK retire — CDS/CDNSKEY = {new} only (parent drops old)\n",
            z->name);
}

/* retire -> done: promote the new KSK to current, drop the old one. */
static void ksk_rollover_finish(zone_entry_t *z) {
    char k[360], pem[MAX_PEM];
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_next", z->name);
    if (vk_get(k, pem, sizeof(pem)) && pem[0]) {
        char ck[360];
        snprintf(ck, sizeof(ck), "dnssec:%.255s:ksk", z->name);
        vk_set(ck, pem, 0);
    }
    vk_del(k);
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_ed25519_next", z->name);
    if (vk_get(k, pem, sizeof(pem)) && pem[0]) {
        char ck[360];
        snprintf(ck, sizeof(ck), "dnssec:%.255s:ksk_ed25519", z->name);
        vk_set(ck, pem, 0);
    }
    vk_del(k);
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_rollover", z->name);
    vk_del(k);
    char now_s[32];
    snprintf(now_s, sizeof(now_s), "%lld", (long long) time(NULL));
    snprintf(k, sizeof(k), "dnssec:%.255s:ksk_created", z->name);
    vk_set(k, now_s, 0);
    zone_dnssec_reload(z); /* current = promoted KSK; next/phase cleared */
    serial_bump(z);
    notify_send();
    dns_log(LOG_NOTICE, "[Rollover] %s: KSK complete — active KSK tags %u/%u\n", z->name,
            z->ksk_tag, z->ksk_ed_tag);
}

/* Drive each zone's rollover state machine one step (time- and request-based). */
static void rollover_tick(void) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_zones_mutex);
    int n = g_zone_count;
    pthread_mutex_unlock(&g_zones_mutex);
    for (int i = 0; i < n; i++) {
        zone_entry_t *z = &g_zones[i];
        if (!z->active)
            continue; /* deprovisioned catalog member — no key rollover */
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

        /* KSK rollover (RFC 6781 §4.1.2). Independent of the ZSK roll, but we do
         * not *start* one while a ZSK roll is mid-flight, to limit DNSKEY churn. */
        pthread_mutex_lock(&g_zsk_mutex);
        int kphase = z->ksk_roll_phase;
        time_t ksince = z->ksk_roll_since, kcreated = z->ksk_created;
        int zsk_idle = (z->roll_phase == ROLL_NONE);
        pthread_mutex_unlock(&g_zsk_mutex);
        if (kphase == KROLL_NONE) {
            long req = roll_cfg(z->name, "ksk_rollover_request", 0);
            char sk[360], sv[64] = "";
            snprintf(sk, sizeof(sk), "dnssec:%.255s:ksk_rollover_seen", z->name);
            vk_get(sk, sv, sizeof(sv));
            long seen = sv[0] ? atol(sv) : 0;
            int manual = (req > 0 && req != seen);
            long validity = roll_cfg(z->name, "ksk_validity", 0); /* 0 = no auto-roll */
            int age_due = (validity > 0 && (now - kcreated) >= validity);
            if ((manual || age_due) && zsk_idle) {
                ksk_rollover_start(z);
                if (manual) {
                    char b[32];
                    snprintf(b, sizeof(b), "%ld", req);
                    vk_set(sk, b, 0);
                }
            }
        } else if (kphase == KROLL_DOUBLE) {
            if ((now - ksince) >= roll_cfg(z->name, "ksk_publish_hold", 3600))
                ksk_rollover_to_retire(z);
        } else if (kphase == KROLL_RETIRE) {
            if ((now - ksince) >= roll_cfg(z->name, "ksk_commit_hold", 3600))
                ksk_rollover_finish(z);
        }
    }
    /* Catalog membership lives under zone:* (not subscribed), so the periodic
     * tick is the live-pickup path for RFC 9432 provisioning/deprovisioning. */
    catalog_scan_all();
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
    snprintf(k, sizeof(k), "config:zone:%s:soa_ttl", z->name);
    if (vk_get(k, v, sizeof(v)) && v[0])
        z->soa_ttl = (uint32_t) strtoul(v, NULL, 10);
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
                g_soa_expire, g_soa_minimum, g_soa_ttl, g_axfr_allow, g_notify_targets);
}
static void zones_post_load(void) {
    pthread_mutex_lock(&g_zones_mutex);
    int n = g_zone_count;
    pthread_mutex_unlock(&g_zones_mutex);
    for (int i = 0; i < n; i++) {
        if (!g_zones[i].active)
            continue; /* deprovisioned catalog member — leave its keys untouched */
        zone_apply_config(&g_zones[i]);
        if (!g_zones[i].zsk && !g_zones[i].zsk_ed && !g_zones[i].ksk && !g_zones[i].ksk_ed)
            zone_dnssec_init(&g_zones[i]);
        zonemd_seed_if_stale(&g_zones[i]);
    }
}
static void dnssec_init(void) {
    zones_post_load();
}

/* ==========================================================================
 * Catalog zones (RFC 9432) — bulk provisioning of member zones
 *
 * A catalog zone is an ordinary authoritative zone (it has a zone_table:<cat>
 * entry, so dnsd serves it and secondaries can AXFR it) that additionally
 * carries the RFC 9432 schema-version record  version.<cat> TXT "2"  and a list
 * of member zones as  <id>.zones.<cat> PTR <member-zone>.  dnsd consumes that
 * list and provisions each member into its in-memory zone table — deriving SOA
 * names from the member, inheriting the catalog's SOA timers / transfer ACL /
 * NOTIFY targets, and generating per-zone DNSSEC keys via the normal path — so
 * an operator gets a new signed zone just by adding a PTR, with no per-zone
 * zone_table:* edit.  Members dropped from the catalog are deactivated.
 *
 * Boundary (CLAUDE.md): dnsd only READS the catalog (zone:<cat>:* records,
 * written by the control plane) and writes only what it already owns for a
 * provisioned zone (dnssec:<member>:* keys).  It never writes zone_table:* —
 * provisioning is purely in-memory, re-derived from the catalog on every scan.
 *
 * Scans run at boot, on config:* / zone_table:* changes, and once per rollover
 * tick.  Catalog membership lives under zone:* (which dnsd does not subscribe
 * to), so the periodic tick is the live-pickup path — the same poll model a
 * catalog consumer uses anyway.
 * ======================================================================= */

/* True if `cat` carries the RFC 9432 §4.1 schema-version record
 * (version.<cat> TXT "2").  Creating that record is what opts a zone in. */
static int catalog_is_catalog_zone(const char *cat) {
    char k[768];
    snprintf(k, sizeof(k), "zone:%.255s:TXT:version.%.255s", cat, cat);
    char v[128] = "";
    if (!vk_get(k, v, sizeof(v)) || !v[0])
        return 0;
    const char *p = strchr(v, '|'); /* value is the usual ttl|rdata */
    p = p ? p + 1 : v;
    while (*p == ' ' || *p == '"') /* tolerate quoting / whitespace */
        p++;
    return p[0] == '2' && (p[1] == 0 || p[1] == ' ' || p[1] == '"');
}

/* Enumerate member zone names from a catalog: keys
 *   zone:<cat>:PTR:<id>.zones.<cat>  →  value = PTR target (the member zone).
 * Returns the count and fills out[] (each NUL-terminated, <256 chars). */
static int catalog_members(const char *cat, char out[][256], int max) {
    char pat[768];
    snprintf(pat, sizeof(pat), "zone:%.255s:PTR:*.zones.%.255s", cat, cat);
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "KEYS", pat) < 0 || r.type != 5) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    char keys[MAX_ZONES * 4][768];
    int maxk = (int) (sizeof(keys) / sizeof(keys[0]));
    int nk = 0;
    for (int i = 0; i < r.count; i++) {
        resp_reply_t kr;
        if (resp_parse(&vk, &kr) < 0)
            break;
        if (kr.type == 2 && nk < maxk)
            safe_strcpy(keys[nk++], kr.str, sizeof(keys[0]));
    }
    pthread_mutex_unlock(&g_vk_mutex);
    int n = 0;
    for (int i = 0; i < nk && n < max; i++) {
        char v[512] = "";
        if (!vk_get(keys[i], v, sizeof(v)) || !v[0])
            continue;
        const char *p = strchr(v, '|'); /* strip optional ttl| prefix */
        p = p ? p + 1 : v;
        char m[256];
        safe_strcpy(m, p, sizeof(m));
        size_t ml = strlen(m);
        if (ml && m[ml - 1] == '.')
            m[ml - 1] = 0; /* drop trailing dot */
        if (!m[0])
            continue;
        int dup = 0; /* a member listed twice is provisioned once */
        for (int j = 0; j < n; j++)
            if (strcasecmp(out[j], m) == 0) {
                dup = 1;
                break;
            }
        if (!dup)
            safe_strcpy(out[n++], m, sizeof(out[0]));
    }
    return n;
}

/* Find a zone slot by name (caller holds g_zones_mutex). */
static int catalog_find_zone_idx(const char *name) {
    for (int i = 0; i < g_zone_count; i++)
        if (strcasecmp(g_zones[i].name, name) == 0)
            return i;
    return -1;
}

/* SOA/transfer template a catalog hands to its members. Copied out of the live
 * zone_entry_t so we never read its key pointers as if they were template data. */
typedef struct {
    char name[256];
    uint32_t refresh, retry, expire, minimum, soa_ttl;
    char axfr_allow[1024];
    char notify_targets[1024];
} catalog_tmpl_t;

/* Provision (or re-affirm) one catalog member zone. Returns its slot index, or
 * -1 on capacity exhaustion. Never overrides an operator-defined zone or a
 * member owned by a different catalog, and never disturbs the SOA serial / keys
 * of a member it has already provisioned (re-affirm is just active=1). */
static int catalog_provision_member(const char *cat, const char *member,
                                    const catalog_tmpl_t *tmpl) {
    pthread_mutex_lock(&g_zones_mutex);
    int idx = catalog_find_zone_idx(member);
    if (idx >= 0) {
        const char *orig = g_zones[idx].catalog_origin;
        if (!orig[0]) { /* operator-defined zone with this name — leave it alone */
            pthread_mutex_unlock(&g_zones_mutex);
            return idx;
        }
        if (strcasecmp(orig, cat) != 0) { /* owned by another catalog */
            pthread_mutex_unlock(&g_zones_mutex);
            dns_log(LOG_WARNING,
                    "[Catalog] %s: member %s already provisioned by catalog %s — skipping\n", cat,
                    member, orig);
            return idx;
        }
        g_zones[idx].active = 1; /* ours: re-affirm without touching serial/keys */
        pthread_mutex_unlock(&g_zones_mutex);
        return idx;
    }
    pthread_mutex_unlock(&g_zones_mutex);

    /* Fresh provisioning: derive SOA names from the member, inherit timers / ACL
     * / NOTIFY from the catalog, restore the persisted serial if any. */
    char mname[300], rname[300];
    snprintf(mname, sizeof(mname), "ns1.%.255s", member);
    snprintf(rname, sizeof(rname), "hostmaster.%.255s", member);
    uint32_t serial = 1;
    char sk[600], sv[64] = "";
    snprintf(sk, sizeof(sk), "config:zone:%.255s:serial", member);
    if (vk_get(sk, sv, sizeof(sv)) && sv[0])
        serial = (uint32_t) strtoul(sv, NULL, 10);
    idx = zone_upsert(member, mname, rname, serial, tmpl->refresh, tmpl->retry, tmpl->expire,
                      tmpl->minimum, tmpl->soa_ttl, tmpl->axfr_allow, tmpl->notify_targets);
    if (idx < 0) {
        dns_log(LOG_WARNING, "[Catalog] %s: cannot provision %s — zone table full (MAX_ZONES=%d)\n",
                cat, member, MAX_ZONES);
        return -1;
    }
    pthread_mutex_lock(&g_zones_mutex);
    safe_strcpy(g_zones[idx].catalog_origin, cat, sizeof(g_zones[idx].catalog_origin));
    g_zones[idx].active = 1;
    pthread_mutex_unlock(&g_zones_mutex);
    zone_apply_config(&g_zones[idx]);
    if (!g_zones[idx].zsk && !g_zones[idx].zsk_ed && !g_zones[idx].ksk && !g_zones[idx].ksk_ed)
        zone_dnssec_init(&g_zones[idx]);
    dns_log(LOG_NOTICE, "[Catalog] %s: provisioned member zone %s\n", cat, member);
    return idx;
}

/* Reconcile every catalog zone's membership against the in-memory zone table:
 * provision newly-listed members, deactivate members no longer listed. */
static void catalog_scan_all(void) {
    pthread_mutex_lock(&g_catalog_mutex); /* one scan at a time (boot/keyspace/rollover) */

    /* Snapshot candidate catalog zones (a catalog must be a served zone) and the
     * template each would hand its members; detection needs Valkey, so it is done
     * below outside g_zones_mutex. */
    catalog_tmpl_t cand[MAX_ZONES];
    int ncand = 0;
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count && ncand < MAX_ZONES; i++) {
        if (!g_zones[i].active || g_zones[i].catalog_origin[0])
            continue; /* inactive, or itself a catalog member — not a catalog */
        zone_entry_t *z = &g_zones[i];
        catalog_tmpl_t *t = &cand[ncand++];
        safe_strcpy(t->name, z->name, sizeof(t->name));
        t->refresh = z->soa_refresh;
        t->retry = z->soa_retry;
        t->expire = z->soa_expire;
        t->minimum = z->soa_minimum;
        t->soa_ttl = z->soa_ttl;
        safe_strcpy(t->axfr_allow, z->axfr_allow, sizeof(t->axfr_allow));
        safe_strcpy(t->notify_targets, z->notify_targets, sizeof(t->notify_targets));
    }
    pthread_mutex_unlock(&g_zones_mutex);

    int seen[MAX_ZONES];
    memset(seen, 0, sizeof(seen));
    for (int c = 0; c < ncand; c++) {
        if (!catalog_is_catalog_zone(cand[c].name))
            continue;
        char members[MAX_ZONES][256];
        int nm = catalog_members(cand[c].name, members, MAX_ZONES);
        for (int m = 0; m < nm; m++) {
            if (strcasecmp(members[m], cand[c].name) == 0)
                continue; /* a catalog cannot be its own member */
            int idx = catalog_provision_member(cand[c].name, members[m], &cand[c]);
            if (idx >= 0 && idx < MAX_ZONES)
                seen[idx] = 1;
        }
    }

    /* Deprovision: catalog-owned slots not reaffirmed this scan. */
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count && i < MAX_ZONES; i++) {
        zone_entry_t *z = &g_zones[i];
        if (z->active && z->catalog_origin[0] && !seen[i]) {
            z->active = 0;
            dns_log(LOG_NOTICE,
                    "[Catalog] deprovisioned member zone %s (no longer in catalog %s)\n", z->name,
                    z->catalog_origin);
        }
    }
    pthread_mutex_unlock(&g_zones_mutex);

    pthread_mutex_unlock(&g_catalog_mutex);
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
    int ok = (mlen == (unsigned) t.mac_len) && (CRYPTO_memcmp(mac, t.mac, mlen) == 0);
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
/* Emit SOA rdata for the current zone (t_zone) but with an explicit serial —
 * used to frame IXFR difference sequences (the old/new serial of each step). */
static int build_soa_rdata_serial(uint8_t *rd, int rdlen, uint32_t serial) {
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
    put32(rd, pos, serial);
    pos += 4;
    pthread_mutex_lock(&g_soa_mutex);
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

static int build_soa_rdata(uint8_t *rd, int rdlen) {
    /* Emit SOA for the current request's zone (t_zone), falling back to the
     * legacy single-zone globals when no zone has been selected. */
    pthread_mutex_lock(&g_soa_mutex);
    uint32_t serial = t_zone ? t_zone->soa_serial : g_soa_serial;
    pthread_mutex_unlock(&g_soa_mutex);
    return build_soa_rdata_serial(rd, rdlen, serial);
}

/* SOA MINIMUM field for the current zone (the RDATA value; also the legacy
 * negative-cache TTL). */
static uint32_t zone_soa_minimum(void) {
    return t_zone ? t_zone->soa_minimum : g_soa_minimum;
}

/* TTL the SOA RR is served with for the current zone. Configured soa_ttl, or
 * soa_minimum when unset (0) — preserving the legacy single-TTL behavior. */
static uint32_t zone_soa_ttl(void) {
    uint32_t t = t_zone ? t_zone->soa_ttl : g_soa_ttl;
    return t ? t : zone_soa_minimum();
}

/* RFC 9077: the TTL for NSEC/NSEC3 (and their RRSIGs) and the authority-section
 * SOA in a negative response is min(SOA.MINIMUM, the SOA's TTL), so a validator
 * doing aggressive-NSEC use cannot cache a denial past the negative window. */
static uint32_t zone_negative_ttl(void) {
    uint32_t mn = zone_soa_minimum();
    uint32_t st = zone_soa_ttl();
    return st < mn ? st : mn;
}

/* ==========================================================================
 * EDNS(0) — edns_info_t, edns_parse, edns_append_opt live in libdnswire.
 * dnsd_edns_opt wraps edns_append_opt with daemon-specific NSID and
 * IP-bound server-cookie computation (RFC 9018 §4.2).
 * ======================================================================= */
static int dnsd_edns_opt(uint8_t *buf, int off, int blen, int is_tcp, int do_bit,
                         uint16_t rcode_ext, const edns_info_t *ei, const struct in_addr *cip,
                         int ede_code, const char *ede_text) {
    uint8_t sc[DNS_COOKIE_SERVER_LEN];
    if (ei && ei->has_client_cookie) {
        const struct in_addr zero = {0};
        compute_server_cookie(ei->client_cookie, cip ? cip : &zero, (uint32_t) time(NULL), sc);
    }
    return edns_append_opt(buf, off, blen, is_tcp, do_bit, rcode_ext, ei, g_nsid[0] ? g_nsid : NULL,
                           (ei && ei->has_client_cookie) ? sc : NULL, ede_code, ede_text);
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
    return CRYPTO_memcmp(expected, ei->server_cookie, DNS_COOKIE_SERVER_LEN) == 0;
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
    off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_NSEC, zone_negative_ttl(), rd,
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

/* Convert a stored record value (the part AFTER the optional "ttl|" prefix) to
 * wire rdata for `type`. `pipe` is mutated (tokenised in place). Returns the
 * rdata length, or -1 if `type` is not value-encoded here or on a conversion
 * error. Shared by the live query path (build_query_resp) and AXFR
 * (axfr_send_runtime) so the per-type encodings can never diverge. A/AAAA are
 * NOT handled here — they are multi-address and parsed by their callers. */
static int stored_rdata(uint16_t type, char *pipe, uint8_t *rd, int rdcap) {
    switch (type) {
        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:
        case DNS_TYPE_DNAME: {
            int n = name_to_wire(pipe, rd, rdcap);
            if (n < 0)
                return -1;
            return n;
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
            int n = name_to_wire(pipe, rd + 2, rdcap - 2);
            if (n < 0)
                return -1;
            return 2 + n;
        }
        case DNS_TYPE_TXT: {
            int tl = txt_encode(pipe, rd, rdcap);
            if (tl < 0)
                return -1;
            return tl;
        }
        case DNS_TYPE_SRV: { /* prio|weight|port|target */
            uint16_t prio = 0, weight = 0, port = 0;
            char target[256] = "";
            char *sp14 = NULL;
            char *tok = strtok_r(pipe, "|", &sp14);
            if (tok)
                prio = (uint16_t) atoi(tok);
            tok = strtok_r(NULL, "|", &sp14);
            if (tok)
                weight = (uint16_t) atoi(tok);
            tok = strtok_r(NULL, "|", &sp14);
            if (tok)
                port = (uint16_t) atoi(tok);
            tok = strtok_r(NULL, "|", &sp14);
            if (tok)
                safe_strcpy(target, tok, sizeof(target));
            rd[0] = prio >> 8;
            rd[1] = prio & 0xFF;
            rd[2] = weight >> 8;
            rd[3] = weight & 0xFF;
            rd[4] = port >> 8;
            rd[5] = port & 0xFF;
            int n = name_to_wire(target, rd + 6, rdcap - 6);
            if (n < 0)
                return -1;
            return 6 + n;
        }
        case DNS_TYPE_CAA: { /* flags|tag|value */
            uint8_t flags = 0;
            char tag[64] = "", caaval[256] = "";
            char *sp15 = NULL;
            char *tok = strtok_r(pipe, "|", &sp15);
            if (tok)
                flags = (uint8_t) atoi(tok);
            tok = strtok_r(NULL, "|", &sp15);
            if (tok)
                safe_strcpy(tag, tok, sizeof(tag));
            tok = strtok_r(NULL, "|", &sp15);
            if (tok)
                safe_strcpy(caaval, tok, sizeof(caaval));
            int tl = (int) strlen(tag);
            rd[0] = flags;
            rd[1] = (uint8_t) tl;
            memcpy(rd + 2, tag, tl);
            memcpy(rd + 2 + tl, caaval, strlen(caaval));
            return 2 + tl + (int) strlen(caaval);
        }
        case DNS_TYPE_SSHFP: { /* alg|fptype|fingerprint_hex */
            uint8_t alg = 0, fptype = 0;
            uint8_t fp[64] = {0};
            int fplen = 0;
            char *sp16 = NULL;
            char *tok = strtok_r(pipe, "|", &sp16);
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
            return 2 + fplen;
        }
        case DNS_TYPE_TLSA: { /* usage|selector|mtype|data_hex */
            uint8_t usage = 0, sel = 0, mtype = 0;
            uint8_t data[512] = {0};
            int dlen = 0;
            char *sp17 = NULL;
            char *tok = strtok_r(pipe, "|", &sp17);
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
            return 3 + dlen;
        }
        case DNS_TYPE_LOC: { /* raw hex of wire rdata */
            return hex_dec(pipe, rd, rdcap);
        }
        case DNS_TYPE_URI: { /* priority|weight|target */
            uint16_t prio = 0, weight = 0;
            char *sp18 = NULL;
            char *tok = strtok_r(pipe, "|", &sp18);
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
            return 4 + tlen;
        }
        case DNS_TYPE_NAPTR: { /* order|pref|flags|service|regexp|replacement */
            uint16_t order2 = 0, pref2 = 0;
            char flags2[64] = "", svc2[64] = "", re2[256] = "", repl2[256] = "";
            char *sp19 = NULL;
            char *tok = strtok_r(pipe, "|", &sp19);
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
            int nn2 = name_to_wire(repl2[0] ? repl2 : ".", rd + rp2, rdcap - rp2);
            if (nn2 > 0)
                rp2 += nn2;
            return rp2;
        }
        case DNS_TYPE_SVCB:
        case DNS_TYPE_HTTPS: {
            /* Stored value is hex(TLV) — the ADR-003 structured SvcParams
             * encoding. Decode to the TLV blob, then emit RFC 9460 wire. */
            uint8_t tlv[512];
            int tl = hex_dec(pipe, tlv, sizeof(tlv));
            if (tl < 0)
                return -1;
            return svcb_tlv_to_wire(tlv, tl, rd, rdcap);
        }
        case DNS_TYPE_ZONEMD: {
            /* Stored value is hex(TLV) — the ADR-003 structured ZONEMD encoding
             * (server-generated, see zonemd_update). Decode, then emit RFC 8976
             * Serial|Scheme|HashAlg|Digest wire. */
            uint8_t tlv[256];
            int tl = hex_dec(pipe, tlv, sizeof(tlv));
            if (tl < 0)
                return -1;
            return zonemd_tlv_to_wire(tlv, tl, rd, rdcap);
        }
        case DNS_TYPE_CSYNC: { /* serial|flags|NS,A,AAAA (comma-separated type list) */
            uint32_t serial = 0;
            uint16_t flags = 0;
            char types[256] = "";
            char *sp20 = NULL;
            char *tok = strtok_r(pipe, "|", &sp20);
            if (tok)
                serial = (uint32_t) strtoul(tok, NULL, 10);
            tok = strtok_r(NULL, "|", &sp20);
            if (tok)
                flags = (uint16_t) atoi(tok);
            tok = strtok_r(NULL, "|", &sp20);
            if (tok)
                safe_strcpy(types, tok, sizeof(types));
            return csync_encode_rdata(serial, flags, types, rd, rdcap);
        }
        default:
            return -1;
    }
}

/* Health-table lookup (CLAUDE-loadbalance.md Gap 2). Returns 1 if `ip` is up
 * OR not in the table (unknown = fail-open), 0 only if explicitly probed down.
 * Caller must hold g_lb_health_mutex. */
static int lb_ip_is_up(const char *ip) {
    for (int i = 0; i < g_lb_health_count; i++)
        if (strcmp(g_lb_health[i].ip, ip) == 0)
            return g_lb_health[i].up;
    return 1;
}

/* Emit a multi-address A/AAAA RRset from a stored "ttl|ip|ip|..." value,
 * applying load-balancing rotation (config:lb_mode) to the emission order
 * (CLAUDE-loadbalance.md Gap 1) and, when health checking is enabled (Gap 2),
 * dropping addresses currently marked down — unless every address is down, in
 * which case all are emitted (fail-open: a degraded answer beats an empty
 * NOERROR resolvers negative-cache). `val` is mutated (tokenised) in place.
 * Rotation is signature-neutral: emit_rr signs each address RR on its own. */
static int emit_addr_rrset(uint8_t *resp, int off, int resp_len, const char *name, uint16_t type,
                           char *val, int dnssec_ok, int *answers) {
    const int af = (type == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
    const uint16_t addrlen = (type == DNS_TYPE_AAAA) ? 16 : 4;
    uint32_t ttl = DEFAULT_TTL;
    char *pipe = strchr(val, '|');
    if (pipe) {
        ttl = (uint32_t) atoi(val);
        pipe++;
    } else {
        pipe = val;
    }
    /* 1. collect */
    char *ips[LB_MAX_ADDRS];
    int n = 0;
    char *sp = NULL;
    for (char *ip = strtok_r(pipe, "|", &sp); ip && n < LB_MAX_ADDRS; ip = strtok_r(NULL, "|", &sp))
        ips[n++] = ip;
    if (n == 0)
        return off;
    /* 1b. health filter (opt-in). Keep only up addresses; if that leaves none,
     * fall back to all of them (fail-open). No lock/scan when disabled. */
    char *healthy[LB_MAX_ADDRS];
    int hn = 0;
    if (g_lb_health_enabled) {
        pthread_mutex_lock(&g_lb_health_mutex);
        for (int i = 0; i < n; i++)
            if (lb_ip_is_up(ips[i]))
                healthy[hn++] = ips[i];
        pthread_mutex_unlock(&g_lb_health_mutex);
    }
    char **set = ips;
    int sn = n;
    if (g_lb_health_enabled && hn > 0) {
        set = healthy;
        sn = hn;
        if (hn < n) {
            pthread_mutex_lock(&g_stat_mutex);
            g_stat_lb_down_skips += (uint64_t) (n - hn);
            pthread_mutex_unlock(&g_stat_mutex);
        }
    }
    /* 2. pick rotation start (over the emitted set) */
    int start = 0;
    if (g_lb_mode == LB_RR)
        start = (int) (atomic_fetch_add(&g_lb_counter, 1u) % (uint32_t) sn);
    else if (g_lb_mode == LB_RANDOM)
        start = rand() % sn;
    /* 3. emit rotated */
    for (int i = 0; i < sn; i++) {
        const char *ip = set[(start + i) % sn];
        uint8_t rd[16];
        if (inet_pton(af, ip, rd) == 1)
            off = emit_rr(resp, off, resp_len, name, type, ttl, rd, addrlen, dnssec_ok, answers);
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
                  zone_negative_ttl(), soa_rd, (uint16_t) soa_len, dnssec_ok, auth_count);
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
        off = emit_rr(resp, off, resp_len, nsec3_owner, DNS_TYPE_NSEC3, zone_negative_ttl(), n3rd,
                      (uint16_t) n3len, dnssec_ok, auth_count);
    }
    return off;
}

/* ==========================================================================
 * Out-of-zone forwarder (CLAUDE-forwarder.md) — relay queries we are not
 * authoritative for to one or more upstream resolvers. OFF by default and
 * gated by a client ACL (see g_forward_*). This is NOT a validating resolver:
 * DO-bit queries pass through unsigned-verified; clients do their own DNSSEC
 * validation. The trusted core only relays bytes — it never parses the answer
 * RRs beyond the header/question echo it validates for anti-spoofing.
 * ======================================================================= */

/* Read exactly `n` bytes from a (blocking, timeout-armed) TCP socket. Returns 0
 * on success, -1 on EOF/error/timeout. */
static int fwd_read_full(int fd, uint8_t *buf, int n) {
    int got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, (size_t) (n - got), 0);
        if (r <= 0)
            return -1;
        got += (int) r;
    }
    return 0;
}

/* Validate an upstream reply against the original query (RFC 5452): the ID must
 * match and the (single) question must be byte-identical to ours. `qsec` points
 * at the original question section (qname+qtype+qclass), `qsec_len` its length.
 * Returns 1 if the reply is acceptable. */
static int fwd_reply_valid(const uint8_t *resp, int rlen, uint16_t qid, const uint8_t *qsec,
                           int qsec_len) {
    if (rlen < 12)
        return 0;
    if (get16(resp, 0) != qid)
        return 0;
    if (get16(resp, 4) != 1) /* QDCOUNT must echo our single question */
        return 0;
    if (rlen < 12 + qsec_len)
        return 0;
    if (memcmp(resp + 12, qsec, (size_t) qsec_len) != 0)
        return 0;
    return 1;
}

/* One UDP exchange with a single upstream. Fresh socket → OS-random ephemeral
 * source port (anti-spoofing). Returns reply length, or -1 on timeout/invalid.
 * Off-path spoofed packets are discarded and we keep waiting until the deadline,
 * so a flood of forgeries cannot knock out the legitimate answer. */
static int fwd_exchange_udp(const uint8_t *query, int qlen, uint8_t *resp, int resp_len,
                            const struct sockaddr_in *up, uint16_t qid, const uint8_t *qsec,
                            int qsec_len) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    if (sendto(s, query, (size_t) qlen, 0, (const struct sockaddr *) up, sizeof(*up)) != qlen) {
        close(s);
        return -1;
    }
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed =
            (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1000000L;
        int remaining = g_forward_timeout_ms - (int) elapsed;
        if (remaining <= 0)
            break;
        struct pollfd pfd = {.fd = s, .events = POLLIN};
        int pr = poll(&pfd, 1, remaining);
        if (pr <= 0)
            break; /* timeout or error */
        struct sockaddr_in from = {0};
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(s, resp, (size_t) resp_len, 0, (struct sockaddr *) &from, &fl);
        if (n < 12)
            continue;
        /* Source must be the forwarder we queried (RFC 5452). */
        if (fl != sizeof(from) || from.sin_addr.s_addr != up->sin_addr.s_addr ||
            from.sin_port != up->sin_port)
            continue;
        if (!fwd_reply_valid(resp, (int) n, qid, qsec, qsec_len))
            continue;
        close(s);
        return (int) n;
    }
    close(s);
    return -1;
}

/* One TCP exchange with a single upstream (used to follow a truncated UDP reply
 * when the client can carry the full answer). Length-prefixed framing per
 * RFC 1035 §4.2.2. Returns reply length, or -1 on failure. */
static int fwd_exchange_tcp(const uint8_t *query, int qlen, uint8_t *resp, int resp_len,
                            const struct sockaddr_in *up, uint16_t qid, const uint8_t *qsec,
                            int qsec_len) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    struct timeval tv = {.tv_sec = g_forward_timeout_ms / 1000,
                         .tv_usec = (g_forward_timeout_ms % 1000) * 1000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(s, (const struct sockaddr *) up, sizeof(*up)) != 0) {
        close(s);
        return -1;
    }
    uint8_t lb[2] = {(uint8_t) (qlen >> 8), (uint8_t) (qlen & 0xFF)};
    if (send(s, lb, 2, 0) != 2 || send(s, query, (size_t) qlen, 0) != qlen) {
        close(s);
        return -1;
    }
    if (fwd_read_full(s, lb, 2) != 0) {
        close(s);
        return -1;
    }
    int rlen = (lb[0] << 8) | lb[1];
    if (rlen < 12 || rlen > resp_len) {
        close(s);
        return -1;
    }
    if (fwd_read_full(s, resp, rlen) != 0) {
        close(s);
        return -1;
    }
    close(s);
    if (!fwd_reply_valid(resp, rlen, qid, qsec, qsec_len))
        return -1;
    return rlen;
}

/* Build a minimal SERVFAIL response echoing the original ID/question, with RD
 * copied and RA set. Used when every forwarder fails. Returns its length. */
static int fwd_servfail(const uint8_t *query, int qlen, uint8_t *resp, int resp_len) {
    int qsec_len = 0;
    char qn[256];
    int after = name_from_wire(query, qlen, 12, qn, sizeof(qn));
    if (after > 0 && after + 4 <= qlen)
        qsec_len = after - 12 + 4;
    dns_hdr_t *rh = (dns_hdr_t *) resp;
    rh->id = ((const dns_hdr_t *) query)->id;
    uint16_t rd = (ntohs(((const dns_hdr_t *) query)->flags) & DNS_RD);
    rh->flags = htons(DNS_QR | rd | DNS_RA | DNS_RCODE_SERVFAIL);
    rh->qdcount = htons(qsec_len ? 1 : 0);
    rh->ancount = rh->nscount = rh->arcount = 0;
    int off = 12;
    if (qsec_len && 12 + qsec_len <= resp_len) {
        memcpy(resp + 12, query + 12, (size_t) qsec_len);
        off = 12 + qsec_len;
    }
    return off;
}

/* Relay one query to the configured upstreams, in order. The original query
 * bytes are sent unchanged (EDNS/DO pass through). On a valid reply we set RA
 * and return it verbatim; on truncation with a TCP-capable client we retry the
 * same forwarder over TCP. Always returns a valid response (SERVFAIL on total
 * failure) so callers can relay it directly. */
static int forward_query(const uint8_t *query, int qlen, uint8_t *resp, int resp_len, int is_tcp) {
    char qn[256];
    int after = name_from_wire(query, qlen, 12, qn, sizeof(qn));
    if (after < 0 || after + 4 > qlen) {
        STAT_INC(g_stat_forward_fail);
        return fwd_servfail(query, qlen, resp, resp_len);
    }
    int qsec_len = after - 12 + 4; /* qname + qtype + qclass */
    uint16_t qid = get16(query, 0);
    const uint8_t *qsec = query + 12;

    char list[1024];
    safe_strcpy(list, g_forwarders, sizeof(list));
    char *sp = NULL;
    for (char *tok = strtok_r(list, ",", &sp); tok; tok = strtok_r(NULL, ",", &sp)) {
        while (*tok == ' ')
            tok++;
        char ipbuf[128];
        safe_strcpy(ipbuf, tok, sizeof(ipbuf));
        /* Strip a trailing space. */
        for (char *e = ipbuf + strlen(ipbuf); e > ipbuf && e[-1] == ' '; e--)
            e[-1] = 0;
        int port = DNS_PORT_DEFAULT;
        char *colon = strchr(ipbuf, ':'); /* IPv4[:port] only */
        if (colon) {
            *colon = 0;
            int p = atoi(colon + 1);
            if (p > 0 && p <= 65535)
                port = p;
        }
        struct sockaddr_in up = {.sin_family = AF_INET, .sin_port = htons((uint16_t) port)};
        if (inet_pton(AF_INET, ipbuf, &up.sin_addr) != 1)
            continue;
        int n = fwd_exchange_udp(query, qlen, resp, resp_len, &up, qid, qsec, qsec_len);
        if (n < 0)
            continue; /* timeout/invalid — try the next forwarder */
        uint8_t rc = (uint8_t) (get16(resp, 2) & 0xF);
        /* Treat SERVFAIL as a failure and fall through to the next upstream. */
        if (rc == DNS_RCODE_SERVFAIL)
            continue;
        /* Follow truncation over TCP only if the client itself is on TCP. */
        if (is_tcp && (get16(resp, 2) & DNS_TC)) {
            int t = fwd_exchange_tcp(query, qlen, resp, resp_len, &up, qid, qsec, qsec_len);
            if (t > 0)
                n = t;
        }
        /* Set RA on the relayed response; everything else is verbatim. */
        put16(resp, 2, (uint16_t) (get16(resp, 2) | DNS_RA));
        STAT_INC(g_stat_forwarded);
        return n;
    }
    STAT_INC(g_stat_forward_fail);
    return fwd_servfail(query, qlen, resp, resp_len);
}

/* Cheap pre-dispatch predicate for the UDP listeners: would this raw query be
 * forwarded? (enabled + QUERY opcode + RD set + single question + client in ACL
 * + name out-of-zone and not locally served). Mirrors the decision in
 * build_query_resp so a forwardable UDP query is dispatched to a worker thread
 * rather than blocking the listener. */
static int forward_should(const uint8_t *pkt, int plen, const struct in_addr *cip) {
    if (!g_forward_enabled || !g_forward_allow[0])
        return 0; /* fail closed */
    if (plen < 12)
        return 0;
    const dns_hdr_t *h = (const dns_hdr_t *) pkt;
    uint16_t flags = ntohs(h->flags);
    if ((flags & DNS_OPCODE_MASK) != DNS_OPCODE_QUERY)
        return 0;
    if (!(flags & DNS_RD))
        return 0;
    if (ntohs(h->qdcount) != 1)
        return 0;
    if (!ip_list_allowed(g_forward_allow, cip))
        return 0;
    char qname[256];
    int after = name_from_wire(pkt, plen, 12, qname, sizeof(qname));
    if (after < 0)
        return 0;
    if (zone_for_qname(qname) != NULL)
        return 0; /* authoritative for it */
    if (is_local_zone(qname))
        return 0; /* RFC 6303 locally served */
    return 1;
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
        off = dnsd_edns_opt(resp, off, resp_len, is_tcp, 0,
                            (uint16_t) ((DNS_RCODE_BADVERS >> 4) & 0xFF), &ei, cip, -1, NULL);
        return off;
    }
    if (!cookie_verify(&ei, cip)) {
        /* RFC 9018: emit BADCOOKIE with a fresh server cookie so the client
         * can retry.  Header rcode = low 4 bits of 23; OPT TTL carries the
         * high 8 bits per RFC 6891 §6.1.3. */
        rh->flags = htons(DNS_QR | DNS_AA | (DNS_RCODE_BADCOOKIE & 0xF));
        rh->ancount = rh->nscount = htons(0);
        off = dnsd_edns_opt(resp, off, resp_len, is_tcp, 0,
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
            /* Out-of-zone forwarding (CLAUDE-forwarder.md Gap 2). Only here for
             * TCP/DoT/DoH, which already run one thread per connection so the
             * 1.5s upstream wait is contained. UDP is dispatched to a worker
             * thread *before* dns_process (forward_should/forward_dispatch_udp)
             * so it never blocks a listener — by the time a UDP query reaches
             * here it is, by construction, not forwardable, so it falls through
             * to REFUSED exactly as before. */
            if (is_tcp && g_forward_enabled && (ntohs(qh->flags) & DNS_RD) && g_forward_allow[0] &&
                ip_list_allowed(g_forward_allow, cip)) {
                int fr = forward_query(query, qlen, resp, resp_len, is_tcp);
                if (fr > 0)
                    return fr;
            }
            rh->flags = htons(DNS_QR | DNS_RCODE_REFUSED);
            rh->qdcount = htons(1);
            /* Copy question section so the client knows which query was refused */
            int qsec2 = after - 12 + 4;
            if (12 + qsec2 <= resp_len) {
                memcpy(resp + 12, query + 12, qsec2);
                off = 12 + qsec2;
            } else
                off = 12;
            off = dnsd_edns_opt(resp, off, resp_len, is_tcp, 0, 0, &ei, cip, EDE_NOT_AUTH,
                                "Not authoritative for this zone");
            dns_log(LOG_DEBUG, "[REFUSED] %s %s\n", type2str(qtype), qname);
            STAT_INC(g_stat_refused);
            return off;
        }
    }
    /* Secondary: a zone past its SOA expire stops answering authoritatively
     * (RFC 1035 §4.3.5 / RFC 1996) until the next successful transfer — Gap 6. */
    if (t_zone && g_zone_secondary && t_zone->xfr_last_ok &&
        time(NULL) - t_zone->xfr_last_ok > (time_t) t_zone->soa_expire) {
        dns_log(LOG_WARNING, "[XFR] %s past SOA expire (%us) — SERVFAIL\n", t_zone->name,
                t_zone->soa_expire);
        rh->flags = htons(DNS_QR | DNS_RCODE_SERVFAIL);
        rh->qdcount = htons(1);
        int qsec3 = after - 12 + 4;
        if (after > 0 && 12 + qsec3 <= resp_len) {
            memcpy(resp + 12, query + 12, (size_t) qsec3);
            return 12 + qsec3;
        }
        return 12;
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
        off = dnsd_edns_opt(resp, off, resp_len, is_tcp, dnssec_ok, 0, &ei, cip, EDE_NXDOMAIN,
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
    /* Incoming KSK set during a KSK rollover (RFC 6781 §4.1.2 Double-Signature).
     * Published + double-signs the DNSKEY RRset throughout the roll. CDS/CDNSKEY
     * (and the apex DS answer) advertise the old KSK while phase != RETIRE and
     * the new KSK while phase != NONE — so DOUBLE = {old,new}, RETIRE = {new}. */
    int ksk_phase = t_zone ? t_zone->ksk_roll_phase : KROLL_NONE;
    EVP_PKEY *g_ksk_next = (ksk_phase != KROLL_NONE) ? t_zone->ksk_next : NULL;
    EVP_PKEY *g_ksk_ed_next = (ksk_phase != KROLL_NONE) ? t_zone->ksk_ed_next : NULL;
    uint16_t g_ksk_next_tag = t_zone ? t_zone->ksk_next_tag : 0;
    uint16_t g_ksk_ed_next_tag = t_zone ? t_zone->ksk_ed_next_tag : 0;
    int cds_old = (ksk_phase != KROLL_RETIRE); /* advertise current KSK's DS */
    int cds_new = (ksk_phase != KROLL_NONE);   /* advertise incoming KSK's DS */
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
        /* KSK rollover (Double-Signature): publish the incoming KSK set and sign
         * the DNSKEY RRset with it too, so the RRset validates against the DS of
         * either KSK while the parent's DS is being swapped. */
        if (g_ksk_next && dnskey_rdata_ksk_ecdsa(g_ksk_next, dkrd, sizeof(dkrd)) > 0) {
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 68);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
            if (dnssec_ok) {
                uint8_t sig[512];
                int sl = make_rrsig(qname, DNS_TYPE_DNSKEY, 3600, dkrd, 68, g_ksk_next,
                                    DNS_ALG_ECDSAP256SHA256, g_ksk_next_tag, sig);
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
        if (g_ksk_ed_next && dnskey_rdata_ksk_ed25519(g_ksk_ed_next, dkrd, sizeof(dkrd)) > 0) {
            int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, DNS_CLASS_IN, 3600,
                               dkrd, 36);
            if (n2 > 0) {
                off = n2;
                answers++;
            }
            if (dnssec_ok) {
                uint8_t sig[512];
                int sl = make_rrsig(qname, DNS_TYPE_DNSKEY, 3600, dkrd, 36, g_ksk_ed_next,
                                    DNS_ALG_ED25519, g_ksk_ed_next_tag, sig);
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
    /* RFC 7344: CDS (child DS) — the DS the child wants the parent to publish.
     * DS-format rdata over the *KSK* (the SEP that signs the DNSKEY RRset), so it
     * matches the DS answer below. During a KSK rollover this advertises the old
     * KSK (phase != RETIRE) and/or the new KSK (phase != NONE), driving the
     * parent's DS swap (cds_old / cds_new computed above). */
    if (qtype == DNS_TYPE_CDS || qtype == DNS_TYPE_ANY) {
        int before = off;
        if (cds_old) {
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_CDS, g_ksk,
                               DNS_ALG_ECDSAP256SHA256, g_ksk_tag, dnssec_ok, &answers);
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_CDS, g_ksk_ed, DNS_ALG_ED25519,
                               g_ksk_ed_tag, dnssec_ok, &answers);
        }
        if (cds_new) {
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_CDS, g_ksk_next,
                               DNS_ALG_ECDSAP256SHA256, g_ksk_next_tag, dnssec_ok, &answers);
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_CDS, g_ksk_ed_next,
                               DNS_ALG_ED25519, g_ksk_ed_next_tag, dnssec_ok, &answers);
        }
        if (off > before)
            found = 1;
    }
    /* RFC 7344: CDNSKEY — the DNSKEY the child wants the parent to publish a DS
     * for: the KSK(s), in DNSKEY rdata format. Same old/new phase logic as CDS. */
    if (qtype == DNS_TYPE_CDNSKEY || qtype == DNS_TYPE_ANY) {
        int before = off;
        if (cds_old) {
            off = emit_cdnskey(resp, off, resp_len, qname, g_ksk, DNS_ALG_ECDSAP256SHA256,
                               dnssec_ok, &answers);
            off = emit_cdnskey(resp, off, resp_len, qname, g_ksk_ed, DNS_ALG_ED25519, dnssec_ok,
                               &answers);
        }
        if (cds_new) {
            off = emit_cdnskey(resp, off, resp_len, qname, g_ksk_next, DNS_ALG_ECDSAP256SHA256,
                               dnssec_ok, &answers);
            off = emit_cdnskey(resp, off, resp_len, qname, g_ksk_ed_next, DNS_ALG_ED25519,
                               dnssec_ok, &answers);
        }
        if (off > before)
            found = 1;
    }
    /* RFC 4034 §5: DS — Delegation Signer over the zone's KSK(s). Kept identical
     * to CDS (same emit_ds_like + old/new phase logic) so CDS == DS always. */
    if (qtype == DNS_TYPE_DS || qtype == DNS_TYPE_ANY) {
        int before = off;
        if (cds_old) {
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_DS, g_ksk,
                               DNS_ALG_ECDSAP256SHA256, g_ksk_tag, dnssec_ok, &answers);
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_DS, g_ksk_ed, DNS_ALG_ED25519,
                               g_ksk_ed_tag, dnssec_ok, &answers);
        }
        if (cds_new) {
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_DS, g_ksk_next,
                               DNS_ALG_ECDSAP256SHA256, g_ksk_next_tag, dnssec_ok, &answers);
            off = emit_ds_like(resp, off, resp_len, qname, DNS_TYPE_DS, g_ksk_ed_next,
                               DNS_ALG_ED25519, g_ksk_ed_next_tag, dnssec_ok, &answers);
        }
        if (off > before)
            found = 1;
    }
    /* SOA at the zone apex (RFC 1035) — answer authoritatively from the
     * selected zone's SOA parameters. */
    if ((qtype == DNS_TYPE_SOA || qtype == DNS_TYPE_ANY) && t_zone &&
        streq_ci(qname, t_zone->name)) {
        uint8_t soa_rd[512];
        int soa_len = build_soa_rdata(soa_rd, sizeof(soa_rd));
        if (soa_len > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_SOA, zone_soa_ttl(), soa_rd,
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
            off = emit_addr_rrset(resp, off, resp_len, qname, DNS_TYPE_A, val, dnssec_ok, &answers);
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
            off = emit_addr_rrset(resp, off, resp_len, qname, DNS_TYPE_AAAA, val, dnssec_ok,
                                  &answers);
        }
    }
    /* PTR (reverse DNS). Served from both the dynamic lease (ddns:<zone>:PTR:*,
     * TTL = remaining lease — auto-PTR registrations) and the static store
     * (zone:<zone>:PTR:*, "ttl|<target>"). The owning in-addr.arpa / ip6.arpa
     * zone is picked by the same longest-suffix match as any other zone. */
    if (qtype == DNS_TYPE_PTR || qtype == DNS_TYPE_ANY) {
        char val[512], k[768];
        dkey(k, sizeof(k), "PTR", qname);
        if (vk_get(k, val, sizeof(val)) && val[0]) {
            found = 1;
            uint8_t rd[300];
            int rl = name_to_wire(val, rd, sizeof(rd));
            if (rl > 0) {
                long tl = vk_ttl(k);
                if (tl < 1)
                    tl = 1;
                off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_PTR, (uint32_t) tl, rd,
                              (uint16_t) rl, dnssec_ok, &answers);
            }
        }
        zkey(k, sizeof(k), "PTR", qname);
        if (vk_get(k, val, sizeof(val)) && val[0]) {
            found = 1;
            uint32_t ttl = DEFAULT_TTL;
            char *pipe = strchr(val, '|');
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                pipe++;
            } else {
                pipe = val;
            }
            uint8_t rd[300];
            int rl = name_to_wire(pipe, rd, sizeof(rd));
            if (rl > 0)
                off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_PTR, ttl, rd, (uint16_t) rl,
                              dnssec_ok, &answers);
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
                          DNS_TYPE_SVCB,
                          DNS_TYPE_HTTPS,
                          DNS_TYPE_ZONEMD,
                          DNS_TYPE_CSYNC,
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
            int rl = stored_rdata(pt, pipe, rd, (int) sizeof(rd));
            if (rl < 0)
                continue;
            uint16_t rdlen = (uint16_t) rl;
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
        /* RFC 9715 / DNS Flag Day 2020: never emit a UDP datagram larger than
         * the fragmentation-safe size, even if the client advertised a bigger
         * EDNS buffer — cap and fall back to TC/TCP instead of fragmenting. */
        if (max_udp > EDNS_MAX_UDP)
            max_udp = EDNS_MAX_UDP;
        if ((uint16_t) off > max_udp) {
            /* Truncate: keep header + question, set TC, drop answers */
            int qend = 12 + (after - 12) + 4; /* header + question section */
            rh->flags = htons(ntohs(rh->flags) | DNS_TC);
            rh->ancount = rh->nscount = rh->arcount = 0;
            off = qend;
        }
    }
    /* EDNS OPT in response */
    off = dnsd_edns_opt(resp, off, resp_len, is_tcp, dnssec_ok, 0, &ei, cip, ede_code, ede_text);
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

/* RFC 2136 / discovery Gap 3: is `name` permitted by config:ddns_allow_suffix?
 * Empty suffix = unrestricted (legacy). Otherwise `name` must equal the suffix
 * (a leading dot is ignored) or sit strictly under it at a label boundary.
 * Case-insensitive. */
static int ddns_name_allowed(const char *name) {
    if (!g_ddns_allow_suffix[0])
        return 1;
    const char *suf = g_ddns_allow_suffix;
    while (*suf == '.')
        suf++; /* normalise ".dyn.corp.local" -> "dyn.corp.local" */
    size_t nl = strlen(name), sl = strlen(suf);
    if (sl == 0)
        return 1;
    if (nl == sl)
        return strcasecmp(name, suf) == 0;
    if (nl > sl + 1)
        return name[nl - sl - 1] == '.' && strcasecmp(name + nl - sl, suf) == 0;
    return 0;
}

/* discovery Gap 4: build the reverse-DNS owner name for an IPv4/IPv6 address
 * string. "10.0.0.42" -> "42.0.0.10.in-addr.arpa"; "2001:db8::1" -> its nibble-
 * reversed ip6.arpa name. Returns the address family on success, -1 if `ipstr`
 * is not a valid address or the name would not fit. */
static int ddns_reverse_name(const char *ipstr, char *out, size_t cap) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ipstr, &a4) == 1) {
        const uint8_t *b = (const uint8_t *) &a4;
        int n = snprintf(out, cap, "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
        return (n > 0 && (size_t) n < cap) ? AF_INET : -1;
    }
    if (inet_pton(AF_INET6, ipstr, &a6) == 1) {
        char *p = out;
        size_t left = cap;
        /* Least-significant nibble first: low then high nibble of each byte,
         * walking the address from its last byte to its first. */
        for (int i = 15; i >= 0; i--) {
            int n = snprintf(p, left, "%x.%x.", a6.s6_addr[i] & 0x0f, (a6.s6_addr[i] >> 4) & 0x0f);
            if (n < 0 || (size_t) n >= left)
                return -1;
            p += n;
            left -= (size_t) n;
        }
        int n = snprintf(p, left, "ip6.arpa");
        return (n > 0 && (size_t) n < left) ? AF_INET6 : -1;
    }
    return -1;
}

/* discovery Gap 4: keep the reverse PTR lease in step with a forward A/AAAA
 * DDNS registration. No-op unless config:ddns_auto_ptr is set and an
 * in-addr.arpa / ip6.arpa zone covering `ipstr` is configured locally (picked by
 * the same longest-suffix match as any query). `del` removes the PTR, otherwise
 * it is written/renewed as ddns:<revzone>:PTR:<revname> -> <fqdn> with the
 * forward lease's TTL. `bump` advances the reverse zone's serial + IXFR journal
 * so the change replicates; an unchanged refresh passes bump=0 to renew the
 * lease TTL without churning the serial. The reverse zone is a different zone
 * than the forward one, so its key/serial/journal are addressed explicitly. */
static void auto_ptr_apply(const char *fqdn, const char *ipstr, uint32_t ttl, int del, int bump) {
    if (!g_ddns_auto_ptr)
        return;
    char rev[320];
    if (ddns_reverse_name(ipstr, rev, sizeof(rev)) < 0)
        return;
    zone_entry_t *rz = zone_for_qname(rev);
    if (!rz)
        return; /* no reverse zone here — reverse DNS simply isn't served */
    char key[800];
    snprintf(key, sizeof(key), "ddns:%s:PTR:%s", rz->name, rev);
    if (del) {
        char had[256] = "";
        if (!(vk_get(key, had, sizeof(had)) && had[0]))
            return; /* nothing to retract → no replication event */
        vk_del(key);
    } else {
        vk_set(key, fqdn, ttl ? ttl : DEFAULT_TTL);
    }
    if (!bump)
        return;
    uint32_t prev = rz->soa_serial;
    uint32_t next = serial_bump(rz);
    ixfr_journal_append(rz->name, prev, next, del ? 'D' : 'A', rev, fqdn);
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
    /* A secondary is a read-only replica: never apply a local UPDATE (it would
     * fork the zone from the master and corrupt IXFR history). RFC 2136 §6 lets
     * a secondary forward to the primary; we don't — point ACME/DDNS clients at
     * the hidden master. Hidden-master plan Gap 7. */
    if (g_zone_secondary) {
        dns_log(LOG_NOTICE, "[UPDATE] refused on secondary (zone_role=secondary) — NOTAUTH\n");
        rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | DNS_RCODE_NOTAUTH);
        return 12;
    }
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
        /* discovery Gap 3: confine dynamic registrants to config:ddns_allow_suffix
         * so a shared TSIG key cannot overwrite apex/infrastructure names. Refuse
         * the whole update (don't partially apply) if any name is out of bounds. */
        if (!ddns_name_allowed(un)) {
            dns_log(LOG_WARNING, "[DDNS] REFUSED update of %s — outside ddns_allow_suffix [%s]\n",
                    un, g_ddns_allow_suffix);
            rh->flags = htons(DNS_QR | DNS_OPCODE_UPDATE | DNS_RCODE_REFUSED);
            return tsig_append(resp, 12, BUF_SIZE, ntohs(h->id), 0);
        }
        char k[768];
        if (uc == DNS_CLASS_IN && rdlen > 0) {
            if (ut == DNS_TYPE_A && rdlen == 4) {
                char ip[32];
                snprintf(ip, sizeof(ip), "%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3]);
                dkey(k, sizeof(k), "A", un);
                /* discovery Gap 3: a lease refresh re-stores the same IP — renew
                 * the TTL but skip the serial bump + journal when unchanged, so a
                 * fleet refreshing every TTL/2 doesn't churn the serial/IXFR. */
                char old[64] = "";
                int changed = !(vk_get(k, old, sizeof(old)) && strcmp(old, ip) == 0);
                vk_set(k, ip, uttl ? uttl : DEFAULT_TTL);
                if (changed) {
                    uint32_t prev = t_zone ? t_zone->soa_serial : g_soa_serial;
                    uint32_t next = serial_bump(t_zone);
                    ixfr_journal_append(t_zone ? t_zone->name : g_zone_name, prev, next, 'A', un,
                                        ip);
                    /* auto-PTR: retract the previous address's PTR (if the IP moved),
                     * then publish the new one. Both bump the reverse zone. */
                    if (old[0] && strcmp(old, ip) != 0)
                        auto_ptr_apply(un, old, 0, 1, 1);
                    auto_ptr_apply(un, ip, uttl, 0, 1);
                } else {
                    auto_ptr_apply(un, ip, uttl, 0, 0); /* renew PTR lease, no churn */
                }
                dns_log(LOG_NOTICE, "[DDNS] A %s->%s%s\n", un, ip, changed ? "" : " (refresh)");
                STAT_INC(g_stat_ddns);
            } else if (ut == DNS_TYPE_AAAA && rdlen == 16) {
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rd, ip6, sizeof(ip6));
                dkey(k, sizeof(k), "AAAA", un);
                char old[INET6_ADDRSTRLEN] = "";
                int changed = !(vk_get(k, old, sizeof(old)) && strcmp(old, ip6) == 0);
                vk_set(k, ip6, uttl ? uttl : DEFAULT_TTL);
                if (changed) {
                    uint32_t prev = t_zone ? t_zone->soa_serial : g_soa_serial;
                    uint32_t next = serial_bump(t_zone);
                    ixfr_journal_append(t_zone ? t_zone->name : g_zone_name, prev, next, 'A', un,
                                        ip6);
                    if (old[0] && strcmp(old, ip6) != 0)
                        auto_ptr_apply(un, old, 0, 1, 1);
                    auto_ptr_apply(un, ip6, uttl, 0, 1);
                } else {
                    auto_ptr_apply(un, ip6, uttl, 0, 0); /* renew PTR lease, no churn */
                }
                dns_log(LOG_NOTICE, "[DDNS] AAAA %s->%s%s\n", un, ip6, changed ? "" : " (refresh)");
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
            const char *zn = t_zone ? t_zone->name : g_zone_name;
            int other = 0; /* a non-journaled type was deleted → single serial bump below */
            /* A/AAAA deletes are journaled (op 'D') so a secondary can apply them
             * incrementally; capture the old value before removing it. */
            if (ut == DNS_TYPE_A || ut == DNS_TYPE_ANY) {
                dkey(k, sizeof(k), "A", un);
                char old[64] = "";
                int had = vk_get(k, old, sizeof(old)) && old[0];
                vk_del(k);
                if (had) {
                    uint32_t prev = t_zone ? t_zone->soa_serial : g_soa_serial;
                    uint32_t next = serial_bump(t_zone);
                    ixfr_journal_append(zn, prev, next, 'D', un, old);
                    auto_ptr_apply(un, old, 0, 1, 1); /* retract the reverse PTR too */
                }
            }
            if (ut == DNS_TYPE_AAAA || ut == DNS_TYPE_ANY) {
                dkey(k, sizeof(k), "AAAA", un);
                char old[INET6_ADDRSTRLEN] = "";
                int had = vk_get(k, old, sizeof(old)) && old[0];
                vk_del(k);
                if (had) {
                    uint32_t prev = t_zone ? t_zone->soa_serial : g_soa_serial;
                    uint32_t next = serial_bump(t_zone);
                    ixfr_journal_append(zn, prev, next, 'D', un, old);
                    auto_ptr_apply(un, old, 0, 1, 1);
                }
            }
            if (ut == DNS_TYPE_TXT || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "TXT", un);
                vk_del(k);
                other = 1;
            }
            if (ut == DNS_TYPE_CNAME || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "CNAME", un);
                vk_del(k);
                other = 1;
            }
            if (ut == DNS_TYPE_MX || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "MX", un);
                vk_del(k);
                other = 1;
            }
            if (ut == DNS_TYPE_SRV || ut == DNS_TYPE_ANY) {
                zkey(k, sizeof(k), "SRV", un);
                vk_del(k);
                other = 1;
            }
            /* Non-journaled types bump the serial once; this intentionally leaves
             * a gap in the IXFR chain so those serials force an AXFR fallback. */
            if (other)
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
 * Per-zone journal stored in Valkey as a list:
 *   ixfr:<zone>:journal  — RPUSH entries of the form:
 *       "<from_serial>|<to_serial>|A|<name>|<value>"   (add)
 *       "<from_serial>|<to_serial>|D|<name>|<value>"   (delete)
 * Each entry records a single A/AAAA change and the serial transition it
 * caused (to_serial == from_serial's successor).  Capped at IXFR_JOURNAL_MAX
 * entries; older entries are dropped.  Only A/AAAA DDNS changes are journaled;
 * any other mutation bumps the serial WITHOUT a journal entry, which leaves a
 * gap in the serial chain — ixfr_journal_fetch() detects the gap and the
 * server falls back to AXFR (RFC 1995 §4), so a partial diff is never sent.
 * ======================================================================= */
#define IXFR_JOURNAL_MAX 4096

/* Build the per-zone journal key (ixfr:<zone>:journal). */
static void ixfr_journal_key(char *out, size_t cap, const char *zone) {
    snprintf(out, cap, "ixfr:%.200s:journal", (zone && zone[0]) ? zone : g_zone_name);
}

/* Append one A/AAAA change to `zone`'s IXFR journal. */
static void ixfr_journal_append(const char *zone, uint32_t from_serial, uint32_t to_serial, char op,
                                const char *name, const char *value) {
    char key[256];
    ixfr_journal_key(key, sizeof(key), zone);
    char entry[1024];
    snprintf(entry, sizeof(entry), "%u|%u|%c|%s|%s", from_serial, to_serial, op, name, value);
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) >= 0) {
        resp_reply_t r;
        resp_cmd(&vk, &r, 3, "RPUSH", key, entry);
        /* Trim to the most-recent IXFR_JOURNAL_MAX entries. */
        if (r.type == 3 && r.integer > IXFR_JOURNAL_MAX) {
            resp_reply_t r2;
            char ltrim_idx[32];
            snprintf(ltrim_idx, sizeof(ltrim_idx), "%d", -IXFR_JOURNAL_MAX);
            resp_cmd(&vk, &r2, 4, "LTRIM", key, ltrim_idx, "-1");
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
}

/* Fetch the journal entries forming a CONTIGUOUS serial chain from `from_serial`
 * up to `current_serial` for `zone`.  Returns the entry count (>=1) on success,
 * with each entry strdup'd into out_entries (caller frees).  Returns -1 if no
 * such complete chain exists — a missing start serial, a gap (a non-journaled
 * mutation), or a chain that does not reach current_serial — in which case the
 * caller must fall back to AXFR so the secondary is never left inconsistent. */
static int ixfr_journal_fetch(const char *zone, uint32_t from_serial, uint32_t current_serial,
                              char **out_entries, int max_entries) {
    char key[256];
    ixfr_journal_key(key, sizeof(key), zone);
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    resp_reply_t r;
    resp_cmd(&vk, &r, 4, "LRANGE", key, "0", "-1");
    if (r.type != 5 || r.count <= 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    int count = r.count;
    char **all = calloc((size_t) count, sizeof(char *));
    int na = 0;
    for (int i = 0; i < count; i++) {
        resp_reply_t er;
        if (resp_parse(&vk, &er) < 0)
            break;
        if (er.type == 2 && all) {
            char *dup = strdup(er.str);
            if (dup)
                all[na++] = dup;
        }
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (!all)
        return -1;
    /* Walk a contiguous chain: find the entry whose from_serial == from_serial,
     * then require each subsequent entry to start where the previous one ended,
     * until we reach current_serial. Any gap aborts the chain (→ AXFR). */
    int n = 0, ok = 0, started = 0;
    uint32_t want = from_serial;
    for (int i = 0; i < na; i++) {
        uint32_t fs = 0, ts = 0;
        if (sscanf(all[i], "%u|%u|", &fs, &ts) != 2)
            continue;
        if (!started) {
            if (fs != from_serial)
                continue; /* keep scanning for the chain start */
            started = 1;
        } else if (fs != want) {
            break; /* gap in the serial chain — incomplete diff */
        }
        if (n >= max_entries)
            break; /* too many changes — ok stays 0, fall back to AXFR */
        out_entries[n++] = strdup(all[i]);
        want = ts;
        if (ts == current_serial) {
            ok = 1;
            break;
        }
    }
    for (int i = 0; i < na; i++)
        free(all[i]);
    free(all);
    if (!ok) {
        for (int j = 0; j < n; j++)
            free(out_entries[j]);
        return -1;
    }
    return n;
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

/* Thin wrapper kept for the AXFR call site; the matching logic lives once in
 * ip_list_allowed() (CLAUDE-forwarder.md Gap 1). */
static int axfr_ip_allowed(const struct in_addr *cip, const char *allow_list) {
    return ip_list_allowed(allow_list, cip);
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

/* Collect all Valkey keys matching `pattern` (KEYS) into a freshly malloc'd
 * array of malloc'd strings. Returns the count; the caller frees each element
 * and the array. *out is NULL on error/empty. Keys are gathered under the lock
 * and returned, so the (slow) per-key fetch + network send happens unlocked. */
static int vk_list_keys(const char *pattern, char ***out) {
    *out = NULL;
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "KEYS", pattern) < 0 || r.type != 5 || r.count <= 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0;
    }
    char **arr = malloc((size_t) r.count * sizeof(char *));
    int n = 0;
    for (int i = 0; i < r.count; i++) {
        resp_reply_t kr;
        if (resp_parse(&vk, &kr) < 0)
            break;
        if (kr.type == 2 && arr)
            arr[n++] = strdup(kr.str);
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (!arr)
        return 0;
    *out = arr;
    return n;
}

/* Like vk_list_keys but distinguishes a genuinely empty match (returns 0,
 * *out=NULL) from a Valkey connection/protocol error (returns -1). The sweeper
 * needs this: treating a transient KEYS failure as "every lease vanished" would
 * falsely replay deletes for records that still exist, diverging secondaries. */
static int vk_list_keys_strict(const char *pattern, char ***out) {
    *out = NULL;
    pthread_mutex_lock(&g_vk_mutex);
    if (valkey_ensure(&vk) < 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    resp_reply_t r;
    if (resp_cmd(&vk, &r, 2, "KEYS", pattern) < 0 || r.type != 5) {
        pthread_mutex_unlock(&g_vk_mutex);
        return -1;
    }
    if (r.count <= 0) {
        pthread_mutex_unlock(&g_vk_mutex);
        return 0; /* genuinely no matching keys */
    }
    char **arr = malloc((size_t) r.count * sizeof(char *));
    int n = 0;
    for (int i = 0; i < r.count; i++) {
        resp_reply_t kr;
        if (resp_parse(&vk, &kr) < 0)
            break;
        if (kr.type == 2 && arr)
            arr[n++] = strdup(kr.str);
    }
    pthread_mutex_unlock(&g_vk_mutex);
    if (!arr)
        return -1;
    *out = arr;
    return n;
}

/* Send one AXFR record message (one RR, with TSIG MAC chaining). Each message
 * must echo the request ID (RFC 5936 §2.2). */
static void axfr_emit_one(int fd, SSL *ssl, uint16_t qid, const char *name, uint16_t type,
                          uint32_t ttl, const uint8_t *rd, uint16_t rdlen, uint8_t mac[64],
                          int *maclen) {
    uint8_t mb[BUF_SIZE];
    compress_reset();
    memset(mb, 0, 12);
    dns_hdr_t *mh = (dns_hdr_t *) mb;
    mh->id = htons(qid);
    mh->flags = htons(DNS_QR | DNS_AA);
    mh->ancount = htons(1);
    int mo = append_rr(mb, 12, sizeof(mb), name, type, DNS_CLASS_IN, ttl, rd, rdlen);
    if (mo < 0)
        return;
    tsig_axfr_mid(mb, mo, mac, maclen);
    tcp_send_msg(fd, ssl, mb, mo);
}

/* ==========================================================================
 * RFC 8976 ZONEMD — whole-zone message digest (SIMPLE scheme, SHA-384).
 *
 * The digest is computed over exactly the set of RRs that an AXFR of the zone
 * transfers (SOA + static_zone + zone:<z>:* + ddns:<z>:A/AAAA/PTR + ZSK
 * DNSKEY), reusing the same per-record encoders (build_soa_rdata_serial,
 * stored_rdata, dnskey_rdata_*) so the digest can never diverge from the
 * transfer. dnsd is an online signer, so RRSIG/NSEC are not materialised into
 * the zone and are therefore (correctly) not part of the transferred set or the
 * digest. The apex ZONEMD RRset itself is excluded (RFC 8976 §3.3.2). Recomputed
 * only on serial_bump, then served + signed like any apex RRset — never per
 * query. Opt-in: config:[zone:<z>:]zonemd (default off). check-zonemd's Python
 * verifier independently recomputes the digest over the live AXFR.
 * ======================================================================= */

/* One canonical RR (RFC 4034 §6.2 form) collected for the digest. */
typedef struct {
    char owner[256]; /* lowercased owner — §6.1 cross-RRset ordering */
    uint16_t type;
    uint8_t *wire; /* canonical RR: owner|type|class|ttl|rdlen|canon_rdata */
    int wirelen;
    uint8_t *rdata; /* -> canonical rdata within wire (RRset tie-break) */
    int rdatalen;
} zmd_rr_t;

#define ZMD_MAX_RR 200000

/* Canonicalize one RR and append it to the growable collection. Returns 0 on
 * success, -1 on error (encoding failure / overflow / OOM). */
static int zmd_add(zmd_rr_t **arr, int *n, int *cap, const char *owner, uint16_t type, uint32_t ttl,
                   const uint8_t *rdata, int rdlen) {
    if (*n >= ZMD_MAX_RR)
        return -1;
    uint8_t canon[CANON_RR_MAX];
    int clen = canon_rdata(rdata, rdlen, 0, rdlen, type, canon, (int) sizeof(canon));
    if (clen < 0)
        return -1;
    char low[256];
    safe_strcpy(low, owner, sizeof(low));
    strlower(low);
    uint8_t ow[256];
    int owl = name_to_wire(low, ow, (int) sizeof(ow));
    if (owl < 0)
        return -1;
    int wl = owl + 10 + clen;
    uint8_t *w = malloc((size_t) wl);
    if (!w)
        return -1;
    int p = 0;
    memcpy(w, ow, (size_t) owl);
    p += owl;
    w[p++] = (uint8_t) (type >> 8);
    w[p++] = (uint8_t) (type & 0xFF);
    w[p++] = 0;
    w[p++] = DNS_CLASS_IN;
    w[p++] = (uint8_t) (ttl >> 24);
    w[p++] = (uint8_t) ((ttl >> 16) & 0xFF);
    w[p++] = (uint8_t) ((ttl >> 8) & 0xFF);
    w[p++] = (uint8_t) (ttl & 0xFF);
    w[p++] = (uint8_t) (clen >> 8);
    w[p++] = (uint8_t) (clen & 0xFF);
    memcpy(w + p, canon, (size_t) clen);
    if (*n == *cap) {
        int nc = *cap ? *cap * 2 : 256;
        zmd_rr_t *na = realloc(*arr, (size_t) nc * sizeof(zmd_rr_t));
        if (!na) {
            free(w);
            return -1;
        }
        *arr = na;
        *cap = nc;
    }
    zmd_rr_t *e = &(*arr)[*n];
    safe_strcpy(e->owner, low, sizeof(e->owner));
    e->type = type;
    e->wire = w;
    e->wirelen = wl;
    e->rdata = w + owl + 10;
    e->rdatalen = clen;
    (*n)++;
    return 0;
}

/* RFC 8976 §3.3 ordering: by canonical owner (§6.1), then type, then canonical
 * rdata as octet strings (§6.3). */
static int zmd_cmp(const void *pa, const void *pb) {
    const zmd_rr_t *a = (const zmd_rr_t *) pa;
    const zmd_rr_t *b = (const zmd_rr_t *) pb;
    int c = canon_name_cmp(a->owner, b->owner);
    if (c)
        return c;
    if (a->type != b->type)
        return a->type < b->type ? -1 : 1;
    int min = a->rdatalen < b->rdatalen ? a->rdatalen : b->rdatalen;
    c = memcmp(a->rdata, b->rdata, (size_t) min);
    if (c)
        return c;
    return a->rdatalen - b->rdatalen;
}

/* Enumerate one ddns/zone A or AAAA stored value (ttl|ip|ip… or a bare ip) into
 * per-address RRs. Mirrors axfr_send_runtime's A/AAAA handling. */
static void zmd_add_addr(zmd_rr_t **arr, int *n, int *cap, const char *owner, uint16_t type,
                         uint32_t ttl, char *iplist) {
    const int af = (type == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
    const int alen = (type == DNS_TYPE_AAAA) ? 16 : 4;
    char *sp = NULL;
    for (char *ip = strtok_r(iplist, "|", &sp); ip; ip = strtok_r(NULL, "|", &sp)) {
        uint8_t rd[16];
        if (inet_pton(af, ip, rd) == 1)
            zmd_add(arr, n, cap, owner, type, ttl, rd, alen);
    }
}

/* Compute the SIMPLE/SHA-384 digest of zone `z` at `serial`. Returns the digest
 * length (48) on success, -1 on error. Caller sets t_zone = z. */
static int zonemd_compute(zone_entry_t *z, uint32_t serial, uint8_t *out_digest) {
    const char *zname = z ? z->name : g_zone_name;
    zmd_rr_t *arr = NULL;
    int n = 0, cap = 0;
    int rc = 0;
    /* Apex SOA — TTL matches the AXFR (soa_minimum). */
    uint8_t soa_rd[512];
    int soa_len = build_soa_rdata_serial(soa_rd, sizeof(soa_rd), serial);
    uint32_t soa_ttl = z ? z->soa_minimum : g_soa_minimum;
    if (soa_len > 0)
        zmd_add(&arr, &n, &cap, zname, DNS_TYPE_SOA, soa_ttl, soa_rd, soa_len);
    /* static_zone[] records belonging to this zone (same filter as AXFR). */
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
        zmd_add(&arr, &n, &cap, r->name, r->type, r->ttl, rd, rdlen);
    }
    /* Provisioned + dynamic records (zone:<z>:* and ddns:<z>:A/AAAA/PTR),
     * mirroring axfr_send_runtime — but the apex ZONEMD RRset is EXCLUDED from
     * its own digest (RFC 8976 §3.3.2), so it is omitted from ztypes here. */
    static const uint16_t ztypes[] = {
        DNS_TYPE_A,   DNS_TYPE_AAAA,  DNS_TYPE_CNAME, DNS_TYPE_MX,   DNS_TYPE_TXT,   DNS_TYPE_NS,
        DNS_TYPE_SRV, DNS_TYPE_CAA,   DNS_TYPE_SSHFP, DNS_TYPE_TLSA, DNS_TYPE_DNAME, DNS_TYPE_LOC,
        DNS_TYPE_URI, DNS_TYPE_NAPTR, DNS_TYPE_PTR,   DNS_TYPE_SVCB, DNS_TYPE_HTTPS,
    };
    static const uint16_t dtypes[] = {DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_PTR};
    for (int pass = 0; pass < 2; pass++) {
        const char *ns = (pass == 0) ? "zone" : "ddns";
        const uint16_t *tt = (pass == 0) ? ztypes : dtypes;
        int ntypes = (pass == 0) ? (int) (sizeof(ztypes) / sizeof(ztypes[0]))
                                 : (int) (sizeof(dtypes) / sizeof(dtypes[0]));
        for (int ti = 0; ti < ntypes; ti++) {
            uint16_t T = tt[ti];
            char prefix[768], pat[800];
            int pl = snprintf(prefix, sizeof(prefix), "%s:%s:%s:", ns, zname, type2str(T));
            snprintf(pat, sizeof(pat), "%s*", prefix);
            char **keys = NULL;
            int nk = vk_list_keys(pat, &keys);
            for (int i = 0; i < nk; i++) {
                const char *name = keys[i] + pl;
                char val[768];
                if (!vk_get(keys[i], val, sizeof(val)) || !val[0])
                    continue;
                if (T == DNS_TYPE_A || T == DNS_TYPE_AAAA) {
                    if (pass == 1) { /* ddns: bare IP, TTL = remaining lease */
                        long tl = vk_ttl(keys[i]);
                        if (tl < 1)
                            tl = 1;
                        zmd_add_addr(&arr, &n, &cap, name, T, (uint32_t) tl, val);
                    } else { /* zone: ttl|ip|ip|... */
                        uint32_t ttl = DEFAULT_TTL;
                        char *pipe = strchr(val, '|');
                        if (pipe) {
                            ttl = (uint32_t) atoi(val);
                            pipe++;
                        } else {
                            pipe = val;
                        }
                        zmd_add_addr(&arr, &n, &cap, name, T, ttl, pipe);
                    }
                } else if (pass == 1) { /* ddns PTR lease: bare target */
                    long tl = vk_ttl(keys[i]);
                    if (tl < 1)
                        tl = 1;
                    uint8_t rd[300];
                    int rl = name_to_wire(val, rd, sizeof(rd));
                    if (rl > 0)
                        zmd_add(&arr, &n, &cap, name, T, (uint32_t) tl, rd, rl);
                } else { /* rich provisioned types via the shared encoder */
                    uint32_t ttl = DEFAULT_TTL;
                    char *pipe = strchr(val, '|');
                    if (pipe) {
                        ttl = (uint32_t) atoi(val);
                        pipe++;
                    } else {
                        pipe = val;
                    }
                    uint8_t rd[512];
                    int rl = stored_rdata(T, pipe, rd, (int) sizeof(rd));
                    if (rl > 0)
                        zmd_add(&arr, &n, &cap, name, T, ttl, rd, (uint16_t) rl);
                }
            }
            for (int i = 0; i < nk; i++)
                free(keys[i]);
            free(keys);
        }
    }
    /* ZSK DNSKEY RRset (ECDSA + Ed25519), TTL 3600 — matches the AXFR. */
    if (z) {
        uint8_t dkrd[68];
        if (z->zsk && dnskey_rdata_ecdsa(z->zsk, dkrd, sizeof(dkrd)) > 0)
            zmd_add(&arr, &n, &cap, zname, DNS_TYPE_DNSKEY, 3600, dkrd, 68);
        if (z->zsk_ed && dnskey_rdata_ed25519(z->zsk_ed, dkrd, sizeof(dkrd)) > 0)
            zmd_add(&arr, &n, &cap, zname, DNS_TYPE_DNSKEY, 3600, dkrd, 36);
    }
    /* Sort canonically, then hash, suppressing duplicate RRs (RFC 8976 §3.3.1). */
    qsort(arr, (size_t) n, sizeof(zmd_rr_t), zmd_cmp);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        rc = -1;
        goto cleanup;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        rc = -1;
        goto cleanup;
    }
    for (int i = 0; i < n; i++) {
        if (i > 0 && arr[i].wirelen == arr[i - 1].wirelen &&
            memcmp(arr[i].wire, arr[i - 1].wire, (size_t) arr[i].wirelen) == 0)
            continue; /* duplicate RR */
        if (EVP_DigestUpdate(ctx, arr[i].wire, (size_t) arr[i].wirelen) != 1) {
            EVP_MD_CTX_free(ctx);
            rc = -1;
            goto cleanup;
        }
    }
    unsigned int dl = 0;
    if (EVP_DigestFinal_ex(ctx, out_digest, &dl) != 1 || dl != ZONEMD_SHA384_LEN)
        rc = -1;
    else
        rc = (int) dl;
    EVP_MD_CTX_free(ctx);
cleanup:
    for (int i = 0; i < n; i++)
        free(arr[i].wire);
    free(arr);
    return rc;
}

/* Recompute + store zone `z`'s apex ZONEMD (opt-in via config:[zone:<z>:]zonemd,
 * default off). Stored as zone:<z>:ZONEMD:<apex> = ttl|hex(TLV). Called from
 * serial_bump after the new serial is committed. */
static void zonemd_update(zone_entry_t *z, uint32_t new_serial) {
    const char *zname = z ? z->name : g_zone_name;
    if (roll_cfg(zname, "zonemd", 0) == 0)
        return; /* not enabled for this zone */
    zone_entry_t *saved = t_zone;
    t_zone = z;
    uint8_t dg[ZONEMD_SHA384_LEN];
    int dlen = zonemd_compute(z, new_serial, dg);
    t_zone = saved;
    if (dlen != ZONEMD_SHA384_LEN)
        return;
    uint8_t tlv[256];
    int tl = zonemd_build_tlv(new_serial, ZONEMD_SCHEME_SIMPLE, ZONEMD_HASH_SHA384, dg,
                              ZONEMD_SHA384_LEN, tlv, sizeof(tlv));
    if (tl < 0)
        return;
    char hex[2 * 256 + 1];
    hex_enc(tlv, tl, hex);
    uint32_t ttl = z ? z->soa_minimum : g_soa_minimum;
    char key[768], val[700];
    snprintf(key, sizeof(key), "zone:%s:ZONEMD:%s", zname, zname);
    snprintf(val, sizeof(val), "%u|%s", ttl, hex);
    vk_set(key, val, 0);
}

/* Recompute the apex ZONEMD at boot/reload only when it is missing or its
 * embedded serial no longer matches the zone's current serial. A zone whose
 * content never changes (so serial_bump never fires) still publishes an
 * up-to-date digest; an unchanged zone is left untouched so a config reload of
 * a large zone does not rehash on every keyspace notification. */
static void zonemd_seed_if_stale(zone_entry_t *z) {
    const char *zname = z ? z->name : g_zone_name;
    if (roll_cfg(zname, "zonemd", 0) == 0)
        return; /* not enabled for this zone */
    uint32_t cur = z ? z->soa_serial : g_soa_serial;
    char key[768], val[700];
    snprintf(key, sizeof(key), "zone:%s:ZONEMD:%s", zname, zname);
    if (vk_get(key, val, sizeof(val)) && val[0]) {
        /* Stored as ttl|hex(TLV); the wire form leads with the 4-byte serial. */
        char *pipe = strchr(val, '|');
        const char *hexp = pipe ? pipe + 1 : val;
        uint8_t tlv[256];
        int tl = hex_dec(hexp, tlv, sizeof(tlv));
        uint8_t wire[128];
        int wl = (tl > 0) ? zonemd_tlv_to_wire(tlv, tl, wire, sizeof(wire)) : -1;
        if (wl >= 4) {
            uint32_t stored = ((uint32_t) wire[0] << 24) | ((uint32_t) wire[1] << 16) |
                              ((uint32_t) wire[2] << 8) | wire[3];
            if (stored == cur)
                return; /* up to date */
        }
    }
    zonemd_update(z, cur);
}

/* Append every runtime record of `zname` to an in-progress AXFR: the
 * zone:<zname>:* records (every provisioned type) and the ddns:<zname>:A/AAAA
 * dynamic leases (TTL = remaining lease). These are served locally but were
 * historically omitted from transfers, leaving a secondary with a near-empty
 * zone (CLAUDE-discovery.md Gap 1). Reuses stored_rdata() so the wire encoding
 * matches the live query path exactly. */
static void axfr_send_runtime(int fd, SSL *ssl, uint16_t qid, const char *zname, uint8_t mac[64],
                              int *maclen) {
    typedef struct {
        const char *ts;
        uint16_t t;
    } xtype_t;
    static const xtype_t ztypes[] = {
        {"A", DNS_TYPE_A},         {"AAAA", DNS_TYPE_AAAA},   {"CNAME", DNS_TYPE_CNAME},
        {"MX", DNS_TYPE_MX},       {"TXT", DNS_TYPE_TXT},     {"NS", DNS_TYPE_NS},
        {"SRV", DNS_TYPE_SRV},     {"CAA", DNS_TYPE_CAA},     {"SSHFP", DNS_TYPE_SSHFP},
        {"TLSA", DNS_TYPE_TLSA},   {"DNAME", DNS_TYPE_DNAME}, {"LOC", DNS_TYPE_LOC},
        {"URI", DNS_TYPE_URI},     {"NAPTR", DNS_TYPE_NAPTR}, {"PTR", DNS_TYPE_PTR},
        {"SVCB", DNS_TYPE_SVCB},   {"HTTPS", DNS_TYPE_HTTPS}, {"ZONEMD", DNS_TYPE_ZONEMD},
        {"CSYNC", DNS_TYPE_CSYNC},
    };
    /* ddns:* leases that transfer: A/AAAA plus auto-PTR reverse records. */
    static const xtype_t dtypes[] = {
        {"A", DNS_TYPE_A},
        {"AAAA", DNS_TYPE_AAAA},
        {"PTR", DNS_TYPE_PTR},
    };
    const int nz = (int) (sizeof(ztypes) / sizeof(ztypes[0]));
    const int nd = (int) (sizeof(dtypes) / sizeof(dtypes[0]));
    for (int pass = 0; pass < 2; pass++) {
        const char *ns = (pass == 0) ? "zone" : "ddns";
        const xtype_t *tt = (pass == 0) ? ztypes : dtypes;
        const int ntypes = (pass == 0) ? nz : nd;
        for (int ti = 0; ti < ntypes; ti++) {
            char prefix[768], pat[800];
            int pl = snprintf(prefix, sizeof(prefix), "%s:%s:%s:", ns, zname, tt[ti].ts);
            snprintf(pat, sizeof(pat), "%s*", prefix);
            char **keys = NULL;
            int nk = vk_list_keys(pat, &keys);
            for (int i = 0; i < nk; i++) {
                const char *name = keys[i] + pl; /* strip "ns:zname:TYPE:" */
                char val[768];
                if (!vk_get(keys[i], val, sizeof(val)) || !val[0])
                    continue;
                uint16_t T = tt[ti].t;
                if (T == DNS_TYPE_A || T == DNS_TYPE_AAAA) {
                    const int af = (T == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
                    const uint16_t alen = (T == DNS_TYPE_AAAA) ? 16 : 4;
                    if (pass == 1) { /* ddns: bare IP, TTL = remaining lease */
                        long tl = vk_ttl(keys[i]);
                        if (tl < 1)
                            tl = 1;
                        uint8_t rd[16];
                        if (inet_pton(af, val, rd) == 1)
                            axfr_emit_one(fd, ssl, qid, name, T, (uint32_t) tl, rd, alen, mac,
                                          maclen);
                    } else { /* zone: ttl|ip|ip|... */
                        uint32_t ttl = DEFAULT_TTL;
                        char *pipe = strchr(val, '|');
                        if (pipe) {
                            ttl = (uint32_t) atoi(val);
                            pipe++;
                        } else {
                            pipe = val;
                        }
                        char *sp = NULL;
                        for (char *ip = strtok_r(pipe, "|", &sp); ip;
                             ip = strtok_r(NULL, "|", &sp)) {
                            uint8_t rd[16];
                            if (inet_pton(af, ip, rd) == 1)
                                axfr_emit_one(fd, ssl, qid, name, T, ttl, rd, alen, mac, maclen);
                        }
                    }
                } else if (pass == 1) { /* ddns PTR lease: bare target, TTL = remaining lease */
                    long tl = vk_ttl(keys[i]);
                    if (tl < 1)
                        tl = 1;
                    uint8_t rd[300];
                    int rl = name_to_wire(val, rd, sizeof(rd));
                    if (rl > 0)
                        axfr_emit_one(fd, ssl, qid, name, T, (uint32_t) tl, rd, (uint16_t) rl, mac,
                                      maclen);
                } else { /* rich provisioned types via the shared encoder */
                    uint32_t ttl = DEFAULT_TTL;
                    char *pipe = strchr(val, '|');
                    if (pipe) {
                        ttl = (uint32_t) atoi(val);
                        pipe++;
                    } else {
                        pipe = val;
                    }
                    uint8_t rd[512];
                    int rl = stored_rdata(T, pipe, rd, (int) sizeof(rd));
                    if (rl > 0)
                        axfr_emit_one(fd, ssl, qid, name, T, ttl, rd, (uint16_t) rl, mac, maclen);
                }
            }
            for (int i = 0; i < nk; i++)
                free(keys[i]);
            free(keys);
        }
    }
}

/* ==========================================================================
 * Zone transfer CLIENT — a secondary pulls AXFR from the master.
 * hidden-master plan Gap 3. AXFR over plain TCP or TLS (server-cert verified
 * against config:xfr_ca_pem, optional client cert / mTLS). The transferred
 * RRset replaces the local zone:<zone>:* store, but only after a COMPLETE
 * transfer (the closing SOA) — a partial/failed pull leaves the old data
 * intact. TSIG signing + chained-response verification is Gap 4 (next); until
 * then run the transfer over TLS (config:primary_tls=1 + config:xfr_ca_pem) so
 * the channel — and therefore the data — is authenticated.
 * ======================================================================= */
#define XFR_MAX_RECORDS 50000
#define XFR_MAX_DIFFS 8192 /* cap on incremental (IXFR) changes applied in one pull */

typedef struct {
    char name[256];
    uint16_t type;
    uint32_t ttl;
    char val[600]; /* store value; for A/AAAA the bare address (grouped on apply) */
} xfr_rec_t;

/* One change from an incremental (IXFR) response: op 'A' = add, 'D' = delete. */
typedef struct {
    char op;
    char name[256];
    uint16_t type;
    uint32_t ttl;
    char val[600];
} xfr_diff_t;

/* Read exactly n bytes from a plain fd or an SSL conn. 0 on success, -1 else. */
static int xfr_read_full(int fd, SSL *ssl, uint8_t *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = ssl ? SSL_read(ssl, buf + got, n - got)
                    : (int) recv(fd, buf + got, (size_t) (n - got), 0);
        if (r <= 0)
            return -1;
        got += r;
    }
    return 0;
}

/* Convert a received RR's wire rdata to its store-string for `type`. Returns 0
 * (val filled) on success, -1 if the type is not replicated into zone:* (skip).
 * For A/AAAA, val is the bare address; apply groups them into ttl|ip|ip. */
static int xfr_rdata_to_store(const uint8_t *pkt, int plen, uint16_t type, int rdoff, int rdlen,
                              char *val, int valcap) {
    switch (type) {
        case DNS_TYPE_A:
            if (rdlen != 4)
                return -1;
            snprintf(val, valcap, "%u.%u.%u.%u", pkt[rdoff], pkt[rdoff + 1], pkt[rdoff + 2],
                     pkt[rdoff + 3]);
            return 0;
        case DNS_TYPE_AAAA: {
            char b[INET6_ADDRSTRLEN];
            if (rdlen != 16 || !inet_ntop(AF_INET6, pkt + rdoff, b, sizeof(b)))
                return -1;
            safe_strcpy(val, b, valcap);
            return 0;
        }
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME: {
            char tgt[256];
            if (name_from_wire(pkt, plen, rdoff, tgt, sizeof(tgt)) < 0)
                return -1;
            safe_strcpy(val, tgt, valcap);
            return 0;
        }
        case DNS_TYPE_MX: {
            char tgt[256];
            if (rdlen < 3 || name_from_wire(pkt, plen, rdoff + 2, tgt, sizeof(tgt)) < 0)
                return -1;
            snprintf(val, valcap, "%u|%s", get16(pkt, rdoff), tgt);
            return 0;
        }
        case DNS_TYPE_TXT: {
            int sl = (rdlen >= 1) ? pkt[rdoff] : -1;
            if (sl < 0 || sl > rdlen - 1)
                return -1;
            if (sl >= valcap)
                sl = valcap - 1;
            memcpy(val, pkt + rdoff + 1, (size_t) sl);
            val[sl] = 0;
            return 0;
        }
        case DNS_TYPE_SRV: {
            char tgt[256];
            if (rdlen < 7 || name_from_wire(pkt, plen, rdoff + 6, tgt, sizeof(tgt)) < 0)
                return -1;
            snprintf(val, valcap, "%u|%u|%u|%s", get16(pkt, rdoff), get16(pkt, rdoff + 2),
                     get16(pkt, rdoff + 4), tgt);
            return 0;
        }
        default:
            return -1; /* SOA/DNSKEY/RRSIG/NSEC/… not replicated into zone:* */
    }
}

/* Persist `zone`'s SOA serial to the master's value (never generated locally on
 * a secondary — the master's serial is authoritative). */
static void xfr_set_serial(const char *zone, uint32_t serial) {
    char ikey[320], buf[32];
    int primary = (strcasecmp(zone, g_zone_name) == 0);
    if (primary)
        safe_strcpy(ikey, "config:zone_serial", sizeof(ikey));
    else
        snprintf(ikey, sizeof(ikey), "config:zone:%.255s:serial", zone);
    snprintf(buf, sizeof(buf), "%u", serial);
    vk_set(ikey, buf, 0);
    pthread_mutex_lock(&g_soa_mutex);
    if (primary)
        g_soa_serial = serial;
    pthread_mutex_unlock(&g_soa_mutex);
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count; i++)
        if (strcasecmp(g_zones[i].name, zone) == 0)
            g_zones[i].soa_serial = serial;
    pthread_mutex_unlock(&g_zones_mutex);
}

/* Replace zone:<zone>:* with the transferred RRset (delete-then-write, grouping
 * A/AAAA by owner), then adopt the master's serial. Called only on a complete
 * transfer. */
static void xfr_apply(const char *zone, xfr_rec_t *recs, int n, uint32_t serial) {
    char pat[768];
    snprintf(pat, sizeof(pat), "zone:%.255s:*", zone);
    char **old = NULL;
    int no = vk_list_keys(pat, &old);
    for (int i = 0; i < no; i++)
        vk_del(old[i]);
    for (int i = 0; i < no; i++)
        free(old[i]);
    free(old);
    char *written = calloc((size_t) (n > 0 ? n : 1), 1);
    if (!written)
        return;
    for (int i = 0; i < n; i++) {
        if (written[i])
            continue;
        char key[900], val[1024];
        snprintf(key, sizeof(key), "zone:%.255s:%.16s:%.255s", zone, type2str(recs[i].type),
                 recs[i].name);
        if (recs[i].type == DNS_TYPE_A || recs[i].type == DNS_TYPE_AAAA) {
            int off = snprintf(val, sizeof(val), "%u", recs[i].ttl);
            for (int j = i; j < n; j++) {
                if (!written[j] && recs[j].type == recs[i].type &&
                    strcasecmp(recs[j].name, recs[i].name) == 0) {
                    if (off < (int) sizeof(val) - 1)
                        off += snprintf(val + off, sizeof(val) - off, "|%s", recs[j].val);
                    written[j] = 1;
                }
            }
        } else {
            snprintf(val, sizeof(val), "%u|%s", recs[i].ttl, recs[i].val);
            written[i] = 1;
        }
        vk_set(key, val, 0);
    }
    free(written);
    xfr_set_serial(zone, serial);
}

/* Read the local SOA serial for `zone` (0 if unknown / first ever pull). */
static uint32_t xfr_get_serial(const char *zone) {
    uint32_t s = 0;
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count; i++)
        if (strcasecmp(g_zones[i].name, zone) == 0) {
            s = g_zones[i].soa_serial;
            break;
        }
    pthread_mutex_unlock(&g_zones_mutex);
    return s;
}

/* Apply one incremental (IXFR) change to the local zone:<zone>:* store. A/AAAA
 * records are grouped per owner as "ttl|ip|ip…": an add appends the IP (if not
 * already present), a delete removes it (deleting the key when the last IP
 * goes). Other types: add overwrites, delete removes the key. */
static void xfr_apply_one_diff(const char *zone, char op, const char *name, uint16_t type,
                               uint32_t ttl, const char *val) {
    char key[900];
    snprintf(key, sizeof(key), "zone:%.255s:%.16s:%.255s", zone, type2str(type), name);
    if (type != DNS_TYPE_A && type != DNS_TYPE_AAAA) {
        if (op == 'A') {
            char v[1024];
            snprintf(v, sizeof(v), "%u|%s", ttl, val);
            vk_set(key, v, 0);
        } else {
            vk_del(key);
        }
        return;
    }
    /* A/AAAA: rebuild the grouped "ttl|ip|ip…" value. */
    char cur[1024] = "";
    vk_get(key, cur, sizeof(cur));
    uint32_t out_ttl = ttl ? ttl : DEFAULT_TTL;
    char ips[64][INET6_ADDRSTRLEN];
    int nip = 0;
    if (cur[0]) {
        char *sp = NULL;
        char *tok = strtok_r(cur, "|", &sp);
        if (tok) {
            out_ttl = (uint32_t) strtoul(tok, NULL, 10); /* first field is the TTL */
            for (tok = strtok_r(NULL, "|", &sp); tok && nip < 64; tok = strtok_r(NULL, "|", &sp))
                safe_strcpy(ips[nip++], tok, sizeof(ips[0]));
        }
    }
    int present = 0;
    for (int i = 0; i < nip; i++)
        if (strcasecmp(ips[i], val) == 0) {
            present = i + 1;
            break;
        }
    if (op == 'A') {
        if (ttl)
            out_ttl = ttl;
        if (!present && nip < 64)
            safe_strcpy(ips[nip++], val, sizeof(ips[0]));
    } else if (present) { /* delete: drop the matching IP */
        for (int i = present - 1; i < nip - 1; i++)
            safe_strcpy(ips[i], ips[i + 1], sizeof(ips[0]));
        nip--;
    }
    if (nip == 0) {
        vk_del(key);
        return;
    }
    char v[1024];
    int off = snprintf(v, sizeof(v), "%u", out_ttl);
    for (int i = 0; i < nip && off < (int) sizeof(v) - 1; i++)
        off += snprintf(v + off, sizeof(v) - off, "|%s", ips[i]);
    vk_set(key, v, 0);
}

/* Apply an ordered list of incremental changes, then adopt the master serial. */
static void xfr_apply_diffs(const char *zone, xfr_diff_t *d, int n, uint32_t serial) {
    for (int i = 0; i < n; i++)
        xfr_apply_one_diff(zone, d[i].op, d[i].name, d[i].type, d[i].ttl, d[i].val);
    xfr_set_serial(zone, serial);
}

/* Build a TLS client context for the transfer (server-cert verify against
 * xfr_ca_pem; present a client cert if configured). NULL on error. */
static SSL_CTX *xfr_client_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (g_xfr_ca_pem[0]) {
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        BIO *b = BIO_new_mem_buf(g_xfr_ca_pem, -1);
        X509 *cax;
        while ((cax = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
            X509_STORE_add_cert(store, cax);
            X509_free(cax);
        }
        BIO_free(b);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    if (g_xfr_client_cert_pem[0] && g_xfr_client_key_pem[0]) {
        BIO *cb = BIO_new_mem_buf(g_xfr_client_cert_pem, -1);
        X509 *cc = PEM_read_bio_X509(cb, NULL, NULL, NULL);
        if (cc) {
            SSL_CTX_use_certificate(ctx, cc);
            X509_free(cc);
        }
        BIO_free(cb);
        BIO *kb = BIO_new_mem_buf(g_xfr_client_key_pem, -1);
        EVP_PKEY *pk = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
        if (pk) {
            SSL_CTX_use_PrivateKey(ctx, pk);
            EVP_PKEY_free(pk);
        }
        BIO_free(kb);
    }
    return ctx;
}

/* Build TSIG signing variables from a parsed TSIG RR (mirrors the block in
 * tsig_verify): key name, class ANY, ttl 0, algorithm, time, fudge, error,
 * other-len 0. Returns the byte count. Used to verify the chained AXFR MAC. */
static int xfr_tsig_vars_from_rr(const tsig_rr_t *t, uint8_t vars[512]) {
    int vp = 0;
    char tmp2[256];
    safe_strcpy(tmp2, t->key_name, sizeof(tmp2));
    char *sp = NULL;
    for (char *lbl = strtok_r(tmp2, ".", &sp); lbl; lbl = strtok_r(NULL, ".", &sp)) {
        int ll = (int) strlen(lbl);
        vars[vp++] = (uint8_t) ll;
        memcpy(vars + vp, lbl, ll);
        vp += ll;
    }
    vars[vp++] = 0; /* end of key name */
    vars[vp++] = 0;
    vars[vp++] = 255; /* class ANY */
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0;
    vars[vp++] = 0; /* ttl 0 (4 bytes) */
    memcpy(vars + vp, "\x0bhmac-sha256\x00", 13);
    vp += 13;
    vars[vp++] = (uint8_t) (t->time_high >> 8);
    vars[vp++] = (uint8_t) (t->time_high & 0xFF);
    vars[vp++] = (uint8_t) ((t->time_low >> 24) & 0xFF);
    vars[vp++] = (uint8_t) ((t->time_low >> 16) & 0xFF);
    vars[vp++] = (uint8_t) ((t->time_low >> 8) & 0xFF);
    vars[vp++] = (uint8_t) (t->time_low & 0xFF);
    vars[vp++] = t->fudge >> 8;
    vars[vp++] = t->fudge & 0xFF;
    vars[vp++] = t->error >> 8;
    vars[vp++] = t->error & 0xFF;
    vars[vp++] = 0;
    vars[vp++] = 0; /* other len 0 */
    return vp;
}

/* Sign an outgoing AXFR query with TSIG (RFC 8945): MAC = HMAC(query || vars).
 * Returns the new length and stores the request MAC (which seeds the response
 * chain). No-op (returns off) if TSIG is not configured. */
static int xfr_tsig_sign_query(uint8_t *buf, int off, int blen, uint16_t qid, uint8_t *reqmac,
                               int *reqmac_len) {
    *reqmac_len = 0;
    if (g_tsig_secret_len == 0)
        return off;
    time_t now = time(NULL);
    uint8_t vars[512];
    int vp = tsig_vars_build(vars, now, 0);
    EVP_MAC *em;
    EVP_MAC_CTX *ctx = tsig_hmac_new(&em);
    if (!ctx)
        return off;
    EVP_MAC_update(ctx, buf, off);
    EVP_MAC_update(ctx, vars, vp);
    size_t ml = 64;
    EVP_MAC_final(ctx, reqmac, &ml, 64);
    *reqmac_len = (int) ml;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(em);
    return tsig_rr_write(buf, off, blen, qid, 0, now, reqmac, *reqmac_len);
}

/* Verify one AXFR response message against the running MAC (RFC 8945 §5.3.1).
 * A signed message (TSIG RR present): MAC = HMAC(prior || msg-minus-TSIG ||
 * vars) must equal the RR's MAC; prior is reseeded to it. An unsigned
 * intermediate: prior = HMAC(prior || msg). Returns 1 on success (sets
 * *was_signed), 0 if a signed message fails verification. */
static int xfr_tsig_verify_msg(const uint8_t *msg, int mlen, uint8_t *prior, int *prior_len,
                               int *was_signed) {
    tsig_rr_t t;
    memset(&t, 0, sizeof(t));
    const uint8_t *trr = tsig_find(msg, mlen, &t);
    EVP_MAC *em;
    EVP_MAC_CTX *ctx = tsig_hmac_new(&em);
    if (!ctx)
        return 0;
    tsig_hmac_prepend(ctx, prior, *prior_len);
    if (!trr) { /* unsigned intermediate — fold whole message into the chain */
        EVP_MAC_update(ctx, msg, mlen);
        uint8_t mac[64];
        size_t ml = 64;
        EVP_MAC_final(ctx, mac, &ml, 64);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(em);
        memcpy(prior, mac, ml);
        *prior_len = (int) ml;
        *was_signed = 0;
        return 1;
    }
    int minus = (int) (trr - msg);
    if (minus <= 0) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(em);
        return 0;
    }
    uint8_t *tmp = malloc((size_t) minus);
    if (!tmp) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(em);
        return 0;
    }
    memcpy(tmp, msg, (size_t) minus);
    uint16_t ar = ((uint16_t) tmp[10] << 8) | tmp[11];
    ar--;
    tmp[10] = ar >> 8;
    tmp[11] = ar & 0xFF;
    uint8_t vars[512];
    int vp = xfr_tsig_vars_from_rr(&t, vars);
    EVP_MAC_update(ctx, tmp, minus);
    EVP_MAC_update(ctx, vars, vp);
    free(tmp);
    uint8_t mac[64];
    size_t ml = 64;
    EVP_MAC_final(ctx, mac, &ml, 64);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(em);
    int ok = ((int) ml == t.mac_len) && CRYPTO_memcmp(mac, t.mac, ml) == 0;
    if (ok) {
        memcpy(prior, t.mac, (size_t) t.mac_len);
        *prior_len = t.mac_len;
    }
    *was_signed = 1;
    return ok;
}

/* Pull `zone` from the configured master via AXFR and replace the local store.
 * Returns 0 on success, -1 on any failure (store left untouched on failure). */
static int xfr_pull(const char *zone) {
    if (!g_primary_host[0])
        return -1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", g_primary_port);
    if (getaddrinfo(g_primary_host, portstr, &hints, &res) != 0 || !res)
        return -1;
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    SSL_CTX *cctx = NULL;
    SSL *ssl = NULL;
    if (g_primary_tls) {
        cctx = xfr_client_ctx();
        if (!cctx) {
            close(fd);
            return -1;
        }
        ssl = SSL_new(cctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, g_primary_host);
        /* When a CA is pinned (so SSL_VERIFY_PEER is on) also bind the hostname,
         * so a pinned-CA transfer authenticates the primary's identity, not just
         * its chain. No-CA transfers stay integrity-protected by TSIG. */
        if (g_xfr_ca_pem[0])
            tls_verify_peer_name(ssl, g_primary_host);
        static const uint8_t alpn[] = {3, 'd', 'o', 't'};
        SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));
        if (SSL_connect(ssl) <= 0 || (g_xfr_ca_pem[0] && SSL_get_verify_result(ssl) != X509_V_OK)) {
            dns_log(LOG_WARNING, "[XFR] %s: TLS handshake/verify to %s failed\n", zone,
                    g_primary_host);
            SSL_free(ssl);
            SSL_CTX_free(cctx);
            close(fd);
            return -1;
        }
    }
    /* Build + send the transfer query (id 0x5858 "XX"). Request IXFR (RFC 1995)
     * when we already hold a serial — carrying it as an SOA in the authority
     * section — so the master can answer with just the diff; the master may
     * still reply with a full AXFR-style transfer, which we detect below and
     * apply as a full replace. The very first pull (serial 0) asks for AXFR. */
    uint32_t local_serial = xfr_get_serial(zone);
    int want_ixfr = (local_serial > 0);
    uint8_t q[600];
    memset(q, 0, 12);
    dns_hdr_t *qh = (dns_hdr_t *) q;
    uint16_t qid = 0x5858;
    qh->id = htons(qid);
    qh->flags = 0; /* opcode QUERY, no RD (a transfer is not a recursive query) */
    qh->qdcount = htons(1);
    int qo = name_to_wire(zone, q + 12, sizeof(q) - 12);
    if (qo < 0) {
        if (ssl) {
            SSL_free(ssl);
            SSL_CTX_free(cctx);
        }
        close(fd);
        return -1;
    }
    qo += 12;
    put16(q, qo, want_ixfr ? DNS_TYPE_IXFR : DNS_TYPE_AXFR);
    qo += 2;
    put16(q, qo, DNS_CLASS_IN);
    qo += 2;
    if (want_ixfr) {
        /* Authority section: SOA carrying our current serial (RFC 1995 §3). */
        int an = name_to_wire(zone, q + qo, (int) sizeof(q) - qo);
        if (an > 0) {
            qo += an;
            put16(q, qo, DNS_TYPE_SOA);
            qo += 2;
            put16(q, qo, DNS_CLASS_IN);
            qo += 2;
            put32(q, qo, 0); /* TTL */
            qo += 4;
            int rdlen_off = qo;
            qo += 2; /* rdlen placeholder */
            int rdstart = qo;
            int nn = name_to_wire(zone, q + qo, (int) sizeof(q) - qo); /* mname */
            qo += (nn > 0) ? nn : 0;
            nn = name_to_wire(zone, q + qo, (int) sizeof(q) - qo); /* rname */
            qo += (nn > 0) ? nn : 0;
            put32(q, qo, local_serial);
            qo += 4;
            put32(q, qo, 3600);
            qo += 4;
            put32(q, qo, 900);
            qo += 4;
            put32(q, qo, 604800);
            qo += 4;
            put32(q, qo, 300);
            qo += 4;
            put16(q, rdlen_off, (uint16_t) (qo - rdstart));
            qh->nscount = htons(1);
        }
    }
    /* TSIG-sign the request (RFC 8945, Gap 4) if a key is configured; the
     * request MAC seeds the response-chain verification below. */
    uint8_t prior[64];
    int prior_len = 0;
    qo = xfr_tsig_sign_query(q, qo, sizeof(q), qid, prior, &prior_len);
    uint8_t lb[2] = {(uint8_t) (qo >> 8), (uint8_t) (qo & 0xFF)};
    int sok = ssl ? (SSL_write(ssl, lb, 2) == 2 && SSL_write(ssl, q, qo) == qo)
                  : (send(fd, lb, 2, 0) == 2 && send(fd, q, qo, 0) == qo);
    if (!sok) {
        if (ssl) {
            SSL_free(ssl);
            SSL_CTX_free(cctx);
        }
        close(fd);
        return -1;
    }
    /* Read the transfer stream. Both AXFR and IXFR responses open and close with
     * SOA(current); the structure is told apart by what follows the opening SOA:
     *   - a data RR  → AXFR-style full transfer (collect records, full replace);
     *   - an SOA RR  → incremental, a series of difference sequences
     *                  [ SOA(old), deletions, SOA(new), additions ].
     * SOA framing parity drives the section: counting SOAs after the opening,
     * an even count begins a deletion section (or is the closing SOA when its
     * serial equals the target), an odd count begins an addition section. */
    xfr_rec_t *recs = malloc(sizeof(xfr_rec_t) * XFR_MAX_RECORDS);
    xfr_diff_t *diffs = malloc(sizeof(xfr_diff_t) * XFR_MAX_DIFFS);
    int nrec = 0, ndiff = 0, ok = 0, overflow = 0;
    int soa_count = 0;   /* total SOAs seen */
    int mode = 0;        /* 0 unknown, 1 AXFR-style full, 2 incremental */
    int in_add = 0;      /* current incremental section: 1 = additions, 0 = deletions */
    int done = 0;        /* saw the closing SOA(target) */
    uint32_t target = 0; /* serial we will converge to (first/opening SOA) */
    /* TSIG chain state (Gap 4): require verification when a key is configured. */
    int tsig = (g_tsig_secret_len > 0), tsig_fail = 0, last_signed = 0, unsigned_run = 0;
    uint8_t *msg = malloc(65536);
    if (recs && diffs && msg) {
        while (!done) {
            uint8_t mlb[2];
            if (xfr_read_full(fd, ssl, mlb, 2) != 0)
                break;
            int mlen = (mlb[0] << 8) | mlb[1];
            if (mlen < 12 || mlen > 65535 || xfr_read_full(fd, ssl, msg, mlen) != 0)
                break;
            if (tsig) {
                int was_signed = 0;
                if (!xfr_tsig_verify_msg(msg, mlen, prior, &prior_len, &was_signed)) {
                    dns_log(LOG_WARNING, "[XFR] %s: TSIG verification FAILED — rejecting\n", zone);
                    tsig_fail = 1;
                    break;
                }
                last_signed = was_signed;
                unsigned_run = was_signed ? 0 : unsigned_run + 1;
                if (unsigned_run > 99) { /* RFC 8945 §5.3.1 */
                    dns_log(LOG_WARNING, "[XFR] %s: >99 unsigned messages — rejecting\n", zone);
                    tsig_fail = 1;
                    break;
                }
            }
            int qd = (int) ntohs(((dns_hdr_t *) msg)->qdcount);
            int an = (int) ntohs(((dns_hdr_t *) msg)->ancount);
            int off = 12;
            for (int i = 0; i < qd; i++) { /* skip question section */
                char tmpn[256];
                int a = name_from_wire(msg, mlen, off, tmpn, sizeof(tmpn));
                if (a < 0 || a + 4 > mlen)
                    goto stream_done;
                off = a + 4;
            }
            for (int i = 0; i < an && !done; i++) {
                char rname[256];
                int a = name_from_wire(msg, mlen, off, rname, sizeof(rname));
                if (a < 0 || a + 10 > mlen)
                    goto stream_done;
                uint16_t rtype = get16(msg, a);
                uint32_t rttl = get32(msg, a + 4);
                uint16_t rdlen = get16(msg, a + 8);
                int rdoff = a + 10;
                if (rdoff + rdlen > mlen)
                    goto stream_done;
                off = rdoff + rdlen;
                if (rtype == DNS_TYPE_SOA) {
                    uint32_t s = 0;
                    char nm[256];
                    int p = name_from_wire(msg, mlen, rdoff, nm, sizeof(nm));
                    if (p > 0)
                        p = name_from_wire(msg, mlen, p, nm, sizeof(nm));
                    if (p > 0 && p + 4 <= mlen)
                        s = get32(msg, p);
                    soa_count++;
                    if (soa_count == 1) { /* opening SOA → the target serial */
                        target = s;
                        continue;
                    }
                    /* An even-count SOA whose serial is the target is the closer. */
                    if ((soa_count % 2 == 0) && s == target) {
                        done = 1;
                        break;
                    }
                    if (mode == 0)
                        mode = 2;                  /* a 2nd SOA before any data RR → incremental */
                    in_add = (soa_count % 2 == 1); /* odd: additions, even: deletions */
                    continue;
                }
                /* Data RR. */
                if (soa_count == 1 && mode == 0)
                    mode = 1; /* data right after the opening SOA → full AXFR */
                char val[600];
                if (xfr_rdata_to_store(msg, mlen, rtype, rdoff, rdlen, val, sizeof(val)) != 0)
                    continue; /* unsupported type — skip */
                if (mode == 2) {
                    if (ndiff >= XFR_MAX_DIFFS) {
                        overflow = 1;
                        goto stream_done;
                    }
                    diffs[ndiff].op = in_add ? 'A' : 'D';
                    safe_strcpy(diffs[ndiff].name, rname, sizeof(diffs[ndiff].name));
                    diffs[ndiff].type = rtype;
                    diffs[ndiff].ttl = rttl;
                    safe_strcpy(diffs[ndiff].val, val, sizeof(diffs[ndiff].val));
                    ndiff++;
                } else { /* AXFR full transfer (or still-unknown — treated as full) */
                    if (nrec >= XFR_MAX_RECORDS) {
                        overflow = 1;
                        goto stream_done;
                    }
                    safe_strcpy(recs[nrec].name, rname, sizeof(recs[nrec].name));
                    recs[nrec].type = rtype;
                    recs[nrec].ttl = rttl;
                    safe_strcpy(recs[nrec].val, val, sizeof(recs[nrec].val));
                    nrec++;
                }
            }
        }
    stream_done:;
        /* When TSIG is configured the transfer must verify and the final message
         * must be signed (RFC 8945 §5.3.1); otherwise reject (no apply). */
        int tsig_ok = (!tsig || (!tsig_fail && last_signed));
        /* A single opening SOA whose serial matches ours (no closing SOA needed)
         * is the "already up to date" reply — success, nothing to apply. */
        int up_to_date = (!done && soa_count == 1 && target == local_serial && tsig_ok);
        if (up_to_date)
            done = 1;
        ok = up_to_date || (done && !overflow && tsig_ok);
    }
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(cctx);
    }
    close(fd);
    if (ok && mode == 2) {
        xfr_apply_diffs(zone, diffs, ndiff, target);
        dns_log(LOG_NOTICE, "[XFR] %s: IXFR from %s:%d complete — %d changes, serial %u\n", zone,
                g_primary_host, g_primary_port, ndiff, target);
    } else if (ok && soa_count == 1 && target == local_serial) {
        dns_log(LOG_NOTICE, "[XFR] %s: already current at serial %u (%s:%d)\n", zone, target,
                g_primary_host, g_primary_port);
    } else if (ok) {
        xfr_apply(zone, recs, nrec, target);
        dns_log(LOG_NOTICE, "[XFR] %s: AXFR from %s:%d complete — %d records, serial %u\n", zone,
                g_primary_host, g_primary_port, nrec, target);
    } else {
        dns_log(LOG_WARNING,
                "[XFR] %s: transfer from %s:%d failed (incomplete) — store unchanged\n", zone,
                g_primary_host, g_primary_port);
    }
    free(recs);
    free(diffs);
    free(msg);
    return ok ? 0 : -1;
}

/* Wake the refresh thread for an immediate re-check (Gap 5, NOTIFY path).
 * RFC 1996 §4.7: a NOTIFY makes the secondary behave as if the SOA refresh
 * timer had expired, so force every zone due now — otherwise a zone with a
 * normal (long) refresh interval would ignore the NOTIFY until its timer
 * eventually elapsed, defeating the prompt-notification / IXFR re-pull. */
static void xfr_refresh_kick(void) {
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count; i++)
        g_zones[i].xfr_next_check = 0;
    pthread_mutex_unlock(&g_zones_mutex);
    pthread_mutex_lock(&g_xfr_mutex);
    g_xfr_wake = 1;
    pthread_cond_signal(&g_xfr_cond);
    pthread_mutex_unlock(&g_xfr_mutex);
}

/* Zone-maintenance loop for a secondary (hidden-master plan Gap 6): pull each
 * zone from the master on its SOA refresh timer (retry timer after a failure),
 * immediately on a NOTIFY (Gap 5). The first pass loads every zone at startup.
 * Records the last successful contact per zone (xfr_last_ok) so the query path
 * can SERVFAIL a zone that has gone past its SOA expire (RFC 1035 §4.3.5). */
static void *xfr_refresh_thread(void *arg) {
    (void) arg;
    /* Seed the expire clock at boot: a secondary that can never reach its master
     * still expires the zone after soa_expire (rather than serving forever). */
    {
        time_t boot = time(NULL);
        pthread_mutex_lock(&g_zones_mutex);
        for (int i = 0; i < g_zone_count; i++)
            if (g_zones[i].xfr_last_ok == 0)
                g_zones[i].xfr_last_ok = boot;
        pthread_mutex_unlock(&g_zones_mutex);
    }
    for (;;) {
        /* Snapshot zone names + timers; do the (slow) network pulls unlocked. */
        char names[MAX_ZONES][256];
        uint32_t refresh[MAX_ZONES], retry[MAX_ZONES];
        time_t due[MAX_ZONES];
        int nz = 0;
        time_t now = time(NULL);
        pthread_mutex_lock(&g_zones_mutex);
        for (int i = 0; i < g_zone_count && nz < MAX_ZONES; i++) {
            safe_strcpy(names[nz], g_zones[i].name, sizeof(names[0]));
            refresh[nz] = g_zones[i].soa_refresh ? g_zones[i].soa_refresh : 3600;
            retry[nz] = g_zones[i].soa_retry ? g_zones[i].soa_retry : 900;
            due[nz] = g_zones[i].xfr_next_check;
            nz++;
        }
        pthread_mutex_unlock(&g_zones_mutex);
        for (int i = 0; i < nz; i++) {
            if (due[i] != 0 && now < due[i])
                continue; /* not yet due (0 = never checked → pull now) */
            int ok = (xfr_pull(names[i]) == 0);
            time_t next = time(NULL) + (ok ? (time_t) refresh[i] : (time_t) retry[i]);
            pthread_mutex_lock(&g_zones_mutex);
            for (int j = 0; j < g_zone_count; j++)
                if (strcasecmp(g_zones[j].name, names[i]) == 0) {
                    g_zones[j].xfr_next_check = next;
                    if (ok)
                        g_zones[j].xfr_last_ok = time(NULL);
                    break;
                }
            pthread_mutex_unlock(&g_zones_mutex);
        }
        /* Sleep until the soonest next_check (capped), or until a NOTIFY kick. */
        now = time(NULL);
        long sleep_s = 3600;
        pthread_mutex_lock(&g_zones_mutex);
        for (int i = 0; i < g_zone_count; i++) {
            long d = (long) (g_zones[i].xfr_next_check - now);
            if (g_zones[i].xfr_next_check != 0 && d < sleep_s)
                sleep_s = d;
        }
        pthread_mutex_unlock(&g_zones_mutex);
        if (sleep_s < 1)
            sleep_s = 1;
        struct timespec ts = {.tv_sec = now + sleep_s, .tv_nsec = 0};
        pthread_mutex_lock(&g_xfr_mutex);
        if (!g_xfr_wake)
            pthread_cond_timedwait(&g_xfr_cond, &g_xfr_mutex, &ts);
        g_xfr_wake = 0;
        pthread_mutex_unlock(&g_xfr_mutex);
    }
    return NULL;
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

    /* ── IXFR path (RFC 1995) ──
     * Response framing: SOA(current), then one difference sequence per journaled
     * change [ SOA(from), <deleted RR>, SOA(to), <added RR> ], then SOA(current).
     * The op field selects the deletion vs addition section so a 'D' entry is a
     * real delete and an 'A' a real add (the previous code emitted every change
     * as an addition inside the deletion section). */
    /* RFC 1982 serial arithmetic: a raw `<` mis-decides across the 2^32 wrap
     * (e.g. our serial wrapped to a small value while the client still holds a
     * large older one), needlessly forcing AXFR. serial_lt orders correctly. */
    if (c.ixfr && c.ixfr_serial > 0 && serial_lt(c.ixfr_serial, t_zone->soa_serial)) {
        char *entries[IXFR_JOURNAL_MAX];
        int ne =
            ixfr_journal_fetch(zname, c.ixfr_serial, t_zone->soa_serial, entries, IXFR_JOURNAL_MAX);
        if (ne > 0) {
            uint8_t mb[BUF_SIZE];
            int mo;
            uint8_t ixfr_mac[64];
            int ixfr_mac_len = 0;
            /* Opening SOA(current) — first (signed) message, echoes the question. */
            compress_reset();
            memset(mb, 0, 12);
            dns_hdr_t *mh = (dns_hdr_t *) mb;
            mh->id = htons(c.query_id);
            mh->flags = htons(DNS_QR | DNS_AA);
            mo = 12;
            int qn = name_to_wire(zname, mb + mo, (int) sizeof(mb) - mo);
            if (qn > 0) {
                mo += qn;
                put16(mb, mo, DNS_TYPE_IXFR);
                mo += 2;
                put16(mb, mo, DNS_CLASS_IN);
                mo += 2;
                mh->qdcount = htons(1);
            }
            mh->ancount = htons(1);
            if (soa_len > 0)
                mo = append_rr(mb, mo, sizeof(mb), zname, DNS_TYPE_SOA, DNS_CLASS_IN,
                               t_zone->soa_minimum, soa_rd, (uint16_t) soa_len);
            mo = tsig_axfr_first(mb, mo, sizeof(mb), c.query_id, ixfr_mac, &ixfr_mac_len);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
            /* One difference sequence per journal entry. */
            for (int ei = 0; ei < ne; ei++) {
                char *e = entries[ei];
                if (!e)
                    continue;
                uint32_t fs = 0, ts = 0;
                char op = 'A';
                char ename[256] = "";
                char eval[256] = "";
                sscanf(e, "%u|%u|%c|%255[^|]|%255[^\n]", &fs, &ts, &op, ename, eval);
                uint16_t rtype = 0;
                uint8_t rd[16];
                uint16_t rdlen = 0;
                struct in_addr a4;
                struct in6_addr a6;
                if (inet_pton(AF_INET, eval, &a4) == 1) {
                    rtype = DNS_TYPE_A;
                    memcpy(rd, &a4, 4);
                    rdlen = 4;
                } else if (inet_pton(AF_INET6, eval, &a6) == 1) {
                    rtype = DNS_TYPE_AAAA;
                    memcpy(rd, &a6, 16);
                    rdlen = 16;
                } else {
                    free(e);
                    continue;
                }
                uint8_t soa_from[512];
                uint8_t soa_to[512];
                int from_len = build_soa_rdata_serial(soa_from, sizeof(soa_from), fs);
                int to_len = build_soa_rdata_serial(soa_to, sizeof(soa_to), ts);
                /* SOA(from): begins this step's deletion section. */
                if (from_len > 0)
                    axfr_emit_one(c.fd, c.ssl, c.query_id, zname, DNS_TYPE_SOA, t_zone->soa_minimum,
                                  soa_from, (uint16_t) from_len, ixfr_mac, &ixfr_mac_len);
                if (op == 'D')
                    axfr_emit_one(c.fd, c.ssl, c.query_id, ename, rtype, DEFAULT_TTL, rd, rdlen,
                                  ixfr_mac, &ixfr_mac_len);
                /* SOA(to): begins this step's addition section. */
                if (to_len > 0)
                    axfr_emit_one(c.fd, c.ssl, c.query_id, zname, DNS_TYPE_SOA, t_zone->soa_minimum,
                                  soa_to, (uint16_t) to_len, ixfr_mac, &ixfr_mac_len);
                if (op == 'A')
                    axfr_emit_one(c.fd, c.ssl, c.query_id, ename, rtype, DEFAULT_TTL, rd, rdlen,
                                  ixfr_mac, &ixfr_mac_len);
                free(e);
            }
            /* Closing SOA(current) — final (signed) message. */
            compress_reset();
            memset(mb, 0, 12);
            mh = (dns_hdr_t *) mb;
            mh->id = htons(c.query_id);
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
            STAT_INC(g_stat_axfr);
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
        mh->id = htons(c.query_id);
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
    rh->id = htons(c.query_id);
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
        mh->id = htons(c.query_id);
        mh->flags = htons(DNS_QR | DNS_AA);
        mh->ancount = htons(1);
        int mo = 12;
        mo = append_rr(mb, mo, sizeof(mb), r->name, r->type, DNS_CLASS_IN, r->ttl, rd, rdlen);
        tsig_axfr_mid(mb, mo, axfr_mac, &axfr_mac_len);
        tcp_send_msg(c.fd, c.ssl, mb, mo);
    }

    /* Send all runtime records (zone:<zone>:* + ddns:<zone>:A/AAAA) — the
     * provisioning / DDNS / discovery data that the static_zone[] loop above
     * does not cover (CLAUDE-discovery.md Gap 1). */
    axfr_send_runtime(c.fd, c.ssl, c.query_id, zname, axfr_mac, &axfr_mac_len);

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
            mh->id = htons(c.query_id);
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
            mh->id = htons(c.query_id);
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
        mh->id = htons(c.query_id);
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
 * DNS NOTIFY sender (RFC 1996) — TSIG-signed, retried in the background
 *
 * A zone change enqueues one job per (zone, target). A dedicated worker thread
 * (re)transmits each NOTIFY — TSIG-signed when config:tsig_secret_b64 is set, so
 * the secondary can authenticate the sender (RFC 1996 §3.6 + RFC 8945) — and
 * retries with exponential backoff until the secondary's NOTIFY response is seen
 * (matching id, QR set, opcode NOTIFY) or NOTIFY_MAX_TRIES is reached. Retrying
 * in the background means a slow/down secondary never blocks the request handler
 * that triggered the change. Re-arming an already-pending (zone,target) collapses
 * rapid changes into one in-flight NOTIFY (RFC 1996 §3.5).
 * ======================================================================= */
#define NOTIFY_MAX_TRIES 5
#define NOTIFY_BASE_RETRY_S 2
#define NOTIFY_MAX_RETRY_S 16
#define NOTIFY_QUEUE_MAX 4096

typedef struct notify_job {
    char zone[256];
    struct sockaddr_in dst;
    uint16_t id;
    int tries;
    time_t next_at; /* earliest next (re)send; 0 = send on the next worker pass */
    int fd;         /* UDP socket connect()ed to dst, polled for the ACK */
    struct notify_job *next;
} notify_job_t;

static notify_job_t *g_notify_jobs = NULL;
static pthread_mutex_t g_notify_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_notify_cond = PTHREAD_COND_INITIALIZER;

/* Build a (optionally TSIG-signed) NOTIFY request for `zone`. Returns length or
 * -1. The TSIG RR, when a key is configured, also bumps the header arcount. */
static int notify_build_packet(const char *zone, uint16_t id, uint8_t *pkt, int cap) {
    if (cap < 12)
        return -1;
    memset(pkt, 0, 12);
    dns_hdr_t *h = (dns_hdr_t *) pkt;
    h->id = htons(id);
    h->flags = htons(DNS_OPCODE_NOTIFY | DNS_AA); /* request: QR=0, AA per §3.7 */
    h->qdcount = htons(1);
    int off = 12;
    int n = name_to_wire(zone, pkt + off, cap - off);
    if (n <= 0 || off + n + 4 > cap)
        return -1;
    off += n;
    put16(pkt, off, DNS_TYPE_SOA);
    off += 2;
    put16(pkt, off, DNS_CLASS_IN);
    off += 2;
    uint8_t mac[64];
    int maclen = 0;
    off = xfr_tsig_sign_query(pkt, off, cap, id, mac, &maclen); /* no-op without a key */
    return off;
}

/* Has `fd` received this job's NOTIFY response? Drains up to a few datagrams
 * (the socket is connect()ed to the target, so only its replies arrive). */
static int notify_got_ack(int fd, uint16_t id) {
    uint8_t rsp[512];
    for (int i = 0; i < 8; i++) {
        ssize_t r = recv(fd, rsp, sizeof(rsp), MSG_DONTWAIT);
        if (r < 12)
            break;
        const dns_hdr_t *rh = (const dns_hdr_t *) rsp;
        uint16_t fl = ntohs(rh->flags);
        if (ntohs(rh->id) == id && (fl & DNS_QR) && (fl & DNS_OPCODE_MASK) == DNS_OPCODE_NOTIFY)
            return 1;
    }
    return 0;
}

static void *notify_thread(void *arg) {
    (void) arg;
    pthread_mutex_lock(&g_notify_mutex);
    for (;;) {
        while (!g_notify_jobs)
            pthread_cond_wait(&g_notify_cond, &g_notify_mutex);
        time_t now = time(NULL);
        notify_job_t **pp = &g_notify_jobs;
        while (*pp) {
            notify_job_t *j = *pp;
            if (notify_got_ack(j->fd, j->id)) {
                dns_log(LOG_NOTICE, "[NOTIFY] %s: acknowledged by %s\n", j->zone,
                        inet_ntoa(j->dst.sin_addr));
                *pp = j->next;
                close(j->fd);
                free(j);
                continue;
            }
            if (now >= j->next_at) {
                if (j->tries >= NOTIFY_MAX_TRIES) {
                    dns_log(LOG_WARNING,
                            "[NOTIFY] %s: no response from %s after %d tries — giving up\n",
                            j->zone, inet_ntoa(j->dst.sin_addr), j->tries);
                    *pp = j->next;
                    close(j->fd);
                    free(j);
                    continue;
                }
                uint8_t pkt[512];
                int len = notify_build_packet(j->zone, j->id, pkt, sizeof(pkt));
                if (len > 0 && send(j->fd, pkt, (size_t) len, 0) == len) {
                    int backoff = NOTIFY_BASE_RETRY_S << j->tries;
                    if (backoff > NOTIFY_MAX_RETRY_S)
                        backoff = NOTIFY_MAX_RETRY_S;
                    j->tries++;
                    j->next_at = now + backoff;
                    dns_log(LOG_NOTICE, "[NOTIFY] %s sent to %s (try %d, retry in %ds)\n", j->zone,
                            inet_ntoa(j->dst.sin_addr), j->tries, backoff);
                } else {
                    j->next_at = now + NOTIFY_BASE_RETRY_S; /* transient send error — retry soon */
                }
            }
            pp = &j->next;
        }
        if (!g_notify_jobs)
            continue; /* all acked/exhausted → back to the idle wait */
        /* Wake at the soonest retry, capped at 1s so acks are noticed promptly. */
        time_t soonest = 0;
        for (notify_job_t *j = g_notify_jobs; j; j = j->next)
            if (soonest == 0 || j->next_at < soonest)
                soonest = j->next_at;
        now = time(NULL);
        long wait_s = (long) (soonest - now);
        if (wait_s < 1)
            wait_s = 1;
        if (wait_s > 1)
            wait_s = 1;
        struct timespec ts = {.tv_sec = now + wait_s, .tv_nsec = 0};
        pthread_cond_timedwait(&g_notify_cond, &g_notify_mutex, &ts);
    }
    pthread_mutex_unlock(&g_notify_mutex); /* unreachable */
    return NULL;
}

/* Enqueue (or re-arm) a NOTIFY for `zone` to one target. */
static void notify_enqueue(const char *zone, const struct sockaddr_in *dst) {
    pthread_mutex_lock(&g_notify_mutex);
    int count = 0;
    for (notify_job_t *j = g_notify_jobs; j; j = j->next) {
        count++;
        if (strcasecmp(j->zone, zone) == 0 && j->dst.sin_addr.s_addr == dst->sin_addr.s_addr &&
            j->dst.sin_port == dst->sin_port) {
            j->tries = 0; /* re-arm: the zone changed again — notify afresh (§3.5) */
            j->next_at = 0;
            pthread_cond_signal(&g_notify_cond);
            pthread_mutex_unlock(&g_notify_mutex);
            return;
        }
    }
    if (count >= NOTIFY_QUEUE_MAX) {
        pthread_mutex_unlock(&g_notify_mutex);
        dns_log(LOG_WARNING, "[NOTIFY] queue full (%d) — dropping %s\n", count, zone);
        return;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0 && connect(fd, (const struct sockaddr *) dst, sizeof(*dst)) != 0) {
        close(fd);
        fd = -1;
    }
    notify_job_t *j = (fd >= 0) ? calloc(1, sizeof(*j)) : NULL;
    if (!j) {
        if (fd >= 0)
            close(fd);
        pthread_mutex_unlock(&g_notify_mutex);
        return;
    }
    safe_strcpy(j->zone, zone, sizeof(j->zone));
    j->dst = *dst;
    j->id = csprng_u16();
    j->tries = 0;
    j->next_at = 0; /* send on the next worker pass (immediately) */
    j->fd = fd;
    j->next = g_notify_jobs;
    g_notify_jobs = j;
    pthread_cond_signal(&g_notify_cond);
    pthread_mutex_unlock(&g_notify_mutex);
}

/* Queue a NOTIFY for one zone to a comma-separated "ip[:port]" target list. */
static void notify_zone(const char *zname, const char *targets_csv) {
    if (!zname[0] || !targets_csv[0])
        return;
    char targets[1024];
    safe_strcpy(targets, targets_csv, sizeof(targets));
    char *sp23 = NULL;
    for (char *tok = strtok_r(targets, ",", &sp23); tok; tok = strtok_r(NULL, ",", &sp23)) {
        while (*tok == ' ')
            tok++;
        if (!*tok)
            continue;
        int port = 53;
        char *col = strchr(tok, ':');
        if (col) {
            *col = 0;
            port = atoi(col + 1);
        }
        struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons((uint16_t) port)};
        if (inet_pton(AF_INET, tok, &dst.sin_addr) != 1)
            continue;
        notify_enqueue(zname, &dst);
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

/* NOTIFY a single zone's secondaries by name (look up its configured targets). */
static void notify_one_zone(const char *zname) {
    char targets[1024] = "";
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count; i++)
        if (strcasecmp(g_zones[i].name, zname) == 0) {
            safe_strcpy(targets, g_zones[i].notify_targets, sizeof(targets));
            break;
        }
    pthread_mutex_unlock(&g_zones_mutex);
    if (!targets[0] && strcasecmp(zname, g_zone_name) == 0)
        safe_strcpy(targets, g_notify_targets, sizeof(targets)); /* legacy single-zone */
    if (targets[0])
        notify_zone(zname, targets);
}

/* ==========================================================================
 * DDNS lease-expiry sweeper (CLAUDE-discovery.md Gap 2)
 *
 * A ddns:<zone>:<TYPE>:<name> lease expiring in Valkey is a *silent* deletion:
 * the add path bumped the serial + journalled when the lease was created, but
 * the TTL-driven removal fires no event, so a secondary keeps serving the dead
 * name until an unrelated change advances the serial. This thread (primary
 * only) closes that hole. Each tick it lists the live ddns:* keys and diffs
 * them against the previous tick's snapshot; every lease that vanished is
 * replayed as a real deletion — serial_bump + ixfr_journal_append('D') on the
 * owning zone — and each affected zone gets one batched NOTIFY.
 *
 * Self-contained: it works off the actual keyspace, so leases written by any
 * front-end (RFC 2136 here, REST /update in apid, auto-PTR) are all covered
 * without an explicit index. An explicitly-deleted lease (which already
 * journalled its own 'D') may be replayed once more as an idempotent delete —
 * harmless: a secondary deleting an already-absent record is a no-op, and the
 * serial chain stays contiguous. Discovery leases expire rather than being
 * deleted, so that path carries no redundancy.
 * ======================================================================= */
typedef struct {
    char *key; /* full Valkey key, e.g. "ddns:dyn.example:A:host.dyn.example" */
    char *val; /* last-seen value (the journal 'D' needs it) */
} ddns_lease_t;

#define DDNS_SWEEP_MAX 100000 /* defensive cap on tracked leases per tick */

static int ddns_key_cmp(const void *a, const void *b) {
    const ddns_lease_t *la = a;
    const ddns_lease_t *lb = b;
    return strcmp(la->key, lb->key);
}

/* Parse "ddns:<zone>:<type>:<name>" into its parts (zone/type/name copied out).
 * Returns 0 on success, -1 if the key is malformed. <name> may contain dots but
 * never a colon, so the split is unambiguous. */
static int ddns_key_split(const char *key, char *zone, size_t zcap, char *type, size_t tcap,
                          char *name, size_t ncap) {
    if (strncmp(key, "ddns:", 5) != 0)
        return -1;
    const char *z = key + 5;
    const char *c1 = strchr(z, ':');
    if (!c1)
        return -1;
    const char *t = c1 + 1;
    const char *c2 = strchr(t, ':');
    if (!c2)
        return -1;
    const char *nm = c2 + 1;
    if ((size_t) (c1 - z) >= zcap || (size_t) (c2 - t) >= tcap || strlen(nm) >= ncap)
        return -1;
    memcpy(zone, z, (size_t) (c1 - z));
    zone[c1 - z] = 0;
    memcpy(type, t, (size_t) (c2 - t));
    type[c2 - t] = 0;
    safe_strcpy(name, nm, ncap);
    return 0;
}

/* Replay one vanished lease as a replicated deletion on its owning zone, and
 * return the zone name (via zname_out) so the caller can batch a NOTIFY. */
static void ddns_replay_expiry(const ddns_lease_t *l, char *zname_out, size_t zcap) {
    zname_out[0] = 0;
    char zone[256], type[16], name[256];
    if (ddns_key_split(l->key, zone, sizeof(zone), type, sizeof(type), name, sizeof(name)) != 0)
        return;
    /* Find the owning zone; snapshot its current serial, then bump unlocked. */
    zone_entry_t *z = NULL;
    pthread_mutex_lock(&g_zones_mutex);
    for (int i = 0; i < g_zone_count; i++)
        if (g_zones[i].active && strcasecmp(g_zones[i].name, zone) == 0) {
            z = &g_zones[i];
            break;
        }
    pthread_mutex_unlock(&g_zones_mutex);
    if (!z)
        return; /* zone gone (deprovisioned) — nothing to replicate */
    uint32_t prev = z->soa_serial;
    uint32_t next = serial_bump(z);
    ixfr_journal_append(z->name, prev, next, 'D', name, l->val ? l->val : "");
    safe_strcpy(zname_out, z->name, zcap);
    dns_log(LOG_NOTICE, "[DDNS] lease expired: %s %s %s — serial %u->%u\n", zone, type, name, prev,
            next);
}

/* ==========================================================================
 * Load-balancing health checks (CLAUDE-loadbalance.md Gap 2)
 *
 * Background thread that TCP-probes the A/AAAA addresses behind the names in
 * config:lb_health_targets and publishes an up/down table the query path
 * consults (emit_addr_rrset). Local serving policy only — it filters emission
 * and never writes the zone, so it is safe on a public secondary (CLAUDE.md
 * Gap 7) and may differ per instance.
 * ======================================================================= */

/* Non-blocking TCP connect probe. 1 = connected within timeout, 0 = not. */
static int lb_tcp_probe(const char *ip, int port, int timeout_ms) {
    int af = strchr(ip, ':') ? AF_INET6 : AF_INET;
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t slen;
    if (af == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *) &ss;
        s->sin_family = AF_INET;
        s->sin_port = htons((uint16_t) port);
        if (inet_pton(AF_INET, ip, &s->sin_addr) != 1)
            return 0;
        slen = sizeof(*s);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *) &ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons((uint16_t) port);
        if (inet_pton(AF_INET6, ip, &s->sin6_addr) != 1)
            return 0;
        slen = sizeof(*s);
    }
    int fd = socket(af, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return 0;
    int up = 0;
    int r = connect(fd, (struct sockaddr *) &ss, slen);
    if (r == 0) {
        up = 1; /* connected immediately (loopback) */
    } else if (errno == EINPROGRESS) {
        struct pollfd p = {.fd = fd, .events = POLLOUT};
        if (poll(&p, 1, timeout_ms > 0 ? timeout_ms : 1000) > 0 && (p.revents & POLLOUT)) {
            int err = 0;
            socklen_t el = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0)
                up = 1;
        }
    }
    close(fd);
    return up;
}

/* Read `name`'s stored A+AAAA addresses (from its owning zone) into out[],
 * returning the count. Skips ddns:* leases — only zone:* RRsets are balanced. */
static int lb_addrs_for_name(const char *name, char out[][INET6_ADDRSTRLEN], int cap) {
    int n = 0;
    zone_entry_t *z = zone_for_qname(name);
    const char *zn = z ? z->name : g_zone_name;
    const char *types[2] = {"A", "AAAA"};
    for (int t = 0; t < 2 && n < cap; t++) {
        char key[800];
        snprintf(key, sizeof(key), "zone:%.255s:%s:%.255s", zn, types[t], name);
        char val[512];
        if (!vk_get(key, val, sizeof(val)) || !val[0])
            continue;
        char *pipe = strchr(val, '|');
        char *p = pipe ? pipe + 1 : val; /* skip the ttl| prefix */
        char *sp = NULL;
        for (char *ip = strtok_r(p, "|", &sp); ip && n < cap; ip = strtok_r(NULL, "|", &sp))
            safe_strcpy(out[n++], ip, INET6_ADDRSTRLEN);
    }
    return n;
}

/* One probe round: gather every address behind every configured target, probe
 * it, and swap in the fresh up/down table. Transitions are logged. */
static void lb_health_probe_round(void) {
    char targets[1024];
    safe_strcpy(targets, g_lb_health_targets, sizeof(targets));
    lb_health_entry_t *next = calloc(LB_HEALTH_MAX, sizeof(lb_health_entry_t));
    if (!next)
        return;
    int nn = 0;
    char *sp = NULL;
    for (char *tok = strtok_r(targets, ",", &sp); tok && nn < LB_HEALTH_MAX;
         tok = strtok_r(NULL, ",", &sp)) {
        while (*tok == ' ')
            tok++;
        if (!*tok)
            continue;
        int port = LB_HEALTH_DEFAULT_PORT;
        /* "name:port" — a colon is unambiguous here (DNS names carry none). */
        char *colon = strrchr(tok, ':');
        if (colon) {
            *colon = 0;
            port = atoi(colon + 1);
            if (port <= 0 || port > 65535)
                port = LB_HEALTH_DEFAULT_PORT;
        }
        char addrs[LB_MAX_ADDRS][INET6_ADDRSTRLEN];
        int na = lb_addrs_for_name(tok, addrs, LB_MAX_ADDRS);
        for (int a = 0; a < na && nn < LB_HEALTH_MAX; a++) {
            int dup = 0;
            for (int j = 0; j < nn; j++)
                if (strcmp(next[j].ip, addrs[a]) == 0) {
                    dup = 1;
                    break;
                }
            if (dup)
                continue;
            int up = lb_tcp_probe(addrs[a], port, g_lb_health_timeout_ms);
            safe_strcpy(next[nn].ip, addrs[a], sizeof(next[nn].ip));
            next[nn].up = up;
            nn++;
        }
    }
    /* Swap the table in, logging only the addresses whose state changed. */
    pthread_mutex_lock(&g_lb_health_mutex);
    for (int i = 0; i < nn; i++) {
        int prev = -1;
        for (int j = 0; j < g_lb_health_count; j++)
            if (strcmp(g_lb_health[j].ip, next[i].ip) == 0) {
                prev = g_lb_health[j].up;
                break;
            }
        if (prev != next[i].up)
            dns_log(LOG_NOTICE, "[LB] %s is %s\n", next[i].ip, next[i].up ? "UP" : "DOWN");
    }
    lb_health_entry_t *old = g_lb_health;
    g_lb_health = next;
    g_lb_health_count = nn;
    pthread_mutex_unlock(&g_lb_health_mutex);
    free(old);
}

static void *lb_health_thread(void *arg) {
    (void) arg;
    for (;;) {
        if (g_lb_health_enabled && g_lb_health_targets[0])
            lb_health_probe_round();
        int interval = g_lb_health_interval > 0 ? g_lb_health_interval : 10;
        sleep((unsigned) interval);
    }
    return NULL;
}

static void *ddns_sweeper_thread(void *arg) {
    (void) arg;
    ddns_lease_t *prev = NULL;
    int nprev = 0;
    for (;;) {
        int interval = g_ddns_sweep_secs > 0 ? g_ddns_sweep_secs : 30;
        sleep((unsigned) interval);
        if (g_ddns_sweep_secs <= 0 || g_zone_secondary)
            continue; /* disabled, or a secondary owns no leases to sweep */

        /* Build this tick's snapshot: every live ddns:* key + its value. A
         * Valkey error returns -1 (vs 0 for genuinely empty) — skip the tick and
         * keep the previous baseline rather than mistaking the blip for a mass
         * expiry that would replay bogus deletes. */
        char **keys = NULL;
        int nk = vk_list_keys_strict("ddns:*", &keys);
        if (nk < 0)
            continue;
        if (nk > DDNS_SWEEP_MAX) { /* implausible; don't trust this snapshot */
            for (int i = 0; i < nk; i++)
                free(keys[i]);
            free(keys);
            continue;
        }
        ddns_lease_t *cur = NULL;
        int ncur = 0;
        if (nk > 0)
            cur = calloc((size_t) nk, sizeof(ddns_lease_t));
        if (nk > 0 && !cur) { /* OOM — skip the tick, keep the baseline */
            for (int i = 0; i < nk; i++)
                free(keys[i]);
            free(keys);
            continue;
        }
        for (int i = 0; i < nk; i++) {
            char val[768] = "";
            vk_get(keys[i], val, sizeof(val)); /* best-effort; existence is what matters */
            cur[ncur].key = strdup(keys[i]);
            cur[ncur].val = strdup(val);
            if (cur[ncur].key && cur[ncur].val)
                ncur++;
        }
        if (cur)
            qsort(cur, (size_t) ncur, sizeof(ddns_lease_t), ddns_key_cmp);
        for (int i = 0; i < nk; i++)
            free(keys[i]);
        free(keys);

        /* A lease present last tick but absent now has expired. Batch one NOTIFY
         * per affected zone (dedup by name). */
        char notified[MAX_ZONES][256];
        int nnotified = 0;
        for (int i = 0; i < nprev; i++) {
            ddns_lease_t want = {.key = prev[i].key, .val = NULL};
            if (cur && bsearch(&want, cur, (size_t) ncur, sizeof(ddns_lease_t), ddns_key_cmp))
                continue; /* still present */
            char zn[256];
            ddns_replay_expiry(&prev[i], zn, sizeof(zn));
            if (!zn[0])
                continue;
            int seen = 0;
            for (int j = 0; j < nnotified; j++)
                if (strcasecmp(notified[j], zn) == 0) {
                    seen = 1;
                    break;
                }
            if (!seen && nnotified < MAX_ZONES)
                safe_strcpy(notified[nnotified++], zn, sizeof(notified[0]));
        }
        for (int j = 0; j < nnotified; j++)
            notify_one_zone(notified[j]);

        /* Adopt this tick's snapshot as the baseline for the next. */
        for (int i = 0; i < nprev; i++) {
            free(prev[i].key);
            free(prev[i].val);
        }
        free(prev);
        prev = cur;
        nprev = ncur;
    }
    return NULL;
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
        /* Accept and acknowledge NOTIFY. On a secondary, a NOTIFY from the
         * configured master triggers an immediate refresh (RFC 1996 §4.7,
         * hidden-master plan Gap 5). Verify the source (RFC 1996 §3.10) so a
         * stranger can't make us re-pull on demand; the pull itself is TLS-
         * authenticated regardless. */
        dns_hdr_t *rh = (dns_hdr_t *) resp;
        rh->id = h->id;
        rh->flags = htons(DNS_QR | DNS_OPCODE_NOTIFY | DNS_RCODE_NOERROR);
        rh->qdcount = rh->ancount = rh->nscount = rh->arcount = 0;
        if (g_zone_secondary && g_primary_host[0] && cip) {
            int from_primary = 0;
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            if (getaddrinfo(g_primary_host, NULL, &hints, &res) == 0) {
                for (struct addrinfo *p = res; p; p = p->ai_next)
                    if (((struct sockaddr_in *) p->ai_addr)->sin_addr.s_addr == cip->s_addr) {
                        from_primary = 1;
                        break;
                    }
                freeaddrinfo(res);
            }
            if (from_primary) {
                dns_log(LOG_NOTICE, "[NOTIFY] from master — triggering refresh\n");
                xfr_refresh_kick();
            } else {
                dns_log(LOG_NOTICE, "[NOTIFY] ignored (source is not the configured master)\n");
            }
        } else {
            dns_log(LOG_NOTICE, "[NOTIFY] Received NOTIFY\n");
        }
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
            uint8_t _rc = get16(resp, 2) & 0xF;
            int _an = rlen >= 8 ? get16(resp, 6) : 0;
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
             dd = g_stat_ddns, si = g_stat_signed, fw = g_stat_forwarded, ff = g_stat_forward_fail,
             lbd = g_stat_lb_down_skips;
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
             "# HELP dns_forward_total Out-of-zone queries forwarded by outcome\n"
             "# TYPE dns_forward_total counter\n"
             "dns_forward_total{result=\"ok\"}   %llu\n"
             "dns_forward_total{result=\"fail\"} %llu\n"
             "# HELP dns_zone_serial Current SOA serial\n"
             "# TYPE dns_zone_serial gauge\n"
             "dns_zone_serial %u\n"
             "# HELP dns_rrl_enabled Whether RRL is active\n"
             "# TYPE dns_rrl_enabled gauge\n"
             "dns_rrl_enabled %d\n"
             "# HELP dns_forward_enabled Whether out-of-zone forwarding is active\n"
             "# TYPE dns_forward_enabled gauge\n"
             "dns_forward_enabled %d\n"
             "# HELP dns_lb_down_skips_total A/AAAA addresses suppressed as unhealthy\n"
             "# TYPE dns_lb_down_skips_total counter\n"
             "dns_lb_down_skips_total %llu\n"
             "# HELP dns_lb_health_enabled Whether load-balancing health checks are active\n"
             "# TYPE dns_lb_health_enabled gauge\n"
             "dns_lb_health_enabled %d\n",
             (unsigned long long) sq, (unsigned long long) sn, (unsigned long long) snx,
             (unsigned long long) sr, (unsigned long long) ss, (unsigned long long) rd,
             (unsigned long long) rt, (unsigned long long) ax, (unsigned long long) dd,
             (unsigned long long) si, (unsigned long long) fw, (unsigned long long) ff,
             g_soa_serial, g_rrl_enabled, (g_forward_enabled && g_forward_allow[0]) ? 1 : 0,
             (unsigned long long) lbd, g_lb_health_enabled ? 1 : 0);
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

/* ── SO_REUSEPORT UDP worker model (config:udp_workers > 1) ──────────────────
 * Each worker owns its own IPv4 UDP socket bound to the DNS port with
 * SO_REUSEPORT (the kernel hashes datagrams across them) and its own Valkey
 * connection (t_vk_conn → lock-free vk_get). This breaks the single-threaded,
 * one-packet-in-flight serialization that caps the legacy select() loop:
 * workers' blocking Valkey round-trips now overlap. dns_process() is already
 * thread-safe (it runs in DoT worker threads and uses __thread request state).
 * IPv6/TCP/DoT/metrics stay on the main select loop. */
typedef struct {
    int sock;
    int id;
} udp_worker_t;

static int make_reuseport_udp_socket(int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        close(s);
        return -1;
    }
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons(port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

/* ── UDP out-of-zone forwarding off the listener thread (CLAUDE-forwarder.md) ──
 * A forwardable UDP query is handed to a short-lived detached worker so the
 * upstream round-trip (up to forward_timeout_ms) never blocks the single-thread
 * select() loop (nor stalls a SO_REUSEPORT worker's recv queue). The worker
 * replies with sendto() on the shared listener fd — concurrent sendto on a UDP
 * socket is safe. The in-flight count is capped so a dead upstream cannot
 * accumulate threads. */
typedef struct {
    int sock;                    /* listener fd to reply on */
    struct sockaddr_storage cli; /* client to reply to (v4 or v6) */
    socklen_t clen;
    struct in_addr cip; /* client v4 addr for RRL keying (0 = non-mapped v6) */
    int plen;
    uint8_t pkt[BUF_SIZE];
} fwd_work_t;

static void *fwd_worker_thread(void *arg) {
    fwd_work_t *w = (fwd_work_t *) arg;
    uint8_t resp[BUF_SIZE];
    char cipstr[INET6_ADDRSTRLEN] = "?";
    char qn[256] = "?";
    uint16_t qt = 0;
    int a = name_from_wire(w->pkt, w->plen, 12, qn, sizeof(qn));
    if (a >= 0 && a + 1 < w->plen)
        qt = get16(w->pkt, a);
    if (w->cli.ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *) &w->cli)->sin6_addr, cipstr, sizeof(cipstr));
    else
        inet_ntop(AF_INET, &((struct sockaddr_in *) &w->cli)->sin_addr, cipstr, sizeof(cipstr));
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rlen = forward_query(w->pkt, w->plen, resp, sizeof(resp), 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long rtt = (long) ((t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000L);
    if (rlen > 0) {
        /* RRL covers forwarded responses too (Gap 3). */
        int rrl_action = g_rrl_enabled ? rrl_check(&w->cip, qn) : 0;
        if (rrl_action == 1) {
            dns_log(LOG_DEBUG, "[RRL] DROP fwd %s %s\n", type2str(qt), qn);
            STAT_INC(g_stat_rrl_drop);
        } else {
            if (rrl_action == 2) {
                /* Truncate to header+question so the client retries over TCP. */
                dns_log(LOG_DEBUG, "[RRL] TC fwd %s %s\n", type2str(qt), qn);
                STAT_INC(g_stat_rrl_tc);
                dns_hdr_t *rh = (dns_hdr_t *) resp;
                rh->flags = htons(ntohs(rh->flags) | DNS_TC);
                rh->ancount = rh->nscount = rh->arcount = 0;
                int qa = name_from_wire(resp, rlen, 12, qn, sizeof(qn));
                rlen = (qa > 0) ? 12 + (qa - 12) + 4 : 12;
            }
            sendto(w->sock, resp, (size_t) rlen, 0, (struct sockaddr *) &w->cli, w->clen);
            uint8_t rc = rlen >= 4 ? (get16(resp, 2) & 0xF) : 2;
            int an = rlen >= 8 ? get16(resp, 6) : 0;
            qlog_write(cipstr, qn, qt, rc, an, rtt, "fwd");
        }
    }
    pthread_mutex_lock(&g_fwd_mutex);
    g_fwd_inflight--;
    pthread_mutex_unlock(&g_fwd_mutex);
    free(w);
    return NULL;
}

/* Reply SERVFAIL directly on the listener fd (used when we can't dispatch). */
static void fwd_servfail_now(int sock, const uint8_t *pkt, int plen, const struct sockaddr *cli,
                             socklen_t clen) {
    uint8_t sf[512];
    int n = fwd_servfail(pkt, plen, sf, sizeof(sf));
    if (n > 0)
        sendto(sock, sf, (size_t) n, 0, cli, clen);
    STAT_INC(g_stat_forward_fail);
}

/* If this raw UDP query should be forwarded, dispatch it to a worker thread (or
 * answer SERVFAIL when over the in-flight cap / on failure) and return 1. Return
 * 0 when the caller should keep handling the query normally. */
static int forward_dispatch_udp(int sock, const uint8_t *pkt, int plen, const struct sockaddr *cli,
                                socklen_t clen, const struct in_addr *cip) {
    if (!forward_should(pkt, plen, cip))
        return 0;
    if (plen > (int) BUF_SIZE)
        return 0; /* shouldn't happen; let the normal path REFUSE it */
    pthread_mutex_lock(&g_fwd_mutex);
    int over = (g_fwd_inflight >= FWD_MAX_INFLIGHT);
    if (!over)
        g_fwd_inflight++;
    pthread_mutex_unlock(&g_fwd_mutex);
    if (over) {
        dns_log(LOG_WARNING, "[FORWARD] in-flight cap (%d) reached — SERVFAIL\n", FWD_MAX_INFLIGHT);
        fwd_servfail_now(sock, pkt, plen, cli, clen);
        return 1;
    }
    fwd_work_t *w = malloc(sizeof(*w));
    if (!w) {
        pthread_mutex_lock(&g_fwd_mutex);
        g_fwd_inflight--;
        pthread_mutex_unlock(&g_fwd_mutex);
        fwd_servfail_now(sock, pkt, plen, cli, clen);
        return 1;
    }
    w->sock = sock;
    memcpy(&w->cli, cli, clen);
    w->clen = clen;
    w->cip = *cip;
    w->plen = plen;
    memcpy(w->pkt, pkt, (size_t) plen);
    pthread_t tid;
    if (pthread_create(&tid, NULL, fwd_worker_thread, w) != 0) {
        free(w);
        pthread_mutex_lock(&g_fwd_mutex);
        g_fwd_inflight--;
        pthread_mutex_unlock(&g_fwd_mutex);
        fwd_servfail_now(sock, pkt, plen, cli, clen);
        return 1;
    }
    pthread_detach(tid);
    return 1;
}

/* Parse, log, resolve one IPv4 UDP query. Returns response length (0 = drop).
 * Shared by the per-packet and the recvmmsg/sendmmsg worker loops. */
static int udp_serve_one(const uint8_t *pkt, int nn, const struct sockaddr_in *cli, uint8_t *resp,
                         int resp_cap) {
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli->sin_addr, cip, sizeof(cip));
    char qn[256] = "?";
    uint16_t qt = 0;
    int a = name_from_wire(pkt, nn, 12, qn, sizeof(qn));
    if (a >= 0 && a + 1 < nn)
        qt = get16(pkt, a);
    dns_log(LOG_DEBUG, "[DNS ] %s  %s %s\n", cip, type2str(qt), qn);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rlen = dns_process(pkt, nn, resp, resp_cap, 0, &cli->sin_addr);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long rtt = (long) ((t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000L);
    if (rlen > 0) {
        uint8_t rc = rlen >= 4 ? (get16(resp, 2) & 0xF) : 2;
        int an = rlen >= 8 ? get16(resp, 6) : 0;
        qlog_write(cip, qn, qt, rc, an, rtt, "udp");
    }
    return rlen;
}

static void *udp_worker_thread(void *arg) {
    udp_worker_t *w = (udp_worker_t *) arg;
    /* This worker's private Valkey connection — vk_get() now runs lock-free. */
    resp_conn_t conn = {.fd = -1};
    t_vk_conn = &conn;

    int batch = g_udp_rx_batch;
    if (batch <= 1) {
        /* Per-packet path (default). */
        uint8_t pkt[BUF_SIZE], resp[BUF_SIZE];
        for (;;) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            ssize_t nn = recvfrom(w->sock, pkt, sizeof(pkt), 0, (struct sockaddr *) &cli, &clen);
            if (nn <= 0)
                continue;
            /* Out-of-zone forward → off-thread, so a slow upstream cannot stall
             * this worker's recv queue. */
            if (forward_dispatch_udp(w->sock, pkt, (int) nn, (struct sockaddr *) &cli, clen,
                                     &cli.sin_addr))
                continue;
            int rlen = udp_serve_one(pkt, (int) nn, &cli, resp, sizeof(resp));
            if (rlen > 0)
                sendto(w->sock, resp, rlen, 0, (struct sockaddr *) &cli, clen);
        }
    }

    /* Batched path: recvmmsg up to `batch` datagrams per syscall, reply with one
     * sendmmsg. Buffers are heap-allocated once per worker. */
    if (batch > UDP_BATCH_MAX)
        batch = UDP_BATCH_MAX;
    /* typedef avoids a `uint8_t (*p)[BUF_SIZE]` declarator, which different
     * clang-format versions render with/without a space before `(`. */
    typedef uint8_t batchbuf_t[BUF_SIZE];
    batchbuf_t *rxbuf = malloc((size_t) batch * sizeof(batchbuf_t));
    batchbuf_t *txbuf = malloc((size_t) batch * sizeof(batchbuf_t));
    struct sockaddr_in *addrs = malloc((size_t) batch * sizeof(*addrs));
    struct mmsghdr *rxmsgs = malloc((size_t) batch * sizeof(*rxmsgs));
    struct iovec *rxiov = malloc((size_t) batch * sizeof(*rxiov));
    struct mmsghdr *txmsgs = malloc((size_t) batch * sizeof(*txmsgs));
    struct iovec *txiov = malloc((size_t) batch * sizeof(*txiov));
    if (!rxbuf || !txbuf || !addrs || !rxmsgs || !rxiov || !txmsgs || !txiov) {
        dns_log(LOG_ERR, "[UDP ] worker %d: batch alloc failed — exiting worker\n", w->id);
        free(rxbuf);
        free(txbuf);
        free(addrs);
        free(rxmsgs);
        free(rxiov);
        free(txmsgs);
        free(txiov);
        return NULL;
    }
    for (;;) {
        for (int i = 0; i < batch; i++) {
            rxiov[i].iov_base = rxbuf[i];
            rxiov[i].iov_len = BUF_SIZE;
            memset(&rxmsgs[i].msg_hdr, 0, sizeof(rxmsgs[i].msg_hdr));
            rxmsgs[i].msg_hdr.msg_name = &addrs[i];
            rxmsgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
            rxmsgs[i].msg_hdr.msg_iov = &rxiov[i];
            rxmsgs[i].msg_hdr.msg_iovlen = 1;
        }
        int n = recvmmsg(w->sock, rxmsgs, batch, MSG_WAITFORONE, NULL);
        if (n <= 0)
            continue;
        int nt = 0;
        for (int i = 0; i < n; i++) {
            int nn = (int) rxmsgs[i].msg_len;
            if (nn <= 0)
                continue;
            /* Forwardable queries are dispatched off-thread (they reply
             * themselves) and excluded from this sendmmsg batch. */
            if (forward_dispatch_udp(w->sock, rxbuf[i], nn, (struct sockaddr *) &addrs[i],
                                     sizeof(addrs[i]), &addrs[i].sin_addr))
                continue;
            int rlen = udp_serve_one(rxbuf[i], nn, &addrs[i], txbuf[nt], BUF_SIZE);
            if (rlen <= 0)
                continue;
            txiov[nt].iov_base = txbuf[nt];
            txiov[nt].iov_len = (size_t) rlen;
            memset(&txmsgs[nt].msg_hdr, 0, sizeof(txmsgs[nt].msg_hdr));
            txmsgs[nt].msg_hdr.msg_name = &addrs[i];
            txmsgs[nt].msg_hdr.msg_namelen = sizeof(addrs[i]);
            txmsgs[nt].msg_hdr.msg_iov = &txiov[nt];
            txmsgs[nt].msg_hdr.msg_iovlen = 1;
            nt++;
        }
        /* sendmmsg may send fewer than nt; loop until all are flushed. */
        int sent = 0;
        while (sent < nt) {
            int s = sendmmsg(w->sock, txmsgs + sent, nt - sent, 0);
            if (s <= 0)
                break;
            sent += s;
        }
    }
    return NULL;
}

/* ADR-003 schema-version gate. dnsd is the SEEDER: on an absent key it writes the
 * compiled version so the rest of the fleet has a contract to check against. A
 * major mismatch (or unparseable value) is fatal — the inter-daemon bus format is
 * incompatible; a minor mismatch only warns (additive change). By the time this
 * runs dnsd has already hard-required Valkey at boot, so ABSENT means "not seeded
 * yet", not "Valkey down". Returns 0 to proceed, -1 to refuse. */
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
            vk_set("schema:version", SCHEMA_VERSION_STR, 0);
            dns_log(LOG_INFO, "[Schema] seeded schema:version=%s\n", SCHEMA_VERSION_STR);
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

    /* Phase 2a: schema-version contract (ADR-003) — seed it (dnsd is the seeder)
     * or refuse to start on an incompatible major. */
    if (schema_gate() != 0)
        return 1;

    /* In-process record cache: allocate once here if enabled at boot. */
    if (g_rcache_ttl > 0)
        rcache_init(g_rcache_size);

    /* Phase 2b: Populate multi-zone table (primary seed + zone_table:*) */
    seed_primary_zone();
    zones_load_from_valkey();
    dns_log(LOG_INFO, "[Zones] %d zone(s) loaded\n", g_zone_count);

    /* Phase 3: DNSSEC (both algorithms) */
    dnssec_init();

    /* Phase 3b: Provision catalog-zone (RFC 9432) members before serving, so a
     * member zone is signed and answerable from the first query. */
    catalog_scan_all();

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

    /* NOTIFY sender: background worker that TSIG-signs + retries master→secondary
     * NOTIFYs (RFC 1996 §3.6). Idle until a zone change enqueues a job. */
    {
        pthread_t ntid;
        if (pthread_create(&ntid, NULL, notify_thread, NULL) == 0)
            pthread_detach(ntid);
        else
            dns_log(LOG_ERR, "[NOTIFY] Failed to start NOTIFY sender thread\n");
    }

    /* Primary: DDNS lease-expiry sweeper — replays silent ddns:* expiries as
     * replicated deletions so secondaries converge (CLAUDE-discovery.md Gap 2). */
    if (!g_zone_secondary) {
        pthread_t stid;
        if (pthread_create(&stid, NULL, ddns_sweeper_thread, NULL) == 0)
            pthread_detach(stid);
        else
            dns_log(LOG_ERR, "[DDNS] Failed to start lease-expiry sweeper\n");
    }

    /* Load-balancing health-check probe thread (CLAUDE-loadbalance.md Gap 2).
     * Idle (just sleeps) until config:lb_health_enabled is set. */
    {
        pthread_t htid;
        if (pthread_create(&htid, NULL, lb_health_thread, NULL) == 0)
            pthread_detach(htid);
        else
            dns_log(LOG_ERR, "[LB] Failed to start health-check thread\n");
    }

    /* Secondary: zone-maintenance thread — startup pull, then SOA refresh/retry
     * timers + NOTIFY-triggered re-pull (hidden-master plan Gap 6/5). Detached so
     * an unreachable master never blocks the server. */
    if (g_zone_secondary && g_primary_host[0]) {
        pthread_t xtid;
        if (pthread_create(&xtid, NULL, xfr_refresh_thread, NULL) == 0)
            pthread_detach(xtid);
        else
            dns_log(LOG_ERR, "[XFR] Failed to start transfer-client thread\n");
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
    /* IPv4 UDP: legacy single socket (workers<=1) handled by the select loop,
     * OR N SO_REUSEPORT sockets (workers>1) handled by worker threads. Bind here
     * — before the sandbox / privilege drop — so privileged ports still work;
     * the worker threads are spawned post-sandbox using these pre-bound fds. */
    int dns_sock = -1;
    int worker_socks[64];
    int n_worker_socks = 0;
    if (g_udp_workers <= 1) {
        dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dns_sock < 0) {
            perror("dns socket");
            return 1;
        }
        setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in sa = {.sin_family = AF_INET,
                                 .sin_port = htons(g_dns_port),
                                 .sin_addr.s_addr = INADDR_ANY};
        if (bind(dns_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("dns bind");
            return 1;
        }
    } else {
        for (int i = 0; i < g_udp_workers; i++) {
            int ws = make_reuseport_udp_socket(g_dns_port);
            if (ws < 0)
                break; /* keep however many bound; need at least one */
            worker_socks[n_worker_socks++] = ws;
        }
        if (n_worker_socks == 0) {
            perror("dns reuseport bind");
            return 1;
        }
        dns_log(LOG_INFO, "[UDP ] %d/%d SO_REUSEPORT worker sockets bound on :%d\n", n_worker_socks,
                g_udp_workers, g_dns_port);
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
    dns_log(LOG_INFO, "║  DoT client-cert (mTLS) required            %-20s       ║\n",
            (g_dot_require_client_cert && g_mtls_ca_pem[0]) ? "yes" : "no");
    dns_log(LOG_INFO, "║  Zone role                                  %-20s       ║\n",
            g_zone_secondary ? "secondary (read-only)" : "primary");
    if (g_zone_secondary && g_primary_host[0])
        dns_log(LOG_INFO, "║  Pull zones from master                     %s:%-5d%s║\n",
                g_primary_host, g_primary_port, g_primary_tls ? " (TLS)   " : "        ");
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
    dns_log(LOG_INFO, "║  Forwarding (out-of-zone)                   %s               ║\n",
            (g_forward_enabled && g_forward_allow[0]) ? "ENABLED " : "disabled");
    dns_log(LOG_INFO, "║  A/AAAA load-balancing                      %-20s       ║\n",
            g_lb_mode == LB_RR ? "round-robin" : (g_lb_mode == LB_RANDOM ? "random" : "none"));
    dns_log(LOG_INFO, "║  LB health checks                           %-20s       ║\n",
            g_lb_health_enabled ? "enabled" : "disabled");
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

    /* All privileged resources are now bound. Hand the sandbox to the shared
     * libsandbox: it resolves the unprivileged account (needs the host passwd
     * db), confines the filesystem view, irreversibly drops root, and installs
     * the seccomp filter — all before serving untrusted input (CLAUDE.md
     * principle #4). Config is read HERE, before the chroot, so a chroot that
     * hides Valkey cannot silently downgrade the seccomp mode. */
    sandbox_config_t sb;
    memset(&sb, 0, sizeof(sb));
    vk_get("config:chroot_dir", sb.chroot_dir, sizeof(sb.chroot_dir));
    sandbox_env_override(sb.chroot_dir, sizeof(sb.chroot_dir), "DNS_CHROOT");
    vk_get("config:isolation_mode", sb.isolation_mode, sizeof(sb.isolation_mode));
    sandbox_env_override(sb.isolation_mode, sizeof(sb.isolation_mode), "DNS_ISOLATION");
    vk_get("config:privdrop_user", sb.privdrop_user, sizeof(sb.privdrop_user));
    sandbox_env_override(sb.privdrop_user, sizeof(sb.privdrop_user), "DNS_USER");
    vk_get("config:privdrop_group", sb.privdrop_group, sizeof(sb.privdrop_group));
    sandbox_env_override(sb.privdrop_group, sizeof(sb.privdrop_group), "DNS_GROUP");
    vk_get("config:seccomp_mode", sb.seccomp_mode, sizeof(sb.seccomp_mode));
    sandbox_env_override(sb.seccomp_mode, sizeof(sb.seccomp_mode), "DNS_SECCOMP");
    sb.seccomp_default = SANDBOX_SECCOMP_ENFORCE; /* whitelist audit-validated for dnsd */
    sb.log = dns_log;
    sb.tag = "dnsd";
    sandbox_apply(&sb);

    /* Spawn IPv4 UDP worker threads (workers>1) on the pre-bound REUSEPORT
     * sockets. Post-sandbox is fine: dnsd already pthread_create()s DoT threads
     * and reconnects to Valkey after sandboxing, so the seccomp whitelist covers
     * clone/socket/connect/recvfrom/sendto. */
    if (g_udp_workers > 1) {
        int started = 0;
        for (int i = 0; i < n_worker_socks; i++) {
            udp_worker_t *w = malloc(sizeof(*w));
            if (!w)
                continue;
            w->sock = worker_socks[i];
            w->id = i;
            pthread_t wt;
            if (pthread_create(&wt, NULL, udp_worker_thread, w) == 0) {
                pthread_detach(wt);
                started++;
            } else {
                free(w);
            }
        }
        dns_log(LOG_NOTICE, "[UDP ] %d UDP worker threads serving IPv4 :%d\n", started, g_dns_port);
    }

    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        if (dns_sock >= 0)
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

        if (dns_sock >= 0 && FD_ISSET(dns_sock, &fds)) {
            uint8_t pkt[BUF_SIZE], resp[BUF_SIZE];
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            ssize_t nn = recvfrom(dns_sock, pkt, sizeof(pkt), 0, (struct sockaddr *) &cli, &clen);
            if (nn > 0 && forward_dispatch_udp(dns_sock, pkt, (int) nn, (struct sockaddr *) &cli,
                                               clen, &cli.sin_addr)) {
                /* forwarded off-thread; nothing more to do in the select loop */
            } else if (nn > 0) {
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
                    uint8_t _rc = rlen >= 4 ? (get16(resp, 2) & 0xF) : 2;
                    int _an = rlen >= 8 ? get16(resp, 6) : 0;
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
                /* Map IPv4-mapped addresses for cookie/logging/ACL. The forward
                 * ACL is IPv4-only, so a non-mapped v6 client (dummy4 == 0) will
                 * never match it and falls through to the normal path (fail
                 * closed). */
                struct in_addr dummy4 = {.s_addr = 0};
                if (IN6_IS_ADDR_V4MAPPED(&cli6.sin6_addr))
                    memcpy(&dummy4, ((uint8_t *) &cli6.sin6_addr) + 12, 4);
                if (forward_dispatch_udp(dns6_sock, pkt6, (int) nn6, (struct sockaddr *) &cli6, cl6,
                                         &dummy4))
                    continue;
                struct timespec _t0, _t1;
                clock_gettime(CLOCK_MONOTONIC, &_t0);
                int rlen6 = dns_process(pkt6, (int) nn6, resp6, sizeof(resp6), 0, &dummy4);
                clock_gettime(CLOCK_MONOTONIC, &_t1);
                long _rtt6 = (long) ((_t1.tv_sec - _t0.tv_sec) * 1000000L +
                                     (_t1.tv_nsec - _t0.tv_nsec) / 1000L);
                if (rlen6 > 0) {
                    sendto(dns6_sock, resp6, rlen6, 0, (struct sockaddr *) &cli6, cl6);
                    uint8_t _rc6 = rlen6 >= 4 ? (get16(resp6, 2) & 0xF) : 2;
                    int _an6 = rlen6 >= 8 ? get16(resp6, 6) : 0;
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
        if (z->ksk_next)
            EVP_PKEY_free(z->ksk_next);
        if (z->ksk_ed_next)
            EVP_PKEY_free(z->ksk_ed_next);
    }
    if (g_syslog_enabled)
        closelog();
    pthread_mutex_lock(&g_log_mutex);
    rsyslog_disconnect();
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}
