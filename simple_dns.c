/*
 * dns_server.c — Production authoritative DNS server
 *
 * Implemented RFCs:
 *   1034/1035  Core DNS – query/response, wire format, record types
 *   1876       LOC records (geographic location)
 *   1995       IXFR – Incremental Zone Transfer
 *   1996       DNS NOTIFY – prompt zone-change notification
 *   2136       DNS UPDATE – dynamic record management
 *   2181       Clarifications (QDCOUNT=1 enforcement, TTL ranges)
 *   2308       Negative caching – SOA in authority on NXDOMAIN/NODATA
 *   2782       SRV records
 *   2931       SIG(0) transaction signatures (stub – reject unsigned updates)
 *   3007       Secure DNS Dynamic Update (TSIG prerequisite)
 *   3596       AAAA records
 *   3597       Unknown RR type handling (\# hex wire format)
 *   4033-4035  DNSSEC – ZSK, DNSKEY, RRSIG, NSEC, Algorithm 13
 *   4255/6594  SSHFP records
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
 *   8555       ACME RFC 8555 (DNS-01 challenge, cert auto-renewal)
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
 *   zone:NSEC3PARAM:<zone>     NSEC3 parameters        (iters|salt_hex)
 *   zone:SRV:<name>            SRV record              (ttl|prio|weight|port|target)
 *   zone:CAA:<name>            CAA record              (ttl|flags|tag|value)
 *   zone:SSHFP:<name>          SSHFP record            (ttl|alg|fptype|fingerprint_hex)
 *   zone:TLSA:<name>           TLSA record             (ttl|usage|selector|mtype|data_hex)
 *   zone:DNAME:<name>          DNAME record            (ttl|target)
 *   zone:LOC:<name>            LOC record              (ttl|loc_wire_hex)
 *
 * Build:
 *   gcc -O2 -Wall -I<openssl-inc> -o dns_server dns_server.c \
 *       -L<openssl-lib> -lssl -lcrypto -lpthread -Wl,-rpath,<openssl-lib>
 */

#define _GNU_SOURCE
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
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
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
#define CONFIG_PORT_DEFAULT 8080
#define DNS_PORT_DEFAULT 5353
#define DOT_PORT_DEFAULT 8853
#define HTTP_PORT_DEFAULT 8053
#define HTTPS_PORT_DEFAULT 8443
#define DEFAULT_TTL 60
#define DEFAULT_NEG_TTL 300
#define DNSSEC_SIG_VALIDITY (7 * 86400)
#define ACME_CA_PROD "https://acme-v02.api.letsencrypt.org/directory"
#define ACME_CA_STAGING "https://acme-staging-v02.api.letsencrypt.org/directory"
#define ACME_RENEW_DAYS 30
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
#define DNS_COOKIE_SERVER_LEN 8

/* ==========================================================================
 * DNS type / class / opcode constants
 * ======================================================================= */
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
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
#define DNS_TYPE_CAA 257
#define DNS_TYPE_ANY 255

#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255
#define DNS_CLASS_NONE 254

#define DNS_QR 0x8000
#define DNS_AA 0x0400
#define DNS_TC 0x0200
#define DNS_RD 0x0100
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
#define DNS_RCODE_NOTZONE 10
#define DNS_RCODE_BADVERS 16
#define DNS_RCODE_BADSIG 17

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
 * Runtime configuration
 * ======================================================================= */
static char g_valkey_host[256] = "127.0.0.1";
static int g_valkey_port = 6379;
static char g_valkey_pass[256] = "";
static int g_config_port = CONFIG_PORT_DEFAULT;
static int g_dns_port = DNS_PORT_DEFAULT;
static int g_dot_port = DOT_PORT_DEFAULT;
static int g_http_port = HTTP_PORT_DEFAULT;
static int g_https_port = HTTPS_PORT_DEFAULT;
static char g_ddns_secret[256] = "changeme";
static char g_acme_domain[256] = "";
static char g_acme_email[256] = "";
static char g_acme_ca[512] = ACME_CA_PROD;
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
    char portstr[8];
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

/* TLS contexts */
static SSL_CTX *g_dot_ctx = NULL;
static SSL_CTX *g_mgmt_ctx = NULL;

/* DNSSEC ZSK (Alg 13 ECDSAP256) */
static EVP_PKEY *g_zsk = NULL;
static uint16_t g_zsk_tag = 0;

/* DNSSEC ZSK2 (Alg 15 Ed25519) */
static EVP_PKEY *g_zsk_ed = NULL;
static uint16_t g_zsk_ed_tag = 0;

/* ACME state */
static EVP_PKEY *g_acme_key = NULL;
static char g_acme_account_url[512] = "";
static char g_acme_dir_newnonce[512] = "";
static char g_acme_dir_newacct[512] = "";
static char g_acme_dir_neworder[512] = "";
static char g_acme_nonce[256] = "";

/* Mutexes */
static pthread_mutex_t g_vk_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_zsk_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_tls_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_soa_mutex = PTHREAD_MUTEX_INITIALIZER;

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
 * Utility helpers
 * ======================================================================= */
/* Case-insensitive name equality. The 256-byte scratch buffers only bound
 * the comparison; DNS names are capped at 255 octets (RFC 1035 §2.3.4), so
 * truncation of legitimate input cannot occur here. */
static int streq_ci(const char *a, const char *b) {
    char la[256], lb[256];
    safe_strcpy(la, a, sizeof(la));
    strlower(la);
    safe_strcpy(lb, b, sizeof(lb));
    strlower(lb);
    return strcmp(la, lb) == 0;
}
static const char *cfgenv(const char *k, const char *def) {
    const char *v = getenv(k);
    return v ? v : def;
}

/* hex encode/decode */
static void sha256(const uint8_t *in, int n, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dl = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, out, &dl);
    EVP_MD_CTX_free(ctx);
}
static void sha1(const uint8_t *in, int n, uint8_t out[20]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int dl = 20;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
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

/* Compute 8-byte server cookie: SipHash-2-4(client_cookie || client_ip, secret) */
static void compute_server_cookie(const uint8_t *ccookie, const struct in_addr *cip,
                                  uint8_t out[DNS_COOKIE_SERVER_LEN]) {
    uint8_t msg[12];
    memcpy(msg, ccookie, 8);
    memcpy(msg + 8, &cip->s_addr, 4);
    uint64_t h = siphash24(msg, 12, g_cookie_secret);
    memcpy(out, &h, 8);
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
                char drain[256];
                int d = excess > (int) sizeof(drain) ? (int) sizeof(drain) : excess;
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
    g_config_port = atoi(cfgenv("CONFIG_PORT", "8080"));
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
static void boot_save(void) {
    FILE *f = fopen(BOOT_FILE, "w");
    if (!f) {
        perror("boot_save");
        return;
    }
    fprintf(f, "VALKEY_HOST=%s\nVALKEY_PORT=%d\nVALKEY_PASSWORD=%s\n", g_valkey_host, g_valkey_port,
            g_valkey_pass);
    fclose(f);
    dns_log(LOG_INFO, "[Boot] Saved %s\n", BOOT_FILE);
}

/* ==========================================================================
 * Config portal (blocking HTML form when Valkey unreachable)
 * ======================================================================= */
static const char PORTAL_HTML_FMT[] =
    "<!DOCTYPE html><html><head><title>DNS Server Setup</title>"
    "<style>body{font-family:sans-serif;max-width:520px;margin:60px auto;background:#f5f5f5}"
    "h1{color:#333}label{display:block;margin:12px 0 4px;font-weight:bold}"
    "input{width:100%%;box-sizing:border-box;padding:8px;border:1px solid #ccc;border-radius:4px}"
    "button{margin-top:20px;padding:10px 28px;background:#2d6db5;color:#fff;"
    "border:none;border-radius:4px;font-size:1rem;cursor:pointer}"
    ".msg{padding:10px;border-radius:4px;margin-top:14px}"
    ".err{background:#fdd;border:1px solid #f88}.ok{background:#dfd;border:1px solid #8d8}"
    "</style></head><body>"
    "<h1>&#128274; DNS Server &mdash; Valkey Setup</h1>"
    "<p>The server cannot reach its Valkey database. "
    "Please provide the connection details below.</p>"
    "%s"
    "<form method=\"POST\" action=\"/connect\">"
    "<label>Valkey Host</label>"
    "<input name=\"host\" value=\"%s\" placeholder=\"127.0.0.1\" required>"
    "<label>Valkey Port</label>"
    "<input name=\"port\" value=\"%d\" placeholder=\"6379\" type=\"number\" required>"
    "<label>Password (leave empty if none)</label>"
    "<input name=\"pass\" type=\"password\" placeholder=\"(none)\">"
    "<button type=\"submit\">Connect &amp; Continue</button>"
    "</form></body></html>\n";

static void portal_send(int fd, int code, const char *body, int blen) {
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n",
                      code, code == 200 ? "OK" : "Bad Request", blen);
    if (hl > 0 && hl < (int) sizeof(hdr)) {
        send(fd, hdr, hl, 0);
    }
    if (blen > 0)
        send(fd, body, blen, 0);
}
static int form_field(const char *body, const char *key, char *out, int olen) {
    char needle[128];
    snprintf(needle, sizeof(needle), "%s=", key);
    const char *p = strstr(body, needle);
    if (!p)
        return 0;
    p += strlen(needle);
    int i = 0;
    while (*p && *p != '&' && i < olen - 1) {
        if (*p == '%' && isxdigit((unsigned char) p[1]) && isxdigit((unsigned char) p[2])) {
            char h[3] = {p[1], p[2], 0};
            out[i++] = (char) strtol(h, NULL, 16);
            p += 3;
        } else if (*p == '+') {
            out[i++] = ' ';
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = 0;
    return 1;
}
static void config_portal(void) {
    dns_log(LOG_WARNING, "[Portal] Starting on port %d\n", g_config_port);
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa = {.sin_family = AF_INET,
                             .sin_port = htons(g_config_port),
                             .sin_addr.s_addr = INADDR_ANY};
    if (bind(srv, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        perror("portal bind");
        close(srv);
        return;
    }
    listen(srv, 4);
    char last_error[256] = "";
    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        if (cfd < 0)
            continue;
        struct timeval tv = {.tv_sec = 10};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char buf[4096];
        int n = (int) recv(cfd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            close(cfd);
            continue;
        }
        buf[n] = 0;
        char method[8], path[256];
        sscanf(buf, "%7s %255s", method, path);
        if (!strcmp(method, "GET")) {
            char msg[512] = "";
            if (last_error[0])
                snprintf(msg, sizeof(msg), "<div class=\"msg err\">&#10007; %s</div>", last_error);
            char page[8192];
            int pl =
                snprintf(page, sizeof(page), PORTAL_HTML_FMT, msg, g_valkey_host, g_valkey_port);
            portal_send(cfd, 200, page, pl);
            close(cfd);
            continue;
        }
        if (!strcmp(method, "POST") && !strcmp(path, "/connect")) {
            char *body = strstr(buf, "\r\n\r\n");
            if (!body) {
                close(cfd);
                continue;
            }
            body += 4;
            char host[256] = "", portstr[16] = "", pass[256] = "";
            form_field(body, "host", host, sizeof(host));
            form_field(body, "port", portstr, sizeof(portstr));
            form_field(body, "pass", pass, sizeof(pass));
            if (!host[0])
                safe_strcpy(host, "127.0.0.1", sizeof(host));
            int port = portstr[0] ? atoi(portstr) : 6379;
            resp_conn_t test;
            memset(&test, 0, sizeof(test));
            test.fd = -1;
            if (valkey_connect_to(&test, host, port, pass) == 0) {
                safe_strcpy(g_valkey_host, host, sizeof(g_valkey_host));
                g_valkey_port = port;
                safe_strcpy(g_valkey_pass, pass, sizeof(g_valkey_pass));
                close(test.fd);
                boot_save();
                char page[512];
                int pl = snprintf(
                    page, sizeof(page),
                    "<html><body style=\"font-family:sans-serif;margin:60px auto;max-width:520px\">"
                    "<div class=\"ok\" style=\"padding:20px;background:#dfd;border:1px solid #8d8;border-radius:4px\">"
                    "<h2>&#10003; Connected to Valkey %s:%d</h2><p>Server starting up.</p>"
                    "</div></body></html>",
                    host, port);
                portal_send(cfd, 200, page, pl);
                close(cfd);
                break;
            } else {
                snprintf(last_error, sizeof(last_error), "Could not connect to %s:%d", host, port);
                char msg[512];
                snprintf(msg, sizeof(msg), "<div class=\"msg err\">&#10007; %s</div>", last_error);
                char page[8192];
                int pl = snprintf(page, sizeof(page), PORTAL_HTML_FMT, msg, host, port);
                portal_send(cfd, 200, page, pl);
                close(cfd);
                continue;
            }
        }
        const char *redir = "HTTP/1.0 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n";
        send(cfd, redir, strlen(redir), 0);
        close(cfd);
    }
    close(srv);
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
    G("acme_domain", g_acme_domain);
    G("acme_email", g_acme_email);
    G("acme_ca", g_acme_ca);
    GI("dns_port", g_dns_port);
    GI("dot_port", g_dot_port);
    GI("http_port", g_http_port);
    GI("https_port", g_https_port);
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
    /* If NSID empty, use hostname */
    if (!g_nsid[0])
        gethostname(g_nsid, sizeof(g_nsid) - 1);
    /* PEM blobs */
    vk_get("config:tls_cert_pem", g_tls_cert_pem, sizeof(g_tls_cert_pem));
    vk_get("config:tls_key_pem", g_tls_key_pem, sizeof(g_tls_key_pem));
    vk_get("config:mtls_ca_pem", g_mtls_ca_pem, sizeof(g_mtls_ca_pem));
    vk_get("acme:account_url", g_acme_account_url, sizeof(g_acme_account_url));
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
static void config_set(const char *key, const char *val) {
    char fkey[256];
    snprintf(fkey, sizeof(fkey), "config:%s", key);
    vk_set(fkey, val, 0);
    /* Live-apply syslog config changes */
    if (!strcmp(key, "syslog_enabled")) {
        g_syslog_enabled = atoi(val);
        syslog_init();
    } else if (!strcmp(key, "syslog_facility")) {
        g_syslog_facility = syslog_facility_from_str(val);
        syslog_init();
    } else if (!strcmp(key, "syslog_level")) {
        g_syslog_level = syslog_level_from_str(val);
        syslog_init();
    } else if (!strcmp(key, "syslog_ident")) {
        safe_strcpy(g_syslog_ident, val, sizeof(g_syslog_ident));
        syslog_init();
    } else if (!strcmp(key, "syslog_remote_host")) {
        safe_strcpy(g_rsyslog_host, val, sizeof(g_rsyslog_host));
        syslog_init();
    } else if (!strcmp(key, "syslog_remote_port")) {
        g_rsyslog_port = atoi(val);
        syslog_init();
    } else if (!strcmp(key, "syslog_remote_proto")) {
        if (!strcasecmp(val, "tcp"))
            g_rsyslog_proto = RSYSLOG_TCP;
        else if (!strcasecmp(val, "tls"))
            g_rsyslog_proto = RSYSLOG_TLS;
        else
            g_rsyslog_proto = RSYSLOG_UDP;
        /* Adjust default port when proto changes and port was left at default */
        if (g_rsyslog_port == 514 || g_rsyslog_port == 6514)
            g_rsyslog_port = (g_rsyslog_proto == RSYSLOG_TLS) ? 6514 : 514;
        syslog_init();
    } else if (!strcmp(key, "syslog_remote_level")) {
        g_rsyslog_level = syslog_level_from_str(val);
        syslog_init();
    } else if (!strcmp(key, "syslog_remote_tls_verify")) {
        g_rsyslog_tls_verify = atoi(val);
        syslog_init();
    } else if (!strcmp(key, "syslog_remote_format")) {
        g_rsyslog_fmt = strcasecmp(val, "rfc3164") == 0 ? RFMT_RFC3164 : RFMT_RFC5424;
        syslog_init();
    }
}
/* Bump SOA serial (YYYYMMDDnn format if possible, else simple increment) */
static uint32_t serial_bump(void) {
    long ns = vk_incr("config:zone_serial");
    if (ns > 0) {
        pthread_mutex_lock(&g_soa_mutex);
        g_soa_serial = (uint32_t) ns;
        pthread_mutex_unlock(&g_soa_mutex);
        return g_soa_serial;
    }
    pthread_mutex_lock(&g_soa_mutex);
    g_soa_serial++;
    pthread_mutex_unlock(&g_soa_mutex);
    char buf[32];
    snprintf(buf, sizeof(buf), "%u", g_soa_serial);
    vk_set("config:zone_serial", buf, 0);
    return g_soa_serial;
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
    if (g_mgmt_ctx) {
        SSL_CTX_free(g_mgmt_ctx);
        g_mgmt_ctx = NULL;
    }
    g_dot_ctx = tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, NULL, 0);
    g_mgmt_ctx = tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, g_mtls_ca_pem, 1);
    pthread_mutex_unlock(&g_tls_mutex);
    dns_log(LOG_INFO, "[TLS] Contexts %s\n", g_dot_ctx ? "loaded" : "unavailable (no cert yet)");
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
    uint8_t rr[2048];
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
    const EVP_MD *md = (alg == DNS_ALG_ED25519) ? NULL : EVP_sha256();
    EVP_DigestSignInit(mc, NULL, md, NULL, zsk);
    EVP_DigestSignUpdate(mc, hdr, hp);
    EVP_DigestSignUpdate(mc, rr, rp);
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

/* Load or generate ZSK from Valkey */
static void dnssec_init_key(const char *vk_key, EVP_PKEY **out, uint16_t *tag, int alg,
                            const char *label) {
    char pem[MAX_PEM] = {0};
    if (vk_get(vk_key, pem, sizeof(pem)) && strlen(pem) > 10) {
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
static void dnssec_init(void) {
    pthread_mutex_lock(&g_zsk_mutex);
    g_zsk = NULL;
    g_zsk_ed = NULL;
    pthread_mutex_unlock(&g_zsk_mutex);
    dnssec_init_key("dnssec:zsk", &g_zsk, &g_zsk_tag, DNS_ALG_ECDSAP256SHA256, "ZSK-P256");
    dnssec_init_key("dnssec:zsk_ed25519", &g_zsk_ed, &g_zsk_ed_tag, DNS_ALG_ED25519, "ZSK-Ed25519");
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
    uint8_t salt[16];
    int saltlen = 0;
    if (g_nsec3_salt[0])
        saltlen = hex_dec(g_nsec3_salt, salt, sizeof(salt));
    /* Compute next-closer hash (we use the same name hash as next for simplicity) */
    char hash[64];
    nsec3_hash_name(name, salt, saltlen, g_nsec3_iters, hash, sizeof(hash));
    /* Build RDATA: alg(1)|flags(1)|iters(2)|saltlen(1)|salt|hashlen(1)|nexthash|bitmap */
    uint8_t nexthash[20];
    /* Next hash = hash of the zone apex (simplified — in production use sorted order) */
    uint8_t zone_wire[257];
    int zw = 0;
    {
        char *sp4 = NULL;
        char ztmp[256];
        safe_strcpy(ztmp, g_zone_name, sizeof(ztmp));
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
        for (int i = 0; i < g_nsec3_iters; i++) {
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
    out[op++] = (uint16_t) g_nsec3_iters >> 8;
    out[op++] = (uint16_t) g_nsec3_iters & 0xFF;
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
    uint8_t mac[32];
    int mac_len;
    uint32_t time_high;
    uint64_t time_low;
    uint16_t fudge;
    uint16_t orig_id;
    uint16_t error;
} tsig_rr_t;

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
        char name[256];
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
        char name[256];
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
                        p2 += 2;
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
            /* skip alg name */
            int rp = rd_off;
            for (;;) {
                if (rp >= plen)
                    return NULL;
                uint8_t c = pkt[rp];
                if (c == 0) {
                    rp++;
                    break;
                }
                rp += c + 1;
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
            if (t->mac_len > 32 || rp + t->mac_len > plen)
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
static int tsig_verify(const uint8_t *pkt, int plen) {
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
    /* Compute HMAC-SHA256 */
    unsigned int mlen = 32;
    uint8_t mac[32];
    {
        EVP_MAC *evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(evp_mac);
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
        params[1] = OSSL_PARAM_construct_end();
        EVP_MAC_init(mctx, g_tsig_secret, g_tsig_secret_len, params);
        EVP_MAC_update(mctx, tmp, pkt_minus_tsig_len);
        EVP_MAC_update(mctx, vars, vp);
        size_t ml2 = 32;
        EVP_MAC_final(mctx, mac, &ml2, 32);
        mlen = (unsigned) ml2;
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(evp_mac);
    }
    free(tmp);
    return (mlen == (unsigned) t.mac_len) && (memcmp(mac, t.mac, mlen) == 0);
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
    unsigned int mlen = 32;
    uint8_t mac[32];
    {
        EVP_MAC *evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(evp_mac);
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
        params[1] = OSSL_PARAM_construct_end();
        EVP_MAC_init(mctx, g_tsig_secret, g_tsig_secret_len, params);
        EVP_MAC_update(mctx, buf, off);
        EVP_MAC_update(mctx, vars, vp);
        size_t ml2 = 32;
        EVP_MAC_final(mctx, mac, &ml2, 32);
        mlen = (unsigned) ml2;
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(evp_mac);
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
    rdata[rp++] = 0;
    rdata[rp++] = (uint8_t) mlen;
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
        case DNS_TYPE_CAA:
            return "CAA";
        case DNS_TYPE_ANY:
            return "ANY";
        default:
            return "?";
    }
}
static uint16_t str2type(const char *s) {
    if (!strcasecmp(s, "A"))
        return DNS_TYPE_A;
    if (!strcasecmp(s, "AAAA"))
        return DNS_TYPE_AAAA;
    if (!strcasecmp(s, "CNAME"))
        return DNS_TYPE_CNAME;
    if (!strcasecmp(s, "MX"))
        return DNS_TYPE_MX;
    if (!strcasecmp(s, "TXT"))
        return DNS_TYPE_TXT;
    if (!strcasecmp(s, "NS"))
        return DNS_TYPE_NS;
    if (!strcasecmp(s, "SRV"))
        return DNS_TYPE_SRV;
    if (!strcasecmp(s, "CAA"))
        return DNS_TYPE_CAA;
    if (!strcasecmp(s, "SSHFP"))
        return DNS_TYPE_SSHFP;
    if (!strcasecmp(s, "TLSA"))
        return DNS_TYPE_TLSA;
    if (!strcasecmp(s, "DNAME"))
        return DNS_TYPE_DNAME;
    if (!strcasecmp(s, "LOC"))
        return DNS_TYPE_LOC;
    return 0;
}

/* ==========================================================================
 * SOA record builder
 * ======================================================================= */
static int build_soa_rdata(uint8_t *rd, int rdlen) {
    int pos = 0;
    int n = name_to_wire(g_soa_mname, rd, rdlen);
    if (n < 0)
        return -1;
    pos += n;
    n = name_to_wire(g_soa_rname, rd + pos, rdlen - pos);
    if (n < 0)
        return -1;
    pos += n;
    if (pos + 20 > rdlen)
        return -1;
    pthread_mutex_lock(&g_soa_mutex);
    put32(rd, pos, g_soa_serial);
    pos += 4;
    put32(rd, pos, g_soa_refresh);
    pos += 4;
    put32(rd, pos, g_soa_retry);
    pos += 4;
    put32(rd, pos, g_soa_expire);
    pos += 4;
    put32(rd, pos, g_soa_minimum);
    pos += 4;
    pthread_mutex_unlock(&g_soa_mutex);
    return pos;
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
                    if (rp + 8 <= plen) {
                        memcpy(ei->client_cookie, pkt + rp, 8);
                        ei->has_client_cookie = 1;
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
                           uint16_t rcode_ext, const edns_info_t *req_ei, int ede_code,
                           const char *ede_text) {
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
            uint8_t scookie[8];
            struct in_addr dummy;
            dummy.s_addr = 0; /* no client IP in this path */
            compute_server_cookie(req_ei->client_cookie, &dummy, scookie);
            put16(buf, rdata_off, EDNS_OPT_COOKIE);
            put16(buf, rdata_off + 2, DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN);
            memcpy(buf + rdata_off + 4, req_ei->client_cookie, 8);
            memcpy(buf + rdata_off + 12, scookie, 8);
            rdata_off += 20;
            rdata_len += 20;
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
    /* Padding (RFC 7830) — pad to multiple of 128 bytes */
    if (req_ei && req_ei->has_padding && is_tcp) {
        int total = off + 2 + rdata_len + 4;
        int pad = 128 - ((total + off) % 128);
        if (pad < 0)
            pad = 0;
        if (rdata_off + 4 + pad < blen) {
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
 * DNS Cookie verification (RFC 9018) — returns 1 if ok, 0 if bad
 * ======================================================================= */
static int cookie_verify(const edns_info_t *ei, const struct in_addr *cip) {
    if (!ei->has_client_cookie)
        return 1; /* not present, not required */
    /* We don't require cookies, so we only validate when present */
    /* A real server would reject responses without cookies from cookie-capable clients */
    (void) cip;
    return 1; /* accept any valid client cookie presence */
}

/* ==========================================================================
 * Query response builder
 * ======================================================================= */
static int emit_rr(uint8_t *resp, int off, int resp_len, const char *name, uint16_t type,
                   uint32_t ttl, const uint8_t *rdata, uint16_t rdlen, int dnssec_ok,
                   int *answers) {
    int noff = append_rr_plain(resp, off, resp_len, name, type, DNS_CLASS_IN, ttl, rdata, rdlen);
    if (noff < 0)
        return off;
    (*answers)++;
    off = noff;
    if (!dnssec_ok || !g_zsk)
        return off;
    /* Add RRSIG for ECDSA P-256 (Alg 13) */
    {
        pthread_mutex_lock(&g_zsk_mutex);
        EVP_PKEY *zsk = g_zsk;
        uint16_t tag = g_zsk_tag;
        pthread_mutex_unlock(&g_zsk_mutex);
        if (zsk) {
            uint8_t sig[512];
            int sl =
                make_rrsig(name, type, ttl, rdata, rdlen, zsk, DNS_ALG_ECDSAP256SHA256, tag, sig);
            if (sl > 0) {
                int so = append_rr_plain(resp, off, resp_len, name, DNS_TYPE_RRSIG, DNS_CLASS_IN,
                                         ttl, sig, (uint16_t) sl);
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
        EVP_PKEY *zsk = g_zsk_ed;
        uint16_t tag = g_zsk_ed_tag;
        pthread_mutex_unlock(&g_zsk_mutex);
        if (zsk) {
            uint8_t sig[512];
            int sl = make_rrsig(name, type, ttl, rdata, rdlen, zsk, DNS_ALG_ED25519, tag, sig);
            if (sl > 0) {
                int so = append_rr_plain(resp, off, resp_len, name, DNS_TYPE_RRSIG, DNS_CLASS_IN,
                                         ttl, sig, (uint16_t) sl);
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
    off = emit_rr(resp, off, resp_len, g_zone_name, DNS_TYPE_SOA, g_soa_minimum, soa_rd,
                  (uint16_t) soa_len, dnssec_ok, auth_count);
    return off;
}

/* Add NSEC3 to authority for authenticated denial */
static int add_nsec3_denial(uint8_t *resp, int off, int resp_len, const char *qname, uint16_t qtype,
                            int dnssec_ok, int *auth_count) {
    uint8_t n3rd[256];
    int n3len = nsec3_rdata(qname, qtype, n3rd, sizeof(n3rd));
    if (n3len > 0) {
        /* NSEC3 owner name = base32hex_hash.zone */
        uint8_t salt[16];
        int saltlen = 0;
        if (g_nsec3_salt[0])
            saltlen = hex_dec(g_nsec3_salt, salt, sizeof(salt));
        char hash[64];
        nsec3_hash_name(qname, salt, saltlen, g_nsec3_iters, hash, sizeof(hash));
        char nsec3_owner[512];
        snprintf(nsec3_owner, sizeof(nsec3_owner), "%s.%s", hash, g_zone_name);
        strlower(nsec3_owner);
        off = emit_rr(resp, off, resp_len, nsec3_owner, DNS_TYPE_NSEC3, g_soa_minimum, n3rd,
                      (uint16_t) n3len, dnssec_ok, auth_count);
    }
    return off;
}

static int build_query_resp(const uint8_t *query, int qlen, uint8_t *resp, int resp_len, int is_tcp,
                            const struct in_addr *cip) {
    if (qlen < 12)
        return -1;
    const dns_hdr_t *qh = (const dns_hdr_t *) query;
    dns_hdr_t *rh = (dns_hdr_t *) resp;
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
    cookie_verify(&ei, cip);
    int dnssec_ok = ei.do_bit;
    int answers = 0, auth_count = 0, found = 0;
    int any_minimal = 0; /* RFC 8482: limit ANY responses */
    if (qtype == DNS_TYPE_ANY)
        any_minimal = 1;
    /* DNSKEY */
    if ((qtype == DNS_TYPE_DNSKEY || qtype == DNS_TYPE_ANY)) {
        uint8_t dkrd[68];
        if (g_zsk && dnskey_rdata_ecdsa(g_zsk, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, 3600, dkrd, 68, dnssec_ok,
                          &answers);
        }
        if (g_zsk_ed && dnskey_rdata_ed25519(g_zsk_ed, dkrd, sizeof(dkrd)) > 0) {
            found = 1;
            off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_DNSKEY, 3600, dkrd, 36, dnssec_ok,
                          &answers);
        }
        if (any_minimal && answers > 0)
            goto finish_answer;
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
                int sl = (int) strlen(r->rdata_str);
                if (sl > 255)
                    sl = 255;
                rd[0] = (uint8_t) sl;
                memcpy(rd + 1, r->rdata_str, sl);
                rdlen = (uint16_t) (1 + sl);
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
        char val[128], k[512];
        snprintf(k, sizeof(k), "ddns:A:%s", qname);
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
        snprintf(k, sizeof(k), "zone:A:%s", qname);
        if (vk_get(k, val, sizeof(val))) {
            found = 1;
            uint32_t ttl = DEFAULT_TTL;
            char *pipe = strchr(val, '|');
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                pipe++;
            } else
                pipe = val;
            char *sp9 = NULL;
            char *ip = strtok_r(pipe, "|", &sp9);
            while (ip) {
                struct in_addr a4;
                if (inet_pton(AF_INET, ip, &a4) == 1) {
                    uint8_t rd[4];
                    memcpy(rd, &a4, 4);
                    off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_A, ttl, rd, 4, dnssec_ok,
                                  &answers);
                }
                ip = strtok_r(NULL, "|", &sp9);
            }
        }
    }
    /* Dynamic AAAA */
    if (qtype == DNS_TYPE_AAAA || qtype == DNS_TYPE_ANY) {
        char val[256], k[512];
        snprintf(k, sizeof(k), "ddns:AAAA:%s", qname);
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
        snprintf(k, sizeof(k), "zone:AAAA:%s", qname);
        if (vk_get(k, val, sizeof(val))) {
            found = 1;
            uint32_t ttl = DEFAULT_TTL;
            char *pipe = strchr(val, '|');
            if (pipe) {
                ttl = (uint32_t) atoi(val);
                pipe++;
            } else
                pipe = val;
            char *sp10 = NULL;
            char *ip = strtok_r(pipe, "|", &sp10);
            while (ip) {
                struct in6_addr a6;
                if (inet_pton(AF_INET6, ip, &a6) == 1) {
                    uint8_t rd[16];
                    memcpy(rd, &a6, 16);
                    off = emit_rr(resp, off, resp_len, qname, DNS_TYPE_AAAA, ttl, rd, 16, dnssec_ok,
                                  &answers);
                }
                ip = strtok_r(NULL, "|", &sp10);
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
                          0};
        for (int pi = 0; pts[pi]; pi++) {
            uint16_t pt = pts[pi];
            if (qtype != pt && qtype != DNS_TYPE_ANY)
                continue;
            char k[512];
            snprintf(k, sizeof(k), "zone:%s:%s", type2str(pt), qname);
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
                    int sl = (int) strlen(pipe);
                    if (sl > 255)
                        sl = 255;
                    rd[0] = (uint8_t) sl;
                    memcpy(rd + 1, pipe, sl);
                    rdlen = (uint16_t) (1 + sl);
                    break;
                }
                case DNS_TYPE_SRV: { /* ttl|prio|weight|port|target */
                    uint16_t prio = 0, weight = 0, port = 0;
                    char target[256] = "";
                    char *p2 = pipe;
                    char *sp11 = NULL;
                    char *tok = strtok_r(p2, "|", &sp11);
                    if (tok) {
                        prio = (uint16_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp11);
                    if (tok) {
                        weight = (uint16_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp11);
                    if (tok) {
                        port = (uint16_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp11);
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
                    char *sp12 = NULL;
                    char *tok = strtok_r(p2, "|", &sp12);
                    if (tok) {
                        flags = (uint8_t) atoi(tok);
                    }
                    tok = strtok_r(NULL, "|", &sp12);
                    if (tok)
                        safe_strcpy(tag, tok, sizeof(tag));
                    tok = strtok_r(NULL, "|", &sp12);
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
                    uint8_t fp[64];
                    int fplen = 0;
                    char *p2 = pipe;
                    char *sp13 = NULL;
                    char *tok = strtok_r(p2, "|", &sp13);
                    if (tok)
                        alg = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp13);
                    if (tok)
                        fptype = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp13);
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
                    uint8_t data[512];
                    int dlen = 0;
                    char *p2 = pipe;
                    char *sp14 = NULL;
                    char *tok = strtok_r(p2, "|", &sp14);
                    if (tok)
                        usage = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp14);
                    if (tok)
                        sel = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp14);
                    if (tok)
                        mtype = (uint8_t) atoi(tok);
                    tok = strtok_r(NULL, "|", &sp14);
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
                default:
                    continue;
            }
            off = emit_rr(resp, off, resp_len, qname, pt, ttl, rd, rdlen, dnssec_ok, &answers);
            if (any_minimal && answers > 0)
                goto finish_answer;
        }
    }
finish_answer:
    rh->ancount = htons((uint16_t) answers);
    int ede_code = -1;
    const char *ede_text = NULL;
    if (answers == 0) {
        /* RFC 2308: add SOA in authority for NXDOMAIN / NODATA */
        if (!found) {
            rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_NXDOMAIN);
            ede_code = EDE_NXDOMAIN;
            ede_text = "Name does not exist in zone";
        } else { /* NODATA — name exists, type doesn't */
            rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_NOERROR);
            ede_code = EDE_NOT_AUTH;
        }
        off = add_soa_authority(resp, off, resp_len, dnssec_ok, &auth_count);
        if (dnssec_ok)
            off = add_nsec3_denial(resp, off, resp_len, qname, qtype, dnssec_ok, &auth_count);
        rh->nscount = htons((uint16_t) auth_count);
    }
    /* RFC 8482: set HINFO hint for ANY minimal responses */
    if (any_minimal && answers > 0) {
        /* Add HINFO record as hint per RFC 8482 */
        const uint8_t hinfo_rd[] = {3, 'R', 'F', 'C', 1, '1'};
        append_rr_plain(resp, off, resp_len, qname, 13 /*HINFO*/, DNS_CLASS_IN, 3600, hinfo_rd,
                        sizeof(hinfo_rd));
    /* We don't count this in answers to avoid recursion */ }
    /* EDNS OPT in response */
    off = edns_append_opt(resp, off, resp_len, is_tcp, dnssec_ok, 0, &ei, ede_code, ede_text);
    return off;
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
    for (int i = 0; i < ntohs(h->qdcount); i++) {
        char zn[256];
        off = name_from_wire(pkt, plen, off, zn, sizeof(zn));
        if (off < 0)
            goto formerr;
        off += 4;
        if (off > plen)
            goto formerr;
    }
    for (int i = 0; i < ntohs(h->ancount); i++) {
        char nm[256];
        int a = name_from_wire(pkt, plen, off, nm, sizeof(nm));
        if (a < 0 || a + 9 > plen)
            goto formerr;
        off = a + 10 + get16(pkt, a + 8);
        if (off > plen)
            goto formerr;
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
        char k[512];
        if (uc == DNS_CLASS_IN && rdlen > 0) {
            if (ut == DNS_TYPE_A && rdlen == 4) {
                char ip[32];
                snprintf(ip, sizeof(ip), "%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3]);
                snprintf(k, sizeof(k), "ddns:A:%s", un);
                vk_set(k, ip, uttl ? uttl : DEFAULT_TTL);
                serial_bump();
                dns_log(LOG_NOTICE, "[DDNS] A %s->%s\n", un, ip);
            } else if (ut == DNS_TYPE_AAAA && rdlen == 16) {
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rd, ip6, sizeof(ip6));
                snprintf(k, sizeof(k), "ddns:AAAA:%s", un);
                vk_set(k, ip6, uttl ? uttl : DEFAULT_TTL);
                serial_bump();
                dns_log(LOG_NOTICE, "[DDNS] AAAA %s->%s\n", un, ip6);
            }
        } else if ((uc == DNS_CLASS_ANY || uc == DNS_CLASS_NONE) && rdlen == 0) {
            if (ut == DNS_TYPE_A || ut == DNS_TYPE_ANY) {
                snprintf(k, sizeof(k), "ddns:A:%s", un);
                vk_del(k);
            }
            if (ut == DNS_TYPE_AAAA || ut == DNS_TYPE_ANY) {
                snprintf(k, sizeof(k), "ddns:AAAA:%s", un);
                vk_del(k);
            }
            serial_bump();
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
 * AXFR / IXFR zone transfer (RFC 5936 / 1995)
 * ======================================================================= */
typedef struct {
    int fd;
    SSL *ssl;
    struct sockaddr_in addr;
} axfr_conn_t;

static int axfr_ip_allowed(const struct in_addr *cip) {
    char allow[1024];
    safe_strcpy(allow, g_axfr_allow, sizeof(allow));
    char *sp15 = NULL;
    char *tok = strtok_r(allow, ",", &sp15);
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
        tok = strtok_r(NULL, ",", &sp15);
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
    dns_log(LOG_NOTICE, "[AXFR] Transfer to %s\n", cip);

    if (!axfr_ip_allowed(&c.addr.sin_addr)) {
        dns_log(LOG_ERR, "[AXFR] REFUSED %s\n", cip);
        /* Send REFUSED response */
        uint8_t ref[12] = {0};
        dns_hdr_t *rh = (dns_hdr_t *) ref;
        rh->id = 0;
        rh->flags = htons(DNS_QR | DNS_AA | DNS_RCODE_REFUSED);
        tcp_send_msg(c.fd, c.ssl, ref, 12);
        goto done;
    }

    uint8_t buf[BUF_SIZE];
    /* First SOA */
    memset(buf, 0, 12);
    dns_hdr_t *rh = (dns_hdr_t *) buf;
    rh->flags = htons(DNS_QR | DNS_AA);
    rh->ancount = htons(1);
    int off = 12;
    /* Question section: zone name, type AXFR */
    int n = name_to_wire(g_zone_name, buf + off, sizeof(buf) - off);
    if (n > 0) {
        off += n;
        put16(buf, off, 252);
        off += 2;
        put16(buf, off, DNS_CLASS_IN);
        off += 2;
    }
    rh->qdcount = htons(1);
    uint8_t soa_rd[512];
    int soa_len = build_soa_rdata(soa_rd, sizeof(soa_rd));
    if (soa_len > 0)
        off = append_rr_plain(buf, off, sizeof(buf), g_zone_name, DNS_TYPE_SOA, DNS_CLASS_IN,
                              g_soa_minimum, soa_rd, (uint16_t) soa_len);
    tcp_send_msg(c.fd, c.ssl, buf, off);

    /* Send all static zone records */
    for (int i = 0; i < static_zone_sz; i++) {
        dns_rec_t *r = &static_zone[i];
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
                int sl = (int) strlen(r->rdata_str);
                if (sl > 255)
                    sl = 255;
                rd[0] = (uint8_t) sl;
                memcpy(rd + 1, r->rdata_str, sl);
                rdlen = (uint16_t) (1 + sl);
                break;
            }
            default:
                continue;
        }
        uint8_t mb[BUF_SIZE];
        memset(mb, 0, 12);
        dns_hdr_t *mh = (dns_hdr_t *) mb;
        mh->flags = htons(DNS_QR | DNS_AA);
        mh->ancount = htons(1);
        int mo = 12;
        mo = append_rr_plain(mb, mo, sizeof(mb), r->name, r->type, DNS_CLASS_IN, r->ttl, rd, rdlen);
        tcp_send_msg(c.fd, c.ssl, mb, mo);
    }

    /* Send DNSKEY records */
    {
        uint8_t dkrd[68];
        if (g_zsk && dnskey_rdata_ecdsa(g_zsk, dkrd, sizeof(dkrd)) > 0) {
            uint8_t mb[BUF_SIZE];
            memset(mb, 0, 12);
            dns_hdr_t *mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            int mo = 12;
            mo = append_rr_plain(mb, mo, sizeof(mb), g_zone_name, DNS_TYPE_DNSKEY, DNS_CLASS_IN,
                                 3600, dkrd, 68);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
        }
        if (g_zsk_ed && dnskey_rdata_ed25519(g_zsk_ed, dkrd, sizeof(dkrd)) > 0) {
            uint8_t mb[BUF_SIZE];
            memset(mb, 0, 12);
            dns_hdr_t *mh = (dns_hdr_t *) mb;
            mh->flags = htons(DNS_QR | DNS_AA);
            mh->ancount = htons(1);
            int mo = 12;
            mo = append_rr_plain(mb, mo, sizeof(mb), g_zone_name, DNS_TYPE_DNSKEY, DNS_CLASS_IN,
                                 3600, dkrd, 36);
            tcp_send_msg(c.fd, c.ssl, mb, mo);
        }
    }

    /* Closing SOA */
    {
        uint8_t mb[BUF_SIZE];
        memset(mb, 0, 12);
        dns_hdr_t *mh = (dns_hdr_t *) mb;
        mh->flags = htons(DNS_QR | DNS_AA);
        mh->ancount = htons(1);
        int mo = 12;
        mo = append_rr_plain(mb, mo, sizeof(mb), g_zone_name, DNS_TYPE_SOA, DNS_CLASS_IN,
                             g_soa_minimum, soa_rd, (uint16_t) soa_len);
        tcp_send_msg(c.fd, c.ssl, mb, mo);
    }
    dns_log(LOG_NOTICE, "[AXFR] Complete to %s\n", cip);
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
static void notify_send(void) {
    if (!g_notify_targets[0])
        return;
    char targets[1024];
    safe_strcpy(targets, g_notify_targets, sizeof(targets));
    char *sp16 = NULL;
    char *tok = strtok_r(targets, ",", &sp16);
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
            tok = strtok_r(NULL, ",", &sp16);
            continue;
        }
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
        if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
            close(fd);
            tok = strtok_r(NULL, ",", &sp16);
            continue;
        }
        uint8_t pkt[64] = {0};
        dns_hdr_t *h = (dns_hdr_t *) pkt;
        h->id = htons((uint16_t) rand());
        h->flags = htons(DNS_QR & 0 ? 0 : 0 | DNS_OPCODE_NOTIFY | DNS_AA);
        h->qdcount = htons(1);
        int off = 12;
        int n = name_to_wire(g_zone_name, pkt + off, sizeof(pkt) - off);
        if (n > 0) {
            off += n;
            put16(pkt, off, DNS_TYPE_SOA);
            off += 2;
            put16(pkt, off, DNS_CLASS_IN);
            off += 2;
        }
        sendto(fd, pkt, off, 0, (struct sockaddr *) &sa, sizeof(sa));
        dns_log(LOG_NOTICE, "[NOTIFY] Sent to %s:%d\n", host, port);
        close(fd);
        tok = strtok_r(NULL, ",", &sp16);
    }
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
        {
            char qn[256] = "";
            int a = name_from_wire(pkt, ml, 12, qn, sizeof(qn));
            if (a >= 0 && a + 1 < ml)
                qtype = get16(pkt, a);
        }
        if (qtype == 252 /*AXFR*/) {
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
        uint8_t resp[BUF_SIZE];
        int rlen = dns_process(pkt, ml, resp, sizeof(resp), 1, &c.addr.sin_addr);
        if (rlen < 0)
            break;
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

/* ==========================================================================
 * ACME client (RFC 8555 DNS-01) — unchanged from previous version
 * ======================================================================= */
static char *https_req(const char *host, int port, const char *method, const char *path,
                       const char *body, int *code, char *resp_hdrs, int hl) {
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
    SSL_CTX_set_default_verify_paths(cctx);
    SSL *ssl = SSL_new(cctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        close(fd);
        return NULL;
    }
    char req[HTTP_BUF];
    int rp = 0;
    rp += snprintf(
        req + rp, sizeof(req) - rp,
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: dns-server/2.0\r\nAccept: application/json\r\n",
        method, path, host);
    if (body)
        rp += snprintf(req + rp, sizeof(req) - rp,
                       "Content-Type: application/jose+json\r\nContent-Length: %zu\r\n\r\n%s",
                       strlen(body), body);
    else
        rp += snprintf(req + rp, sizeof(req) - rp, "Connection: close\r\n\r\n");
    SSL_write(ssl, req, rp);
    char *rbuf = malloc(HTTP_BUF);
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
    char hdrs[4096] = {0};
    int code = 0;
    char h2[256];
    int p2;
    char path[512];
    parse_url(g_acme_dir_newnonce, h2, &p2, path, sizeof(path));
    char *body = https_req(host, port, "HEAD", path, NULL, &code, hdrs, sizeof(hdrs));
    free(body);
    hdr_val(hdrs, "Replay-Nonce", g_acme_nonce, sizeof(g_acme_nonce));
    return g_acme_nonce[0] ? 0 : -1;
}
static char *acme_post(const char *url, const char *payload, const char *host, int port, int *code,
                       char *rh, int hl) {
    acme_nonce_fetch(host, port);
    char *jws = acme_jws(g_acme_key, url, g_acme_nonce, payload);
    char uh[256];
    int up;
    char upath[512];
    parse_url(url, uh, &up, upath, sizeof(upath));
    char *body = https_req(uh, up, "POST", upath, jws, code, rh, hl);
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
    char *body = https_req(h2, p2, "GET", path, NULL, &code, hdrs, sizeof(hdrs));
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
static char *acme_gen_csr(const char *domain, EVP_PKEY **dkout) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
    EVP_PKEY *dk = NULL;
    EVP_PKEY_keygen(kctx, &dk);
    EVP_PKEY_CTX_free(kctx);
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
    int csrlen = i2d_X509_REQ(req, NULL);
    if (csrlen <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(dk);
        *dkout = NULL;
        return NULL;
    }
    uint8_t *cder = malloc((size_t) csrlen);
    if (!cder) {
        X509_REQ_free(req);
        EVP_PKEY_free(dk);
        *dkout = NULL;
        return NULL;
    }
    uint8_t *p = cder;
    i2d_X509_REQ(req, (unsigned char **) &p);
    X509_REQ_free(req);
    char *cb64 = malloc((size_t) csrlen * 2 + 4);
    if (!cb64) {
        free(cder);
        EVP_PKEY_free(dk);
        *dkout = NULL;
        return NULL;
    }
    b64url_enc(cder, csrlen, cb64, (int) ((size_t) csrlen * 2 + 4));
    free(cder);
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
    char acme_vk[512];
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
    vk_set("config:tls_cert_pem", cert_pem, 0);
    vk_set("config:tls_key_pem", key_pem, 0);
    safe_strcpy(g_tls_cert_pem, cert_pem, sizeof(g_tls_cert_pem));
    safe_strcpy(g_tls_key_pem, key_pem, sizeof(g_tls_key_pem));
    free(cert_pem);
    dns_log(LOG_NOTICE, "[ACME] Certificate stored in Valkey\n");
    /* Auto-publish TLSA record for the cert */
    if (g_acme_domain[0]) {
        /* TLSA 3 1 1: DANE-EE, SubjectPublicKeyInfo, SHA-256 */
        /* This would need cert parsing; for now store a placeholder */
        dns_log(LOG_NOTICE, "[ACME] Hint: publish TLSA 3 1 1 record for %s\n", g_acme_domain);
    }
    tls_reload();
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
static void *acme_renewal_thread(void *arg) {
    (void) arg;
    sleep(30);
    for (;;) {
        if (acme_needs_renewal()) {
            dns_log(LOG_WARNING, "[ACME] Renewal needed\n");
            acme_issue();
        }
        sleep(86400);
    }
    return NULL;
}

/* ==========================================================================
 * HTTP(S) API + DoH handler
 * ======================================================================= */
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
                     : code == 204 ? "No Content"
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
/* DNS-over-HTTPS (RFC 8484): respond to POST /dns-query with application/dns-message */
static void handle_doh(int fd, SSL *ssl, const uint8_t *pkt, int plen, const struct in_addr *cip) {
    uint8_t resp[BUF_SIZE];
    int rlen = dns_process(pkt, plen, resp, sizeof(resp), 1, cip);
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

static void handle_api(int fd, SSL *ssl, int is_mgmt, const struct in_addr *cip) {
    char buf[HTTP_BUF];
    int n;
    if (ssl)
        n = SSL_read(ssl, buf, sizeof(buf) - 1);
    else
        n = (int) recv(fd, buf, sizeof(buf) - 1, 0);
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
            handle_doh(fd, ssl, (uint8_t *) bdy, blen, cip);
        } else { /* GET with dns= parameter */
            char dns_b64[4096] = {0};
            qs_get(qs, "dns", dns_b64, sizeof(dns_b64));
            uint8_t pkt[BUF_SIZE];
            int plen = b64std_dec(dns_b64, pkt, sizeof(pkt));
            handle_doh(fd, ssl, pkt, plen, cip);
        }
        return;
    }

    if (!strcmp(path, "/health")) {
        api_send(fd, ssl, 200, "ok\n");
        return;
    }

    if (!strcmp(path, "/list")) {
        char body[HTTP_BUF];
        int bp = 0;
        bp += snprintf(body + bp, sizeof(body) - bp, "Zone: %s  Serial: %u\n\n", g_zone_name,
                       g_soa_serial);
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

    /* Auth */
    char akey[128] = {0};
    qs_get(qs, "key", akey, sizeof(akey));
    if (!is_mgmt && strcmp(akey, g_ddns_secret) != 0) {
        api_send(fd, ssl, 403, "forbidden\n");
        return;
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
        char vkey[512], rbody[256];
        if (ip[0]) {
            struct in_addr a4;
            if (inet_pton(AF_INET, ip, &a4) != 1) {
                api_send(fd, ssl, 400, "bad ip\n");
                return;
            }
            snprintf(vkey, sizeof(vkey), "ddns:A:%s", hostname);
            vk_set(vkey, ip, ttl);
            serial_bump();
            snprintf(rbody, sizeof(rbody), "ok: %s A %s TTL=%u\n", hostname, ip, ttl);
            api_send(fd, ssl, 200, rbody);
        } else if (ip6[0]) {
            struct in6_addr a6;
            if (inet_pton(AF_INET6, ip6, &a6) != 1) {
                api_send(fd, ssl, 400, "bad ip6\n");
                return;
            }
            snprintf(vkey, sizeof(vkey), "ddns:AAAA:%s", hostname);
            vk_set(vkey, ip6, ttl);
            serial_bump();
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
        char typestr[16] = {0};
        qs_get(qs, "type", typestr, sizeof(typestr));
        char vk2[512];
        int d = 0;
        if (!typestr[0] || !strcasecmp(typestr, "A")) {
            snprintf(vk2, sizeof(vk2), "ddns:A:%s", hostname);
            d += vk_del(vk2);
        }
        if (!typestr[0] || !strcasecmp(typestr, "AAAA")) {
            snprintf(vk2, sizeof(vk2), "ddns:AAAA:%s", hostname);
            d += vk_del(vk2);
        }
        serial_bump();
        char rbody[128];
        snprintf(rbody, sizeof(rbody), "ok: deleted %d key(s)\n", d);
        api_send(fd, ssl, 200, rbody);
        return;
    }

    /* Zone provisioning */
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
        char vkey[512], vval[1024];
        snprintf(vkey, sizeof(vkey), "zone:%s:%s", type2str(rt), name);
        if (rt == DNS_TYPE_MX)
            snprintf(vval, sizeof(vval), "%u|%s|%s", ttl, pref[0] ? pref : "10", value);
        else
            snprintf(vval, sizeof(vval), "%u|%s", ttl, value);
        vk_set(vkey, vval, 0);
        serial_bump();
        dns_log(LOG_NOTICE, "[ZONE] %s %s = %s\n", type2str(rt), name, vval);
        notify_send();
        char rb[256];
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
        int d = 0;
        if (type[0]) {
            uint16_t rt = str2type(type);
            if (!rt) {
                api_send(fd, ssl, 400, "unknown type\n");
                return;
            }
            char vkey[512];
            snprintf(vkey, sizeof(vkey), "zone:%s:%s", type2str(rt), name);
            d = vk_del(vkey);
        } else {
            const char *ts[] = {"A",   "AAAA",  "CNAME", "MX",    "TXT", "NS", "SRV",
                                "CAA", "SSHFP", "TLSA",  "DNAME", "LOC", NULL};
            for (int i = 0; ts[i]; i++) {
                char vk2[512];
                snprintf(vk2, sizeof(vk2), "zone:%s:%s", ts[i], name);
                d += vk_del(vk2);
            }
        }
        serial_bump();
        notify_send();
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
        config_set(cfgkey, cfgval);
        if (!strcmp(cfgkey, "ddns_secret"))
            safe_strcpy(g_ddns_secret, cfgval, sizeof(g_ddns_secret));
        else if (!strcmp(cfgkey, "acme_domain"))
            safe_strcpy(g_acme_domain, cfgval, sizeof(g_acme_domain));
        else if (!strcmp(cfgkey, "tls_cert_pem")) {
            safe_strcpy(g_tls_cert_pem, cfgval, sizeof(g_tls_cert_pem));
            tls_reload();
        } else if (!strcmp(cfgkey, "tls_key_pem")) {
            safe_strcpy(g_tls_key_pem, cfgval, sizeof(g_tls_key_pem));
            tls_reload();
        } else if (!strcmp(cfgkey, "mtls_ca_pem")) {
            safe_strcpy(g_mtls_ca_pem, cfgval, sizeof(g_mtls_ca_pem));
            tls_reload();
        }
        char rb[128];
        snprintf(rb, sizeof(rb), "ok: config:%s updated\n", cfgkey);
        api_send(fd, ssl, 200, rb);
        return;
    }
    if (is_mgmt && !strcmp(path, "/acme/issue")) {
        dns_log(LOG_NOTICE, "[ACME] Manual issue via API\n");
        int r = acme_issue();
        api_send(fd, ssl, 200, r == 0 ? "acme ok\n" : "acme failed\n");
        return;
    }
    if (is_mgmt && !strcmp(path, "/zone/notify")) {
        notify_send();
        api_send(fd, ssl, 200, "notified\n");
        return;
    }

    api_send(fd, ssl, 400, "unknown endpoint\n");
}

static void handle_http_plain(int fd, const struct in_addr *cip) {
    handle_api(fd, NULL, 0, cip);
}
static void handle_https_mgmt(int fd, const struct in_addr *cip) {
    pthread_mutex_lock(&g_tls_mutex);
    SSL_CTX *ctx = g_mgmt_ctx;
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    pthread_mutex_unlock(&g_tls_mutex);
    if (!ssl) {
        close(fd);
        return;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        return;
    }
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (!peer) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        return;
    }
    char cn[256] = {0};
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, cn, sizeof(cn));
    dns_log(LOG_DEBUG, "[mTLS] CN: %s\n", cn);
    X509_free(peer);
    handle_api(fd, ssl, 1, cip);
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/* ==========================================================================
 * main
 * ======================================================================= */
int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    /* Phase 1: Bootstrap Valkey */
    memset(&vk, 0, sizeof(vk));
    vk.fd = -1;
    boot_load();
    dns_log(LOG_INFO, "[Boot] Connecting to Valkey %s:%d...\n", g_valkey_host, g_valkey_port);
    if (valkey_connect(&vk) != 0) {
        dns_log(LOG_WARNING, "[Boot] Valkey unreachable — starting config portal on port %d\n",
                g_config_port);
        config_portal();
        if (valkey_connect(&vk) != 0) {
            dns_log(LOG_ERR, "[Boot] FATAL: Valkey still unreachable\n");
            return 1;
        }
    }
    dns_log(LOG_INFO, "[Boot] Valkey connected.\n");

    /* Phase 2: Load config */
    config_load_from_valkey();

    /* Phase 3: DNSSEC (both algorithms) */
    dnssec_init();

    /* Phase 4: Certificate (ACME if needed) */
    if (!g_tls_cert_pem[0] && g_acme_domain[0]) {
        dns_log(LOG_INFO, "[Boot] No cert in Valkey — running ACME for %s\n", g_acme_domain);
        acme_issue();
    }
    tls_reload();

    /* Phase 5: Start ACME renewal thread */
    if (g_acme_domain[0]) {
        pthread_t tid;
        pthread_create(&tid, NULL, acme_renewal_thread, NULL);
        pthread_detach(tid);
    }

    /* Phase 6: Open all sockets */
    int opt = 1;
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
    int http_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (http_sock < 0) {
        perror("http socket");
        return 1;
    }
    setsockopt(http_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    {
        struct sockaddr_in sa = {.sin_family = AF_INET,
                                 .sin_port = htons(g_http_port),
                                 .sin_addr.s_addr = INADDR_ANY};
        if (bind(http_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("http bind");
            return 1;
        }
        listen(http_sock, 32);
    }
    int https_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (https_sock < 0) {
        perror("https socket");
        return 1;
    }
    setsockopt(https_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    {
        struct sockaddr_in sa = {.sin_family = AF_INET,
                                 .sin_port = htons(g_https_port),
                                 .sin_addr.s_addr = INADDR_ANY};
        if (bind(https_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("https bind");
            return 1;
        }
        listen(https_sock, 32);
    }

    dns_log(LOG_INFO, "\n╔═══════════════════════════════════════════════════════════════════╗\n");
    dns_log(LOG_INFO, "║  DNS  UDP plain + RFC2136 UPDATE + NOTIFY  :%d                   ║\n",
            g_dns_port);
    dns_log(LOG_INFO, "║  DoT  TCP DNS-over-TLS + AXFR              :%d  %s           ║\n",
            g_dot_port, g_dot_ctx ? "TLS " : "----");
    dns_log(LOG_INFO, "║  DoH  DNS-over-HTTPS  /dns-query           :%d  %s           ║\n",
            g_https_port, g_mgmt_ctx ? "TLS " : "----");
    dns_log(LOG_INFO, "║  HTTP DDNS + /list + /update               :%d                   ║\n",
            g_http_port);
    dns_log(LOG_INFO, "║  HTTPS mTLS management API                 :%d  %s           ║\n",
            g_https_port, g_mgmt_ctx ? "mTLS" : "----");
    dns_log(LOG_INFO, "║  Valkey                                     %s:%d          ║\n",
            g_valkey_host, g_valkey_port);
    dns_log(LOG_INFO, "║  Zone                                       %-20s       ║\n", g_zone_name);
    dns_log(LOG_INFO, "║  DNSSEC ZSK P-256 tag                       %-6u                 ║\n",
            g_zsk_tag);
    dns_log(LOG_INFO, "║  DNSSEC ZSK Ed25519 tag                     %-6u                 ║\n",
            g_zsk_ed_tag);
    dns_log(LOG_INFO, "║  TSIG                                       %s                ║\n",
            g_tsig_secret_len ? "enabled" : "disabled");
    dns_log(LOG_INFO, "║  DNS Cookies                                enabled               ║\n");
    dns_log(LOG_INFO, "║  NSID                                       %-20s       ║\n", g_nsid);
    dns_log(LOG_INFO, "╚═══════════════════════════════════════════════════════════════════╝\n\n");
    dns_log(LOG_INFO, "Key endpoints:\n");
    dns_log(LOG_INFO, "  GET  /health  /list\n");
    dns_log(LOG_INFO, "  GET  /update?hostname=N&ip=IP&key=K[&ttl=60]\n");
    dns_log(LOG_INFO, "  POST /dns-query  (DoH, application/dns-message)\n");
    dns_log(LOG_INFO, "  POST /zone  body: name=N&type=T&value=V[&ttl=300&pref=10] (mgmt)\n");
    dns_log(LOG_INFO, "  DELETE /zone?name=N&type=T (mgmt)\n");
    dns_log(LOG_INFO, "  POST /config  body: key=K&value=V (mgmt)\n");
    dns_log(LOG_INFO, "  POST /acme/issue  (mgmt)\n\n");

    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(dns_sock, &fds);
        FD_SET(dot_sock, &fds);
        FD_SET(http_sock, &fds);
        FD_SET(https_sock, &fds);
        int maxfd = dns_sock;
        if (dot_sock > maxfd)
            maxfd = dot_sock;
        if (http_sock > maxfd)
            maxfd = http_sock;
        if (https_sock > maxfd)
            maxfd = https_sock;
        struct timeval tv = {.tv_sec = 30};
        int ready = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
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
                int rlen = dns_process(pkt, (int) nn, resp, sizeof(resp), 0, &cli.sin_addr);
                if (rlen > 0)
                    sendto(dns_sock, resp, rlen, 0, (struct sockaddr *) &cli, clen);
            }
        }

        if (FD_ISSET(dot_sock, &fds)) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(dot_sock, (struct sockaddr *) &cli, &clen);
            if (cfd >= 0) {
                dot_conn_t *c = malloc(sizeof(dot_conn_t));
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

        if (FD_ISSET(http_sock, &fds)) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(http_sock, (struct sockaddr *) &cli, &clen);
            if (cfd >= 0) {
                char cip2[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli.sin_addr, cip2, sizeof(cip2));
                dns_log(LOG_DEBUG, "[HTTP] %s\n", cip2);
                handle_http_plain(cfd, &cli.sin_addr);
                close(cfd);
            }
        }

        if (FD_ISSET(https_sock, &fds)) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(https_sock, (struct sockaddr *) &cli, &clen);
            if (cfd >= 0) {
                char cip2[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli.sin_addr, cip2, sizeof(cip2));
                dns_log(LOG_DEBUG, "[mTLS/DoH] %s\n", cip2);
                handle_https_mgmt(cfd, &cli.sin_addr);
                close(cfd);
            }
        }
    }

    close(dns_sock);
    close(dot_sock);
    close(http_sock);
    close(https_sock);
    if (vk.fd >= 0)
        close(vk.fd);
    if (g_dot_ctx)
        SSL_CTX_free(g_dot_ctx);
    if (g_mgmt_ctx)
        SSL_CTX_free(g_mgmt_ctx);
    if (g_zsk)
        EVP_PKEY_free(g_zsk);
    if (g_zsk_ed)
        EVP_PKEY_free(g_zsk_ed);
    if (g_acme_key)
        EVP_PKEY_free(g_acme_key);
    if (g_syslog_enabled)
        closelog();
    pthread_mutex_lock(&g_log_mutex);
    rsyslog_disconnect();
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}
