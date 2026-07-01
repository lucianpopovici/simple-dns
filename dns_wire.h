/* dns_wire.h — libdnswire: the single shared DNS wire-format implementation.
 *
 * Migration Step 1 (CLAUDE.md): these helpers used to exist as three diverging
 * static copies inside dns_server.c, dns_client.c and simple_dns.c. They are
 * now defined once, in dns_wire.c, and linked by every binary. Fix parser
 * bugs HERE, never in a per-binary copy.
 *
 * Conventions (do not weaken):
 *   - Every helper that writes to a caller buffer returns -1 on
 *     overflow/parse error; callers must check before advancing offsets.
 *   - Parsers fail closed on malformed input (truncation, bad compression
 *     pointers, oversized labels).
 */
#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include <stddef.h>
#include <stdint.h>

/* ── DNS type constants (RFC 1035 and later) ─────────────────────────────── */

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_LOC 29
#define DNS_TYPE_SRV 33
#define DNS_TYPE_NAPTR 35
#define DNS_TYPE_DNAME 39
#define DNS_TYPE_OPT 41
#define DNS_TYPE_SSHFP 44
#define DNS_TYPE_DS 43 /* RFC 4034 §5 — delegation signer */
#define DNS_TYPE_RRSIG 46
#define DNS_TYPE_NSEC 47
#define DNS_TYPE_DNSKEY 48
#define DNS_TYPE_NSEC3 50
#define DNS_TYPE_NSEC3PARAM 51
#define DNS_TYPE_TLSA 52
#define DNS_TYPE_CDS 59     /* RFC 7344 — child DS */
#define DNS_TYPE_CDNSKEY 60 /* RFC 7344 — child DNSKEY */
#define DNS_TYPE_CSYNC 62   /* RFC 7477 — child-to-parent synchronisation */
#define DNS_TYPE_ZONEMD 63  /* RFC 8976 — message digest for DNS zones */
#define DNS_TYPE_SVCB 64    /* RFC 9460 — service binding */
#define DNS_TYPE_HTTPS 65   /* RFC 9460 — HTTPS-specific service binding */
#define DNS_TYPE_URI 256    /* RFC 7553 */
#define DNS_TYPE_CAA 257
#define DNS_TYPE_IXFR 251 /* RFC 1995 — incremental zone transfer */
#define DNS_TYPE_AXFR 252 /* RFC 5936 — full zone transfer */
#define DNS_TYPE_ANY 255
#define DNS_TTL_MAX 2147483647u /* RFC 2181 §8 — 2^31-1 */

/* ── DNS class constants ─────────────────────────────────────────────────── */

#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255
#define DNS_CLASS_NONE 254

/* ── DNS header flags / opcode / rcode ───────────────────────────────────── */

#define DNS_QR 0x8000
#define DNS_AA 0x0400
#define DNS_TC 0x0200
#define DNS_RD 0x0100
#define DNS_RA 0x0080 /* Recursion Available */
#define DNS_AD 0x0020 /* RFC 4035 §3.1.6 — Authenticated Data */
#define DNS_RCODE_MASK 0x000F
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
#define DNS_RCODE_NOTAUTH 9 /* RFC 2136 §2.2: not authoritative / not authorized */
#define DNS_RCODE_NOTZONE 10
#define DNS_RCODE_BADVERS 16
#define DNS_RCODE_BADSIG 17
#define DNS_RCODE_BADCOOKIE 23

/* ── EDNS(0) constants (RFC 6891) ────────────────────────────────────────── */

#define EDNS_MAX_UDP 1232 /* current BCP 2020 recommendation */
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

/* ── DNS Cookie constants (RFC 9018) ─────────────────────────────────────── */

#define DNS_COOKIE_CLIENT_LEN 8
#define DNS_COOKIE_SERVER_LEN 16 /* RFC 9018 §4.2: version|reserved|timestamp|hash */
#define DNS_COOKIE_VALIDITY 3600 /* seconds */

/* ── DNSSEC / TSIG constants ─────────────────────────────────────────────── */

#define DNS_ALG_ECDSAP256SHA256 13
#define DNS_ALG_ED25519 15
#define DNS_DNSKEY_FLAG_ZSK 256
#define DNS_DNSKEY_FLAG_KSK 257 /* Secure Entry Point — RFC 3757 */
#define NSEC3_ALG_SHA1 1
/* TSIG time window (RFC 8945 §5.2.3); emitted in both digest input and RDATA
 * — keep every emit site on this constant so they cannot drift. */
#define TSIG_FUDGE 300

/* ── DNS header ──────────────────────────────────────────────────────────── */

typedef struct {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((packed)) dns_hdr_t;

/* ── EDNS parsed OPT fields ──────────────────────────────────────────────── */

typedef struct {
    int present;
    uint16_t max_udp;
    uint8_t version;
    int do_bit;
    uint8_t client_cookie[DNS_COOKIE_CLIENT_LEN];
    int has_client_cookie;
    uint8_t server_cookie[DNS_COOKIE_SERVER_LEN];
    int server_cookie_len;
    int has_server_cookie;
    int nsid_req;
    int has_padding;
    uint16_t padding_req;
    int keepalive_req;
} edns_info_t;

/* ── Small string helpers ────────────────────────────────────────────────── */

/* In-place ASCII lowercase. */
void strlower(char *s);

/* Bounded copy that always NUL-terminates (never use bare strncpy).
 * Pass the real destination size: safe_strcpy(dst, src, sizeof(dst)). */
void safe_strcpy(char *dst, const char *src, size_t dstsz);

/* ── Hex / base64 / base32hex codecs ─────────────────────────────────────── */

/* Lowercase hex; out must hold 2*n+1 bytes. */
void hex_enc(const uint8_t *in, int n, char *out);
/* Returns number of decoded bytes (stops at first non-pair / maxlen). */
int hex_dec(const char *in, uint8_t *out, int maxlen);

/* Standard base64 (RFC 4648 §4) decode; returns decoded length. */
int b64std_dec(const char *in, uint8_t *out, int olen);
/* base64url (RFC 4648 §5, no padding) decode; -1 if input too long. */
int b64url_dec(const char *in, uint8_t *out, int olen);
/* base64url (no padding) encode; returns encoded length. */
int b64url_enc(const uint8_t *in, int ilen, char *out, int olen);

/* base32hex (RFC 4648 §7) encode, uppercase — used for NSEC3 owner names. */
int base32hex_enc(const uint8_t *in, int ilen, char *out, int olen);

/* ── Fixed-width big-endian accessors ────────────────────────────────────── */

void put16(uint8_t *b, int o, uint16_t v);
void put32(uint8_t *b, int o, uint32_t v);
uint16_t get16(const uint8_t *b, int o);
uint32_t get32(const uint8_t *b, int o);

/* ── DNS names ───────────────────────────────────────────────────────────── */

/* Dotted name → uncompressed wire format. Returns wire length or -1. */
int name_to_wire(const char *name, uint8_t *buf, int blen);

/* Wire name at pkt+off → dotted lowercase string. Follows compression
 * pointers; per RFC 1035 §4.1.4 a pointer must target an offset strictly
 * before the pointer itself, otherwise the packet is rejected (-1).
 * Returns the offset just past the name (past the pointer if compressed). */
int name_from_wire(const uint8_t *pkt, int plen, int off, char *out, int olen);

/* TXT rdata: split s into <len><bytes> chunks of ≤255 (RFC 1035 §3.3.14).
 * Returns total rdata length or -1. */
int txt_encode(const char *s, uint8_t *rd, int maxlen);

/* ── Compressing name emission (RFC 1035 §4.1.4) ─────────────────────────── */

/* Per-message compression context: suffixes already emitted and their
 * absolute offsets. The implementation keeps one thread-local context;
 * call compress_reset() at every outgoing-message boundary. */
typedef struct {
    int count;
    uint16_t offsets[128];
    char names[128][256];
} compress_ctx_t;

void compress_reset(void);

/* Emit name to buf+pos with compression against the thread-local context.
 * abs_off is the absolute message offset where buf+pos lands. Returns bytes
 * written or -1. */
int name_to_wire_c(const char *name, uint8_t *buf, int pos, int blen, int abs_off);

/* Append one resource record. append_rr compresses the owner name against
 * the thread-local context (use in dnsd, where compress_reset() is called per
 * message). append_rr_plain emits the owner uncompressed (no context needed).
 * Both return the new offset or -1; rdata is copied verbatim. */
int append_rr(uint8_t *buf, int off, int blen, const char *name, uint16_t type, uint16_t cls,
              uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);
int append_rr_plain(uint8_t *buf, int off, int blen, const char *name, uint16_t type, uint16_t cls,
                    uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);

/* ── DNS type name utilities ─────────────────────────────────────────────── */

/* Return the mnemonic string for a DNS type (e.g. 1 → "A", 28 → "AAAA").
 * Unknown types are returned as "TYPE<n>" in a static buffer (not re-entrant
 * for back-to-back unknown types; callers that need two simultaneous results
 * must copy one first). */
const char *type2str(uint16_t t);

/* Parse a type mnemonic or "TYPE<n>" string into its numeric value.
 * Returns 0 for unrecognised input. */
uint16_t str2type(const char *s);

/* ── RFC 1982 serial-number arithmetic ───────────────────────────────────── */

/* Returns 1 if a < b in serial-number space (RFC 1982 §3.2). */
int serial_lt(uint32_t a, uint32_t b);

/* Returns 1 if a >= b in serial-number space. */
int serial_ge(uint32_t a, uint32_t b);

/* ── EDNS(0) parsing and response building ───────────────────────────────── */

/* Parse the OPT RR from a DNS packet into *ei. If no OPT RR is present,
 * ei->present is left 0 and ei->max_udp is set to 512. */
void edns_parse(const uint8_t *pkt, int plen, edns_info_t *ei);

/* Append an EDNS OPT RR to buf[off..blen) and return the new offset.
 * Returns the unchanged off on overflow (caller can still send a bare response).
 *
 *   nsid    - NSID option value (ASCII); NULL omits the option.
 *   scookie - pre-computed server cookie (DNS_COOKIE_SERVER_LEN bytes);
 *             NULL omits the cookie option. The client cookie is taken from
 *             req_ei->client_cookie when req_ei != NULL and scookie != NULL.
 *   ede_code - RFC 8914 info code; -1 omits the EDE option.
 *
 * The correct server cookie is IP-bound (RFC 9018 §4.2): callers must compute
 * it before calling this function and pass the result as scookie. */
int edns_append_opt(uint8_t *buf, int off, int blen, int is_tcp, int do_bit, uint16_t rcode_ext,
                    const edns_info_t *req_ei, const char *nsid, const uint8_t *scookie,
                    int ede_code, const char *ede_text);

/* ── RFC 4034 §6 canonical-form helpers ──────────────────────────────────── */

/* Write the canonical rdata for an RR of the given type (RFC 4034 §6.2):
 * embedded domain names in name-bearing types are decompressed and lowercased;
 * all other rdata is copied verbatim. Returns the canonical length or -1. */
int canon_rdata(const uint8_t *pkt, int plen, int rdoff, int rdlen, uint16_t rtype, uint8_t *out,
                int outsz);

/* Maximum byte size of one canonicalized RR:
 * owner (255) + type/class/ttl/rdlen (10) + SOA rdata (255+255+20) = 795 → 800 */
#define CANON_RR_MAX 800

typedef struct {
    uint8_t buf[CANON_RR_MAX];
    int len;
} canon_rr_t;

/* Canonical RRset order (RFC 4034 §6.3): compare canonical rdata as
 * left-justified octet sequences; shorter is less when a prefix matches. */
int canon_rr_cmp(const canon_rr_t *a, const canon_rr_t *b);

/* ── Versioned length-prefixed TLV codec (ADR-003 structured values) ──────────
 * The on-Valkey encoding for complex/extensible record values (SVCB SvcParams,
 * NAPTR, ZONEMD, ENUM rules, EPP objects) — everything ADR-003 keeps OUT of the
 * fragile pipe-delimited format. Layout:
 *
 *     blob := version(1) { tag(1) length(2, big-endian) value(length) }*
 *
 * Writers append items left-to-right; readers iterate and SKIP unknown tags, so
 * a new optional field is an additive, backward-compatible change within a major
 * version (a breaking change bumps the blob version and ships a migration). Every
 * call is bounds-checked and returns -1 on overflow / malformed framing — fail
 * closed, never emit or trust a truncated item (same convention as the rest of
 * libdnswire). See the format registry in CLAUDE.md. */

#define TLV_HDR_LEN 3 /* tag(1) + length(2) per item */

/* Begin a blob: write the 1-byte version. Returns the new offset (1) or -1. */
int tlv_begin(uint8_t *buf, int buflen, uint8_t version);

/* Append one item (tag + length-prefixed value). vlen must be 0..65535 and, when
 * > 0, val must be non-NULL. Returns the new offset or -1 on overflow/bad args. */
int tlv_put(uint8_t *buf, int buflen, int off, uint8_t tag, const uint8_t *val, int vlen);

/* Scalar convenience writers (value stored big-endian). Return new offset or -1. */
int tlv_put_u8(uint8_t *buf, int buflen, int off, uint8_t tag, uint8_t v);
int tlv_put_u16(uint8_t *buf, int buflen, int off, uint8_t tag, uint16_t v);
int tlv_put_u32(uint8_t *buf, int buflen, int off, uint8_t tag, uint32_t v);

/* Read the blob version byte. Returns the version (0..255) or -1 if empty. */
int tlv_version(const uint8_t *buf, int buflen);

/* Iterate items. Initialise *off = 1 (just past the version) before the first
 * call. On return 1, the out-params tag/val/vlen describe the next item (val
 * points INTO buf — no copy) and *off advances past it. Returns 0 at a clean end
 * and -1 on malformed framing (truncated header or value running past buflen). */
int tlv_next(const uint8_t *buf, int buflen, int *off, uint8_t *tag, const uint8_t **val,
             uint16_t *vlen);

/* ── RFC 9460 SVCB / HTTPS service binding ────────────────────────────────────
 * SvcParamKeys (IANA registry). */
#define SVCB_KEY_MANDATORY 0
#define SVCB_KEY_ALPN 1
#define SVCB_KEY_NO_DEFAULT_ALPN 2
#define SVCB_KEY_PORT 3
#define SVCB_KEY_IPV4HINT 4
#define SVCB_KEY_ECH 5
#define SVCB_KEY_IPV6HINT 6
#define SVCB_KEY_MAX 6

/* On-Valkey value is a TLV blob (ADR-003 — SvcParams off the pipe delimiter):
 *   SVCB_TLV_PRIORITY(u16)  SVCB_TLV_TARGET(presentation name)
 *   { (SVCB_TLV_PARAM_BASE | key) : SvcParamValue in RFC 9460 wire form }*
 * One param tag per key; svcb_tlv_to_wire emits them ascending by key. */
#define SVCB_TLV_VERSION 1
#define SVCB_TLV_PRIORITY 0x01
#define SVCB_TLV_TARGET 0x02
#define SVCB_TLV_PARAM_BASE 0x10 /* 0x10..0x16 = SvcParamKey 0..6 */

/* Parse RFC 9460 §2.1 zone-file presentation (e.g.
 * "1 svc.example.net. alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1")
 * into a TLV blob. AliasMode (priority 0) carries only the target. Returns the
 * blob length or -1 on malformed input / overflow. Used by the control plane. */
int svcb_present_to_tlv(const char *present, uint8_t *tlv, int cap);

/* Emit RFC 9460 §2.2 rdata (SvcPriority(2) | TargetName | SvcParams sorted by
 * key) from a TLV blob. Returns the rdata length or -1. Used by dnsd. */
int svcb_tlv_to_wire(const uint8_t *tlv, int tlvlen, uint8_t *out, int outcap);

/* ── RFC 8976 ZONEMD (message digest for DNS zones) ───────────────────────────
 * Schemes / hash algorithms (IANA). */
#define ZONEMD_SCHEME_SIMPLE 1
#define ZONEMD_HASH_SHA384 1
#define ZONEMD_HASH_SHA512 2
#define ZONEMD_SHA384_LEN 48
#define ZONEMD_SHA512_LEN 64

/* On-Valkey value is a server-generated TLV blob (ADR-003 — off the pipe
 * delimiter; the variable-length binary digest fits a TLV item cleanly):
 *   ZONEMD_TLV_SERIAL(u32) ZONEMD_TLV_SCHEME(u8) ZONEMD_TLV_HASHALG(u8)
 *   ZONEMD_TLV_DIGEST(bytes) */
#define ZONEMD_TLV_VERSION 1
#define ZONEMD_TLV_SERIAL 0x01
#define ZONEMD_TLV_SCHEME 0x02
#define ZONEMD_TLV_HASHALG 0x03
#define ZONEMD_TLV_DIGEST 0x04

/* Build the ZONEMD TLV blob from components. Returns blob length or -1. */
int zonemd_build_tlv(uint32_t serial, uint8_t scheme, uint8_t hashalg, const uint8_t *digest,
                     int diglen, uint8_t *tlv, int cap);

/* Emit RFC 8976 §2.2 rdata (Serial(4) | Scheme(1) | Hash Algorithm(1) |
 * Digest) from a TLV blob. Returns the rdata length or -1. Used by dnsd. */
int zonemd_tlv_to_wire(const uint8_t *tlv, int tlvlen, uint8_t *out, int outcap);

/* RFC 4034 §6.1 canonical DNS name ordering: compare two presentation names
 * label-by-label from the RIGHT (TLD first), each label octet-wise on the
 * lowercased form. Returns <0, 0, >0 like memcmp. (canon_rr_cmp is a bytewise
 * compare valid only WITHIN one RRset; whole-zone ordering needs this.) */
int canon_name_cmp(const char *a, const char *b);

/* ── RFC 7477 CSYNC (child-to-parent synchronisation, type 62) ───────────────
 * Emit RFC 7477 §2.1 rdata: SOA-serial(4) flags(2) type-bitmap(NSEC format).
 * types_csv: comma-separated type mnemonics to include (e.g. "NS,A,AAAA");
 * types >= 256 are silently ignored (window 0 only).
 * Returns rdata length or -1 on overflow / no buffer. */
int csync_encode_rdata(uint32_t serial, uint16_t flags, const char *types_csv, uint8_t *out,
                       int outsz);

/* ── Schema version contract (ADR-003) ────────────────────────────────────────
 * The Valkey bus is a versioned inter-daemon contract. Daemons compile in the
 * version they speak and compare it against the `schema:version` key at startup.
 * major.minor: a major bump is a breaking change (incompatible — fail closed); a
 * minor bump is additive (compatible — warn). */
#define SCHEMA_VERSION_MAJOR 1
#define SCHEMA_VERSION_MINOR 0
#define SCHEMA_VERSION_STR "1.0"

enum {
    SCHEMA_OK = 0,          /* stored == compiled */
    SCHEMA_MINOR_DIFF = 1,  /* same major, different minor — caller should warn */
    SCHEMA_MAJOR_DIFF = -1, /* incompatible major — caller must fail closed */
    SCHEMA_ABSENT = -2,     /* key empty/missing — caller should seed or assume current */
    SCHEMA_MALFORMED = -3   /* not "major.minor" — caller must fail closed */
};

/* Compare a stored "major.minor" string against the compiled SCHEMA_VERSION.
 * Returns one of the SCHEMA_* codes above (pure function — no I/O). */
int schema_version_check(const char *stored);

#endif /* DNS_WIRE_H */
