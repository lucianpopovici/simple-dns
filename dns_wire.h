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
#include <openssl/ssl.h> /* tls_server_ctx_from_pem / dot_alpn_select_cb */

/* ── DNS type constants (RFC 1035 and later) ─────────────────────────────── */

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_SIG 24 /* RFC 2931 §3 — transaction signature (SIG(0)) when type-covered=0 */
#define DNS_TYPE_KEY 25 /* RFC 2535 §3 — public key, reused unchanged by RFC 2931 SIG(0) */
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
#define DNS_CLASS_CH 3 /* RFC 1035 — CHAOS; used for id.server/hostname.bind (RFC 4892) */
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
#define DNS_OPCODE_DSO 0x3000 /* RFC 8490 §5.1 — DNS Stateful Operations */
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
#define DNS_RCODE_DSOTYPENI 11 /* RFC 8490 §5.2 — DSO TLV Type Not Implemented */
#define DNS_RCODE_BADVERS 16
#define DNS_RCODE_BADSIG 17
#define DNS_RCODE_BADCOOKIE 23

/* ── EDNS(0) constants (RFC 6891) ────────────────────────────────────────── */

#define EDNS_MAX_UDP 1232       /* current BCP 2020 recommendation */
#define EDNS_OPT_UPDATE_LEASE 2 /* RFC 9664 — "UL": DNS-SD SRP lease negotiation */
#define EDNS_OPT_NSID 3
#define EDNS_OPT_COOKIE 10
#define EDNS_OPT_KEEPALIVE 11
#define EDNS_OPT_PADDING 12
#define EDNS_OPT_EDE 15
#define EDNS_OPT_REPORT_CHANNEL 18 /* RFC 9567 */
#define EDNS_OPT_ZONEVERSION 19    /* RFC 9660 */
#define EDNS_ZV_TYPE_SOA_SERIAL 0  /* RFC 9660 §3: the only defined VERSION type */

/* Extended DNS Error info codes — RFC 8914 §4 / IANA "Extended DNS Error
 * Codes" registry. Numbering must match the registry exactly; these are sent
 * on the wire to real clients/validators, not just used internally. */
#define EDE_OTHER 0
#define EDE_UNSUPPORTED_DNSKEY_ALG 1
#define EDE_UNSUPPORTED_DS_DIGEST 2
#define EDE_STALE_ANSWER 3
#define EDE_FORGED_ANSWER 4
#define EDE_DNSSEC_INDETERMINATE 5
#define EDE_DNSSEC_BOGUS 6
#define EDE_SIG_EXPIRED 7
#define EDE_SIG_NOT_YET_VALID 8
#define EDE_DNSKEY_MISSING 9
#define EDE_RRSIGS_MISSING 10
#define EDE_NO_ZONE_KEY_BIT_SET 11
#define EDE_NSEC_MISSING 12
#define EDE_CACHED_ERROR 13
#define EDE_NOT_READY 14
#define EDE_BLOCKED 15
#define EDE_CENSORED 16
#define EDE_FILTERED 17
#define EDE_PROHIBITED 18
#define EDE_STALE_NXDOMAIN_ANSWER 19
#define EDE_NOT_AUTHORITATIVE 20
#define EDE_NOT_SUPPORTED 21
#define EDE_NO_REACHABLE_AUTHORITY 22
#define EDE_NETWORK_ERROR 23
#define EDE_INVALID_DATA 24

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
    int zoneversion_req;  /* RFC 9660: client sent OPTION-CODE 19, OPTION-LENGTH 0 */
    int has_update_lease; /* RFC 9664: client sent OPTION-CODE 2 (4 or 8 bytes) */
    uint32_t update_lease;
    int has_update_key_lease; /* set iff the 8-byte variant was sent */
    uint32_t update_key_lease;
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
/* base32hex decode, case-insensitive; returns decoded length or -1 on a
 * non-alphabet character. */
int base32hex_dec(const char *in, uint8_t *out, int outlen);

/* RFC 5155 §5: iterated salted SHA-1 NSEC3 owner hash, raw 20-byte digest
 * (not base32hex-encoded). Shared by dnsd (signing) and resolverd (RFC 8198
 * aggressive-cache gap matching) so the two can never diverge. */
void nsec3_hash_raw(const char *name, const uint8_t *salt, int saltlen, int iters, uint8_t out[20]);

/* ── Generic DNSSEC-algorithm signature verification ─────────────────────────
 * Shared by resolverd (RRSIG validation) and dnsd (RFC 2931 SIG(0) transaction
 * signatures) — both verify the same two algorithms against the same raw
 * (non-DER) 64-byte signature encoding DNSSEC uses; only what counts as
 * "data" differs (canonical RRset vs. a DNS message), which the caller
 * assembles before calling in. */

/* Verify an ECDSA P-256 (alg 13) signature.
 * sig_raw: 64-byte raw R||S (not DER). pubkey_xy: 64-byte X||Y (the DNSKEY/KEY
 * rdata's public-key field, after its 4-byte flags/protocol/algorithm
 * prefix). Returns 1 if valid, 0 otherwise (including on any internal error —
 * fail closed). */
int verify_ecdsa_p256(const uint8_t *sig_raw, const uint8_t *data, int dlen,
                      const uint8_t pubkey_xy[64]);

/* Verify an Ed25519 (alg 15) signature.
 * sig_raw: 64-byte signature. pubkey: 32-byte raw Ed25519 public key. */
int verify_ed25519(const uint8_t *sig_raw, const uint8_t *data, int dlen, const uint8_t pubkey[32]);

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
 *   zv_labels - RFC 9660: label count of the zone that answered, for the
 *             ZONEVERSION option; -1 means "no authoritative zone matched"
 *             and omits the option even if the client requested it (a server
 *             must only echo a version it actually has).
 *   zv_serial - that zone's SOA serial (SOA-SERIAL VERSION type, the only one
 *             this codebase implements); ignored when zv_labels < 0.
 *   report_agent - RFC 9567 §4: dotted domain name of the DNS Error Reporting
 *             agent; NULL/empty omits the Report-Channel option. Unlike EDE,
 *             this is unconditional (not gated on ede_code) — a resolver may
 *             validate a cached RRset, and thus discover an error, well after
 *             the response that carried this option.
 *   has_ul / ul_lease / has_ul_key_lease / ul_key_lease - RFC 9664 §1: the
 *             granted Update Lease option for an SRP registration response
 *             (RFC 9665). has_ul=0 omits the option entirely; has_ul_key_lease
 *             selects the 8-byte (LEASE+KEY-LEASE) vs 4-byte (LEASE only)
 *             wire variant.
 *
 * The correct server cookie is IP-bound (RFC 9018 §4.2): callers must compute
 * it before calling this function and pass the result as scookie. */
int edns_append_opt(uint8_t *buf, int off, int blen, int is_tcp, int do_bit, uint16_t rcode_ext,
                    const edns_info_t *req_ei, const char *nsid, const uint8_t *scookie,
                    int ede_code, const char *ede_text, int zv_labels, uint32_t zv_serial,
                    const char *report_agent, int has_ul, uint32_t ul_lease, int has_ul_key_lease,
                    uint32_t ul_key_lease);

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

/* ── TLS server helpers (DNS-over-TLS, RFC 7858) ─────────────────────────────
 * Shared by dnsd (authoritative DoT/XoT listener) and resolverd (stub-facing
 * DoT listener, RFC 9462 DDR) so the cert-loading and ALPN-selection code —
 * previously a dnsd-only static pair — exists once. */

/* Build a server-role SSL_CTX from in-memory cert+key PEM (TLS 1.2 minimum).
 * ca_pem + verify_client enable mTLS (require and verify a client
 * certificate); pass NULL/0 for a plain server. Returns NULL on any
 * load/parse failure — the caller must fail closed (never start a listener
 * without a context). Does not select ALPN; pair with
 * SSL_CTX_set_alpn_select_cb(ctx, dot_alpn_select_cb, NULL). */
SSL_CTX *tls_server_ctx_from_pem(const char *cert_pem, const char *key_pem, const char *ca_pem,
                                 int verify_client);

/* RFC 7858 §3.2 / RFC 9103 §7.1 ALPN select callback ("dot"). A TLS server
 * that never calls SSL_CTX_set_alpn_select_cb silently sends no ALPN
 * extension at all — SSL_CTX_set_alpn_protos only configures what a
 * *client* offers, and is a no-op on a server SSL_CTX. */
int dot_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg);

/* Split a cert:current blob (certd's output: cert chain + private key PEM,
 * concatenated in either order) into separate cert-chain and key buffers.
 * Shared by dnsd, apid, and mdnsd (each hot-reloads its own TLS listener off
 * cert:current) so the parsing exists once. Returns -1 on malformed input
 * (no key block, no "BEGIN CERTIFICATE", or either output buffer too small);
 * caller must treat that as "no valid cert yet", not partial success. */
int cert_current_split(const char *blob, char *cert_out, size_t cert_sz, char *key_out,
                       size_t key_sz);

/* ── Valkey RESP client + keyspace-notification watcher ──────────────────────
 * Every daemon that talks to Valkey (certd, apid, mdnsd, doqd, resolverd,
 * dns_server.c, and the untracked simple_dns.c) carries its OWN hand-rolled,
 * near-identical copy of a resp_conn_t/resp_fill/resp_readline/.../
 * valkey_connect/valkey_ensure client — the exact "duplicated parser" class
 * CLAUDE.md's Do-NOT list forbids, just never consolidated because each
 * predates libdnswire's split-out. eppd is the first caller of this shared
 * version; repointing the existing daemons at it is a separate, optional
 * follow-up. Named with a vkc_ prefix (not the resp_/valkey_ names those
 * daemons already use for their own copies) specifically so
 * this header can be included by those daemons today without colliding with
 * their own static resp_conn_t/resp_reply_t/resp_fill/... — those are
 * distinct per-TU identifiers until (if ever) a daemon is repointed at this
 * one. One divergence this hoist fixes as a side effect: mdnsd's own copy
 * sized its reply buffer at 4096 bytes (every other copy used 65536, matching
 * VKC_BUF below) — large enough to silently truncate a multi-intermediate-CA
 * cert:current chain read through its own vk_get. The shared version uses
 * the larger size for every caller. */
#define VKC_BUF 65536

typedef struct {
    int fd;
    char rbuf[VKC_BUF];
    int rlen, rpos;
} vkc_conn_t;

typedef struct {
    int type; /* 0 simple-string, 1 error, 2 bulk-string, 3 integer, 4 nil, 5 array */
    long integer;
    char str[VKC_BUF];
    int count;
} vkc_reply_t;

/* Refill c->rbuf from the socket (compacting first). -1 on any recv error
 * (including EOF) — callers must treat that as connection-lost. */
int vkc_fill(vkc_conn_t *c);

/* Read one CRLF-terminated line (the CR is optional/stripped if present).
 * Blocks (via vkc_fill) until a newline arrives or the connection drops. */
int vkc_readline(vkc_conn_t *c, char *out, int olen);

/* Read exactly n bytes plus the trailing CRLF a RESP bulk string carries,
 * discarding the CRLF. Blocks until n+2 bytes are available or the
 * connection drops. */
int vkc_readbytes(vkc_conn_t *c, char *out, int n);

/* Parse one RESP reply into `r`. Bulk strings longer than sizeof(r->str)-1
 * are truncated in r->str but the excess is still drained from the wire
 * (fail-closed framing: never leaves a partial reply for the next call). */
int vkc_parse(vkc_conn_t *c, vkc_reply_t *r);

/* Write `len` bytes, retrying on short writes. -1 on any send error. */
int vkc_send(vkc_conn_t *c, const char *cmd, int len);

/* Encode `argc` string arguments as a RESP array (the client->server command
 * form), send it, and parse the one reply Valkey sends back. */
int vkc_cmd(vkc_conn_t *c, vkc_reply_t *r, int argc, ...);

/* Same encoding as vkc_cmd but does not read a reply — for (P)SUBSCRIBE,
 * whose reply and subsequent push messages are consumed by a read loop
 * instead of a single vkc_parse call. */
int vkc_send_cmd(vkc_conn_t *c, int argc, ...);

/* Open a fresh connection to host:port (closing any existing c->fd first),
 * AUTH if pass is non-empty, then SELECT db 0. -1 on any failure (socket,
 * resolve, connect, or a rejected AUTH). */
int vkc_connect_to(vkc_conn_t *c, const char *host, int port, const char *pass);

/* PING an existing connection; reconnect via vkc_connect_to on any failure
 * (including c->fd < 0, i.e. never connected). The common lazy-connect entry
 * point for a request/reply-style vk_get/vk_set pair. */
int vkc_ensure_to(vkc_conn_t *c, const char *host, int port, const char *pass);

/* Per-key callback for a live keyspace-notification pmessage. `key` has the
 * "__keyspace@<db>__:" channel prefix already stripped — just the Valkey key
 * that changed. */
typedef void (*keyspace_on_key_fn)(const char *key, void *ctx);

/* Full state catch-up, called once right after every (re)connect and before
 * (re)subscribing — so changes made while disconnected are never missed. */
typedef void (*keyspace_catchup_fn)(void *ctx);

typedef void (*vkc_log_fn)(int level, const char *fmt, ...);

/* Config for keyspace_watch_loop — mirrors sandbox_config_t's shape
 * (daemon-scoped config + callback + log fn) rather than a long parameter
 * list. `prefixes` is a NULL-terminated array of key patterns to PSUBSCRIBE
 * (e.g. "cert:current", "config:mdns_*"); `db` is the Valkey DB index
 * (KEYSPACE_DB is 0 everywhere today). */
typedef struct {
    const char *host;
    int port;
    const char *pass;
    int db;
    const char **prefixes;
    keyspace_catchup_fn on_reconnect;
    keyspace_on_key_fn on_key;
    void *ctx;
    vkc_log_fn log;
    const char *tag; /* e.g. "eppd" — prefixes log lines */
} keyspace_watch_config_t;

/* Runs forever: connect, enable keyspace notifications, run on_reconnect,
 * PSUBSCRIBE every prefix, then dispatch each pmessage to on_key. Any
 * disconnect (including a failed PSUBSCRIBE) triggers a capped-backoff
 * reconnect that re-runs on_reconnect, so a Valkey restart neither misses
 * updates nor causes a reconnect storm. Matches the pthread thread-function
 * signature (void *(*)(void *), arg = a keyspace_watch_config_t *) so a
 * caller can pthread_create it directly with no wrapper. Never returns. */
void *keyspace_watch_loop(void *arg);

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
