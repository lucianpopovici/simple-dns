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
