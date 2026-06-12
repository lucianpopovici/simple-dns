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

void     put16(uint8_t *b, int o, uint16_t v);
void     put32(uint8_t *b, int o, uint32_t v);
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
    int      count;
    uint16_t offsets[128];
    char     names[128][256];
} compress_ctx_t;

void compress_reset(void);

/* Emit name to buf+pos with compression against the thread-local context.
 * abs_off is the absolute message offset where buf+pos lands. Returns bytes
 * written or -1. */
int name_to_wire_c(const char *name, uint8_t *buf, int pos, int blen,
                   int abs_off);

/* Append one resource record. append_rr compresses the owner name against
 * the thread-local context (use in dnsd, where compress_reset() is called per
 * message). append_rr_plain emits the owner uncompressed (no context needed).
 * Both return the new offset or -1; rdata is copied verbatim. */
int append_rr(uint8_t *buf, int off, int blen, const char *name,
              uint16_t type, uint16_t cls, uint32_t ttl,
              const uint8_t *rdata, uint16_t rdlen);
int append_rr_plain(uint8_t *buf, int off, int blen, const char *name,
                    uint16_t type, uint16_t cls, uint32_t ttl,
                    const uint8_t *rdata, uint16_t rdlen);

#endif /* DNS_WIRE_H */
