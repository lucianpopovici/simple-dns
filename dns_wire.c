/* dns_wire.c — libdnswire implementation. See dns_wire.h for the contract.
 *
 * These bodies are the canonical versions of helpers that previously existed
 * as three static copies (dns_server.c, dns_client.c, simple_dns.c). Behavior
 * is unchanged from those copies, including the -1-on-overflow convention.
 */
#include "dns_wire.h"

#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <arpa/inet.h>   /* inet_pton — RFC 9460 ipv4hint/ipv6hint */
#include <openssl/evp.h> /* nsec3_hash_raw */

/* ── Small string helpers ────────────────────────────────────────────────── */

void strlower(char *s) {
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s += 32;
}

void safe_strcpy(char *dst, const char *src, size_t dstsz) {
    if (dstsz == 0)
        return;
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
}

/* ── Hex ─────────────────────────────────────────────────────────────────── */

void hex_enc(const uint8_t *in, int n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[2 * i] = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 0xF];
    }
    out[2 * n] = 0;
}

int hex_dec(const char *in, uint8_t *out, int maxlen) {
    int n = 0;
    while (in[0] && in[1] && n < maxlen) {
        char h[3] = {in[0], in[1], 0};
        out[n++] = (uint8_t) strtol(h, NULL, 16);
        in += 2;
    }
    return n;
}

/* ── base64 / base64url ──────────────────────────────────────────────────── */

int b64std_dec(const char *in, uint8_t *out, int olen) {
    int inlen = (int) strlen(in), o = 0;
    static const int8_t rev[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62,
        -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 0,  -1, -1, -1, 0,
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
    for (int i = 0; i + 3 < inlen && o + 2 < olen; i += 4) {
#ifdef __clang_analyzer__
        /* The clang static analyzer does not use strlen()'s guarantee that
           in[0..inlen) is initialized, so it false-positives
           ("array subscript is undefined") on the rev[] index reads below.
           Skip the body under analysis only; real builds are unaffected and
           the base64 path is covered by make check-dnssec. */
        break;
#else
        int8_t a = rev[(uint8_t) in[i]], b = rev[(uint8_t) in[i + 1]], c = rev[(uint8_t) in[i + 2]],
               d = rev[(uint8_t) in[i + 3]];
        if (a < 0 || b < 0)
            break;
        out[o++] = (uint8_t) ((a << 2) | (b >> 4));
        if (c >= 0 && o < olen)
            out[o++] = (uint8_t) ((b << 4) | (c >> 2));
        if (d >= 0 && o < olen)
            out[o++] = (uint8_t) ((c << 6) | d);
#endif
    }
    return o;
}

/* RFC 8484 §4.1.1: DoH GET uses base64url (RFC 4648 §5): chars -_ instead of
 * +/, no padding. Translate to standard base64 then call b64std_dec. */
int b64url_dec(const char *in, uint8_t *out, int olen) {
    char tmp[4096];
    int n = (int) strlen(in);
    if (n >= (int) sizeof(tmp) - 4)
        return -1;
    for (int i = 0; i < n; i++) {
        char c = in[i];
        if (c == '-')
            tmp[i] = '+';
        else if (c == '_')
            tmp[i] = '/';
        else
            tmp[i] = c;
    }
    while (n % 4 != 0)
        tmp[n++] = '=';
    tmp[n] = 0;
    return b64std_dec(tmp, out, olen);
}

static const char B64U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int b64url_enc(const uint8_t *in, int ilen, char *out, int olen) {
    int i = 0, o = 0;
    for (; i + 2 < ilen && o + 3 < olen; i += 3) {
        out[o++] = B64U[in[i] >> 2];
        out[o++] = B64U[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = B64U[((in[i + 1] & 0xF) << 2) | (in[i + 2] >> 6)];
        out[o++] = B64U[in[i + 2] & 0x3F];
    }
    if (i < ilen && o + 1 < olen) {
        out[o++] = B64U[in[i] >> 2];
        if (i + 1 < ilen && o + 1 < olen) {
            out[o++] = B64U[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            if (o < olen)
                out[o++] = B64U[(in[i + 1] & 0xF) << 2];
        } else if (o < olen) {
            out[o++] = B64U[(in[i] & 3) << 4];
        }
    }
    if (o < olen)
        out[o] = 0;
    return o;
}

/* ── base32hex (NSEC3 owner names, RFC 4648 §7) ──────────────────────────── */

static const char B32H[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

int base32hex_enc(const uint8_t *in, int ilen, char *out, int olen) {
    int i = 0, o = 0;
    while (i < ilen && o + 7 < olen) {
        uint64_t v = 0;
        int take = ilen - i < 5 ? ilen - i : 5;
        for (int j = 0; j < take; j++)
            v |= (uint64_t) in[i + j] << (32 - j * 8);
        int bits = take * 8;
        for (int j = 0; j < 8 && bits > 0; j++) {
            out[o++] = B32H[(v >> (35 - j * 5)) & 0x1F];
            bits -= 5;
        }
        i += take;
    }
    out[o] = 0;
    return o;
}

static int b32h_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'V')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'v')
        return c - 'a' + 10;
    return -1;
}

int base32hex_dec(const char *in, uint8_t *out, int outlen) {
    int ilen = (int) strlen(in);
    int oi = 0, i = 0;
    while (i < ilen) {
        int take = ilen - i < 8 ? ilen - i : 8;
        uint64_t v = 0;
        for (int j = 0; j < take; j++) {
            int val = b32h_val(in[i + j]);
            if (val < 0)
                return -1;
            v |= (uint64_t) val << (35 - j * 5);
        }
        int obytes;
        switch (take) {
            case 8:
                obytes = 5;
                break;
            case 7:
                obytes = 4;
                break;
            case 5:
                obytes = 3;
                break;
            case 4:
                obytes = 2;
                break;
            case 2:
                obytes = 1;
                break;
            default:
                return -1; /* not a valid base32 group length */
        }
        if (oi + obytes > outlen)
            return -1;
        for (int j = 0; j < obytes; j++)
            out[oi + j] = (uint8_t) ((v >> (32 - j * 8)) & 0xFF);
        oi += obytes;
        i += take;
    }
    return oi;
}

/* ── NSEC3 owner hash (RFC 5155 §5) ──────────────────────────────────────── */

static void wire_sha1(const uint8_t *in, int n, uint8_t out[20]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return;
    unsigned int dl = 20;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, in, n);
    EVP_DigestFinal_ex(ctx, out, &dl);
    EVP_MD_CTX_free(ctx);
}

void nsec3_hash_raw(const char *name, const uint8_t *salt, int saltlen, int iters,
                    uint8_t out[20]) {
    char lname[256];
    safe_strcpy(lname, name, sizeof(lname));
    strlower(lname);
    uint8_t wire[257];
    int wlen = 0;
    /* strtok_r destroys its input, but lname isn't needed again after this
     * loop — tokenize it in place instead of taking a second bounded copy
     * (which GCC's -Wstringop-truncation flags here: with two chained
     * fixed-size safe_strcpy calls it can prove the second copy's source is
     * exactly as long as the destination buffer). */
    char *sp = NULL;
    char *lbl = strtok_r(lname, ".", &sp);
    while (lbl) {
        int ll = (int) strlen(lbl);
        if (ll > 63 || wlen + ll + 1 > 255)
            break; /* enforce label and total limits */
        wire[wlen++] = (uint8_t) ll;
        memcpy(wire + wlen, lbl, ll);
        wlen += ll;
        lbl = strtok_r(NULL, ".", &sp);
    }
    if (wlen < 256)
        wire[wlen++] = 0; /* root label */
    /* Iterative SHA-1: H(x) = SHA-1(x || salt), repeated iters+1 times */
    uint8_t h[20];
    uint8_t ibuf[256 + 64];
    int iblen = wlen;
    memcpy(ibuf, wire, wlen);
    if (saltlen > 0)
        memcpy(ibuf + wlen, salt, saltlen);
    iblen += saltlen;
    wire_sha1(ibuf, iblen, h);
    for (int i = 0; i < iters; i++) {
        memcpy(ibuf, h, 20);
        if (saltlen > 0)
            memcpy(ibuf + 20, salt, saltlen);
        wire_sha1(ibuf, 20 + saltlen, h);
    }
    memcpy(out, h, 20);
}

/* ── Fixed-width big-endian accessors ────────────────────────────────────── */

void put16(uint8_t *b, int o, uint16_t v) {
    b[o] = v >> 8;
    b[o + 1] = v & 0xFF;
}

void put32(uint8_t *b, int o, uint32_t v) {
    b[o] = v >> 24;
    b[o + 1] = (v >> 16) & 0xFF;
    b[o + 2] = (v >> 8) & 0xFF;
    b[o + 3] = v & 0xFF;
}

uint16_t get16(const uint8_t *b, int o) {
    return ((uint16_t) b[o] << 8) | b[o + 1];
}

uint32_t get32(const uint8_t *b, int o) {
    return ((uint32_t) b[o] << 24) | ((uint32_t) b[o + 1] << 16) | ((uint32_t) b[o + 2] << 8) |
           b[o + 3];
}

/* ── DNS names ───────────────────────────────────────────────────────────── */

/* A trailing dot needs no special handling: strtok_r treats consecutive and
 * trailing delimiters as one, so "a.b." tokenizes identically to "a.b". */
int name_to_wire(const char *name, uint8_t *buf, int blen) {
    int pos = 0;
    char tmp[256];
    safe_strcpy(tmp, name, sizeof(tmp));
    char *saveptr = NULL;
    char *lbl = strtok_r(tmp, ".", &saveptr);
    while (lbl) {
        int ll = (int) strlen(lbl);
        /* RFC 1035 §3.1: a label length octet must be <= 63 — a longer one
         * collides with the 0xC0 compression-pointer marker on re-parse. */
        if (ll > 63)
            return -1;
        if (pos + ll + 1 >= blen)
            return -1;
        buf[pos++] = (uint8_t) ll;
        memcpy(buf + pos, lbl, ll);
        pos += ll;
        lbl = strtok_r(NULL, ".", &saveptr);
    }
    if (pos >= blen)
        return -1;
    buf[pos++] = 0;
    return pos;
}

int name_from_wire(const uint8_t *pkt, int plen, int off, char *out, int olen) {
    int pos = off, opos = 0, jumped = 0, jret = -1, steps = 0;
    while (steps++ < 128) {
        if (pos >= plen)
            return -1;
        uint8_t c = pkt[pos];
        if ((c & 0xC0) == 0xC0) {
            if (pos + 1 >= plen)
                return -1;
            int ptr = ((c & 0x3F) << 8) | pkt[pos + 1];
            /* RFC 1035 §4.1.4: a pointer may only target a PRIOR occurrence,
             * i.e. strictly before the pointer itself. Forward/self targets
             * are malformed and enable loops; the steps cap stays as a
             * backstop. */
            if (ptr >= pos)
                return -1;
            if (!jumped) {
                jret = pos + 2;
                jumped = 1;
            }
            pos = ptr;
            continue;
        }
        if (c == 0) {
            pos++;
            break;
        }
        int ll = c;
        pos++;
        if (pos + ll > plen || opos + ll + 1 >= olen)
            return -1;
        if (opos)
            out[opos++] = '.';
        memcpy(out + opos, pkt + pos, ll);
        opos += ll;
        pos += ll;
    }
    out[opos] = 0;
    strlower(out);
    return jumped ? jret : pos;
}

/* RFC 1035 §3.3.14: TXT rdata is one or more <len><bytes> character strings,
 * each up to 255 bytes. Splits s across as many chunks as needed and writes
 * them back-to-back. Returns total rdata length, or -1 on overflow. */
int txt_encode(const char *s, uint8_t *rd, int maxlen) {
    int slen = (int) strlen(s), out = 0;
    while (slen > 0) {
        int chunk = slen > 255 ? 255 : slen;
        if (out + 1 + chunk > maxlen)
            return -1;
        rd[out++] = (uint8_t) chunk;
        memcpy(rd + out, s, chunk);
        out += chunk;
        s += chunk;
        slen -= chunk;
    }
    return out;
}

/* ── Compressing name emission ───────────────────────────────────────────── */

/* RFC 1035 §4.1.4 DNS name compression.
 *
 * Per-response context tracks suffixes already emitted into the message and
 * the absolute byte offset of each, so subsequent names that share a suffix
 * can be replaced with a 2-byte back-pointer (0xC000 | offset).
 *
 * One context per outgoing DNS message; held in a thread-local so emit
 * helpers like append_rr don't need a new parameter. Callers reset the
 * context at every message boundary (build_query_resp, AXFR message, NOTIFY,
 * mDNS). Pointer offsets are 14-bit (max 0x3FFF) — the lookup-and-register
 * code below silently skips registration past that boundary, so names emitted
 * deep in a >16KB message simply won't be compression sources.
 *
 * Compression is only safe where the spec permits it. RRSIG signer's name
 * (RFC 4034 §3.1.7) and a few NSEC next-owner contexts must remain
 * uncompressed; those paths construct rdata via name_to_wire (uncompressed)
 * and not via append_rr's owner-name emit, so they stay correct. */
static __thread compress_ctx_t g_cc;

void compress_reset(void) {
    g_cc.count = 0;
}

/* Emit `name` to buf+pos using g_cc. `abs_off` is the absolute byte offset
 * inside the final DNS message where buf+pos lands — required so registered
 * pointers can be looked up by subsequent names. For owner-name emission
 * into the response buffer, buf=resp, pos=off, abs_off=off (they coincide). */
int name_to_wire_c(const char *name, uint8_t *buf, int pos, int blen, int abs_off) {
    char work[256];
    safe_strcpy(work, name, sizeof(work));
    char *labels[64];
    int nlabels = 0;
    char *saveptr = NULL;
    for (char *lbl = strtok_r(work, ".", &saveptr); lbl && nlabels < 64;
         lbl = strtok_r(NULL, ".", &saveptr))
        labels[nlabels++] = lbl;
    int start = pos;
    for (int i = 0; i < nlabels; i++) {
        /* Compose suffix from label i onward */
        char suffix[256];
        int sp = 0;
        for (int j = i; j < nlabels; j++) {
            int ll = (int) strlen(labels[j]);
            if (sp + ll + 1 >= (int) sizeof(suffix))
                break;
            if (j > i)
                suffix[sp++] = '.';
            memcpy(suffix + sp, labels[j], ll);
            sp += ll;
        }
        suffix[sp] = 0;
        /* Lookup existing offset */
        for (int k = 0; k < g_cc.count; k++) {
            if (strcasecmp(g_cc.names[k], suffix) == 0) {
                if (pos + 2 > blen)
                    return -1;
                buf[pos++] = 0xC0 | (g_cc.offsets[k] >> 8);
                buf[pos++] = g_cc.offsets[k] & 0xFF;
                return pos - start;
            }
        }
        /* Register this suffix at its absolute offset (14-bit max) */
        int suffix_abs = abs_off + (pos - start);
        if (g_cc.count < 128 && suffix_abs < 0x4000) {
            g_cc.offsets[g_cc.count] = (uint16_t) suffix_abs;
            safe_strcpy(g_cc.names[g_cc.count], suffix, sizeof(g_cc.names[g_cc.count]));
            g_cc.count++;
        }
        /* Emit this label */
        int ll = (int) strlen(labels[i]);
        if (ll > 63) /* RFC 1035 §3.1: label length octet must be <= 63 */
            return -1;
        if (pos + ll + 1 >= blen)
            return -1;
        buf[pos++] = (uint8_t) ll;
        memcpy(buf + pos, labels[i], ll);
        pos += ll;
    }
    if (pos >= blen)
        return -1;
    buf[pos++] = 0;
    return pos - start;
}

int append_rr(uint8_t *buf, int off, int blen, const char *name, uint16_t type, uint16_t cls,
              uint32_t ttl, const uint8_t *rdata, uint16_t rdlen) {
    /* Owner name uses compression (RFC 1035 §4.1.4); rdata is copied verbatim,
     * so any names inside rdata were already encoded by their builder. */
    int n = name_to_wire_c(name, buf, off, blen, off);
    if (n < 0 || off + n + 10 + (int) rdlen > blen)
        return -1;
    off += n;
    put16(buf, off, type);
    off += 2;
    put16(buf, off, cls);
    off += 2;
    put32(buf, off, ttl);
    off += 4;
    put16(buf, off, rdlen);
    off += 2;
    if (rdlen)
        memcpy(buf + off, rdata, rdlen);
    return off + rdlen;
}

int append_rr_plain(uint8_t *buf, int off, int blen, const char *name, uint16_t type, uint16_t cls,
                    uint32_t ttl, const uint8_t *rdata, uint16_t rdlen) {
    int n = name_to_wire(name, buf + off, blen - off);
    if (n < 0 || off + n + 10 + (int) rdlen > blen)
        return -1;
    off += n;
    put16(buf, off, type);
    off += 2;
    put16(buf, off, cls);
    off += 2;
    put32(buf, off, ttl);
    off += 4;
    put16(buf, off, rdlen);
    off += 2;
    if (rdlen)
        memcpy(buf + off, rdata, rdlen);
    return off + rdlen;
}

/* ── Versioned length-prefixed TLV codec (ADR-003 structured values) ───────────
 * See dns_wire.h for the format and rationale. Every function is bounds-checked
 * and fails closed (-1) on overflow or malformed framing. */

int tlv_begin(uint8_t *buf, int buflen, uint8_t version) {
    if (!buf || buflen < 1)
        return -1;
    buf[0] = version;
    return 1;
}

int tlv_put(uint8_t *buf, int buflen, int off, uint8_t tag, const uint8_t *val, int vlen) {
    if (!buf || off < 0 || vlen < 0 || vlen > 0xFFFF)
        return -1;
    if (vlen > 0 && !val)
        return -1;
    if (off + TLV_HDR_LEN + vlen > buflen)
        return -1;
    buf[off] = tag;
    put16(buf, off + 1, (uint16_t) vlen);
    if (vlen > 0)
        memcpy(buf + off + TLV_HDR_LEN, val, (size_t) vlen);
    return off + TLV_HDR_LEN + vlen;
}

int tlv_put_u8(uint8_t *buf, int buflen, int off, uint8_t tag, uint8_t v) {
    return tlv_put(buf, buflen, off, tag, &v, 1);
}

int tlv_put_u16(uint8_t *buf, int buflen, int off, uint8_t tag, uint16_t v) {
    uint8_t b[2];
    put16(b, 0, v);
    return tlv_put(buf, buflen, off, tag, b, 2);
}

int tlv_put_u32(uint8_t *buf, int buflen, int off, uint8_t tag, uint32_t v) {
    uint8_t b[4];
    put32(b, 0, v);
    return tlv_put(buf, buflen, off, tag, b, 4);
}

int tlv_version(const uint8_t *buf, int buflen) {
    if (!buf || buflen < 1)
        return -1;
    return buf[0];
}

int tlv_next(const uint8_t *buf, int buflen, int *off, uint8_t *tag, const uint8_t **val,
             uint16_t *vlen) {
    if (!buf || !off || *off < 0)
        return -1;
    if (*off == buflen)
        return 0; /* clean end of blob */
    if (*off + TLV_HDR_LEN > buflen)
        return -1; /* truncated item header */
    uint8_t t = buf[*off];
    uint16_t l = get16(buf, *off + 1);
    if (*off + TLV_HDR_LEN + (int) l > buflen)
        return -1; /* value runs past the buffer */
    if (tag)
        *tag = t;
    if (val)
        *val = buf + *off + TLV_HDR_LEN;
    if (vlen)
        *vlen = l;
    *off += TLV_HDR_LEN + (int) l;
    return 1;
}

/* ── RFC 9460 SVCB/HTTPS codec (TLV schema documented in dns_wire.h) ───────── */

/* Map a SvcParamKey presentation name to its number (known keys only). Returns
 * -1 for unknown / generic keyNNNNN (unsupported in this version). */
static int svcb_keyname(const char *s) {
    if (!strcasecmp(s, "mandatory"))
        return SVCB_KEY_MANDATORY;
    if (!strcasecmp(s, "alpn"))
        return SVCB_KEY_ALPN;
    if (!strcasecmp(s, "no-default-alpn"))
        return SVCB_KEY_NO_DEFAULT_ALPN;
    if (!strcasecmp(s, "port"))
        return SVCB_KEY_PORT;
    if (!strcasecmp(s, "ipv4hint"))
        return SVCB_KEY_IPV4HINT;
    if (!strcasecmp(s, "ech"))
        return SVCB_KEY_ECH;
    if (!strcasecmp(s, "ipv6hint"))
        return SVCB_KEY_IPV6HINT;
    return -1;
}

/* Build the RFC 9460 wire value for one SvcParam and store it as a TLV item.
 * `value` is the presentation value (NULL for a valueless key). */
static int svcb_param_to_tlv(uint8_t *tlv, int cap, int off, int key, const char *value) {
    uint8_t v[512];
    int vl = 0;
    char tmp[512];
    char *sp = NULL, *t;
    switch (key) {
        case SVCB_KEY_NO_DEFAULT_ALPN:
            vl = 0; /* valueless */
            break;
        case SVCB_KEY_ALPN:
            if (!value)
                return -1;
            safe_strcpy(tmp, value, sizeof(tmp));
            for (t = strtok_r(tmp, ",", &sp); t; t = strtok_r(NULL, ",", &sp)) {
                int l = (int) strlen(t);
                if (l < 1 || l > 255 || vl + 1 + l > (int) sizeof(v))
                    return -1;
                v[vl++] = (uint8_t) l;
                memcpy(v + vl, t, (size_t) l);
                vl += l;
            }
            if (vl == 0)
                return -1;
            break;
        case SVCB_KEY_PORT: {
            if (!value)
                return -1;
            char *end = NULL;
            long p = strtol(value, &end, 10);
            if (end == value || *end || p < 0 || p > 65535)
                return -1;
            v[0] = (uint8_t) (p >> 8);
            v[1] = (uint8_t) (p & 0xFF);
            vl = 2;
            break;
        }
        case SVCB_KEY_IPV4HINT:
            if (!value)
                return -1;
            safe_strcpy(tmp, value, sizeof(tmp));
            for (t = strtok_r(tmp, ",", &sp); t; t = strtok_r(NULL, ",", &sp)) {
                if (vl + 4 > (int) sizeof(v) || inet_pton(AF_INET, t, v + vl) != 1)
                    return -1;
                vl += 4;
            }
            if (vl == 0)
                return -1;
            break;
        case SVCB_KEY_IPV6HINT:
            if (!value)
                return -1;
            safe_strcpy(tmp, value, sizeof(tmp));
            for (t = strtok_r(tmp, ",", &sp); t; t = strtok_r(NULL, ",", &sp)) {
                if (vl + 16 > (int) sizeof(v) || inet_pton(AF_INET6, t, v + vl) != 1)
                    return -1;
                vl += 16;
            }
            if (vl == 0)
                return -1;
            break;
        case SVCB_KEY_ECH: {
            if (!value)
                return -1;
            int dl = b64std_dec(value, v, sizeof(v));
            if (dl < 0)
                return -1;
            vl = dl;
            break;
        }
        case SVCB_KEY_MANDATORY:
            if (!value)
                return -1;
            safe_strcpy(tmp, value, sizeof(tmp));
            for (t = strtok_r(tmp, ",", &sp); t; t = strtok_r(NULL, ",", &sp)) {
                int mk = svcb_keyname(t);
                if (mk < 0 || vl + 2 > (int) sizeof(v))
                    return -1;
                v[vl++] = (uint8_t) (mk >> 8);
                v[vl++] = (uint8_t) (mk & 0xFF);
            }
            if (vl == 0)
                return -1;
            break;
        default:
            return -1;
    }
    return tlv_put(tlv, cap, off, (uint8_t) (SVCB_TLV_PARAM_BASE + key), vl ? v : NULL, vl);
}

int svcb_present_to_tlv(const char *present, uint8_t *tlv, int cap) {
    char work[1024];
    safe_strcpy(work, present, sizeof(work));
    char *sp = NULL;
    char *tok = strtok_r(work, " \t", &sp);
    if (!tok)
        return -1;
    char *end = NULL;
    long prio = strtol(tok, &end, 10);
    if (end == tok || *end || prio < 0 || prio > 65535)
        return -1;
    char *target = strtok_r(NULL, " \t", &sp);
    if (!target)
        return -1;
    int off = tlv_begin(tlv, cap, SVCB_TLV_VERSION);
    if (off < 0)
        return -1;
    off = tlv_put_u16(tlv, cap, off, SVCB_TLV_PRIORITY, (uint16_t) prio);
    if (off < 0)
        return -1;
    off = tlv_put(tlv, cap, off, SVCB_TLV_TARGET, (const uint8_t *) target, (int) strlen(target));
    if (off < 0)
        return -1;
    int seen[SVCB_KEY_MAX + 1] = {0};
    for (char *kv = strtok_r(NULL, " \t", &sp); kv; kv = strtok_r(NULL, " \t", &sp)) {
        char *eq = strchr(kv, '=');
        const char *value = NULL;
        if (eq) {
            *eq = 0;
            value = eq + 1;
        }
        int key = svcb_keyname(kv);
        if (key < 0 || seen[key]) /* unknown or duplicate SvcParamKey */
            return -1;
        if (prio == 0) /* AliasMode carries no SvcParams (RFC 9460 §2.4.2) */
            return -1;
        seen[key] = 1;
        off = svcb_param_to_tlv(tlv, cap, off, key, value);
        if (off < 0)
            return -1;
    }
    return off;
}

int svcb_tlv_to_wire(const uint8_t *tlv, int tlvlen, uint8_t *out, int outcap) {
    if (tlv_version(tlv, tlvlen) != SVCB_TLV_VERSION)
        return -1;
    int prio = -1;
    char target[256] = "";
    const uint8_t *pval[SVCB_KEY_MAX + 1] = {0};
    int plen[SVCB_KEY_MAX + 1] = {0};
    int has[SVCB_KEY_MAX + 1] = {0};
    int off = 1;
    uint8_t tag;
    const uint8_t *val;
    uint16_t vlen;
    int rc;
    while ((rc = tlv_next(tlv, tlvlen, &off, &tag, &val, &vlen)) == 1) {
        if (tag == SVCB_TLV_PRIORITY) {
            if (vlen != 2)
                return -1;
            prio = (val[0] << 8) | val[1];
        } else if (tag == SVCB_TLV_TARGET) {
            if (vlen >= (uint16_t) sizeof(target))
                return -1;
            memcpy(target, val, vlen);
            target[vlen] = 0;
        } else if (tag >= SVCB_TLV_PARAM_BASE && tag <= SVCB_TLV_PARAM_BASE + SVCB_KEY_MAX) {
            int key = tag - SVCB_TLV_PARAM_BASE;
            pval[key] = val;
            plen[key] = vlen;
            has[key] = 1;
        }
        /* unknown tag → skip (additive forward-compat) */
    }
    if (rc < 0 || prio < 0)
        return -1;
    int o = 0;
    if (o + 2 > outcap)
        return -1;
    out[o++] = (uint8_t) (prio >> 8);
    out[o++] = (uint8_t) (prio & 0xFF);
    /* TargetName is uncompressed (RFC 9460 §2.2); "." (root) is valid. */
    int n = name_to_wire(target[0] ? target : ".", out + o, outcap - o);
    if (n < 0)
        return -1;
    o += n;
    /* SvcParams MUST appear in ascending key order with no duplicates
     * (RFC 9460 §2.2); iterating keys 0..MAX yields exactly that. */
    for (int key = 0; key <= SVCB_KEY_MAX; key++) {
        if (!has[key])
            continue;
        if (o + 4 + plen[key] > outcap)
            return -1;
        out[o++] = (uint8_t) (key >> 8);
        out[o++] = (uint8_t) (key & 0xFF);
        out[o++] = (uint8_t) (plen[key] >> 8);
        out[o++] = (uint8_t) (plen[key] & 0xFF);
        if (plen[key] > 0) {
            memcpy(out + o, pval[key], (size_t) plen[key]);
            o += plen[key];
        }
    }
    return o;
}

/* ── RFC 8976 ZONEMD codec (TLV schema documented in dns_wire.h) ───────────── */

int zonemd_build_tlv(uint32_t serial, uint8_t scheme, uint8_t hashalg, const uint8_t *digest,
                     int diglen, uint8_t *tlv, int cap) {
    if (diglen < 0 || !digest)
        return -1;
    int off = tlv_begin(tlv, cap, ZONEMD_TLV_VERSION);
    if (off < 0)
        return -1;
    off = tlv_put_u32(tlv, cap, off, ZONEMD_TLV_SERIAL, serial);
    if (off < 0)
        return -1;
    off = tlv_put_u8(tlv, cap, off, ZONEMD_TLV_SCHEME, scheme);
    if (off < 0)
        return -1;
    off = tlv_put_u8(tlv, cap, off, ZONEMD_TLV_HASHALG, hashalg);
    if (off < 0)
        return -1;
    off = tlv_put(tlv, cap, off, ZONEMD_TLV_DIGEST, digest, diglen);
    return off;
}

int zonemd_tlv_to_wire(const uint8_t *tlv, int tlvlen, uint8_t *out, int outcap) {
    if (tlv_version(tlv, tlvlen) != ZONEMD_TLV_VERSION)
        return -1;
    int have_serial = 0, have_scheme = 0, have_hashalg = 0, have_digest = 0;
    uint32_t serial = 0;
    uint8_t scheme = 0, hashalg = 0;
    const uint8_t *digest = NULL;
    uint16_t diglen = 0;
    int off = 1;
    uint8_t tag;
    const uint8_t *val;
    uint16_t vlen;
    int rc;
    while ((rc = tlv_next(tlv, tlvlen, &off, &tag, &val, &vlen)) == 1) {
        if (tag == ZONEMD_TLV_SERIAL) {
            if (vlen != 4)
                return -1;
            serial = ((uint32_t) val[0] << 24) | ((uint32_t) val[1] << 16) |
                     ((uint32_t) val[2] << 8) | val[3];
            have_serial = 1;
        } else if (tag == ZONEMD_TLV_SCHEME) {
            if (vlen != 1)
                return -1;
            scheme = val[0];
            have_scheme = 1;
        } else if (tag == ZONEMD_TLV_HASHALG) {
            if (vlen != 1)
                return -1;
            hashalg = val[0];
            have_hashalg = 1;
        } else if (tag == ZONEMD_TLV_DIGEST) {
            digest = val;
            diglen = vlen;
            have_digest = 1;
        }
        /* unknown tag → skip (additive forward-compat) */
    }
    if (rc < 0 || !have_serial || !have_scheme || !have_hashalg || !have_digest)
        return -1;
    if (6 + (int) diglen > outcap)
        return -1;
    int o = 0;
    out[o++] = (uint8_t) (serial >> 24);
    out[o++] = (uint8_t) (serial >> 16);
    out[o++] = (uint8_t) (serial >> 8);
    out[o++] = (uint8_t) (serial & 0xFF);
    out[o++] = scheme;
    out[o++] = hashalg;
    if (diglen > 0) {
        memcpy(out + o, digest, diglen);
        o += diglen;
    }
    return o;
}

/* ── RFC 7477 CSYNC rdata encoder ─────────────────────────────────────────── */

int csync_encode_rdata(uint32_t serial, uint16_t flags, const char *types_csv, uint8_t *out,
                       int outsz) {
    if (outsz < 6)
        return -1;
    out[0] = (uint8_t) (serial >> 24);
    out[1] = (uint8_t) (serial >> 16);
    out[2] = (uint8_t) (serial >> 8);
    out[3] = (uint8_t) serial;
    out[4] = (uint8_t) (flags >> 8);
    out[5] = (uint8_t) flags;
    /* Type bitmap: NSEC window-block format, window 0 only (all CSYNC types < 256). */
    uint8_t bitmap[32] = {0};
    int max_bit = -1;
    char buf[256];
    safe_strcpy(buf, types_csv ? types_csv : "", sizeof(buf));
    char *sp = NULL;
    for (char *tn = strtok_r(buf, ",", &sp); tn; tn = strtok_r(NULL, ",", &sp)) {
        uint16_t t = str2type(tn);
        if (t == 0 || t >= 256)
            continue;
        bitmap[t / 8] |= (uint8_t) (0x80u >> (t % 8));
        if ((int) t > max_bit)
            max_bit = (int) t;
    }
    int blen = (max_bit >= 0) ? (max_bit / 8 + 1) : 0;
    if (outsz < 6 + (blen > 0 ? 2 + blen : 0))
        return -1;
    int pos = 6;
    if (blen > 0) {
        out[pos++] = 0; /* window block 0 */
        out[pos++] = (uint8_t) blen;
        memcpy(out + pos, bitmap, blen);
        pos += blen;
    }
    return pos;
}

/* RFC 4034 §6.1 canonical name ordering — compare label-by-label from the right
 * (TLD first), each label octet-wise on its lowercased form. */
int canon_name_cmp(const char *a, const char *b) {
    /* Split into labels (root "." → zero labels). */
    char na[256], nb[256];
    safe_strcpy(na, a, sizeof(na));
    safe_strcpy(nb, b, sizeof(nb));
    strlower(na);
    strlower(nb);
    const char *la[128];
    const char *lb[128];
    int ca = 0, cb = 0;
    char *sp = NULL, *t;
    for (t = strtok_r(na, ".", &sp); t && ca < 128; t = strtok_r(NULL, ".", &sp))
        la[ca++] = t;
    sp = NULL;
    for (t = strtok_r(nb, ".", &sp); t && cb < 128; t = strtok_r(NULL, ".", &sp))
        lb[cb++] = t;
    /* Walk from the least significant (rightmost) label toward the root. */
    int ia = ca - 1, ib = cb - 1;
    while (ia >= 0 && ib >= 0) {
        const char *sa = la[ia];
        const char *sb = lb[ib];
        size_t lena = strlen(sa), lenb = strlen(sb);
        size_t min = lena < lenb ? lena : lenb;
        int c = memcmp(sa, sb, min);
        if (c)
            return c;
        if (lena != lenb)
            return lena < lenb ? -1 : 1;
        ia--;
        ib--;
    }
    /* Shared suffix equal: the name with fewer labels sorts first. */
    return (ca - cb);
}

/* ── DNS type name utilities ─────────────────────────────────────────────── */

const char *type2str(uint16_t t) {
    switch (t) {
        case DNS_TYPE_A:
            return "A";
        case DNS_TYPE_NS:
            return "NS";
        case DNS_TYPE_CNAME:
            return "CNAME";
        case DNS_TYPE_SOA:
            return "SOA";
        case DNS_TYPE_PTR:
            return "PTR";
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
        case DNS_TYPE_NAPTR:
            return "NAPTR";
        case DNS_TYPE_DNAME:
            return "DNAME";
        case DNS_TYPE_SSHFP:
            return "SSHFP";
        case DNS_TYPE_DS:
            return "DS";
        case DNS_TYPE_RRSIG:
            return "RRSIG";
        case DNS_TYPE_NSEC:
            return "NSEC";
        case DNS_TYPE_DNSKEY:
            return "DNSKEY";
        case DNS_TYPE_NSEC3:
            return "NSEC3";
        case DNS_TYPE_NSEC3PARAM:
            return "NSEC3PARAM";
        case DNS_TYPE_TLSA:
            return "TLSA";
        case DNS_TYPE_CDS:
            return "CDS";
        case DNS_TYPE_CDNSKEY:
            return "CDNSKEY";
        case DNS_TYPE_CSYNC:
            return "CSYNC";
        case DNS_TYPE_ZONEMD:
            return "ZONEMD";
        case DNS_TYPE_SVCB:
            return "SVCB";
        case DNS_TYPE_HTTPS:
            return "HTTPS";
        case DNS_TYPE_URI:
            return "URI";
        case DNS_TYPE_CAA:
            return "CAA";
        case DNS_TYPE_IXFR:
            return "IXFR";
        case DNS_TYPE_AXFR:
            return "AXFR";
        case DNS_TYPE_ANY:
            return "ANY";
        default: {
            static char buf[12];
            snprintf(buf, sizeof(buf), "TYPE%u", (unsigned) t);
            return buf;
        }
    }
}

uint16_t str2type(const char *s) {
    if (!strcasecmp(s, "A"))
        return DNS_TYPE_A;
    if (!strcasecmp(s, "NS"))
        return DNS_TYPE_NS;
    if (!strcasecmp(s, "CNAME"))
        return DNS_TYPE_CNAME;
    if (!strcasecmp(s, "SOA"))
        return DNS_TYPE_SOA;
    if (!strcasecmp(s, "PTR"))
        return DNS_TYPE_PTR;
    if (!strcasecmp(s, "MX"))
        return DNS_TYPE_MX;
    if (!strcasecmp(s, "TXT"))
        return DNS_TYPE_TXT;
    if (!strcasecmp(s, "AAAA"))
        return DNS_TYPE_AAAA;
    if (!strcasecmp(s, "LOC"))
        return DNS_TYPE_LOC;
    if (!strcasecmp(s, "SRV"))
        return DNS_TYPE_SRV;
    if (!strcasecmp(s, "NAPTR"))
        return DNS_TYPE_NAPTR;
    if (!strcasecmp(s, "DNAME"))
        return DNS_TYPE_DNAME;
    if (!strcasecmp(s, "SSHFP"))
        return DNS_TYPE_SSHFP;
    if (!strcasecmp(s, "DS"))
        return DNS_TYPE_DS;
    if (!strcasecmp(s, "RRSIG"))
        return DNS_TYPE_RRSIG;
    if (!strcasecmp(s, "NSEC"))
        return DNS_TYPE_NSEC;
    if (!strcasecmp(s, "DNSKEY"))
        return DNS_TYPE_DNSKEY;
    if (!strcasecmp(s, "NSEC3"))
        return DNS_TYPE_NSEC3;
    if (!strcasecmp(s, "NSEC3PARAM"))
        return DNS_TYPE_NSEC3PARAM;
    if (!strcasecmp(s, "TLSA"))
        return DNS_TYPE_TLSA;
    if (!strcasecmp(s, "CDS"))
        return DNS_TYPE_CDS;
    if (!strcasecmp(s, "CDNSKEY"))
        return DNS_TYPE_CDNSKEY;
    if (!strcasecmp(s, "CSYNC"))
        return DNS_TYPE_CSYNC;
    if (!strcasecmp(s, "ZONEMD"))
        return DNS_TYPE_ZONEMD;
    if (!strcasecmp(s, "SVCB"))
        return DNS_TYPE_SVCB;
    if (!strcasecmp(s, "HTTPS"))
        return DNS_TYPE_HTTPS;
    if (!strcasecmp(s, "URI"))
        return DNS_TYPE_URI;
    if (!strcasecmp(s, "CAA"))
        return DNS_TYPE_CAA;
    if (!strcasecmp(s, "IXFR"))
        return DNS_TYPE_IXFR;
    if (!strcasecmp(s, "AXFR"))
        return DNS_TYPE_AXFR;
    if (!strcasecmp(s, "ANY"))
        return DNS_TYPE_ANY;
    /* Numeric TYPE<n> notation (RFC 3597) */
    if (!strncasecmp(s, "TYPE", 4) && s[4] >= '0' && s[4] <= '9')
        return (uint16_t) atoi(s + 4);
    if (s[0] >= '0' && s[0] <= '9')
        return (uint16_t) atoi(s);
    return 0;
}

/* ── RFC 1982 serial-number arithmetic ───────────────────────────────────── */

int serial_lt(uint32_t a, uint32_t b) {
    return (a != b) && (((b - a) & 0x80000000u) == 0);
}

int serial_ge(uint32_t a, uint32_t b) {
    return !serial_lt(a, b);
}

/* ── EDNS(0) parsing ─────────────────────────────────────────────────────── */

/* Skip a wire-format name starting at pkt[off]; return new offset or -1. */
static int skip_name(const uint8_t *pkt, int plen, int off) {
    int steps = 0;
    while (steps++ < 128) {
        if (off >= plen)
            return -1;
        uint8_t c = pkt[off];
        if ((c & 0xC0) == 0xC0) {
            off += 2;
            return (off <= plen) ? off : -1;
        }
        if (c == 0)
            return off + 1;
        off += c + 1;
    }
    return -1;
}

void edns_parse(const uint8_t *pkt, int plen, edns_info_t *ei) {
    memset(ei, 0, sizeof(*ei));
    ei->max_udp = 512;
    if (plen < 12)
        return;
    int arcount = (int) get16(pkt, 10);
    if (arcount == 0)
        return;
    int off = 12;
    /* Skip question section */
    int qdcount = (int) get16(pkt, 4);
    for (int i = 0; i < qdcount; i++) {
        off = skip_name(pkt, plen, off);
        if (off < 0 || off + 4 > plen)
            return;
        off += 4; /* qtype + qclass */
    }
    /* Skip answer and authority sections */
    int ancount = (int) get16(pkt, 6);
    int nscount = (int) get16(pkt, 8);
    int skip_rrs = ancount + nscount;
    for (int i = 0; i < skip_rrs; i++) {
        off = skip_name(pkt, plen, off);
        if (off < 0 || off + 10 > plen)
            return;
        uint16_t rdlen = get16(pkt, off + 8);
        off += 10 + (int) rdlen;
    }
    /* Scan additional section for OPT */
    for (int i = 0; i < arcount; i++) {
        if (off >= plen)
            break;
        off = skip_name(pkt, plen, off);
        if (off < 0 || off + 10 > plen)
            break;
        uint16_t rtype = get16(pkt, off);
        if (rtype == DNS_TYPE_OPT) {
            ei->present = 1;
            ei->max_udp = get16(pkt, off + 2);
            /* OPT TTL field (RFC 6891 §6.1.3): ext-RCODE(off+4) | VERSION
             * (off+5) | flags(off+6, off+7). DO is the top bit of the 2-octet
             * flags field at off+6 — NOT off+4 (that is the extended RCODE). */
            ei->version = pkt[off + 5];
            ei->do_bit = (pkt[off + 6] & 0x80) ? 1 : 0;
            uint16_t rdlen = get16(pkt, off + 8);
            int rp = off + 10;
            int rend = off + 10 + (int) rdlen;
            while (rp + 4 <= rend && rp + 4 <= plen) {
                uint16_t oc = get16(pkt, rp);
                uint16_t ol = get16(pkt, rp + 2);
                rp += 4;
                if (oc == EDNS_OPT_NSID) {
                    ei->nsid_req = 1;
                } else if (oc == EDNS_OPT_COOKIE && ol >= DNS_COOKIE_CLIENT_LEN) {
                    if (rp + ol <= plen) {
                        memcpy(ei->client_cookie, pkt + rp, DNS_COOKIE_CLIENT_LEN);
                        ei->has_client_cookie = 1;
                        /* Server cookie: bytes after the 8-byte client cookie,
                         * length 8..DNS_COOKIE_SERVER_LEN (RFC 9018). */
                        if (ol > DNS_COOKIE_CLIENT_LEN &&
                            ol <= DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN) {
                            int slen = ol - DNS_COOKIE_CLIENT_LEN;
                            memcpy(ei->server_cookie, pkt + rp + DNS_COOKIE_CLIENT_LEN, slen);
                            ei->server_cookie_len = slen;
                            ei->has_server_cookie = 1;
                        }
                    }
                } else if (oc == EDNS_OPT_KEEPALIVE) {
                    ei->keepalive_req = 1;
                } else if (oc == EDNS_OPT_PADDING) {
                    ei->has_padding = 1;
                    ei->padding_req = ol;
                } else if (oc == EDNS_OPT_ZONEVERSION && ol == 0) {
                    /* RFC 9660 §3: OPTION-LENGTH must be 0 in a query; a
                     * nonzero length here is malformed and ignored rather
                     * than honored. */
                    ei->zoneversion_req = 1;
                }
                if (rp + (int) ol > plen)
                    break;
                rp += (int) ol;
            }
            break;
        }
        uint16_t rdlen = get16(pkt, off + 8);
        off += 10 + (int) rdlen;
    }
}

/* ── EDNS(0) response building ───────────────────────────────────────────── */

int edns_append_opt(uint8_t *buf, int off, int blen, int is_tcp, int do_bit, uint16_t rcode_ext,
                    const edns_info_t *req_ei, const char *nsid, const uint8_t *scookie,
                    int ede_code, const char *ede_text, int zv_labels, uint32_t zv_serial,
                    const char *report_agent) {
    if (off + 11 > blen)
        return off;
    buf[off++] = 0; /* root name */
    buf[off++] = 0;
    buf[off++] = 41; /* OPT type */
    /* class = max UDP payload */
    uint16_t maxudp = is_tcp ? 65535 : EDNS_MAX_UDP;
    buf[off++] = maxudp >> 8;
    buf[off++] = maxudp & 0xFF;
    /* TTL = ext-RCODE | version=0 | DO | Z */
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
    if (nsid && nsid[0]) {
        int nsid_len = (int) strlen(nsid);
        if (rdata_off + 4 + nsid_len < blen) {
            put16(buf, rdata_off, EDNS_OPT_NSID);
            put16(buf, rdata_off + 2, (uint16_t) nsid_len);
            memcpy(buf + rdata_off + 4, nsid, nsid_len);
            rdata_off += 4 + nsid_len;
            rdata_len += 4 + nsid_len;
        }
    }
    /* Cookie option: emit client cookie + pre-computed server cookie */
    if (req_ei && req_ei->has_client_cookie && scookie) {
        int total = 4 + DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN;
        if (rdata_off + total < blen) {
            put16(buf, rdata_off, EDNS_OPT_COOKIE);
            put16(buf, rdata_off + 2, DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_LEN);
            memcpy(buf + rdata_off + 4, req_ei->client_cookie, DNS_COOKIE_CLIENT_LEN);
            memcpy(buf + rdata_off + 4 + DNS_COOKIE_CLIENT_LEN, scookie, DNS_COOKIE_SERVER_LEN);
            rdata_off += total;
            rdata_len += total;
        }
    }
    /* TCP keepalive: suggest 30s (300 units of 100ms, RFC 7828) */
    if (is_tcp && req_ei && req_ei->keepalive_req) {
        if (rdata_off + 6 < blen) {
            put16(buf, rdata_off, EDNS_OPT_KEEPALIVE);
            put16(buf, rdata_off + 2, 2);
            put16(buf, rdata_off + 4, 300);
            rdata_off += 6;
            rdata_len += 6;
        }
    }
    /* EDE option (RFC 8914) */
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
    /* ZONEVERSION (RFC 9660): echo the SOA serial of the zone that answered.
     * Only when the client asked (req_ei->zoneversion_req) AND the caller
     * knows which zone answered (zv_labels >= 0) — a server must not guess an
     * authority it doesn't have (e.g. REFUSED / no zone match). */
    if (req_ei && req_ei->zoneversion_req && zv_labels >= 0 && zv_labels <= 255) {
        if (rdata_off + 4 + 6 < blen) {
            put16(buf, rdata_off, EDNS_OPT_ZONEVERSION);
            put16(buf, rdata_off + 2, 6); /* LABELCOUNT(1) + TYPE(1) + VERSION(4) */
            buf[rdata_off + 4] = (uint8_t) zv_labels;
            buf[rdata_off + 5] = EDNS_ZV_TYPE_SOA_SERIAL;
            put32(buf, rdata_off + 6, zv_serial);
            rdata_off += 4 + 6;
            rdata_len += 4 + 6;
        }
    }
    /* Report-Channel (RFC 9567 §4): tell the client where to send DNS Error
     * Reports for names under this server's authority. Unconditional (not
     * gated on ede_code) — the resolver may not discover the error itself
     * until well after this response, from its own cache. AGENT-DOMAIN is
     * uncompressed wire format (RFC 9567 §4), not a compression pointer. */
    if (report_agent && report_agent[0]) {
        uint8_t agent_wire[256];
        int al = name_to_wire(report_agent, agent_wire, (int) sizeof(agent_wire));
        if (al > 0 && rdata_off + 4 + al < blen) {
            put16(buf, rdata_off, EDNS_OPT_REPORT_CHANNEL);
            put16(buf, rdata_off + 2, (uint16_t) al);
            memcpy(buf + rdata_off + 4, agent_wire, (size_t) al);
            rdata_off += 4 + al;
            rdata_len += 4 + al;
        }
    }
    /* Padding (RFC 7830 / RFC 8467):
     *   - Encrypted transports (is_tcp): always pad to RFC 8467 §4 block size (468).
     *   - If client requested padding: use 128-byte blocks instead. */
    if (is_tcp) {
        int block = (req_ei && req_ei->has_padding) ? 128 : 468;
        int cur = off + 2 + rdata_len + 4;
        int pad = block - (cur % block);
        if (pad == block)
            pad = 0;
        if (pad > 0 && rdata_off + 4 + pad < blen) {
            put16(buf, rdata_off, EDNS_OPT_PADDING);
            put16(buf, rdata_off + 2, (uint16_t) pad);
            memset(buf + rdata_off + 4, 0, pad);
            rdata_off += 4 + pad;
            rdata_len += 4 + pad;
        }
    }
    put16(buf, off, (uint16_t) rdata_len);
    off = rdata_off;
    /* Increment arcount (offset 10 in DNS header) */
    put16(buf, 10, (uint16_t) (get16(buf, 10) + 1));
    return off;
}

/* ── RFC 4034 §6 canonical-form helpers ──────────────────────────────────── */

int canon_rdata(const uint8_t *pkt, int plen, int rdoff, int rdlen, uint16_t rtype, uint8_t *out,
                int outsz) {
    if (rdoff < 0 || rdlen < 0 || rdoff + rdlen > plen)
        return -1;
    char nm[256];
    switch (rtype) {
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
        case DNS_TYPE_DNAME: {
            if (name_from_wire(pkt, plen, rdoff, nm, sizeof(nm)) < 0)
                return -1;
            return name_to_wire(nm, out, outsz);
        }
        case DNS_TYPE_MX: {
            if (rdlen < 3 || outsz < 2)
                return -1;
            out[0] = pkt[rdoff];
            out[1] = pkt[rdoff + 1];
            if (name_from_wire(pkt, plen, rdoff + 2, nm, sizeof(nm)) < 0)
                return -1;
            int n = name_to_wire(nm, out + 2, outsz - 2);
            if (n < 0)
                return -1;
            return 2 + n;
        }
        case DNS_TYPE_SRV: {
            if (rdlen < 7 || outsz < 6)
                return -1;
            memcpy(out, pkt + rdoff, 6);
            if (name_from_wire(pkt, plen, rdoff + 6, nm, sizeof(nm)) < 0)
                return -1;
            int n = name_to_wire(nm, out + 6, outsz - 6);
            if (n < 0)
                return -1;
            return 6 + n;
        }
        case DNS_TYPE_SOA: {
            int a = name_from_wire(pkt, plen, rdoff, nm, sizeof(nm));
            if (a < 0)
                return -1;
            int pos = name_to_wire(nm, out, outsz);
            if (pos < 0)
                return -1;
            int b = name_from_wire(pkt, plen, a, nm, sizeof(nm));
            if (b < 0)
                return -1;
            int n = name_to_wire(nm, out + pos, outsz - pos);
            if (n < 0)
                return -1;
            pos += n;
            if (b + 20 > plen || pos + 20 > outsz)
                return -1;
            memcpy(out + pos, pkt + b, 20); /* serial..minimum: 5×u32 */
            return pos + 20;
        }
        default:
            if (rdlen > outsz)
                return -1;
            memcpy(out, pkt + rdoff, rdlen);
            return rdlen;
    }
}

int canon_rr_cmp(const canon_rr_t *a, const canon_rr_t *b) {
    int min = a->len < b->len ? a->len : b->len;
    int c = memcmp(a->buf, b->buf, min);
    if (c)
        return c;
    return a->len - b->len;
}

/* ── Schema version contract (ADR-003) ───────────────────────────────────────
 * Pure comparator: no I/O. The daemon reads `schema:version` from Valkey and
 * passes it here; the SCHEMA_* return code drives its startup policy. */

int schema_version_check(const char *stored) {
    if (!stored || !stored[0])
        return SCHEMA_ABSENT;
    char *end = NULL;
    long major = strtol(stored, &end, 10);
    if (end == stored || *end != '.')
        return SCHEMA_MALFORMED;
    const char *minor_str = end + 1;
    if (!*minor_str)
        return SCHEMA_MALFORMED;
    char *end2 = NULL;
    long minor = strtol(minor_str, &end2, 10);
    if (end2 == minor_str || *end2 != '\0')
        return SCHEMA_MALFORMED;
    if (major < 0 || minor < 0)
        return SCHEMA_MALFORMED;
    if (major != SCHEMA_VERSION_MAJOR)
        return SCHEMA_MAJOR_DIFF;
    if (minor != SCHEMA_VERSION_MINOR)
        return SCHEMA_MINOR_DIFF;
    return SCHEMA_OK;
}
