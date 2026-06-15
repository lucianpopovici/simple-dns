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
        int8_t a = rev[(uint8_t) in[i]], b = rev[(uint8_t) in[i + 1]], c = rev[(uint8_t) in[i + 2]],
               d = rev[(uint8_t) in[i + 3]];
        if (a < 0 || b < 0)
            break;
        out[o++] = (uint8_t) ((a << 2) | (b >> 4));
        if (c >= 0 && o < olen)
            out[o++] = (uint8_t) ((b << 4) | (c >> 2));
        if (d >= 0 && o < olen)
            out[o++] = (uint8_t) ((c << 6) | d);
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
