/* tests/test_csync.c — RFC 7477 CSYNC codec (csync_encode_rdata in libdnswire).
 *
 * Known-answer + negative tests for the Valkey pipe format →
 * serial(4)|flags(2)|type-bitmap wire encoding.
 *
 * Build (from repo root): see `make check-csync`.
 */
#include "dns_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_failures = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            printf("  PASS  %s\n", msg);                                                           \
        } else {                                                                                   \
            printf("  FAIL  %s\n", msg);                                                           \
            g_failures++;                                                                          \
        }                                                                                          \
    } while (0)

/* KAT 1 — exact wire for serial=1, flags=3 (immediate|soaminimum), types=NS,A,AAAA.
 *
 * Serial:  0x00000001
 * Flags:   0x0003
 * Type bitmap (0x80u >> (t%8)):
 *   A (1):    bitmap[0] |= 0x80>>1 = 0x40
 *   NS (2):   bitmap[0] |= 0x80>>2 = 0x20   → byte 0 = 0x60
 *   AAAA (28):bitmap[3] |= 0x80>>4 = 0x08   → byte 3 = 0x08
 *   max_bit = 28, blen = 4
 *   window=0x00, len=0x04, 0x60, 0x00, 0x00, 0x08
 */
static void kat_exact(void) {
    uint8_t wire[64];
    int n = csync_encode_rdata(1u, 3u, "NS,A,AAAA", wire, sizeof(wire));
    const uint8_t expect[] = {
        0x00, 0x00, 0x00, 0x01, /* serial = 1 */
        0x00, 0x03,             /* flags = 3 */
        0x00, 0x04,             /* window 0, bitmap len 4 */
        0x60, 0x00, 0x00, 0x08  /* A(1)+NS(2)=0x60, _, _, AAAA(28)=0x08 */
    };
    CHECK(n == (int) sizeof(expect) && memcmp(wire, expect, sizeof(expect)) == 0,
          "exact wire: serial=1 flags=3 NS,A,AAAA");
}

/* KAT 2 — serial/flags survive round-trip (check big-endian encoding). */
static void kat_serial_flags(void) {
    uint8_t w[64];
    uint32_t s = 0xDEADBEEFu;
    uint16_t f = 0x0002u; /* soaminimum only */
    int n = csync_encode_rdata(s, f, "NS", w, sizeof(w));
    if (n < 6) {
        CHECK(0, "rdata length >= 6");
        return;
    }
    uint32_t got_s =
        ((uint32_t) w[0] << 24) | ((uint32_t) w[1] << 16) | ((uint32_t) w[2] << 8) | w[3];
    uint16_t got_f = (uint16_t) (((uint16_t) w[4] << 8) | w[5]);
    CHECK(got_s == s, "serial big-endian survives round-trip");
    CHECK(got_f == f, "flags big-endian survives round-trip");
}

/* KAT 3 — empty type list → no bitmap section (just serial + flags). */
static void kat_empty_types(void) {
    uint8_t w[16];
    int n = csync_encode_rdata(0u, 0u, "", w, sizeof(w));
    CHECK(n == 6, "empty type list → rdata is exactly 6 bytes");
}

/* KAT 4 — single type NS (type 2):
 *   byte 0 = 0x20, blen = 1, window=0, len=1, 0x20
 */
static void kat_single_ns(void) {
    uint8_t w[32];
    int n = csync_encode_rdata(42u, 0u, "NS", w, sizeof(w));
    const uint8_t expect[] = {
        0x00, 0x00, 0x00, 0x2A, /* serial = 42 */
        0x00, 0x00,             /* flags = 0 */
        0x00, 0x01,             /* window 0, len 1 */
        0x20                    /* NS(2): byte 0 bit 5 = 0x20 */
    };
    CHECK(n == (int) sizeof(expect) && memcmp(w, expect, sizeof(expect)) == 0,
          "single NS type bitmap");
}

/* KAT 5 — type order in the CSV does not matter; bitmap is positional. */
static void kat_order_independent(void) {
    uint8_t w1[64], w2[64];
    int n1 = csync_encode_rdata(1u, 1u, "A,NS,AAAA", w1, sizeof(w1));
    int n2 = csync_encode_rdata(1u, 1u, "AAAA,NS,A", w2, sizeof(w2));
    CHECK(n1 == n2 && n1 > 0 && memcmp(w1, w2, n1) == 0,
          "type order in CSV does not change bitmap");
}

/* KAT 6 — buffer too small → -1 (fail closed). */
static void kat_overflow(void) {
    uint8_t small[3];
    int n = csync_encode_rdata(1u, 0u, "A", small, sizeof(small));
    CHECK(n == -1, "buffer too small returns -1");
}

int main(void) {
    printf("RFC 7477 CSYNC codec tests\n");
    kat_exact();
    kat_serial_flags();
    kat_empty_types();
    kat_single_ns();
    kat_order_independent();
    kat_overflow();
    if (g_failures) {
        printf("FAIL: %d test(s) failed\n", g_failures);
        return 1;
    }
    printf("OK: all tests passed\n");
    return 0;
}
