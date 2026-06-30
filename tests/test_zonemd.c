/* tests/test_zonemd.c — RFC 8976 ZONEMD codec + RFC 4034 §6.1 canonical name
 * ordering (zonemd_build_tlv / zonemd_tlv_to_wire / canon_name_cmp in
 * libdnswire).
 *
 * Known-answer + round-trip + negative tests for the structured (ADR-003 TLV)
 * ZONEMD value and its emitted §2.2 rdata, plus the whole-zone owner ordering
 * used to sort RRs before hashing (RFC 8976 §3.3 → RFC 4034 §6.1/§6.3).
 *
 * Build (from repo root): see `make check-zonemd`.
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

/* KAT — exact §2.2 wire bytes for serial 2021071219, scheme 1 (SIMPLE),
 * hash 1 (SHA-384), digest = 0x01 0x02 0x03:
 *   Serial 0x7878F2B3 | Scheme 0x01 | Hash 0x01 | Digest 010203 */
static void kat_exact(void) {
    const uint8_t dg[] = {0x01, 0x02, 0x03};
    uint8_t tlv[256];
    int tl = zonemd_build_tlv(0x7878F2B3u, ZONEMD_SCHEME_SIMPLE, ZONEMD_HASH_SHA384, dg,
                              (int) sizeof(dg), tlv, sizeof(tlv));
    CHECK(tl > 0, "TLV builds");
    uint8_t wire[256];
    int n = zonemd_tlv_to_wire(tlv, tl, wire, sizeof(wire));
    const uint8_t expect[] = {0x78, 0x78, 0xF2, 0xB3, 0x01, 0x01, 0x01, 0x02, 0x03};
    CHECK(n == (int) sizeof(expect) && memcmp(wire, expect, sizeof(expect)) == 0,
          "exact §2.2 wire: serial|scheme|hash|digest");
}

/* Round-trip a full SHA-384 (48-byte) digest through TLV → wire and check every
 * field decodes. */
static void kat_roundtrip(void) {
    uint8_t dg[ZONEMD_SHA384_LEN];
    for (int i = 0; i < ZONEMD_SHA384_LEN; i++)
        dg[i] = (uint8_t) (i * 7 + 1);
    uint8_t tlv[256];
    int tl = zonemd_build_tlv(0xDEADBEEFu, ZONEMD_SCHEME_SIMPLE, ZONEMD_HASH_SHA384, dg,
                              ZONEMD_SHA384_LEN, tlv, sizeof(tlv));
    uint8_t w[256];
    int n = zonemd_tlv_to_wire(tlv, tl, w, sizeof(w));
    if (n < 0) {
        CHECK(0, "round-trip emits rdata");
        return;
    }
    uint32_t serial = ((uint32_t) w[0] << 24) | ((uint32_t) w[1] << 16) | ((uint32_t) w[2] << 8) |
                      w[3];
    CHECK(n == 6 + ZONEMD_SHA384_LEN, "rdata length = 6 + 48");
    CHECK(serial == 0xDEADBEEFu, "serial survives round-trip");
    CHECK(w[4] == ZONEMD_SCHEME_SIMPLE, "scheme == SIMPLE(1)");
    CHECK(w[5] == ZONEMD_HASH_SHA384, "hash == SHA-384(1)");
    CHECK(memcmp(w + 6, dg, ZONEMD_SHA384_LEN) == 0, "digest survives round-trip");
}

/* Unknown trailing tag must be skipped (ADR-003 additive forward-compat). */
static void kat_unknown_tag(void) {
    uint8_t dg[ZONEMD_SHA512_LEN];
    memset(dg, 0xAB, sizeof(dg));
    uint8_t tlv[256];
    int tl = zonemd_build_tlv(1u, ZONEMD_SCHEME_SIMPLE, ZONEMD_HASH_SHA512, dg, ZONEMD_SHA512_LEN,
                              tlv, sizeof(tlv));
    /* Append a bogus unknown tag 0x7F with a 2-byte value by hand. */
    tlv[tl++] = 0x7F;
    tlv[tl++] = 0x00;
    tlv[tl++] = 0x02;
    tlv[tl++] = 0xCA;
    tlv[tl++] = 0xFE;
    uint8_t w[256];
    int n = zonemd_tlv_to_wire(tlv, tl, w, sizeof(w));
    CHECK(n == 6 + ZONEMD_SHA512_LEN && w[5] == ZONEMD_HASH_SHA512,
          "unknown trailing TLV tag skipped, SHA-512 digest intact");
}

static void negatives(void) {
    uint8_t dg[8] = {0};
    uint8_t tlv[256];
    int tl = zonemd_build_tlv(1u, ZONEMD_SCHEME_SIMPLE, ZONEMD_HASH_SHA384, dg, 8, tlv,
                              sizeof(tlv));
    uint8_t w[256];
    /* Wrong version byte → reject. */
    uint8_t bad = tlv[0];
    tlv[0] = 0x7E;
    CHECK(zonemd_tlv_to_wire(tlv, tl, w, sizeof(w)) < 0, "reject: bad TLV version");
    tlv[0] = bad;
    /* Truncated (drop the last byte of the digest item value) → reject. */
    CHECK(zonemd_tlv_to_wire(tlv, tl - 1, w, sizeof(w)) < 0, "reject: truncated TLV");
    /* Output buffer too small → reject (fail closed, no overflow). */
    CHECK(zonemd_tlv_to_wire(tlv, tl, w, 4) < 0, "reject: output buffer too small");
    /* Builder rejects a negative digest length. */
    CHECK(zonemd_build_tlv(1u, 1, 1, dg, -1, tlv, sizeof(tlv)) < 0, "reject: negative diglen");
}

/* RFC 4034 §6.1 canonical name ordering — the worked example from the RFC:
 *   example. < a.example. < yljkjljk.a.example. < Z.a.example. <
 *   zABC.a.EXAMPLE. < z.example. < \001.z.example. < *.z.example. <
 *   200.z.example. < z.z.example.
 * We test the ordering relations that matter for whole-zone RR sorting
 * (label-from-the-right, case-insensitive). */
static void canon_ordering(void) {
    CHECK(canon_name_cmp("example", "a.example") < 0, "example < a.example (fewer labels first)");
    CHECK(canon_name_cmp("a.example", "z.example") < 0, "a.example < z.example (leftmost label)");
    CHECK(canon_name_cmp("z.example", "zabc.a.example") > 0,
          "z.example > zABC.a.example (compare from right: a < e)");
    CHECK(canon_name_cmp("Z.a.EXAMPLE", "z.a.example") == 0, "case-insensitive equality");
    CHECK(canon_name_cmp("yljkjljk.a.example", "Z.a.example") < 0,
          "y.a.example < Z.a.example (case-folded leftmost)");
    CHECK(canon_name_cmp("a.example", "a.example") == 0, "identical names equal");
    /* Ordering is by the RIGHTMOST label first, not a plain string compare. */
    CHECK(canon_name_cmp("b.a", "a.b") < 0, "b.a < a.b (suffix 'a' < 'b')");
}

int main(void) {
    kat_exact();
    kat_roundtrip();
    kat_unknown_tag();
    negatives();
    canon_ordering();
    if (g_failures) {
        printf("\n%d FAILURE(S)\n", g_failures);
        return 1;
    }
    printf("\nALL TESTS PASSED\n");
    return 0;
}
