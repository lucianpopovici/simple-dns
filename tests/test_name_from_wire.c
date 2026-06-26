/* Unit tests for name_from_wire compression handling.
 *
 * Builds against resolverd.c (all three copies of the function are
 * byte-identical until the libdnswire extraction). Verifies that:
 *   - uncompressed and legitimately compressed (backward-pointer) names parse;
 *   - forward pointers, self-pointers, and pointer loops are rejected;
 *   - truncated packets and over-long names are rejected.
 *
 * Compile:  cc -DUNIT_TEST -I. tests/test_name_from_wire.c -lssl -lcrypto -lpthread
 */
#define UNIT_TEST 1
#include "resolverd.c"

#include <assert.h>

static int g_fail = 0;

static void check(int cond, const char *what) {
    printf("  %s  %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) {
        g_fail = 1;
    }
}

int main(void) {
    char out[256];

    /* Plain uncompressed name at offset 0: "www.example.com" */
    {
        const uint8_t pkt[] = {3,   'w', 'w', 'w', 7,   'e', 'x', 'a', 'm',
                               'p', 'l', 'e', 3,   'c', 'o', 'm', 0};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == (int) sizeof(pkt) && strcmp(out, "www.example.com") == 0,
              "uncompressed name parses");
    }

    /* Legitimate compression: name at 0, pointer to it from a later offset. */
    {
        uint8_t pkt[64] = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
        /* "www." + pointer back to offset 0 */
        pkt[20] = 3;
        pkt[21] = 'w';
        pkt[22] = 'w';
        pkt[23] = 'w';
        pkt[24] = 0xC0;
        pkt[25] = 0x00;
        int r = name_from_wire(pkt, sizeof(pkt), 20, out, sizeof(out));
        check(r == 26 && strcmp(out, "www.example.com") == 0,
              "backward compression pointer parses");
    }

    /* Forward pointer: pointer at 0 targets offset 2 (> 0) — must reject. */
    {
        const uint8_t pkt[] = {0xC0, 0x02, 3, 'f', 'o', 'o', 0};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == -1, "forward pointer rejected");
    }

    /* Self-pointer: pointer at 0 targets offset 0 — must reject. */
    {
        const uint8_t pkt[] = {0xC0, 0x00};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == -1, "self-pointer rejected");
    }

    /* Two-pointer loop: 0 -> 2 -> 0. The first hop is already forward. */
    {
        const uint8_t pkt[] = {0xC0, 0x02, 0xC0, 0x00};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == -1, "pointer loop rejected");
        /* Starting at the second pointer: 2 -> 0 -> (0xC0 at 0) -> 2 would
           loop, but the hop 0 -> 2 is forward from offset 0 — reject. */
        r = name_from_wire(pkt, sizeof(pkt), 2, out, sizeof(out));
        check(r == -1, "pointer loop rejected (second entry point)");
    }

    /* Pointer target out of bounds (beyond plen). */
    {
        const uint8_t pkt[] = {3, 'f', 'o', 'o', 0, 0xC0, 0x3F};
        int r = name_from_wire(pkt, sizeof(pkt), 5, out, sizeof(out));
        check(r == -1, "pointer past end of packet rejected");
    }

    /* Truncated: label length runs past plen. */
    {
        const uint8_t pkt[] = {7, 'e', 'x', 'a'};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == -1, "truncated label rejected");
    }

    /* Missing terminating zero. */
    {
        const uint8_t pkt[] = {3, 'f', 'o', 'o'};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == -1, "missing root label rejected");
    }

    /* Output buffer too small for the name. */
    {
        const uint8_t pkt[] = {3,   'w', 'w', 'w', 7,   'e', 'x', 'a', 'm',
                               'p', 'l', 'e', 3,   'c', 'o', 'm', 0};
        char tiny[8];
        int r = name_from_wire(pkt, sizeof(pkt), 0, tiny, sizeof(tiny));
        check(r == -1, "name longer than output buffer rejected");
    }

    /* Long pointer chain, each hop strictly backward — must still parse
       (the steps cap is a backstop, not the primary limit). Layout:
       label at 0, then pointers at 8,10,12,... each targeting the previous. */
    {
        uint8_t pkt[128] = {3, 'a', 'b', 'c', 0};
        int n = 8;
        pkt[n] = 0xC0;
        pkt[n + 1] = 0x00;
        for (int i = 1; i < 20; i++) {
            pkt[n + 2 * i] = 0xC0;
            pkt[n + 2 * i + 1] = (uint8_t) (n + 2 * (i - 1));
        }
        int r = name_from_wire(pkt, sizeof(pkt), n + 2 * 19, out, sizeof(out));
        check(r == n + 2 * 19 + 2 && strcmp(out, "abc") == 0,
              "monotonically backward pointer chain parses");
    }

    /* name_to_wire must reject a label > 63 octets (RFC 1035 §3.1) — a longer
       length octet collides with the 0xC0 compression-pointer marker on re-parse
       (CSA-WIRE-001). */
    {
        char longlabel[80];
        memset(longlabel, 'a', 64);
        longlabel[64] = '.';
        memcpy(longlabel + 65, "com", 3);
        longlabel[68] = 0; /* 64-octet label — over the limit */
        uint8_t wbuf[256];
        int r = name_to_wire(longlabel, wbuf, sizeof(wbuf));
        check(r == -1, "name_to_wire rejects label > 63 octets");
        int r2 = name_to_wire("www.example.com", wbuf, sizeof(wbuf));
        check(r2 > 0, "name_to_wire accepts a valid name");
    }

    /* ── ADR-003 TLV codec: round-trip, skip-unknown, fail-closed framing ───── */
    {
        uint8_t blob[64];
        int off = tlv_begin(blob, sizeof(blob), 1);
        check(off == 1, "tlv_begin writes version byte");
        off = tlv_put_u16(blob, sizeof(blob), off, 1 /*tag*/, 0x1234);
        off = tlv_put_u8(blob, sizeof(blob), off, 2 /*tag*/, 0x7F);
        const uint8_t hint[4] = {1, 2, 3, 4};
        off = tlv_put(blob, sizeof(blob), off, 3 /*tag*/, hint, 4);
        check(off > 0, "tlv_put items succeed within buffer");
        int total = off;

        /* Read it back; also prove an unknown tag in the middle is skipped. */
        check(tlv_version(blob, total) == 1, "tlv_version reads version");
        int roff = 1;
        uint8_t tag = 0;
        const uint8_t *val = NULL;
        uint16_t vlen = 0;
        int seen_u16 = 0, seen_u8 = 0, seen_blob = 0;
        int r;
        while ((r = tlv_next(blob, total, &roff, &tag, &val, &vlen)) == 1) {
            if (tag == 1 && vlen == 2 && get16(val, 0) == 0x1234)
                seen_u16 = 1;
            else if (tag == 2 && vlen == 1 && val[0] == 0x7F)
                seen_u8 = 1;
            else if (tag == 3 && vlen == 4 && memcmp(val, hint, 4) == 0)
                seen_blob = 1;
        }
        check(r == 0, "tlv_next reaches a clean end (returns 0)");
        check(seen_u16 && seen_u8 && seen_blob, "tlv round-trips every item");

        /* Overflow: a value that does not fit must fail closed, not truncate. */
        uint8_t small[4];
        int o2 = tlv_begin(small, sizeof(small), 1);
        check(tlv_put(small, sizeof(small), o2, 9, hint, 4) == -1,
              "tlv_put rejects an item that overflows the buffer");

        /* Malformed framing: a length that runs past the blob must be rejected. */
        uint8_t bad[] = {1 /*ver*/, 5 /*tag*/, 0x00, 0x10 /*len=16*/, 0xAA};
        int boff = 1;
        check(tlv_next(bad, sizeof(bad), &boff, &tag, &val, &vlen) == -1,
              "tlv_next rejects a length running past the buffer");
    }

    /* ── ADR-003 schema version comparator ──────────────────────────────────── */
    {
        check(schema_version_check(SCHEMA_VERSION_STR) == SCHEMA_OK,
              "schema_version_check accepts the compiled version");
        check(schema_version_check("") == SCHEMA_ABSENT, "empty schema version is ABSENT");
        check(schema_version_check(NULL) == SCHEMA_ABSENT, "NULL schema version is ABSENT");
        check(schema_version_check("1.7") == SCHEMA_MINOR_DIFF, "newer minor warns (MINOR_DIFF)");
        check(schema_version_check("2.0") == SCHEMA_MAJOR_DIFF,
              "major bump fails closed (MAJOR_DIFF)");
        check(schema_version_check("9") == SCHEMA_MALFORMED, "missing minor is MALFORMED");
        check(schema_version_check("1.x") == SCHEMA_MALFORMED, "non-numeric minor is MALFORMED");
        check(schema_version_check("1.0.3") == SCHEMA_MALFORMED, "trailing junk is MALFORMED");
    }

    printf("%s\n", g_fail ? "FAILURES" : "ALL TESTS PASSED");
    return g_fail;
}
