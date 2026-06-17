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

    printf("%s\n", g_fail ? "FAILURES" : "ALL TESTS PASSED");
    return g_fail;
}
