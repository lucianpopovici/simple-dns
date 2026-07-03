/* tests/test_doq.c
 *
 * Known-answer test for doqd's RFC 9250 §4.3 stream-framing parser
 * (doq_frame_next, `static` inside doqd.c). This is the pure, memory-safety-
 * fuzzed (fuzz/fuzz_doq.c) part of doqd's only structured parsing of client
 * bytes; this KAT pins down the exact accept/reject boundary the fuzz target
 * only checks for memory safety, not correctness: a 2-octet length prefix
 * that must exactly match the remaining bytes (RFC 9250 forbids more than
 * one message per client-initiated stream, so "declared != available" is
 * always a hard reject, never "wait for more").
 *
 * Build (from repo root):
 *   clang -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -DUNIT_TEST -I. \
 *       -Wno-unused-function -o test_doq tests/test_doq.c dns_wire.c -lssl -lcrypto -lpthread
 */

#define UNIT_TEST 1
#include "doqd.c"

static int g_failures = 0;

#define CHECK(cond, msg)                                                                          \
    do {                                                                                          \
        if (cond) {                                                                               \
            printf("  PASS  %s\n", msg);                                                          \
        } else {                                                                                  \
            printf("  FAIL  %s\n", msg);                                                          \
            g_failures++;                                                                         \
        }                                                                                         \
    } while (0)

static int frame_ok(const uint8_t *buf, int len, int *out_msglen) {
    const uint8_t *msg = NULL;
    int msglen = 0;
    int r = doq_frame_next(buf, len, &msg, &msglen);
    if (r == 0 && out_msglen)
        *out_msglen = msglen;
    return r;
}

static void test_doq_frame_next(void) {
    printf("== doq_frame_next: KAT ==\n");

    /* Minimum legal DNS message is 12 bytes (a bare header); anything the
     * framing parser declares below that can never be a real message, so
     * doqd rejects it before ever handing bytes to dns_forward. */
    uint8_t exact12[2 + 12] = {0x00, 0x0c};
    memset(exact12 + 2, 'A', 12);
    int msglen = -1;
    CHECK(frame_ok(exact12, sizeof(exact12), &msglen) == 0 && msglen == 12,
          "declared=12, buffer=2+12: accepted, msglen=12");

    uint8_t larger[2 + 300];
    larger[0] = (300 >> 8) & 0xff;
    larger[1] = 300 & 0xff;
    memset(larger + 2, 'B', 300);
    msglen = -1;
    CHECK(frame_ok(larger, sizeof(larger), &msglen) == 0 && msglen == 300,
          "declared=300, buffer=2+300: accepted, msglen=300");

    uint8_t below_min[2 + 11] = {0x00, 0x0b};
    memset(below_min + 2, 'C', 11);
    CHECK(frame_ok(below_min, sizeof(below_min), NULL) == -1,
          "declared=11 (< 12-byte DNS header floor): rejected");

    uint8_t truncated[2 + 5] = {0x00, 0x0c};
    memset(truncated + 2, 'D', 5);
    CHECK(frame_ok(truncated, sizeof(truncated), NULL) == -1,
          "declared=12 but only 5 bytes follow: rejected (truncation)");

    uint8_t trailing[2 + 12 + 4];
    trailing[0] = 0x00;
    trailing[1] = 0x0c;
    memset(trailing + 2, 'E', 12 + 4);
    CHECK(frame_ok(trailing, sizeof(trailing), NULL) == -1,
          "declared=12 but 16 bytes follow: rejected (RFC 9250 forbids a "
          "second message on the same stream, and doqd reads to a clean FIN "
          "before calling this — trailing bytes are never legitimate)");

    CHECK(frame_ok(exact12, 1, NULL) == -1, "1-byte buffer (no full length prefix): rejected");
    CHECK(frame_ok(exact12, 0, NULL) == -1, "0-byte buffer: rejected");

    uint8_t zero_len[2] = {0x00, 0x00};
    CHECK(frame_ok(zero_len, sizeof(zero_len), NULL) == -1,
          "declared=0, nothing follows: rejected (below 12-byte floor)");

    /* A length prefix claiming more than fits in a DNS message's own 16-bit
     * length ceiling cannot happen from a 2-octet field (max 65535), but the
     * exact-match rule alone already rejects it unless the buffer is exactly
     * that large too — confirm the boundary at the top of the range. */
    static uint8_t max_frame[2 + 65535];
    max_frame[0] = 0xff;
    max_frame[1] = 0xff;
    memset(max_frame + 2, 'F', 65535);
    msglen = -1;
    CHECK(frame_ok(max_frame, sizeof(max_frame), &msglen) == 0 && msglen == 65535,
          "declared=65535 (max), buffer=2+65535: accepted");
}

int main(void) {
    test_doq_frame_next();
    printf("\n%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
