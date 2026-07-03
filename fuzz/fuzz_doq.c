/* fuzz/fuzz_doq.c
 *
 * libFuzzer harness for doqd's RFC 9250 §4.3 stream-framing parser
 * (doq_frame_next(), `static` inside doqd.c). This is the only part of doqd
 * that parses attacker-controlled bytes with any structure to it — everything
 * past a valid frame is opaque and handed straight to dnsd over loopback
 * (dns_forward), which doqd never interprets. A framing bug here (accepting
 * a length that doesn't match the buffer, or reading past it) is exactly the
 * kind of bug CLAUDE.md's fuzzing-is-mandatory rule exists to catch before it
 * reaches a QUIC stream from a real client.
 *
 * Target: doq_frame_next(buf, len, &msg, &msglen) — must never report success
 * with the returned message pointer/length describing bytes outside
 * [buf, buf+len), and must reject (return -1) on any length prefix that does
 * not exactly match the available
 * bytes (RFC 9250 forbids more than one message per stream, so "declared len
 * != remaining len" is a hard error, not "wait for more data" — doqd reads to
 * a clean FIN before ever calling this, so there is no partial-buffer case to
 * distinguish from a truncation attack).
 *
 * Because the target is `static` inside doqd.c, the harness is compiled as
 * part of doqd.c's translation unit by #including it (same pattern as
 * fuzz_response.c for resolverd.c). -DUNIT_TEST drops doqd's own main() so
 * libFuzzer can supply one.
 *
 * Build (against the ASan+UBSan+fuzzer toolchain; needs OpenSSL 3.5+ headers
 * for doqd.c's own includes, same floor as the doqd-ossl-sanity Makefile
 * check):
 *
 *     clang -g -O1 -fsanitize=fuzzer,address,undefined -DUNIT_TEST -I. \
 *           -Wno-unused-function -o fuzz/fuzz_doq \
 *           fuzz/fuzz_doq.c dns_wire.c -lssl -lcrypto -lpthread
 *
 * Run a 60s smoke and grow the corpus:
 *
 *     mkdir -p fuzz/corpus_doq
 *     ./fuzz/fuzz_doq -max_total_time=60 fuzz/corpus_doq
 *
 * Every parser bug fixed MUST add its triggering input to fuzz/corpus_doq as
 * a permanent regression case (CLAUDE.md -> Development process -> Testing).
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "doqd.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (size_t) INT_MAX) {
        return 0;
    }
    int len = (int) size;

    const uint8_t *msg = NULL;
    int msglen = 0;
    int r = doq_frame_next(data, len, &msg, &msglen);
    if (r == 0) {
        /* Every byte doq_frame_next claims as the message must be a real,
         * in-bounds subrange of the input the fuzzer gave us — touch the
         * first and last byte so ASan catches an off-by-one immediately
         * rather than only on a lucky heap layout. */
        if (msglen < 0 || msg < data || msg + msglen > data + len) {
            __builtin_trap();
        }
        if (msglen > 0) {
            volatile uint8_t first = msg[0];
            volatile uint8_t last = msg[msglen - 1];
            (void) first;
            (void) last;
        }
    }
    (void) r;
    return 0;
}
