/* fuzz/fuzz_name_from_wire.c
 *
 * libFuzzer harness for the DNS name decompression parser — the single
 * highest-risk function in the codebase (untrusted input, pointer following,
 * manual length math).
 *
 * DEPENDENCY: this assumes migration Step 1 is done, i.e. name_from_wire has
 * been moved into libdnswire and is declared in dns_wire.h with external
 * linkage. The expected prototype is:
 *
 *     int name_from_wire(const uint8_t *pkt, int plen, int off,
 *                        char *out, int olen);
 *
 * Until Step 1 lands, name_from_wire is `static` inside dns_server.c and is not
 * linkable here. (Stop-gap only if you must fuzz before the split: copy the
 * function + its strlower dependency into a small standalone .c and link that
 * instead — but prefer doing Step 1 first.)
 *
 * Build (against the ASan+UBSan+fuzzer toolchain):
 *
 *     clang -g -O1 -fsanitize=fuzzer,address,undefined -I. \
 *           fuzz/fuzz_name_from_wire.c dns_wire.c -o fuzz_name_from_wire
 *
 * Run a 60s smoke and grow the corpus:
 *
 *     mkdir -p fuzz/corpus
 *     ./fuzz_name_from_wire -max_total_time=60 fuzz/corpus
 *
 * Reproduce a crash:
 *
 *     ./fuzz_name_from_wire crash-<hash>
 *
 * Every parser bug fixed MUST add its triggering input to fuzz/corpus as a
 * permanent regression case (see CLAUDE.md → Development process → Testing).
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "dns_wire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (size_t) INT_MAX) {
        return 0;
    }

    /* Treat the whole input as a DNS message. Output buffer is the maximum
     * legal name length (255) + NUL; name_from_wire must never write past it. */
    char out[256];
    int plen = (int) size;

    /* (1) Start offset derived from the input so the fuzzer explores names
     *     beginning anywhere — including mid-label and out-of-range offsets.
     *     name_from_wire guards pos >= plen, so any offset is safe to pass. */
    int off = (int) (data[0] % size);
    (void) name_from_wire(data, plen, off, out, (int) sizeof(out));

    /* (2) Also exercise offset 12, the canonical position of the first name in
     *     a real query (immediately after the 12-byte header). */
    if (plen > 12) {
        (void) name_from_wire(data, plen, 12, out, (int) sizeof(out));
    }

    /* Return value is intentionally ignored: this harness hunts memory-safety
     * and non-termination bugs. ASan/UBSan catch the former; libFuzzer's
     * timeout catches compression-pointer loops. Correctness (right name out)
     * is covered by the unit tests, not here. */
    return 0;
}
