/* fuzz/fuzz_tlv.c
 *
 * libFuzzer harness for the ADR-003 length-prefixed TLV codec (dns_wire.c) — the
 * structured encoding for complex/extensible Valkey values (SVCB SvcParams,
 * NAPTR, ZONEMD, ENUM, EPP). The READER parses bytes that arrive over the
 * inter-daemon bus, so it must never read out of bounds on a corrupt/hostile
 * blob; the WRITER must never overflow its destination. This hunts both.
 *
 * Build (against the ASan+UBSan+fuzzer toolchain):
 *
 *     clang -g -O1 -fsanitize=fuzzer,address,undefined -I. \
 *           fuzz/fuzz_tlv.c dns_wire.c -o fuzz/fuzz_tlv
 *
 *     mkdir -p fuzz/corpus_tlv
 *     ./fuzz/fuzz_tlv -max_total_time=60 fuzz/corpus_tlv
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "dns_wire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (size_t) INT_MAX) {
        return 0;
    }
    int len = (int) size;

    /* (1) READER: walk the blob as untrusted input. Every item must stay in
     *     bounds; a malformed length must return -1, a clean end 0 — never an
     *     OOB read (ASan would trip). */
    int version = tlv_version(data, len);

    /* (2) WRITER round-trip: re-encode each item the reader yields into a fresh
     *     blob. This exercises tlv_begin/tlv_put overflow handling on attacker-
     *     influenced tag/length/value triples. When the output fills, tlv_put
     *     returns -1 and we stop appending (ooff stays negative). */
    uint8_t out[70000];
    int ooff = tlv_begin(out, (int) sizeof(out), (uint8_t) (version < 0 ? 1 : version));

    int off = 1;
    uint8_t tag = 0;
    const uint8_t *val = NULL;
    uint16_t vlen = 0;
    int r;
    while ((r = tlv_next(data, len, &off, &tag, &val, &vlen)) == 1) {
        if (ooff >= 0) {
            ooff = tlv_put(out, (int) sizeof(out), ooff, tag, val, vlen);
        }
    }
    /* r is now 0 (clean end) or -1 (malformed framing); both are valid results.
     * Memory-safety is the property under test, not the return value. */
    (void) r;
    return 0;
}
