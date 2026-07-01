/* fuzz/fuzz_response.c
 *
 * libFuzzer harness for resolverd's UNTRUSTED upstream-response parsers — the
 * bytes that come back from a recursive/forwarding query and feed the cache and
 * the RFC 5452 / RFC 7873 anti-spoofing checks. This is the audit's stated
 * highest-value next step (SECURITY_AUDIT.md, Phase 0 #6) and the Definition-of-
 * Done fuzz requirement for the CSA-NET-001 response-validation change.
 *
 * Targets (all `static` inside resolverd.c):
 *   - response_opt_parse()        EDNS/OPT walk + Server-Cookie extraction
 *   - response_matches_query()    RFC 5452 ID/question acceptance gate
 *   - parse_response_to_entry()   full answer/negative/SOA parse + allocation
 *
 * Because the targets are static and lean on file-scope state (g_cfg cache
 * bounds, g_stat_mutex), the harness is compiled as part of resolverd.c's
 * translation unit by #including it. resolverd's main() is already wrapped in
 * `#ifndef UNIT_TEST`, so -DUNIT_TEST drops it and libFuzzer supplies main.
 *
 * Build (against the ASan+UBSan+fuzzer toolchain):
 *
 *     clang -g -O1 -fsanitize=fuzzer,address,undefined -DUNIT_TEST -I. \
 *           -Wno-unused-function -o fuzz/fuzz_response \
 *           fuzz/fuzz_response.c dns_wire.c sandbox.c -lssl -lcrypto -lpthread
 *
 * Run a 60s smoke and grow the corpus:
 *
 *     mkdir -p fuzz/corpus_response
 *     ./fuzz/fuzz_response -max_total_time=60 fuzz/corpus_response
 *
 * Every parser bug fixed MUST add its triggering input to fuzz/corpus_response
 * as a permanent regression case (CLAUDE.md -> Development process -> Testing).
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "resolverd.c"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    /* Give the cache-TTL clamp realistic, non-zero bounds so that path is
     * exercised meaningfully rather than collapsing every TTL to 0. */
    g_cfg.cache_ttl_max = 86400;
    g_cfg.cache_neg_ttl = 3600;
    g_cfg.cache_neg_ttl_min = 60;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* A DNS message is at least a 12-byte header; below that the parsers all
     * early-return and there is nothing to explore. */
    if (size < 12 || size > (size_t) INT_MAX) {
        return 0;
    }
    const uint8_t *resp = data;
    int rlen = (int) size;

    /* (1) EDNS/OPT + Server-Cookie extraction. scookie sized exactly as the
     *     real call site (the function clamps the copy to this length). */
    uint8_t scookie[DNS_COOKIE_SERVER_MAX];
    int slen = 0;
    (void) response_opt_parse(resp, rlen, scookie, &slen);

    /* (2) RFC 5452 acceptance gate. Derive the expected txn ID from the packet's
     *     own header so the ID check passes and the deeper question-name / QTYPE
     *     / QCLASS parse is reached; drive QTYPE from the input. Run both a
     *     matching and a deliberately-mismatched ID so the reject path is
     *     covered too. */
    uint16_t id = get16(resp, 0);
    uint16_t qtype = get16(resp, 4); /* arbitrary input-derived 16 bits */
    (void) response_matches_query(resp, rlen, id, "example.com", qtype, 0);
    (void) response_matches_query(resp, rlen, (uint16_t) (id ^ 0x55), "example.com", qtype, 0);
    /* enforce_case exercises qname_from_wire_case_preserving (RFC 5452 0x20)
     * on the same untrusted bytes — new parser surface, same coverage. */
    (void) response_matches_query(resp, rlen, id, "example.com", qtype, 1);
    (void) response_matches_query(resp, rlen, id, "ExAmPlE.CoM", qtype, 1);

    /* (3) Full response -> cache entry: answer RRs, NXDOMAIN/NODATA negative
     *     caching, SOA-minimum extraction, per-RR rdata allocation. Free what it
     *     builds so ASan accounts every allocation on every iteration. */
    cache_entry_t *e = parse_response_to_entry(resp, rlen, "example.com", qtype);
    if (e) {
        cache_entry_free(e);
    }

    /* Memory-safety / non-termination hunt: return values are intentionally
     * ignored. ASan/UBSan catch OOB + UB; libFuzzer's timeout catches loops. */
    return 0;
}
