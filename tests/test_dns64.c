/* tests/test_dns64.c
 *
 * Known-answer + negative tests for RFC 6147 DNS64 AAAA synthesis in
 * resolverd.c:
 *   - dns64_synthesize    IPv4-in-/96-prefix embedding (RFC 6147 §5.1)
 *   - dns64_excluded      DNS64_EXCLUDE suffix matching
 *   - dns64_synthesize_from_a   the pure synthesis loop (A -> AAAA, CNAME
 *                          passthrough), independent of any live upstream
 *   - dns64_maybe_synthesize's guard conditions (disabled / wrong qtype /
 *     not a genuine NODATA / DNSSEC SECURE) — all four return before ever
 *     touching dns_resolve_core, so they're directly testable here without
 *     network I/O. The positive (upstream-calling) path is covered
 *     end-to-end by the live `make check-dns64` test instead.
 *
 * Build (from repo root):
 *   gcc -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -I. \
 *       -o test_dns64 tests/test_dns64.c dns_wire.c sandbox.c -lssl -lcrypto -lpthread
 */

#define UNIT_TEST 1
#include "resolverd.c"

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

static void test_synthesize(void) {
    printf("== dns64_synthesize: KAT ==\n");
    uint8_t prefix[16];
    inet_pton(AF_INET6, "64:ff9b::", prefix);
    struct in_addr a4;
    inet_pton(AF_INET, "203.0.113.90", &a4);
    uint8_t out[16];
    dns64_synthesize(prefix, (const uint8_t *) &a4, out);
    char txt[64];
    inet_ntop(AF_INET6, out, txt, sizeof(txt));
    CHECK(strcmp(txt, "64:ff9b::cb00:715a") == 0, "203.0.113.90 -> 64:ff9b::cb00:715a");

    /* A different prefix must still embed correctly at the same offset. */
    inet_pton(AF_INET6, "2001:db8:64::", prefix);
    inet_pton(AF_INET, "192.0.2.1", &a4);
    dns64_synthesize(prefix, (const uint8_t *) &a4, out);
    inet_ntop(AF_INET6, out, txt, sizeof(txt));
    CHECK(strcmp(txt, "2001:db8:64::c000:201") == 0,
          "network-specific prefix: 192.0.2.1 -> 2001:db8:64::c000:201");
}

static void test_excluded(void) {
    printf("== dns64_excluded ==\n");
    safe_strcpy(g_cfg.dns64_exclude, "excluded.test,other.example", sizeof(g_cfg.dns64_exclude));
    CHECK(dns64_excluded("host.excluded.test") == 1, "subdomain of an excluded suffix matches");
    CHECK(dns64_excluded("excluded.test") == 1, "the excluded suffix itself matches");
    CHECK(dns64_excluded("other.example") == 1, "second comma-separated entry matches");
    CHECK(dns64_excluded("notexcluded.test") == 0, "unrelated name does not match");
    g_cfg.dns64_exclude[0] = 0;
    CHECK(dns64_excluded("anything.test") == 0, "empty exclude list excludes nothing");
}

static void test_synthesize_from_a(void) {
    printf("== dns64_synthesize_from_a: pure synthesis loop ==\n");
    uint8_t prefix[16];
    inet_pton(AF_INET6, "64:ff9b::", prefix);
    memcpy(g_cfg.dns64_prefix, prefix, 16);

    resolve_result_t a_result, result;
    memset(&a_result, 0, sizeof(a_result));
    memset(&result, 0, sizeof(result));
    a_result.ancount = 2;
    a_result.answer_types[0] = DNS_TYPE_A;
    safe_strcpy(a_result.answer_names[0], "v4only.test", sizeof(a_result.answer_names[0]));
    safe_strcpy(a_result.answers[0], "203.0.113.90", sizeof(a_result.answers[0]));
    a_result.answer_ttls[0] = 60;
    a_result.answer_types[1] = DNS_TYPE_A;
    safe_strcpy(a_result.answer_names[1], "v4only.test", sizeof(a_result.answer_names[1]));
    safe_strcpy(a_result.answers[1], "203.0.113.91", sizeof(a_result.answers[1]));
    a_result.answer_ttls[1] = 60;

    dns64_synthesize_from_a(&a_result, &result);
    CHECK(result.ancount == 2, "two A records -> two synthesized AAAA records");
    CHECK(result.answer_types[0] == DNS_TYPE_AAAA && result.answer_types[1] == DNS_TYPE_AAAA,
          "synthesized records are type AAAA");
    CHECK(strcmp(result.answers[0], "64:ff9b::cb00:715a") == 0,
          "first record synthesized correctly");
    CHECK(strcmp(result.answers[1], "64:ff9b::cb00:715b") == 0,
          "second record synthesized correctly");
    CHECK(result.answer_ttls[0] == 60, "TTL carried over from the A record");
    CHECK(strcmp(result.answer_names[0], "v4only.test") == 0, "owner name carried over");

    /* CNAME chain: a CNAME hop followed by the A record must both survive,
     * with the AAAA's owner name matching the CNAME target, not the
     * original query name. */
    memset(&a_result, 0, sizeof(a_result));
    memset(&result, 0, sizeof(result));
    a_result.ancount = 2;
    a_result.answer_types[0] = DNS_TYPE_CNAME;
    safe_strcpy(a_result.answer_names[0], "alias.test", sizeof(a_result.answer_names[0]));
    safe_strcpy(a_result.answers[0], "target.test", sizeof(a_result.answers[0]));
    a_result.answer_ttls[0] = 120;
    a_result.answer_types[1] = DNS_TYPE_A;
    safe_strcpy(a_result.answer_names[1], "target.test", sizeof(a_result.answer_names[1]));
    safe_strcpy(a_result.answers[1], "192.0.2.1", sizeof(a_result.answers[1]));
    a_result.answer_ttls[1] = 60;

    dns64_synthesize_from_a(&a_result, &result);
    CHECK(result.ancount == 2, "CNAME + A -> CNAME + synthesized AAAA (chain preserved)");
    CHECK(result.answer_types[0] == DNS_TYPE_CNAME && result.answer_types[1] == DNS_TYPE_AAAA,
          "CNAME record kept as-is, second record synthesized");
    CHECK(strcmp(result.answer_names[1], "target.test") == 0,
          "synthesized AAAA's owner is the CNAME target, not the original qname");
    CHECK(strcmp(result.answers[1], "64:ff9b::c000:201") == 0, "CNAME-chain synthesis is correct");

    /* Negative: a malformed A rdata string must be skipped, not crash or
     * synthesize garbage. */
    memset(&a_result, 0, sizeof(a_result));
    memset(&result, 0, sizeof(result));
    a_result.ancount = 1;
    a_result.answer_types[0] = DNS_TYPE_A;
    safe_strcpy(a_result.answer_names[0], "bad.test", sizeof(a_result.answer_names[0]));
    safe_strcpy(a_result.answers[0], "not-an-ip", sizeof(a_result.answers[0]));
    dns64_synthesize_from_a(&a_result, &result);
    CHECK(result.ancount == 0, "unparseable A rdata is skipped, not synthesized");
}

static void test_maybe_synthesize_guards(void) {
    printf("== dns64_maybe_synthesize: guard conditions (no live upstream needed) ==\n");
    resolve_result_t result;

    /* Guard 1: disabled entirely. */
    g_cfg.dns64_enabled = 0;
    memset(&result, 0, sizeof(result));
    result.rcode = 0;
    result.ancount = 0;
    dns64_maybe_synthesize("v4only.test", DNS_TYPE_AAAA, &result, 0);
    CHECK(result.ancount == 0, "dns64_enabled=0 -> no synthesis attempted");

    g_cfg.dns64_enabled = 1;

    /* Guard 2: wrong qtype (A, not AAAA). */
    memset(&result, 0, sizeof(result));
    result.rcode = 0;
    result.ancount = 0;
    dns64_maybe_synthesize("v4only.test", DNS_TYPE_A, &result, 0);
    CHECK(result.ancount == 0, "qtype=A is never touched by DNS64");

    /* Guard 3: not a genuine NODATA — a real AAAA answer already present. */
    memset(&result, 0, sizeof(result));
    result.rcode = 0;
    result.ancount = 1;
    result.answer_types[0] = DNS_TYPE_AAAA;
    safe_strcpy(result.answers[0], "::1234", sizeof(result.answers[0]));
    dns64_maybe_synthesize("dual.test", DNS_TYPE_AAAA, &result, 0);
    CHECK(result.ancount == 1 && strcmp(result.answers[0], "::1234") == 0,
          "a real AAAA answer is never overwritten");

    /* Guard 3b: NXDOMAIN is not NODATA — must not synthesize either. */
    memset(&result, 0, sizeof(result));
    result.rcode = 3; /* NXDOMAIN */
    result.ancount = 0;
    dns64_maybe_synthesize("doesnotexist.test", DNS_TYPE_AAAA, &result, 3);
    CHECK(result.ancount == 0, "NXDOMAIN is not synthesized over (only genuine NODATA is)");

    /* Guard 4: the critical DNSSEC×DNS64 guardrail — a validated SECURE
     * negative response must never be overwritten with synthesized data. */
    memset(&result, 0, sizeof(result));
    result.rcode = 0;
    result.ancount = 0;
    result.dnssec_status = (int) DNSSEC_SECURE;
    dns64_maybe_synthesize("v4only.test", DNS_TYPE_AAAA, &result, 0);
    CHECK(result.ancount == 0, "DNSSEC SECURE NODATA is never synthesized over (RFC 6147 §3/§5.5)");

    /* Guard 5: excluded name. */
    safe_strcpy(g_cfg.dns64_exclude, "v4only.test", sizeof(g_cfg.dns64_exclude));
    memset(&result, 0, sizeof(result));
    result.rcode = 0;
    result.ancount = 0;
    dns64_maybe_synthesize("v4only.test", DNS_TYPE_AAAA, &result, 0);
    CHECK(result.ancount == 0, "excluded name is never synthesized for");
    g_cfg.dns64_exclude[0] = 0;
}

int main(void) {
    test_synthesize();
    test_excluded();
    test_synthesize_from_a();
    test_maybe_synthesize_guards();

    if (g_failures == 0) {
        printf("\nALL TESTS PASSED\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED\n", g_failures);
    return 1;
}
