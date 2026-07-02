/* tests/test_ede.c
 *
 * Known-answer test for resolverd's RFC 8914 Extended DNS Error mapping:
 * ede_for_resolve_failure() turns a dns_resolve() failure code into the
 * IANA-numbered EDE info code a stub client sees on the wire. This locks
 * the mapping against a silently-wrong constant (the exact bug class that
 * motivated auditing dns_wire.h's EDE_* values in the first place — see
 * CLAUDE-resolverd.md Add 5).
 *
 * The live network path (OPT gated on the client sending EDNS, EDE_NETWORK_
 * ERROR appearing on the wire for an unreachable upstream) is covered by
 * `make check-ede`'s dig-driven half. DNSSEC_BOGUS (rc==-2) is not
 * independently live-tested here: reaching it for real requires a
 * signature-tampering stub upstream, and dnssec_validate_response's BOGUS
 * detection itself already has known-answer + negative coverage in
 * check-dnssec — this test only needs to confirm the mapping from that
 * already-proven rc value to the correct wire constant.
 *
 * Build (from repo root):
 *   gcc -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -I. \
 *       -o test_ede tests/test_ede.c dns_wire.c sandbox.c -lssl -lcrypto -lpthread
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

int main(void) {
    printf("== ede_for_resolve_failure: rc -> RFC 8914 info code ==\n");

    int ede_code = -1;
    const char *ede_text = NULL;
    ede_for_resolve_failure(-2, &ede_code, &ede_text);
    CHECK(ede_code == EDE_DNSSEC_BOGUS, "rc=-2 (DNSSEC BOGUS) -> EDE_DNSSEC_BOGUS (6)");
    CHECK(ede_text != NULL && ede_text[0] != 0, "rc=-2 carries non-empty EXTRA-TEXT");

    ede_code = -1;
    ede_text = NULL;
    ede_for_resolve_failure(-1, &ede_code, &ede_text);
    CHECK(ede_code == EDE_NETWORK_ERROR, "rc=-1 (upstream unreachable) -> EDE_NETWORK_ERROR (23)");
    CHECK(ede_text != NULL && ede_text[0] != 0, "rc=-1 carries non-empty EXTRA-TEXT");

    /* Any other negative code (defensive — dns_resolve today only returns
     * -1/-2) must still fail closed to a defined code, not garbage. */
    ede_code = -1;
    ede_text = NULL;
    ede_for_resolve_failure(-99, &ede_code, &ede_text);
    CHECK(ede_code == EDE_NETWORK_ERROR, "unrecognized negative rc defaults to EDE_NETWORK_ERROR");

    /* The two codes must be numerically what the IANA registry says, not
     * just internally self-consistent (the whole point of the audit that
     * preceded this). */
    CHECK(EDE_DNSSEC_BOGUS == 6, "EDE_DNSSEC_BOGUS == IANA code 6");
    CHECK(EDE_NETWORK_ERROR == 23, "EDE_NETWORK_ERROR == IANA code 23");

    if (g_failures == 0) {
        printf("\nALL TESTS PASSED\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED\n", g_failures);
    return 1;
}
