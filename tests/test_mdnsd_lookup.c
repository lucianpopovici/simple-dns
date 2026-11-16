/* mdnsd unit tests (CLAUDE-medium-fixes.md 7f: CSA-DOS-005 / CSA-INJ-001).
 * Builds mdnsd.c with UNIT_TEST (no main) and checks:
 *   - zone_key_for keeps glob metacharacters literal (no pattern anywhere);
 *   - zone_lookup_get finds a record by suffix walk and a crafted '*' label
 *     does NOT match it (it used to, via SCAN MATCH zone:*:A:<qname>);
 *   - source_is_onlink accepts loopback / link-local and refuses a routed
 *     IPv6 address and an IPv4 address on no local subnet.
 * The lookup case needs Valkey on 127.0.0.1:6379 and is skipped without it. */
#define UNIT_TEST 1
#include "mdnsd.c"

static int g_fail = 0;
#define CHECK(c, msg)                                                                              \
    do {                                                                                           \
        printf("  %s  %s\n", (c) ? "PASS" : "FAIL", msg);                                          \
        if (!(c))                                                                                  \
            g_fail++;                                                                              \
    } while (0)

int main(void) {
    char k[700];
    CHECK(zone_key_for(k, sizeof(k), "lab.local", "A", "*.lab.local") &&
              strcmp(k, "zone:lab.local:A:*.lab.local") == 0,
          "zone_key_for: '*' stays a literal byte in a GET key");

    struct sockaddr_in s4;
    memset(&s4, 0, sizeof(s4));
    s4.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &s4.sin_addr);
    CHECK(source_is_onlink(AF_INET, &s4), "on-link: IPv4 loopback accepted");
    inet_pton(AF_INET, "198.51.100.77", &s4.sin_addr); /* TEST-NET-2: on no local subnet */
    CHECK(!source_is_onlink(AF_INET, &s4), "on-link: routed IPv4 source refused");
    struct sockaddr_in6 s6;
    memset(&s6, 0, sizeof(s6));
    s6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "fe80::1", &s6.sin6_addr);
    CHECK(source_is_onlink(AF_INET6, &s6), "on-link: IPv6 link-local accepted");
    inet_pton(AF_INET6, "2001:db8::1", &s6.sin6_addr);
    CHECK(!source_is_onlink(AF_INET6, &s6), "on-link: routed IPv6 source refused");

    char val[512];
    if (vkc_ensure_to(&vk, g_valkey_host, g_valkey_port, g_valkey_pass) < 0) {
        printf("  SKIP  Valkey not reachable — lookup cases skipped\n");
    } else {
        static vkc_reply_t r; /* large reply buffer: keep it off the stack */
        vkc_cmd(&vk, &r, 3, "SET", "zone:mdtest.local:A:host.mdtest.local", "60|10.9.8.7");
        CHECK(zone_lookup_get("A", "host.mdtest.local", val, sizeof(val)) &&
                  strcmp(val, "60|10.9.8.7") == 0,
              "zone_lookup_get: record found by suffix walk");
        CHECK(!zone_lookup_get("A", "*.mdtest.local", val, sizeof(val)),
              "zone_lookup_get: a '*' label does not match another record (CSA-INJ-001)");
        CHECK(!zone_lookup_get("A", "h?st.mdtest.local", val, sizeof(val)),
              "zone_lookup_get: a '?' label does not match another record");
        vkc_cmd(&vk, &r, 2, "DEL", "zone:mdtest.local:A:host.mdtest.local");
    }
    printf("%s\n", g_fail ? "FAILURES" : "ALL TESTS PASSED");
    return g_fail;
}
