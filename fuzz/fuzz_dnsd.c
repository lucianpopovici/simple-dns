/* fuzz/fuzz_dnsd.c
 *
 * libFuzzer harness over dnsd's request entry point, dns_process() — the
 * function every UDP/TCP/DoT/DoH/DoQ message reaches — covering QUERY,
 * UPDATE and NOTIFY handling, EDNS/cookie parsing, and the TSIG / SIG(0) RR
 * parsers (tsig_find, sig0_present) that the audit asked to fuzz
 * (CLAUDE-roadmap.md Phase 0b step 9; SECURITY_AUDIT.md 2026-11-15).
 *
 * The harness #includes dns_server.c (its main() is gated by UNIT_TEST) so the
 * static functions and file-scope state are reachable.
 *
 * Isolation: dnsd's Valkey client is pointed at a port nothing listens on, so
 * every Valkey read misses and every write fails — a fuzzed UPDATE can never
 * reach a real Valkey. The primary zone is seeded in memory, a TSIG key is
 * configured (so tsig_verify runs its full MAC path), and unsigned UPDATE is
 * allowed from the harness's client address so the UPDATE parser past the
 * authentication gate is exercised too.
 *
 * Build + 60 s smoke:  make fuzz-dnsd   (clang, ASan+UBSan+libFuzzer)
 * Every parser bug fixed MUST add its triggering input to fuzz/corpus_dnsd.
 */
#include <stddef.h>
#include <stdint.h>

#include "dns_server.c"

static client_addr_t g_fuzz_client;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    g_valkey_port = 1; /* nothing listens here: Valkey calls fail fast */
    g_console_level = LOG_EMERG;
    g_syslog_enabled = 0;
    safe_strcpy(g_zone_name, "example.local", sizeof(g_zone_name));
    seed_primary_zone();
    static const char key[] = "0123456789abcdef0123456789abcdef";
    memcpy(g_tsig_secret, key, sizeof(key) - 1);
    g_tsig_secret_len = (int) sizeof(key) - 1;
    safe_strcpy(g_tsig_key_name, "tsig-key", sizeof(g_tsig_key_name));
    safe_strcpy(g_update_unsigned_allow, "127.0.0.1", sizeof(g_update_unsigned_allow));
    memset(&g_fuzz_client, 0, sizeof(g_fuzz_client));
    g_fuzz_client.family = AF_INET;
    g_fuzz_client.u.v4.s_addr = htonl(INADDR_LOOPBACK);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535)
        return 0;
    static uint8_t resp[65535];
    /* UDP and TCP framing take different size limits / truncation paths. */
    dns_process(data, (int) size, resp, (int) sizeof(resp), 0, &g_fuzz_client);
    dns_process(data, (int) size, resp, (int) sizeof(resp), 1, &g_fuzz_client);
    /* The RR-level parsers, called directly as well. */
    tsig_rr_t t;
    memset(&t, 0, sizeof(t));
    if (tsig_find(data, (int) size, &t))
        (void) tsig_verify(data, (int) size, &t);
    (void) sig0_present(data, (int) size);
    return 0;
}
