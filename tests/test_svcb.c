/* tests/test_svcb.c — RFC 9460 SVCB/HTTPS codec (svcb_present_to_tlv +
 * svcb_tlv_to_wire in libdnswire).
 *
 * Known-answer + parse-back + negative tests for the presentation → TLV → wire
 * path. Also doubles as the hex-TLV generator for the dnsd integration test
 * (`make check-svcb`): run with `--encode "<presentation>"` to print the hex
 * blob that gets stored as a zone:<z>:{SVCB,HTTPS}:<name> value.
 *
 * Build (from repo root): see `make check-svcb`.
 */
#include "dns_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

/* present → TLV → wire. Returns wire length or -1. */
static int present_to_wire(const char *present, uint8_t *wire, int cap) {
    uint8_t tlv[512];
    int tl = svcb_present_to_tlv(present, tlv, sizeof(tlv));
    if (tl < 0)
        return -1;
    return svcb_tlv_to_wire(tlv, tl, wire, cap);
}

/* KAT 1 — exact wire bytes for "1 . port=53":
 *   SvcPriority 0x0001 | TargetName "." (0x00) | key 3 (port) len 2 value 0x0035 */
static void kat_exact(void) {
    const uint8_t expect[] = {0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x35};
    uint8_t wire[64];
    int n = present_to_wire("1 . port=53", wire, sizeof(wire));
    CHECK(n == (int) sizeof(expect) && memcmp(wire, expect, sizeof(expect)) == 0,
          "exact wire for '1 . port=53'");
}

/* KAT 2 — parse the emitted wire back and check every field for a ServiceMode
 * record carrying alpn, no-default-alpn, port, ipv4hint, and ipv6hint. */
static void kat_parse_back(void) {
    const char *p = "1 svc.example.net. alpn=h2,h3 no-default-alpn port=8443 "
                    "ipv4hint=192.0.2.1 ipv6hint=2001:db8::1";
    uint8_t w[256];
    int n = present_to_wire(p, w, sizeof(w));
    if (n < 0) {
        CHECK(0, "ServiceMode record encodes");
        return;
    }
    int o = 0;
    uint16_t prio = (uint16_t) ((w[0] << 8) | w[1]);
    o = 2;
    char target[256];
    int t = name_from_wire(w, n, o, target, sizeof(target));
    CHECK(prio == 1, "ServiceMode priority == 1");
    CHECK(t > 0 && strcasecmp(target, "svc.example.net") == 0, "target == svc.example.net");
    o = t;
    /* Walk SvcParams: key(2) len(2) value(len), ascending keys, no dups. */
    int seen_alpn = 0, seen_ndalpn = 0, seen_port = 0, seen_v4 = 0, seen_v6 = 0;
    int order_ok = 1, last_key = -1;
    while (o + 4 <= n) {
        int key = (w[o] << 8) | w[o + 1];
        int vl = (w[o + 2] << 8) | w[o + 3];
        o += 4;
        if (o + vl > n)
            break;
        if (key <= last_key)
            order_ok = 0;
        last_key = key;
        if (key == SVCB_KEY_ALPN)
            seen_alpn = (vl == 6 && w[o] == 2 && w[o + 1] == 'h' && w[o + 2] == '2' &&
                         w[o + 3] == 2 && w[o + 4] == 'h' && w[o + 5] == '3');
        else if (key == SVCB_KEY_NO_DEFAULT_ALPN)
            seen_ndalpn = (vl == 0);
        else if (key == SVCB_KEY_PORT)
            seen_port = (vl == 2 && ((w[o] << 8) | w[o + 1]) == 8443);
        else if (key == SVCB_KEY_IPV4HINT)
            seen_v4 = (vl == 4 && w[o] == 192 && w[o + 1] == 0 && w[o + 2] == 2 && w[o + 3] == 1);
        else if (key == SVCB_KEY_IPV6HINT)
            seen_v6 = (vl == 16 && w[o] == 0x20 && w[o + 1] == 0x01 && w[o + 2] == 0x0d &&
                       w[o + 3] == 0xb8 && w[o + 15] == 0x01);
        o += vl;
    }
    CHECK(o == n, "SvcParams consume the whole rdata exactly");
    CHECK(order_ok, "SvcParams emitted in ascending key order");
    CHECK(seen_alpn, "alpn = h2,h3 (length-prefixed)");
    CHECK(seen_ndalpn, "no-default-alpn present, empty value");
    CHECK(seen_port, "port = 8443");
    CHECK(seen_v4, "ipv4hint = 192.0.2.1");
    CHECK(seen_v6, "ipv6hint = 2001:db8::1");
}

/* KAT 3 — AliasMode: priority 0, target only, no SvcParams. */
static void kat_alias(void) {
    uint8_t w[64];
    int n = present_to_wire("0 svc.example.net.", w, sizeof(w));
    int prio = (w[0] << 8) | w[1];
    char target[256];
    int t = name_from_wire(w, n, 2, target, sizeof(target));
    CHECK(n > 0 && prio == 0, "AliasMode priority == 0");
    CHECK(t == n && strcasecmp(target, "svc.example.net") == 0, "AliasMode target only, no params");
}

static void negatives(void) {
    uint8_t w[256];
    CHECK(present_to_wire("1", w, sizeof(w)) < 0, "reject: no target");
    CHECK(present_to_wire("1 . port=99999", w, sizeof(w)) < 0, "reject: port out of range");
    CHECK(present_to_wire("1 . bogus=x", w, sizeof(w)) < 0, "reject: unknown SvcParamKey");
    CHECK(present_to_wire("1 . alpn=h2 alpn=h3", w, sizeof(w)) < 0, "reject: duplicate key");
    CHECK(present_to_wire("0 svc.example.net. alpn=h2", w, sizeof(w)) < 0,
          "reject: AliasMode with SvcParams");
    CHECK(present_to_wire("70000 .", w, sizeof(w)) < 0, "reject: priority out of range");
    CHECK(present_to_wire("1 . ipv4hint=not.an.ip", w, sizeof(w)) < 0, "reject: bad ipv4hint");
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--encode") == 0) {
        uint8_t tlv[512];
        int tl = svcb_present_to_tlv(argv[2], tlv, sizeof(tlv));
        if (tl < 0) {
            fprintf(stderr, "encode failed\n");
            return 1;
        }
        char hex[1100];
        hex_enc(tlv, tl, hex);
        printf("%s\n", hex);
        return 0;
    }
    kat_exact();
    kat_parse_back();
    kat_alias();
    negatives();
    if (g_failures) {
        printf("\n%d FAILURE(S)\n", g_failures);
        return 1;
    }
    printf("\nALL TESTS PASSED\n");
    return 0;
}
