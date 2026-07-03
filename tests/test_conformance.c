/* Conformance tests for libdnswire (dns_wire.{c,h}).
 *
 * Covers:
 *   RFC 1982 — serial number arithmetic (serial_lt / serial_ge)
 *   RFC 2181 — DNS_TTL_MAX value
 *   RFC 4343 — case-insensitive type name round-trip (type2str / str2type)
 *   RFC 6891 — EDNS OPT RR parsing: do_bit position, NSID, Cookie, Padding
 *   RFC 9267 — label > 63 rejected; name_from_wire rejects forward pointers
 *   RFC 8906 — EDNS version field parsed correctly
 *
 * Compile (done via Makefile):
 *   cc -std=c99 -I. tests/test_conformance.c dns_wire.c -lssl -lcrypto -lpthread
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns_wire.h"

static int g_fail = 0;

static void check(int cond, const char *what) {
    printf("  %s  %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond)
        g_fail = 1;
}

/* ── RFC 1982: serial number arithmetic ─────────────────────────────────── */
static void test_serial_arithmetic(void) {
    printf("== RFC 1982 serial arithmetic ==\n");

    /* Basic less-than: adjacent values */
    check(serial_lt(1, 2), "serial_lt(1,2) is true");
    check(!serial_lt(2, 1), "serial_lt(2,1) is false");
    check(!serial_lt(5, 5), "serial_lt(5,5) is false (equal)");

    /* Wrap-around: 2^32-1 < 0 in serial space */
    check(serial_lt(0xFFFFFFFFu, 0), "serial_lt(MAX,0) wraps: MAX < 0");
    check(!serial_lt(0, 0xFFFFFFFFu), "serial_lt(0,MAX) wraps: 0 > MAX");

    /* Half-range boundary (RFC 1982 §3.2): when the difference is exactly
     * 2^31 the relationship is undefined — neither direction is true. */
    check(!serial_lt(0, 0x80000000u), "serial_lt(0, 2^31) undefined: returns false");
    check(!serial_lt(0x80000000u, 0), "serial_lt(2^31, 0) undefined: returns false");

    /* serial_ge is complement of serial_lt with equal allowed */
    check(serial_ge(2, 1), "serial_ge(2,1) is true");
    check(serial_ge(5, 5), "serial_ge(5,5) is true (equal)");
    check(!serial_ge(1, 2), "serial_ge(1,2) is false");
    check(serial_ge(0, 0xFFFFFFFFu), "serial_ge(0,MAX) wraps");

    /* Zone serial bump: old < new */
    check(serial_lt(2024010101u, 2024010102u), "zone serial bump: old < new");
    check(!serial_lt(2024010102u, 2024010101u), "zone serial bump: new > old");
}

/* ── RFC 2181: TTL range ────────────────────────────────────────────────── */
static void test_ttl_max(void) {
    printf("== RFC 2181 DNS_TTL_MAX ==\n");
    /* RFC 2181 §8: TTLs are unsigned 32-bit but the top bit must be zero */
    check(DNS_TTL_MAX == 0x7FFFFFFFu, "DNS_TTL_MAX is 2^31-1");
    check((uint32_t) DNS_TTL_MAX < 0x80000000u, "DNS_TTL_MAX high bit clear");
}

/* ── RFC 4343: case-insensitive type round-trip ──────────────────────────── */
static void test_type_names(void) {
    printf("== RFC 4343 type name case-insensitivity ==\n");

    /* Standard types round-trip */
    static const struct {
        uint16_t t;
        const char *name;
    } cases[] = {
        {DNS_TYPE_A, "A"},         {DNS_TYPE_NS, "NS"},     {DNS_TYPE_CNAME, "CNAME"},
        {DNS_TYPE_SOA, "SOA"},     {DNS_TYPE_PTR, "PTR"},   {DNS_TYPE_MX, "MX"},
        {DNS_TYPE_TXT, "TXT"},     {DNS_TYPE_AAAA, "AAAA"}, {DNS_TYPE_SRV, "SRV"},
        {DNS_TYPE_TLSA, "TLSA"},   {DNS_TYPE_CAA, "CAA"},   {DNS_TYPE_DS, "DS"},
        {DNS_TYPE_RRSIG, "RRSIG"}, {DNS_TYPE_NSEC, "NSEC"}, {DNS_TYPE_DNSKEY, "DNSKEY"},
        {DNS_TYPE_NSEC3, "NSEC3"}, {DNS_TYPE_ANY, "ANY"},
    };
    for (int i = 0; i < (int) (sizeof(cases) / sizeof(cases[0])); i++) {
        const char *got = type2str(cases[i].t);
        check(strcmp(got, cases[i].name) == 0, cases[i].name);
        check(str2type(cases[i].name) == cases[i].t, cases[i].name);
    }

    /* Case-insensitive parse (RFC 4343 §3) */
    check(str2type("aaaa") == DNS_TYPE_AAAA, "str2type('aaaa') case-insensitive");
    check(str2type("Cname") == DNS_TYPE_CNAME, "str2type('Cname') case-insensitive");

    /* Numeric TYPE<n> form */
    check(str2type("TYPE1") == DNS_TYPE_A, "str2type('TYPE1') numeric form");
    check(str2type("TYPE255") == DNS_TYPE_ANY, "str2type('TYPE255') = ANY");
    check(str2type("65535") == 65535, "str2type bare numeric");

    /* Unknown type gives TYPE<n> string */
    const char *unk = type2str(9999);
    check(strncmp(unk, "TYPE", 4) == 0, "unknown type gives TYPE<n> string");
}

/* ── RFC 9267: wire-format name rejection ───────────────────────────────── */
static void test_name_wire_rejection(void) {
    printf("== RFC 9267 name_to_wire / name_from_wire guards ==\n");

    uint8_t buf[256];
    char out[256];

    /* Label > 63 octets must be rejected (CSA-WIRE-001 guard) */
    {
        char longlabel[80];
        memset(longlabel, 'a', 64);
        longlabel[64] = '.';
        memcpy(longlabel + 65, "com", 3);
        longlabel[68] = 0;
        int r = name_to_wire(longlabel, buf, sizeof(buf));
        check(r == -1, "name_to_wire rejects label > 63 octets");
    }

    /* Valid name must succeed */
    {
        int r = name_to_wire("www.example.com", buf, sizeof(buf));
        check(r > 0, "name_to_wire accepts valid name");
    }

    /* Forward pointer in name_from_wire must be rejected */
    {
        const uint8_t pkt[] = {0xC0, 0x02, 3, 'f', 'o', 'o', 0};
        int r = name_from_wire(pkt, sizeof(pkt), 0, out, sizeof(out));
        check(r == -1, "name_from_wire rejects forward pointer");
    }

    /* Name > 255 octets: 32 labels of 7 chars = 256 bytes > limit */
    {
        char longname[512];
        int pos = 0;
        for (int i = 0; i < 32; i++) {
            memcpy(longname + pos, "abcdefg.", 8);
            pos += 8;
        }
        longname[pos - 1] = 0; /* trim trailing dot */
        int r = name_to_wire(longname, buf, sizeof(buf));
        check(r == -1, "name_to_wire rejects name > 255 octets");
    }
}

/* ── RFC 6891 / RFC 8906: EDNS OPT RR parsing ──────────────────────────── */
static void test_edns_parse(void) {
    printf("== RFC 6891 EDNS OPT RR parsing ==\n");

    /* Build a minimal DNS message with one OPT RR carrying:
     *   - max UDP payload 1232
     *   - DO bit set
     *   - EDNS version 0
     * Header: id=0x1234, QR+RD, qdcount=1, arcount=1
     * Question: root . IN A
     * OPT RR:  name=0, type=41, class=1232, ttl=(version=0|DO=1<<15), rdlen=0
     */
    uint8_t pkt[512];
    int off = 0;

    /* Header */
    put16(pkt, 0, 0x1234); /* id */
    put16(pkt, 2, 0x0100); /* QR=0 RD=1 */
    put16(pkt, 4, 1);      /* qdcount */
    put16(pkt, 6, 0);      /* ancount */
    put16(pkt, 8, 0);      /* nscount */
    put16(pkt, 10, 1);     /* arcount */
    off = 12;

    /* Question: root (1-byte 0), type A, class IN */
    pkt[off++] = 0; /* root name */
    put16(pkt, off, DNS_TYPE_A);
    off += 2;
    put16(pkt, off, DNS_CLASS_IN);
    off += 2;

    /* OPT RR: name=0 (root), type=41, class=maxudp, ttl=version|flags, rdlen=0 */
    pkt[off++] = 0; /* root name */
    put16(pkt, off, DNS_TYPE_OPT);
    off += 2;
    put16(pkt, off, 1232); /* max UDP payload */
    off += 2;
    pkt[off++] = 0;    /* extended rcode = 0 */
    pkt[off++] = 0;    /* EDNS version = 0 */
    pkt[off++] = 0x80; /* DO bit (byte 6 of OPT RR from owner start) */
    pkt[off++] = 0;
    put16(pkt, off, 0); /* rdlen = 0 */
    off += 2;

    int plen = off;
    edns_info_t ei;
    edns_parse(pkt, plen, &ei);

    check(ei.present, "EDNS OPT RR detected");
    check(ei.max_udp == 1232, "EDNS max UDP payload = 1232");
    check(ei.version == 0, "EDNS version = 0");
    check(ei.do_bit == 1, "DO bit set (RFC 6891 §6.1.3)");
    check(!ei.has_client_cookie, "no cookie when not present");
    check(!ei.nsid_req, "no NSID when not requested");
}

static void test_edns_parse_do_bit_position(void) {
    printf("== RFC 6891 DO-bit byte position ==\n");

    /* Build OPT with DO bit CLEAR — verify do_bit reads 0 */
    uint8_t pkt[64];
    put16(pkt, 0, 0);
    put16(pkt, 2, 0);
    put16(pkt, 4, 0);
    put16(pkt, 6, 0);
    put16(pkt, 8, 0);
    put16(pkt, 10, 1);

    int off = 12;
    pkt[off++] = 0;
    put16(pkt, off, DNS_TYPE_OPT);
    off += 2;
    put16(pkt, off, 512);
    off += 2;
    pkt[off++] = 0; /* rcode ext */
    pkt[off++] = 0; /* version */
    pkt[off++] = 0; /* DO bit CLEAR */
    pkt[off++] = 0;
    put16(pkt, off, 0);
    off += 2;

    edns_info_t ei;
    edns_parse(pkt, off, &ei);
    check(ei.present, "OPT present");
    check(ei.do_bit == 0, "DO bit clear when byte is 0x00");

    /* Now set only the DO bit (0x80 in byte offset +6 from OPT owner start) */
    pkt[off - 4] = 0x80;
    edns_parse(pkt, off, &ei);
    check(ei.do_bit == 1, "DO bit set when byte is 0x80 at correct offset");
}

static void test_edns_parse_nsid_cookie(void) {
    printf("== EDNS NSID + Cookie option parsing ==\n");

    /* Build OPT with NSID request (zero-length) and 8-byte client cookie */
    uint8_t pkt[128];
    int off = 0;

    /* Header */
    for (int i = 0; i < 12; i++)
        pkt[i] = 0;
    put16(pkt, 10, 1); /* arcount=1 */
    off = 12;

    /* OPT RR owner (root) */
    pkt[off++] = 0;
    put16(pkt, off, DNS_TYPE_OPT);
    off += 2;
    put16(pkt, off, 1232);
    off += 2;
    pkt[off++] = 0; /* rcode ext */
    pkt[off++] = 0; /* version */
    pkt[off++] = 0; /* flags hi */
    pkt[off++] = 0; /* flags lo */

    /* RDATA: NSID(code=3, len=0) + Cookie(code=10, len=8, value=1..8) */
    int rdlen_off = off;
    put16(pkt, off, 0);
    off += 2; /* rdlen placeholder */

    int rdata_start = off;
    put16(pkt, off, EDNS_OPT_NSID);
    off += 2;
    put16(pkt, off, 0);
    off += 2; /* zero-length NSID request */

    static const uint8_t ccookie[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    put16(pkt, off, EDNS_OPT_COOKIE);
    off += 2;
    put16(pkt, off, 8);
    off += 2;
    memcpy(pkt + off, ccookie, 8);
    off += 8;

    put16(pkt, rdlen_off, (uint16_t) (off - rdata_start));

    edns_info_t ei;
    edns_parse(pkt, off, &ei);

    check(ei.present, "OPT present");
    check(ei.nsid_req, "NSID option requested");
    check(ei.has_client_cookie, "client cookie present");
    check(memcmp(ei.client_cookie, ccookie, 8) == 0, "client cookie bytes correct");
}

/* ── edns_append_opt: appends valid OPT RR ──────────────────────────────── */
static void test_edns_append(void) {
    printf("== edns_append_opt output ==\n");

    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));
    /* arcount starts at 0 */
    int off = edns_append_opt(buf, 12, sizeof(buf), 0, 1, 0, NULL, NULL, NULL, -1, NULL, -1, 0,
                              NULL, 0, 0, 0, 0);
    check(off > 12, "edns_append_opt returns new offset > 12");
    check(get16(buf, 10) == 1, "arcount incremented to 1");
    /* Verify OPT type at wire position 12: 1 byte root name + 2 bytes type */
    check(buf[12] == 0, "OPT owner is root (byte 0)");
    check(get16(buf, 13) == DNS_TYPE_OPT, "OPT type = 41");
    /* DO bit is byte at offset 12+3+2+1+1 = 12+7 from buf start = 19 */
    /* Owner(1)+type(2)+class(2)+rcode(1)+version(1)+flags_hi(1)+flags_lo(1) */
    int opt_flags_hi = 12 + 1 + 2 + 2 + 1 + 1; /* = 19 */
    check((buf[opt_flags_hi] & 0x80) != 0, "DO bit set in response OPT");
}

/* ── RFC 9664: EDNS Update Lease option (SRP) ─────────────────────────────── */
static void test_update_lease_option(void) {
    printf("== RFC 9664 Update Lease option ==\n");

    /* Parse: 8-byte variant (LEASE + KEY-LEASE) in a request. */
    {
        uint8_t pkt[128];
        memset(pkt, 0, 12);
        put16(pkt, 10, 1); /* arcount=1 */
        int off = 12;
        pkt[off++] = 0; /* OPT owner = root */
        put16(pkt, off, DNS_TYPE_OPT);
        off += 2;
        put16(pkt, off, 1232);
        off += 2;
        pkt[off++] = 0;
        pkt[off++] = 0;
        pkt[off++] = 0;
        pkt[off++] = 0;
        int rdlen_off = off;
        off += 2;
        int rdata_start = off;
        put16(pkt, off, EDNS_OPT_UPDATE_LEASE);
        off += 2;
        put16(pkt, off, 8);
        off += 2;
        put32(pkt, off, 7200); /* LEASE = 2h */
        off += 4;
        put32(pkt, off, 1209600); /* KEY-LEASE = 14d */
        off += 4;
        put16(pkt, rdlen_off, (uint16_t) (off - rdata_start));

        edns_info_t ei;
        edns_parse(pkt, off, &ei);
        check(ei.has_update_lease, "8-byte variant: has_update_lease set");
        check(ei.update_lease == 7200, "8-byte variant: LEASE = 7200");
        check(ei.has_update_key_lease, "8-byte variant: has_update_key_lease set");
        check(ei.update_key_lease == 1209600, "8-byte variant: KEY-LEASE = 1209600");
    }

    /* Parse: 4-byte variant (LEASE only) — KEY-LEASE must NOT be set. */
    {
        uint8_t pkt[128];
        memset(pkt, 0, 12);
        put16(pkt, 10, 1);
        int off = 12;
        pkt[off++] = 0;
        put16(pkt, off, DNS_TYPE_OPT);
        off += 2;
        put16(pkt, off, 1232);
        off += 2;
        pkt[off++] = 0;
        pkt[off++] = 0;
        pkt[off++] = 0;
        pkt[off++] = 0;
        int rdlen_off = off;
        off += 2;
        int rdata_start = off;
        put16(pkt, off, EDNS_OPT_UPDATE_LEASE);
        off += 2;
        put16(pkt, off, 4);
        off += 2;
        put32(pkt, off, 3600);
        off += 4;
        put16(pkt, rdlen_off, (uint16_t) (off - rdata_start));

        edns_info_t ei;
        edns_parse(pkt, off, &ei);
        check(ei.has_update_lease, "4-byte variant: has_update_lease set");
        check(ei.update_lease == 3600, "4-byte variant: LEASE = 3600");
        check(!ei.has_update_key_lease, "4-byte variant: has_update_key_lease NOT set");
    }

    /* Append: round-trip through edns_append_opt then edns_parse. */
    {
        uint8_t buf[512];
        memset(buf, 0, sizeof(buf));
        int off = edns_append_opt(buf, 12, sizeof(buf), 0, 0, 0, NULL, NULL, NULL, -1, NULL, -1, 0,
                                  NULL, 1, 5400, 1, 864000);
        check(off > 12, "edns_append_opt with has_ul=1 returns new offset");

        edns_info_t ei;
        edns_parse(buf, off, &ei);
        check(ei.has_update_lease && ei.update_lease == 5400, "round-trip: LEASE echoed correctly");
        check(ei.has_update_key_lease && ei.update_key_lease == 864000,
              "round-trip: KEY-LEASE echoed correctly");
    }

    /* Omitted when has_ul=0 — must not appear even if buffer has room. */
    {
        uint8_t buf[512];
        memset(buf, 0, sizeof(buf));
        int off = edns_append_opt(buf, 12, sizeof(buf), 0, 0, 0, NULL, NULL, NULL, -1, NULL, -1, 0,
                                  NULL, 0, 5400, 1, 864000);
        edns_info_t ei;
        edns_parse(buf, off, &ei);
        check(!ei.has_update_lease, "has_ul=0 omits the option entirely");
    }
}

/* ── RFC 4648 §4: base64 padding must terminate decoding ──────────────────
 * Regression for a real bug found via RFC 2931 SIG(0) KEY-lookup: the
 * decode alphabet table mapped '=' to 0 (i.e. treated it as 'A') instead of
 * -1 (padding/terminator), so any input whose true length wasn't a multiple
 * of 3 bytes silently decoded 1-2 bytes too many. This is the "known-answer
 * + negative" pattern CLAUDE.md asks for on a crypto-adjacent parser bug —
 * every SIG(0)/TSIG-secret decode goes through this exact function. */
static void test_base64_padding(void) {
    printf("== RFC 4648 base64 padding ==\n");

    uint8_t out[64];
    /* No padding needed: 6 bytes -> 8 base64 chars, exact multiple of 3. */
    int n = b64std_dec("Zm9vYmFy", out, sizeof(out));
    check(n == 6 && memcmp(out, "foobar", 6) == 0, "unpadded input decodes exactly");

    /* One '=' (2 padding bytes worth of zero-fill in the encoding): "fo" (2
     * bytes) encodes as "Zm8=". */
    n = b64std_dec("Zm8=", out, sizeof(out));
    check(n == 2 && memcmp(out, "fo", 2) == 0, "single '=' padding decodes to 2 bytes, not 3");

    /* Two '==': "f" (1 byte) encodes as "Zg==". This is the exact shape
     * that triggered the bug (a 64-byte EC pubkey has the same 1-byte
     * remainder, so its base64 also ends in "=="). */
    n = b64std_dec("Zg==", out, sizeof(out));
    check(n == 1 && out[0] == 'f', "double '==' padding decodes to 1 byte, not 3");

    /* A realistic 64-byte payload round-tripped through openssl-style
     * base64 (88 chars, trailing "=="): must decode to exactly 64 bytes. */
    n = b64std_dec(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0"
        "+Pw==",
        out, sizeof(out));
    int seq_ok = (n == 64);
    for (int i = 0; seq_ok && i < 64; i++)
        seq_ok = (out[i] == i);
    check(seq_ok, "64-byte 0x00-0x3F sequence with '==' padding decodes to exactly 64 bytes (was "
                  "66), all bytes correct");
}

int main(void) {
    test_serial_arithmetic();
    test_ttl_max();
    test_type_names();
    test_name_wire_rejection();
    test_edns_parse();
    test_edns_parse_do_bit_position();
    test_edns_parse_nsid_cookie();
    test_edns_append();
    test_update_lease_option();
    test_base64_padding();

    printf("%s\n", g_fail ? "FAILURES" : "ALL TESTS PASSED");
    return g_fail;
}
