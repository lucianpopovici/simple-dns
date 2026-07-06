/* tests/test_eppd.c
 *
 * Known-answer tests for eppd's two hand-rolled parsers (both `static`
 * inside eppd.c): the RFC 5734 §4 frame-length validator (epp_frame_next)
 * and the bounded XML tokenizer (xml_find_child / xml_text_decode). Memory
 * safety of the same functions is covered separately by fuzz/fuzz_eppd.c;
 * this KAT pins down the exact accept/reject boundaries and decoded values
 * the fuzz target doesn't check.
 *
 * Unlike doqd's doq_frame_next (one message per QUIC stream, exact-match
 * only), epp_frame_next serves a persistent connection carrying a sequence
 * of frames, so it has a genuine "not enough data yet" (0) outcome distinct
 * from "malformed" (-1) — both are exercised below.
 *
 * Build (from repo root):
 *   clang -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -DUNIT_TEST -I. \
 *       -Wno-unused-function -o test_eppd tests/test_eppd.c dns_wire.c sandbox.c \
 *       -lssl -lcrypto -lpthread -lseccomp
 */

#define UNIT_TEST 1
#include "eppd.c"

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

static void test_epp_frame_next(void) {
    printf("== epp_frame_next: KAT ==\n");

    uint8_t exact[4 + 10];
    exact[0] = exact[1] = exact[2] = 0;
    exact[3] = 14; /* total length includes the 4 header bytes */
    memset(exact + 4, 'A', 10);
    int xoff, xlen, consumed;
    CHECK(epp_frame_next(exact, sizeof(exact), &xoff, &xlen, &consumed) == 1 && xoff == 4 &&
              xlen == 10 && consumed == 14,
          "complete frame: total=14 -> xml_off=4 xml_len=10 consumed=14");

    /* Two frames back to back: only the first is extracted; consumed must
     * point exactly at the second frame's header, not past or short of it. */
    uint8_t two[28];
    two[0] = two[1] = two[2] = 0;
    two[3] = 14;
    memset(two + 4, 'A', 10);
    two[14] = two[15] = two[16] = 0;
    two[17] = 11;
    memset(two + 18, 'B', 7);
    CHECK(epp_frame_next(two, sizeof(two), &xoff, &xlen, &consumed) == 1 && consumed == 14 &&
              xlen == 10,
          "two pipelined frames: first extracted, consumed==14 (start of second)");
    int r2 = epp_frame_next(two + consumed, sizeof(two) - consumed, &xoff, &xlen, &consumed);
    CHECK(r2 == 1 && xlen == 7, "second pipelined frame extracted after dropping the first");

    CHECK(epp_frame_next(exact, 0, &xoff, &xlen, &consumed) == 0, "0-byte buffer: need more data");
    CHECK(epp_frame_next(exact, 3, &xoff, &xlen, &consumed) == 0,
          "3-byte buffer (incomplete header): need more data");
    uint8_t partial_body[4 + 3];
    partial_body[0] = partial_body[1] = partial_body[2] = 0;
    partial_body[3] = 14; /* declares 10 bytes of body, only 3 present */
    memset(partial_body + 4, 'C', 3);
    CHECK(epp_frame_next(partial_body, sizeof(partial_body), &xoff, &xlen, &consumed) == 0,
          "declared body longer than what's buffered: need more data, not malformed");

    uint8_t too_short[4] = {0, 0, 0, 3}; /* total=3 < the 4-byte header itself */
    CHECK(epp_frame_next(too_short, sizeof(too_short), &xoff, &xlen, &consumed) == -1,
          "declared total < 4 (shorter than its own header): malformed");

    uint8_t zero_total[4] = {0, 0, 0, 0};
    CHECK(epp_frame_next(zero_total, sizeof(zero_total), &xoff, &xlen, &consumed) == -1,
          "declared total = 0: malformed");

    /* Exactly at the EPP_MAX_FRAME ceiling: accepted. One over: rejected,
     * even if the buffer conveniently happened to be big enough (a
     * resource-exhaustion guard must reject the CLAIM, not wait to see if
     * the bytes show up). */
    static uint8_t at_max[4 + EPP_MAX_FRAME];
    at_max[0] = (uint8_t) (((uint32_t) EPP_MAX_FRAME + 4) >> 24);
    at_max[1] = (uint8_t) (((uint32_t) EPP_MAX_FRAME + 4) >> 16);
    at_max[2] = (uint8_t) (((uint32_t) EPP_MAX_FRAME + 4) >> 8);
    at_max[3] = (uint8_t) ((uint32_t) EPP_MAX_FRAME + 4);
    CHECK(epp_frame_next(at_max, sizeof(at_max), &xoff, &xlen, &consumed) == 1 &&
              xlen == EPP_MAX_FRAME,
          "declared total = EPP_MAX_FRAME+4 (at the ceiling): accepted");
    uint8_t over_max_hdr[4];
    uint32_t over = (uint32_t) EPP_MAX_FRAME + 5;
    over_max_hdr[0] = (uint8_t) (over >> 24);
    over_max_hdr[1] = (uint8_t) (over >> 16);
    over_max_hdr[2] = (uint8_t) (over >> 8);
    over_max_hdr[3] = (uint8_t) over;
    CHECK(epp_frame_next(over_max_hdr, sizeof(over_max_hdr), &xoff, &xlen, &consumed) == -1,
          "declared total = EPP_MAX_FRAME+5 (one over): rejected regardless of buffer size");
}

static void test_xml_tokenizer(void) {
    printf("== xml_find_child / xml_text_decode: KAT ==\n");

    const char *simple = "<a><b>hello</b><c/></a>";
    int len = (int) strlen(simple);
    int es, ee, enp;
    CHECK(xml_find_child(simple, 0, len, "a", &es, &ee, &enp) == 1, "finds top-level <a>");
    int bs, be, bnp;
    CHECK(xml_find_child(simple, es, ee, "b", &bs, &be, &bnp) == 1, "finds direct child <b>");
    char text[32];
    CHECK(xml_text_decode(simple, bs, be, text, sizeof(text)) == 5 && strcmp(text, "hello") == 0,
          "decodes <b>'s text content exactly");
    int cs, ce, cnp;
    CHECK(xml_find_child(simple, bnp, ee, "c", &cs, &ce, &cnp) == 1 && cs == ce,
          "finds self-closing <c/> with empty content");

    const char *ns = "<x:y a=\"1\">v</x:y>";
    int xs, xe, xnp;
    CHECK(xml_find_child(ns, 0, (int) strlen(ns), "x:y", &xs, &xe, &xnp) == 1,
          "namespace-prefixed tag name matched as a literal string");
    char nstext[8];
    xml_text_decode(ns, xs, xe, nstext, sizeof(nstext));
    CHECK(strcmp(nstext, "v") == 0, "content after a quoted attribute decodes correctly");

    const char *entities = "<a>&lt;&gt;&amp;&apos;&quot;&#65;&#x42;</a>";
    int as, ae, anp;
    xml_find_child(entities, 0, (int) strlen(entities), "a", &as, &ae, &anp);
    char dec[32];
    int dl = xml_text_decode(entities, as, ae, dec, sizeof(dec));
    CHECK(dl > 0 && strcmp(dec, "<>&'\"AB") == 0, "all six entity forms decode correctly");

    const char *cdata = "<a><![CDATA[<raw>&stuff</raw>]]></a>";
    xml_find_child(cdata, 0, (int) strlen(cdata), "a", &as, &ae, &anp);
    dl = xml_text_decode(cdata, as, ae, dec, sizeof(dec));
    CHECK(dl > 0 && strcmp(dec, "<raw>&stuff</raw>") == 0,
          "CDATA content passed through verbatim, no entity decoding inside it");

    const char *withcomment = "<a><!-- a comment --><b>ok</b></a>";
    xml_find_child(withcomment, 0, (int) strlen(withcomment), "a", &as, &ae, &anp);
    CHECK(xml_find_child(withcomment, as, ae, "b", &bs, &be, &bnp) == 1,
          "a comment before the real child is skipped, not mistaken for a tag");

    const char *doctype = "<a><!DOCTYPE foo><b>x</b></a>";
    xml_find_child(doctype, 0, (int) strlen(doctype), "a", &as, &ae, &anp);
    CHECK(xml_find_child(doctype, as, ae, "b", &bs, &be, &bnp) == -1,
          "a DOCTYPE is rejected outright (XXE guardrail), not silently skipped");

    const char *unterminated = "<a><b>no close";
    CHECK(xml_find_child(unterminated, 0, (int) strlen(unterminated), "a", &as, &ae, &anp) == -1,
          "an element with no matching close tag: malformed");

    const char *mismatched = "<a><b>x</c></a>";
    xml_find_child(mismatched, 0, (int) strlen(mismatched), "a", &as, &ae, &anp);
    CHECK(xml_find_child(mismatched, as, ae, "b", &bs, &be, &bnp) == -1,
          "mismatched close tag (<b>...</c>): malformed, not silently accepted");

    const char *deep = "<a>";
    char deepbuf[4096];
    int dpos = snprintf(deepbuf, sizeof(deepbuf), "%s", deep);
    for (int i = 0; i < 200; i++)
        dpos += snprintf(deepbuf + dpos, sizeof(deepbuf) - (size_t) dpos, "<n>");
    dpos += snprintf(deepbuf + dpos, sizeof(deepbuf) - (size_t) dpos, "x");
    for (int i = 0; i < 200; i++)
        dpos += snprintf(deepbuf + dpos, sizeof(deepbuf) - (size_t) dpos, "</n>");
    dpos += snprintf(deepbuf + dpos, sizeof(deepbuf) - (size_t) dpos, "</a>");
    CHECK(xml_find_child(deepbuf, 0, dpos, "a", &as, &ae, &anp) == -1,
          "nesting deeper than EPP_XML_MAX_DEPTH (200 > 32): fails closed, no stack overflow");

    const char *notfound = "<a><b>x</b></a>";
    CHECK(xml_find_child(notfound, 0, (int) strlen(notfound), "a", &as, &ae, &anp) == 1 &&
              xml_find_child(notfound, as, ae, "zzz", &bs, &be, &bnp) == 0,
          "a genuinely absent child returns 0 (not found), not an error");
}

/* Phase 2: <transfer op="request"> is the one place this parser reads an
 * attribute value rather than element content — xml_find_child_attr's own
 * KAT, since xml_find_child never exercises it. */
static void test_xml_find_child_attr(void) {
    printf("== xml_find_child_attr: KAT ==\n");
    const char *withop = "<command><transfer op=\"request\"><domain:name>x</domain:name>"
                         "</transfer></command>";
    int len = (int) strlen(withop);
    int cs, ce, cnp;
    CHECK(xml_find_child(withop, 0, len, "command", &cs, &ce, &cnp) == 1, "finds <command>");
    char op[16];
    int ts, te, tnp;
    CHECK(xml_find_child_attr(withop, cs, ce, "transfer", "op", op, sizeof(op), &ts, &te, &tnp) ==
              1 &&
              strcmp(op, "request") == 0,
          "extracts op=\"request\" from <transfer op=\"request\">");

    const char *noop = "<command><transfer><domain:name>x</domain:name></transfer></command>";
    xml_find_child(noop, 0, (int) strlen(noop), "command", &cs, &ce, &cnp);
    CHECK(xml_find_child_attr(noop, cs, ce, "transfer", "op", op, sizeof(op), &ts, &te, &tnp) == 1 &&
              op[0] == 0,
          "attribute absent: match still succeeds, attr_out is empty (not an error)");

    const char *singlequote = "<transfer op='approve'/>";
    CHECK(xml_find_child_attr(singlequote, 0, (int) strlen(singlequote), "transfer", "op", op,
                              sizeof(op), &ts, &te, &tnp) == 1 &&
              strcmp(op, "approve") == 0,
          "single-quoted attribute value accepted");

    const char *decoy = "<transfer stop=\"x\" op=\"cancel\"/>";
    CHECK(xml_find_child_attr(decoy, 0, (int) strlen(decoy), "transfer", "op", op, sizeof(op), &ts,
                              &te, &tnp) == 1 &&
              strcmp(op, "cancel") == 0,
          "a decoy attribute ending in \"op\" (\"stop\") does not false-positive match");

    const char *unterminated = "<transfer op=\"cancel";
    CHECK(xml_find_child_attr(unterminated, 0, (int) strlen(unterminated), "transfer", "op", op,
                              sizeof(op), &ts, &te, &tnp) == -1,
          "unterminated tag: malformed, not a false match");
}

/* Phase 2 TLV round-trips: encode then decode must reproduce every field,
 * including the new ownership (clid), RGP, DS (RFC 5910), and transfer
 * fields. Pure functions, no Valkey needed — memory safety of the same
 * codec is covered by make fuzz-tlv (dns_wire.c's tlv_* is shared, already
 * fuzzed there); this pins down eppd's own tag mapping. */
static void test_domain_tlv_roundtrip(void) {
    printf("== epp_domain_encode/decode: TLV round-trip KAT ==\n");
    epp_domain_t d;
    memset(&d, 0, sizeof(d));
    safe_strcpy(d.roid, "1-EPPD-D", sizeof(d.roid));
    safe_strcpy(d.clid, "registrar1", sizeof(d.clid));
    safe_strcpy(d.status[0], "ok", sizeof(d.status[0]));
    safe_strcpy(d.status[1], "clientHold", sizeof(d.status[1]));
    d.nstatus = 2;
    safe_strcpy(d.authinfo, "deadbeefcafef00d00112233445566ff", sizeof(d.authinfo));
    d.crdate = 1700000000;
    d.exdate = 1731536000;
    safe_strcpy(d.registrant, "EPPTC1", sizeof(d.registrant));
    safe_strcpy(d.ns[0], "ns1.example.test", sizeof(d.ns[0]));
    safe_strcpy(d.ns[1], "ns2.example.test", sizeof(d.ns[1]));
    d.nns = 2;
    d.ds[0].keytag = 12345;
    d.ds[0].alg = 13;
    d.ds[0].digtype = 2;
    d.ds[0].digestlen = 32;
    for (int i = 0; i < 32; i++)
        d.ds[0].digest[i] = (uint8_t) i;
    d.nds = 1;
    d.rgp_state = EPP_RGP_REDEMPTION;
    d.rgp_until = 1731600000;
    safe_strcpy(d.transfer_reid, "registrar2", sizeof(d.transfer_reid));
    d.transfer_redate = 1730000000;
    safe_strcpy(d.transfer_status, "pending", sizeof(d.transfer_status));

    uint8_t buf[4096];
    int len = epp_domain_encode(&d, buf, sizeof(buf));
    CHECK(len > 0, "encode succeeds");

    epp_domain_t d2;
    CHECK(epp_domain_decode(buf, len, &d2) == 0, "decode succeeds");
    CHECK(strcmp(d.roid, d2.roid) == 0, "roid round-trips");
    CHECK(strcmp(d.clid, d2.clid) == 0, "clid round-trips");
    CHECK(d2.nstatus == 2 && strcmp(d2.status[0], "ok") == 0 &&
              strcmp(d2.status[1], "clientHold") == 0,
          "status[] round-trips in order");
    CHECK(strcmp(d.authinfo, d2.authinfo) == 0, "authinfo round-trips");
    CHECK(d2.crdate == d.crdate && d2.exdate == d.exdate, "crdate/exdate round-trip");
    CHECK(strcmp(d.registrant, d2.registrant) == 0, "registrant round-trips");
    CHECK(d2.nns == 2 && strcmp(d2.ns[0], "ns1.example.test") == 0 &&
              strcmp(d2.ns[1], "ns2.example.test") == 0,
          "ns[] round-trips in order");
    CHECK(d2.nds == 1 && d2.ds[0].keytag == 12345 && d2.ds[0].alg == 13 &&
              d2.ds[0].digtype == 2 && d2.ds[0].digestlen == 32 &&
              memcmp(d2.ds[0].digest, d.ds[0].digest, 32) == 0,
          "ds[] (RFC 5910) round-trips including the full digest");
    CHECK(d2.rgp_state == EPP_RGP_REDEMPTION && d2.rgp_until == d.rgp_until,
          "rgp_state/rgp_until (RFC 3915) round-trip");
    CHECK(strcmp(d.transfer_reid, d2.transfer_reid) == 0 && d2.transfer_redate == d.transfer_redate &&
              strcmp(d.transfer_status, d2.transfer_status) == 0,
          "transfer_reid/transfer_redate/transfer_status round-trip");

    epp_domain_t empty;
    memset(&empty, 0, sizeof(empty));
    safe_strcpy(empty.roid, "2-EPPD-D", sizeof(empty.roid));
    empty.crdate = 1700000001;
    uint8_t buf2[4096];
    int len2 = epp_domain_encode(&empty, buf2, sizeof(buf2));
    epp_domain_t empty2;
    CHECK(len2 > 0 && epp_domain_decode(buf2, len2, &empty2) == 0 &&
              empty2.rgp_state == EPP_RGP_NONE && empty2.nds == 0 && empty2.clid[0] == 0 &&
              empty2.transfer_status[0] == 0,
          "a domain with none of the Phase 2 fields set decodes back to all-zero/NONE defaults");
}

static void test_host_contact_tlv_roundtrip(void) {
    printf("== epp_host_encode/decode + epp_contact_encode/decode: clid round-trip KAT ==\n");
    epp_host_t h;
    memset(&h, 0, sizeof(h));
    safe_strcpy(h.roid, "1-EPPD-H", sizeof(h.roid));
    safe_strcpy(h.clid, "registrar1", sizeof(h.clid));
    safe_strcpy(h.v4[0], "192.0.2.1", sizeof(h.v4[0]));
    h.nv4 = 1;
    h.crdate = 1700000000;
    uint8_t hbuf[4096];
    int hlen = epp_host_encode(&h, hbuf, sizeof(hbuf));
    epp_host_t h2;
    CHECK(hlen > 0 && epp_host_decode(hbuf, hlen, &h2) == 0 && strcmp(h.clid, h2.clid) == 0 &&
              h2.nv4 == 1 && strcmp(h2.v4[0], "192.0.2.1") == 0,
          "host clid + addr round-trip");

    epp_contact_t c;
    memset(&c, 0, sizeof(c));
    safe_strcpy(c.roid, "1-EPPD-C", sizeof(c.roid));
    safe_strcpy(c.clid, "registrar1", sizeof(c.clid));
    safe_strcpy(c.authinfo, "0123456789abcdef0123456789abcdef", sizeof(c.authinfo));
    uint8_t cbuf[2048];
    int clen = epp_contact_encode(&c, cbuf, sizeof(cbuf));
    epp_contact_t c2;
    CHECK(clen > 0 && epp_contact_decode(cbuf, clen, &c2) == 0 && strcmp(c.clid, c2.clid) == 0 &&
              strcmp(c.authinfo, c2.authinfo) == 0,
          "contact clid + authinfo round-trip");
}

/* Phase 3: RFC 8543 org object TLV round-trip. */
static void test_org_tlv_roundtrip(void) {
    printf("== epp_org_encode/decode: TLV round-trip KAT (RFC 8543) ==\n");
    epp_org_t o;
    memset(&o, 0, sizeof(o));
    safe_strcpy(o.id, "reseller1", sizeof(o.id));
    safe_strcpy(o.roid, "1-EPPD-O", sizeof(o.roid));
    safe_strcpy(o.clid, "registrar1", sizeof(o.clid));
    safe_strcpy(o.status[0], "ok", sizeof(o.status[0]));
    o.nstatus = 1;
    safe_strcpy(o.parentid, "parentorg", sizeof(o.parentid));
    safe_strcpy(o.roles[0], "reseller", sizeof(o.roles[0]));
    safe_strcpy(o.roles[1], "privacyproxy", sizeof(o.roles[1]));
    o.nroles = 2;
    safe_strcpy(o.email, "org@example.invalid", sizeof(o.email));
    safe_strcpy(o.voice, "+1.5551234567", sizeof(o.voice));
    o.crdate = 1700000000;

    uint8_t buf[2048];
    int len = epp_org_encode(&o, buf, sizeof(buf));
    epp_org_t o2;
    CHECK(len > 0 && epp_org_decode(buf, len, &o2) == 0 && strcmp(o.id, o2.id) == 0 &&
              strcmp(o.roid, o2.roid) == 0 && strcmp(o.clid, o2.clid) == 0 &&
              strcmp(o.parentid, o2.parentid) == 0 && o2.nroles == 2 &&
              strcmp(o2.roles[0], "reseller") == 0 && strcmp(o2.roles[1], "privacyproxy") == 0 &&
              o2.crdate == o.crdate,
          "org id/roid/clid/parentid/roles[]/crdate round-trip");
}

/* Phase 3: RFC 5730 poll message + RFC 8590 changePoll fields TLV round-trip. */
static void test_poll_tlv_roundtrip(void) {
    printf("== epp_poll_encode/decode: TLV round-trip KAT (RFC 5730/8590) ==\n");
    epp_poll_msg_t m;
    memset(&m, 0, sizeof(m));
    safe_strcpy(m.msg, "Transfer of example.test requested by registrar2", sizeof(m.msg));
    m.qdate = 1700000000;
    safe_strcpy(m.objtype, "domain", sizeof(m.objtype));
    safe_strcpy(m.objid, "example.test", sizeof(m.objid));
    safe_strcpy(m.cp_state, "before", sizeof(m.cp_state));
    safe_strcpy(m.cp_operation, "transfer", sizeof(m.cp_operation));
    safe_strcpy(m.cp_who, "registrar2", sizeof(m.cp_who));
    safe_strcpy(m.cp_reason, "registrar-initiated", sizeof(m.cp_reason));
    safe_strcpy(m.resdata, "<trnData><name>example.test</name></trnData>", sizeof(m.resdata));

    uint8_t buf[2048];
    int len = epp_poll_encode(&m, buf, sizeof(buf));
    epp_poll_msg_t m2;
    CHECK(len > 0 && epp_poll_decode(buf, len, &m2) == 0 && strcmp(m.msg, m2.msg) == 0 &&
              m2.qdate == m.qdate && strcmp(m.objtype, m2.objtype) == 0 &&
              strcmp(m.objid, m2.objid) == 0 && strcmp(m.cp_state, m2.cp_state) == 0 &&
              strcmp(m.cp_operation, m2.cp_operation) == 0 && strcmp(m.cp_who, m2.cp_who) == 0 &&
              strcmp(m.cp_reason, m2.cp_reason) == 0 && strcmp(m.resdata, m2.resdata) == 0,
          "poll message + changePoll fields + resData round-trip");

    epp_poll_msg_t plain;
    memset(&plain, 0, sizeof(plain));
    safe_strcpy(plain.msg, "Domain purged: redemptionPeriod elapsed", sizeof(plain.msg));
    plain.qdate = 1700000001;
    uint8_t buf2[2048];
    int len2 = epp_poll_encode(&plain, buf2, sizeof(buf2));
    epp_poll_msg_t plain2;
    CHECK(len2 > 0 && epp_poll_decode(buf2, len2, &plain2) == 0 &&
              strcmp(plain.msg, plain2.msg) == 0 && plain2.cp_state[0] == 0 &&
              plain2.resdata[0] == 0,
          "a plain message with no changePoll/resData fields decodes back empty, not garbage");
}

/* epp_gen_authinfo (RFC 9154): must produce a fixed-length hex token, not
 * silently truncate or leave the buffer partially filled. */
static void test_gen_authinfo(void) {
    printf("== epp_gen_authinfo: KAT ==\n");
    char a[256], b[256];
    epp_gen_authinfo(a, sizeof(a));
    epp_gen_authinfo(b, sizeof(b));
    CHECK(strlen(a) == 32, "32 hex chars (128-bit token)");
    int all_hex = 1;
    for (size_t i = 0; i < strlen(a); i++)
        if (!isxdigit((unsigned char) a[i]))
            all_hex = 0;
    CHECK(all_hex, "every character is a hex digit");
    CHECK(strcmp(a, b) != 0, "two calls produce different tokens (not a fixed/predictable value)");
}

int main(void) {
    test_epp_frame_next();
    test_xml_tokenizer();
    test_xml_find_child_attr();
    test_domain_tlv_roundtrip();
    test_host_contact_tlv_roundtrip();
    test_org_tlv_roundtrip();
    test_poll_tlv_roundtrip();
    test_gen_authinfo();
    printf("\n%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
