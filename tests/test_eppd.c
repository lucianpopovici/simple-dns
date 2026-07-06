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

int main(void) {
    test_epp_frame_next();
    test_xml_tokenizer();
    printf("\n%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
