/* fuzz/fuzz_eppd.c
 *
 * libFuzzer harness for eppd's two untrusted-input parsers: the RFC 5734
 * §4 transport-framing validator (epp_frame_next) and the hand-rolled
 * bounded XML tokenizer (xml_next_tag / xml_skip_to_close / xml_find_child
 * / xml_text_decode). These are the only structured parsing eppd does on
 * bytes a registrar sent before any authentication — exactly the "parser
 * surface" CLAUDE.md's fuzzing-mandatory rule targets.
 *
 * Deliberately does NOT drive the full epp_dispatch()/command-handler path:
 * those touch Valkey (vk_get/vk_set) via the shared vkc_* client, which
 * would make every fuzz iteration pay for a real (locally-refused, but
 * still real) TCP connect attempt for no parser-coverage benefit. The
 * tokenizer calls below mirror the exact navigation epp_dispatch performs
 * (epp -> command -> {hello,login,logout,check,create,info,update,delete}
 * -> {domain,host,contact}:<op> -> clTRID/authInfo-shaped children) so the
 * same code paths are exercised without any I/O.
 *
 * Because the targets are `static` inside eppd.c, the harness is compiled
 * as part of eppd.c's translation unit by #including it (same pattern as
 * fuzz_response.c for resolverd.c and fuzz_doq.c for doqd.c). -DUNIT_TEST
 * drops eppd's own main() so libFuzzer can supply one.
 *
 * Build:
 *     clang -g -O1 -fsanitize=fuzzer,address,undefined -DUNIT_TEST -I. \
 *           -Wno-unused-function -o fuzz/fuzz_eppd \
 *           fuzz/fuzz_eppd.c dns_wire.c sandbox.c \
 *           -lssl -lcrypto -lpthread -lseccomp
 *
 * Run a 60s smoke and grow the corpus:
 *     mkdir -p fuzz/corpus_eppd
 *     ./fuzz/fuzz_eppd -max_total_time=60 fuzz/corpus_eppd
 *
 * Every parser bug fixed MUST add its triggering input to fuzz/corpus_eppd
 * as a permanent regression case (CLAUDE.md -> Development process ->
 * Testing) — the tokenizer bug found during task #5's live testing (see
 * feature-work-progress.md) is exactly the class of bug this exists to
 * keep caught.
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "eppd.c"

static void probe_children(const char *xml, int s, int e) {
    static const char *leaf_tags[] = {
        "clTRID",       "clID",       "pw",        "authInfo",       "hostObj",
        "hostAttr",     "hostName",   "hostAddr",  "period",         "registrant",
        "add",          "rem",        "chg",       "status",         "extension",
        "secDNS:create", "secDNS:update", "secDNS:add", "secDNS:rem", "secDNS:chg",
        "secDNS:dsData", "secDNS:keyTag", "secDNS:alg", "secDNS:digestType",
        "secDNS:digest", "rgp:update",    "rgp:restore",
    };
    for (size_t i = 0; i < sizeof(leaf_tags) / sizeof(leaf_tags[0]); i++) {
        int cs, ce, cnp;
        if (xml_find_child(xml, s, e, leaf_tags[i], &cs, &ce, &cnp) == 1) {
            char out[256];
            xml_text_decode(xml, cs, ce, out, sizeof(out));
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (size_t) INT_MAX)
        return 0;
    int len = (int) size;
    const char *xml = (const char *) data;

    /* RFC 5734 framing — must never report a frame whose bounds fall
     * outside [data, data+len), and must reject a declared length that
     * can't possibly fit rather than guess. */
    int xoff, xlen, consumed;
    int fr = epp_frame_next(data, len, &xoff, &xlen, &consumed);
    if (fr > 0) {
        if (xlen < 0 || xoff < 0 || xoff + xlen > len || consumed > len) {
            __builtin_trap();
        }
    }

    /* XML tokenizer — the same <epp> -> <command> -> op -> object navigation
     * epp_dispatch performs, minus anything that would touch Valkey. */
    int es, ee, enp;
    if (xml_find_child(xml, 0, len, "epp", &es, &ee, &enp) != 1)
        return 0;
    int hs, he, hnp;
    xml_find_child(xml, es, ee, "hello", &hs, &he, &hnp);
    int cs, ce, cnp;
    if (xml_find_child(xml, es, ee, "command", &cs, &ce, &cnp) != 1)
        return 0;
    probe_children(xml, cs, ce);

    /* <transfer op="..."> (RFC 5731 §3.2.4) — the one place this parser reads
     * an attribute value rather than element content. */
    int ts, te, tnp;
    char top[16];
    if (xml_find_child_attr(xml, cs, ce, "transfer", "op", top, sizeof(top), &ts, &te, &tnp) == 1) {
        probe_children(xml, ts, te);
        int qs, qe, qnp;
        if (xml_find_child(xml, ts, te, "domain:transfer", &qs, &qe, &qnp) == 1)
            probe_children(xml, qs, qe);
    }

    static const char *ops[] = {"login", "logout", "check", "create", "info", "update", "delete"};
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        int os, oe, onp;
        if (xml_find_child(xml, cs, ce, ops[i], &os, &oe, &onp) != 1)
            continue;
        probe_children(xml, os, oe);
        static const char *objs[] = {"domain", "host", "contact"};
        for (size_t j = 0; j < 3; j++) {
            char qname[32];
            snprintf(qname, sizeof(qname), "%s:%s", objs[j], ops[i]);
            int qs, qe, qnp;
            if (xml_find_child(xml, os, oe, qname, &qs, &qe, &qnp) == 1)
                probe_children(xml, qs, qe);
        }
    }
    return 0;
}
