/* tests/test_rollover.c
 *
 * Known-answer + negative tests for the ZSK rollover invariant (RFC 6781
 * §4.1.1.1 Pre-Publish), the new DNSSEC key-rollover engine in dns_server.c.
 *
 * The security property a ZSK rollover must never violate is: at every phase,
 * the key that produced an RRSIG is present in the published DNSKEY RRset, so a
 * validator selecting the DNSKEY by the RRSIG key tag always finds it and the
 * signature verifies. A "validation gap" is exactly the opposite — the signer
 * switched to (or away from) a key that the published RRset does not contain.
 *
 * dns_server.c implements pre-publish as three (published DNSKEY set, signer)
 * states; this test transcribes those states verbatim and checks each against
 * the *real* resolver-side verifier (dnssec_verify_rrset from dns_client.c):
 *
 *   phase     published DNSKEY set     signer        from dns_server.c
 *   --------  -----------------------  ------------  -----------------------------
 *   publish   {current, next}          current       build_query_resp publishes
 *   commit    {current, next}          next            both keys for the whole
 *   done      {next (promoted)}        next            rollover; emit_rr's
 *                                                       use_next == (phase==COMMIT)
 *
 * For each phase a validator picks the DNSKEY whose key tag matches the RRSIG
 * (RFC 4034 App. B key tag, computed here). The tests assert:
 *
 *   1. publish/commit/done: the signer's key IS in the published set and the
 *      signature verifies                                   (known-answer, no gap)
 *   2. commit-before-publish (signer=next, set={current})  → no matching key, and
 *      verifying with the wrong key rejects                 (negative, gap caught)
 *   3. retire-current-too-early (signer=current, set={next})→ same              (negative)
 *   4. a signature checked against the wrong key            → reject  (crypto KAT)
 *
 * Runs for both supported algorithms: Ed25519 (15) and ECDSA P-256 (13).
 *
 * Build (from repo root):
 *   gcc -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -I. \
 *       -o test_rollover tests/test_rollover.c dns_wire.c -lssl -lcrypto -lpthread
 */

#define UNIT_TEST 1
#include "dns_client.c"

#include <openssl/core_names.h>

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

/* www.example.com / example.com in wire format */
static const uint8_t WIRE_QNAME[] = {3,   'w', 'w', 'w', 7,   'e', 'x', 'a', 'm',
                                     'p', 'l', 'e', 3,   'c', 'o', 'm', 0};
static const uint8_t WIRE_SIGNER[] = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};

#define ORIG_TTL 3600u
#define PKT_TTL 1234u
#define ZSK_FLAGS 256u /* DNSKEY flags for a Zone Signing Key (RFC 4034 §2.1.1) */

/* RFC 4034 Appendix B key tag over a DNSKEY rdata blob. */
static uint16_t dnskey_keytag(const uint8_t *rd, int n) {
    unsigned long ac = 0;
    for (int i = 0; i < n; i++)
        ac += (i & 1) ? (unsigned long) rd[i] : (unsigned long) rd[i] << 8;
    ac += (ac >> 16) & 0xFFFFu;
    return (uint16_t) (ac & 0xFFFFu);
}

/* A published DNSKEY: its rdata and the key tag a validator would index it by. */
typedef struct {
    uint8_t rd[128];
    int len;
    uint16_t tag;
} pubkey_t;

/* Build the ZSK DNSKEY rdata (flags|proto|alg|pubkey) and its key tag. */
static void make_dnskey(pubkey_t *k, uint8_t alg, const uint8_t *pub, int publen) {
    put16(k->rd, 0, ZSK_FLAGS);
    k->rd[2] = 3; /* protocol */
    k->rd[3] = alg;
    memcpy(k->rd + 4, pub, (size_t) publen);
    k->len = 4 + publen;
    k->tag = dnskey_keytag(k->rd, k->len);
}

/* Extract the raw DNSKEY public-key bytes from an EVP_PKEY (64 for P-256,
 * 32 for Ed25519). Returns the length, or 0 on failure. */
static int extract_pub(EVP_PKEY *pkey, int is_ed, uint8_t *pub) {
    if (is_ed) {
        size_t l = 32;
        if (EVP_PKEY_get_raw_public_key(pkey, pub, &l) <= 0 || l != 32)
            return 0;
        return 32;
    }
    uint8_t enc[80];
    size_t l = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, enc, sizeof(enc),
                                        &l) <= 0 ||
        l != 65 || enc[0] != 0x04)
        return 0;
    memcpy(pub, enc + 1, 64); /* strip the uncompressed-point tag */
    return 64;
}

/* Sign `data` with pkey, emitting the 64-byte DNSSEC signature (raw R||S for
 * ECDSA, the native 64-byte form for Ed25519). Returns 1 on success. */
static int sign_data(EVP_PKEY *pkey, int is_ed, const uint8_t *data, size_t dlen, uint8_t sig64[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t der[256];
    size_t slen = sizeof(der);
    int ok = 0;
    if (!ctx)
        return 0;
    if (EVP_DigestSignInit(ctx, NULL, is_ed ? NULL : EVP_sha256(), NULL, pkey) > 0 &&
        EVP_DigestSign(ctx, der, &slen, data, dlen) > 0) {
        if (is_ed) {
            if (slen == 64) {
                memcpy(sig64, der, 64);
                ok = 1;
            }
        } else {
            const uint8_t *pp = der;
            ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &pp, (long) slen);
            if (es) {
                const BIGNUM *r = NULL, *s = NULL;
                ECDSA_SIG_get0(es, &r, &s);
                if (BN_bn2binpad(r, sig64, 32) == 32 && BN_bn2binpad(s, sig64 + 32, 32) == 32)
                    ok = 1;
                ECDSA_SIG_free(es);
            }
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* A response packet carrying one A RR (www.example.com A 192.0.2.1) plus its
 * RRSIG, signed by a chosen key. */
typedef struct {
    uint8_t pkt[512];
    int plen;
    int rr_off; /* offset of the A RR (owner name) for dnssec_verify_rrset */
    uint8_t rrsig_rd[256];
    int rrsig_rdlen;
} signed_pkt_t;

/* Build the RRSIG header (rdata up to and including the signer name). The
 * key tag field carries `tag` — what a validator uses to pick the DNSKEY. */
static int build_rrsig_hdr(uint8_t alg, uint16_t tag, uint8_t *hdr) {
    put16(hdr, 0, 1); /* type covered: A */
    hdr[2] = alg;
    hdr[3] = 3; /* labels: www.example.com */
    put32(hdr, 4, ORIG_TTL);
    put32(hdr, 8, 0xFFFFFFFFu); /* expiration (not checked here) */
    put32(hdr, 12, 0);          /* inception  (not checked here) */
    put16(hdr, 16, tag);
    memcpy(hdr + 18, WIRE_SIGNER, sizeof(WIRE_SIGNER));
    return 18 + (int) sizeof(WIRE_SIGNER);
}

/* Build a signed response: sign the A RRset with `signer`, stamp the RRSIG key
 * tag with `tag`. */
static int build_signed(signed_pkt_t *t, uint8_t alg, EVP_PKEY *signer, int is_ed, uint16_t tag) {
    uint8_t hdr[18 + sizeof(WIRE_SIGNER)];
    int hdr_len = build_rrsig_hdr(alg, tag, hdr);

    /* Canonical signing input: RRSIG header || (owner|type|class|origTTL|rdlen|rdata). */
    uint8_t sin[256];
    int o = 0;
    memcpy(sin + o, hdr, (size_t) hdr_len);
    o += hdr_len;
    memcpy(sin + o, WIRE_QNAME, sizeof(WIRE_QNAME));
    o += (int) sizeof(WIRE_QNAME);
    put16(sin, o, 1);
    o += 2;
    put16(sin, o, 1);
    o += 2;
    put32(sin, o, ORIG_TTL);
    o += 4;
    put16(sin, o, 4);
    o += 2;
    sin[o++] = 192;
    sin[o++] = 0;
    sin[o++] = 2;
    sin[o++] = 1;

    uint8_t sig[64];
    if (!sign_data(signer, is_ed, sin, (size_t) o, sig))
        return 0;

    uint8_t *p = t->pkt;
    int q = 0;
    put16(p, 0, 0x1234);
    put16(p, 2, 0x8180);
    put16(p, 4, 1); /* qd */
    put16(p, 6, 2); /* an: A + RRSIG */
    put16(p, 8, 0);
    put16(p, 10, 0);
    q = 12;
    /* question */
    memcpy(p + q, WIRE_QNAME, sizeof(WIRE_QNAME));
    q += (int) sizeof(WIRE_QNAME);
    put16(p, q, 1);
    q += 2;
    put16(p, q, 1);
    q += 2;
    /* answer 1: A 192.0.2.1 */
    t->rr_off = q;
    memcpy(p + q, WIRE_QNAME, sizeof(WIRE_QNAME));
    q += (int) sizeof(WIRE_QNAME);
    put16(p, q, 1);
    q += 2;
    put16(p, q, 1);
    q += 2;
    put32(p, q, PKT_TTL);
    q += 4;
    put16(p, q, 4);
    q += 2;
    p[q++] = 192;
    p[q++] = 0;
    p[q++] = 2;
    p[q++] = 1;
    /* answer 2: RRSIG */
    int rdlen = hdr_len + 64;
    memcpy(p + q, WIRE_QNAME, sizeof(WIRE_QNAME));
    q += (int) sizeof(WIRE_QNAME);
    put16(p, q, DNS_TYPE_RRSIG);
    q += 2;
    put16(p, q, 1);
    q += 2;
    put32(p, q, PKT_TTL);
    q += 4;
    put16(p, q, (uint16_t) rdlen);
    q += 2;
    int rdstart = q;
    memcpy(p + q, hdr, (size_t) hdr_len);
    q += hdr_len;
    memcpy(p + q, sig, 64);
    q += 64;
    memcpy(t->rrsig_rd, p + rdstart, (size_t) rdlen);
    t->rrsig_rdlen = rdlen;
    t->plen = q;
    return 1;
}

/* The validator selects the published DNSKEY whose key tag matches the RRSIG. */
static const pubkey_t *select_key(const pubkey_t *set, int n, uint16_t tag) {
    for (int i = 0; i < n; i++)
        if (set[i].tag == tag)
            return &set[i];
    return NULL;
}

/* Verify a signed packet against a specific DNSKEY rdata. */
static int verify_with(const signed_pkt_t *t, const pubkey_t *k) {
    int rr_offs[1] = {t->rr_off};
    return dnssec_verify_rrset(t->pkt, t->plen, rr_offs, 1, t->rrsig_rd, t->rrsig_rdlen, k->rd,
                               k->len);
}

static void run_alg(uint8_t alg) {
    const int is_ed = (alg == 15);
    printf("== algorithm %u (%s) ==\n", alg, is_ed ? "Ed25519" : "ECDSA P-256");

    /* The current ZSK and the incoming ("next") ZSK of a rollover. Regenerate
     * until their key tags differ so selection is unambiguous (tag collisions
     * are rare but possible). */
    EVP_PKEY *cur = NULL, *next = NULL;
    pubkey_t kc, kn;
    for (int tries = 0; tries < 16; tries++) {
        if (cur)
            EVP_PKEY_free(cur);
        if (next)
            EVP_PKEY_free(next);
        cur = is_ed ? EVP_PKEY_Q_keygen(NULL, NULL, "ED25519") : EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        next = is_ed ? EVP_PKEY_Q_keygen(NULL, NULL, "ED25519") : EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        uint8_t pc[80], pn[80];
        int lc = cur ? extract_pub(cur, is_ed, pc) : 0;
        int ln = next ? extract_pub(next, is_ed, pn) : 0;
        if (!lc || !ln) {
            printf("  FAIL  keygen/pubkey extraction\n");
            g_failures++;
            if (cur)
                EVP_PKEY_free(cur);
            if (next)
                EVP_PKEY_free(next);
            return;
        }
        make_dnskey(&kc, alg, pc, lc);
        make_dnskey(&kn, alg, pn, ln);
        if (kc.tag != kn.tag)
            break;
    }
    CHECK(kc.tag != kn.tag, "distinct key tags for current/next ZSK");

    /* The published DNSKEY sets per pre-publish phase. */
    pubkey_t both[2] = {kc, kn};
    pubkey_t only_cur[1] = {kc};
    pubkey_t only_next[1] = {kn};

    signed_pkt_t t;

    /* Phase: publish — set {current,next}, signer current. */
    if (build_signed(&t, alg, cur, is_ed, kc.tag)) {
        const pubkey_t *k = select_key(both, 2, kc.tag);
        CHECK(k != NULL, "publish: signer (current) is in the published DNSKEY set");
        CHECK(k && verify_with(&t, k) == 1, "publish: signature verifies — no validation gap");
    } else {
        printf("  FAIL  publish: signing\n");
        g_failures++;
    }

    /* Phase: commit — set {current,next}, signer next. */
    if (build_signed(&t, alg, next, is_ed, kn.tag)) {
        const pubkey_t *k = select_key(both, 2, kn.tag);
        CHECK(k != NULL, "commit: signer (next) is in the published DNSKEY set");
        CHECK(k && verify_with(&t, k) == 1, "commit: signature verifies — no validation gap");

        /* Negative: had dnsd committed (signed with next) BEFORE publishing
         * next — i.e. set still {current} — a validator finds no matching key. */
        CHECK(select_key(only_cur, 1, kn.tag) == NULL,
              "commit-before-publish: next key absent from set → gap detected");
        /* And the crypto core rejects the wrong key, the last line of defence. */
        CHECK(verify_with(&t, &kc) == 0,
              "commit-before-publish: verifying next's RRSIG with current key rejects");
    } else {
        printf("  FAIL  commit: signing\n");
        g_failures++;
    }

    /* Phase: done — current retired, set {next}, signer next. */
    if (build_signed(&t, alg, next, is_ed, kn.tag)) {
        const pubkey_t *k = select_key(only_next, 1, kn.tag);
        CHECK(k != NULL, "done: promoted key is in the published DNSKEY set");
        CHECK(k && verify_with(&t, k) == 1, "done: signature verifies — no validation gap");

        /* Negative: had dnsd retired current too early — set {next} while a
         * cached RRSIG was still made by current — no matching key. */
        signed_pkt_t old;
        if (build_signed(&old, alg, cur, is_ed, kc.tag)) {
            CHECK(select_key(only_next, 1, kc.tag) == NULL,
                  "retire-too-early: current key absent from set → gap detected");
            CHECK(verify_with(&old, &kn) == 0,
                  "retire-too-early: verifying current's RRSIG with next key rejects");
        }
    } else {
        printf("  FAIL  done: signing\n");
        g_failures++;
    }

    /* Crypto known-answer cross-check: a signature only verifies under its own
     * key (guards against a verifier that ignores the key). */
    if (build_signed(&t, alg, cur, is_ed, kc.tag)) {
        CHECK(verify_with(&t, &kc) == 1, "KAT: current RRSIG verifies with current key");
        CHECK(verify_with(&t, &kn) == 0, "KAT: current RRSIG rejects under next key");
    }

    EVP_PKEY_free(cur);
    EVP_PKEY_free(next);
}

int main(void) {
    run_alg(15); /* Ed25519 */
    run_alg(13); /* ECDSA P-256 */
    if (g_failures) {
        printf("\n%d FAILURE(S)\n", g_failures);
        return 1;
    }
    printf("\nALL TESTS PASSED\n");
    return 0;
}
