/* tests/test_dnssec_verify.c
 *
 * Known-answer + negative tests for dnssec_verify_rrset /
 * dnssec_validate_response.
 *
 * Strategy: build a synthetic DNS response containing an A RRset (two records,
 * deliberately emitted in non-canonical order, one owner name compressed),
 * an RRSIG and a DNSKEY. The test constructs the RFC 4034 §3.1.8.1 signing
 * input INDEPENDENTLY (hand-laid bytes, not via the code under test), signs it
 * with a freshly generated key, and then checks:
 *
 *   1. the verifier accepts the intact packet            (known-answer)
 *   2. one flipped bit in the A rdata        → reject    (negative)
 *   3. one flipped bit in the signature      → reject    (negative)
 *   4. end-to-end dnssec_validate_response: SECURE with a trust anchor,
 *      BOGUS after tampering with the answer rdata.
 *
 * Runs for both supported algorithms: Ed25519 (15) and ECDSA P-256 (13).
 *
 * Build (from repo root):
 *   gcc -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -I. \
 *       -o test_dnssec_verify tests/test_dnssec_verify.c -lssl -lcrypto -lpthread
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

/* www.example.com in wire format */
static const uint8_t WIRE_QNAME[] = {3,   'w', 'w', 'w', 7,   'e', 'x', 'a', 'm',
                                     'p', 'l', 'e', 3,   'c', 'o', 'm', 0};
/* example.com in wire format (RRSIG signer name) */
static const uint8_t WIRE_SIGNER[] = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};

#define ORIG_TTL 3600u /* original TTL carried in the RRSIG */
#define PKT_TTL 1234u  /* TTL in the packet — must NOT be what gets signed */

typedef struct {
    uint8_t pkt[1024];
    int plen;
    int rr_offs[2];   /* offsets of the two A RRs */
    int a1_rdata_off; /* offset of first A record's rdata (for tampering) */
    int sig_off;      /* offset of the signature bytes inside the packet */
    uint8_t rrsig_rd[512];
    int rrsig_rdlen;
    uint8_t dnskey_rd[128];
    int dnskey_rdlen;
} testpkt_t;

/* Hand-build the canonical signing input: RRSIG header || sorted canonical
 * RRset. Both A records share owner www.example.com, type 1, class 1,
 * original TTL 3600. Canonical order sorts by rdata: 192.0.2.1 < 192.0.2.99. */
static int build_signing_input(const uint8_t *rrsig_hdr, int hdr_len, uint8_t *out) {
    int o = 0;
    memcpy(out + o, rrsig_hdr, (size_t) hdr_len);
    o += hdr_len;
    const uint8_t rdatas[2][4] = {{192, 0, 2, 1}, {192, 0, 2, 99}};
    for (int i = 0; i < 2; i++) {
        memcpy(out + o, WIRE_QNAME, sizeof(WIRE_QNAME));
        o += (int) sizeof(WIRE_QNAME);
        put16(out, o, 1);
        o += 2; /* type A */
        put16(out, o, 1);
        o += 2; /* class IN */
        put32(out, o, ORIG_TTL);
        o += 4; /* ORIGINAL ttl, not PKT_TTL */
        put16(out, o, 4);
        o += 2; /* rdlength */
        memcpy(out + o, rdatas[i], 4);
        o += 4;
    }
    return o;
}

/* Build the full response packet for algorithm `alg` using signature `sig`
 * (64 bytes) and DNSKEY public key material pub/publen. */
static void build_packet(testpkt_t *t, uint8_t alg, const uint8_t *sig, const uint8_t *pub,
                         int publen) {
    uint8_t *p = t->pkt;
    memset(t, 0, offsetof(testpkt_t, rrsig_rd));
    int o = 0;
    /* header: id, QR=1 RD/RA, qd=1 an=4 */
    put16(p, 0, 0x1234);
    put16(p, 2, 0x8180);
    put16(p, 4, 1);
    put16(p, 6, 4);
    put16(p, 8, 0);
    put16(p, 10, 0);
    o = 12;
    /* question: www.example.com A IN  (qname at offset 12) */
    memcpy(p + o, WIRE_QNAME, sizeof(WIRE_QNAME));
    o += (int) sizeof(WIRE_QNAME);
    put16(p, o, 1);
    o += 2;
    put16(p, o, 1);
    o += 2;
    /* answer 1: owner = compression pointer to qname, A 192.0.2.99
     * (out of canonical order on purpose; .99 sorts after .1) */
    t->rr_offs[0] = o;
    p[o++] = 0xC0;
    p[o++] = 0x0C;
    put16(p, o, 1);
    o += 2;
    put16(p, o, 1);
    o += 2;
    put32(p, o, PKT_TTL);
    o += 4;
    put16(p, o, 4);
    o += 2;
    t->a1_rdata_off = o;
    p[o++] = 192;
    p[o++] = 0;
    p[o++] = 2;
    p[o++] = 99;
    /* answer 2: owner spelled out in full, A 192.0.2.1 */
    t->rr_offs[1] = o;
    memcpy(p + o, WIRE_QNAME, sizeof(WIRE_QNAME));
    o += (int) sizeof(WIRE_QNAME);
    put16(p, o, 1);
    o += 2;
    put16(p, o, 1);
    o += 2;
    put32(p, o, PKT_TTL);
    o += 4;
    put16(p, o, 4);
    o += 2;
    p[o++] = 192;
    p[o++] = 0;
    p[o++] = 2;
    p[o++] = 1;
    /* answer 3: RRSIG covering the A RRset */
    int rdlen = 18 + (int) sizeof(WIRE_SIGNER) + 64;
    p[o++] = 0xC0;
    p[o++] = 0x0C;
    put16(p, o, DNS_TYPE_RRSIG);
    o += 2;
    put16(p, o, 1);
    o += 2;
    put32(p, o, PKT_TTL);
    o += 4;
    put16(p, o, (uint16_t) rdlen);
    o += 2;
    int rdstart = o;
    put16(p, o, 1);
    o += 2;       /* type covered: A */
    p[o++] = alg; /* algorithm */
    p[o++] = 3;   /* labels: www.example.com = 3 */
    put32(p, o, ORIG_TTL);
    o += 4; /* original TTL */
    put32(p, o, 0xFFFFFFFFu);
    o += 4; /* expiration (not checked) */
    put32(p, o, 0);
    o += 4; /* inception  (not checked) */
    put16(p, o, 0);
    o += 2; /* key tag    (not checked) */
    memcpy(p + o, WIRE_SIGNER, sizeof(WIRE_SIGNER));
    o += (int) sizeof(WIRE_SIGNER);
    t->sig_off = o;
    memcpy(p + o, sig, 64);
    o += 64;
    memcpy(t->rrsig_rd, p + rdstart, (size_t) rdlen);
    t->rrsig_rdlen = rdlen;
    /* answer 4: DNSKEY (owner example.com via pointer into the qname) */
    p[o++] = 0xC0;
    p[o++] = 0x10;
    put16(p, o, DNS_TYPE_DNSKEY);
    o += 2;
    put16(p, o, 1);
    o += 2;
    put32(p, o, PKT_TTL);
    o += 4;
    put16(p, o, (uint16_t) (4 + publen));
    o += 2;
    int dkstart = o;
    put16(p, o, 0x0101);
    o += 2;     /* flags: ZK + SEP */
    p[o++] = 3; /* protocol */
    p[o++] = alg;
    memcpy(p + o, pub, (size_t) publen);
    o += publen;
    memcpy(t->dnskey_rd, p + dkstart, (size_t) (4 + publen));
    t->dnskey_rdlen = 4 + publen;
    t->plen = o;
}

/* Sign `data` with pkey. For Ed25519 the output is the raw 64-byte signature;
 * for ECDSA the DER signature is converted to raw R||S (as DNSSEC encodes it). */
static int sign_data(EVP_PKEY *pkey, int is_ed, const uint8_t *data, size_t dlen,
                     uint8_t sig64[64]) {
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

static void run_alg(uint8_t alg) {
    const int is_ed = (alg == 15);
    printf("== algorithm %u (%s) ==\n", alg, is_ed ? "Ed25519" : "ECDSA P-256");

    EVP_PKEY *pkey = is_ed ? EVP_PKEY_Q_keygen(NULL, NULL, "ED25519")
                           : EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!pkey) {
        printf("  FAIL  keygen\n");
        g_failures++;
        return;
    }

    /* Extract the DNSKEY public-key bytes */
    uint8_t pub[80];
    int publen;
    if (is_ed) {
        size_t l = sizeof(pub);
        if (EVP_PKEY_get_raw_public_key(pkey, pub, &l) <= 0 || l != 32) {
            printf("  FAIL  raw pubkey extraction\n");
            g_failures++;
            EVP_PKEY_free(pkey);
            return;
        }
        publen = 32;
    } else {
        uint8_t enc[80];
        size_t l = 0;
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, enc,
                                            sizeof(enc), &l) <= 0 ||
            l != 65 || enc[0] != 0x04) {
            printf("  FAIL  EC pubkey extraction\n");
            g_failures++;
            EVP_PKEY_free(pkey);
            return;
        }
        memcpy(pub, enc + 1, 64); /* strip the 0x04 uncompressed-point tag */
        publen = 64;
    }

    /* Build the RRSIG header exactly as it will appear in rdata, construct
     * the signing input independently, and sign it. */
    uint8_t hdr[18 + sizeof(WIRE_SIGNER)];
    put16(hdr, 0, 1); /* covered: A */
    hdr[2] = alg;
    hdr[3] = 3; /* labels */
    put32(hdr, 4, ORIG_TTL);
    put32(hdr, 8, 0xFFFFFFFFu);
    put32(hdr, 12, 0);
    put16(hdr, 16, 0);
    memcpy(hdr + 18, WIRE_SIGNER, sizeof(WIRE_SIGNER));

    uint8_t signing[512];
    int siglen_in = build_signing_input(hdr, (int) sizeof(hdr), signing);

    uint8_t sig[64];
    if (!sign_data(pkey, is_ed, signing, (size_t) siglen_in, sig)) {
        printf("  FAIL  signing\n");
        g_failures++;
        EVP_PKEY_free(pkey);
        return;
    }

    testpkt_t t;
    build_packet(&t, alg, sig, pub, publen);

    /* 1. known-answer: intact packet verifies */
    int r = dnssec_verify_rrset(t.pkt, t.plen, t.rr_offs, 2, t.rrsig_rd, t.rrsig_rdlen, t.dnskey_rd,
                                t.dnskey_rdlen);
    CHECK(r == 1, "intact RRset verifies (known-answer)");

    /* 2. negative: flip one bit of A rdata → must reject */
    t.pkt[t.a1_rdata_off + 3] ^= 0x01;
    r = dnssec_verify_rrset(t.pkt, t.plen, t.rr_offs, 2, t.rrsig_rd, t.rrsig_rdlen, t.dnskey_rd,
                            t.dnskey_rdlen);
    CHECK(r == 0, "tampered A rdata rejected");
    t.pkt[t.a1_rdata_off + 3] ^= 0x01;

    /* 3. negative: flip one bit of the signature → must reject */
    t.rrsig_rd[t.rrsig_rdlen - 1] ^= 0x01;
    r = dnssec_verify_rrset(t.pkt, t.plen, t.rr_offs, 2, t.rrsig_rd, t.rrsig_rdlen, t.dnskey_rd,
                            t.dnskey_rdlen);
    CHECK(r == 0, "tampered signature rejected");
    t.rrsig_rd[t.rrsig_rdlen - 1] ^= 0x01;

    /* 4. end-to-end through dnssec_validate_response with a trust anchor */
    {
        uint8_t hash[32];
        char hex[65];
        sha256_buf(t.dnskey_rd, t.dnskey_rdlen, hash);
        for (int i = 0; i < 32; i++)
            sprintf(hex + 2 * i, "%02x", hash[i]);
        g_trust_anchor_count = 0; /* reset between algorithms */
        dnssec_add_trust_anchor(hex);

        dnssec_status_t st = dnssec_validate_response(t.pkt, t.plen, "www.example.com");
        CHECK(st == DNSSEC_SECURE, "validate_response: intact → SECURE");

        t.pkt[t.a1_rdata_off + 3] ^= 0x01;
        st = dnssec_validate_response(t.pkt, t.plen, "www.example.com");
        CHECK(st == DNSSEC_BOGUS, "validate_response: tampered rdata → BOGUS");
        t.pkt[t.a1_rdata_off + 3] ^= 0x01;

        t.pkt[t.sig_off] ^= 0x01;
        st = dnssec_validate_response(t.pkt, t.plen, "www.example.com");
        CHECK(st == DNSSEC_BOGUS, "validate_response: tampered signature → BOGUS");
        t.pkt[t.sig_off] ^= 0x01;
    }

    EVP_PKEY_free(pkey);
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
