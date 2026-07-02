/* tests/test_aggressive_nsec.c
 *
 * Known-answer + negative tests for RFC 8198 aggressive use of the
 * DNSSEC-validated negative cache, added to resolverd.c:
 *
 *   - nsec_parse_rdata     NSEC/NSEC3 rdata -> nsec_proof_t extraction
 *   - aggressive_nsec_answer / name_in_zone / nsec_bitmap_has_type
 *                          the gap-covering lookup that lets a later cache
 *                          miss be answered without an upstream query
 *   - dnssec_validate_negative
 *                          end-to-end SOA+NSEC authority-section validation:
 *                          known-answer SECURE, negative BOGUS on a flipped
 *                          signature byte, fail-closed with no SOA present
 *
 * Build (from repo root):
 *   gcc -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -I. \
 *       -o test_aggressive_nsec tests/test_aggressive_nsec.c dns_wire.c \
 *       sandbox.c -lssl -lcrypto -lpthread
 */

#define UNIT_TEST 1
#include "resolverd.c"

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

#define Z_ORIG_TTL 3600u

/* =========================================================================
 * Part A — nsec_parse_rdata: NSEC and NSEC3 rdata extraction
 * ======================================================================= */

static void test_nsec_parse_nsec(void) {
    printf("== nsec_parse_rdata: NSEC ==\n");
    uint8_t rdata[128];
    int o = 0;
    o += name_to_wire("m.example.com", rdata + o, sizeof(rdata) - o);
    rdata[o++] = 0;    /* window block 0 */
    rdata[o++] = 1;    /* bitmap length: 1 byte covers types 0-7 */
    rdata[o++] = 0x42; /* bit1 (A=1) | bit6 (SOA=6) */
    int rdlen = o;

    nsec_proof_t proof;
    int ok =
        nsec_parse_rdata(rdata, sizeof(rdata), "a.example.com", DNS_TYPE_NSEC, 0, rdlen, &proof);
    CHECK(ok == 1, "NSEC rdata parses");
    CHECK(!proof.is_nsec3, "NSEC: is_nsec3 is false");
    CHECK(strcmp(proof.owner, "a.example.com") == 0, "NSEC: owner preserved");
    CHECK(strcmp(proof.next, "m.example.com") == 0, "NSEC: next domain name decoded");
    CHECK(nsec_bitmap_has_type(proof.bitmap, proof.bitmap_len, DNS_TYPE_A) == 1,
          "NSEC: bitmap has A set");
    CHECK(nsec_bitmap_has_type(proof.bitmap, proof.bitmap_len, DNS_TYPE_SOA) == 1,
          "NSEC: bitmap has SOA set");
    CHECK(nsec_bitmap_has_type(proof.bitmap, proof.bitmap_len, DNS_TYPE_TXT) == 0,
          "NSEC: bitmap does not have TXT");

    /* negative: rdlen too short for even the next-name's root label */
    ok = nsec_parse_rdata(rdata, sizeof(rdata), "a.example.com", DNS_TYPE_NSEC, 0, 0, &proof);
    CHECK(ok == 0, "NSEC: zero-length rdata rejected (fail closed)");
}

static void test_nsec_parse_nsec3(void) {
    printf("== nsec_parse_rdata: NSEC3 ==\n");
    uint8_t salt[2] = {0xAB, 0xCD};
    uint8_t owner_hash[20], next_hash[20];
    nsec3_hash_raw("a.example.com", salt, 2, 3, owner_hash);
    nsec3_hash_raw("m.example.com", salt, 2, 3, next_hash);
    char label[64];
    base32hex_enc(owner_hash, 20, label, sizeof(label));
    strlower(label); /* name_from_wire would have lowercased it on a real decode */
    char owner[256];
    snprintf(owner, sizeof(owner), "%s.example.com", label);

    uint8_t rdata[128];
    int o = 0;
    rdata[o++] = NSEC3_ALG_SHA1;
    rdata[o++] = 0; /* flags: no opt-out */
    put16(rdata, o, 3);
    o += 2; /* iterations */
    rdata[o++] = 2;
    memcpy(rdata + o, salt, 2);
    o += 2; /* salt */
    rdata[o++] = 20;
    memcpy(rdata + o, next_hash, 20);
    o += 20; /* next hashed owner */
    rdata[o++] = 0;
    rdata[o++] = 1;
    rdata[o++] = 0x40; /* bitmap: window0 len1, bit1 (A) set */
    int rdlen = o;

    nsec_proof_t proof;
    int ok = nsec_parse_rdata(rdata, sizeof(rdata), owner, DNS_TYPE_NSEC3, 0, rdlen, &proof);
    CHECK(ok == 1, "NSEC3 rdata parses");
    CHECK(proof.is_nsec3, "NSEC3: is_nsec3 is true");
    CHECK(memcmp(proof.owner_hash, owner_hash, 20) == 0,
          "NSEC3: owner hash decoded from the owner's base32hex label");
    CHECK(memcmp(proof.next_hash, next_hash, 20) == 0, "NSEC3: next hashed owner copied");
    CHECK(proof.optout == 0, "NSEC3: opt-out clear");
    CHECK(proof.nsec3_iters == 3, "NSEC3: iterations decoded");
    CHECK(proof.nsec3_saltlen == 2 && memcmp(proof.nsec3_salt, salt, 2) == 0,
          "NSEC3: salt decoded");
    CHECK(nsec_bitmap_has_type(proof.bitmap, proof.bitmap_len, DNS_TYPE_A) == 1,
          "NSEC3: bitmap has A set");

    /* opt-out variant */
    rdata[1] = 0x01;
    ok = nsec_parse_rdata(rdata, sizeof(rdata), owner, DNS_TYPE_NSEC3, 0, rdlen, &proof);
    CHECK(ok == 1 && proof.optout == 1, "NSEC3: opt-out flag decoded");

    /* negative: alg other than SHA-1 (1) is rejected — we only support alg 1 */
    rdata[0] = 2;
    ok = nsec_parse_rdata(rdata, sizeof(rdata), owner, DNS_TYPE_NSEC3, 0, rdlen, &proof);
    CHECK(ok == 0, "NSEC3: unsupported hash algorithm rejected (fail closed)");
}

/* =========================================================================
 * Part B — aggressive_nsec_answer: the gap-covering lookup
 * ======================================================================= */

static void reset_agg_store(void) {
    memset(g_agg_nsec, 0, sizeof(g_agg_nsec));
    g_agg_nsec_next = 0;
}

static void test_aggressive_answer_nsec(void) {
    printf("== aggressive_nsec_answer: NSEC gap covering ==\n");
    g_cfg.aggressive_nsec_enabled = 1;
    reset_agg_store();

    nsec_proof_t p;
    memset(&p, 0, sizeof(p));
    safe_strcpy(p.zone, "example.com", sizeof(p.zone));
    safe_strcpy(p.owner, "a.example.com", sizeof(p.owner));
    safe_strcpy(p.next, "m.example.com", sizeof(p.next));
    p.bitmap[0] = 0;
    p.bitmap[1] = 1;
    p.bitmap[2] = 0x40; /* type A exists at a.example.com */
    p.bitmap_len = 3;
    aggressive_nsec_insert(&p, 300);

    agg_nsec_result_t r;
    CHECK(aggressive_nsec_answer("g.example.com", DNS_TYPE_TXT, &r) == 1 && r.is_nxdomain,
          "gap match: g.example.com (between a. and m.) -> NXDOMAIN");
    CHECK(aggressive_nsec_answer("z.example.com", DNS_TYPE_A, &r) == 0,
          "no match: z.example.com is outside the covered range");
    CHECK(aggressive_nsec_answer("a.example.com", DNS_TYPE_A, &r) == 0,
          "owner-exact match but queried type IS in the bitmap -> can't help, no answer");
    CHECK(aggressive_nsec_answer("a.example.com", DNS_TYPE_TXT, &r) == 1 && !r.is_nxdomain,
          "owner-exact match, TXT absent from bitmap -> NODATA");
    CHECK(aggressive_nsec_answer("g.other.com", DNS_TYPE_A, &r) == 0,
          "zone-scoping: a name outside example.com never matches this span");

    /* Wraparound: the last NSEC in the chain, next == the zone apex. */
    reset_agg_store();
    safe_strcpy(p.owner, "z.example.com", sizeof(p.owner));
    safe_strcpy(p.next, "example.com", sizeof(p.next));
    p.bitmap_len = 0;
    aggressive_nsec_insert(&p, 300);
    CHECK(aggressive_nsec_answer("zz.example.com", DNS_TYPE_A, &r) == 1 && r.is_nxdomain,
          "wraparound: a name after the last owner is still covered");
    CHECK(aggressive_nsec_answer("m.example.com", DNS_TYPE_A, &r) == 0,
          "wraparound: a name before the covered tail is not covered by it");

    /* Expiry: an expired span must never answer. */
    reset_agg_store();
    safe_strcpy(p.owner, "a.example.com", sizeof(p.owner));
    safe_strcpy(p.next, "m.example.com", sizeof(p.next));
    aggressive_nsec_insert(&p, 300);
    g_agg_nsec[0].expiry = time(NULL) - 1; /* force-expire */
    CHECK(aggressive_nsec_answer("g.example.com", DNS_TYPE_A, &r) == 0,
          "expired span is never used");

    /* Config gate. */
    reset_agg_store();
    aggressive_nsec_insert(&p, 300);
    g_cfg.aggressive_nsec_enabled = 0;
    CHECK(aggressive_nsec_answer("g.example.com", DNS_TYPE_A, &r) == 0,
          "aggressive_nsec_enabled=0 disables the lookup entirely");
    g_cfg.aggressive_nsec_enabled = 1;
}

static void test_aggressive_answer_nsec3(void) {
    printf("== aggressive_nsec_answer: NSEC3 gap covering + opt-out ==\n");
    g_cfg.aggressive_nsec_enabled = 1;
    reset_agg_store();

    /* A maximally wide hash range (0x00.. to 0xFF..) so any real name's
     * SHA-1 hash lands inside it with overwhelming probability — this tests
     * the covering arithmetic itself, not a specific preimage. */
    nsec_proof_t p;
    memset(&p, 0, sizeof(p));
    safe_strcpy(p.zone, "example.com", sizeof(p.zone));
    p.is_nsec3 = 1;
    p.nsec3_iters = 0;
    p.nsec3_saltlen = 0;
    memset(p.owner_hash, 0x00, 20);
    memset(p.next_hash, 0xFF, 20);
    p.optout = 0;
    aggressive_nsec_insert(&p, 300);

    agg_nsec_result_t r;
    CHECK(aggressive_nsec_answer("anything.example.com", DNS_TYPE_A, &r) == 1 && r.is_nxdomain,
          "NSEC3: near-full hash range covers an arbitrary name -> NXDOMAIN");
    CHECK(aggressive_nsec_answer("anything.other.com", DNS_TYPE_A, &r) == 0,
          "NSEC3: zone-scoping still applies");

    /* Opt-out: RFC 5155 §7.2.1 / RFC 8198 §5 — must never be used to
     * synthesize non-existence. */
    reset_agg_store();
    p.optout = 1;
    aggressive_nsec_insert(&p, 300);
    CHECK(aggressive_nsec_answer("anything.example.com", DNS_TYPE_A, &r) == 0,
          "NSEC3: an opt-out span is never used for aggressive synthesis");
}

/* =========================================================================
 * Part C — dnssec_validate_negative: end-to-end SOA+NSEC authority-section
 * validation (Ed25519).
 * ======================================================================= */

/* Sign `data` with pkey, emitting the 64-byte DNSSEC signature (the native
 * form for Ed25519). Returns 1 on success. */
static int sign_data(EVP_PKEY *pkey, int is_ed, const uint8_t *data, size_t dlen,
                     uint8_t sig64[64]) {
    (void) is_ed;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t slen = 64;
    int ok = 0;
    if (!ctx)
        return 0;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) > 0 &&
        EVP_DigestSign(ctx, sig64, &slen, data, dlen) > 0 && slen == 64)
        ok = 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* owner(wire) type(2) class(2) ttl(4) rdlen(2) rdata(rdlen) — the exact
 * canonical RR form (RFC 4034 §6.2) for these all-lowercase names, so it
 * doubles as both the packet bytes and the signing input. */
static int build_rr(uint8_t *out, const char *owner, uint16_t type, uint32_t ttl,
                    const uint8_t *rdata, int rdlen, int *rdata_off_out) {
    int o = 0;
    o += name_to_wire(owner, out + o, 256);
    put16(out, o, type);
    o += 2;
    put16(out, o, 1);
    o += 2; /* class IN */
    put32(out, o, ttl);
    o += 4;
    put16(out, o, (uint16_t) rdlen);
    o += 2;
    if (rdata_off_out)
        *rdata_off_out = o;
    memcpy(out + o, rdata, (size_t) rdlen);
    o += rdlen;
    return o;
}

/* RRSIG rdata up to (and including) the signer name; sig_off_out receives
 * the offset of the 64-byte signature that follows. */
static int build_rrsig_rdata(uint8_t *out, uint16_t covered, uint8_t alg, uint8_t labels,
                             uint32_t origttl, const char *signer, const uint8_t sig64[64],
                             int *sig_off_out) {
    int o = 0;
    put16(out, o, covered);
    o += 2;
    out[o++] = alg;
    out[o++] = labels;
    put32(out, o, origttl);
    o += 4;
    put32(out, o, 0xFFFFFFFFu);
    o += 4; /* expiration: not checked here */
    put32(out, o, 0);
    o += 4; /* inception: not checked here */
    put16(out, o, 0);
    o += 2; /* key tag: not checked here */
    o += name_to_wire(signer, out + o, 256);
    if (sig_off_out)
        *sig_off_out = o;
    memcpy(out + o, sig64, 64);
    o += 64;
    return o;
}

typedef struct {
    uint8_t pkt[1500];
    int plen;
    int soa_sig_pkt_off;
    int nsec_sig_pkt_off;
} negpkt_t;

/* Builds: header (NXDOMAIN, qd=1 ns=4 ar=1), question nx.example.com,
 * authority {SOA, RRSIG(SOA), NSEC(a.->m.), RRSIG(NSEC)}, additional
 * {DNSKEY}. include_soa=0 drops the SOA/RRSIG(SOA) pair for the
 * malformed-proof negative test. */
static void build_neg_packet(negpkt_t *t, EVP_PKEY *key, const uint8_t dnskey_rd[36],
                             int include_soa) {
    uint8_t sig[64];
    uint8_t sin[600];
    int sl;

    /* SOA */
    uint8_t soa_rd[128];
    int so = 0;
    so += name_to_wire("ns1.example.com", soa_rd + so, 128);
    so += name_to_wire("admin.example.com", soa_rd + so, 128 - so);
    put32(soa_rd, so, 1);
    so += 4;
    put32(soa_rd, so, 3600);
    so += 4;
    put32(soa_rd, so, 1800);
    so += 4;
    put32(soa_rd, so, 604800);
    so += 4;
    put32(soa_rd, so, 300);
    so += 4;
    int soa_rdlen = so;

    uint8_t canon_soa[256];
    int canon_soa_len =
        build_rr(canon_soa, "example.com", DNS_TYPE_SOA, Z_ORIG_TTL, soa_rd, soa_rdlen, NULL);
    uint8_t soa_hdr[300];
    int soa_hdr_len =
        build_rrsig_rdata(soa_hdr, DNS_TYPE_SOA, 15, 2, Z_ORIG_TTL, "example.com", sig, NULL);
    sl = 0;
    memcpy(sin, soa_hdr, (size_t) (soa_hdr_len - 64));
    sl += soa_hdr_len - 64;
    memcpy(sin + sl, canon_soa, (size_t) canon_soa_len);
    sl += canon_soa_len;
    CHECK(sign_data(key, 1, sin, (size_t) sl, sig) == 1, "  (setup) SOA RRSIG signs");
    uint8_t soa_rrsig_rd[300];
    int soa_sig_off;
    int soa_rrsig_rdlen = build_rrsig_rdata(soa_rrsig_rd, DNS_TYPE_SOA, 15, 2, Z_ORIG_TTL,
                                            "example.com", sig, &soa_sig_off);

    /* NSEC */
    uint8_t nsec_rd[64];
    int no = 0;
    no += name_to_wire("m.example.com", nsec_rd + no, 64);
    nsec_rd[no++] = 0;
    nsec_rd[no++] = 1;
    nsec_rd[no++] = 0x40;
    int nsec_rdlen = no;

    uint8_t canon_nsec[256];
    int canon_nsec_len =
        build_rr(canon_nsec, "a.example.com", DNS_TYPE_NSEC, Z_ORIG_TTL, nsec_rd, nsec_rdlen, NULL);
    uint8_t nsec_hdr[300];
    int nsec_hdr_len =
        build_rrsig_rdata(nsec_hdr, DNS_TYPE_NSEC, 15, 3, Z_ORIG_TTL, "example.com", sig, NULL);
    sl = 0;
    memcpy(sin, nsec_hdr, (size_t) (nsec_hdr_len - 64));
    sl += nsec_hdr_len - 64;
    memcpy(sin + sl, canon_nsec, (size_t) canon_nsec_len);
    sl += canon_nsec_len;
    CHECK(sign_data(key, 1, sin, (size_t) sl, sig) == 1, "  (setup) NSEC RRSIG signs");
    uint8_t nsec_rrsig_rd[300];
    int nsec_sig_off;
    int nsec_rrsig_rdlen = build_rrsig_rdata(nsec_rrsig_rd, DNS_TYPE_NSEC, 15, 3, Z_ORIG_TTL,
                                             "example.com", sig, &nsec_sig_off);

    /* Assemble the packet. */
    uint8_t *pkt = t->pkt;
    int o = 12;
    o += name_to_wire("nx.example.com", pkt + o, (int) sizeof(t->pkt) - o);
    put16(pkt, o, 1);
    o += 2;
    put16(pkt, o, 1);
    o += 2;

    int nscount = 0;
    t->soa_sig_pkt_off = -1;
    if (include_soa) {
        int rdoff;
        int rrlen =
            build_rr(pkt + o, "example.com", DNS_TYPE_SOA, Z_ORIG_TTL, soa_rd, soa_rdlen, &rdoff);
        o += rrlen;
        nscount++;
        rrlen = build_rr(pkt + o, "example.com", DNS_TYPE_RRSIG, Z_ORIG_TTL, soa_rrsig_rd,
                         soa_rrsig_rdlen, &rdoff);
        t->soa_sig_pkt_off = o + rdoff + soa_sig_off;
        o += rrlen;
        nscount++;
    }
    {
        int rdoff;
        int rrlen = build_rr(pkt + o, "a.example.com", DNS_TYPE_NSEC, Z_ORIG_TTL, nsec_rd,
                             nsec_rdlen, &rdoff);
        o += rrlen;
        nscount++;
        rrlen = build_rr(pkt + o, "a.example.com", DNS_TYPE_RRSIG, Z_ORIG_TTL, nsec_rrsig_rd,
                         nsec_rrsig_rdlen, &rdoff);
        t->nsec_sig_pkt_off = o + rdoff + nsec_sig_off;
        o += rrlen;
        nscount++;
    }
    int arcount = 0;
    {
        int rdoff;
        o += build_rr(pkt + o, "example.com", DNS_TYPE_DNSKEY, Z_ORIG_TTL, dnskey_rd, 36, &rdoff);
        arcount++;
    }

    put16(pkt, 0, 0x1234);
    put16(pkt, 2, 0x8183); /* QR|RD|RA, rcode=3 NXDOMAIN */
    put16(pkt, 4, 1);      /* qdcount */
    put16(pkt, 6, 0);      /* ancount */
    put16(pkt, 8, (uint16_t) nscount);
    put16(pkt, 10, (uint16_t) arcount);
    t->plen = o;
}

static void test_validate_negative(void) {
    printf("== dnssec_validate_negative: end-to-end (Ed25519) ==\n");
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (!key) {
        printf("  FAIL  keygen\n");
        g_failures++;
        return;
    }
    uint8_t pub[32];
    size_t publen = 32;
    if (EVP_PKEY_get_raw_public_key(key, pub, &publen) <= 0 || publen != 32) {
        printf("  FAIL  extract pubkey\n");
        g_failures++;
        return;
    }
    uint8_t dnskey_rd[36];
    put16(dnskey_rd, 0, 0x0101);
    dnskey_rd[2] = 3;
    dnskey_rd[3] = 15;
    memcpy(dnskey_rd + 4, pub, 32);

    uint8_t hash[32];
    char hex[65];
    sha256_buf(dnskey_rd, 36, hash);
    for (int i = 0; i < 32; i++)
        sprintf(hex + 2 * i, "%02x", hash[i]);
    g_trust_anchor_count = 0;
    dnssec_add_trust_anchor(hex);

    negpkt_t t;
    build_neg_packet(&t, key, dnskey_rd, 1);

    nsec_proof_t proofs[MAX_NEG_PROOFS];
    int proof_n = 0;
    dnssec_status_t st =
        dnssec_validate_negative(t.pkt, t.plen, "nx.example.com", proofs, MAX_NEG_PROOFS, &proof_n);
    CHECK(st == DNSSEC_SECURE, "intact SOA+NSEC authority section -> SECURE");
    CHECK(proof_n == 1, "exactly one denial span extracted");
    if (proof_n == 1) {
        CHECK(!proofs[0].is_nsec3, "extracted span is NSEC, not NSEC3");
        CHECK(strcmp(proofs[0].owner, "a.example.com") == 0, "extracted span owner matches");
        CHECK(strcmp(proofs[0].next, "m.example.com") == 0, "extracted span next matches");
        CHECK(strcmp(proofs[0].zone, "example.com") == 0, "extracted span zone == SOA owner");
    }

    /* Negative: flip a bit in the NSEC RRSIG signature -> BOGUS. */
    t.pkt[t.nsec_sig_pkt_off] ^= 0x01;
    proof_n = 0;
    st =
        dnssec_validate_negative(t.pkt, t.plen, "nx.example.com", proofs, MAX_NEG_PROOFS, &proof_n);
    CHECK(st == DNSSEC_BOGUS, "tampered NSEC RRSIG -> BOGUS");
    t.pkt[t.nsec_sig_pkt_off] ^= 0x01;

    /* Negative: flip a bit in the SOA RRSIG signature -> BOGUS. */
    t.pkt[t.soa_sig_pkt_off] ^= 0x01;
    proof_n = 0;
    st =
        dnssec_validate_negative(t.pkt, t.plen, "nx.example.com", proofs, MAX_NEG_PROOFS, &proof_n);
    CHECK(st == DNSSEC_BOGUS, "tampered SOA RRSIG -> BOGUS");
    t.pkt[t.soa_sig_pkt_off] ^= 0x01;

    /* Negative: untrusted key -> valid signatures, but INSECURE not SECURE. */
    g_trust_anchor_count = 0;
    proof_n = 0;
    st =
        dnssec_validate_negative(t.pkt, t.plen, "nx.example.com", proofs, MAX_NEG_PROOFS, &proof_n);
    CHECK(st == DNSSEC_INSECURE, "valid signatures under an untrusted key -> INSECURE");
    CHECK(proof_n == 0, "no span extracted without a trusted key");
    dnssec_add_trust_anchor(hex); /* restore for the next case */

    /* Negative: no SOA at all -> not a well-formed denial proof, fail closed. */
    negpkt_t t2;
    build_neg_packet(&t2, key, dnskey_rd, 0);
    proof_n = 0;
    st = dnssec_validate_negative(t2.pkt, t2.plen, "nx.example.com", proofs, MAX_NEG_PROOFS,
                                  &proof_n);
    CHECK(st == DNSSEC_INSECURE, "no SOA in authority section -> INSECURE (fail closed)");

    EVP_PKEY_free(key);
}

int main(void) {
    test_nsec_parse_nsec();
    test_nsec_parse_nsec3();
    test_aggressive_answer_nsec();
    test_aggressive_answer_nsec3();
    test_validate_negative();

    if (g_failures == 0) {
        printf("\nALL TESTS PASSED\n");
        return 0;
    }
    printf("\n%d TEST(S) FAILED\n", g_failures);
    return 1;
}
