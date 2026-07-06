/* tests/test_certd_challenges.c
 *
 * Known-answer + live tests for certd's two optional ACME additions
 * (CLAUDE-certd.md Add 2/Add 3, both `static` inside certd.c):
 *
 *   - RFC 8738 (ACME for IP identifiers): is_ip_literal's dns/ip split, and
 *     make_csr_der producing an "IP:" SAN for an IP identifier vs. the
 *     unchanged "DNS:" SAN for a domain (so the dns-01 path is provably
 *     untouched by this change).
 *   - RFC 8737 (TLS-ALPN-01): the ephemeral challenge cert (SAN +
 *     acmeIdentifier extension correctness), and a *live* handshake against
 *     tlsalpn01_start/tlsalpn01_stop's real listener — proving the server
 *     negotiates "acme-tls/1" and nothing else, and that the presented cert
 *     carries the right SHA-256(keyAuthorization) digest.
 *
 * A full mock ACME server (directory/newOrder/authz/finalize) exercising
 * acme_issue() end-to-end is out of scope here, matching the project's
 * existing precedent: check-ari also stops at the new isolated piece
 * (directory + ARI parsing) rather than a full issuance flow, since that
 * still needs a real/staging CA. These tests give the same treatment to the
 * two new isolated pieces Add 2/Add 3 actually touch.
 *
 * Build (from repo root):
 *   clang -std=c99 -D_GNU_SOURCE -g -fsanitize=address,undefined -DUNIT_TEST -I. \
 *       -Wno-unused-function -o tests/test_certd_challenges \
 *       tests/test_certd_challenges.c dns_wire.c -lssl -lcrypto -lpthread
 */

#define UNIT_TEST 1
#include "certd.c"

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

static void test_is_ip_literal(void) {
    printf("== is_ip_literal: dns vs ip identifier split (RFC 8738) ==\n");
    CHECK(is_ip_literal("192.0.2.1") == 1, "IPv4 literal recognized");
    CHECK(is_ip_literal("2001:db8::1") == 1, "IPv6 literal recognized");
    CHECK(is_ip_literal("www.example.local") == 0, "DNS name is not an IP literal");
    CHECK(is_ip_literal("256.0.0.1") == 0, "malformed IPv4 is not an IP literal");
}

static X509_REQ *csr_from_der(uint8_t *der, int derlen) {
    const uint8_t *p = der;
    return d2i_X509_REQ(NULL, &p, derlen);
}

static int req_san_matches(X509_REQ *req, int expect_ip, const char *expect_val) {
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if (!exts)
        return 0;
    int found = 0;
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_alt_name)
            continue;
        GENERAL_NAMES *gns = X509V3_EXT_d2i(ext);
        if (!gns)
            continue;
        for (int j = 0; j < sk_GENERAL_NAME_num(gns); j++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(gns, j);
            if (expect_ip && gn->type == GEN_IPADD) {
                unsigned char want[16];
                int wlen = strchr(expect_val, ':') ? 16 : 4;
                inet_pton(wlen == 16 ? AF_INET6 : AF_INET, expect_val, want);
                if (ASN1_STRING_length(gn->d.iPAddress) == wlen &&
                    memcmp(ASN1_STRING_get0_data(gn->d.iPAddress), want, wlen) == 0)
                    found = 1;
            } else if (!expect_ip && gn->type == GEN_DNS) {
                const char *s = (const char *) ASN1_STRING_get0_data(gn->d.dNSName);
                int slen = ASN1_STRING_length(gn->d.dNSName);
                if ((int) strlen(expect_val) == slen && memcmp(s, expect_val, slen) == 0)
                    found = 1;
            }
        }
        GENERAL_NAMES_free(gns);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return found;
}

static void test_csr_san(void) {
    printf("== make_csr_der: IP vs DNS SAN (RFC 8738) ==\n");
    EVP_PKEY *dk = NULL;
    int derlen = 0;
    uint8_t *der = make_csr_der("192.0.2.55", 1, &dk, &derlen);
    CHECK(der != NULL, "IP-identifier CSR built");
    if (der) {
        X509_REQ *req = csr_from_der(der, derlen);
        CHECK(req != NULL, "IP-identifier CSR parses back as a valid PKCS#10 request");
        if (req) {
            CHECK(req_san_matches(req, 1, "192.0.2.55"), "SAN is IP:192.0.2.55, not a dNSName");
            X509_REQ_free(req);
        }
        free(der);
        EVP_PKEY_free(dk);
    }

    EVP_PKEY *dk2 = NULL;
    int derlen2 = 0;
    uint8_t *der2 = make_csr_der("www.example.local", 0, &dk2, &derlen2);
    CHECK(der2 != NULL, "DNS-identifier CSR built");
    if (der2) {
        X509_REQ *req2 = csr_from_der(der2, derlen2);
        CHECK(req2 != NULL, "DNS-identifier CSR parses back as a valid PKCS#10 request");
        if (req2) {
            CHECK(req_san_matches(req2, 0, "www.example.local"),
                  "SAN is still DNS:www.example.local — dns-01 path unchanged");
            X509_REQ_free(req2);
        }
        free(der2);
        EVP_PKEY_free(dk2);
    }
}

static void test_acme_identifier_ext(void) {
    printf("== make_acme_identifier_ext: id-pe-acmeIdentifier encoding (RFC 8737 s3) ==\n");
    uint8_t hash[32];
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t) i;
    X509_EXTENSION *ext = make_acme_identifier_ext(hash);
    CHECK(ext != NULL, "extension built");
    if (!ext)
        return;
    CHECK(X509_EXTENSION_get_critical(ext) == 1, "marked critical");
    char oidbuf[64];
    OBJ_obj2txt(oidbuf, sizeof(oidbuf), X509_EXTENSION_get_object(ext), 1);
    CHECK(strcmp(oidbuf, OID_ACME_IDENTIFIER) == 0,
          "OID is 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)");
    ASN1_OCTET_STRING *val = X509_EXTENSION_get_data(ext);
    const unsigned char *p = ASN1_STRING_get0_data(val);
    ASN1_OCTET_STRING *inner = d2i_ASN1_OCTET_STRING(NULL, &p, ASN1_STRING_length(val));
    CHECK(inner != NULL, "extnValue decodes as a nested DER OCTET STRING");
    if (inner) {
        CHECK(ASN1_STRING_length(inner) == 32, "inner value is exactly 32 bytes");
        CHECK(memcmp(ASN1_STRING_get0_data(inner), hash, 32) == 0,
              "inner value equals the SHA-256(keyAuthorization) digest passed in");
        ASN1_OCTET_STRING_free(inner);
    }
    X509_EXTENSION_free(ext);
}

static int cert_san_matches(X509 *cert, int expect_ip, const char *expect_val) {
    GENERAL_NAMES *gns = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!gns)
        return 0;
    int found = 0;
    for (int j = 0; j < sk_GENERAL_NAME_num(gns); j++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(gns, j);
        if (expect_ip && gn->type == GEN_IPADD) {
            unsigned char want[16];
            int wlen = strchr(expect_val, ':') ? 16 : 4;
            inet_pton(wlen == 16 ? AF_INET6 : AF_INET, expect_val, want);
            if (ASN1_STRING_length(gn->d.iPAddress) == wlen &&
                memcmp(ASN1_STRING_get0_data(gn->d.iPAddress), want, wlen) == 0)
                found = 1;
        } else if (!expect_ip && gn->type == GEN_DNS) {
            const char *s = (const char *) ASN1_STRING_get0_data(gn->d.dNSName);
            int slen = ASN1_STRING_length(gn->d.dNSName);
            if ((int) strlen(expect_val) == slen && memcmp(s, expect_val, slen) == 0)
                found = 1;
        }
    }
    GENERAL_NAMES_free(gns);
    return found;
}

static int cert_has_acme_identifier(X509 *cert, const uint8_t expect_hash[32]) {
    ASN1_OBJECT *want = OBJ_txt2obj(OID_ACME_IDENTIFIER, 1);
    if (!want)
        return 0;
    int ok = 0;
    int n = X509_get_ext_count(cert);
    for (int i = 0; i < n; i++) {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        if (OBJ_cmp(X509_EXTENSION_get_object(ext), want) != 0)
            continue;
        if (!X509_EXTENSION_get_critical(ext))
            break;
        ASN1_OCTET_STRING *val = X509_EXTENSION_get_data(ext);
        const unsigned char *p = ASN1_STRING_get0_data(val);
        ASN1_OCTET_STRING *inner = d2i_ASN1_OCTET_STRING(NULL, &p, ASN1_STRING_length(val));
        if (inner) {
            ok = ASN1_STRING_length(inner) == 32 &&
                 memcmp(ASN1_STRING_get0_data(inner), expect_hash, 32) == 0;
            ASN1_OCTET_STRING_free(inner);
        }
        break;
    }
    ASN1_OBJECT_free(want);
    return ok;
}

/* Minimal client-side ALPN probe: connects, offers exactly one ALPN protocol,
 * and returns the peer cert on a successful handshake (NULL if the server
 * rejected it, e.g. no ALPN overlap). Verification is intentionally off —
 * this is a self-signed one-shot challenge cert, not a trust decision. */
static X509 *tls_test_connect(int port, const char *alpn_proto, char *negotiated,
                              int negotiated_sz) {
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx)
        return NULL;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    unsigned char alpn[64];
    size_t plen = strlen(alpn_proto);
    alpn[0] = (unsigned char) plen;
    memcpy(alpn + 1, alpn_proto, plen);
    SSL_CTX_set_alpn_protos(cctx, alpn, (unsigned int) (plen + 1));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        SSL_CTX_free(cctx);
        return NULL;
    }
    struct timeval tv = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t) port)};
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        close(fd);
        SSL_CTX_free(cctx);
        return NULL;
    }
    SSL *ssl = SSL_new(cctx);
    SSL_set_fd(ssl, fd);
    X509 *peer = NULL;
    if (SSL_connect(ssl) > 0) {
        const unsigned char *np = NULL;
        unsigned int nlen = 0;
        SSL_get0_alpn_selected(ssl, &np, &nlen);
        if (np && negotiated && negotiated_sz > 0) {
            int n = (int) nlen < negotiated_sz - 1 ? (int) nlen : negotiated_sz - 1;
            memcpy(negotiated, np, (size_t) n);
            negotiated[n] = 0;
        }
        peer = SSL_get1_peer_certificate(ssl);
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    close(fd);
    return peer;
}

static void test_tlsalpn01_listener(void) {
    printf("== tls-alpn-01: live listener (RFC 8737) ==\n");
    uint8_t hash[32];
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t) (0xA0 + i);
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    CHECK(tlsalpn01_make_cert("192.0.2.77", 1, hash, &cert, &key) == 0,
          "tlsalpn01_make_cert: builds a challenge cert for an IP identifier");
    if (!cert) {
        g_failures++;
        return;
    }

    int port = 15743;
    tlsalpn01_listener_t *l = NULL;
    pthread_t tid;
    int started = tlsalpn01_start(port, cert, key, &l, &tid) == 0;
    CHECK(started, "tlsalpn01_start: binds and listens");
    if (!started) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return;
    }

    char negotiated[32] = {0};
    X509 *seen = tls_test_connect(port, ACME_TLS_ALPN_PROTO, negotiated, sizeof(negotiated));
    CHECK(seen != NULL, "a client offering acme-tls/1 completes the handshake");
    CHECK(!strcmp(negotiated, ACME_TLS_ALPN_PROTO),
          "server negotiates acme-tls/1 (and nothing else)");
    if (seen) {
        CHECK(cert_san_matches(seen, 1, "192.0.2.77"),
              "presented cert's SAN matches the identifier under validation");
        CHECK(cert_has_acme_identifier(seen, hash),
              "presented cert carries the correct acmeIdentifier digest");
        X509_free(seen);
    }

    char negotiated2[32] = {0};
    X509 *rejected = tls_test_connect(port, "http/1.1", negotiated2, sizeof(negotiated2));
    CHECK(rejected == NULL,
          "a client NOT offering acme-tls/1 is refused (fail-closed ALPN, RFC 8737 s3)");
    if (rejected)
        X509_free(rejected);

    tlsalpn01_stop(l, tid);
    X509_free(cert);
    EVP_PKEY_free(key);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_is_ip_literal();
    test_csr_san();
    test_acme_identifier_ext();
    test_tlsalpn01_listener();
    printf("\n%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
