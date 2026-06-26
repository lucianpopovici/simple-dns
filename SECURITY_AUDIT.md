# Security Audit — simple-dns

> Per-run sections below, **newest first**. Finding IDs (`CSA-<area>-NNN`) are
> stable across runs so status can be tracked over time.

---

## 2026-06-25 — Incremental re-audit (@ commit 42a8ce5)

**Scope:** the trust-boundary code changed since the 2026-06-23 full audit —
resolverd's new RFC 7873 client DNS-cookie exchange (`response_opt_parse`,
`edns_append`, the per-upstream cookie store), the Valkey cache-load path
(`cache_load_valkey` / `entry_remaining_ttl` / `cache_entry_free`), the `--proto`
CLI handler, and the resolverd seccomp default — plus re-verification of all 11
prior findings. Method: manual review of the new parser/auth code (Passes 1–3, 5,
7) and pattern greps for each prior finding's signature.

**Deltas first:**
- **All 11 prior findings remain OPEN** — none fixed, none regressed. Line numbers
  shifted; current locations in the table below.
- **Mitigation strengthened:** `resolverd` seccomp now defaults to **enforce**
  (was `audit` at the last audit; whitelist harvest-validated across all upstream
  transports). `dnsd` was already enforce.
- **Security defects fixed this session** (were not separate findings before, but
  are security-relevant — recorded for the diff):
  - *resolverd Valkey cache-load NULL-deref* — a remotely-triggerable crash (DoS)
    on the first cache hit after an in-memory miss (restarted resolverd). Fixed
    (ordering + NULL guards); regression `make check-resolverd-cache`. This sits
    in the "resolverd cache concurrency" area the prior audit deferred.
  - *resolverd `--proto dot/tcp/doh` silent downgrade* — the CLI flag set
    `g_cfg.proto` but not `upstream_proto[0]`, so a CLI-configured DoT/DoH upstream
    silently sent **plaintext UDP** (confidentiality downgrade). Fixed. (env path
    was always correct.)
- **New code audited clean for memory safety:** `response_opt_parse`
  (`resolverd.c`, parses untrusted upstream responses) bounds-checks every field
  read and clamps the server-cookie copy to the 32-byte destination; the
  per-upstream cookie store is `g_cookie_mutex`-guarded (no race); the Client
  Cookie derives from a `RAND_bytes` secret (CSPRNG). No memory-safety finding.
- **One new finding:** `CSA-NET-002` (cookie learned from an unvalidated response)
  — Low, and a direct facet of the still-open `CSA-NET-001`.

**Counts (this run):** Critical 0 · High 3 · Medium 2 · Low 5 · Info 2
(prior 11 carried + 1 new Low). **All 12 were FIXED in this working tree during
this session** — see the status table and "Fixes applied" below.

### Finding status (carried IDs)

| ID | Sev | Status | Fix |
|---|---|---|---|
| CSA-TLS-001 | High | **Fixed** | `certd.c`: `SSL_VERIFY_PEER` hoisted out of the `if`, now set on both CA paths |
| CSA-TLS-002 | High | **Fixed** | `tls_verify_peer_name()` (set1_host / set1_ip for IP literals) on resolverd DoT+DoH, certd, dnsd XFR |
| CSA-NET-001 | High | **Fixed** | `resolverd.c` `response_matches_query()` — drop any reply whose ID/QR/question ≠ the query, before accept/cache/cookie-learn |
| CSA-NET-002 | Low | **Fixed** | closed by CSA-NET-001 (cookie learned only from a validated response) |
| CSA-RAND-001 | Medium | **Fixed** | `resolverd.c` `csprng_u16()` (RAND_bytes) for txn IDs + source ports, incl. cookie-retry ID |
| CSA-TIME-001 | Medium | **Fixed** | `apid.c`: DDNS secret via `CRYPTO_memcmp` after length check |
| CSA-TIME-002 | Low | **Fixed** | `dns_server.c`: TSIG MAC compares via `CRYPTO_memcmp` (verify + XFR) |
| CSA-TIME-003 | Low | **Fixed** | `dns_server.c`: server-cookie compare via `CRYPTO_memcmp` |
| CSA-TLS-003 | Low | **Fixed** | rsyslog already defaulted verify-on; added hostname verify on both rsyslog and pinned-CA XFR |
| CSA-DOS-001 | Low | **Fixed** | `apid.c` `http_read_request()` — loop to CRLFCRLF + Content-Length, bounded by buffer + `SO_RCVTIMEO` |
| CSA-WIRE-001 | Info | **Fixed** | `dns_wire.c`: `name_to_wire`/`name_to_wire_c` reject labels > 63 (test added) |
| CSA-RAND-002 | Info | **Fixed** | `dns_server.c`: outbound NOTIFY IDs via `csprng_u16()` |

Not addressed (out of scope): `simple_dns.c` mirrors of TLS/strcmp findings — it
is a reference artifact with **no build target** (not shipped), so its copies are
dead code; left as-is and noted here.

### Fixes applied — verification

- Builds: all daemons compile clean (`-Werror` warning set); clang-format clean.
- Tests (all green): `check`, `check-resolverd{,-cache,-cookie}`, `check-xfr-tsig`,
  `check-notify`, `check-ddns-acl`, `check-dot-mtls`, `check-forwarder`,
  `check-ptr`, `check-axfr`, `check-ixfr`, `check-wire` (new label-cap case),
  `check-dnssec`.
- TLS: DoT verified live against 1.1.1.1 **by IP** (set1_ip path) and by hostname
  (set1_host path) — both still resolve; identity is now bound to the cert.
- Anti-spoofing: real resolution through `response_matches_query` still works
  (A/AAAA/MX via 8.8.8.8); the cookie handshake test still passes.

### New finding (now fixed)

#### CSA-NET-002 — resolverd learns/stores the Server Cookie from an unvalidated response  [Low] [Fixed]
- Location: `resolverd.c` `upstream_query_one` (cookie-learning + BADCOOKIE retry),
  `cookie_store_server`, `response_opt_parse`.
- Reachability: any upstream answer; an off-path spoofer (same precondition as
  CSA-NET-001 — the transaction ID and question are still not validated).
- Issue: the RFC 7873 client exchange copies the Server Cookie out of the first
  response that parses and stores it per-upstream, then replays it on later
  queries. Because the response is not ID/question-validated, a spoofed response
  can plant a bogus Server Cookie.
- Impact: low and self-correcting — replaying a wrong Server Cookie to the real
  upstream yields BADCOOKIE, which triggers a re-learn; no memory unsafety. It
  does add a second unvalidated-response code path, so it is bounded by the same
  fix as CSA-NET-001.
- Fix: validate the response transaction ID + question before trusting *any* of
  its contents (closes CSA-NET-001 and this together); only update the stored
  cookie from a response that also answers the asked question.
- Tooling: manual.

> The 2026-06-23 full-audit findings (unchanged text) follow.

---

## 2026-06-23 — Full audit

## Summary

**Scope:** Whole repository, all C translation units: `dns_wire.c`/`dns_wire.h`
(libdnswire), `sandbox.c`/`sandbox.h` (libsandbox), `dns_server.c` (dnsd),
`resolverd.c`, `apid.c`, `certd.c`, `mdnsd.c`, `simple_dns.c` (reference impl).
Method: Pass-0 attack-surface mapping, targeted manual review of the
untrusted-input parsers / crypto / TLS / privilege paths, and pattern greps
(dangerous copies, weak RNG, non-constant-time compares, TLS verify config,
allocation overflow) across every TU. Tooling available in the sandbox was
limited (`clang-tidy`, `gcc`/`clang`, `readelf`; **no** cppcheck / scan-build /
valgrind / checksec). Binary-hardening was confirmed from the Makefile rather
than the production ELF (the production binary was not built at audit time).

**Trust map (entry points / boundaries):**

| Surface | Component | Trust |
|---|---|---|
| DNS wire (UDP/TCP 53, DoT 853) | dnsd | Internet, untrusted |
| Upstream responses (UDP/TCP/DoT/DoH) | resolverd | Internet, untrusted |
| HTTP/HTTPS, DoH, mgmt API | apid | Internet, untrusted (mTLS-gated writes) |
| ACME/EST to CA | certd | Outbound to semi-trusted CA, on-path attacker possible |
| mDNS multicast | mdnsd | Link-local |
| Valkey bus | all daemons | Trusted infrastructure (integration contract) |
| AXFR/IXFR to primary | dnsd (secondary role) | Outbound, TSIG-authenticated |

**Counts:** Critical 0 · High 3 · Medium 3 · Low 4 · Info 2

**New since last run:** all (first audit — no prior `SECURITY_AUDIT.md`).
**Fixed since last run:** n/a. **Regressed:** n/a.

The codebase is, on the whole, defensively written: `libdnswire` enforces the
`-1`-on-overflow convention with consistent call-site checks; the DNS message /
EDNS-OPT parser in `dnsd` bounds every field read; `libsandbox` drops privilege
in the correct order (`setgroups`→`setgid`→`setuid`), verifies the drop is
irreversible, sets `PR_SET_DUMPABLE 0`, and its seccomp allowlist excludes
`execve`/`ptrace`. Two historically-noted bugs (the `fudge` constant and the
EDNS DO-bit offset) are confirmed fixed. The findings below concentrate in the
**TLS peer-authentication** and **resolver anti-spoofing** paths.

---

## Findings

### CSA-TLS-001 — certd performs no TLS server-cert verification on the default (system-trust) path  [High] [Open]
- Location: `certd.c:535-544` (`https_connect`-style setup), no `SSL_get_verify_result` anywhere in `certd.c`.
- Reachability: Every ACME (directory/order/finalize) and EST connection certd
  makes when **no explicit CA PEM is configured** — the normal deployment that
  relies on the public/system trust store for a public ACME CA.
- Issue: `SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, …)` is called **only inside
  the `if (ca_pem)` branch**. The `else` branch calls
  `SSL_CTX_set_default_verify_paths()` but leaves the verify mode at its default
  `SSL_VERIFY_NONE`, and certd never calls `SSL_get_verify_result()`. Result:
  the handshake completes against **any** certificate, including self-signed.
- Impact: A man-in-the-middle between certd and the CA can impersonate the
  ACME/EST server — feed forged challenge instructions, capture EST mTLS client
  credentials, or hand back attacker-chosen "issued" certs that then land in
  `cert:current` and are served by dnsd/apid. CA impersonation / credential
  exposure.
- Fix: Always `SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL)` (move it out of
  the `if`), and add hostname verification (see CSA-TLS-002 fix). In `else`,
  verify `set_default_verify_paths` succeeds; fail closed if the chain or
  hostname does not verify.
- Tooling: manual.

### CSA-TLS-002 — No TLS hostname verification on any outbound connection (DoT MITM)  [High] [Open]
- Location: `resolverd.c:1620, 1755` (DoT/`dot_connect`), `certd.c:573`,
  `dns_server.c:952` (rsyslog), `dns_server.c:7490` (XFR client),
  `simple_dns.c:3644`. No `SSL_set1_host` / `X509_VERIFY_PARAM_set1_host` /
  `X509_check_host` exists anywhere in the tree.
- Reachability: resolverd's DoT path to every upstream; an on-path attacker
  between resolverd and the upstream resolver.
- Issue: The code calls `SSL_set_tlsext_host_name()`, which only sets the **SNI**
  extension in the ClientHello — it does **not** validate that the presented
  certificate matches the expected hostname. With `SSL_VERIFY_PEER` the chain is
  checked, but **any** CA-valid certificate for **any** name is accepted.
- Impact: An attacker holding any legitimately-issued certificate (trivial via a
  public CA for a domain they control) who is on-path can MITM resolverd's DoT
  sessions — defeating DoT confidentiality and forging responses for unsigned
  zones. (DNSSEC validation mitigates forgery for *signed* zones only;
  confidentiality is lost regardless.)
- Fix: After `SSL_new`, call
  `SSL_set1_host(ssl, expected_hostname)` (and optionally
  `SSL_set_hostflags(…, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)`) so the handshake
  fails on a name mismatch. Apply to resolverd DoT, certd, and the dnsd XFR
  client.
- Tooling: manual + grep (no host-check API present).

### CSA-NET-001 — resolverd does not validate the response transaction ID or question section  [High] [Open]
- Location: `resolverd.c:1995-2120` (`upstream_query_one` / `upstream_query`);
  `build_query` sets `h->id` at `resolverd.c:1576` but nothing ever reads the
  response ID back.
- Reachability: Every UDP/TCP/DoT/DoH answer from an upstream; an off-path
  attacker spoofing the upstream's source address.
- Issue: After `recv()`, the response is returned/cached without checking that
  `id(response) == id(query)` or that the answered question matches the asked
  question (QNAME/QTYPE; also no 0x20 case randomisation). The UDP socket *is*
  `connect()`ed, so the kernel filters on the local ephemeral port + remote
  addr:port — but with the transaction ID unchecked, the only secret an off-path
  spoofer must guess is the source port (16 bits), halving the search space that
  normally also includes the 16-bit ID.
- Impact: Markedly easier off-path cache poisoning, compounded by CSA-RAND-001
  (the source port is drawn from a predictable PRNG). DNSSEC validation limits
  the damage to unsigned zones, which are the majority of the namespace.
- Fix: Reject any response whose header ID ≠ the query ID and whose question
  section does not byte-match (case-insensitively) the query; on mismatch, keep
  reading / time out rather than accepting. Consider 0x20 query-name
  randomisation as defense-in-depth.
- Tooling: manual (grep confirmed no ID comparison exists).

### CSA-RAND-001 — Predictable PRNG for resolver transaction IDs and source ports  [Medium] [Open]
- Location: `resolverd.c:1997` (`id = rand() & 0xFFFF`), `resolverd.c:2036`
  (`sp = 1024 + rand() % 64511`), seeded `srand(time(NULL))` at
  `resolverd.c:3834`. Same pattern: `dns_server.c:8814/8164`,
  `simple_dns.c:4583/3460`.
- Reachability: Off-path spoofer attacking resolverd's cache.
- Issue: `rand()`/`srand(time(NULL))` is a non-cryptographic PRNG seeded from
  wall-clock seconds. Once the seed is guessed (a small range around process
  start) the ID and source-port streams are reconstructable. These two fields
  are the resolver's primary anti-spoofing entropy.
- Impact: Combined with CSA-NET-001, off-path poisoning of unsigned zones
  becomes practical.
- Fix: Use a CSPRNG (`RAND_bytes` — already linked via OpenSSL — or
  `getrandom()`) for transaction IDs and source-port selection. `getrandom` is
  already in the seccomp allowlist.
- Tooling: grep + manual.

### CSA-TIME-001 — DDNS shared secret compared with non-constant-time strcmp  [Medium] [Open]
- Location: `apid.c:1041` (`strcmp(akey, secret)`), mirrored at
  `simple_dns.c:4336`.
- Reachability: Unauthenticated HTTP `/update` request (the `?key=` DDNS path)
  on apid's plain-HTTP listener; gates zone-record writes.
- Issue: `strcmp` short-circuits on the first differing byte, leaking a timing
  oracle on the secret. The secret authorises `zone:*`/`ddns:*` writes.
- Impact: Byte-by-byte recovery of the DDNS secret over the network (harder over
  WAN jitter, but it is an authentication secret and should not be compared in
  variable time), leading to unauthorised dynamic-record injection.
- Fix: Compare with `CRYPTO_memcmp()` over a fixed length after confirming equal
  lengths (or hash both sides and compare digests). Rate-limit failures.
- Tooling: grep + manual.

### CSA-TIME-002 — TSIG MAC verified with non-constant-time memcmp  [Low] [Open]
- Location: `dns_server.c:4238`, `dns_server.c:7445` (XFR), `simple_dns.c:2204`.
- Reachability: Any TSIG-signed request (UPDATE, AXFR/IXFR) from a client that
  knows a key name.
- Issue: `memcmp(mac, t.mac, mlen)` short-circuits; comparing a secret-derived
  HMAC in variable time is a timing side-channel. TSIG also binds a time/fudge
  window, which raises the bar, but constant-time comparison is the standard.
- Impact: Theoretical MAC-forgery assist via timing; low practical risk over a
  network but easy to fix.
- Fix: Use `CRYPTO_memcmp()`.
- Tooling: grep + manual.

### CSA-TIME-003 — DNS cookie compared with non-constant-time memcmp  [Low] [Open]
- Location: `dns_server.c:5024` (`memcmp(expected, ei->server_cookie, …)`).
- Reachability: Any query echoing a server cookie (RFC 7873/9018).
- Issue: Non-constant-time comparison of the server cookie (a keyed anti-spoof
  token).
- Impact: Minor timing leak on the cookie; low impact since cookies are an
  anti-amplification/anti-spoof aid, not a primary auth secret.
- Fix: `CRYPTO_memcmp()`.
- Tooling: grep + manual.

### CSA-TLS-003 — Outbound TLS allows verification-disabled / unpinned modes (rsyslog, XFR)  [Low] [Open]
- Location: `dns_server.c:941` (rsyslog `SSL_VERIFY_NONE` when
  `g_rsyslog_tls_verify` off), `dns_server.c:7300-7308, 7493` (XFR client only
  enables `SSL_VERIFY_PEER` / checks `SSL_get_verify_result` when an XFR CA PEM
  is configured).
- Reachability: Operator-configurable; rsyslog log shipping and secondary→primary
  zone transfer.
- Issue: rsyslog has an explicit no-verify toggle; the XFR client performs no
  cert verification when no CA is pinned. Both also lack hostname verification
  (CSA-TLS-002).
- Impact: Log disclosure / injection (rsyslog) and transfer-channel MITM (XFR).
  Lower than CSA-TLS-001/002 because rsyslog is opt-in and AXFR/IXFR data
  integrity is independently protected by TSIG (recently added).
- Fix: Default rsyslog verify on; for the XFR client, require chain + hostname
  verification (TSIG covers integrity but TLS should still authenticate the
  endpoint). Document the no-verify mode as insecure.
- Tooling: manual.

### CSA-DOS-001 — apid reads the HTTP request with a single recv(); large/slow bodies are truncated  [Low] [Open]
- Location: `apid.c:945-988` (`handle_api`): one `SSL_read`/`recv` of
  `HTTP_BUF-1`, then `blen = n - (bdy - buf)` for the DoH POST body.
- Reachability: Any HTTP(S) client.
- Issue: The request (including a DoH POST DNS message) is not read in a loop to
  the declared `Content-Length`; a body split across TCP segments is silently
  truncated, and there is no header/body size cap or slow-loris timeout shown
  here. No memory-safety bug (the copied length is derived from bytes actually
  read), but a correctness/availability gap.
- Impact: Dropped/garbled DoH queries; potential for slow-client resource
  pinning.
- Fix: Loop until headers are complete, then read exactly `Content-Length`
  bytes (bounded by a max); apply a per-request read deadline.
- Tooling: manual.

### CSA-WIRE-001 — name_to_wire does not reject labels > 63 octets  [Info] [Open]
- Location: `dns_wire.c:185-204` (`name_to_wire`).
- Reachability: Name emission for records sourced from config/zone data.
- Issue: A label longer than 63 bytes is written with a length octet ≥ 0x40,
  whose top bits collide with the compression-pointer marker on re-parse. No
  buffer overflow (the `pos+ll+1 >= blen` check holds), but it can emit a
  malformed name.
- Impact: Correctness/robustness only; not currently a memory-safety issue.
- Fix: Reject (return -1) any label with `ll > 63`.
- Tooling: manual.

### CSA-RAND-002 — Outbound NOTIFY/query IDs use rand()  [Info] [Open]
- Location: `dns_server.c:8164` (`h->id = htons((uint16_t) rand())`).
- Reachability: dnsd's outbound NOTIFY / probe messages to secondaries.
- Issue: Predictable IDs as in CSA-RAND-001, but for the authoritative server's
  outbound notifications, where the recipient authenticates via TSIG/SOA, so the
  ID's unpredictability matters far less.
- Impact: Negligible in current use; flagged for consistency with the CSPRNG fix.
- Fix: Same CSPRNG migration as CSA-RAND-001.
- Tooling: grep.

---

## Notes / non-findings (verified safe)

- **libdnswire parsers** (`name_from_wire`, `b64*_dec`, `txt_encode`,
  `append_rr*`): bounds-checked; compression pointers must target strictly prior
  offsets and a 128-step cap backstops loops; output indices guarded before
  every write.
- **dnsd DNS/EDNS-OPT parser** (`dns_server.c:4793-4889`): every field read is
  guarded by `off+10 <= plen` / `rp+4 <= …`; cookie copies are length-checked.
  The `fudge` constant (`TSIG_FUDGE 300`) and the EDNS DO-bit offset are
  confirmed correct (both were historical bugs).
- **libsandbox** (`sandbox.c`): correct privilege-drop order, irreversibility
  check, `getpwnam` before chroot, `PR_SET_DUMPABLE 0`, seccomp allowlist with
  no `execve`/`ptrace`; mountns/pivot_root fail-closed.
- **Committed key material:** `bootstrap.key`/`.pem`/`.crt`, `*-ca.pem`,
  `chain.p7` exist in the working tree but are **gitignored and untracked**
  (`git ls-files` confirms) — local fixtures, not a repository secret leak.
- **apid RESP/Valkey client** (`apid.c:105-215`): bulk-string reads are capped
  to the destination buffer with the excess drained; no overflow.
- **No** `system`/`popen`/`exec*` usage anywhere; the `strcpy`/`sprintf` hits in
  certd/simple_dns are constant-string assignments (`strcpy(path,"/")` etc.).

## Coverage caveat

This was a focused, high-yield pass over the parsers, crypto, TLS, privilege,
and authentication surfaces plus a pattern sweep across all ~23K lines — not a
line-by-line audit of every function. Areas worth a dedicated follow-up:
resolverd cache concurrency (rwlock/UAF under reload), dnsd dynamic-UPDATE and
AXFR/IXFR memory handling, and the mdnsd multicast parser.

**Done (2026-06-26):** the audit's stated highest-value next step — a libFuzzer
harness over the resolver's *response* parser (not just `name_from_wire`) under
ASan+UBSan, seeded from real upstream replies — is shipped:
`fuzz/fuzz_response.c` (`make fuzz-response`, CI job *Fuzz smoke (resolverd
response parser)*) drives `response_opt_parse`, `response_matches_query`, and
`parse_response_to_entry` by #including resolverd.c. Seed corpus in
`fuzz/corpus_response/` (5 hand-built replies: A, AAAA, NXDOMAIN+SOA, NODATA+SOA,
A+EDNS-cookie); first 60s run (≈7M execs) found no crash/leak. This closes the
Definition-of-Done fuzz requirement for the CSA-NET-001 response-validation
change. Remaining follow-ups above are still open.
