# CLAUDE-roadmap.md — execution order for the spec set

The migration (`specs/CLAUDE-migration.md`) is complete: the monolith is fully
decomposed into `dnsd` / `resolverd` / `apid` / `certd` / `mdnsd` +
`libdnswire` / `libsandbox`. What remains is a backlog of **security fixes**,
**architecture decisions**, and **feature specs** spread across the
`CLAUDE-*.md` files and `SECURITY_AUDIT.md`. This file is the single ordering
for that backlog. `CLAUDE-index.md` maps *what* each spec is; this file says
*when* to do it and *why that order*.

Keep both in sync: when an item lands, tick it here and update its status in
`CLAUDE-index.md`.

## How to read this

The backlog files are not all the same kind of work. Sort before sequencing:

| Kind | Files | Where it goes |
|------|-------|---------------|
| **Live code vulnerabilities** | `SECURITY_AUDIT.md` | Phase 0 — first |
| **System decisions (no/low code)** | `CLAUDE-architecture.md` (ADR-003…007) | Phase 1 — before new record types |
| **Feature specs** | `CLAUDE-rfc-additions*.md`, `CLAUDE-ENUM.md`, `CLAUDE-libdnswire.md`, `CLAUDE-certd.md`, `CLAUDE-mdnsd.md`, `CLAUDE-resolverd*.md`, `CLAUDE-DoQ.md`, `CLAUDE-eppd.md` | Phase 2 |
| **In-flight feature plans** | `CLAUDE-discovery.md`, `CLAUDE-hidden-master.md`, `CLAUDE-loadbalance.md` | Own track — see below |
| **Skill edits (not codebase)** | `c-security-audit-improvements.md`, `c-security-audit.patch.md` | Out-of-band — Settings → Capabilities |
| **Research playbook (not code)** | `CLAUDE-sec.md` | Background, parallel |
| **Triage / exclusion record** | `CLAUDE-rfc-skipped.md` | Read-and-track only (no code) |
| **The maps** | `CLAUDE-index.md`, `CLAUDE.md` (master), `README.md` | Keep in sync as items land |
| **Decision tracker** | `CLAUDE-roadmap.md` (this file) | — |

In-flight on their own track (do not re-sequence) — feature plans largely landed
(PRs #7–#19), only the tails remain:
- `CLAUDE-hidden-master.md` — NOTIFY-sender TSIG.
- `CLAUDE-loadbalance.md` — LB health checks.
- `CLAUDE-discovery.md` — gaps 1–4 done; nothing outstanding.
- Plus the `resolverd` seccomp `audit`→`enforce` flip after whitelist harvest
  (not a spec file; tracked in `CLAUDE.md`).

---

## Phase 0 — Security audit fixes (do first)

`SECURITY_AUDIT.md` documents live vulnerabilities in already-shipped code.
Small, no design needed, highest priority. Every item here touches DNS wire /
TLS / crypto / resolver anti-spoofing paths, so the **security-sensitive change
gate** applies (second reviewer + hostile-input test evidence in the PR), and
the parser/crypto changes pull in the relevant `make check-*` + fuzz corpus
entry per the Definition of Done.

Order:

1. **CSA-TLS-001** — certd performs no TLS server-cert verification on the
   system-trust path. *High.* MITM CA impersonation → forged certs land in
   `cert:current` and are served by dnsd/apid. Move `SSL_CTX_set_verify(…,
   SSL_VERIFY_PEER, …)` out of the `if (ca_pem)` branch; fail closed.
2. **CSA-TLS-002** — no TLS hostname verification on any outbound connection
   (resolverd DoT, certd, dnsd XFR client, rsyslog). *High.* `SSL_set1_host()` /
   `X509_VERIFY_PARAM_set1_host()` after `SSL_new`. (`SSL_set_tlsext_host_name`
   is SNI only — it does not verify.)
3. **CSA-NET-001 + CSA-RAND-001** — fix together. resolverd never checks the
   response transaction ID or question section (*High*), and draws IDs/source
   ports from `rand()`/`srand(time())` (*Medium*). Together they make off-path
   cache poisoning of unsigned zones practical. Reject any response whose
   header ID ≠ query ID or whose question doesn't case-insensitively match;
   switch IDs + source ports to a CSPRNG (`RAND_bytes`/`getrandom` — already in
   the seccomp allowlist). Consider 0x20 case randomisation as defense-in-depth.
4. **Constant-time comparisons** — `CRYPTO_memcmp` for the DDNS secret
   (CSA-TIME-001, *Medium*), TSIG MAC (CSA-TIME-002, *Low*), DNS cookie
   (CSA-TIME-003, *Low*).
5. **Remaining Low/Info** — apid HTTP read-to-Content-Length loop + slow-loris
   deadline (CSA-DOS-001), `name_to_wire` reject labels > 63 (CSA-WIRE-001),
   NOTIFY/outbound IDs to CSPRNG (CSA-RAND-002), default rsyslog verify on +
   XFR-client chain/host verify (CSA-TLS-003).
6. **libFuzzer harness over resolverd's *response* parser** under ASan+UBSan,
   seeded from real upstream replies. This is the audit's stated highest-value
   next step and the DoD fuzz requirement for the Phase-0 parser changes.
   **DONE** (PR #31): `fuzz/fuzz_response.c` / `make fuzz-response` over
   `response_opt_parse` / `response_matches_query` / `parse_response_to_entry`,
   CI job + seed corpus. **Phase 0 complete.**

> Coverage caveat from the audit: resolverd cache concurrency (rwlock/UAF under
> reload), dnsd dynamic-UPDATE + AXFR/IXFR memory handling, and the mdnsd
> multicast parser were **not** line-by-line reviewed. Fold a dedicated pass on
> these into Phase 2 when the owning daemon's feature work comes up.

**Decision (sequencing):** finish the in-flight branch (ddns-expiry-sweeper,
merged as PR #19), then start Phase 0 before any new feature spec.

---

## Phase 1 — Architecture decision: ADR-003 / ADR-004

`CLAUDE-architecture.md` ADR-003 (Valkey schema as a versioned inter-daemon
contract) and ADR-004 (atomicity / snapshot) are marked "blocking for
decomposition." The split is already done, so they are now a **retrofit
decision** — but they must be settled **before** Phase 2 adds new record types.
The feature specs ahead (SVCB SvcParams, ENUM rules, ZONEMD, EPP objects) are
exactly the "complex, extensible values that strain a flat `|` delimiter" that
ADR-003 calls out. Decide now so those records land on a versioned/structured
format instead of more unversioned pipe-delimited values you'd later migrate.

**Decision:** decide ADR-003/004 before new record types (recommended option
C — hybrid: keep pipe for simple stable scalars, structured encoding for
complex/extensible values; add a `schema:version` key + an in-repo format
registry). This is mostly a decision + a registry doc, not much code.
ADR-005/006/007 (data access/cache, key custody, HA/DR): skim and defer; revisit
when their trigger arrives.

**DONE (2026-06-26):**
- **ADR-003 — Accepted (option C), implemented.** `schema:version` key (1.0) +
  `schema_version_check()` startup gate in all five daemons (dnsd seeds; major
  mismatch fatal, minor warns); length-prefixed **TLV codec** (`tlv_*` in
  `libdnswire`) as the structured encoding (unit-tested via `make check-wire`,
  fuzzed via `make fuzz-tlv`); **format registry** added to `CLAUDE.md`. New
  Phase-2 complex record types must land on TLV, not pipe.
- **ADR-004 — Accepted (decision only): A (MULTI/EXEC writes) + C
  (journal-anchored AXFR snapshot) + SCAN-not-KEYS.** Implementation is a
  **separate follow-up PR** (security-sensitive zone-write/AXFR path; independent
  of the encoding foundation). It does **not** gate Phase 2 record formats —
  ADR-003 does — so Phase 2 is unblocked now.

---

## Phase 2 — Feature specs

Per `CLAUDE-index.md`'s build order, with correctness ahead of new features. New
record formats here use the Phase-1 schema decision.

1. **libdnswire conformance** (`CLAUDE-libdnswire.md`) — lock the shared
   sign/validate canonical-form gate; move RFC 1982 serial arithmetic here
   (dnsd Add 9). Unblocks everything downstream.
   **Canonical-form gate CLOSED (2026-06-26):** `canon_rdata`/`canon_rr_cmp`
   are single-source in `dns_wire.c`; dnsd's `make_rrsig` no longer copies rdata
   verbatim but canonicalizes through the shared codec (fixed a latent
   mixed-case name-bearing-rdata BOGUS bug across the dnsd↔resolverd boundary).
   Interop KAT + negative added to `make check-dnssec` (`run_canon_mx`, alg
   13 + 15). 9267/8906 conformance now gated in CI (`make check-conformance` in
   the unit-tests step). Remaining libdnswire tail (low value, deferred): move
   the `name_from_wire` fuzz harness into the lib test tree.
2. **dnsd — correctness first, then features**
   (`CLAUDE-rfc-additions*.md`, `CLAUDE-ENUM.md`):
   - Correctness of existing behavior: 9077 (NSEC/NSEC3 negative-TTL), 1982
     (serial arithmetic, via libdnswire), ~~9715 (UDP fragmentation
     avoidance)~~ **DONE 2026-06-26** — effective UDP size capped at 1232 +
     TC fallback (`make check-frag`, in CI). **1982 DONE 2026-06-26** — the IXFR
     ordering compare now uses `serial_lt` (was a raw `<` that mis-decides across
     the 2^32 wrap → needless AXFR); `make check-ixfr-wrap` guards it (in CI).
     Next correctness item: **9077** (NSEC/NSEC3 negative-TTL — note dnsd already
     caps denial RRs at `soa_minimum`; mostly a verifying-test + confirming the
     min(MINIMUM, SOA-TTL) rule).
   - Then new record types/features: 9460 (SVCB/HTTPS), 8976 (ZONEMD), 7477
     (CSYNC), 5782 (DNSxL), 1794 (RR rotation), 6116/6117/6118 (ENUM over
     NAPTR), 2317 (classless reverse delegation), and the batch-3 complementary
     items.
3. **certd ARI** (`CLAUDE-certd.md`, RFC 9773) — small. Note Phase 0 already
   touched this file (CSA-TLS-001).
4. **mdnsd Discovery Proxy** (`CLAUDE-mdnsd.md`, RFC 8766) and **resolverd
   Option A** (`CLAUDE-resolverd.md` / `-1.md`: 9156 QNAME-min, 8198 aggressive
   NSEC, 8767+9520 serve-stale, 5452 anti-spoof, 8914 EDE, 9462/9463 DDR/DNR,
   6147 DNS64). Coordinate 5452 with the Phase-0 resolver anti-spoofing work so
   they don't collide.
5. **DoQ** (`CLAUDE-DoQ.md`) — new transport, larger effort.
6. **eppd** (`CLAUDE-eppd.md`) — separate program. Gate on the
   public-vs-private-registry decision before starting phase 1 (core EPP).

---

## Out-of-band (not part of the sequence)

- **Skill edits:** apply `c-security-audit-improvements.md` and
  `c-security-audit.patch.md` to the `c-security-audit` skill via Settings →
  Capabilities (the skill can't be edited from a session). Anytime.
- **Research:** `CLAUDE-sec.md` is a DNS-security literature-review playbook;
  run it in parallel, it gates nothing. Outputs land under `research/`.

---

## Definition of Done (applies to every Phase 0/2 item)

From `CLAUDE.md`:
- Tests added/updated (unit + fuzz-corpus entry for any parser change).
- `make debug` (ASan/UBSan) and `make` build clean with `-Werror`.
- The relevant `make check-*` runs and its output is shown, not asserted.
- Docs in sync: RFC-coverage list, Valkey schema, `CLAUDE.md` ownership table,
  `CLAUDE-index.md` status, and this file.
- Security-sensitive gate satisfied where applicable (all of Phase 0; any
  wire/crypto/TLS/sandbox/Valkey-boundary change in Phase 2).
