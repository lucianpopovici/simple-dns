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

In-flight on their own track (do not re-sequence) — feature plans landed (PRs
#7–#19); **corrected 2026-07-01: all three were already complete, this section
was stale.** `CLAUDE-hidden-master.md` says outright "All hidden-master gaps
(1–8) are complete," including the master-side NOTIFY-sender TSIG hardening
this file used to list as a tail (independently reconfirmed this session via
`make check-notify`: TSIG-signed, retried until ACK). `CLAUDE-loadbalance.md`
marks Gap 2 (health checks) done. `CLAUDE-discovery.md` says gaps 1–4 done,
nothing outstanding. Nothing left on this track.
- Remaining, not stale: the `resolverd` seccomp `audit`→`enforce` flip after
  whitelist harvest (not a spec file; tracked in `CLAUDE.md`) — already
  `enforce` by default per `CLAUDE.md`, re-harvest only needed when porting to
  a different libc/kernel.

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
     **9077 DONE 2026-06-26** — added a real per-zone SOA-record TTL
     (`config:soa_ttl`, `config:zone:<z>:soa_ttl`, optional `zone_table` trailing
     field); the SOA RR is served at that TTL while negative-response NSEC/NSEC3
     + authority SOA are capped at `min(soa_ttl, soa_minimum)` per RFC 9077.
     `make check-negttl` (both min() arms) in CI. **Phase 2.2 correctness done
     (9715 + 1982 + 9077).**
   - Feature record types: **9460 (SVCB/HTTPS) DONE 2026-06-26** — types 64/65
     on TLV per ADR-003 (`svcb_present_to_tlv` + `svcb_tlv_to_wire` in
     libdnswire; keys mandatory/alpn/no-default-alpn/port/ipv4hint/ech/ipv6hint).
     dnsd serves over query + AXFR, DNSSEC-signed; `make check-svcb` (codec KAT +
     dig integration) in CI. **Follow-up:** apid/dashboard presentation→TLV
     writer (operators currently store the hex TLV directly; the encoder is
     shared in libdnswire ready to adopt). Generic `keyNNNNN` SvcParams deferred.
   - **7477 CSYNC DONE 2026-07-01** — type 62, `csync_encode_rdata` in libdnswire;
     stored as `serial|flags|NS,A,AAAA`; dnsd serves+AXFR, DNSSEC-signed;
     `make check-csync` (6 KATs + dig integration). In CI.
   - **5782 DNSxL DONE 2026-07-01** — `dnsxl_try` synthesis handler in dnsd;
     `config:dnsxl_zones` (comma-separated suffixes); per-IP in Valkey as
     `dnsxl:<zone>:<ip>` → `low_octet|reason`; listed→A 127.0.0.x + TXT,
     unlisted→NXDOMAIN; RFC 5782 §5 mandatory test points in `make check-dnsxl`. In CI.
   - **1794 RR rotation DONE 2026-07-01** — `config:rr_rotate`; per-name djb2
     counter array `g_rr_rot[1024]` mutex-guarded; `rr_rotate_offset()` in dnsd;
     applied at all three A/AAAA emit paths via `emit_addr_rrset()` (main zone +
     CNAME-chain hop now refactored to call `emit_addr_rrset`, wildcard Valkey
     path likewise); lb_mode takes precedence when set; `make check-rr-rotate`
     (3 distinct first-addrs in 6 queries + RRSIGs intact + disabled is stable).
   - **6116/6117/6118 ENUM DONE 2026-07-01** — `config:enum_apex` (tree root);
     NAPTR `|`-in-regexp parser fix (split at LAST `|` after first 4 fields so
     ENUM regexps with alternation survive round-trip); Enumservice warning when
     service field is not `E2U+...`; RFC 6116/6117/6118 in header comment +
     mislabelled "9250" corrected to "3403"; `make check-enum` in CI.
   - **2317 classless reverse delegation DONE 2026-07-01** — `dnsd` was already
     wire-capable (CNAME chain in the `/24` + PTR in a co-hosted classless
     subzone, both DNSSEC-signed) so no `dns_server.c` change was needed; added
     `POST /reverse/classless` (mgmt-only) to `apid` to provision a CIDR
     (`/25`-`/31`) as a `/24`-zone CNAME per address plus either a co-hosted
     subzone in `zone_table` or an NS delegation; `make check-2317` drives the
     wire path directly against Valkey (CNAME→subzone PTR, RRSIG present). In CI.
   - **9660 ZONEVERSION DONE 2026-07-01** — EDNS option 19 (`EDNS_OPT_ZONEVERSION`
     in libdnswire): `edns_parse` records a bare-length-0 request, `dnsd_edns_opt`
     sources LABELCOUNT (label count of `t_zone->name`) + the zone's SOA serial
     from `t_zone`, `edns_append_opt` gains `zv_labels`/`zv_serial` params and
     emits TYPE=0 (SOA-SERIAL) only when both the client asked and a zone
     actually matched (`zv_labels >= 0` — never echoed on REFUSED/no-zone-match);
     `make check-zoneversion` decodes the wire OPT bytes via `dig +ednsopt=19`
     and checks LABELCOUNT/TYPE/serial plus the opt-in-only and
     not-authoritative-omits-it cases. In CI.
   - **9103 XoT DONE 2026-07-01** — while verifying ALPN negotiation for the
     conformance pass, found the DoT/XoT listener was never actually
     *selecting* "dot": the old code called `SSL_CTX_set_alpn_protos` on the
     server `SSL_CTX`, which is the client-side API and a silent no-op for a
     server (confirmed empirically with `openssl s_client -alpn dot` — "No
     ALPN negotiated" despite the code and its comment claiming otherwise).
     Fixed with `SSL_CTX_set_alpn_select_cb` (`dot_alpn_select_cb`, using
     `SSL_select_next_proto`), which shares the port with plain DoT queries.
     Per-message EDNS padding (the batch3 doc's other conformance target) was
     deliberately **not** added: RFC 9103 §7.9.1 states padding
     recommendations are out of scope of the RFC itself (not a MUST), and this
     codebase's AXFR/IXFR path streams one RR per DNS message, so padding
     every message would be a large invasive change for a non-required nicety
     — a conscious scope decision, not an oversight. `make check-xot` (needs
     openssl s_client) confirms "dot" is selected when offered, an unrelated
     protocol is correctly left unselected (not a handshake failure), and an
     ordinary DoT query still works. In CI.
   - **9859 generalized NOTIFY DONE 2026-07-01** — `notify_job_t` gained a
     `qtype` field (part of the job's dedup identity, so a pending SOA notify
     and a pending CDS notify to the same target never coalesce);
     `notify_build_packet`/`notify_enqueue`/`notify_zone_type` thread it
     through; `notify_parent()` (new) NOTIFYs
     `config:[zone:<z>:]parent_notify_target` with CDS then CDNSKEY — hooked
     into `ksk_rollover_start` and `ksk_rollover_to_retire` (the two KSK
     rollover phase transitions where the advertised CDS/CDNSKEY RRset
     actually changes; `ksk_rollover_finish` doesn't change the advertised
     set, so it deliberately does not fire one). CSYNC-triggered parent
     NOTIFY was considered but not implemented: CSYNC records are written
     directly by the control plane (apid/dashboard) via the ordinary
     `zone:*` namespace, which dnsd only subscribes to for record-cache
     invalidation and only when the record cache is enabled — not a reliable
     trigger to hang a parent-NOTIFY on, so this stays a control-plane
     concern rather than a dnsd one. `make check-parent-notify` (Python stub
     parent listener) confirms NOTIFY(CDS)+NOTIFY(CDNSKEY) fire on a KSK
     rollover start. In CI.
   - **9567 error reporting DONE 2026-07-01** — EDNS0 Report-Channel option
     (`EDNS_OPT_REPORT_CHANNEL` = 18) carrying `config:error_report_agent` in
     uncompressed wire format; unconditional (unlike EDE, not gated on an
     error code in *this* response — the resolver may only discover the
     error later, from its own cache); the RFC 9567 §4 MUST NOT (agent must
     not be a subdomain of the zone it reports on) is enforced per-response
     against `t_zone`, failing closed (option omitted) rather than just
     logged. `make check-error-reporting` checks the option appears with the
     configured domain, is omitted when unset, and is omitted for a
     subdomain-of-zone agent. In CI.
   - **Batch 3 is now fully closed** — every item in
     `CLAUDE-rfc-additions-batch3.md` is Done.
   - **3258 anycast deployment note DONE 2026-07-01** (batch4) — mostly
     operational guidance, not a wire feature: run N identical `dnsd` nodes on
     a shared service IP, keep their zone data at the same serial (shared or
     replicated Valkey, or per-node Valkey kept in sync via the existing
     AXFR/IXFR+NOTIFY path — pick one and hold nodes at the same serial), set a
     distinct `config:nsid` per node, and keep AXFR/IXFR on each node's
     *unicast* management address rather than the anycast service IP (a
     re-route mid-transfer must not sever it). The one concrete optional code
     add the note names — CHAOS-class `id.server`/`hostname.bind` (RFC 4892 /
     the BIND convention) — is implemented: `qclass`/`qtype` gate a new
     early-return branch in `build_query_resp` (ahead of the zone-authority
     check, since these names aren't part of any zone) that answers `CH TXT`
     with `config:nsid` (already discloses the same identity over EDNS NSID,
     so no new config knob). An `IN`-class query for the same literal name
     (`id.server A`) is unaffected — the branch is class-gated, not
     name-gated. `make check-id-server` covers both names, the IN-class
     non-interception case, and that ordinary queries still work. In CI.
   - This closes out both RFC-addition batches (3 and 4) entirely; remaining
     spec work is items 3–6 below plus the in-flight-plan tails in
     `CLAUDE.md`.
3. **certd ARI DONE 2026-07-01** (`CLAUDE-certd.md` Add 1, RFC 9773) — the CA
   now drives renewal timing instead of a fixed threshold. `ari_cert_id`
   computes the RFC 9773 §4.1 CertID (base64url AKI keyIdentifier + "." +
   base64url serial value bytes, both unpadded) from the active cert;
   `acme_needs_renewal` refreshes the ACME directory (populating
   `g_acme_dir_renewalinfo` even on a freshly started certd that has never
   run `acme_issue`) and, when the CA offers `renewalInfo`, fetches the
   suggested window via `ari_fetch_window` (unauthenticated GET, RFC 3339
   `start`/`end` parsed with `timegm` since the window is always UTC) and
   renews at a randomized point inside it — never exactly at window start,
   per the §4.1 anti-thundering-herd guardrail. Falls back to the existing
   fixed-threshold check whenever ARI is absent, unreachable, or malformed;
   ARI availability never blocks renewal. `make check-ari` spins up a local
   CA + a minimal Python HTTPS stub (ACME directory + `/renewal-info` only —
   full issuance still needs a real/staging CA per this file's own test
   section) and confirms a future window suppresses renewal while a past
   window triggers it, via the ARI decision log line. In CI.
4. **mdnsd Discovery Proxy** (`CLAUDE-mdnsd.md`, RFC 8766) and **resolverd
   Option A** (`CLAUDE-resolverd.md` / `-1.md`: 9156 QNAME-min, 8198 aggressive
   NSEC, 8767+9520 serve-stale, 5452 anti-spoof, 8914 EDE, 9462/9463 DDR/DNR,
   6147 DNS64).
   - **5452 anti-spoof DONE 2026-07-01** — coordinated with the Phase-0
     resolver anti-spoofing work as planned: transaction ID (CSPRNG) and
     per-query source port randomization were already in place from that
     pass, so this added the missing third leg, 0x20 QNAME case
     randomization. `dns0x20_mix` lowercases then flips a random subset of
     letters to uppercase (fresh `RAND_bytes` per query — replaying an old
     pattern doesn't help a forger); `dns0x20_active_for` gates it globally
     (`DNS0X20_ENABLED`, default on) with a per-upstream opt-out
     (`DNS0X20_DISABLE`, comma-separated hostnames) per the RFC's own
     guardrail for upstreams that break on it. The verification side needed
     a new `qname_from_wire_case_preserving` in resolverd.c specifically:
     libdnswire's shared `name_from_wire` always lowercases (correct for
     cache keys/comparisons everywhere else), which would silently defeat
     0x20 if reused for the case check, so `response_matches_query` gained
     an `enforce_case` path using the case-preserving decode instead — any
     mismatch is treated as a forged/stray packet and dropped, same as an
     ID or QNAME-content mismatch. `make check-dns0x20` (a Python stub
     upstream with "echo" vs "corrupt" modes) confirms the case pattern
     varies across queries, a case-mismatched reply is rejected by default,
     and both `DNS0X20_ENABLED=0` and the per-upstream opt-out correctly
     restore acceptance. In CI. The other six resolverd items and the mdnsd
     Discovery Proxy remain.
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
