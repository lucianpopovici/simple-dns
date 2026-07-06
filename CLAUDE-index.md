# CLAUDE-*.md index — spec map

Single front page for the spec set. Maps every file to its component, lists each
feature by Add-number and status, and gathers the cross-cutting roadmap and
reference-only RFCs. Keep this in sync when adding or promoting items.

## Status legend

- **Specced** — full spec: exact-location anchors, guardrails, acceptance, tests.
- **Complementary** — lighter spec (anchor + intent), same file.
- **Conditional** — a forward requirement; not actionable against current code.
- **Follow-on** — design-heavy, deliberately deferred behind other Adds.
- **Roadmap** — deferred future work with a stated trigger.
- **Reference** — no code; read-and-track only.
- **Done** — already implemented in the monolith / `dns_client`.

## File map

| File | Component | Covers |
|------|-----------|--------|
| `CLAUDE.md` | (root) | Master instructions *(pre-existing)* |
| `specs/CLAUDE-fixes.md` | dnsd | Code-defect fixes — **done**, archived untracked |
| `specs/CLAUDE-migration.md` | all | Monolith → daemons decomposition checklist *(pre-existing)* |
| `specs/CLAUDE-hidden-master.md` | dnsd | Hidden-master / public-secondary — **done**, archived untracked |
| `specs/CLAUDE-loadbalance.md` | dnsd | A/AAAA rotation + health checks — **done**, archived untracked |
| `specs/CLAUDE-forwarder.md` | dnsd | Out-of-zone forwarding — **done**, archived untracked |
| `specs/CLAUDE-discovery.md` | dnsd | Automatic FQDN registration — **done**, archived untracked |
| `CLAUDE-architecture.md` | all | System-level ADRs (schema, atomicity, data access, keys, HA/DR, embedded store/objectdb) |
| `specs/CLAUDE-rfc-additions.md` | dnsd | Batch 1–2: Adds 1–5 + doc reconciliations — **done**, archived untracked |
| `specs/CLAUDE-rfc-additions-batch3.md` | dnsd (+libdnswire) | Batch 3: Adds 7–10 done (Add 8/9471 done 2026-07-06, alongside eppd's dnsd prerequisites); Add 11 (9824) deliberately deferred as a follow-on — archived untracked |
| `specs/CLAUDE-rfc-additions-batch4.md` | dnsd | Batch 4: Add 12 (2317, Done) + 3258 anycast note (Done) — archived untracked |
| `CLAUDE-ENUM.md` | dnsd | ADR-001, Add 6 (ENUM), bind config, ENUM roadmap |
| `CLAUDE-eppd.md` | eppd | ADR-002, registry back-end (phased) — **Phase 1+2+3 ALL DONE** 2026-07-06 (session shell + domain/host/contact/org check/create/info/update/delete + zone:* publish pipeline incl. DS; registrar ownership + association guards; RFC 9154 secure authInfo; RFC 5910 DS mapping; RFC 5731 transfer+renew; RFC 3915 RGP + background sweep; RFC 5730 poll + RFC 8590 changePoll; RFC 8748 fee (flat informational); RFC 8543 org object; also required three dnsd prerequisites: RFC 9471 referrals + multi-value NS + signed DS-at-cut read path, plus an unrelated pre-existing dnsd RRSIG signer-name bug fixed along the way — see CLAUDE.md's eppd section); only RDAP/escrow/EPP-for-ENUM remain open (not required for a private/internal registry) |
| `specs/CLAUDE-libdnswire.md` | libdnswire | Shared wire codec extraction + conformance — **done** (fuzzer-harness-location cleanup optionally remains), archived untracked |
| `CLAUDE-certd.md` | certd | PKI: ACME/EST extraction (done) + ARI (Add 1, done) + tls-alpn-01/RFC 8738 IP identifiers (Add 2/3, done 2026-07-06, `make check-acme-challenges`); TLSA/CAA integration + STAR roadmap still open |
| `specs/CLAUDE-mdnsd.md` | mdnsd | mDNS/DNS-SD extraction + Discovery Proxy (Add 1) + DSO/Push (Add 2) + SRP (Add 3, registration handler lives in dnsd) — **done**, archived untracked |
| `specs/CLAUDE-resolverd.md` | resolverd | Forwarding/validating cache, Option A — **done** (Add 1 skipped, Adds 2–7 done), archived untracked |
| `specs/CLAUDE-DoQ.md` | doqd | RFC 9250 DNS-over-QUIC sidecar — **done** (Gaps 1–3; Gap 4, resolverd outbound DoQ client, deferred by the plan itself), archived untracked |
| `CLAUDE-rfc-skipped.md` | (triage) | Exclusion record with reasons |
| `CLAUDE-roadmap.md` | all | Execution order (Phase 0 security → 1 ADRs → 2 features) |
| `CLAUDE-index.md` | (this file) | The map |

---

## dnsd — authoritative server

Feature Adds are a single 1–12 sequence **spread across four files** — note Add 6
lives in `CLAUDE-ENUM.md`, not the additions files.

| Add | RFC | Feature | Status | File |
|----:|-----|---------|--------|------|
| 1 | 1794 | Round-robin RRset rotation | **Done** (config:rr_rotate; per-name djb2 counters; emit_addr_rrset + CNAME-hop + wildcard paths; `make check-rr-rotate`) | rfc-additions |
| 2 | 5782 | DNSxL (DNSBL/DNSWL) synthesis | **Done** (dnsxl_try synthesis handler; config:dnsxl_zones; `make check-dnsxl`) | rfc-additions |
| 3 | 9460 | SVCB / HTTPS records (64/65) | **Done** (TLV; dnsd serves; apid writer TODO) | rfc-additions |
| 4 | 9077 | NSEC/NSEC3 + negative-response TTL | **Done** | rfc-additions |
| 5 | 7477 | CSYNC record (62) | **Done** (pipe serial\|flags\|NS,A,AAAA; dnsd serves+AXFR; DNSSEC-signed; `make check-csync`) | rfc-additions |
| 6 | 6116/6117/6118 | ENUM profile over NAPTR | **Done** (config:enum_apex; NAPTR `\|`-in-regexp parser fix; Enumservice warning; `make check-enum`) | ENUM |
| 7 | 8976 | ZONEMD (63) | **Done** (SIMPLE/SHA-384, `zonemd_compute` reuses the AXFR encoders; PR #39, 2026-06-30) | batch3 |
| 8 | 9471 | Glue in referrals | **Done** (dnsd zone-cut/referral engine; done 2026-07-06 as an eppd prerequisite) | batch3 |
| 9 | 1982 | Serial-number arithmetic | **Done** (libdnswire + IXFR uses serial_lt) | batch3 |
| 10 | 9715 | UDP fragmentation avoidance | **Done** | batch3 |
| 11 | 9824 (+4470) | Compact denial of existence | Follow-on | batch3 |
| 12 | 2317 | Classless reverse delegation | **Done** (dnsd already wire-capable — CNAME chain + co-hosted subzone PTR, DNSSEC-signed; `POST /reverse/classless` provisioning in apid; `make check-2317`) | batch4 |

Complementary (batch3) — **all Done, batch 3 fully closed 2026-07-01**:
- **9103 XoT Done** — server-side ALPN was a latent conformance bug
  (`SSL_CTX_set_alpn_protos` is the client-side API and is a silent no-op on a
  server `SSL_CTX`; fixed via `SSL_CTX_set_alpn_select_cb`); `make check-xot`.
- **9859 generalized NOTIFY Done** — `notify_job_t`/`notify_build_packet` carry
  a qtype; `notify_parent()` NOTIFYs a configured
  `config:[zone:<z>:]parent_notify_target` with CDS/CDNSKEY on KSK rollover
  phase transitions; `make check-parent-notify`.
- **9660 ZONEVERSION Done** — EDNS option 19; echoes the answering zone's
  LABELCOUNT + SOA serial, opt-in only, omitted when no zone matched;
  `make check-zoneversion`.
- **9567 error reporting Done** — EDNS0 Report-Channel option 18
  (`config:error_report_agent`), unconditional (not gated on EDE), omitted when
  unset or when the agent would be a subdomain of the answering zone (§4 MUST
  NOT); `make check-error-reporting`.

Deployment note (batch4): **3258 Done** — mostly operational guidance (no
protocol code: zone-data consistency choice, per-node `config:nsid`, keep
AXFR off the anycast service IP), plus the one concrete optional add it names:
CHAOS-class `id.server`/`hostname.bind` (RFC 4892 / BIND convention) so
`dig CH TXT id.server` reveals which anycast node answered, reusing
`config:nsid`; class-gated (an `IN`-class query for the same name is
unaffected); `make check-id-server`.
Doc reconciliations (rfc-additions): 8484 Done, 2671→6891, 3833/7626
coverage matrix, 8499/9499, **NAPTR = 3403** (header mislabels it 9250).

---

## resolverd — forwarding/validating cache (Option A) — **fully closed 2026-07-02**

| Add | RFC | Feature | Status |
|----:|-----|---------|--------|
| 1 | 9156 | QNAME minimisation | **Skipped** 2026-07-01 — inapplicable to a single-hop forwarder (no delegation chain to hide labels from); would require pulling forward Option B's iterative resolver, so deferred rather than forced |
| 2 | 8198 | Aggressive use of DNSSEC-validated cache | **Done** (`make check-aggressive-nsec`) |
| 3 | 8767 + 9520 | Serve-stale + failure caching | **Done** (`make check-serve-stale`) |
| 4 | 5452 | Resilience to forged answers (port + 0x20) | **Done** (port + transaction ID were already CSPRNG from the Phase-0 security pass; 0x20 QNAME case randomization added — `dns0x20_mix`/`dns0x20_active_for` in resolverd, case-sensitive verification via a case-preserving question decode, per-upstream opt-out; `make check-dns0x20`) |
| 5 | 8914 | Extended DNS Errors (generation) | **Done** (`make check-ede`) |
| 6 | 9462 / 9463 | DDR / DNR | **Done** (`make check-ddr`); RFC 9463 DNR explicitly out of scope (host-side, not resolver-side) |
| 7 | 6147 | DNS64 (NAT64 AAAA synthesis) | **Done** (`make check-dns64`; DNSSEC guardrail: synthesis skipped whenever the AAAA NODATA validated SECURE — this also surfaced and fixed a `serve_cached_entry` bug that was losing `dnssec_status` on cache hits) |

Roadmap (Option B — iterative): 8109 priming, 8806 root-on-loopback, full
delegation following, 5011 trust-anchor rollover. Full detail archived at
`specs/CLAUDE-resolverd.md`.

---

## certd — PKI (ACME + EST)

Done: 8555 (ACME DNS-01), 7030 (EST).

| Add | RFC | Feature | Status |
|----:|-----|---------|--------|
| 1 | 9773 | ACME Renewal Information (ARI) | **Done** (`ari_cert_id`/`ari_fetch_window` in certd; falls back to the fixed-threshold check when unavailable; `make check-ari`) |
| 2 | 8737 | ACME TLS-ALPN-01 | Optional |
| 3 | 8738 | ACME for IP identifiers | Optional |

Integration: publish TLSA/DANE (6698/7671) for issued certs; honor CAA (8659).
Roadmap: 8739 (STAR short-term certs).

---

## mdnsd — multicast DNS / DNS-SD

Done: 6762 (mDNS), 6763 (DNS-SD).

| Add | RFC | Feature | Status |
|----:|-----|---------|--------|
| 1 | 8766 | Discovery Proxy (mDNS ↔ unicast DNS-SD) | **Done** 2026-07-02 (`make check-dp`) |
| 2 | 8490 + 8765 | DSO + DNS Push Notifications | **Done** 2026-07-03 (`make check-dso`) |
| 3 | 9665 + 9664 | SRP + UPDATE leases | **Done** 2026-07-03 (`make check-srp`; registration handler lives in dnsd, not mdnsd) |

References: 8882, 7558, 8552/8553.

---

## doqd — DNS-over-QUIC sidecar

| Gap | RFC | Feature | Status |
|----:|-----|---------|--------|
| 1 + 2 | 9250 | `doqd` binary + QUIC↔loopback bridge (relays framed messages to dnsd's loopback DNS port, same pattern as apid's DoH) | **Done** (`make check-doq`; framing parser fuzzed via `make fuzz-doq`) |
| 3 | 9250 | `_853._udp` TLSA on dnsd's side (cert_publish_tlsa sibling to DoT's `_853._tcp`) | **Done** |
| 4 | 9250 | resolverd outbound DoQ client | Roadmap (ship when an actual DoQ upstream is needed) |

Needs OpenSSL ≥ 3.5 for the server-side QUIC API (`SSL_new_listener` /
`SSL_accept_connection` / `SSL_accept_stream`) — isolated to this one binary
via the `doqd-ossl-sanity` Makefile gate; the rest of the fleet stays on the
3.0+ floor.

---

## eppd — registry back-end (phased)

| Phase | RFCs | Status |
|-------|------|--------|
| 1 (core) | 5730, 5734, 5731, 5732, 5733 | Specced |
| 2 (security + lifecycle) | 9154, 3915, 5910 | Specced |
| 3 (extensions) | 8748, 8543, 8590 | Specced |
| Companion | 9082/9083 (RDAP), 8909/9022 (escrow) | Conditional (public TLD) |
| ENUM | 4114, 5076 | Roadmap |

---

## libdnswire — shared codec

Owns (identical for all daemons): 1035, 3597, 4034, 6891, 4343, 2181, **1982**
(moved from dnsd Add 9). Conformance tests: 9267, 8906. Critical contract: the
canonical-form (4034 §6) code is shared so `dnsd` signing and `resolverd`
validation never diverge.

---

## Cross-cutting roadmap

| Item | RFCs | Where |
|------|------|-------|
| ENUM number portability | 4769 | ENUM |
| ENUM EPP federation | 4114, 5076 | ENUM / eppd |
| resolverd iterative (Option B) | 8109, 8806, 5011 | resolverd |
| resolverd outbound DoQ client | 9250 | resolverd / doqd |
| certd STAR certs | 8739 | certd |
| dnsd compact denial | 9824, 4470 | batch3 (follow-on) |
| eppd public-registry obligations | 9082/9083, 8909/9022 | eppd |
| Parked dnsd candidates | 9432, 9276, 8020, 7766, 9250, 7314 | skipped (borderline) |

## Reference-only (no code)

9199, 9210, 8624, 6781, 7583, 9905, 9906, 9499, 9076, 3833, 7626, 8499, 1912,
2182, 1536, 3425, 7129, 8552, 8553, 8882, 7558, 6471, 9267, 8906. Full skip
rationale: `CLAUDE-rfc-skipped.md`.

---

## Suggested build order

1. **libdnswire** — unblocks the rest; lock the sign/validate canonical-form gate.
2. **certd** — smallest, mostly extraction; add ARI.
3. **mdnsd** / **resolverd** — extract, then Option A / Discovery Proxy.
4. **dnsd** batches — ongoing on the monolith; correctness items (9077, 1982,
   9715) first, features (9460, 8976) next.
5. **eppd** — separate program; gate on the public-vs-private decision.

## Conventions

- "Add N" numbering is **per component**, except dnsd's single 1–12 sequence
  that spans the four dnsd files (Add 6 = ENUM, in `CLAUDE-ENUM.md`).
- Every specced entry carries: exact-location anchor, `do NOT` guardrails,
  acceptance criteria, shell test.
- Promoting an item from `CLAUDE-rfc-skipped.md` updates both that file and this
  index.
