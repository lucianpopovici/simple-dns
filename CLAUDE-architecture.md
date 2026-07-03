# CLAUDE-architecture.md — system-level decisions

The other spec files are protocol/feature-shaped. This one captures the
**system** properties that decide whether the decomposed design runs in
production. These are decisions for the repo owner; each ADR is **Proposed**
with a recommended option and trade-offs, not a fait accompli.

Two of them (ADR-003 schema contract, ADR-004 atomicity) should be settled
**before** the monolith is split, because the split makes the Valkey schema a
real cross-process API and turns torn-read bugs into multi-writer bugs.

## How these interlock

```
ADR-003 schema contract ──┐
                          ├─> ADR-004 atomicity / snapshot ──> ADR-005 data access / cache
ADR-006 key custody ──────┘                                         │
        │                                                           v
        └──────────────> ADR-007 HA / persistence / DR <────────────┘
                 (in-process cache doubles as Valkey-outage survival;
                  key backup must be encrypted; snapshots need durability)

ADR-008 embedded store (objectdb) ──> candidate *implementation* of ADR-005's
                 in-process cache and ADR-007's degraded mode; never replaces
                 the Valkey bus (ADR-003 contract stays authoritative)
```

---

# ADR-003: Valkey schema is a versioned inter-daemon contract

**Status:** **Accepted (2026-06-26)** — option **C** (hybrid). Implemented in
Phase 1: a compiled `SCHEMA_VERSION` (1.0) + a `schema:version` Valkey key with a
startup gate in every daemon (`schema_version_check()` in `libdnswire`; dnsd
seeds, all daemons fail closed on a major mismatch / warn on minor), the
length-prefixed **TLV codec** (`tlv_*` in `dns_wire.{c,h}`) as the structured
encoding for complex values, and the **format registry** in `CLAUDE.md`. Simple
stable scalars keep the pipe format. See the registry for the per-namespace
encoding and the compatibility rule.

## Context

The decomposition's true API is **not** `libdnswire` — it is the Valkey
key/value formats. `certd` writes `zone:TXT:_acme-challenge…` and `tls:cert`;
`eppd` writes `zone:NS/DS/…`; `dnsd` reads them; `resolverd` shares `cache:`.
Today these are pipe-delimited strings across many namespaces (`config:`,
`zone:`, `zone_table:`, `ddns:`, `dnssec:`, `ixfr:journal`, `stale:`, `cache:`,
`domain_route:`, `tls:`, `epp:`) with **no version and no compatibility
discipline**. The `|`-delimiter fragility already bit us (NAPTR/ENUM regexp).
Once daemons ship independently, a single format change silently breaks the bus.

## Decision

Treat the schema as a versioned contract:

1. A `schema:version` key (major.minor). Every daemon checks it on startup and
   refuses (or warns + read-only) on a major mismatch.
2. A documented **format registry** in-repo (every key namespace, its value
   grammar, its owning daemon).
3. Compatibility rule: additive (new optional trailing fields) within a major;
   readers tolerate unknown trailing fields; any breaking change bumps major and
   ships a migration.

## Options

- **A — keep pipe-delimited, version + document, forbid `|` in fields.**
  Cheap; preserves current parsers; but extensible records (NAPTR, SVCB
  SvcParams, ENUM rules, EPP objects) keep straining a flat delimiter.
- **B — structured encoding (JSON or length-prefixed TLV) for all values.**
  Robust and self-describing; a migration and added C parsing cost everywhere.
- **C — hybrid (recommended).** Keep pipe for simple, stable scalars
  (`config:*`, `ddns:A`); use a structured encoding for complex/extensible
  values (NAPTR, SVCB, ENUM, ZONEMD, EPP). Versioned + registered either way.

## Recommendation

**C** + the version key + the format registry. The simple formats are fine and
fast; the complex ones are exactly where the delimiter breaks and where new
fields keep arriving.

## Consequences

- The `|`-guardrail from earlier specs becomes a formal rule, not a per-RFC note.
- Startup gains a schema-version gate; mixed-version fleets degrade predictably.
- The format registry is a maintained artifact (a natural section of `CLAUDE.md`).

---

# ADR-004: Zone-change atomicity and AXFR snapshot consistency

**Status:** **Accepted (2026-06-26, decision only)** — direction chosen: **A**
(wrap record writes + `serial_bump` in `MULTI`/`EXEC`) for write atomicity, **C**
(journal-anchored snapshot, reusing the existing per-zone IXFR journal) for AXFR
consistency, and replace `KEYS` with `SCAN`. **Implementation is a follow-up PR**
— it touches the security-sensitive zone-write / AXFR path and is independent of
the Phase-1 schema/encoding foundation, so it is sequenced separately rather than
bundled here.

## Context

A zone change is currently `vk_set(key,…)` followed by a **separate**
`serial_bump()` — no transaction. A multi-record update is several independent
`vk_set` calls plus a bump. Two correctness problems:

1. A reader on the `select()` loop can observe a torn zone (some records new,
   some old, serial not matching the data).
2. **AXFR** reads records key-by-key from Valkey; RFC 5936 requires a transfer
   to be a **consistent snapshot at one serial**. A concurrent UPDATE during an
   AXFR violates that.

`zones_load_from_valkey` also uses blocking `KEYS zone_table:*` (the dashboard
uses `SCAN`); on a shared/large Valkey, `KEYS` stalls the server.

## Decision

Make zone writes atomic, and serve AXFR/IXFR from a pinned, consistent snapshot.

## Options

- **A — `MULTI`/`EXEC` around record writes + `serial_bump`.** Cheap, immediate
  win for *write* atomicity. Does not by itself give a *reader* a consistent
  multi-key view.
- **B — versioned / copy-on-write zone.** Write a new version under
  `zone:v<serial>:…`, flip a pointer atomically; AXFR reads a pinned version;
  GC old versions. Clean snapshot semantics; more storage + GC complexity.
- **C — journal-anchored snapshot.** You already keep an IXFR journal; serve a
  transfer as "base snapshot at serial S + replay journal." Reuses existing
  infra; bounded by journal retention.
- **D — per-zone RW lock.** AXFR takes a read view; coarse, stalls writes during
  large transfers — avoid.

## Recommendation

Do **A now** (wrap writes + bump in `MULTI`/`EXEC`) for immediate write
atomicity, and adopt **B or C** for AXFR snapshots — **B** if you want clean
general snapshot reads (also helps the cache in ADR-005), **C** if you prefer to
lean on the journal you already have. Replace `KEYS` with `SCAN` regardless.

## Consequences

- `serial_bump` moves inside the write transaction (serial and data never
  diverge).
- AXFR threads pin a serial; this interacts with ADR-005 (an in-process zone
  snapshot is the natural place to pin) and ADR-007 (snapshot durability).

---

# ADR-005: Data-access and caching model (the QPS path)

**Status:** Proposed

## Context

The known ceiling (~3k–8k QPS authoritative UDP) is: single-threaded `select()`
+ **per-query synchronous Valkey GET** (README: "zone records are read every
request") under one global `g_vk_mutex`. Knowing the bottleneck is not the same
as deciding the data-access model — which is currently "hit Valkey on every
query, serialized by one mutex."

## Decision

Choose how `dnsd` accesses zone data on the query hot path.

## Options

- **A — status quo.** Per-query sync GET under the global mutex. Simple, always
  fresh; caps QPS and puts Valkey RTT + mutex contention in every answer.
- **B — in-process read-through cache + invalidation (recommended core).**
  Cache zone data in `dnsd`; invalidate on change via Valkey keyspace
  notifications / pub-sub on `serial_bump`. Large QPS win; introduces
  cache-invalidation correctness (ties to ADR-004) and a bounded staleness
  window.
- **C — async / pipelined Valkey.** Remove the blocking GET from the event loop;
  keeps Valkey in the path. Bigger rewrite; already on the perf roadmap.
- **D — `SO_REUSEPORT` multi-process workers.** N processes, kernel
  load-balances UDP; scales the `select()`/mutex bottleneck horizontally on one
  host. Each worker still needs A/B/C for data.

## Recommendation

**B + D**: an in-process read-through cache (the single biggest lever, and it
doubles as Valkey-outage survival — see ADR-007) plus `SO_REUSEPORT` workers for
CPU scaling; **C** on the roadmap. B's invalidation correctness depends on
ADR-003/004, which is why those come first.

## Consequences

- Cache invalidation becomes a first-class concern; staleness window must be
  bounded and documented.
- Per-worker memory grows with zone size; the global mutex stops being the
  serialization point for reads.
- A read-through cache is also your degraded-mode data source when Valkey is
  down (ADR-007).

---

# ADR-006: DNSSEC key custody and secrets at rest

**Status:** Proposed

## Context

`dnssec_init_key` stores **KSK/ZSK private keys as PEM in Valkey** (`dnssec:ksk`,
`dnssec:zsk`, …). TSIG secret (`config:tsig_secret_b64`) and cookie secret
(`config:cookie_secret`) live there too. So the most sensitive material is
readable by anything with Valkey access, sitting beside the data it protects,
with no isolation. KSK loss (Valkey data loss, ADR-007) is a chain-of-trust
catastrophe requiring a DS rollover at the parent.

## Decision

Define a custody model commensurate with the KSK's blast radius.

## Options

- **A — status quo.** Plaintext PEM in Valkey. Worst posture.
- **B — encrypt at rest.** Keys/secrets encrypted in Valkey with a master key
  sourced **outside** Valkey (env/file/KMS), decrypted in-process. Mitigates
  "Valkey dump ⇒ keys"; master-key management is the new problem.
- **C — keys out of Valkey.** Private keys loaded from a file/secret store, or a
  **PKCS#11 / HSM** for the KSK; Valkey holds only public DNSKEY/DS. Strongest.
- **D — dedicated signer process.** Keys isolated to one process that signs on
  request; adds latency/complexity.

## Recommendation

Adopt the standard DNSSEC split: **KSK offline/HSM (C), ZSK online**. Near-term
floor: **B** for everything still in Valkey (KSK, ZSK, TSIG, cookie). Target:
KSK via PKCS#11/HSM, ZSK encrypted-at-rest or in a signer process (D) if you
want isolation. The KSK is the only key whose loss is unrecoverable without
parent action — protect it accordingly.

## Consequences

- Signing path and key-rollover procedures change (ties to reference RFCs
  6781/7583).
- Multi-instance/anycast (3258) must distribute/share keys securely.
- Key backups (ADR-007) must be encrypted; a plaintext backup re-creates the
  problem off-box.

---

# ADR-007: Valkey HA, persistence, and disaster recovery

**Status:** Proposed

## Context

A single Valkey is a SPOF for both **availability** and **durability**, holding
zones, certs, DNSSEC keys, and (future) EPP registry objects. Unreviewed:
replication/failover, persistence (RDB/AOF — possibly off), and
backup/restore/DR. The `stale:` shadow keys give partial resilience but no DR
design. If Valkey loses data, you lose the zone *and* the keys.

## Decision

Specify HA, durability, and DR as three explicit dimensions.

## Options / recommendation

- **Availability:** Valkey replica(s) + **Sentinel** for failover (sufficient for
  this read-heavy, modest-dataset workload); Cluster only if sharding is needed.
- **Durability:** enable **AOF (`appendfsync everysec`) + periodic RDB**. Without
  AOF a crash loses recent zone changes and freshly issued certs.
- **DR / backup:** scheduled **encrypted** export (RDB/AOF or keyspace dump) to
  offsite, with a *tested* restore. DNSSEC keys and EPP objects need explicit
  backup discipline (for `eppd`, this overlaps registry data escrow 8909/9022).
- **Degraded mode:** promote the ADR-005 in-process cache into a defined
  "serve last-known-good" mode when Valkey is unreachable, rather than only the
  current first-boot config portal.

## Consequences

- An operational runbook (failover, restore, key recovery) becomes a deliverable.
- The in-process cache (ADR-005) is your Valkey-outage survival path — design the
  two together.
- Anycast nodes (3258) each need a consistent, durable Valkey view; document the
  replication topology per site.

---

# ADR-008: Role of the embedded object store (objectdb) relative to Valkey

**Status:** Proposed — recommended option **C now** (per-daemon embedded store
for single-owner namespaces, pilot: `resolverd`'s `cache:*`), **D later**
(dnsd's in-process zone store, co-designed with ADR-005/ADR-007). Option A
(full Valkey replacement) is **rejected**. Feasibility study 2026-07-03.

## Context

`objectdb` (`lucianpopovici/objectdb`, `object_graph.{c,h}`) is an embedded,
WAL-backed persistent object-graph engine that has been deliberately evolved
toward DNS workloads: an ordered index in RFC 4034 §6.1 canonical DNS-name
order (`index_succ`/`index_pred`/`index_range` — the NSEC-chain primitive), a
durable per-transaction change log (`store_changes_since`, IXFR-style
diffing), `dns.ancestors`/`dns.wildcards` virtual lists (the zone-match and
wildcard-synthesis ladders), `OBJ_BYTES` blobs, crash recovery, and a
thread-safe rwlock. Its test suite passes clean (1308/1308) under this
project's hardening flags.

The question is whether it can replace Valkey. It cannot, wholesale, for
structural reasons:

1. **It is single-process by design.** `store_open()` takes an exclusive
   `flock(LOCK_EX|LOCK_NB)`; there is no server, wire protocol, or shared
   read-only mode. Valkey's role here is precisely the thing an embedded
   library cannot do: the integration bus between six processes (design
   principle 2), which exists for privilege separation.
2. **No pub/sub.** `dnsd`/`apid`/`mdnsd` live-reload via keyspace
   notifications; objectdb's change log is poll-based and in-process only.
3. **No Python access.** The dashboard talks to Valkey directly.
4. **No TTL.** `ddns:*` leases and `stale:*` shadows use `SET … EX`.
5. **Data remodel, not rename.** Field keys and root names cap at 64 bytes
   (< a 255-byte DNS name); the flat `zone:<zone>:<type>:<name>` keyspace
   would become class-tagged objects with indexed `name` fields.

## Decision

Define what role, if any, objectdb plays relative to Valkey.

## Options

- **A — full replacement.** Requires building a network daemon around
  objectdb (protocol, auth, notifications, HA) — re-implementing Valkey and
  placing new, unproven code in the most trusted position. Rejected.
- **B — status quo.** Valkey everywhere; objectdb unused. Foregoes a
  DNS-tailored engine for the hot path and leaves ADR-005 B / ADR-007
  degraded mode as bespoke cache code.
- **C — per-daemon embedded store for single-owner namespaces.** Adopt
  objectdb only where the ownership table shows one writer *and* one reader,
  both the same process: `resolverd`'s `cache:*` (and potentially `certd`'s
  `acme:*`, though certd still needs Valkey for `zone:`/`cert:`). Removes
  resolverd's Valkey dependency and a network round-trip per cache op; the
  inter-daemon contract is untouched.
- **D — dnsd materialized zone store, alongside Valkey.** Valkey remains the
  control-plane bus and source of truth; objectdb becomes dnsd's durable
  in-process copy, fed by the existing keyspace notifications. The ordered
  index serves NSEC denial, the change log maps onto the `ixfr:*` journal,
  and durability turns ADR-005's cache into ADR-007's "serve
  last-known-good" degraded mode (superseding the `stale:` shadow hack).

## Recommendation

**C now, D later, never A.** Pilot with `resolverd`'s cache: self-contained,
one owner, measurable win, and it exercises the sandbox interplay cheaply.
Take up D only together with ADR-005's invalidation design and ADR-004's
snapshot pinning (a pinned store snapshot is a natural AXFR anchor).

## Consequences

- **Sandbox:** the store's snapshot/WAL/vlog files must live inside the
  daemon's chroot, writable by the privdrop user; `fsync`/`rename`-class
  syscalls join the seccomp whitelist (re-harvest via the documented
  audit-then-enforce procedure). The trusted core gains a durable-file
  write path it currently does not have.
- **Ownership table / ADR-003:** any namespace moved into an embedded store
  leaves the Valkey schema contract; the ownership table and format registry
  must record that move in the same change. Embedded-store layout gets its
  own version discipline (objectdb snapshots carry a format version).
- **TTL semantics** must be replaced by explicit sweeps wherever an adopted
  namespace relied on `EX` expiry.
- **Dependency:** objectdb is vendored/pinned and held to this repo's bar —
  its parser/loader surface (snapshot + WAL replay) is untrusted-input-adjacent
  and needs fuzz coverage before it backs the trusted core (security-sensitive
  change gate applies to D).

---

## Open architectural issues (named, not yet decided)

Lower-tier than the ADRs above but real; track and decide before GA.

1. **Cross-daemon observability.** Per-instance NSID/`syslog_ident` and
   `/metrics`/`/health` exist, but there's no query tracing across
   `resolverd → dnsd → Valkey`, no metrics aggregation across instances, and the
   known single-Valkey dashboard limit. Decide a tracing/metrics story.
2. **Process security model.** Run-as UID (the process holds Valkey creds +
   signing keys), capability dropping, seccomp/sandbox, and the
   **unauthenticated config portal on 8080** when Valkey is unreachable. Per-
   feature security is strong; process posture is unreviewed.
3. **Threading & resource bounding.** `select()` + detached AXFR/mDNS/PKI
   threads. Are TCP/DoT/DoH accept loops bounded (connection/FD/thread/memory
   caps)? RRL caps query floods, not connection/thread exhaustion.
4. **Time/clock dependency.** RRSIG inception/expiry, TSIG fudge, and cookie
   timestamps require clock sync; across anycast nodes, skew causes validation
   and TSIG failures. NTP is an unstated hard dependency — make it explicit.
5. **Config versioning & consistent rollout.** Config is part live-read, part
   SIGHUP; across instances/daemons there's no atomic, versioned rollout. Pair
   with ADR-003 (the schema version should cover `config:` too).
6. **Failure-mode matrix.** Document, per daemon, what happens when each
   dependency fails (Valkey down, upstream down, CA unreachable, cert expired,
   key missing) — as one matrix, replacing the current piecemeal handling.

---

## Suggested decision order

1. **ADR-003** (schema contract) and **ADR-004** (atomicity) — before the split.
2. **ADR-006** (key custody) — at least the encrypt-at-rest floor — before any
   production signing or off-box backup.
3. **ADR-007** (HA/DR) — before depending on a single Valkey in production.
4. **ADR-005** (caching/QPS) — when you hit the throughput ceiling; co-design
   with ADR-004's snapshot and ADR-007's degraded mode.
5. **ADR-008** (embedded store) — pilot (option C, resolverd cache) any time;
   the dnsd zone-store role (option D) only together with ADR-005/004.
6. Open issues 1–6 — before GA.
