# eppd — registry back-end (EPP provisioning)

`eppd` is a new top-level component: an EPP registry **front-end** that lets
registrars provision domains/hosts/contacts, and feeds the resulting delegation
data to `dnsd` for publication. It is the largest single component in the
project. This document scopes it as an ADR + a phased build, and is explicit
that the EPP wire protocol is the easy part — **registry policy** (transfers,
grace periods, escrow, RDAP) is the work.

---

# ADR-002: `eppd` is a registry front-end, not a DNS server

**Status:** Accepted
**Date:** 2026-06-22 (ratified 2026-07-03: private/internal registry — RDAP,
data escrow, and public-TLD/ICANN policy obligations are out of scope unless
this later becomes a public registry)
**Deciders:** repo owner

## Context

EPP (RFC 5730) is the protocol between **registrars and a registry**. It
provisions registration objects; it does not serve DNS. Choosing to "be a
registry" means accepting registrar EPP sessions, maintaining the
domain/host/contact object store, enforcing registry lifecycle policy, and
publishing the resulting NS/DS/glue into a zone — which `dnsd` then serves.

This fits the existing role-based decomposition and Valkey-bus model: `eppd` is
another daemon that never serves DNS and integrates only through Valkey.

## Decision

Build `eppd` as a separate component:

- **EPP over TLS on TCP/700** (RFC 5734), mutual-TLS with registrar client certs.
- **Object store in Valkey** (domains/hosts/contacts), matching the project bus.
- **Publish pipeline**: `eppd` writes delegation records (NS, DS, glue) into the
  `zone:*` / `zone_table:*` keyspace that `dnsd` already serves. `dnsd` stays
  read-only on registry-owned delegation data.

`eppd` does **not** answer DNS queries and `dnsd` does **not** speak EPP.

## Why separate (not part of dnsd)

| Dimension | EPP front-end | Authoritative `dnsd` |
|-----------|---------------|----------------------|
| Protocol | XML/EPP over TLS | DNS wire over UDP/TCP/DoT/DoH |
| Port / security | 700, registrar mTLS | 53/853/443, public |
| Lifecycle | transfers, grace periods, escrow | query/response, signing |
| Failure blast radius | provisioning outage | resolution outage |

Different protocol, port, security model, and lifecycle — a textbook separate
role, not a `dnsd` feature.

## Consequences

- **Largest component.** Plan it as a program of work, phased below.
- **Registry policy is the hard part.** Transfer authorization, grace-period
  state machine, data escrow, and RDAP publication dwarf the EPP XML handling.
- **Public-TLD obligations** (escrow, RDAP, possibly ICANN policy) apply only if
  this is a *public* registry; a private/internal registry can defer most of
  them. Decide that early — it changes scope by an order of magnitude.

## Action items

1. [x] Decide **public** vs **private/internal** registry — drives escrow/RDAP/policy scope. **Decided 2026-07-03: private/internal.** RDAP/escrow/public-TLD policy rows below are deferred, not built.
2. [~] Phase 1 (core EPP) **in progress** → Phase 2 (security + lifecycle) → Phase 3 (extensions).
3. [x] Define the Valkey object schema + publish pipeline to `dnsd`. **Done 2026-07-06**: `epp:*` TLV objects + `zone:*` NS/A/AAAA publish, see the checklist below.
4. [ ] RDAP companion service decision (query side of registry data).

---

## Architecture

### The three core objects (RFC 5731/5732/5733)

| Object | Holds | Valkey key (proposed) |
|--------|-------|-----------------------|
| Domain | name, registrant+contacts, NS set, DS data, statuses, authInfo, dates | `epp:domain:<name>` |
| Host | nameserver name + glue A/AAAA | `epp:host:<fqdn>` |
| Contact | registrant/admin/tech/billing identities | `epp:contact:<id>` |

Each carries a repository object id (ROID), status flags (`ok`, `clientHold`,
`serverHold`, `pendingTransfer`, `pendingDelete`, …), and authInfo.

### Publish pipeline (the bridge to `dnsd`)

```
registrar --EPP/TLS:700--> eppd --(policy + object store in Valkey)-->
     publish step: for each active domain, emit delegation RRs -->
        zone:NS:<name>     (child NS set)
        zone:DS:<name>     (DS from EPP 5910 or scanned CDS)
        zone:A/AAAA:<glue> (in-bailiwick host glue)
   --> dnsd serves the parent zone (read-only on these keys)
```

`eppd` owns delegation data; `dnsd` owns serving. The publish step runs on
object change and bumps the parent zone serial (the same `serial_bump` path
`dnsd` already keys on).

---

## Phased RFC plan

### Phase 1 — minimum viable registry (core)

| RFC | What |
|-----|------|
| 5730 | EPP core — session, greeting/login, command/response framing, `<check>`/`<info>`/`<create>`/`<update>`/`<delete>` |
| 5734 | EPP transport over TCP — TLS on 700, 4-byte length-prefixed XML frames |
| 5731 | Domain mapping — the domain object + lifecycle commands |
| 5732 | Host mapping — nameserver objects + glue |
| 5733 | Contact mapping — registrant/admin/tech/billing |

Phase 1 = registrars can create/update/delete domains with NS + glue, and the
publish pipeline produces a servable parent zone.

### Phase 2 — security + lifecycle (required for a real registry)

| RFC | What |
|-----|------|
| 9154 | Secure authInfo — replaces plaintext transfer authInfo (transfers must use this) |
| 3915 | Registry Grace Period (RGP) — add/auto-renew/redemption grace, `pendingDelete` |
| 5910 | DNSSEC mapping — accept DS/DNSKEY data from registrars (parent-side DS) |

### Phase 3 — extensions (as needed)

| RFC | What |
|-----|------|
| 8748 | Registry Fee extension (billing at the EPP layer) |
| 8543 | Organization mapping |
| 8590 | Change Poll extension |

---

## DNSSEC: two parent-side DS paths

As a **registry**, `eppd` is the *parent* that receives child DS records:

1. **EPP 5910** — registrars submit DS data with the domain object. Classic
   registry path.
2. **In-band CDS/CDNSKEY (7344/8078)** — scan children's CDS and accept DS
   changes automatically. `dnsd` already *serves* CDS as a child; here `eppd`
   *consumes* CDS as a parent. Offer both; gate CDS acceptance on policy
   (acceptance window, signed-self-consistency per RFC 8078).

Either path ends the same way: a `zone:DS:<child>` key the parent zone publishes.

---

## Companion: RDAP (the query side)

A registry must publish registration data for lookup. Modern registries use
**RDAP** (RFC 9082/9083 + 7480–7484), not legacy WHOIS. RDAP is a separate
read-only HTTP/JSON service over the same `epp:*` object store. Scope it
alongside `eppd` (it can share the Valkey object model). For a public TLD it is
mandatory; for a private registry it is optional but recommended.

## Data escrow (public-TLD obligation)

A public registry must escrow its data (RFC 8909 registry data escrow + RFC 9022
domain-name escrow). This is a periodic export/deposit job over the `epp:*`
store. Required for public TLDs; skip for private/internal.

---

## Tracked checklist

- [x] **ADR-002** — ratify; choose public vs private registry (private/internal, 2026-07-03)
- [x] **Prerequisites in `dnsd`** (discovered during Phase 1 scoping, not originally
      listed here — see "Prerequisite work" below): RFC 9471 delegation/referral
      support + multi-value NS storage. Both done 2026-07-06.
- [~] **Phase 1** — EPP core (session shell + check/create/info done; update/delete
      + DS mapping intentionally deferred to Phase 2 below)
  - [x] 5734 TCP/700 transport, length-prefixed XML framing, registrar mTLS
        (mandatory — no plain-TLS fallback, unlike `apid`'s DoH/mgmt split)
  - [x] 5730 session: greeting → login/logout → command/response, clTRID/svTRID
  - [x] 5731 domain + 5732 host + 5733 contact objects in Valkey (`epp:*`,
        TLV-encoded/ADR-003, hex-encoded before storing); `check`/`create`/
        `info` implemented, `update`/`delete` still stubbed (2400)
  - [x] Publish pipeline → `zone:NS/A/AAAA` + serial bump (verified live: a
        real `domain:create` + `dig` shows `dnsd` serving the referral with
        glue). **`zone:DS`** intentionally NOT included — DS mapping is RFC
        5910, Phase 2 (`dnsd` has no per-child DS storage today either)
  - [x] `make check-eppd` (KAT + live EPP session + dig verification) /
        `make fuzz-eppd` (XML tokenizer + RFC 5734 framing, 60s clean)
- [ ] **Phase 2** — 9154 secure authInfo; 3915 RGP grace periods; 5910 DS mapping
      (needs a `dnsd`-side `zone:<zone>:DS:<name>` read path first — doesn't
      exist yet, see "Prerequisite work" below); `update`/`delete` for all
      three object types
- [ ] **Phase 3** — 8748 fee; 8543 org; 8590 change poll
- [ ] **RDAP** companion (9082/9083) — query side
- [ ] **Escrow** (8909/9022) — only if public TLD
- [ ] **ENUM** — EPP for E.164 provisioning (4114/5076) — see `CLAUDE-ENUM.md`

## Prerequisite work found during Phase 1 scoping (not anticipated by this doc)

Two gaps between what this document assumed and what `dnsd` actually did,
found via codebase research before writing any `eppd` code (see
`feature-work-progress.md` for the full session log):

1. **`dnsd` had zero delegation/referral concept** — flat-authoritative, no
   zone-cut logic at all (this repo's own `CLAUDE-rfc-additions-batch3.md`
   already named this gap and parked RFC 9471 as a dormant "forward
   requirement... when delegation support is added"). Without it, `eppd`
   could publish all the NS/glue records it wanted and `dnsd` would still
   answer authoritatively for domains it doesn't control, which is wrong.
   **Done**: `dnsd` now answers a qname at/below a configured delegation
   point non-authoritatively (AA=0, unsigned NS in Authority, in-bailiwick
   glue in Additional, TC=1 if oversized) — RFC 9471 in full.
2. **`zone:<zone>:NS:<name>` was single-value only** (`"ttl|name"`), so a
   delegation could never carry more than one nameserver. **Done**: extended
   to `"ttl|ns1|ns2|..."` matching how A/AAAA already worked, across
   query-serving, AXFR, and IXFR apply.

Both are load-bearing for Phase 1's own acceptance criteria below, not
optional polish — `eppd` has nothing real to publish into without them.

---

## Guardrails (do NOT)

- **Do NOT** let `eppd` serve DNS or write non-delegation records. It publishes
  only NS / DS / in-bailiwick glue for domains it is the registry for; zone
  *content* below a delegation belongs to the child, served elsewhere.
- **Do NOT** use plaintext transfer authInfo — Phase 2's RFC 9154 secure
  authInfo is mandatory for transfers; a plaintext implementation is a security
  defect, not a simplification.
- **Do NOT** shortcut the grace-period state machine. `pendingDelete` →
  redemption → purge (RFC 3915) has legal/operational meaning; an "instant
  delete" path is wrong for a registry.
- **Do NOT** accept EPP without registrar mTLS client-cert authentication —
  registrar identity is the basis for every authorization check.
- **Do NOT** accept child DS via CDS without a policy gate (acceptance window,
  RFC 8078 §3 self-consistency) — blind acceptance is a hijack vector.
- **Do NOT** treat this as a small add. Phase 1 alone is a substantial service;
  public-TLD scope (escrow + RDAP + policy) is a multi-component program.

## Acceptance criteria (Phase 1)

- [x] A test registrar (`tests/epp_client.py`, since no standard tool speaks
  EPP) completes login over TCP/700 with a client cert, runs `domain:check`
  and `domain:create` with NS+glue, and the publish pipeline yields an
  NS/glue delegation that `dnsd` serves — **verified live**: `make
  check-eppd` runs the full sequence and confirms via `dig` that the
  resulting `epptest.example.local NS` query returns the referral (RFC 9471)
  with the published nameserver and its glue A record.
- [ ] `<domain:delete>` moves the object through the grace-period states
  (Phase 2), not an immediate purge — not yet implemented (`update`/`delete`
  are still stubbed, 2400).
- [ ] DS submitted via `<domain:update>` (5910) appears as a `zone:DS:<name>`
  the parent zone serves and that validates in `resolverd` — not yet
  implemented; blocked on `dnsd` growing a `zone:<zone>:DS:<name>` read path,
  which doesn't exist today (DS answers are currently synthesized live from
  the zone's own KSK, unrelated to a child's delegation) — a Phase 2
  prerequisite, mirroring this session's P0a/P0b work for NS.

## Test (Phase 1 sketch)

```bash
# Against eppd with a registrar client cert configured:
epp-client --host eppd --port 700 --cert registrar.pem login
epp-client domain:check example.test
epp-client domain:create example.test --ns ns1.example.test=192.0.2.1 --registrant C1
# Confirm dnsd now serves the delegation:
dig @<dnsd-ip> -p 5353 example.test NS
dig @<dnsd-ip> -p 5353 ns1.example.test A   # glue
```
