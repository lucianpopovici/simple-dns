# dns_server.c — ENUM (E.164 to URI) capability

ENUM lets a phone number resolve to service URIs (SIP, email, web) via DNS. In
DNS terms it is **authoritative NAPTR serving over a reverse-digit zone** — not
a new protocol and not a new role. This document records the placement decision
(ADR-001) and the feature spec (Add 6), in the same format as
`CLAUDE-rfc-additions.md`.

---

# ADR-001: ENUM lives in `dnsd`, not a separate binary

**Status:** Accepted — single binary; placement in `dnsd` ratified 2026-06-20.
Separation, when required, is achieved by running **two instances of the same
binary** (see Deployment topology below), not by a second binary.
**Date:** 2026-06-20
**Deciders:** repo owner

## Context

ENUM (RFC 6116) maps an E.164 number to URIs by reversing its digits into a DNS
name under an apex (`e164.arpa` or a private equivalent) and serving NAPTR
records there. The terminal NAPTR carries a regexp that rewrites the number
into a URI — but **that rewrite is performed by the client/resolver, not the
authoritative server**. The authoritative server's entire job is to serve the
right NAPTR RRset at the reversed-digit name, signed and transferable like any
other zone data.

The current server already encodes NAPTR rdata correctly in the
`zone:NAPTR:<name>` handler (`order | pref | flags | service | regexp |
replacement`). The "stub" label means *serve-only, no ENUM profile* — which is
the correct scope for an authoritative server. So most of ENUM is already on
disk; what is missing is an apex convention, provisioning ergonomics, and a few
guardrails.

The planned daemon decomposition splits by **role**: `dnsd` (authoritative),
`mdnsd` (multicast), `resolverd` (recursive), `certd` (PKI), over `libdnswire`.
The question is where ENUM fits.

## Decision

Implement ENUM as a **profile inside `dnsd`**, reusing the existing NAPTR
encoder, zone-serving, DNSSEC, TSIG, and AXFR paths. Put provisioning
(E.164 → NAPTR rule generation) in the **Valkey control plane + dashboard**,
mirroring the DNSxL synthesis model. Do **not** create an `enumd` binary.

## Options considered

### Option A — ENUM profile inside `dnsd` (chosen)

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low — reuses the existing NAPTR encoder and zone path |
| New code | Apex config + provisioning helper + guardrails (~120 lines) |
| Wire stack reuse | Full (EDNS, DNSSEC, TSIG, cookies, AXFR all inherited) |
| Role fit | Exact — ENUM is authoritative DNS |

**Pros:** No duplicated DNS stack; ENUM zones sign and transfer for free; one
operational surface. **Cons:** ENUM apex adds a second authoritative zone (see
Consequences — multi-zone interaction).

### Option B — separate `enumd` binary

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — clones sockets, EDNS, DNSSEC, TSIG, AXFR |
| New code | Effectively a second authoritative server |
| Role fit | None — duplicates `dnsd`'s role with a narrower record set |

**Pros:** Process isolation. **Cons:** All of `dnsd`'s wire/security/transfer
logic re-implemented or wrapped for no functional separation. **Rejected.**

### Option C — synthesis sidecar (not a full DNS daemon)

A small helper process that `dnsd` calls **only** when a NAPTR answer must be
synthesized from an external system (e.g. a real-time number-portability "dip",
RFC 4769), keeping that blocking I/O out of `dnsd`.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — IPC + a narrow synthesis service |
| When justified | Only if synchronous external-DB lookups are a hard requirement |
| Interaction | Collides with the known single-threaded `select()` bottleneck |

**Pros:** Keeps slow external lookups off the event loop. **Cons:** Premature
unless number-portability/external dips are actually required; the cleaner fix
is the async/decomposition work already on the roadmap. **Deferred**, not
rejected — revisit if a real-time external lookup requirement appears.

## Trade-off analysis

The decomposition's organizing principle is role separation, and ENUM is
unambiguously authoritative. The only genuinely separable concern is *slow
external synthesis* (Option C), and that is a function of a specific deployment
requirement, not of ENUM itself. Static and template-synthesized ENUM — the
common cases — have no such requirement and belong in `dnsd`.

## Consequences

- **Easier:** ENUM zones inherit DNSSEC signing, AXFR/IXFR, TSIG, and cookies
  with zero new transport code.
- **Harder / to revisit — per-zone DNSSEC keys, not multi-zone data.**
  Correction after a source check: the server *already* has a multi-zone **data**
  table (`g_zones[16]`, longest-suffix `zone_find`, `/zone/add` API,
  `zone_table:*` keys), so serving a second zone's records works today. What is
  **not** per-zone is DNSSEC: `dnssec_init()` loads exactly one global keyset
  (`g_zsk`/`g_ksk` + Ed25519). That reshapes A1 vs A2:
  - **A1 (subtree):** host ENUM under a subtree of the existing zone, e.g.
    `*.e164.<your-zone>` — one zone, one keyset, fully signed today. Natural for
    a **single instance**.
  - **A2 (independent apex), single instance:** serving the data works, but a
    *signed* independent apex needs its own DNSKEY-at-apex + DS-in-parent, i.e.
    **per-zone keys** the global keyset does not provide. This is the real (and
    only) expensive piece — not multi-zone data.
  - **A2 (independent apex), two instances:** unaffected — each instance's single
    global keyset *is* its one zone's keyset. The global-keyset design is a clean
    fit here; no per-zone-key work needed.
- **Revisit Option C** (synthesis sidecar) only if real-time external number
  lookups are required — see Roadmap: number portability.

## Action items

1. [ ] Choose **deployment topology**: one instance (→ A1) or two instances (→ A2).
   The two are coupled; see Deployment topology.
2. [ ] Implement Add 6 (below) for the chosen layout.
3. [ ] If two instances: the six isolation prerequisites (Valkey keyspace, boot
   file/portal, bind address, subsystem toggles, resolver routing, identity).
4. [ ] Provisioning helper in the dashboard / management API.
5. [ ] Number portability on the roadmap as the Option C trigger (see Roadmap).

---

## Deployment topology: one binary, one or two instances

Separation does not require a second binary. The same `dnsd` binary runs as one
or two **instances**, selected by config. This keeps a single codebase while
allowing process-level isolation when wanted.

### Single instance (default)

One `dnsd` serves both the normal zone and ENUM. ENUM is a **subtree of the
existing signed zone** (layout **A1**). One SOA, one keyset, no multi-zone code.

### Two instances (separation)

Two `dnsd` processes, same binary, different config:

| | Instance A (DNS) | Instance B (ENUM) |
|---|---|---|
| Zone | `example.local` | `e164.arpa` / private apex (**A2**) |
| Bind address | `192.0.2.1` / `2001:db8::1` | `192.0.2.2` / `2001:db8::2` |
| Ports | 5353 / 8853 / 8053 / 8443 | **same** — 5353 / 8853 / 8053 / 8443 |
| DNSSEC keys | own global keyset | own global keyset (separate Valkey) |
| Zones per process | one | one (global keyset = that zone's keyset) |

The two instances differ by **bind IP, not port** — DNS on one address, ENUM on
another, identical well-known ports on each.

Because each process serves one zone, the existing global keyset is exactly
right per instance — no per-zone DNSSEC keys to add. The separation you'd
otherwise write code for happens at the process boundary instead.

#### Isolation prerequisites (the actual work)

1. **Valkey keyspace isolation — the *whole* keyspace, not just `config:`.**
   Keys carry no instance prefix, and the shared set includes **DNSSEC private
   keys** (`dnssec:zsk` / `dnssec:ksk` / `…_ed25519`), the zone table
   (`zone_table:*`), zone and dynamic data (`zone:*`, `ddns:*`),
   `config:zone_serial`, ACME state, and the `stale:*` shadow keys. A shared
   logical DB means the ENUM instance reads the DNS instance's signing keys and
   zones. Options:
   - *Separate Valkey instance per `dnsd`* — zero code; set `DNS_VALKEY_HOST` /
     `DNS_VALKEY_PORT` per instance. **Recommended.**
   - *Separate Valkey logical DB index* — small change: the `SELECT 0` is
     hardcoded; add a `DNS_VALKEY_DB` and pass it.
2. **Boot file + config-portal isolation.** `BOOT_FILE` is a fixed,
   CWD-relative `dns_server.boot`, and the first-boot portal binds `CONFIG_PORT`
   (default 8080). Two instances in one working directory clobber each other's
   boot file; during a Valkey outage both race for 8080. Run each instance in
   its **own working directory** and give each a distinct `CONFIG_PORT`.
3. **Bind address per instance (same ports, different IP).** Today every
   listener binds the wildcard (`INADDR_ANY` / `::`), which claims the port on
   all addresses and blocks a second instance on the same port. Bind each
   instance to a **specific** address so both can use identical ports — see
   "Per-instance bind configuration" below. Required code change.
4. **Subsystem toggles.** The ENUM instance should NOT also run mDNS, ACME/EST
   renewal, or NOTIFY — two responders / duplicate cert-renewal races
   otherwise. Add toggles to run instance B "DNS-only, single-zone":
   `config:enable_mdns`, `config:enable_pki_renewal`, `config:enable_notify`
   (default on; ENUM instance sets them off).
5. **Resolver routing to reach the ENUM instance.** Nothing queries the ENUM IP
   unless resolvers route the apex to it. Configure the forwarder/resolver — with
   the bundled `dns_client`, dnsmasq-style `--server /e164.arpa/192.0.2.2:5353`.
   Without this the ENUM instance is dark.
6. **Per-instance identity.** Set distinct `config:syslog_ident` and
   `config:nsid` so logs and answers reveal which instance acted. Config only.

Items 3 (bind) and 4 (toggles) are the code/work; items 1, 2, 5, 6 are
deployment and config.

### Decision table

| Topology | ENUM layout | Extra work | When |
|----------|-------------|------------|------|
| One instance | A1 (subtree) | none — signed today | Default; separation not required |
| Two instances | A2 (apex) | none for DNSSEC (one keyset = one zone each) | Separation required/likely |
| One instance | A2 (apex) | **per-zone DNSSEC keys** (data already works) | Avoid unless one process must sign an apex |

**Guidance:** if separation is even moderately likely, plan for two-instance +
A2 — it scales to isolation without a later rewrite, at the cost of the three
isolation prerequisites above.

### Per-instance bind configuration

Goal: serve DNS from one IP and ENUM from another, on **identical ports**, by
binding each instance to a specific address instead of the wildcard.

#### Config schema

```
config:bind4     IPv4 address for all IPv4 listeners   (default 0.0.0.0 = all)
config:bind6     IPv6 address for all IPv6 listeners   (default ::      = all)
config:dns_port  UDP/TCP DNS port                      (default 5353)
config:dot_port  DoT port                              (default 8853)
config:http_port HTTP (DDNS / health / metrics) port   (default 8053)
config:https_port HTTPS (DoH + mTLS management) port   (default 8443)
```

DNS instance: `bind4=192.0.2.1`. ENUM instance: `bind4=192.0.2.2`. Ports left
at defaults on both. The IP makes the socket tuples distinct.

#### Exact location in current file

Every listener in the "Phase 6b: Open unicast DNS sockets" block binds the
wildcard. The sites to change (IPv4 **and** IPv6):

| Listener | Current bind |
|----------|--------------|
| DNS UDP v4 | `sa.sin_addr.s_addr = INADDR_ANY` |
| DNS TCP v4 | `sa4t.sin_addr.s_addr = INADDR_ANY` |
| DoT v4 | `INADDR_ANY` |
| HTTP v4 | `INADDR_ANY` |
| HTTPS/DoH v4 | `INADDR_ANY` |
| DNS UDP v6 / DoT v6 | zero-init `sin6_addr` (= `in6addr_any`) |

(mDNS binds `INADDR_ANY` too, but the ENUM instance has mDNS **off** per the
subsystem toggles, so leave the mDNS socket as-is.)

#### What to build

Two small helpers, called at every bind site:

```c
static char g_bind4[64] = "0.0.0.0";
static char g_bind6[64] = "::";

static int fill_bind4(struct sockaddr_in *sa, uint16_t port){
    memset(sa,0,sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port   = htons(port);
    if(!g_bind4[0] || strcmp(g_bind4,"0.0.0.0")==0){
        sa->sin_addr.s_addr = INADDR_ANY;
    } else if(inet_pton(AF_INET, g_bind4, &sa->sin_addr) != 1){
        dns_log(LOG_ERR,"[bind] invalid config:bind4 '%s'\n", g_bind4);
        return -1;
    }
    return 0;
}

static int fill_bind6(struct sockaddr_in6 *sa, uint16_t port){
    memset(sa,0,sizeof(*sa));
    sa->sin6_family = AF_INET6;
    sa->sin6_port   = htons(port);
    if(!g_bind6[0] || strcmp(g_bind6,"::")==0){
        sa->sin6_addr = in6addr_any;
    } else if(inet_pton(AF_INET6, g_bind6, &sa->sin6_addr) != 1){
        dns_log(LOG_ERR,"[bind] invalid config:bind6 '%s'\n", g_bind6);
        return -1;
    }
    return 0;
}
```

Replace each inline `struct sockaddr_in sa = {... INADDR_ANY}` with a
`fill_bind4(&sa, g_dns_port)` call (and `fill_bind6` for the v6 listeners).
Defaults keep current behavior (`0.0.0.0` / `::`) for single-instance
deployments — no behavior change unless `bind4`/`bind6` is set.

#### Guardrail (do NOT)

- **Do NOT leave either instance on the wildcard** when running two on one host.
  A `0.0.0.0` bind grabs the port on every address; the second instance then
  cannot bind the same port even on a specific IP (and SO_REUSEADDR does not
  change that for two live listeners). Both instances must set `bind4`/`bind6`.
- **Do NOT change only the IPv4 sites.** If v6 stays on `::`, the wildcard
  collision reappears on IPv6. Convert v4 and v6 together.
- **Do NOT enable SO_REUSEPORT on the unicast DNS sockets** to "make it work."
  With distinct IPs you do not need it; on a shared wildcard it would silently
  load-balance queries between the two instances — wrong for role separation.
- **Management/DoH share the bound address** here. If you later want the
  dashboard on a separate management IP, add a distinct `config:mgmt_bind`
  then — out of scope for this change.

#### Acceptance criteria

- Instance A (`bind4=192.0.2.1`) and instance B (`bind4=192.0.2.2`), both with
  `dns_port=5353`, start without `EADDRINUSE`.
- `dig @192.0.2.1 -p 5353 example.local SOA` hits the DNS zone;
  `dig @192.0.2.2 -p 5353 <rev>.e164.arpa NAPTR` hits ENUM; neither sees the
  other's data.
- With `bind4` unset, behavior is unchanged (binds all addresses).

#### Test

```bash
valkey-cli -p 6379 SET config:bind4 192.0.2.1     # instance A — DNS
valkey-cli -p 6380 SET config:bind4 192.0.2.2     # instance B — ENUM
# both use default ports; start both dnsd processes

ss -lunp | grep ':5353'    # two distinct listeners: 192.0.2.1:5353, 192.0.2.2:5353
dig @192.0.2.1 -p 5353 example.local SOA
dig @192.0.2.2 -p 5353 4.3.2.1.5.5.5.0.0.8.1.e164.arpa NAPTR
```

### Packaging, management, and trust follow-ups

These do not block a first deploy but are easy to forget:

- **Process supervision.** Two instances = two systemd units (or two supervised
  processes) with distinct env (working dir, `DNS_VALKEY_*`, `CONFIG_PORT`).
  The Makefile install target installs one unit — add a second/templated unit
  (`dnsd@.service` with per-instance env files).
- **Management plane.** The Flask dashboard is single-Valkey; managing the ENUM
  instance needs either a second dashboard pointed at the ENUM Valkey or
  dashboard multi-backend support. Confirm and pick one before relying on the
  UI for ENUM.
- **DNSSEC chain of trust for the ENUM apex.** A signed ENUM zone needs its
  KSK's DS in the parent. Private/internal tree: self-contained (publish the DS
  in your internal parent). Real `e164.arpa`: you must actually hold the
  delegation — otherwise you are a lame authority only reachable via the
  resolver routing in prerequisite 5.
- **CI: two-instance isolation test.** Add a job that starts two instances on
  two loopback IPs (`127.0.0.1` / `127.0.0.2`) with separate Valkey DBs, then
  asserts each answers only its own zone and neither reads the other's keys.
- **Signed sparse-tree coverage.** ENUM trees are deep and sparse; empty
  non-terminals and wildcard delegation stress NSEC3 denial. Add explicit
  ENT + wildcard NSEC3 test cases under the ENUM apex.

---

## Tracked checklist

- [x] **ADR-001** — placement ratified (single binary, in `dnsd`) — status line above says "Accepted... 2026-06-20"
- [x] **Topology** — single instance (A1, ENUM as a subtree of the existing signed zone) is what's actually deployed; two-instance (A2) not undertaken
  - [ ] If two: separate Valkey (or `DNS_VALKEY_DB`) per instance — isolates the
        **whole** keyspace incl. `dnssec:*` keys, `zone_table:*`, `stale:*`
  - [ ] If two: own working dir + distinct `CONFIG_PORT` per instance (boot file / portal)
  - [ ] If two: `config:bind4`/`bind6` per instance (specific IP, same ports); convert all `INADDR_ANY` sites (v4 + v6)
  - [ ] If two: `config:enable_mdns` / `_pki_renewal` / `_notify` toggles (ENUM=off)
  - [ ] If two: resolver routing `/e164.arpa/<enum-ip>` so queries reach ENUM
  - [ ] If two: distinct `config:syslog_ident` + `config:nsid` per instance
  - [ ] Note: A2 single-instance signed ⇒ per-zone DNSSEC keys (data already multi-zone)
- [x] **Add 6** — ENUM profile over NAPTR — done 2026-07-01, `make check-enum` in CI
  - [x] Add `config:enum_apex` (e.g. `e164.arpa` or `e164.example.local`) — `g_enum_apex`, `dns_server.c`
  - [x] Fix NAPTR value parsing for `|` in regexp/replacement (guardrail below) — split at LAST `|` (`dns_server.c` `DNS_TYPE_NAPTR` case)
  - [x] Optional: enumservice validation against the RFC 6117 registry — advisory `E2U+` prefix warning implemented (not the full IANA registry — that part is still not done, and is genuinely optional)
  - [ ] Optional: template synthesis from number ranges (DNSxL-style) — not built
  - [x] Acceptance: reversed-digit NAPTR query returns ordered rules; DNSSEC `ad` — covered by `make check-enum`
- [x] **Provisioning** — `+E.164` → reversed-name NAPTR key writer (dashboard/API) — done 2026-07-06: `POST /enum/provision` in `apid.c` (mgmt-only, mTLS-gated), one rule per call matching `/zone`'s convention; strips to digits, reverses under `config:enum_apex`, defaults order/pref/flags/ttl/replacement, rejects a `|` in `replacement` (the field the parser's LAST-`|` split can't tolerate), advisory-warns non-`E2U+` services. `make check-enum-provision` (drives the real HTTPS mTLS listener with curl, not a direct Valkey write) in CI.
- [ ] **Ops** — second systemd unit; dashboard ENUM backend; ENUM apex DS in parent
- [ ] **Test/CI** — two-instance isolation job; ENT + wildcard NSEC3 cases
- [ ] **Roadmap** — number portability (Option C trigger; RFC 4769)
- [ ] **Roadmap** — EPP federation for ENUM provisioning (RFC 4114/5076 via `eppd`)
- [x] **Doc** — add RFC 6116/6117/6118 + 3402/3403 to the header comment — done (`dns_server.c` header, `3403` corrected from the old "9250" mislabel; `3402` itself — the client-side DDDS algorithm — isn't separately listed since it's not something the server implements)

---

## Add 6: ENUM profile over NAPTR (RFC 6116)

### What it is

A profile that makes the server a clean authoritative ENUM source: it serves
NAPTR RRsets at reversed-digit E.164 names under a configured apex, with the
provisioning ergonomics and validation that distinguish "ENUM" from "raw NAPTR
serving."

### Name construction (RFC 6116 §2.4)

Strip the E.164 number to digits, reverse them, dot-separate, append the apex:

```
+44 20 7946 0000  ->  0.0.0.0.6.4.9.7.0.2.4.4.e164.arpa
+1 800 555 1234   ->  4.3.2.1.5.5.5.0.0.8.1.e164.arpa
```

A terminal NAPTR uses flags `"u"` (output is a URI), an `E2U+<service>` service
field, and a regexp that rewrites the full number (the Application-Unique
String) into the URI. The server stores and serves these verbatim; the client
applies the regexp.

```
;; for +1-800-555-1234
4.3.2.1.5.5.5.0.0.8.1.e164.arpa. IN NAPTR 100 10 "u" "E2U+sip"          "!^.*$!sip:info@example.com!"        .
4.3.2.1.5.5.5.0.0.8.1.e164.arpa. IN NAPTR 102 10 "u" "E2U+email:mailto" "!^.*$!mailto:info@example.com!"     .
```

### Exact location in current file

The NAPTR rdata encoder already exists in the `zone:<TYPE>:` parse switch:

| Need | Existing code |
|------|---------------|
| NAPTR rdata encode | `case DNS_TYPE_NAPTR:` — packs order/pref/flags/service/regexp/replacement |
| Value format | `zone:NAPTR:<name>` → `ttl\|order\|pref\|flags\|service\|regexp\|replacement` |
| Emission / DNSSEC | shared `emit_rr` + RRSIG path, same as every other type |

So a static ENUM record works **today** by writing the reversed-name key:

```
zone:NAPTR:4.3.2.1.5.5.5.0.0.8.1.e164.arpa
   = 3600|100|10|u|E2U+sip|!^.*$!sip:info@example.com!|.
```

### Key schema

```
config:enum_apex     Apex this server treats as an ENUM tree, e.g.
                     "e164.arpa" or "e164.example.local". Informational +
                     used by the provisioning helper to build names.
zone:NAPTR:<revname> Standard NAPTR value (existing format) at the
                     reversed-digit name under the apex.
```

### What to build

Most of this is provisioning and one parser fix; the serving path is reused.

1. `config:enum_apex` read on startup/SIGHUP (a `g_enum_apex[256]`).
2. The **NAPTR `|` parsing fix** (guardrail below) — required because ENUM
   regexps are richer than the simple NAPTR values tested so far.
3. Optional enumservice validation: warn when `service` is not a registered
   `E2U+...` type per RFC 6117.
4. Optional template synthesis (DNSxL-style): a handler that, for a query under
   `config:enum_apex` with no explicit `zone:NAPTR:` key, synthesizes a NAPTR
   from a number-range rule (`enum:range:<prefix>` → rule template). Keep the
   whole rule in one Valkey value to avoid extra round-trips under the global
   mutex.

### Guardrail (do NOT)

- **The `|` delimiter collides with NAPTR regexp/replacement.** The current
  `strtok(p2,"|")` parse splits on `|`, but an ENUM regexp or replacement may
  legally contain a literal `|`, which would mis-split the record. Pick one:
  - **Pragmatic:** document that `|` is forbidden inside ENUM regexp/replacement
    (the `!`-delimited forms above never need it), and validate on write; **or**
  - **Robust:** change the NAPTR value parse to split only the first four fields
    on `|` and treat `service`, then take `regexp` and `replacement` as the last
    two fields without further `|`-splitting (replacement is a hostname and
    carries no `|`). Do not naively `strtok` the whole string.
- **Do NOT** apply the regexp server-side. The authoritative server returns the
  NAPTR rule unchanged; rewriting the number into a URI is the client's job
  (RFC 6116 §2.4.1). Synthesizing a URI in `dnsd` is out of scope and wrong.
- **Do NOT** silently span two zones. If `config:enum_apex` is an independent
  apex (Option A2), it needs its own SOA and DNSSEC keys; until multi-zone is
  built, prefer the A1 subtree layout under the existing signed zone.
- **Do NOT** add a second Valkey lookup for template synthesis hints — one rule
  per key.

### Acceptance criteria

- A reversed-digit NAPTR query under the apex returns the rules in `order`/
  `preference` order with flags/service/regexp/replacement intact.
- A regexp containing the `!` delimiter round-trips byte-exact (the `|` fix
  holds).
- With `+dnssec`, an RRSIG covers the NAPTR RRset and the `ad` flag is set.
- An unknown `E2U+` service logs a validation warning but still serves (warn,
  don't refuse).

### Test

```bash
valkey-cli SET config:enum_apex "e164.arpa"
valkey-cli SET zone:NAPTR:4.3.2.1.5.5.5.0.0.8.1.e164.arpa \
  '3600|100|10|u|E2U+sip|!^.*$!sip:info@example.com!|.'
# (SIGHUP / POST /config)

dig @127.0.0.1 -p 5353 4.3.2.1.5.5.5.0.0.8.1.e164.arpa NAPTR
# Expect: 100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .

# Two rules, ordered:
valkey-cli SET zone:NAPTR:4.3.2.1.5.5.5.0.0.8.1.e164.arpa \
  '3600|102|10|u|E2U+email:mailto|!^.*$!mailto:info@example.com!|.'
# (re-query; verify both rules present and sorted by order)

dig @127.0.0.1 -p 5353 +dnssec 4.3.2.1.5.5.5.0.0.8.1.e164.arpa NAPTR \
  | grep -E 'RRSIG|flags:.* ad'
```

---

## Provisioning (control plane, not a daemon)

The ergonomic part of ENUM — turning `+1-800-555-1234` into the reversed-name
NAPTR keys — lives in the dashboard / management API, exactly like the rest of
the Valkey control plane. A minimal helper:

```
POST /enum/provision
{ "number": "+18005551234",
  "rules": [
    {"order":100,"pref":10,"service":"E2U+sip",
     "regexp":"!^.*$!sip:info@example.com!"},
    {"order":102,"pref":10,"service":"E2U+email:mailto",
     "regexp":"!^.*$!mailto:info@example.com!"}
  ] }
```

Server-side it: validates the E.164 number, builds the reversed name under
`config:enum_apex`, validates each `service` against the RFC 6117 registry,
applies the `|` guardrail, and writes the `zone:NAPTR:<revname>` value(s). This
is also where number-range template synthesis (`enum:range:<prefix>`) is
managed.

### Two provisioning paths: REST helper vs EPP federation

The REST helper above is the **standalone** path — fine when you own the ENUM
tree end to end. If instead you federate with a carrier/registry ENUM
ecosystem (Tier-1/Tier-2), numbers are provisioned via **EPP**, not REST:

- **RFC 4114** — E.164 Number Mapping for EPP: the EPP domain-object extension
  that provisions an ENUM name (the reversed-digit domain under `e164.arpa`)
  with its NAPTR rules.
- **RFC 5076** — ENUM Validation Information for EPP: the proof-of-control /
  validation data attached to an ENUM registration (who is allowed to map the
  number).

In that model the EPP front-end is `eppd` (see `CLAUDE-eppd.md`): registrars
provision E.164 numbers over EPP/TLS:700, `eppd` writes the resulting
`zone:NAPTR:<revname>` keys, and the ENUM `dnsd` instance serves them — same
Valkey bus, same served records, different ingress. Number portability
(RFC 4769, below) typically flows through this EPP/registry path too.

---

## Roadmap: number portability (Option C trigger)

Number portability (NP) is the one ENUM capability that genuinely pulls toward
the synthesis sidecar (Option C). Where static/template ENUM answers come from
Valkey, NP often requires a **real-time lookup** against an external routing
number / portability database to decide the carrier or routing URI for a number
that may have moved. RFC 4769 registers an Enumservice for conveying NP data.

### Why it is roadmap, not now

- It needs a **synchronous external dependency** (the NP database/dip), which is
  exactly the I/O that should not sit on the authoritative hot path.
- It is only relevant to deployments that actually carry ported numbers.

### How the topology helps (and where it does not)

- **Helps:** put NP on the **dedicated ENUM instance** (two-instance topology).
  Slow NP dips then cannot stall the main DNS instance's event loop — the
  blast radius of a slow/unavailable NP backend is contained to ENUM.
- **Does not replace async work:** within the ENUM instance, a synchronous dip
  still blocks *that* process's single-threaded `select()` loop. NP therefore
  still depends on the async/event-loop work in the migration plan. Isolation
  bounds the damage; it does not remove the need for non-blocking lookups.

### Shape when implemented

1. NP backend adapter (config: `config:np_backend`, e.g. an ENUM-tree dip, an
   SS7/SIP redirect source, or an HTTP lookup) — abstracted behind one call.
2. Synthesis handler on the ENUM instance: on a query with no static
   `zone:NAPTR:` rule, consult the NP backend, synthesize the NAPTR (E2U+pstn
   / RFC 4769 NP service), cache briefly in Valkey, serve.
3. Non-blocking lookup path (depends on migration async work) so a slow NP
   backend degrades gracefully (SERVFAIL/stale) rather than stalling ENUM.

### Acceptance (when built)

- A ported number resolves to the NP-derived routing URI; a non-ported number
  falls through to its static rule.
- An unavailable NP backend yields a bounded-latency SERVFAIL (or served-stale),
  never an indefinite stall, and never affects the DNS instance.

---

## Roadmap: EPP federation (registry-grade ENUM provisioning)

Standalone ENUM uses the REST helper above. To participate in a carrier/registry
ENUM ecosystem, provisioning moves to **EPP** via the `eppd` component
(`CLAUDE-eppd.md`):

- **RFC 4114** — E.164 Number Mapping for EPP (provision the reversed-digit
  ENUM domain + NAPTR rules over EPP).
- **RFC 5076** — ENUM Validation Information for EPP (control/validation data).

`eppd` writes the same `zone:NAPTR:<revname>` keys the REST helper would; the
ENUM `dnsd` instance serves them unchanged. This pairs with number portability
(RFC 4769), which in a federated deployment also arrives through the
EPP/registry path rather than a direct backend dip. Park until a federation
requirement is real; the standalone REST path covers self-contained ENUM.

---

## RFCs to add to the header comment

| RFC | What |
|-----|------|
| 6116 | E.164 to URI DDDS Application (ENUM) — core; obsoletes 3761/2916 |
| 6117 | IANA registration of Enumservices (the `E2U+...` registry) |
| 6118 | Guidelines / update for Enumservice registrations |
| 3402 | DDDS algorithm (the rewrite the *client* applies) |
| 3403 | DDDS DNS database — NAPTR record (the served record) |
| 5067 | Infrastructure ENUM requirements (only if Option A2 / private tree) |
| 4769 | Enumservice for number portability data (roadmap — Option C) |
| 4114 | E.164 Number Mapping for EPP (roadmap — EPP federation via eppd) |
| 5076 | ENUM Validation Information for EPP (roadmap — EPP federation via eppd) |

Note: this also gives a second, correct home for the NAPTR label that the
header currently mis-attributes to "9250" — NAPTR is **3403**; record that fix
alongside these additions.
