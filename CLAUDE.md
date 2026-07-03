# CLAUDE.md — Target architecture for the dns_server project

This document describes the **target** architecture and the migration path to
reach it. The current code is a single ~5000-line `dns_server.c` that bundles
the authoritative server, an mDNS responder, ACME and EST PKI clients, an
embedded HTTP/HTTPS management plane, a DoH endpoint, and a first-boot config
portal. Those concerns have different trust models, lifecycles, and failure
modes and must be separated.

Use this file to guide refactoring. Do not attempt the whole split in one pass —
follow the migration order at the bottom. Each step must leave the system
buildable and passing `make check`.

> `specs/CLAUDE-migration.md` is the step-by-step tracker. The prerequisite defect
> fixes (DNSSEC validation, `strtok` thread-safety, etc.) are **complete** —
> their spec is archived untracked at `specs/CLAUDE-fixes.md`; the work itself
> is documented in the migration tracker's Step 0 and the git history.

> Feature work plans (independent of the process split, coordinated with it):
> hidden-master / public-secondary deployment, A/AAAA rotation + health checks,
> out-of-zone forwarding, and automatic FQDN registration for VMs/containers
> are all **complete** — their specs are archived untracked at
> `specs/CLAUDE-{hidden-master,loadbalance,forwarder,discovery}.md`; the work
> itself is documented in `CLAUDE-roadmap.md` and the git history.

---

# Working in this repo (read first)

## Prerequisites

- **OpenSSL 3.0+ is required.** The crypto uses 3.x-only APIs (`EVP_MAC_fetch`,
  `OSSL_PARAM_construct_*`, `EVP_PKEY_fromdata`, `EVP_PKEY_CTX_new_from_name`).
  Building against 1.1.x fails with confusing errors. Verify with
  `openssl version` before debugging a build.
- A running **Valkey** for anything beyond compiling (default
  `127.0.0.1:6379`, no password): `valkey-server &`.
- `gcc` or `clang`, `make`, `pkg-config`, and for tests `dig` (dnsutils).

## Build / run / test (canonical commands)

The `Makefile` derives `OSSL_INC`/`OSSL_LIB` via `pkg-config` (correct
per-platform: Debian multiarch, Fedora `/usr/lib64`, Homebrew, …) and fails
fast with a clear message if the paths are wrong, so a bare `make` works on a
fresh checkout. Override only for a non-standard OpenSSL:
`make OSSL_INC=/opt/openssl/include OSSL_LIB=/opt/openssl/lib`.

```bash
# Debug build — ASan + UBSan, full symbols. Use this while iterating.
make debug

# Production binary WITHOUT signing (no GPG key needed; for local/CI builds).
make dns_server

# Full production build (optimised, stripped, GPG-signed). Needs a signing key.
make

# Run (binds 5353/udp+tcp, 8853 DoT, 8443 DoH/mgmt, 8053 HTTP). Valkey must be up.
./dns_server

# Smoke test (needs Valkey + dig).
make check

# DNSSEC known-answer + negative unit tests.
make check-dnssec

# Run under sanitizers with leak detection.
ASAN_OPTIONS=detect_leaks=1 ./dns_server_debug
```

(The CI workflow hardcodes Debian/Ubuntu paths because the runner image is
fixed; for local work rely on the Makefile's `pkg-config` derivation.)

Relevant env vars: `DNS_VALKEY_HOST`, `DNS_VALKEY_PORT`, `DNS_VALKEY_PASSWORD`,
`CONFIG_PORT` (first-boot portal), `LISTEN_PORT`. On first boot with Valkey
unreachable the server opens a config portal on `CONFIG_PORT` (default 8080).

## Repository map

| Path | What it is |
|---|---|
| `dns_wire.{c,h}` | **`libdnswire`** — the single shared wire-format implementation (migration Step 1, done). Fix parser bugs here, never per-binary. |
| `sandbox.{c,h}` | **`libsandbox`** — the single shared privilege-drop / chroot+mountns / seccomp implementation, linked by `dnsd` and `resolverd`. The caller fills a `sandbox_config_t` (daemon-scoped config + log callback + seccomp default + extra syscall groups) and calls `sandbox_apply()`. Fix sandbox bugs here, never per-binary. |
| `dns_server.c` | **`dnsd`** — the authoritative core (~3600 lines). ACME/EST extracted in Step 2, mDNS in Step 3, the HTTP/DoH/portal surface in Step 4. Now: DNS/DoT + localhost `/health`+`/metrics` only. |
| `certd.c` | **`certd`** — ACME + EST certificate sidecar (migration Step 2, done). Talks only to Valkey and the CA. |
| `mdnsd.c` | **`mdnsd`** — mDNS/DNS-SD responder (migration Step 3, done). Link-local only; explicit interface allowlist via `config:mdns_interfaces`. |
| `apid.c` | **`apid`** — HTTP/HTTPS front for DoH + management (migration Step 4, done). Forwards DoH to `dnsd`; all writes go to Valkey. |
| `resolverd.c` | **`resolverd`** — recursive/forwarding resolver + cache + DNSSEC **validation** (the recursive role; formerly `dns_client.c`). Distinct daemon from `dnsd`; own `make resolverd` target + `make check-resolverd`. |
| `simple_dns.c` | Smaller reference implementation; links `libdnswire` (Step 1 decision), uses non-compressing `append_rr_plain`. |
| `tests/` | Unit tests: `make check-dnssec` (DNSSEC known-answer + negative), `make check-wire` (name parser). |
| `fuzz/` | libFuzzer harness + corpus: `make fuzz-wire` (60s smoke; needs clang). |
| `dashboard/app.py` | Flask control-plane UI; talks to Valkey directly. |
| `Makefile` | Build/sign/install. |
| `keys/` | Code-signing key material. **Do not read, modify, or commit anything here.** |

Source-of-truth specs — ground protocol decisions in these, do not guess:
- RFC-coverage list and the full Valkey schema: header comment at `dns_server.c:1`.
- Valkey namespace ownership (who may write what): the table in this file.

## Do NOT

- **Do not edit the three parser copies independently.** Fix wire helpers once,
  in `libdnswire` (migration Step 1). Diverging copies are how past bugs spread.
- **Do not weaken or remove a bounds check** while refactoring. Preserve the
  `-1`-on-overflow convention in every wire helper and check it at call sites.
- **Do not introduce `strtok`** (use `strtok_r`) or any bare fixed-buffer copy
  (use `safe_strcpy` with a real `sizeof`).
- **Do not continue on a parse/alloc/crypto failure.** Fail closed: drop the
  request or return SERVFAIL; never serve partially-parsed data.
- **Do not write a Valkey namespace you do not own** (see the ownership table).
- **Do not generate, echo, commit, or hard-code signing keys or secrets**, and
  do not touch `keys/`. Secrets live in Valkey and are provisioned out of band.
- **Do not reformat unrelated code** inside a logic change. The clang-format
  reflow is a single isolated no-logic commit.
- **Do not claim a task is done on a clean compile alone** — run the
  verification protocol below.

## Verification protocol (run before reporting any task complete)

1. `make debug …` builds with no new warnings.
2. Run the relevant check and **show its output**, do not just assert success:
   - parser/wire change → the `libdnswire` unit tests + the `name_from_wire`
     fuzz target for ≥60s, and add the case to `fuzz/corpus` if it found one;
   - crypto change (TSIG/DNSSEC) → known-answer tests **and** the negative test
     (flipped byte must fail);
   - anything else → `make check`.

   > The targets (created in migration Step 1): `make check-wire` (parser unit
   > tests), `make fuzz-wire` (60s libFuzzer smoke on `name_from_wire`; needs
   > clang), `make check-dnssec` (DNSSEC/TSIG known-answer + negative tests).
3. Confirm the relevant **Acceptance** boxes in `specs/CLAUDE-migration.md` are
   satisfied.
4. Update any spec that changed: RFC list, Valkey schema, ownership table.

## When working on… read first

| Change type | Read |
|---|---|
| Wire parsing / record encoding | `libdnswire` (`dns_wire.*`), `tests/test_name_from_wire.c`, `fuzz/` |
| TSIG / DNSSEC | the crypto sections of `dns_server.c` / `resolverd.c`, `tests/test_dnssec_verify.c` |
| Process split / new daemon | this file (architecture + Valkey boundary), `specs/CLAUDE-migration.md` |
| Config / control plane | Valkey ownership table, `dashboard/app.py`, README schema |
| Build / CI | `Makefile`, `.github/workflows/ci.yml` |

---

## Design principles

1. **One responsibility per process.** A bug in a low-trust path (mDNS, an HTTP
   parser, an ACME JSON response) must not be a bug in the privileged
   authoritative daemon.
2. **Valkey is the integration bus.** Processes do not call each other
   directly. They communicate by reading and writing well-defined Valkey
   namespaces. This is the only contract between components.
3. **The authoritative daemon is the trusted core and stays small.** Everything
   that can live outside it, does.
4. **Least privilege.** Bind privileged resources, then drop. Sandbox the
   request-handling paths.
5. **One wire-format implementation.** No duplicated parsers.

---

## Target process topology

```
                         ┌─────────────────────────────┐
                         │           Valkey             │
                         │   (source of truth + bus)    │
                         └─────────────────────────────┘
        writes/reads          ▲     ▲     ▲     ▲          reads/writes
   ┌──────────────────────────┘     │     │     └──────────────────────────┐
   │                                 │     │                                 │
┌──┴───────┐   ┌──────────┐   ┌──────┴──┐  │   ┌──────────────┐   ┌──────────┴───┐
│  dnsd    │   │  mdnsd   │   │  certd  │  │   │  dashboard   │   │  resolverd   │
│ (auth.)  │   │ (mDNS)   │   │ (PKI)   │  │   │  (Flask UI)  │   │ (recursive)  │
└──────────┘   └──────────┘   └─────────┘  │   └──────────────┘   └──────────────┘
   ▲  ▲                                     │          ▲
   │  │ DoH / mgmt                          │          │ authenticated
   │  └──────────────────── apid ──────────────────────┘
   │ DNS / DoT (53, 853)         (HTTP/HTTPS front; writes Valkey,
 clients                          forwards DoH to dnsd's DNS port)
```

Shared code: **`libdnswire`** (`dns_wire.c` / `dns_wire.h`) linked by `dnsd`,
`mdnsd`, and `resolverd`.

---

## Components and ownership

### `dnsd` — authoritative DNS server (trusted core)

The minimal authoritative daemon. This is what `dns_server.c` becomes after the
other concerns are extracted.

Owns:
- UDP + TCP listeners (53), DNS-over-TLS (853).
- Query resolution against zone data, wildcards (4592), minimal-ANY (8482),
  QDCOUNT enforcement (9619).
- DNSSEC **signing** (ZSK/KSK, alg 13 + 15), NSEC/NSEC3 authenticated denial.
- Dynamic UPDATE (2136) + TSIG (8945) + zone-authority check (3007).
- AXFR/IXFR (5936/1995, journal-based) + NOTIFY (1996).
- EDNS (6891), cookies (9018), padding, EDE (8914), NSID.

Does **not** contain: mDNS, ACME, EST, the embedded HTTP/HTTPS management API,
the config portal, or DoH HTTP parsing.

Reads from Valkey: `config:*`, `zone:*`, `ddns:*`, DNSSEC key material, current
TLS `cert:*` blobs. Hot-reloads on Valkey keyspace notifications (see below).

Privilege: bind sockets as root, then `setuid`/`setgid` to an unprivileged
service account; confine the filesystem (`config:isolation_mode`: `chroot`
default, or `mountns` = private mount namespace + `pivot_root`); apply a
`seccomp` filter to worker threads. No outbound network except to Valkey.

### `mdnsd` — mDNS / DNS-SD responder (link-local, low trust)

**Done (migration Step 3):** `mdnsd.c`. Separate process. Joins IPv4/IPv6
multicast groups, answers `.local` queries and `_services._dns-sd._udp.local`
browse requests.

Reads from Valkey: `mdns:*`, `config:mdns_*`, and `zone:*` **read-only**
(shared records are served over both unicast DNS and mDNS — the pre-split
behavior). Never writes anything; never touches DNSSEC keys. Runs only on
interfaces it is explicitly configured for (`config:mdns_interfaces`:
comma-separated names, or `"all"` as an explicit opt-in) — never implicitly
all interfaces; it refuses to start unconfigured.

### `certd` — certificate manager sidecar (network-facing, low trust)

**Done (migration Step 2):** `certd.c`. All ACME and EST client code is out of
`dnsd`.

Owns: ACME directory/JWS/order flow, DNS-01 challenge orchestration, EST
mTLS enrollment, CSR generation, renewal scheduling (daemon mode checks daily;
`certd --once` for cron/manual runs).

Integration is entirely through Valkey:
- For ACME DNS-01: writes the challenge as a normal zone record
  (`zone:TXT:_acme-challenge.<domain>`), waits, then deletes it.
- On success: writes the issued cert chain + key to `cert:current` (one PEM
  blob). That is its only output — no `config:*`, no TLSA.
- `dnsd` watches `cert:current` and hot-reloads — it never speaks ACME/EST.
  On change, `dnsd` also publishes TLSA 3 1 1 (owner from the cert's SAN/CN),
  bumps the SOA serial and NOTIFYs — zone writes stay in the zone's owner.

This is the change that removes the most attacker-adjacent parser code from the
trusted core. `certd` is the only component (besides `resolverd`) that makes
arbitrary outbound connections.

### `resolverd` — recursive/forwarding resolver (separate role)

**Done.** `resolverd.c` (renamed from `dns_client.c`) is now a first-class
daemon with its own hardened `make resolverd` / `make resolverd_debug` targets
and a `make check-resolverd` smoke test (proxies through `dnsd`). This was the
last unbuilt piece of the target topology; the whole migration is now complete.

Keep it a distinct daemon — authoritative and recursive are different DNS roles
and must not share a process. Owns upstream UDP/TCP/DoT/DoH, the cache, and
DNSSEC **validation** (validation covers the full canonical RRset per
RFC 4034 §3.1.8.1 — guarded by `make check-dnssec`).

Sandbox (done): `resolverd` gets the same `dnsd`-style hardening via the shared
**`libsandbox`** (`sandbox.{c,h}`) — after its listeners bind it drops root
irreversibly, confines the filesystem (`chroot` default or `mountns` private
mount namespace + `pivot_root`), then installs a `seccomp` syscall filter, all
before the serve loop touches untrusted query/response bytes. The hardening logic
lives once in `sandbox.c`; `resolverd` only supplies a `sandbox_config_t`.
Config is **resolverd-scoped** (it needs a different filesystem view and syscall
set — it makes outbound connections and resolves upstream hostnames, so its
chroot must carry resolver files + a CA bundle):
`config:resolverd_{chroot_dir,isolation_mode,privdrop_user,privdrop_group,
seccomp_mode}` (env `RESOLVERD_{CHROOT,ISOLATION,USER,GROUP,SECCOMP}`). All config
is read **before** the chroot, so a chroot that hides Valkey cannot silently
downgrade the seccomp mode. The seccomp layer defaults to **enforce**: the
whitelist was strace-harvested across every upstream transport (UDP/TCP/DoT-TLS/
DoH, IP + hostname/getaddrinfo upstreams, cache miss/hit, DNSSEC validation) on
glibc/Fedora and confirmed to issue no syscall outside `sandbox.c`'s base[] +
getaddrinfo group (zero gaps; no EPERM observed under enforce). On a different
libc/kernel, set `seccomp_mode=audit` first, confirm the audit log is clean, then
return to `enforce`. To survive the chroot, `resolverd` eagerly loads the
TLS trust store (the system default CA *file*, or `DOT_CA_PEM`) at startup before
confinement — `SSL_CTX_set_default_verify_paths` alone is lazy and would fail
upstream cert verification once `/etc/ssl` is gone. (Its build carries
`-Wno-misleading-indentation` because the dense — but clang-format-conformant —
style trips that gcc heuristic; not a reformat TODO.)

Reads/writes Valkey: its persisted cache namespace only. It does not read the
authoritative zone.

### Control plane: `apid` + `dashboard`

- **Done (migration Step 4):** `apid.c`. Instead of nginx/envoy the project
  uses a small in-house front (decision recorded in `specs/CLAUDE-migration.md`).
  `apid` terminates HTTP/HTTPS, serves DoH by forwarding the DNS message to
  `dnsd`'s loopback DNS port (UDP, TCP retry on truncation — it never parses
  DNS payloads), and serves the management API by writing **Valkey only**
  (it calls nothing inside `dnsd`). This removed the hand-rolled
  HTTP/HTTPS/mTLS server, `url_decode`, `qs_get`, `handle_api`, `handle_doh`
  and the first-boot config portal from `dnsd`.
  - Auth: the HTTPS listener treats a request as management only when a client
    cert verifies against `config:mtls_ca_pem` (mTLS); plain HTTP allows DoH,
    read-only `/list`, and DDNS `/update` gated by `config:ddns_secret`.
  - Because `apid` is the relocated embedded API, it inherits that API's Valkey
    writes (`config:*`, `zone:*` records, `ddns:*`) — see the ownership table.
    `dnsd` applies `config:*`/`zone_table:*` changes live via Valkey keyspace
    notifications (migration Step 6); zone records are read live per query.
- `dashboard/app.py` (Flask) is the control-plane UI. **Done (migration
  Step 5):** it now authenticates — single admin account (werkzeug scrypt
  hash), signed-cookie sessions, a global `before_request` gate, `/login`+
  `/logout`, per-IP login backoff; it refuses to start without a password
  configured. The raw Valkey Explorer is read-only unless explicitly opted in
  (`DASHBOARD_ENABLE_EXPLORER_WRITE=1`) and never reads/writes secret-bearing
  keys (`dnssec:*`, `*secret*`, `cookie_secret`, `*_key`, `key_pem`, `tsig`) —
  those are masked on display and managed only via the dedicated pages.
  Credential provisioning/rotation: see `dashboard/README.md`.
- `dnsd` exposes only a tiny read-only `/health` + `/metrics` (Prometheus)
  bound to **localhost** (`config:metrics_port`, default 8054), scraped by
  `apid`'s `/metrics` proxy. All write operations go through Valkey, not an
  embedded API.

### `libdnswire` — shared wire-format library

Factor the duplicated primitives (`name_from_wire`, `name_to_wire`,
`append_rr`, `get16/put16/get32/put32`, `txt_encode`, hex/base64 helpers) out of
`dns_server.c`, `resolverd.c`, and `simple_dns.c` into one module. All three
binaries link it. This eliminates the divergence-bug class (e.g. a parser fix
applied to one copy but not the others).

`simple_dns.c`: if it is a teaching/reference artifact, label it as such and
exclude it from the production build. If it is live, it must also use
`libdnswire` rather than its own copies.

---

## The Valkey boundary (integration contract)

Each namespace has exactly one writer *category*. The control plane is that
category for `config:*`/`zone:*`/`ddns:*`: it is the dashboard **and** `apid`
(the relocated management API — Step 4), which are the two authenticated
HTTP front-ends. Define and enforce this.

| Namespace | Writer | Readers | Purpose |
|---|---|---|---|
| `config:*` | dashboard, apid (mgmt API) | dnsd, mdnsd, resolverd, certd, apid | Runtime configuration |
| `zone:*` | dashboard, apid (mgmt API), certd (challenge TXT only), dnsd (TLSA on cert change; apex ZONEMD digest, RFC 8976) | dnsd, mdnsd (shared records, read-only) | Authoritative records |
| `ddns:*` | dnsd (RFC 2136 UPDATE), apid (HTTP `/update`, `ddns_secret`-gated) | dnsd | Dynamic records |
| `srp:*` | dnsd (RFC 9665 SRP UPDATE, SIG(0)-authenticated, `config:srp_enabled`-gated) | dnsd (mdnsd read-only in a future add) | Service-registration records + FCFS ownership + lease/key-lease expiry (RFC 9664) |
| `ixfr:*` | dnsd (records each A/AAAA change) | dnsd | RFC 1995 IXFR journal (incremental diff; gap → AXFR fallback) |
| `mdns:*` | dashboard | mdnsd | mDNS/DNS-SD records |
| `dnssec:*` | dnsd / key tooling | dnsd | ZSK/KSK material |
| `cert:current` | certd | dnsd (hot-reload) | Active TLS cert + key |
| `acme:*` | certd | certd | ACME account key, order state |
| `cache:*` | resolverd | resolverd | Persisted resolver cache |
| `metrics:*` (or live `/metrics`) | each daemon | dashboard | Observability |
| `schema:version` | dnsd (seeds on absent) | dnsd, mdnsd, resolverd, certd, apid | ADR-003 schema-version contract (`major.minor`) |

**Live reload (done — migration Step 6):** each daemon runs a subscriber on a
dedicated Valkey connection, enables keyspace notifications
(`notify-keyspace-events KEA`) and PSUBSCRIBEs to the prefixes it owns, so
dashboard edits and `cert:current` updates take effect without a restart —
no more SIGHUP / `POST /config`. `dnsd` watches `config:*`, `cert:current`,
`zone_table:*`, and `dnssec:*` (reloads that zone's key state live — current set
plus any rollover/next set); `apid` watches
`cert:current` + the TLS config keys; `mdnsd` watches `mdns:*` + `config:mdns_*`
and re-announces. zone/ddns records are already read live per query.
Subscribers re-run a full catch-up after every reconnect and use capped
backoff, so a Valkey restart causes neither missed updates nor a reconnect
storm.

### Schema versioning + format registry (ADR-003, done — Phase 1)

The Valkey bus is a **versioned contract**, not an ad-hoc set of strings
(`CLAUDE-architecture.md` ADR-003, Accepted option C):

- **Version key.** `schema:version` holds `major.minor` (current **1.0**). Every
  daemon compares it against its compiled `SCHEMA_VERSION` at startup via
  `schema_version_check()` (in `libdnswire`): a **major** mismatch is fatal —
  the daemon refuses to start; a **minor** mismatch warns and continues
  (minor = additive). `dnsd` is the **seeder** (writes the key when absent); the
  others only read it. Valkey-down/absent is treated as "assume current" and
  never blocks boot.
- **Compatibility rule.** Within a major: additive only — new **optional
  trailing** fields; readers must tolerate unknown trailing fields (and, for
  TLV, unknown tags). Any breaking change bumps the major **and** ships a
  migration under `tools/`.
- **Encoding policy (the registry).** Two encodings, chosen per value:

  | Value kind | Encoding | Examples |
  |---|---|---|
  | Simple, stable scalars | **pipe** `a\|b\|c` (unchanged) | `config:*`, `ddns:A`/`AAAA` (`ttl\|ip`), SOA timers, `zone_table:*` scalars |
  | Complex / extensible | **versioned TLV** (`tlv_*`, see `dns_wire.h`) | SVCB/HTTPS SvcParams, NAPTR, ZONEMD, ENUM rules, EPP objects — everything ADR-003 keeps off the fragile `\|` delimiter |

  TLV layout: `version(1) { tag(1) len(2,BE) value(len) }*` — bounds-checked,
  fail-closed, readers skip unknown tags. **New complex record types (Phase 2)
  land on TLV, not pipe.** Pipe stays only where a field can never contain `|`
  and the field set is fixed. The codec is unit-tested (`make check-wire`) and
  fuzzed (`make fuzz-tlv`).

---

## Trust boundaries

- **Internet-facing, untrusted input:** `dnsd` (DNS wire), `resolverd`
  (upstream responses), the reverse proxy (HTTP/TLS). These get the strongest
  sandboxing.
- **Outbound network:** only `certd` (to the CA / EST server) and `resolverd`
  (to upstreams). `dnsd` should reach nothing but Valkey.
- **Link-local:** `mdnsd` only.
- **Privileged secrets** (TSIG key, cookie secret, DNSSEC private keys) live in
  Valkey and are read by `dnsd` only. The control plane must authenticate before
  it can read or write them.

---

## Multi-zone (migration Step 7 — done, incl. automated ZSK rollover)

`dnsd` serves multiple authoritative zones (it is no longer single-zone):
- Records are keyed `zone:<zonename>:<type>:<name>` and per-zone config as
  `config:zone:<zonename>:*` (NSEC3 params, denial mode, serial). Zone SOA +
  transfer settings live in `zone_table:<zonename>`; DNSSEC keys in
  `dnssec:<zonename>:*`.
- `dnsd` selects the most specific configured zone per query (longest-suffix
  match), and that zone drives SOA, NSEC/NSEC3 denial, and DNSSEC signing keys
  for the whole response. The same selection scopes UPDATE writes and AXFR.
- The primary zone (`config:zone_name`) seeds itself from the legacy global
  `config:*`/`dnssec:*` keys, so a single-zone deployment keeps its existing
  DS/keytags. Existing data is migrated with `tools/migrate-multizone.sh`.
- `apid` and the dashboard resolve the owning zone by longest-suffix match
  before writing `zone:<zone>:*` / `ddns:<zone>:*`.

- Automated per-zone DNSSEC **ZSK rollover** (RFC 6781 §4.1.1.1 Pre-Publish): a
  background engine publishes the incoming ZSK alongside the current one, switches
  the signer to it only after the publish hold, and retires the old key only after
  the commit hold — so a validator always holds the key its RRSIG points at. State
  lives in `dnssec:<zone>:zsk_{created,rollover,next,ed25519_next,rollover_seen}`;
  timing/trigger knobs in `config:[zone:<zone>:]{zsk_validity,rollover_publish_hold,
  rollover_commit_hold,zsk_rollover_request,rollover_tick_secs}`. `dnssec:*` now
  reloads live (no longer restart-flagged). Covered by `make check-dnssec`
  (`tests/test_rollover.c`: per-phase no-validation-gap KAT + negative).

- Automated per-zone DNSSEC **KSK rollover** (RFC 6781 §4.1.2 Double-Signature)
  with CDS/CDNSKEY parent signalling (RFC 7344/8078): the DNSKEY RRset is signed
  by both the old and new KSK throughout the roll while CDS/CDNSKEY advertises
  the DS to publish — {old,new} in the `double` phase, {new} in `retire` — so the
  parent's DS always matches a KSK that signed the published DNSKEY. State in
  `dnssec:<zone>:ksk_{created,rollover,next,ed25519_next,rollover_seen}`; knobs in
  `config:[zone:<zone>:]{ksk_validity,ksk_publish_hold,ksk_commit_hold,ksk_rollover_request}`.
  CDS/CDNSKEY carry DS-format rdata over the KSK (identical to the DS answer by
  construction), guarded by `make check-cds`; KSK no-gap KAT in
  `tests/test_rollover.c`.

- Catalog zones (RFC 9432) for bulk provisioning: `dnsd` consumes a catalog
  zone — an ordinary `zone_table:<cat>` zone carrying the schema-version record
  `version.<cat> TXT "2"` and one `<id>.zones.<cat> PTR <member>` per member —
  and provisions each member into its in-memory zone table (SOA names derived
  from the member, SOA timers / AXFR ACL / NOTIFY inherited from the catalog,
  `dnssec:<member>:*` keys generated via the normal path). Members the catalog
  stops listing are deactivated. dnsd only *reads* the catalog (`zone:<cat>:*`,
  written by the control plane) and writes only `dnssec:<member>:*` (which it
  already owns) — it never writes `zone_table:*`; provisioning is in-memory,
  re-derived on each scan (boot, `config:` / `zone_table:` change, rollover
  tick). Selectable filesystem isolation (`config:isolation_mode` =
  `chroot` (default) or `mountns`, a private mount namespace + `pivot_root`)
  rounds out the sandbox. Guarded by `make check-catalog`.

---

## Migration order

Each step is independently shippable and must pass `make debug`, `make`, and
`make check`.

1. **Extract `libdnswire`.** Move the shared wire helpers into `dns_wire.{c,h}`;
   point all three `.c` files at it. No behavior change. (Also lets parser
   fixes — `name_from_wire` hardening, `strtok_r` — be made once instead of
   three times.)
2. **Split out `certd`.** Move ACME + EST + renewal thread into a new binary
   that talks only through Valkey (`zone:TXT:_acme-challenge.*` and
   `cert:current`). Make `dnsd` watch `cert:current` and hot-reload. Remove the
   ACME/EST code from `dns_server.c`.
3. **Split out `mdnsd`.** Move the mDNS responder into its own binary reading
   `mdns:*`. Remove multicast handling from `dnsd`.
4. **Front the HTTP surfaces with `apid`** (in-house, chosen over nginx/envoy)
   and reduce `dnsd` to a localhost-only read-only `/health` + `/metrics`.
   Removed the embedded management API, config portal, and DoH HTTP parsing
   from the C core.
5. **Add control-plane authentication** to the dashboard; restrict or remove the
   raw Valkey Explorer write path.
6. **Enable Valkey keyspace-notification live reload** across daemons.
7. **Add multi-zone support** in the now-minimal `dnsd`. *(Done: re-keyed
   `zone:<zone>:*` storage, longest-suffix zone selection, per-zone SOA / NSEC3
   / DNSSEC keys / AXFR / NOTIFY / UPDATE, `tools/migrate-multizone.sh`, apid +
   dashboard zone resolution, automated per-zone ZSK **and** KSK rollover
   (RFC 6781 Pre-Publish + Double-Signature, CDS/CDNSKEY per RFC 7344/8078), and
   catalog zones (RFC 9432). All done.)*

After step 4, `dnsd` should be a substantially smaller, single-purpose,
sandboxable daemon — the trusted core this architecture is designed to produce.

Steps 1–7, the optional follow-ups (catalog zones, mount-namespace isolation),
and the `resolverd` split (`dns_client.c` → `resolverd.c`, now a first-class
hardened daemon — see the `resolverd` section above) are **all complete**. The
monolith is fully decomposed and every box in `specs/CLAUDE-migration.md` is ticked.
Remaining work is feature/quality, not migration: the optional plans
(`CLAUDE-{hidden-master,loadbalance,forwarder,discovery,DoQ,sec}.md`). The
performance work (baseline + SO_REUSEPORT workers, in-process record cache,
stale-shadow throttle, recvmmsg/sendmmsg batching) is done and archived at
`specs/CLAUDE-performance.md`.
The `dnsd`-style privilege-drop / seccomp / mount-isolation sandbox has been
extended to `resolverd` and **factored into the shared `libsandbox`**
(`sandbox.{c,h}`), so `dnsd` and `resolverd` now share one implementation
(no duplicated copy to diverge). Both `dnsd` and `resolverd` now default seccomp
to `enforce` (resolverd's whitelist was harvest-validated across all upstream
transports on glibc/Fedora); re-harvest with `seccomp_mode=audit` only when
porting to a different libc/kernel.

---

## Build system implications

- `libdnswire` builds first; `dnsd`, `mdnsd`, `resolverd` link it.
- Each daemon gets its own `make` target and its own signed production binary.
- `make check` should bring up Valkey, start `dnsd` (plus `certd`/`mdnsd` where
  relevant), and smoke-test each independently.
- Keep the existing hardening flags (`-fstack-protector-strong`,
  `_FORTIFY_SOURCE=2`, PIE, RELRO/now) for every binary. (The old
  world-writable `OSSL_INC` default is fixed: paths derive via `pkg-config`
  with an `ossl-sanity` fail-fast check.)

---

## Development process & code quality

These practices exist because of the bug classes already found in this codebase:
a parser duplicated across three files (fixes diverge), a constant silently
written wrong (`fudge=300` encoded as 5) that dense one-line-per-many-statements
style hid, and crypto verification that compiled and "passed" while covering the
wrong bytes. The daemon parses untrusted input from the internet, so the bar is
correctness under hostile input, not just working on a happy-path `dig`.

### Testing (highest-leverage gap)

`make check` is a single happy-path smoke test. That is not enough.

- **Unit tests for `libdnswire`.** Every wire helper (`name_from_wire`,
  `name_to_wire`, `append_rr`, `txt_encode`, hex/base64) gets table-driven tests
  including malformed input: truncated packets, oversized labels, names >255,
  compression pointers that loop, point forward, or point out of bounds.
- **Fuzzing is mandatory for the parser surface.** Add libFuzzer/AFL++ targets
  built against the ASan+UBSan toolchain for: `name_from_wire`, the full DNS
  message parser, TSIG RR parsing, and (until removed) the DoH/HTTP and ACME
  JSON parsers. Keep a seed corpus and a regression corpus. Every parser bug
  fixed must add the triggering input to the corpus.
- **Crypto correctness tests.** DNSSEC verify and TSIG must have known-answer
  tests *and* negative tests (one flipped byte → fail). A verifier that only
  ever sees valid input is untested. (`make check-dnssec` covers DNSSEC.)
- **Differential testing.** Compare `dnsd` responses to a reference resolver
  (`dig`, or Knot/BIND) over a query matrix; diffs are either bugs or documented
  intentional deviations.

### Continuous integration

CI must run on every change and block merge on failure:
- [ ] Build all targets with `-Werror` (promote the current warning set; do not
      silently carry `-Wno-*` suppressions into new code)
- [ ] ASan + UBSan build, then run the unit + smoke tests under it
- [ ] A short fuzz smoke run (e.g. 60s per target) plus full replay of the
      regression corpus
- [ ] Static analysis: `clang --analyze` (scan-build), `clang-tidy`, `cppcheck`
- [ ] `make verify` — confirm the production binary signatures validate
- [ ] (Periodic) Valgrind over the smoke test for leak/uninit detection

### Code style & reviewability

- Add a `.clang-format` and run it on all new and changed code. Existing files
  can be reformatted in a single isolated "no-logic-change" commit so it does
  not pollute future diffs.
- **One statement per line; one declaration per line.** The dense style is how
  the `fudge` byte error and similar slips survive review. This rule applies to
  new and modified code regardless of the surrounding style.
- Magic protocol constants get named `#define`s (fudge, ports, type numbers,
  buffer sizes), defined once and shared — never repeated as bare literals at
  multiple emit sites.

### Memory-safety & error-handling conventions

- No bare fixed-buffer copies. Use the `safe_strcpy` helper (in `libdnswire`);
  pass real `sizeof` sizes, never hardcoded lengths.
- Wire helpers return `-1` on overflow/error and callers must check it before
  advancing offsets — preserve this convention everywhere.
- **Fail closed.** On parse error, allocation failure, or crypto failure, drop
  the request / return SERVFAIL; never serve partially-parsed data.
- Check return values of `setsockopt`, `bind`, allocation, and OpenSSL calls.
  Several socket-option and verify calls currently ignore their result — new and
  touched code must not.

### Security-sensitive change gate

Changes to any of these get a second reviewer and explicit test evidence in the
PR: DNS wire parsing, TSIG/DNSSEC crypto, the privilege-drop / sandbox path, the
Valkey trust boundary (namespace ownership), and TLS/cert handling. The PR must
state what hostile inputs were considered and which tests/fuzz cases cover them.

### Definition of Done (per change)

- [ ] Tests added/updated (unit + fuzz corpus entry for any parser change)
- [ ] `make debug` (ASan/UBSan) and `make` build clean with `-Werror`
- [ ] CI green (analysis + sanitizers + corpus replay)
- [ ] `clang-format` applied to touched code; no new bare `strtok`/fixed-buffer copies
- [ ] Docs in sync: RFC-coverage list, Valkey schema, and the `CLAUDE.md`
      topology/ownership table reflect the change
- [ ] Security-sensitive gate satisfied if applicable

### Documentation hygiene

The README's RFC-coverage list and the Valkey schema are the project's
contract. Update them in the same change that alters behavior, and keep the
namespace ownership table in this file authoritative — if code writes a
namespace not listed there, one of them is wrong.
