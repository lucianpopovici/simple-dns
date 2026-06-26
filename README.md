# simple-dns

A small authoritative DNS server with a Valkey-backed control plane and a Flask
dashboard. It began as one ~5000-line `dns_server.c` and has been decomposed
into a set of single-purpose daemons that share one wire-format library and
integrate only through Valkey — so a bug in a low-trust path (mDNS, an HTTP
parser, an ACME JSON response) can't be a bug in the privileged authoritative
core. It still covers a production surface area: DNSSEC, dynamic updates, zone
transfers, DNS-over-TLS, DNS-over-HTTPS, mDNS/DNS-SD, and ACME/EST PKI.

The full target architecture and the migration that produced it are documented
in `CLAUDE.md` and `CLAUDE-migration.md`.

## Architecture

Processes don't call each other — **Valkey is the integration bus**, and each
namespace has exactly one writer category (see `CLAUDE.md` for the ownership
table). Edits made through the control plane take effect live via Valkey
keyspace notifications; no restarts.

```
                       ┌─────────────────────────────┐
                       │           Valkey            │
                       │   source of truth + bus     │
                       └─────────────────────────────┘
     ▲      ▲        ▲             ▲              ▲          ▲
     │      │        │             │              │          │
 ┌───┴──┐ ┌─┴────┐ ┌─┴────┐   ┌────┴─────┐   ┌────┴─────┐  (reads/writes)
 │ dnsd │ │mdnsd │ │certd │   │   apid   │   │dashboard │
 │auth. │ │ mDNS │ │ PKI  │   │HTTP/DoH/ │   │ Flask UI │
 │      │ │      │ │      │   │   mgmt   │   │          │
 └──┬───┘ └──────┘ └──────┘   └────┬─────┘   └──────────┘
    │ DNS 53 / DoT 853                │ DoH + mgmt (8053/8443)
  clients                          clients
```

| Daemon | Role | Listens on | Talks to |
|---|---|---|---|
| **`dnsd`** (`dns_server.c`) | Authoritative core: query resolution, DNSSEC signing, UPDATE/TSIG, AXFR/IXFR/NOTIFY, EDNS/cookies | `5353/udp+tcp` (DNS), `8853` (DoT), `127.0.0.1:8054` (read-only `/health`+`/metrics`) | Valkey only |
| **`certd`** (`certd.c`) | ACME (RFC 8555, DNS-01) + EST (RFC 7030) cert issuance/renewal | — (outbound to the CA) | Valkey + CA |
| **`mdnsd`** (`mdnsd.c`) | mDNS (RFC 6762) + DNS-SD (RFC 6763) responder, link-local | `5353` multicast on explicitly-configured interfaces | Valkey (read) |
| **`apid`** (`apid.c`) | HTTP/HTTPS front: DoH + management API | `8053` (HTTP), `8443` (HTTPS/mTLS) | Valkey + dnsd (DoH forward) |
| **`dashboard`** (`dashboard/app.py`) | Authenticated control-plane UI | `127.0.0.1:5000` (configurable) | Valkey |

Shared code: **`libdnswire`** (`dns_wire.c` / `dns_wire.h`) — the single
wire-format implementation (name parsing/encoding, RR append, base64/hex, …)
linked by every binary.

## Components

| Path | What it is |
|---|---|
| `dns_server.c` | `dnsd`, the authoritative core. |
| `certd.c` | `certd`, the ACME/EST certificate sidecar. |
| `mdnsd.c` | `mdnsd`, the mDNS/DNS-SD responder. |
| `apid.c` | `apid`, the HTTP/HTTPS front for DoH + management. |
| `dns_wire.{c,h}` | `libdnswire`, the shared wire-format library. |
| `sandbox.{c,h}` | `libsandbox`, the shared privilege-drop / chroot+mountns / seccomp sandbox, linked by `dnsd` and `resolverd`. |
| `resolverd.c` | `resolverd`, the recursive/forwarding resolver + cache + DNSSEC validation (the recursive role; formerly `dns_client.c`). |
| `simple_dns.c` | Smaller reference implementation; links `libdnswire`. |
| `dashboard/` | Flask control-plane UI (see [Dashboard](#dashboard)). |
| `tests/`, `fuzz/` | Unit tests (`make check-dnssec`, `make check-wire`) and a libFuzzer harness (`make fuzz-wire`). |
| `Makefile` | Per-binary production + debug builds, GPG/OpenSSL signing, install. |

## Quick start

```bash
# 1. Build. `make` builds + GPG-signs dnsd (needs a signing key); for local/CI
#    use the unsigned per-binary targets:
make dns_server certd mdnsd apid resolverd   # stripped, hardened production binaries (unsigned)
make debug                           # dnsd ASan/UBSan build → dns_server_debug

# 2. Valkey on 127.0.0.1:6379 (or set DNS_VALKEY_HOST / _PORT / _PASSWORD)
valkey-server &

# 3. Run the authoritative core (binds 5353 udp+tcp, 8853 DoT, 127.0.0.1:8054)
./dns_server

# 4. (optional) the sidecars — each only needs Valkey
./apid                               # DoH + management on 8053/8443
./certd --once                       # one ACME/EST renewal check (or run as a daemon)
./mdnsd                              # needs config:mdns_enabled=1 + config:mdns_interfaces
```

If Valkey is unreachable at startup, `dnsd` retries (≈1 min) and then exits with
a clear error — provision the connection via the env vars or a `dns_server.boot`
file (`VALKEY_HOST=…` lines). There is no first-boot HTTP portal.

OpenSSL ≥ 3.0 is required. The `Makefile` derives `OSSL_INC`/`OSSL_LIB` via
`pkg-config`; override them only for a non-standard install.

## Standards implemented

`dnsd`'s header comment (`dns_server.c:1`) keeps the authoritative list. At a
glance:

- **Core / queries**: RFC 1034/1035, 2181, 2308, 9077 (negative-response
  NSEC/NSEC3 + SOA TTL = min(SOA.MINIMUM, SOA-TTL)), 4592 wildcards, 6303
  locally-served zones, 8482 minimal-ANY, 9619 QDCOUNT enforcement.
- **Record types**: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV (2782),
  CAA (8659), SSHFP (4255), TLSA/DANE (6698/7671), LOC (1876), URI (7553),
  NAPTR (stub), DNAME (6672), CDS/CDNSKEY (7344/8078).
- **DNSSEC**: RFC 4033–4035, 9364. ZSK + KSK with algorithm 13 (ECDSA P-256)
  and algorithm 15 (Ed25519, RFC 8080). NSEC (4034) and NSEC3 (5155)
  authenticated denial. Validation (in `resolverd.c`) covers the full
  canonical RRset per RFC 4034 §3.1.8.1. Automated per-zone ZSK rollover
  follows RFC 6781 §4.1.1.1 (Pre-Publish): the incoming key is published
  alongside the current one before the signer switches, and the old key is
  retired only after old signatures expire from caches — so a validator always
  holds the key its RRSIG points at.
- **Dynamic operation**: NOTIFY (1996) — TSIG-signed and retried in the
  background until the secondary acknowledges — AXFR (5936), IXFR (1995,
  journal-based diffs), UPDATE (2136) with TSIG (8945) and the zone-authority
  check (3007). A
  lease-expiry sweeper turns a silently-expiring `ddns:*` lease into a real
  replicated deletion (serial bump + IXFR delete + NOTIFY) so secondaries don't
  keep serving a dead workload's name.
- **Reverse DNS**: `dnsd` serves `in-addr.arpa` / `ip6.arpa` zones (PTR queries
  + AXFR) like any other zone (longest-suffix selection). With
  `config:ddns_auto_ptr` set, a forward A/AAAA DDNS registration also creates and
  retracts the matching reverse PTR lease in whichever reverse zone is configured
  locally — so discovered hosts get reverse DNS automatically.
- **Load balancing**: per-response A/AAAA rotation (`config:lb_mode` =
  `rr`/`random`) plus optional TCP health checks (`config:lb_health_*`) that drop
  down backends from answers and fail open when all are down. Local serving
  policy — set it on the public secondaries; it never travels in AXFR/IXFR.
- **Multi-zone / provisioning**: `dnsd` serves multiple zones (longest-suffix
  selection, per-zone SOA / DNSSEC keys / AXFR / UPDATE). Catalog zones
  (RFC 9432) bulk-provision member zones: a catalog is a `zone_table:<cat>` zone
  with `version.<cat> TXT "2"` and `<id>.zones.<cat> PTR <member>` records;
  `dnsd` consumes it and auto-provisions each member (derived SOA, inherited
  timers/ACL/NOTIFY, generated DNSSEC keys), deactivating members the catalog
  drops — all in-memory, without writing `zone_table:*`.
- **EDNS / transport**: 6891 OPT, 5001 NSID, 7828 TCP-keepalive, 7830/8467
  padding, 8914 EDE, DNS Cookies (RFC 7873) — `dnsd` is the server side (real
  SipHash-2-4, 9018 server cookies, BADCOOKIE), and `resolverd` is the client
  side: a stable per-upstream Client Cookie, learns and reuses the Server Cookie,
  and retries once on BADCOOKIE (RCODE 23). 9715 / Flag Day 2020 fragmentation
  avoidance: `dnsd` advertises a 1232-byte EDNS buffer and caps the *effective*
  UDP response at 1232 even when a client advertises more, setting TC so the
  client retries over TCP rather than emitting a fragmentable datagram.
- **mDNS / DNS-SD** (`mdnsd`): 6762 + 6763, dual-stack IPv4 + IPv6.
- **PKI bootstrap** (`certd`): ACME (8555, DNS-01) and EST (7030) over mTLS.

## Configuration

All runtime configuration lives in Valkey under `config:*`. Daemons subscribe to
the keys they own and apply changes **live** via keyspace notifications — no
SIGHUP, no `POST /config`, no restart (`dnsd` keeps a SIGHUP handler only as a
manual fallback). Valkey connection details come from, in precedence order:

1. Env: `DNS_VALKEY_HOST`, `DNS_VALKEY_PORT`, `DNS_VALKEY_PASSWORD`.
2. A `dns_server.boot` file in the working directory.
3. Defaults: `127.0.0.1:6379`, no password.

The full schema is in the `dns_server.c` header comment; the most-edited keys:

| Key | Purpose |
|---|---|
| `config:zone_name` | Primary authoritative zone (default `example.local`). Additional zones are added via `zone_table:<zone>`. |
| `config:soa_*` | Default SOA `mname`, `rname`, `refresh`, `retry`, `expire`, `minimum` for the primary zone. |
| `config:soa_ttl` | TTL the SOA RR is served with (default: unset → `soa_minimum`). Negative-response NSEC/NSEC3 + authority SOA are capped at `min(soa_ttl, soa_minimum)` per RFC 9077. Per-zone override: `config:zone:<zone>:soa_ttl`. |
| `config:zone_serial` | Primary zone SOA serial; other zones use `config:zone:<zone>:serial`. |
| `config:tsig_key_name` / `config:tsig_secret_b64` | TSIG HMAC-SHA256 key for UPDATE/AXFR/NOTIFY. |
| `config:cookie_secret` | 16-byte hex; key for DNS Cookies SipHash. Random if absent. |
| `config:axfr_allow` | Comma-separated IPs/CIDRs allowed to do AXFR/IXFR. |
| `config:notify_targets` | Comma-separated `IP:port` recipients for NOTIFY on zone change. |
| `config:ddns_auto_ptr` | When set, a forward A/AAAA DDNS registration also maintains the matching reverse PTR lease in the locally-configured `in-addr.arpa` / `ip6.arpa` zone. |
| `config:ddns_sweep_secs` | Interval (seconds) of the primary's DDNS lease-expiry sweeper (default 30, 0 = off): replays a silently-expired `ddns:*` lease as a serial bump + IXFR delete + NOTIFY so secondaries converge. |
| `config:nsid` | NSID string reported via EDNS option 3. |
| `config:rrl_enabled` / `_rate` / `_window` / `_slip` | Response rate limiting. |
| `config:lb_mode` | A/AAAA RRset rotation: `none` (default), `rr` (round-robin), `random`. Local serving policy — not zone data. |
| `config:lb_health_enabled` / `_targets` / `_interval` / `_timeout_ms` | TCP health checks for load-balanced addresses: probe the addresses behind `_targets` (`name[:port],...`, port default 80) every `_interval`s (default 10) with a `_timeout_ms` connect timeout (default 1000); down addresses are dropped from answers, with fail-open when all are down. |
| `config:nsec3_iters` / `config:nsec3_salt` | NSEC3 parameters. |
| `config:zsk_validity` (or `config:zone:<zone>:zsk_validity`) | ZSK lifetime in seconds; `dnsd` auto-starts a rollover when the active ZSK is older. `0`/unset = no automatic rollover. |
| `config:zone:<zone>:zsk_rollover_request` | Manual trigger: set to a fresh value (e.g. an epoch) to start a ZSK rollover for that zone now. Edge-triggered. |
| `config:rollover_publish_hold` / `config:rollover_commit_hold` | Hold times (seconds) for the publish and commit phases (defaults 3600 each; per-zone overridable via `config:zone:<zone>:*`). Size publish ≥ DNSKEY TTL and commit ≥ max record TTL. |
| `config:ksk_validity` (or `config:zone:<zone>:ksk_validity`) | KSK lifetime in seconds; `dnsd` auto-starts a Double-Signature KSK rollover (RFC 6781 §4.1.2) when the active KSK is older. `0`/unset = no automatic rollover. |
| `config:zone:<zone>:ksk_rollover_request` | Manual trigger to start a KSK rollover for that zone now (edge-triggered). Not started while a ZSK rollover is mid-flight. |
| `config:ksk_publish_hold` / `config:ksk_commit_hold` | KSK hold times (seconds, defaults 3600; per-zone overridable). `ksk_publish_hold` covers the parent publishing DS(new) + propagation (advance early once you've confirmed the parent has DS(new)); `ksk_commit_hold` covers the old DS expiring from caches. |
| `config:metrics_port` | `dnsd` localhost metrics/health port (default 8054). |
| `config:privdrop_user` / `config:privdrop_group` | Unprivileged account `dnsd` drops to after binding sockets (env `DNS_USER` / `DNS_GROUP` override; default user `nobody`). Only acts when started as root; fail-closed if the drop cannot complete. |
| `config:seccomp_mode` | `dnsd` syscall sandbox (env `DNS_SECCOMP` overrides): `enforce` (default — non-whitelisted syscalls return `EPERM`), `audit` (they are logged but permitted — use to re-validate the whitelist after a toolchain/libc/kernel change or unusual config), or `off`. Requires a build with libseccomp (`-DHAVE_SECCOMP`). Implemented by the shared `libsandbox` (`sandbox.{c,h}`); `resolverd` uses the same filter via `config:resolverd_seccomp_mode`. |
| `config:chroot_dir` | If set (env `DNS_CHROOT` overrides), `dnsd` confines its filesystem to this directory after binding sockets, before dropping privileges. Only acts when started as root; fail-closed if confinement fails. With the default `127.0.0.1` Valkey it needs nothing inside the dir; a Valkey *hostname* needs resolver files (`/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, `libnss_*.so`) for reconnects. |
| `config:isolation_mode` | How `config:chroot_dir` is applied (env `DNS_ISOLATION` overrides): `chroot` (default, `chroot(2)` — confines every thread) or `mountns` (a private mount namespace + `pivot_root(2)`, unmounting the old root). `mountns` confines the request-handling threads (UDP loop + TCP/DoT workers spawned after the pivot); the trusted keyspace/rollover threads, started earlier, stay in the parent mount namespace. Linux only. |
| `config:resolverd_privdrop_user` / `config:resolverd_privdrop_group` / `config:resolverd_chroot_dir` / `config:resolverd_isolation_mode` / `config:resolverd_seccomp_mode` | `resolverd`'s own sandbox, mirroring the `dnsd` keys above (env `RESOLVERD_USER` / `RESOLVERD_GROUP` / `RESOLVERD_CHROOT` / `RESOLVERD_ISOLATION` / `RESOLVERD_SECCOMP`). Applied after the listeners bind, before the proxy loop. Scoped separately from `dnsd` because `resolverd` makes outbound connections and resolves upstream hostnames, so its chroot must carry resolver files + a CA bundle. `resolverd_seccomp_mode` defaults to `enforce` (the whitelist was harvest-validated across every upstream transport on glibc/Fedora); set it to `audit` to re-harvest before trusting `enforce` on a different libc/kernel. |
| `config:mdns_enabled` / `config:mdns_interfaces` | Enable `mdnsd` and its interface allowlist (`"all"` or a comma-separated list; it refuses to start unset). |
| `config:acme_*`, `config:est_*` | ACME/EST endpoints + identity for `certd`. |
| `config:dashboard_password_hash` | Dashboard admin password hash (see [Dashboard](#dashboard)). |

### Multi-zone layout

`dnsd` serves multiple authoritative zones. Each zone is registered with a
`zone_table:<zone>` entry (SOA + transfer settings) and its records carry the
owning zone in the key:

* Records: `zone:<zone>:<TYPE>:<fqdn>` (pipe-delimited values)
* Dynamic-update records: `ddns:<zone>:<TYPE>:<fqdn>`
* Per-zone config: `config:zone:<zone>:serial`, `:nsec3_iters`, `:nsec3_salt`,
  `:dnssec_nsec_mode`, `:soa_ttl` (each defaults to the global `config:*` value)
* Per-zone DNSSEC keys: `dnssec:<zone>:{zsk,zsk_ed25519,ksk,ksk_ed25519}`
* Per-zone ZSK-rollover state (written by `dnsd`): `dnssec:<zone>:zsk_created`
  (epoch the active ZSK set was created), `:zsk_rollover` (`publish|<epoch>` or
  `commit|<epoch>`; absent when idle), `:zsk_next` / `:zsk_ed25519_next` (the
  incoming key set, present only during a rollover), `:zsk_rollover_seen` (the
  last manual-trigger value `dnsd` has acted on)

`dnsd` picks the most specific zone for each query by longest-suffix match; that
zone supplies the SOA, NSEC/NSEC3 denial, and signing keys. mDNS-only records
still use `mdns:<TYPE>:<fqdn>`; the active TLS cert+key blob from `certd` is
`cert:current`. Examples:

```
zone_table:example.com                                 →  ns1.example.com|hostmaster.example.com|10|3600|900|604800|300|127.0.0.1||7200
                                                          (fields: mname|rname|serial|refresh|retry|expire|minimum|axfr_allow|notify_targets[|soa_ttl])
zone:example.local:TXT:_acme-challenge.host.example.local → 60|abc...123
zone:example.local:MX:example.local                    →  300|10|mail.example.local
zone:example.com:SRV:_xmpp._tcp.example.com            →  60|10|20|5222|xmpp.example.com
zone:example.com:TLSA:_443._tcp.www.example.com        →  300|3|1|1|<sha256 hex>
ddns:example.local:A:laptop.example.local              →  192.0.2.42   (TTL stored as key TTL)
```

The primary zone (`config:zone_name`) seeds itself from the legacy global
`config:*`/`dnssec:*` keys, so a single-zone deployment keeps its existing
DS records and key tags. To convert an existing single-zone deployment to this
layout, run `tools/migrate-multizone.sh` (dry-run by default; re-run with
`--apply`).

## Operating notes

### Sending a dynamic update

```bash
KEY_B64=$(valkey-cli GET config:tsig_secret_b64)
cat > /tmp/k <<EOF
key "$(valkey-cli GET config:tsig_key_name)" {
  algorithm hmac-sha256;
  secret "$KEY_B64";
};
EOF

nsupdate -k /tmp/k <<EOF
server 127.0.0.1 5353
zone example.local
update add _acme-challenge.www.example.local 60 TXT "challenge-token-here"
send
EOF
```

### Pulling a zone transfer

```bash
dig @127.0.0.1 -p 5353 example.local AXFR -y "hmac-sha256:tsig-key:$KEY_B64"
```

AXFR over DoT works on `:8853` for encrypted transfers.

### Certificates

`certd` performs ACME DNS-01 (it writes the challenge to
`zone:TXT:_acme-challenge.<domain>` and deletes it after validation) or EST
enrollment, then writes the issued chain+key to `cert:current`. `dnsd` and
`apid` watch `cert:current` and hot-reload TLS within seconds; `dnsd` also
publishes the matching TLSA records. Run `certd` as a daemon (daily renewal
check) or `certd --once` from cron.

### Live reload

Every setting applies live. Edit a `config:*`, `zone:*`, `ddns:*` or `mdns:*`
key (via the dashboard, `apid`, or `valkey-cli`) and the owning daemon picks it
up through a keyspace-notification subscriber: config changes re-load runtime
state, `cert:current` hot-reloads TLS, `zone_table:*` rebuilds the zone list,
`mdns:*` triggers a re-announce. Zone/DDNS records are also read live on every
query. Subscribers re-subscribe with backoff across a Valkey restart.

### Logging

Three sinks run in parallel: stdout/stderr with ISO-8601 timestamps, local
syslog (level via `config:syslog_*`), and optional remote syslog. Query logs go
to `config:query_log_path` when set.

## Build & test

```bash
make                 # production dnsd: optimised, stripped, hardened, GPG-signed
make dns_server      # … unsigned (no GPG key needed; for local/CI)
make certd mdnsd apid resolverd   # the sidecars + recursive resolver (unsigned)
make debug           # dnsd under ASan/UBSan, full symbols
make check           # smoke test (needs Valkey + dig)
make check-resolverd # resolverd caching proxy → dnsd (needs Valkey + dig)
make check-resolverd-cache  # resolverd Valkey cache-load regression (needs Valkey + dig)
make check-resolverd-cookie # resolverd RFC 7873 cookie exchange (needs dig + python3)
make check-catalog   # RFC 9432 catalog provision/deprovision (needs Valkey + dig)
make check-dnssec    # DNSSEC known-answer + negative (flipped-byte) tests
make check-wire      # name_from_wire compression/edge-case unit tests
make fuzz-wire       # 60s libFuzzer smoke on the name parser (needs clang)
make help            # full target list
```

Production builds are hardened (`-fPIE -pie -Wl,-z,relro,-z,now`,
`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`). CI (`.github/workflows/ci.yml`)
builds every daemon, runs the unit tests and a fuzz smoke, and blocks on
warnings-as-errors (curated set + `-Werror`), `clang-format`, and static
analysis (scan-build + cppcheck). Format new/changed C with `clang-format -i`.

# Dashboard

A Flask control-plane UI for the Valkey backend, in `dashboard/`. It can read
and write every key (zone data, the TSIG secret, DNSSEC private keys), so it
**requires authentication and refuses to start without an admin password
configured** — there is no blank-auth default.

## Features

| Section | What it does |
|---|---|
| **Dashboard** | Live metrics (auto-polls `/metrics`), Valkey status, zone summary |
| **Live Metrics** | Full Prometheus text output from `dnsd` |
| **Zone Records** | Browse, add, delete `zone:*` records |
| **DDNS / mDNS Records** | Manage `ddns:*` and `mdns:*` records |
| **Server Config** | Tabbed editor for `config:*` keys, grouped by function |
| **DNSSEC** | Key inventory (ZSK/KSK), NSEC3 parameters, key deletion |
| **PKI / TLS** | ACME + EST config, PEM upload, cert status |
| **AXFR / NOTIFY**, **IXFR Journal** | Transfer allow-list/targets and journal view |
| **Valkey Explorer** | Glob key search; writes are opt-in and never touch secret keys (masked on display) |

## Requirements

- Python 3.10+
- Flask + Werkzeug (`pip install -r dashboard/requirements.txt`)
- No other dependencies — the Valkey RESP client is built-in (stdlib `socket`).

## Run

```bash
# Provision an admin password (one of these), then run:
DASHBOARD_PASSWORD='choose-a-strong-one' python3 dashboard/app.py

# Pre-hash to keep the plaintext out of the environment:
python3 dashboard/app.py --gen-password-hash 'pw'      # prints a scrypt hash
DASHBOARD_PASSWORD_HASH='scrypt:...' python3 dashboard/app.py

# Full options
python3 dashboard/app.py \
  --host 127.0.0.1 --port 5000 \
  --valkey-host 127.0.0.1 --valkey-port 6379 --valkey-pass "" \
  --dns-host 127.0.0.1 --dns-metrics-port 8054 \
  --secret-key "$(openssl rand -hex 32)"
```

Credential lookup order: `DASHBOARD_PASSWORD_HASH` → `DASHBOARD_PASSWORD` →
Valkey `config:dashboard_password_hash`. Set a persistent `FLASK_SECRET_KEY`
(`openssl rand -hex 32`) so sessions survive restarts. See
`dashboard/README.md` for credential rotation and the full auth model.

## Security notes

- The dashboard authenticates (login + signed-cookie session, per-IP login
  backoff) and gates every route. The raw Valkey Explorer is read-only unless
  `DASHBOARD_ENABLE_EXPLORER_WRITE=1`, and even then refuses to write/delete
  secret-bearing keys. Still, bind it to localhost or front it with a
  TLS-terminating proxy; never run it with `--debug` exposed.
- `apid`'s management API (`/config`, `/zone*`) requires a client certificate
  verified against `config:mtls_ca_pem` (mTLS); DDNS `/update` over plain HTTP
  is gated by `config:ddns_secret`; DoH and read-only `/list` are open.
- `dnsd`'s only HTTP surface is a read-only `/health`+`/metrics` bound to
  localhost. Secrets (TSIG key, cookie secret, DNSSEC private keys) live in
  Valkey and are read by `dnsd` only.
