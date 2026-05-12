# simple-dns

A single-binary authoritative DNS server with a Valkey-backed control plane and
a Flask dashboard for browsing/editing zone data. Designed to be small enough
to read end-to-end (one C file, ~5000 lines) while covering the surface area
of a production deployment: DNSSEC, dynamic updates, zone transfers,
DNS-over-TLS, DNS-over-HTTPS, mDNS, and ACME/EST PKI bootstrap.

## Components

| Path | What it is |
|---|---|
| `dns_server.c` | The DNS server. Builds to a single binary. |
| `Makefile` | Production + debug builds, GPG/OpenSSL code signing, install targets. |
| `dashboard/` | Flask UI for the Valkey-backed control plane (see [Dashboard](#dashboard)). |
| `simple_dns.c` / `dns_client.c` | Smaller reference DNS implementations. |

## Quick start

```bash
# 1. Build (needs OpenSSL headers — set OSSL_INC if non-standard)
make                       # production build, GPG-signed
make debug                 # ASan/UBSan build, dns_server_debug

# 2. Start Valkey on 127.0.0.1:6379 (or set DNS_VALKEY_HOST / _PORT / _PASSWORD)
valkey-server &

# 3. Run
./dns_server               # binds 5353/udp + 8853/tcp + 8053/tcp + 8443/tcp
```

On first start, when Valkey is unreachable, the server opens a config portal
on port 8080 (`CONFIG_PORT` env var) — fill in the Valkey connection details
and it persists them to `dns_server.boot` and resumes.

## What the DNS server does

### Protocols on the wire

| Port | Transport | Purpose |
|---|---|---|
| `5353/udp` | DNS-over-UDP | Standard queries, NOTIFY, UPDATE, mDNS |
| `5353/tcp` | DNS-over-TCP | Truncation fallback, AXFR/IXFR |
| `8853/tcp` | DNS-over-TLS (RFC 7858) | DoT including AXFR over TLS |
| `8443/tcp` | DNS-over-HTTPS (RFC 8484) | DoH `/dns-query` (GET base64url + POST) |
| `8053/tcp` | HTTP | `/health`, `/metrics`, `/list`, `/update` (DDNS) |
| `8443/tcp` | HTTPS mTLS | Management API: `/zone`, `/config`, `/acme/issue`, `/pki/est`, `/pki/cacerts` |
| `8080/tcp` | HTTP | First-boot config portal (only when Valkey unreachable) |

### Standards implemented

The server's header comment (`dns_server.c:1`) keeps the authoritative list.
At a glance:

- **Core / queries**: RFC 1034/1035, 2181, 2308, 4592 wildcards, 6303 locally-served zones, 8482 minimal-ANY, 9619 QDCOUNT enforcement.
- **Record types**: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV (2782), CAA (8659), SSHFP (4255), TLSA/DANE (6698/7671), LOC (1876), URI (7553), NAPTR (stub), DNAME (6672), CDS/CDNSKEY (7344/8078).
- **DNSSEC**: RFC 4033–4035, 9364. ZSK + KSK with algorithm 13 (ECDSA P-256) and algorithm 15 (Ed25519, RFC 8080). NSEC (4034) and NSEC3 (5155) authenticated denial.
- **Dynamic operation**: NOTIFY (1996), AXFR (5936), IXFR (1995, with real journal-based diffs), UPDATE (2136) with TSIG (8945) and the zone-authority check (3007).
- **EDNS / transport**: 6891 OPT, 5001 NSID, 7828 TCP-keepalive, 7830/8467 padding, 8914 EDE, 9018 DNS Cookies.
- **mDNS / DNS-SD**: 6762 + 6763, dual-stack IPv4 + IPv6.
- **PKI bootstrap**: ACME (8555, DNS-01 challenge for cert auto-renewal) and EST (7030) over mTLS.

### Recent fixes

Several gaps in the originally claimed RFC coverage have been closed:

| Commit | What changed |
|---|---|
| `Extend handle_update for TXT, CNAME, MX, SRV` | RFC 2136 UPDATE handler stops silently dropping non-A/AAAA records. ACME DNS-01 challenges over nsupdate now work end-to-end. |
| `TXT rdata chunking per RFC 1035 §3.3.14` | TXT values longer than 255 bytes (DKIM keys, long SPF, verification tokens) are now split into multiple character strings instead of being truncated. |
| `DNS name compression (RFC 1035 §4.1.4)` | Owner-name back-pointers in responses; ~30–50% size reduction on multi-RR responses. Fewer TC=1 fallbacks near the 512/1232-byte boundary. |
| `DNS Cookie verification + BADCOOKIE (RFC 9018)` | The `cookie_verify` stub is replaced with a real RFC 9018 §4.2 implementation. Server cookies are now 16-byte SipHash-2-4 MACs bound to client IP and timestamp; clients that send a cookie complete a proper BADCOOKIE handshake. |

## Configuration

All runtime configuration lives in Valkey under the `config:*` key prefix.
The server reads them on startup, when `POST /config` lands, and on cert
renewal. Connection details for Valkey itself come from three sources, in
order of precedence:

1. Environment variables: `DNS_VALKEY_HOST`, `DNS_VALKEY_PORT`,
   `DNS_VALKEY_PASSWORD`, `CONFIG_PORT`.
2. `dns_server.boot` file in the working directory (auto-saved by the
   first-boot config portal).
3. Defaults: `127.0.0.1:6379`, no password.

The full Valkey schema is documented in the `dns_server.c` header comment;
the most-edited keys are:

| Key | Purpose |
|---|---|
| `config:zone_name` | Authoritative zone (default `example.local`). |
| `config:soa_*` | SOA `mname`, `rname`, `refresh`, `retry`, `expire`, `minimum`. |
| `config:zone_serial` | SOA serial; auto-incremented on every change. |
| `config:tsig_key_name` / `config:tsig_secret_b64` | TSIG HMAC-SHA256 key for UPDATE/AXFR/NOTIFY. |
| `config:cookie_secret` | 16-byte hex; key for DNS Cookies SipHash. Generated randomly if absent. |
| `config:axfr_allow` | Comma-separated IPs/CIDRs allowed to do AXFR/IXFR. |
| `config:notify_targets` | Comma-separated `IP:port` recipients for NOTIFY on zone change. |
| `config:nsid` | NSID string reported via EDNS option 3. |
| `config:rrl_enabled` / `_rate` / `_window` / `_slip` | Response rate limiting. |
| `config:nsec3_iters` / `config:nsec3_salt` | NSEC3 parameters. |
| `config:acme_*`, `config:est_*` | ACME and EST endpoints / identity for cert auto-renewal. |

Zone records use the `zone:<TYPE>:<fqdn>` namespace with pipe-delimited
values; dynamic-update records use `ddns:<TYPE>:<fqdn>`. Examples:

```
zone:TXT:_acme-challenge.host.example.local   →  60|abc...123
zone:MX:example.local                          →  300|10|mail.example.local
zone:SRV:_xmpp._tcp.example.local              →  60|10|20|5222|xmpp.example.local
zone:TLSA:_443._tcp.www.example.local          →  300|3|1|1|<sha256 hex>
ddns:A:laptop.example.local                    →  192.0.2.42      (TTL stored as key TTL)
```

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

AXFR over DoT works on `:8853` if you prefer encrypted transfers.

### Hot-reloading config

Most settings change live on the next query (zone records are read every
request). Things that need a nudge:

- TSIG / cookie secrets: send `SIGHUP` or `POST /config` to the server.
- TLS cert/key: written via `/zone` upload or ACME — picked up automatically.
- DNSSEC keys: stored in Valkey; re-read on `SIGHUP`.

### Logging

Three sinks run in parallel: stdout/stderr with ISO-8601 timestamps, local
syslog (configurable level via `config:syslog_*`), and optional remote syslog
(`config:rsyslog_host` + `_port`). Query logs are written to the path in
`config:query_log_path` when set.

## Build details

The default `make` target produces a stripped, hardened binary with ASLR
(`-fPIE -pie -Wl,-z,relro,-z,now`), stack-smashing protection, and
`_FORTIFY_SOURCE=2`, then signs it with the first available GPG key. Useful
flags:

```bash
make debug                 # ASan/UBSan, full symbols, dns_server_debug
make GPG_KEY=ops@example.com   # pick the signing key explicitly
make sign-openssl              # add a secondary OpenSSL Ed25519 signature
make verify                    # verify GPG + OpenSSL signatures
make install PREFIX=/usr/local # install binary + .asc signature
make help                      # full target list
```

OpenSSL ≥ 3.0 is required. Override paths with `OSSL_INC=` / `OSSL_LIB=` if
your distribution puts headers somewhere unusual.

# Dashboard

A Flask-based dashboard and configuration interface for `dns_server`'s
Valkey backend. Lives in `dashboard/`.

## Features

| Section | What it does |
|---|---|
| **Dashboard** | Live metrics (auto-polls `/metrics` every 15s), Valkey status, zone summary |
| **Live Metrics** | Full Prometheus text output from dns_server |
| **Zone Records** | Browse, add, delete `zone:*` records with type/name/value/TTL |
| **DDNS Records** | Browse and manage `ddns:*` dynamic records |
| **mDNS Records** | Browse and manage `mdns:*` multicast records |
| **Server Config** | Tabbed editor for all `config:*` Valkey keys, grouped by function |
| **DNSSEC** | Key inventory (ZSK/KSK), NSEC3 parameter editing, key deletion |
| **PKI / TLS** | ACME + EST config, PEM upload for cert/key/CA, cert status |
| **AXFR / NOTIFY** | AXFR allow-list and NOTIFY target editing, transfer stats |
| **IXFR Journal** | Recent incremental transfer journal entries, journal clear |
| **Valkey Explorer** | Raw key search (glob pattern), set/delete arbitrary keys, namespace summary |

## Requirements

- Python 3.10+
- Flask (`pip install flask`)
- No other dependencies — Valkey RESP client is built-in (stdlib `socket` only)

## Run

```bash
# Minimal (connects to Valkey on localhost:6379, metrics on :8053)
python3 dashboard/app.py

# Full options
python3 dashboard/app.py \
  --host 0.0.0.0 \
  --port 5000 \
  --valkey-host 127.0.0.1 \
  --valkey-port 6379 \
  --valkey-pass "" \
  --dns-host 127.0.0.1 \
  --dns-metrics-port 8053 \
  --secret-key "$(openssl rand -hex 32)"

# Environment variables (all options available as env vars too)
VALKEY_HOST=10.0.0.1 VALKEY_PASS=secret DNS_HOST=10.0.0.1 python3 dashboard/app.py
```

## Configuration groups

The **Server Config** page is split into tabs:

| Tab | Keys |
|---|---|
| Zone & SOA | `zone_name`, `zone_serial`, `soa_mname/rname/refresh/retry/expire/minimum` |
| Dynamic DNS | `ddns_secret` |
| Zone Transfer | `axfr_allow`, `notify_targets` |
| Security & Auth | `tsig_key_name`, `tsig_secret_b64`, `cookie_secret`, `nsid` |
| Rate Limiting | `rrl_enabled`, `rrl_rate`, `rrl_window`, `rrl_slip` |
| DNSSEC | `nsec3_iters`, `nsec3_salt` |
| PKI / TLS / ACME | `acme_domain/email/ca`, `est_server/domain` |
| Syslog | all `syslog_*` keys |
| Query Logging | `query_log_path` |

## Architecture

```
browser
  ↕ HTTP
dashboard/app.py (Flask)
  ↕ RESP protocol (stdlib socket)
Valkey  ←→  dns_server (C binary)
              ↕
       DNS / DoT / DoH / mDNS clients
```

The dashboard reads and writes Valkey keys directly. `dns_server` reads them
on startup (`config_load_from_valkey`), on each `POST /config`, and during
cert-renewal polling.

Changes to most keys require either restarting `dns_server` or calling its
`POST /config` API to hot-reload specific settings (TLS cert/key reload is
instant; zone records are live-queried on every DNS request).

## Security note

The dashboard has no authentication by default. Deploy behind a reverse proxy
(nginx, Caddy) with mTLS or basic auth if the port is exposed beyond
localhost. Set `--secret-key` to a strong random value in production. The
`dns_server`'s management HTTPS API on `:8443` is mTLS-only — clients must
present a certificate signed by the configured CA.
