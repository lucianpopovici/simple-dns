# dns_dashboard

Flask-based dashboard and configuration interface for **dns_server**'s Valkey backend.

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
| **Valkey Explorer** | Raw key search (glob pattern); set/delete is **opt-in** and never touches secret keys (see Authentication) |

## Authentication (required)

The dashboard is the control plane: it can read and write every Valkey key
(zone data, the TSIG secret, DNSSEC private keys). It therefore **refuses to
start without an admin password configured** — there is no blank-auth default.

Provision a credential (pick one):

```bash
# 1. Plaintext at startup (hashed in memory; fine for dev / systemd EnvironmentFile)
DASHBOARD_PASSWORD='choose-a-strong-one' python3 app.py

# 2. A pre-computed hash (keeps the plaintext out of the environment)
python3 app.py --gen-password-hash 'choose-a-strong-one'   # prints a scrypt hash
DASHBOARD_PASSWORD_HASH='scrypt:...' python3 app.py

# 3. Store the hash in Valkey (survives restarts, set once)
valkey-cli set config:dashboard_password_hash "$(python3 app.py --gen-password-hash 'pw')"
```

Lookup order: `DASHBOARD_PASSWORD_HASH` → `DASHBOARD_PASSWORD` → Valkey
`config:dashboard_password_hash`. Username defaults to `admin`
(`DASHBOARD_USER` to change).

**Rotation:** regenerate a hash with `--gen-password-hash`, replace the
configured value (env var or `config:dashboard_password_hash`), then restart.
Set a persistent `FLASK_SECRET_KEY` (`openssl rand -hex 32`) so sessions
survive restarts; otherwise an ephemeral key is generated per start and all
sessions reset.

Other controls:
- Every route requires a logged-in session; unauthenticated browser requests
  redirect to `/login`, API/XHR requests get `401`.
- Failed logins are throttled per client IP with escalating backoff.
- The **Valkey Explorer** is read-only unless `DASHBOARD_ENABLE_EXPLORER_WRITE=1`;
  even then it refuses to set/delete secret-bearing keys
  (`dnssec:*`, `*secret*`, `cookie_secret`, `*_key`, `*key_pem*`, `*tsig*`) and
  masks their values on display. Manage those through the DNSSEC/PKI/Config
  pages, never the raw explorer.
- Bind to localhost (default) or front with a TLS-terminating proxy; never run
  `--debug` on an exposed instance (it enables the Werkzeug debugger).
- Session lifetime: `DASHBOARD_SESSION_HOURS` (default 12).

## Requirements

- Python 3.10+
- Flask + Werkzeug (`pip install -r requirements.txt`) — `werkzeug.security`
  provides the password hashing; the Valkey RESP client is built-in (stdlib
  `socket` only)

## Run

```bash
# Minimal (connects to Valkey on localhost:6379, metrics on :8053)
python3 app.py

# Full options
python3 app.py \
  --host 0.0.0.0 \
  --port 5000 \
  --valkey-host 127.0.0.1 \
  --valkey-port 6379 \
  --valkey-pass "" \
  --dns-host 127.0.0.1 \
  --dns-metrics-port 8053 \
  --secret-key "$(openssl rand -hex 32)"

# Environment variables (all options available as env vars too)
VALKEY_HOST=10.0.0.1 VALKEY_PASS=secret DNS_HOST=10.0.0.1 python3 app.py
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
app.py (Flask)
  ↕ RESP protocol (stdlib socket)
Valkey
  ↕ Valkey config keys
dns_server (C binary)
```

The dashboard reads and writes Valkey keys directly. `dns_server` reads them on:
- Startup (`config_load_from_valkey`)
- Each POST to its `/config` management API
- Automatic polling for cert renewal

Changes to most keys require either restarting `dns_server` or calling its
`POST /config` API to hot-reload specific settings (TLS cert/key reload is
instant; zone records are live-queried on every DNS request).

## Security note

The dashboard has no authentication by default. Deploy behind a reverse proxy
(nginx, Caddy) with mTLS or basic auth if the port is exposed beyond localhost.
Set `--secret-key` to a strong random value in production.
