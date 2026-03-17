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
| **Valkey Explorer** | Raw key search (glob pattern), set/delete arbitrary keys, namespace summary |

## Requirements

- Python 3.10+
- Flask (`pip install flask`)
- No other dependencies — Valkey RESP client is built-in (stdlib `socket` only)

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
