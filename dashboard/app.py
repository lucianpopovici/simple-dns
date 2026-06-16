"""
dns_dashboard/app.py
Flask dashboard + configuration UI for dns_server's Valkey backend.

Run:
    python3 app.py [--host 0.0.0.0] [--port 5000]
                   [--valkey-host 127.0.0.1] [--valkey-port 6379]
                   [--valkey-pass ""]
                   [--dns-host 127.0.0.1] [--dns-metrics-port 8053]
                   [--secret-key "change-me"]

Environment overrides:
    VALKEY_HOST, VALKEY_PORT, VALKEY_PASS
    DNS_HOST, DNS_METRICS_PORT
    FLASK_SECRET_KEY
    DASHBOARD_PORT, DASHBOARD_HOST
"""

import os
import re
import time
import json
import socket
import secrets
import urllib.request
import urllib.error
import argparse
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template_string, request, redirect,
                   url_for, flash, jsonify, session, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from valkey_client import ValkeyClient, ValkeyError

# ── App setup ─────────────────────────────────────────────────────────────
app = Flask(__name__)
# Real secret key is set in configure_auth() before the app serves a request;
# a known/default key means forgeable session cookies.
app.secret_key = os.getenv("FLASK_SECRET_KEY", "")

# ── Globals (set by parse_args) ───────────────────────────────────────────
vk: ValkeyClient = None
DNS_HOST = "127.0.0.1"
DNS_METRICS_PORT = 8053

# ── Authentication (migration Step 5) ─────────────────────────────────────
# Single admin account. The password hash is provisioned out-of-band; the app
# refuses to start without one (no blank-auth default). See configure_auth().
DASH_USER      = os.getenv("DASHBOARD_USER", "admin")
DASH_PW_HASH   = None     # werkzeug hash, set in configure_auth()
SESSION_HOURS  = int(os.getenv("DASHBOARD_SESSION_HOURS", "12"))
# Raw Valkey Explorer writes are opt-in; even then, secret namespaces are never
# writable/deletable through that path (use the dedicated config pages).
EXPLORER_WRITE = os.getenv("DASHBOARD_ENABLE_EXPLORER_WRITE", "") in ("1", "true", "yes")
# Secret-bearing keys: masked in the Explorer, never raw-writable there.
SECRET_KEY_RE  = re.compile(r"(^dnssec:|secret|cookie_secret|_key$|key_pem|tsig)", re.I)
# Endpoints reachable without a session.
PUBLIC_ENDPOINTS = {"login", "logout", "static", "healthz"}
# Per-process brute-force throttle: client-ip -> (fail_count, not_before_epoch)
_login_fails = {}


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else (request.remote_addr or "?"))


def is_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_RE.search(key or ""))


def configure_auth(secret_key: str):
    """Set the session secret and load the admin password hash. Returns an
    error string if no credential is configured (caller must refuse to run)."""
    global DASH_PW_HASH
    if secret_key and secret_key not in ("change-in-production",
                                         "dns-dashboard-dev-key-change-in-prod"):
        app.secret_key = secret_key
    else:
        app.secret_key = secrets.token_hex(32)
        print("[dns-dashboard] WARNING: no strong FLASK_SECRET_KEY set — "
              "generated an ephemeral one; sessions reset on restart.")
    # Password hash priority: explicit hash > plaintext env (hashed) > Valkey.
    h = os.getenv("DASHBOARD_PASSWORD_HASH")
    if not h:
        pw = os.getenv("DASHBOARD_PASSWORD")
        if pw:
            h = generate_password_hash(pw)
    if not h and vk is not None:
        try:
            h = vk.get("config:dashboard_password_hash") or None
        except Exception:
            h = None
    DASH_PW_HASH = h
    if not DASH_PW_HASH:
        return ("no dashboard password configured — set DASHBOARD_PASSWORD, "
                "DASHBOARD_PASSWORD_HASH, or Valkey config:dashboard_password_hash")
    return None


@app.before_request
def _require_auth():
    """Gate every endpoint except the public ones behind a logged-in session."""
    if request.endpoint in PUBLIC_ENDPOINTS:
        return
    if session.get("authed"):
        return
    # Unauthenticated: JSON for API/XHR callers, redirect for browsers.
    if request.path.startswith("/api/") or \
       request.accept_mimetypes.best == "application/json":
        return jsonify(error="authentication required"), 401
    return redirect(url_for("login", next=request.path))

# ── Record types served by dns_server ────────────────────────────────────
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV",
                "CAA", "SSHFP", "TLSA", "DNAME", "LOC", "URI",
                "NAPTR", "PTR"]

# ── Config key metadata ───────────────────────────────────────────────────
# (key_suffix, label, input_type, placeholder, group, description)
CONFIG_SCHEMA = [
    # ── Zone ────────────────────────────────────────────────────────────
    ("zone_name",       "Zone Name",         "text",     "example.local",        "zone",   "Authoritative zone FQDN"),
    ("zone_serial",     "SOA Serial",        "number",   "2024010101",           "zone",   "Auto-incremented on changes"),
    ("soa_mname",       "SOA MNAME",         "text",     "ns1.example.local",    "zone",   "Primary nameserver"),
    ("soa_rname",       "SOA RNAME",         "text",     "hostmaster.example.local", "zone", "Responsible mailbox (use . not @)"),
    ("soa_refresh",     "SOA Refresh",       "number",   "3600",                 "zone",   "Seconds between secondary checks"),
    ("soa_retry",       "SOA Retry",         "number",   "900",                  "zone",   "Seconds between failed retries"),
    ("soa_expire",      "SOA Expire",        "number",   "604800",               "zone",   "Secondary data validity window"),
    ("soa_minimum",     "SOA Minimum",       "number",   "300",                  "zone",   "Negative caching TTL"),
    # ── DDNS ────────────────────────────────────────────────────────────
    ("ddns_secret",     "DDNS Secret",       "password", "changeme",             "ddns",   "Shared secret for DDNS /update API"),
    # ── Transfer ────────────────────────────────────────────────────────
    ("axfr_allow",      "AXFR Allow",        "text",     "127.0.0.1,10.0.0.0/8","xfr",    "Comma-separated IPs/CIDRs"),
    ("notify_targets",  "NOTIFY Targets",    "text",     "10.0.0.2:53",          "xfr",    "Comma-separated host:port"),
    # ── Security ────────────────────────────────────────────────────────
    ("tsig_key_name",   "TSIG Key Name",     "text",     "tsig-key",             "security","TSIG key identifier"),
    ("tsig_secret_b64", "TSIG Secret (b64)", "password", "",                     "security","Base64 HMAC secret"),
    ("cookie_secret",   "Cookie Secret",     "password", "16-byte hex",          "security","32 hex chars = 16 bytes"),
    ("nsid",            "NSID",              "text",     "ns1",                  "security","Name Server Identifier string"),
    # ── RRL ─────────────────────────────────────────────────────────────
    ("rrl_enabled",     "RRL Enabled",       "number",   "0",                    "rrl",    "1 = enable response rate limiting"),
    ("rrl_rate",        "RRL Rate",          "number",   "5",                    "rrl",    "Max identical responses per window"),
    ("rrl_window",      "RRL Window (s)",    "number",   "1",                    "rrl",    "Token refill window in seconds"),
    ("rrl_slip",        "RRL Slip",          "number",   "2",                    "rrl",    "Send TC every N-th excess (1=always drop)"),
    # ── DNSSEC ──────────────────────────────────────────────────────────
    ("nsec3_iters",     "NSEC3 Iterations",  "number",   "1",                    "dnssec", "Hash iterations (1 recommended)"),
    ("nsec3_salt",      "NSEC3 Salt",        "text",     "",                     "dnssec", "Hex salt, empty for no salt"),
    # ── ACME ────────────────────────────────────────────────────────────
    ("acme_domain",     "ACME Domain",       "text",     "example.com",          "pki",    "Domain to issue certificate for"),
    ("acme_email",      "ACME Email",        "email",    "admin@example.com",    "pki",    "Let's Encrypt contact email"),
    ("acme_ca",         "ACME CA URL",       "url",      "https://acme-v02.api.letsencrypt.org/directory", "pki", "ACME directory URL"),
    # ── EST ─────────────────────────────────────────────────────────────
    ("est_server",      "EST Server",        "text",     "pki.corp.local:8443",  "pki",    "EST server host:port"),
    ("est_domain",      "EST Domain",        "text",     "server.corp.local",    "pki",    "Domain for EST certificate"),
    # ── Syslog ──────────────────────────────────────────────────────────
    ("syslog_enabled",  "Syslog Enabled",    "number",   "0",                    "syslog", "1 = send to local syslog"),
    ("syslog_facility", "Facility",          "text",     "daemon",               "syslog", "daemon, local0-local7, etc."),
    ("syslog_level",    "Log Level",         "text",     "info",                 "syslog", "debug/info/notice/warning/err"),
    ("syslog_ident",    "Ident",             "text",     "dns_server",           "syslog", "Program name in syslog"),
    ("syslog_remote_host",  "Remote Host",   "text",     "",                     "syslog", "Remote syslog server IP/host"),
    ("syslog_remote_port",  "Remote Port",   "number",   "514",                  "syslog", "514 UDP/TCP, 6514 TLS"),
    ("syslog_remote_proto", "Remote Proto",  "text",     "udp",                  "syslog", "udp / tcp / tls"),
    ("syslog_remote_format","Remote Format", "text",     "rfc5424",              "syslog", "rfc5424 or rfc3164"),
    ("syslog_remote_tls_verify", "TLS Verify", "number", "1",                   "syslog", "1 = verify remote cert"),
    # ── Query Log ───────────────────────────────────────────────────────
    ("query_log_path",  "Query Log Path",    "text",     "/var/log/dns_queries.jsonl", "logging", "Empty = disabled, 'stderr' = stderr"),
]

GROUP_META = {
    "zone":     ("Zone & SOA",        "⬡"),
    "ddns":     ("Dynamic DNS",       "⟳"),
    "xfr":      ("Zone Transfer",     "⇄"),
    "security": ("Security & Auth",   "⚿"),
    "rrl":      ("Rate Limiting",     "⊘"),
    "dnssec":   ("DNSSEC",            "✦"),
    "pki":      ("PKI / TLS / ACME",  "⬤"),
    "syslog":   ("Syslog",            "▣"),
    "logging":  ("Query Logging",     "▤"),
}

# ── Helpers ───────────────────────────────────────────────────────────────
def vk_get(key: str) -> str:
    try:
        return vk.get(key) or ""
    except ValkeyError:
        return ""


def vk_set(key: str, value: str) -> bool:
    try:
        return vk.set(key, value)
    except ValkeyError:
        return False


def vk_del(key: str) -> bool:
    try:
        return bool(vk.delete(key))
    except ValkeyError:
        return False


def valkey_status() -> dict:
    try:
        info = vk.info()
        return {
            "connected": True,
            "version":   info.get("valkey_version") or info.get("redis_version", "?"),
            "used_memory_human": info.get("used_memory_human", "?"),
            "connected_clients": info.get("connected_clients", "?"),
            "uptime_in_seconds": info.get("uptime_in_seconds", "?"),
            "dbsize": vk.dbsize(),
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


def fetch_metrics() -> dict:
    """Fetch Prometheus text metrics from dns_server's /metrics endpoint."""
    try:
        url = f"http://{DNS_HOST}:{DNS_METRICS_PORT}/metrics"
        with urllib.request.urlopen(url, timeout=2) as r:
            text = r.read().decode()
        metrics = {}
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                metrics[parts[0]] = parts[1]
        return {"ok": True, "raw": metrics}
    except Exception as e:
        return {"ok": False, "error": str(e), "raw": {}}


def list_zones() -> list[str]:
    """Configured authoritative zones (zone_table:<zone>), primary first."""
    try:
        zones = sorted(k.split(":", 1)[1] for k in vk.scan_match("zone_table:*"))
    except ValkeyError:
        zones = []
    primary = vk_get("config:zone_name")
    if primary and primary not in zones:
        zones.insert(0, primary)
    return zones


def resolve_zone(name: str) -> str:
    """Longest-suffix match of a record name against the configured zones,
    mirroring dnsd/apid zone selection.  Falls back to config:zone_name."""
    name = (name or "").lower()
    best, best_len = "", -1
    for z in list_zones():
        zl = len(z)
        if name == z or name.endswith("." + z):
            if zl > best_len:
                best, best_len = z, zl
    return best or (vk_get("config:zone_name") or "")


def get_zone_records() -> list[dict]:
    """Return all zone:* and ddns:* records as a sorted list.
    Keys are multi-zone: zone:<zone>:<TYPE>:<name> / ddns:<zone>:<TYPE>:<name>."""
    try:
        keys = vk.scan_match("zone:*") + vk.scan_match("ddns:*")
        if not keys:
            return []
        values = vk.mget(keys)
        ttls   = [vk.ttl(k) for k in keys]
        records = []
        for k, v, t in zip(keys, values, ttls):
            parts = k.split(":", 3)                 # ns:zone:TYPE:name
            ns    = parts[0]                        # zone | ddns
            zone  = parts[1] if len(parts) > 1 else "?"
            rtype = parts[2] if len(parts) > 2 else "?"
            name  = parts[3] if len(parts) > 3 else "?"
            records.append({
                "key":   k,
                "ns":    ns,
                "zone":  zone,
                "type":  rtype,
                "name":  name,
                "value": v or "",
                "ttl":   t,
            })
        return sorted(records, key=lambda r: (r["zone"], r["name"], r["type"]))
    except ValkeyError:
        return []


def get_mdns_records() -> list[dict]:
    try:
        keys = vk.scan_match("mdns:*")
        if not keys:
            return []
        values = vk.mget(keys)
        records = []
        for k, v in zip(keys, values):
            parts = k.split(":", 2)
            rtype = parts[1] if len(parts) > 1 else "?"
            name  = parts[2] if len(parts) > 2 else "?"
            records.append({"key": k, "type": rtype, "name": name, "value": v or ""})
        return sorted(records, key=lambda r: r["name"])
    except ValkeyError:
        return []


def get_ixfr_journal(n: int = 20) -> list[str]:
    try:
        return vk.lrange("ixfr:journal", 0, n - 1)
    except ValkeyError:
        return []


def get_dnssec_info() -> dict:
    """Return DNSSEC key presence for the primary zone's per-zone keys
    (dnssec:<zone>:*), falling back to the legacy un-prefixed keys."""
    info = {}
    zone = vk_get("config:zone_name") or "example.local"
    for suffix in ["zsk", "zsk_ed25519", "ksk", "ksk_ed25519"]:
        key = f"dnssec:{zone}:{suffix}"
        val = vk_get(key) or vk_get(f"dnssec:{suffix}")
        info[key] = {
            "present": bool(val),
            "preview": (val[:60] + "...") if val and len(val) > 60 else (val or ""),
        }
    info["nsec3_iters"] = vk_get("config:nsec3_iters") or "1"
    info["nsec3_salt"]  = vk_get("config:nsec3_salt")  or "(none)"
    return info


# ── Base template ─────────────────────────────────────────────────────────
BASE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ page_title }} — DNS Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:        #07090d;
      --bg2:       #0d1117;
      --bg3:       #141b24;
      --border:    #1e2d3d;
      --border2:   #243344;
      --amber:     #e8a020;
      --amber-dim: #7a5210;
      --green:     #2adb6f;
      --green-dim: #145c35;
      --red:       #e84040;
      --red-dim:   #5c1414;
      --blue:      #4098e8;
      --blue-dim:  #14345c;
      --text:      #c8d4e0;
      --text-dim:  #5a7080;
      --text-bright: #edf2f7;
      --mono:      'IBM Plex Mono', monospace;
      --sans:      'IBM Plex Sans', sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }

    /* Scanline overlay */
    body::before {
      content: '';
      position: fixed; inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,.08) 2px,
        rgba(0,0,0,.08) 4px
      );
      pointer-events: none;
      z-index: 9999;
    }

    /* ── Layout ─────────────────────────────────────────────────────── */
    .shell { display: flex; min-height: 100vh; }

    .sidebar {
      width: 220px;
      flex-shrink: 0;
      background: var(--bg2);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
    }

    .sidebar-logo {
      padding: 20px 16px 14px;
      border-bottom: 1px solid var(--border);
    }
    .sidebar-logo .logotype {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: var(--amber);
    }
    .sidebar-logo .subtitle {
      font-family: var(--mono);
      font-size: 9px;
      color: var(--text-dim);
      letter-spacing: .1em;
      margin-top: 3px;
    }

    .nav-section {
      padding: 8px 0;
      border-bottom: 1px solid var(--border);
    }
    .nav-section-label {
      padding: 6px 16px 3px;
      font-family: var(--mono);
      font-size: 9px;
      font-weight: 600;
      letter-spacing: .14em;
      text-transform: uppercase;
      color: var(--text-dim);
    }
    .nav-link {
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 7px 16px;
      color: var(--text-dim);
      text-decoration: none;
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: .02em;
      transition: color .15s, background .15s;
      border-left: 2px solid transparent;
    }
    .nav-link:hover { color: var(--text); background: var(--bg3); }
    .nav-link.active {
      color: var(--amber);
      border-left-color: var(--amber);
      background: rgba(232,160,32,.07);
    }
    .nav-link .icon { width: 14px; opacity: .7; font-size: 13px; }

    .sidebar-status {
      margin-top: auto;
      padding: 12px 16px;
      border-top: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 10px;
    }
    .status-dot {
      display: inline-block;
      width: 7px; height: 7px;
      border-radius: 50%;
      margin-right: 5px;
      vertical-align: middle;
    }
    .status-dot.ok  { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .status-dot.err { background: var(--red);   box-shadow: 0 0 6px var(--red);   }
    .status-dot.warn{ background: var(--amber); box-shadow: 0 0 6px var(--amber); }

    .content {
      flex: 1;
      overflow-x: hidden;
      padding: 28px 32px;
    }

    /* ── Page header ─────────────────────────────────────────────────── */
    .page-header {
      display: flex;
      align-items: baseline;
      gap: 16px;
      margin-bottom: 24px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--border);
    }
    .page-title {
      font-family: var(--mono);
      font-size: 18px;
      font-weight: 600;
      color: var(--text-bright);
      letter-spacing: -.01em;
    }
    .page-title span { color: var(--amber); }
    .page-meta {
      font-family: var(--mono);
      font-size: 11px;
      color: var(--text-dim);
    }

    /* ── Panels ──────────────────────────────────────────────────────── */
    .panel {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 4px;
      margin-bottom: 20px;
    }
    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 16px;
      border-bottom: 1px solid var(--border);
      background: rgba(255,255,255,.02);
    }
    .panel-title {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: .1em;
      text-transform: uppercase;
      color: var(--amber);
    }
    .panel-body { padding: 16px; }

    /* ── Metric cards ────────────────────────────────────────────────── */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .metric-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 14px 16px;
      position: relative;
      overflow: hidden;
    }
    .metric-card::after {
      content: '';
      position: absolute;
      bottom: 0; left: 0; right: 0;
      height: 2px;
      background: var(--border2);
    }
    .metric-card.green::after { background: var(--green); }
    .metric-card.amber::after { background: var(--amber); }
    .metric-card.red::after   { background: var(--red);   }
    .metric-card.blue::after  { background: var(--blue);  }

    .metric-label {
      font-family: var(--mono);
      font-size: 9px;
      letter-spacing: .1em;
      text-transform: uppercase;
      color: var(--text-dim);
      margin-bottom: 6px;
    }
    .metric-value {
      font-family: var(--mono);
      font-size: 26px;
      font-weight: 600;
      color: var(--text-bright);
      line-height: 1;
    }
    .metric-sub {
      font-family: var(--mono);
      font-size: 10px;
      color: var(--text-dim);
      margin-top: 4px;
    }

    /* ── Tables ──────────────────────────────────────────────────────── */
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--mono);
      font-size: 12px;
    }
    .data-table thead tr {
      background: rgba(255,255,255,.03);
      border-bottom: 1px solid var(--border2);
    }
    .data-table th {
      padding: 8px 12px;
      text-align: left;
      font-size: 9px;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: var(--text-dim);
      font-weight: 600;
    }
    .data-table td {
      padding: 7px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
      word-break: break-all;
    }
    .data-table tr:last-child td { border-bottom: none; }
    .data-table tr:hover td { background: rgba(255,255,255,.02); }
    .data-table .val { color: var(--green); max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .data-table .name { color: var(--text-bright); }
    .data-table .dim  { color: var(--text-dim); }

    /* ── Badges ──────────────────────────────────────────────────────── */
    .badge {
      display: inline-block;
      padding: 1px 7px;
      border-radius: 2px;
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 600;
      letter-spacing: .04em;
    }
    .badge-A     { background: rgba(42,219,111,.15); color: var(--green); border: 1px solid var(--green-dim); }
    .badge-AAAA  { background: rgba(64,152,232,.15); color: var(--blue);  border: 1px solid var(--blue-dim);  }
    .badge-CNAME { background: rgba(232,160,32,.15); color: var(--amber); border: 1px solid var(--amber-dim); }
    .badge-MX    { background: rgba(42,219,111,.12); color: #7de8aa;      border: 1px solid #145c35; }
    .badge-TXT   { background: rgba(232,160,32,.12); color: #e8c078;      border: 1px solid var(--amber-dim); }
    .badge-SRV   { background: rgba(64,152,232,.12); color: #80c0f0;      border: 1px solid var(--blue-dim);  }
    .badge-default { background: var(--bg3); color: var(--text-dim); border: 1px solid var(--border); }
    .badge-zone  { background: rgba(42,219,111,.08); color: var(--green); }
    .badge-ddns  { background: rgba(232,160,32,.08); color: var(--amber); }
    .badge-mdns  { background: rgba(64,152,232,.08); color: var(--blue);  }

    /* ── Forms ───────────────────────────────────────────────────────── */
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 14px;
    }
    .form-field { display: flex; flex-direction: column; gap: 5px; }
    .form-field label {
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: .08em;
      text-transform: uppercase;
      color: var(--text-dim);
    }
    .form-field input, .form-field select, .form-field textarea {
      background: var(--bg3);
      border: 1px solid var(--border2);
      color: var(--text);
      font-family: var(--mono);
      font-size: 12px;
      padding: 7px 10px;
      border-radius: 3px;
      outline: none;
      transition: border-color .15s;
    }
    .form-field input:focus, .form-field select:focus, .form-field textarea:focus {
      border-color: var(--amber);
    }
    .form-field .hint {
      font-size: 10px;
      color: var(--text-dim);
      font-family: var(--mono);
    }
    .form-full { grid-column: 1 / -1; }

    /* ── Buttons ─────────────────────────────────────────────────────── */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 14px;
      border: 1px solid;
      border-radius: 3px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: .05em;
      cursor: pointer;
      text-decoration: none;
      transition: all .15s;
    }
    .btn-primary {
      background: rgba(232,160,32,.12);
      border-color: var(--amber-dim);
      color: var(--amber);
    }
    .btn-primary:hover { background: rgba(232,160,32,.22); border-color: var(--amber); }
    .btn-success {
      background: rgba(42,219,111,.10);
      border-color: var(--green-dim);
      color: var(--green);
    }
    .btn-success:hover { background: rgba(42,219,111,.20); }
    .btn-danger {
      background: rgba(232,64,64,.10);
      border-color: var(--red-dim);
      color: var(--red);
    }
    .btn-danger:hover { background: rgba(232,64,64,.20); }
    .btn-ghost {
      background: transparent;
      border-color: var(--border2);
      color: var(--text-dim);
    }
    .btn-ghost:hover { border-color: var(--text-dim); color: var(--text); }
    .btn-sm { padding: 4px 9px; font-size: 10px; }

    /* ── Alerts ──────────────────────────────────────────────────────── */
    .alert {
      padding: 10px 14px;
      border-radius: 3px;
      font-family: var(--mono);
      font-size: 12px;
      margin-bottom: 16px;
      border-left: 3px solid;
    }
    .alert-success { background: rgba(42,219,111,.08); border-color: var(--green); color: #7de8aa; }
    .alert-error   { background: rgba(232,64,64,.08);  border-color: var(--red);   color: #f08080; }
    .alert-warning { background: rgba(232,160,32,.08); border-color: var(--amber); color: #e8c078; }

    /* ── Config tabs ─────────────────────────────────────────────────── */
    .tab-bar {
      display: flex;
      gap: 2px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .tab-btn {
      padding: 6px 13px;
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 3px;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--text-dim);
      cursor: pointer;
      transition: all .15s;
    }
    .tab-btn.active, .tab-btn:hover {
      background: rgba(232,160,32,.10);
      border-color: var(--amber-dim);
      color: var(--amber);
    }

    /* ── Misc ────────────────────────────────────────────────────────── */
    .key-chip {
      display: inline-block;
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 2px;
      font-family: var(--mono);
      font-size: 10px;
      padding: 1px 6px;
      color: var(--blue);
    }
    .section-sep {
      border: none;
      border-top: 1px solid var(--border);
      margin: 20px 0;
    }
    code {
      font-family: var(--mono);
      background: var(--bg3);
      padding: 1px 5px;
      border-radius: 2px;
      font-size: 11px;
      color: var(--green);
    }
    .ttl-badge {
      font-family: var(--mono);
      font-size: 10px;
      color: var(--text-dim);
      padding: 1px 6px;
      background: var(--bg3);
      border-radius: 2px;
    }
    .search-bar {
      display: flex;
      gap: 8px;
      margin-bottom: 14px;
    }
    .search-bar input {
      flex: 1;
      background: var(--bg3);
      border: 1px solid var(--border2);
      color: var(--text);
      font-family: var(--mono);
      font-size: 12px;
      padding: 7px 12px;
      border-radius: 3px;
      outline: none;
    }
    .search-bar input:focus { border-color: var(--amber); }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .three-col { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
    @media (max-width: 900px) { .two-col, .three-col { grid-template-columns: 1fr; } }

    /* ── Flash messages (Jinja) ──────────────────────────────────────── */
    .flashes { margin-bottom: 16px; }
  </style>
</head>
<body>
<div class="shell">
  <!-- ── Sidebar ─────────────────────────────────────────────────── -->
  <nav class="sidebar">
    <div class="sidebar-logo">
      <div class="logotype">DNS Dashboard</div>
      <div class="subtitle">Valkey Config Interface</div>
    </div>

    <div class="nav-section">
      <div class="nav-section-label">Monitor</div>
      <a href="{{ url_for('dashboard') }}" class="nav-link {% if active=='dashboard' %}active{% endif %}">
        <span class="icon">◈</span> Dashboard
      </a>
      <a href="{{ url_for('metrics') }}" class="nav-link {% if active=='metrics' %}active{% endif %}">
        <span class="icon">▤</span> Live Metrics
      </a>
    </div>

    <div class="nav-section">
      <div class="nav-section-label">Records</div>
      <a href="{{ url_for('records') }}" class="nav-link {% if active=='records' %}active{% endif %}">
        <span class="icon">▦</span> Zone Records
      </a>
      <a href="{{ url_for('ddns') }}" class="nav-link {% if active=='ddns' %}active{% endif %}">
        <span class="icon">⟳</span> DDNS Records
      </a>
      <a href="{{ url_for('mdns') }}" class="nav-link {% if active=='mdns' %}active{% endif %}">
        <span class="icon">⊕</span> mDNS Records
      </a>
    </div>

    <div class="nav-section">
      <div class="nav-section-label">Configuration</div>
      <a href="{{ url_for('config', group='zone') }}" class="nav-link {% if active=='config' %}active{% endif %}">
        <span class="icon">⚙</span> Server Config
      </a>
      <a href="{{ url_for('dnssec_page') }}" class="nav-link {% if active=='dnssec' %}active{% endif %}">
        <span class="icon">✦</span> DNSSEC
      </a>
      <a href="{{ url_for('pki') }}" class="nav-link {% if active=='pki' %}active{% endif %}">
        <span class="icon">⬤</span> PKI / TLS
      </a>
    </div>

    <div class="nav-section">
      <div class="nav-section-label">Transfers</div>
      <a href="{{ url_for('xfr') }}" class="nav-link {% if active=='xfr' %}active{% endif %}">
        <span class="icon">⇄</span> AXFR / NOTIFY
      </a>
      <a href="{{ url_for('ixfr_journal') }}" class="nav-link {% if active=='ixfr' %}active{% endif %}">
        <span class="icon">▤</span> IXFR Journal
      </a>
    </div>

    <div class="nav-section">
      <div class="nav-section-label">System</div>
      <a href="{{ url_for('valkey_explorer') }}" class="nav-link {% if active=='explorer' %}active{% endif %}">
        <span class="icon">◎</span> Valkey Explorer
      </a>
    </div>

    <!-- Valkey status pill -->
    <div class="sidebar-status">
      {% if vk_ok %}
        <span class="status-dot ok"></span>
        <span style="color:var(--green)">Valkey OK</span>
      {% else %}
        <span class="status-dot err"></span>
        <span style="color:var(--red)">Valkey ERR</span>
      {% endif %}
    </div>
    {% if current_user %}
    <div class="sidebar-status" style="justify-content:space-between">
      <span style="color:var(--muted,#8a93a3);font-size:.8rem">&#128100; {{ current_user }}</span>
      <a href="{{ url_for('logout') }}" style="color:var(--muted,#8a93a3);font-size:.8rem">Sign out</a>
    </div>
    {% endif %}
  </nav>

  <!-- ── Content ────────────────────────────────────────────────── -->
  <main class="content">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="flashes">
          {% for cat, msg in messages %}
            <div class="alert alert-{{ 'success' if cat == 'success' else ('error' if cat == 'error' else 'warning') }}">{{ msg }}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>
</div>

<script>
// ── Record filter ─────────────────────────────────────────────────────────
function filterTable(inputId, tableId) {
  const q = document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(tr => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// ── Tab switching ─────────────────────────────────────────────────────────
function showTab(group) {
  document.querySelectorAll('.config-section').forEach(s => s.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const sec = document.getElementById('sec-' + group);
  if (sec) sec.style.display = '';
  const btn = document.getElementById('tab-' + group);
  if (btn) btn.classList.add('active');
  history.replaceState(null, '', '?group=' + group);
}

// ── Live metric refresh ───────────────────────────────────────────────────
function refreshMetrics() {
  fetch('/api/metrics').then(r => r.json()).then(data => {
    if (!data.ok) return;
    Object.entries(data.metrics).forEach(([k, v]) => {
      const el = document.getElementById('m-' + k.replace(/[{}="]/g,'_'));
      if (el) el.textContent = Number(v).toLocaleString();
    });
  }).catch(() => {});
}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════
# Route helpers
# ══════════════════════════════════════════════════════════════════════════
def render(template_str: str, **kwargs):
    vk_ok = vk.ping()
    page_title = kwargs.pop("page_title", "DNS Dashboard")
    return render_template_string(BASE + template_str, vk_ok=vk_ok, page_title=page_title,
                                  current_user=session.get("user"), **kwargs)


# ══════════════════════════════════════════════════════════════════════════
# ── Authentication routes (migration Step 5) ──────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
LOGIN_TMPL = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in — DNS Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;background:#11151c;color:#e6e6e6;
   display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
 .card{background:#1b2230;padding:36px 40px;border-radius:10px;width:320px;
   box-shadow:0 8px 30px rgba(0,0,0,.4)}
 h1{font-size:1.15rem;margin:0 0 4px} p.sub{color:#8a93a3;font-size:.82rem;margin:0 0 22px}
 label{display:block;font-size:.8rem;margin:14px 0 5px;color:#b9c0cc}
 input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #333c4d;
   border-radius:5px;background:#10141b;color:#e6e6e6;font-size:.95rem}
 button{margin-top:22px;width:100%;padding:10px;border:0;border-radius:5px;
   background:#2d6db5;color:#fff;font-size:.95rem;cursor:pointer}
 button:hover{background:#3179c9}
 .err{margin-top:16px;background:#3a1d1d;border:1px solid #8a3b3b;color:#f1b0b0;
   padding:9px 11px;border-radius:5px;font-size:.85rem}
</style></head><body>
 <form class="card" method="POST" action="{{ url_for('login') }}">
   <h1>&#128274; DNS Dashboard</h1>
   <p class="sub">Sign in to manage the control plane.</p>
   {% with messages = get_flashed_messages(with_categories=true) %}
     {% for cat, msg in messages %}<div class="err">{{ msg }}</div>{% endfor %}
   {% endwith %}
   <input type="hidden" name="next" value="{{ next_url }}">
   <label>Username</label>
   <input name="username" autocomplete="username" autofocus>
   <label>Password</label>
   <input name="password" type="password" autocomplete="current-password">
   <button type="submit">Sign in</button>
 </form>
</body></html>"""


def _safe_next(target: str) -> str:
    """Only allow same-site relative redirects (no //host, no scheme)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authed"):
        return redirect(url_for("dashboard"))
    next_url = _safe_next(request.values.get("next", ""))
    if request.method == "POST":
        ip = _client_ip()
        fails, not_before = _login_fails.get(ip, (0, 0))
        if time.time() < not_before:
            flash("Too many attempts — wait a moment and try again.", "error")
            return render_template_string(LOGIN_TMPL, next_url=next_url), 429
        user = request.form.get("username", "")
        pw   = request.form.get("password", "")
        ok = (DASH_PW_HASH is not None
              and secrets.compare_digest(user, DASH_USER)
              and check_password_hash(DASH_PW_HASH, pw))
        if ok:
            _login_fails.pop(ip, None)
            session.clear()
            session["authed"] = True
            session["user"] = user
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=SESSION_HOURS)
            return redirect(next_url)
        # Failure: generic message + escalating backoff (constant-ish time).
        fails += 1
        delay = min(30, 2 ** min(fails, 5)) if fails > 2 else 0
        _login_fails[ip] = (fails, time.time() + delay)
        time.sleep(0.5)
        flash("Invalid credentials.", "error")
        return render_template_string(LOGIN_TMPL, next_url=next_url), 401
    return render_template_string(LOGIN_TMPL, next_url=next_url)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("login"))


def badge(rtype: str) -> str:
    cls = f"badge-{rtype}" if rtype in ("A","AAAA","CNAME","MX","TXT","SRV") else "badge-default"
    return f'<span class="badge {cls}">{rtype}</span>'


# ══════════════════════════════════════════════════════════════════════════
# ── Dashboard ─────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
DASHBOARD_TMPL = r"""
{% set _page_title = "Dashboard" %}
<div class="page-header">
  <div class="page-title">◈ <span>Dashboard</span></div>
  <div class="page-meta" id="last-refresh">—</div>
  <button class="btn btn-ghost btn-sm" onclick="refreshMetrics(); updateTs()">↺ Refresh</button>
</div>

<!-- Metric cards -->
<div class="metrics-grid">
  <div class="metric-card green">
    <div class="metric-label">Total Queries</div>
    <div class="metric-value" id="m-dns_queries_total">{{ m.get('dns_queries_total','—') }}</div>
    <div class="metric-sub">lifetime counter</div>
  </div>
  <div class="metric-card green">
    <div class="metric-label">NOERROR</div>
    <div class="metric-value" id="m-dns_responses_total_rcode__NOERROR__">{{ m.get('dns_responses_total{rcode="NOERROR"}','—') }}</div>
  </div>
  <div class="metric-card amber">
    <div class="metric-label">NXDOMAIN</div>
    <div class="metric-value" id="m-dns_responses_total_rcode__NXDOMAIN__">{{ m.get('dns_responses_total{rcode="NXDOMAIN"}','—') }}</div>
  </div>
  <div class="metric-card red">
    <div class="metric-label">REFUSED</div>
    <div class="metric-value" id="m-dns_responses_total_rcode__REFUSED__">{{ m.get('dns_responses_total{rcode="REFUSED"}','—') }}</div>
  </div>
  <div class="metric-card red">
    <div class="metric-label">SERVFAIL</div>
    <div class="metric-value" id="m-dns_responses_total_rcode__SERVFAIL__">{{ m.get('dns_responses_total{rcode="SERVFAIL"}','—') }}</div>
  </div>
  <div class="metric-card amber">
    <div class="metric-label">RRL Drops</div>
    <div class="metric-value" id="m-dns_rrl_total_action__drop__">{{ m.get('dns_rrl_total{action="drop"}','—') }}</div>
    <div class="metric-sub">rate-limited</div>
  </div>
  <div class="metric-card blue">
    <div class="metric-label">AXFR Done</div>
    <div class="metric-value" id="m-dns_axfr_total">{{ m.get('dns_axfr_total','—') }}</div>
  </div>
  <div class="metric-card blue">
    <div class="metric-label">DNSSEC Sigs</div>
    <div class="metric-value" id="m-dns_dnssec_signatures_total">{{ m.get('dns_dnssec_signatures_total','—') }}</div>
  </div>
  <div class="metric-card green">
    <div class="metric-label">DDNS Updates</div>
    <div class="metric-value" id="m-dns_ddns_total">{{ m.get('dns_ddns_total','—') }}</div>
  </div>
  <div class="metric-card amber">
    <div class="metric-label">Zone Serial</div>
    <div class="metric-value" id="m-dns_zone_serial" style="font-size:16px">{{ m.get('dns_zone_serial', serial) }}</div>
    <div class="metric-sub">{{ zone_name }}</div>
  </div>
</div>

<div class="two-col">
  <!-- Valkey status -->
  <div class="panel">
    <div class="panel-header"><span class="panel-title">◎ Valkey Status</span></div>
    <div class="panel-body">
      {% if vk_status.connected %}
        <table class="data-table">
          <tr><td class="dim">Version</td><td class="name">{{ vk_status.version }}</td></tr>
          <tr><td class="dim">Memory</td><td class="name">{{ vk_status.used_memory_human }}</td></tr>
          <tr><td class="dim">Clients</td><td class="name">{{ vk_status.connected_clients }}</td></tr>
          <tr><td class="dim">Uptime</td><td class="name">{{ (vk_status.uptime_in_seconds|int // 3600) }}h {{ ((vk_status.uptime_in_seconds|int % 3600) // 60) }}m</td></tr>
          <tr><td class="dim">Total Keys</td><td class="name">{{ vk_status.dbsize }}</td></tr>
          <tr><td class="dim">Zone Records</td><td class="name">{{ zone_count }}</td></tr>
          <tr><td class="dim">DDNS Records</td><td class="name">{{ ddns_count }}</td></tr>
          <tr><td class="dim">mDNS Records</td><td class="name">{{ mdns_count }}</td></tr>
        </table>
      {% else %}
        <div class="alert alert-error">Cannot connect to Valkey: {{ vk_status.get('error','unknown') }}</div>
      {% endif %}
    </div>
  </div>

  <!-- Quick zone info -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">⬡ Zone Summary</span>
      <a href="{{ url_for('records') }}" class="btn btn-ghost btn-sm">View All →</a>
    </div>
    <div class="panel-body">
      <table class="data-table">
        <tr><td class="dim">Zone</td><td class="name">{{ zone_name }}</td></tr>
        <tr><td class="dim">Serial</td><td class="name">{{ serial }}</td></tr>
        <tr><td class="dim">MNAME</td><td class="name">{{ mname }}</td></tr>
        <tr><td class="dim">AXFR Allow</td><td class="name">{{ axfr_allow or '(none)' }}</td></tr>
        <tr><td class="dim">TSIG</td><td class="name">{{ tsig_name or 'disabled' }}</td></tr>
        <tr><td class="dim">RRL</td>
          <td class="name">
            {% if rrl_enabled == '1' %}
              <span class="status-dot ok" style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:4px;"></span>enabled ({{ rrl_rate }}/{{ rrl_window }}s)
            {% else %}
              <span class="status-dot" style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--text-dim);margin-right:4px;"></span>disabled
            {% endif %}
          </td>
        </tr>
        <tr><td class="dim">Metrics URL</td><td><code>http://{{ dns_host }}:{{ dns_port }}/metrics</code></td></tr>
      </table>
    </div>
  </div>
</div>

<script>
function updateTs() {
  document.getElementById('last-refresh').textContent =
    'Updated ' + new Date().toLocaleTimeString();
}
updateTs();
// Auto-refresh every 15 s
setInterval(() => { refreshMetrics(); updateTs(); }, 15000);
</script>"""


@app.route("/")
def dashboard():
    m_data = fetch_metrics()
    m = m_data.get("raw", {})
    vk_status = valkey_status()
    zone_name = vk_get("config:zone_name") or "example.local"
    serial    = vk_get("config:zone_serial") or "1"
    mname     = vk_get("config:soa_mname") or f"ns1.{zone_name}"
    axfr_allow= vk_get("config:axfr_allow")
    tsig_name = vk_get("config:tsig_key_name")
    rrl_enabled = vk_get("config:rrl_enabled") or "0"
    rrl_rate    = vk_get("config:rrl_rate") or "5"
    rrl_window  = vk_get("config:rrl_window") or "1"
    try:
        zone_count = len(vk.scan_match("zone:*"))
        ddns_count = len(vk.scan_match("ddns:*"))
        mdns_count = len(vk.scan_match("mdns:*"))
    except Exception:
        zone_count = ddns_count = mdns_count = 0

    return render(DASHBOARD_TMPL,
        active="dashboard", page_title="Dashboard", m=m, vk_status=vk_status,
        zone_name=zone_name, serial=serial, mname=mname,
        axfr_allow=axfr_allow, tsig_name=tsig_name,
        rrl_enabled=rrl_enabled, rrl_rate=rrl_rate, rrl_window=rrl_window,
        zone_count=zone_count, ddns_count=ddns_count, mdns_count=mdns_count,
        dns_host=DNS_HOST, dns_port=DNS_METRICS_PORT)


# ══════════════════════════════════════════════════════════════════════════
# ── Live Metrics ──────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
METRICS_TMPL = r"""
{% set _page_title = "Live Metrics" %}
<div class="page-header">
  <div class="page-title">▤ <span>Live Metrics</span></div>
  <button class="btn btn-ghost btn-sm" onclick="location.reload()">↺ Reload</button>
</div>
{% if not metrics_ok %}
<div class="alert alert-warning">
  Cannot reach dns_server at <code>http://{{ dns_host }}:{{ dns_port }}/metrics</code> — {{ metrics_err }}
</div>
{% endif %}
<div class="panel">
  <div class="panel-header"><span class="panel-title">Prometheus Text Output</span></div>
  <div class="panel-body">
    <table class="data-table">
      <thead><tr><th>Metric</th><th>Value</th></tr></thead>
      <tbody>
        {% for k, v in metrics_rows %}
        <tr>
          <td><code>{{ k }}</code></td>
          <td class="val">{{ v }}</td>
        </tr>
        {% endfor %}
        {% if not metrics_rows %}
        <tr><td colspan="2" class="dim">No metrics available</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
</div>"""


@app.route("/metrics")
def metrics():
    m_data = fetch_metrics()
    rows = sorted(m_data.get("raw", {}).items())
    return render(METRICS_TMPL, active="metrics", page_title="Live Metrics",
        metrics_ok=m_data["ok"],
        metrics_err=m_data.get("error",""),
        metrics_rows=rows,
        dns_host=DNS_HOST, dns_port=DNS_METRICS_PORT)


@app.route("/api/metrics")
def api_metrics():
    m_data = fetch_metrics()
    return jsonify({"ok": m_data["ok"], "metrics": m_data.get("raw", {})})


# ══════════════════════════════════════════════════════════════════════════
# ── Zone Records ──────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
RECORDS_TMPL = r"""
{% set _page_title = "Zone Records" %}
<div class="page-header">
  <div class="page-title">▦ <span>Zone Records</span></div>
  <div class="page-meta">{{ records|length }} record(s)</div>
</div>

<!-- Add record form -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">+ Add / Update Record</span></div>
  <div class="panel-body">
    <form method="POST" action="{{ url_for('record_upsert') }}">
      <div class="form-grid">
        <div class="form-field">
          <label>Namespace</label>
          <select name="ns">
            <option value="zone">zone (static)</option>
            <option value="ddns">ddns (dynamic)</option>
          </select>
        </div>
        <div class="form-field">
          <label>Type</label>
          <select name="rtype">
            {% for t in rtypes %}<option>{{ t }}</option>{% endfor %}
          </select>
        </div>
        <div class="form-field">
          <label>Name (FQDN)</label>
          <input name="name" placeholder="host.example.local" required>
        </div>
        <div class="form-field">
          <label>Value</label>
          <input name="value" placeholder="192.168.1.10" required>
          <span class="hint">A/AAAA: IP · MX: prio|host · SRV: ttl|prio|weight|port|target · TXT: text</span>
        </div>
        <div class="form-field">
          <label>TTL (0 = persist)</label>
          <input name="ttl" type="number" value="300" min="0">
        </div>
      </div>
      <div style="margin-top:14px">
        <button type="submit" class="btn btn-success">⊕ Add / Update Record</button>
      </div>
    </form>
  </div>
</div>

<!-- Record list -->
<div class="panel">
  <div class="panel-header">
    <span class="panel-title">All Records</span>
    <div style="display:flex;gap:8px;align-items:center">
      <input id="rec-filter" onkeyup="filterTable('rec-filter','rec-table')"
             placeholder="filter…" style="background:var(--bg3);border:1px solid var(--border2);
             color:var(--text);font-family:var(--mono);font-size:11px;padding:4px 8px;
             border-radius:3px;outline:none;width:160px">
    </div>
  </div>
  <div class="panel-body" style="padding:0">
    <table class="data-table" id="rec-table">
      <thead><tr>
        <th>NS</th><th>Zone</th><th>Type</th><th>Name</th><th>Value</th><th>TTL</th><th>Actions</th>
      </tr></thead>
      <tbody>
        {% for r in records %}
        <tr>
          <td><span class="badge badge-{{ r.ns }}">{{ r.ns }}</span></td>
          <td class="dim">{{ r.zone }}</td>
          <td>{{ r.type|safe_badge }}</td>
          <td class="name">{{ r.name }}</td>
          <td class="val" title="{{ r.value }}">{{ r.value[:80] }}{% if r.value|length > 80 %}…{% endif %}</td>
          <td>
            {% if r.ttl == -1 %}<span class="ttl-badge">∞</span>
            {% elif r.ttl == -2 %}<span class="ttl-badge" style="color:var(--red)">ERR</span>
            {% else %}<span class="ttl-badge">{{ r.ttl }}s</span>{% endif %}
          </td>
          <td>
            <form method="POST" action="{{ url_for('record_delete') }}" style="display:inline">
              <input type="hidden" name="key" value="{{ r.key }}">
              <button type="submit" class="btn btn-danger btn-sm"
                onclick="return confirm('Delete {{ r.key }}?')">✕</button>
            </form>
          </td>
        </tr>
        {% endfor %}
        {% if not records %}
        <tr><td colspan="6" class="dim" style="text-align:center;padding:24px">No records found</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
</div>"""


@app.route("/records")
def records():
    recs = [r for r in get_zone_records() if r["ns"] == "zone"]
    return render(RECORDS_TMPL, active="records", page_title="Zone Records",
                  records=recs, rtypes=RECORD_TYPES)


@app.route("/ddns")
def ddns():
    recs = [r for r in get_zone_records() if r["ns"] == "ddns"]
    return render(RECORDS_TMPL, active="ddns", page_title="DDNS Records",
                  records=recs, rtypes=["A", "AAAA"])


@app.route("/records/upsert", methods=["POST"])
def record_upsert():
    ns    = request.form.get("ns", "zone")
    rtype = request.form.get("rtype", "A").upper()
    name  = request.form.get("name", "").strip().lower()
    value = request.form.get("value", "").strip()
    ttl   = int(request.form.get("ttl", 0))
    if not name or not value:
        flash("Name and value are required.", "error")
        return redirect(request.referrer or url_for("records"))
    zone = resolve_zone(name)
    if not zone:
        flash(f"No authoritative zone configured for {name}.", "error")
        return redirect(request.referrer or url_for("records"))
    key = f"{ns}:{zone}:{rtype}:{name}"
    try:
        vk.set(key, value, ex=ttl)
        flash(f"Set {key} = {value[:60]}", "success")
    except ValkeyError as e:
        flash(f"Valkey error: {e}", "error")
    return redirect(request.referrer or url_for("records"))


@app.route("/records/delete", methods=["POST"])
def record_delete():
    key = request.form.get("key", "")
    if not key:
        flash("No key specified.", "error")
        return redirect(url_for("records"))
    try:
        vk.delete(key)
        flash(f"Deleted {key}", "success")
    except ValkeyError as e:
        flash(f"Valkey error: {e}", "error")
    return redirect(request.referrer or url_for("records"))


# ══════════════════════════════════════════════════════════════════════════
# ── mDNS Records ──────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
MDNS_TMPL = r"""
{% set _page_title = "mDNS Records" %}
<div class="page-header">
  <div class="page-title">⊕ <span>mDNS Records</span></div>
  <div class="page-meta">{{ records|length }} record(s)</div>
</div>

<div class="panel">
  <div class="panel-header"><span class="panel-title">+ Add mDNS Record</span></div>
  <div class="panel-body">
    <form method="POST" action="{{ url_for('mdns_upsert') }}">
      <div class="form-grid">
        <div class="form-field">
          <label>Type</label>
          <select name="rtype">
            <option>A</option><option>AAAA</option>
            <option>PTR</option><option>SRV</option><option>TXT</option>
          </select>
        </div>
        <div class="form-field">
          <label>Name</label>
          <input name="name" placeholder="myhost.local" required>
        </div>
        <div class="form-field">
          <label>Value</label>
          <input name="value" placeholder="192.168.1.5" required>
          <span class="hint">PTR service: _http._tcp.local → host.local</span>
        </div>
      </div>
      <div style="margin-top:14px">
        <button type="submit" class="btn btn-success">⊕ Add mDNS Record</button>
      </div>
    </form>
  </div>
</div>

<div class="panel">
  <div class="panel-header"><span class="panel-title">mDNS Records</span></div>
  <div class="panel-body" style="padding:0">
    <table class="data-table">
      <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Action</th></tr></thead>
      <tbody>
        {% for r in records %}
        <tr>
          <td>{{ r.type|safe_badge }}</td>
          <td class="name">{{ r.name }}</td>
          <td class="val">{{ r.value }}</td>
          <td>
            <form method="POST" action="{{ url_for('record_delete') }}" style="display:inline">
              <input type="hidden" name="key" value="{{ r.key }}">
              <button class="btn btn-danger btn-sm" onclick="return confirm('Delete?')">✕</button>
            </form>
          </td>
        </tr>
        {% endfor %}
        {% if not records %}
        <tr><td colspan="4" class="dim" style="text-align:center;padding:24px">No mDNS records</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
</div>"""


@app.route("/mdns")
def mdns():
    return render(MDNS_TMPL, active="mdns", page_title="mDNS Records", records=get_mdns_records())


@app.route("/mdns/upsert", methods=["POST"])
def mdns_upsert():
    rtype = request.form.get("rtype", "A").upper()
    name  = request.form.get("name", "").strip().lower()
    value = request.form.get("value", "").strip()
    if not name or not value:
        flash("Name and value required.", "error")
        return redirect(url_for("mdns"))
    key = f"mdns:{rtype}:{name}"
    try:
        vk.set(key, value)
        flash(f"Set {key}", "success")
    except ValkeyError as e:
        flash(f"Valkey error: {e}", "error")
    return redirect(url_for("mdns"))


# ══════════════════════════════════════════════════════════════════════════
# ── Configuration ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
CONFIG_TMPL = r"""
{% set _page_title = "Configuration" %}
<div class="page-header">
  <div class="page-title">⚙ <span>Server Configuration</span></div>
  <div class="page-meta">Stored in Valkey config:* namespace</div>
</div>

<div class="tab-bar">
  {% for gid, (glabel, gicon) in groups.items() %}
  <button class="tab-btn" id="tab-{{ gid }}"
    onclick="showTab('{{ gid }}')">{{ gicon }} {{ glabel }}</button>
  {% endfor %}
</div>

<form method="POST" action="{{ url_for('config_save') }}">
  {% for gid, (glabel, gicon) in groups.items() %}
  <div class="config-section" id="sec-{{ gid }}" style="display:none">
    <div class="panel">
      <div class="panel-header"><span class="panel-title">{{ gicon }} {{ glabel }}</span></div>
      <div class="panel-body">
        <div class="form-grid">
          {% for key, label, itype, ph, group, desc in schema %}
            {% if group == gid %}
            <div class="form-field">
              <label>{{ label }}</label>
              <input type="{{ itype }}" name="{{ key }}"
                     value="{{ values.get(key, '') }}"
                     placeholder="{{ ph }}"
                     {% if itype == 'password' %}autocomplete="new-password"{% endif %}>
              <span class="hint">{{ desc }} — <span class="key-chip">config:{{ key }}</span></span>
            </div>
            {% endif %}
          {% endfor %}
        </div>
      </div>
    </div>
  </div>
  {% endfor %}

  <div style="margin-top:6px;display:flex;gap:10px">
    <button type="submit" class="btn btn-primary">⊘ Save Configuration</button>
    <span style="font-family:var(--mono);font-size:11px;color:var(--text-dim);line-height:2.4">
      Changes take effect on next server config reload.
    </span>
  </div>
</form>

<script>
// Activate the tab from URL param or default to zone
const urlGroup = new URLSearchParams(window.location.search).get('group') || '{{ active_group }}';
showTab(urlGroup);
</script>"""


@app.route("/config")
def config():
    group = request.args.get("group", "zone")
    values = {}
    for key, *_ in CONFIG_SCHEMA:
        values[key] = vk_get(f"config:{key}")
    return render(CONFIG_TMPL, active="config", page_title="Configuration",
                  schema=CONFIG_SCHEMA, values=values,
                  groups=GROUP_META, active_group=group)


@app.route("/config/save", methods=["POST"])
def config_save():
    saved = []
    for key, *_ in CONFIG_SCHEMA:
        val = request.form.get(key, "")
        if val:  # only set non-empty values
            if vk_set(f"config:{key}", val):
                saved.append(key)
    flash(f"Saved {len(saved)} config key(s). Restart or reload dns_server to apply.", "success")
    group = request.form.get("_active_group", "zone")
    return redirect(url_for("config", group=group))


# ══════════════════════════════════════════════════════════════════════════
# ── DNSSEC ────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
DNSSEC_TMPL = r"""
{% set _page_title = "DNSSEC" %}
<div class="page-header">
  <div class="page-title">✦ <span>DNSSEC Keys</span></div>
</div>

<div class="two-col">
  <div class="panel">
    <div class="panel-header"><span class="panel-title">Key Inventory</span></div>
    <div class="panel-body">
      <table class="data-table">
        {% for key, info in dnssec.items() if not key.startswith('nsec') %}
        <tr>
          <td class="dim" style="width:180px"><code>{{ key }}</code></td>
          <td>
            {% if info.present %}
              <span class="status-dot ok" style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:5px"></span>
              <span style="color:var(--green)">Present</span>
            {% else %}
              <span class="status-dot" style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--red);margin-right:5px"></span>
              <span style="color:var(--red)">Missing</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header"><span class="panel-title">NSEC3 Parameters</span></div>
    <div class="panel-body">
      <form method="POST" action="{{ url_for('dnssec_save') }}">
        <div class="form-grid">
          <div class="form-field">
            <label>NSEC3 Iterations</label>
            <input name="nsec3_iters" type="number" value="{{ dnssec.nsec3_iters }}" min="0" max="10">
            <span class="hint">RFC 9276: 0–1 recommended · <code>config:nsec3_iters</code></span>
          </div>
          <div class="form-field">
            <label>NSEC3 Salt (hex)</label>
            <input name="nsec3_salt" value="{{ dnssec.nsec3_salt if dnssec.nsec3_salt != '(none)' else '' }}" placeholder="empty = no salt">
            <span class="hint"><code>config:nsec3_salt</code></span>
          </div>
        </div>
        <div style="margin-top:14px">
          <button type="submit" class="btn btn-primary">Save NSEC3 Config</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- Key regeneration -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">⚠ Key Management</span></div>
  <div class="panel-body">
    <p style="color:var(--text-dim);font-family:var(--mono);font-size:12px;margin-bottom:12px">
      DNSSEC keys are auto-generated by dns_server on first start and stored in Valkey.
      To force regeneration, delete the key from Valkey and restart the server.
    </p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      {% for key in ['dnssec:zsk','dnssec:zsk_ed25519','dnssec:ksk','dnssec:ksk_ed25519'] %}
      <form method="POST" action="{{ url_for('dnssec_delete_key') }}" style="display:inline">
        <input type="hidden" name="key" value="{{ key }}">
        <button type="submit" class="btn btn-danger btn-sm"
          onclick="return confirm('Delete {{ key }}? The server will regenerate it on next start.')">
          ✕ {{ key }}
        </button>
      </form>
      {% endfor %}
    </div>
  </div>
</div>"""


@app.route("/dnssec")
def dnssec_page():
    return render(DNSSEC_TMPL, active="dnssec", page_title="DNSSEC", dnssec=get_dnssec_info())


@app.route("/dnssec/save", methods=["POST"])
def dnssec_save():
    iters = request.form.get("nsec3_iters", "1")
    salt  = request.form.get("nsec3_salt", "")
    vk_set("config:nsec3_iters", iters)
    vk_set("config:nsec3_salt", salt)
    flash("NSEC3 parameters saved.", "success")
    return redirect(url_for("dnssec_page"))


@app.route("/dnssec/delete-key", methods=["POST"])
def dnssec_delete_key():
    key = request.form.get("key", "")
    if key.startswith("dnssec:"):
        vk_del(key)
        flash(f"Deleted {key} — server will regenerate on next start.", "warning")
    return redirect(url_for("dnssec_page"))


# ══════════════════════════════════════════════════════════════════════════
# ── PKI / TLS ─────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
PKI_TMPL = r"""
{% set _page_title = "PKI / TLS" %}
<div class="page-header">
  <div class="page-title">⬤ <span>PKI / TLS / ACME</span></div>
</div>

<div class="two-col">
  <!-- ACME -->
  <div class="panel">
    <div class="panel-header"><span class="panel-title">ACME (Let's Encrypt)</span></div>
    <div class="panel-body">
      <form method="POST" action="{{ url_for('pki_save') }}">
        <div class="form-grid">
          {% for row in pki_fields['acme'] %}
          <div class="form-field {% if row.wide %}form-full{% endif %}">
            <label>{{ row.label }}</label>
            <input type="{{ row.type }}" name="{{ row.key }}"
                   value="{{ values.get(row.key,'') }}" placeholder="{{ row.ph }}">
            <span class="hint"><code>config:{{ row.key }}</code></span>
          </div>
          {% endfor %}
        </div>
        <div style="margin-top:14px">
          <button type="submit" name="_section" value="acme" class="btn btn-primary">Save ACME Config</button>
        </div>
      </form>
    </div>
  </div>

  <!-- EST -->
  <div class="panel">
    <div class="panel-header"><span class="panel-title">EST (Private CA)</span></div>
    <div class="panel-body">
      <form method="POST" action="{{ url_for('pki_save') }}">
        <div class="form-grid">
          {% for row in pki_fields['est'] %}
          <div class="form-field {% if row.wide %}form-full{% endif %}">
            <label>{{ row.label }}</label>
            <input type="{{ row.type }}" name="{{ row.key }}"
                   value="{{ values.get(row.key,'') }}" placeholder="{{ row.ph }}">
            <span class="hint"><code>config:{{ row.key }}</code></span>
          </div>
          {% endfor %}
        </div>
        <div style="margin-top:14px">
          <button type="submit" name="_section" value="est" class="btn btn-primary">Save EST Config</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- TLS Cert / Key status -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">Active TLS Certificate</span></div>
  <div class="panel-body">
    <table class="data-table">
      <tr>
        <td class="dim">config:tls_cert_pem</td>
        <td class="name">
          {% if cert_present %}
            <span style="color:var(--green)">✓ Certificate present</span>
            ({{ cert_lines }} lines)
          {% else %}
            <span style="color:var(--text-dim)">Not configured — server uses self-signed</span>
          {% endif %}
        </td>
      </tr>
      <tr>
        <td class="dim">config:tls_key_pem</td>
        <td class="name">
          {% if key_present %}
            <span style="color:var(--green)">✓ Private key present</span>
          {% else %}
            <span style="color:var(--text-dim)">Not configured</span>
          {% endif %}
        </td>
      </tr>
      <tr>
        <td class="dim">config:mtls_ca_pem</td>
        <td class="name">
          {% if mtls_present %}
            <span style="color:var(--green)">✓ mTLS CA chain present</span>
          {% else %}
            <span style="color:var(--text-dim)">Not configured — mTLS client auth disabled</span>
          {% endif %}
        </td>
      </tr>
      <tr>
        <td class="dim">est:cacerts</td>
        <td class="name">
          {% if est_cacerts %}
            <span style="color:var(--green)">✓ EST CA chain cached</span>
          {% else %}
            <span style="color:var(--text-dim)">Not fetched yet</span>
          {% endif %}
        </td>
      </tr>
    </table>
  </div>
</div>

<!-- Upload PEM -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">Upload TLS Certificate / Key</span></div>
  <div class="panel-body">
    <form method="POST" action="{{ url_for('pki_upload_pem') }}">
      <div class="form-grid">
        <div class="form-field form-full">
          <label>Target Key</label>
          <select name="pem_key">
            <option value="tls_cert_pem">config:tls_cert_pem (certificate)</option>
            <option value="tls_key_pem">config:tls_key_pem (private key)</option>
            <option value="mtls_ca_pem">config:mtls_ca_pem (mTLS CA chain)</option>
            <option value="acme_ca_pem">config:acme_ca_pem (ACME CA cert)</option>
            <option value="est_ca_pem">config:est_ca_pem (EST CA cert)</option>
          </select>
        </div>
        <div class="form-field form-full">
          <label>PEM Content</label>
          <textarea name="pem_value" rows="8" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
            style="font-size:11px;resize:vertical"></textarea>
        </div>
      </div>
      <div style="margin-top:14px">
        <button type="submit" class="btn btn-success">⊕ Store PEM</button>
        <span class="hint" style="margin-left:12px">Server hot-reloads TLS on cert/key update.</span>
      </div>
    </form>
  </div>
</div>"""


@app.route("/pki")
def pki():
    pki_fields = {
        "acme": [
            {"key":"acme_domain","label":"ACME Domain","type":"text","ph":"example.com","wide":False},
            {"key":"acme_email", "label":"ACME Email", "type":"email","ph":"admin@example.com","wide":False},
            {"key":"acme_ca",    "label":"ACME CA URL","type":"url", "ph":"https://acme-v02.api.letsencrypt.org/directory","wide":True},
        ],
        "est": [
            {"key":"est_server","label":"EST Server","type":"text","ph":"pki.corp.local:8443","wide":False},
            {"key":"est_domain","label":"EST Domain","type":"text","ph":"server.corp.local","wide":False},
        ],
    }
    values = {f["key"]: vk_get(f"config:{f['key']}") for fs in pki_fields.values() for f in fs}
    cert_val  = vk_get("config:tls_cert_pem")
    key_val   = vk_get("config:tls_key_pem")
    mtls_val  = vk_get("config:mtls_ca_pem")
    est_ca    = vk_get("est:cacerts")
    return render(PKI_TMPL, active="pki", page_title="PKI / TLS",
        pki_fields=pki_fields, values=values,
        cert_present=bool(cert_val), cert_lines=cert_val.count("\n"),
        key_present=bool(key_val), mtls_present=bool(mtls_val),
        est_cacerts=bool(est_ca))


@app.route("/pki/save", methods=["POST"])
def pki_save():
    keys = ["acme_domain","acme_email","acme_ca","est_server","est_domain"]
    saved = []
    for k in keys:
        v = request.form.get(k, "")
        if v:
            vk_set(f"config:{k}", v)
            saved.append(k)
    flash(f"Saved {len(saved)} PKI key(s).", "success")
    return redirect(url_for("pki"))


@app.route("/pki/upload-pem", methods=["POST"])
def pki_upload_pem():
    pem_key = request.form.get("pem_key", "")
    pem_val = request.form.get("pem_value", "").strip()
    if not pem_key or not pem_val:
        flash("Both key and PEM content are required.", "error")
        return redirect(url_for("pki"))
    allowed = {"tls_cert_pem","tls_key_pem","mtls_ca_pem","acme_ca_pem","est_ca_pem"}
    if pem_key not in allowed:
        flash("Invalid PEM key.", "error")
        return redirect(url_for("pki"))
    if not pem_val.startswith("-----BEGIN"):
        flash("Value does not look like a PEM block.", "warning")
    vk_set(f"config:{pem_key}", pem_val)
    flash(f"Stored config:{pem_key} ({len(pem_val)} chars). Server will hot-reload TLS.", "success")
    return redirect(url_for("pki"))


# ══════════════════════════════════════════════════════════════════════════
# ── AXFR / NOTIFY ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
XFR_TMPL = r"""
{% set _page_title = "AXFR / NOTIFY" %}
<div class="page-header">
  <div class="page-title">⇄ <span>Zone Transfer & NOTIFY</span></div>
</div>

<div class="two-col">
  <div class="panel">
    <div class="panel-header"><span class="panel-title">AXFR Configuration</span></div>
    <div class="panel-body">
      <form method="POST" action="{{ url_for('xfr_save') }}">
        <div class="form-grid">
          <div class="form-field form-full">
            <label>AXFR Allow List</label>
            <input name="axfr_allow" value="{{ axfr_allow }}"
                   placeholder="127.0.0.1, 10.0.0.0/8">
            <span class="hint">Comma-separated IPs/CIDRs · <code>config:axfr_allow</code></span>
          </div>
          <div class="form-field form-full">
            <label>NOTIFY Targets</label>
            <input name="notify_targets" value="{{ notify_targets }}"
                   placeholder="10.0.0.2:53, 10.0.0.3:5353">
            <span class="hint">Comma-separated host:port · <code>config:notify_targets</code></span>
          </div>
        </div>
        <div style="margin-top:14px">
          <button type="submit" class="btn btn-primary">Save</button>
        </div>
      </form>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header"><span class="panel-title">Transfer Stats</span></div>
    <div class="panel-body">
      <table class="data-table">
        <tr><td class="dim">AXFR completed</td>
            <td class="name" id="m-dns_axfr_total">{{ axfr_total }}</td></tr>
        <tr><td class="dim">IXFR journal size</td>
            <td class="name">{{ ixfr_len }} entries</td></tr>
        <tr><td class="dim">Zone serial</td>
            <td class="name">{{ serial }}</td></tr>
      </table>
      <div style="margin-top:14px">
        <a href="{{ url_for('ixfr_journal') }}" class="btn btn-ghost btn-sm">View IXFR Journal →</a>
      </div>
    </div>
  </div>
</div>"""


@app.route("/xfr")
def xfr():
    m = fetch_metrics().get("raw", {})
    return render(XFR_TMPL, active="xfr", page_title="Zone Transfer",
        axfr_allow=vk_get("config:axfr_allow"),
        notify_targets=vk_get("config:notify_targets"),
        axfr_total=m.get("dns_axfr_total","—"),
        ixfr_len=vk.llen("ixfr:journal"),
        serial=vk_get("config:zone_serial"))


@app.route("/xfr/save", methods=["POST"])
def xfr_save():
    vk_set("config:axfr_allow",     request.form.get("axfr_allow",""))
    vk_set("config:notify_targets", request.form.get("notify_targets",""))
    flash("Transfer config saved.", "success")
    return redirect(url_for("xfr"))


# ══════════════════════════════════════════════════════════════════════════
# ── IXFR Journal ──────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
IXFR_TMPL = r"""
{% set _page_title = "IXFR Journal" %}
<div class="page-header">
  <div class="page-title">▤ <span>IXFR Journal</span></div>
  <div class="page-meta">{{ entries|length }} of {{ total }} entries (newest first)</div>
  <form method="POST" action="{{ url_for('ixfr_clear') }}" style="margin-left:auto">
    <button type="submit" class="btn btn-danger btn-sm"
      onclick="return confirm('Clear entire IXFR journal?')">✕ Clear Journal</button>
  </form>
</div>
<div class="panel">
  <div class="panel-header"><span class="panel-title">Recent Journal Entries</span></div>
  <div class="panel-body" style="padding:0">
    <table class="data-table">
      <thead><tr><th>#</th><th>Journal Entry</th></tr></thead>
      <tbody>
        {% for i, e in entries %}
        <tr>
          <td class="dim" style="width:40px">{{ i }}</td>
          <td><code style="font-size:11px;word-break:break-all">{{ e }}</code></td>
        </tr>
        {% else %}
        <tr><td colspan="2" class="dim" style="text-align:center;padding:24px">Journal is empty</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>"""


@app.route("/ixfr")
def ixfr_journal():
    entries_raw = get_ixfr_journal(50)
    total = vk.llen("ixfr:journal")
    return render(IXFR_TMPL, active="ixfr", page_title="IXFR Journal",
        entries=list(enumerate(entries_raw, 1)), total=total)


@app.route("/ixfr/clear", methods=["POST"])
def ixfr_clear():
    try:
        vk.delete("ixfr:journal")
        flash("IXFR journal cleared.", "success")
    except ValkeyError as e:
        flash(f"Error: {e}", "error")
    return redirect(url_for("ixfr_journal"))


# ══════════════════════════════════════════════════════════════════════════
# ── Valkey Explorer ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
EXPLORER_TMPL = r"""
{% set _page_title = "Valkey Explorer" %}
<div class="page-header">
  <div class="page-title">◎ <span>Valkey Explorer</span></div>
  <div class="page-meta">{{ total_keys }} total keys</div>
</div>

<!-- Pattern search -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">Key Search</span></div>
  <div class="panel-body">
    <form method="GET" action="{{ url_for('valkey_explorer') }}">
      <div class="search-bar">
        <input name="pattern" value="{{ pattern }}" placeholder="Pattern: config:*, zone:A:*, *">
        <button type="submit" class="btn btn-primary">Search</button>
        <a href="{{ url_for('valkey_explorer') }}" class="btn btn-ghost">Reset</a>
      </div>
    </form>

    {% if results is not none %}
    <table class="data-table">
      <thead><tr><th>Key</th><th>Value</th><th>TTL</th><th>Actions</th></tr></thead>
      <tbody>
        {% for row in results %}
        <tr>
          <td><code>{{ row.key }}</code></td>
          <td class="val" title="{{ row.value }}">
            {% if row.value|length > 100 %}{{ row.value[:100] }}…{% else %}{{ row.value }}{% endif %}
          </td>
          <td>
            {% if row.ttl == -1 %}<span class="ttl-badge">∞</span>
            {% else %}<span class="ttl-badge">{{ row.ttl }}s</span>{% endif %}
          </td>
          <td>
            <form method="POST" action="{{ url_for('explorer_delete') }}" style="display:inline">
              <input type="hidden" name="key" value="{{ row.key }}">
              <input type="hidden" name="pattern" value="{{ pattern }}">
              <button class="btn btn-danger btn-sm"
                onclick="return confirm('Delete {{ row.key }}?')">✕</button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="4" class="dim" style="text-align:center;padding:24px">No keys match "{{ pattern }}"</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}
  </div>
</div>

<!-- Quick set -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">Set Key</span></div>
  <div class="panel-body">
    <form method="POST" action="{{ url_for('explorer_set') }}">
      <div class="form-grid">
        <div class="form-field">
          <label>Key</label>
          <input name="key" placeholder="config:zone_name" required>
        </div>
        <div class="form-field">
          <label>Value</label>
          <input name="value" placeholder="example.local" required>
        </div>
        <div class="form-field">
          <label>TTL (0 = no expiry)</label>
          <input name="ttl" type="number" value="0" min="0">
        </div>
      </div>
      <div style="margin-top:14px">
        <button type="submit" class="btn btn-success">Set Key</button>
      </div>
    </form>
  </div>
</div>

<!-- Namespace summary -->
<div class="panel">
  <div class="panel-header"><span class="panel-title">Namespace Summary</span></div>
  <div class="panel-body">
    <div class="metrics-grid" style="grid-template-columns:repeat(auto-fill,minmax(120px,1fr))">
      {% for ns, count, color in ns_summary %}
      <div class="metric-card {{ color }}">
        <div class="metric-label">{{ ns }}</div>
        <div class="metric-value" style="font-size:22px">{{ count }}</div>
      </div>
      {% endfor %}
    </div>
  </div>
</div>"""


@app.route("/explorer")
def valkey_explorer():
    pattern = request.args.get("pattern", "")
    results = None
    if pattern:
        try:
            keys = vk.scan_match(pattern)
            values = vk.mget(keys) if keys else []
            ttls   = [vk.ttl(k) for k in keys]
            # Mask secret-bearing values so a read-only Explorer view never
            # leaks the TSIG/cookie secret or DNSSEC private keys.
            results = [{"key": k,
                        "value": ("••• (hidden)" if is_secret_key(k)
                                  else (v or "")),
                        "ttl": t,
                        "secret": is_secret_key(k)}
                       for k, v, t in zip(keys, values, ttls)]
            results.sort(key=lambda r: r["key"])
        except ValkeyError:
            results = []

    ns_map = [
        ("config:",    "amber"),
        ("zone:",      "green"),
        ("ddns:",      "amber"),
        ("mdns:",      "blue"),
        ("dnssec:",    "green"),
        ("acme:",      "blue"),
        ("est:",       "blue"),
        ("ixfr:",      "amber"),
        ("stale:",     ""),
    ]
    ns_summary = []
    try:
        total_keys = vk.dbsize()
        for ns, color in ns_map:
            count = len(vk.scan_match(ns + "*"))
            ns_summary.append((ns.rstrip(":"), count, color))
    except ValkeyError:
        total_keys = 0

    return render(EXPLORER_TMPL, active="explorer", page_title="Valkey Explorer",
        pattern=pattern, results=results, explorer_write=EXPLORER_WRITE,
        total_keys=total_keys, ns_summary=ns_summary)


@app.route("/explorer/set", methods=["POST"])
def explorer_set():
    key = request.form.get("key", "")
    val = request.form.get("value", "")
    ttl = int(request.form.get("ttl", 0))
    if not EXPLORER_WRITE:
        flash("Raw Explorer writes are disabled. Use the dedicated config pages, "
              "or set DASHBOARD_ENABLE_EXPLORER_WRITE=1.", "error")
        return redirect(url_for("valkey_explorer", pattern=request.form.get("pattern", "")))
    if not key:
        flash("Key required.", "error")
        return redirect(url_for("valkey_explorer"))
    if is_secret_key(key):
        flash(f"Refusing raw write to secret-bearing key {key}. "
              "Use the DNSSEC/PKI/config pages.", "error")
        return redirect(url_for("valkey_explorer", pattern=key.rsplit(":", 1)[0] + ":*"))
    try:
        vk.set(key, val, ex=ttl)
        flash(f"Set {key}", "success")
    except ValkeyError as e:
        flash(str(e), "error")
    return redirect(url_for("valkey_explorer", pattern=key.rsplit(":", 1)[0] + ":*"))


@app.route("/explorer/delete", methods=["POST"])
def explorer_delete():
    key     = request.form.get("key", "")
    pattern = request.form.get("pattern", "")
    if not EXPLORER_WRITE:
        flash("Raw Explorer deletes are disabled. Use the dedicated config pages, "
              "or set DASHBOARD_ENABLE_EXPLORER_WRITE=1.", "error")
        return redirect(url_for("valkey_explorer", pattern=pattern))
    if key and is_secret_key(key):
        flash(f"Refusing raw delete of secret-bearing key {key}.", "error")
        return redirect(url_for("valkey_explorer", pattern=pattern))
    if key:
        try:
            vk.delete(key)
            flash(f"Deleted {key}", "success")
        except ValkeyError as e:
            flash(str(e), "error")
    return redirect(url_for("valkey_explorer", pattern=pattern))


# ══════════════════════════════════════════════════════════════════════════
# ── Template filter ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
@app.template_filter("safe_badge")
def safe_badge_filter(rtype: str) -> str:
    cls = (f"badge-{rtype}"
           if rtype in ("A","AAAA","CNAME","MX","TXT","SRV")
           else "badge-default")
    return f'<span class="badge {cls}">{rtype}</span>'


# ══════════════════════════════════════════════════════════════════════════
# ── CLI entry point ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════
def main():
    global vk, DNS_HOST, DNS_METRICS_PORT

    parser = argparse.ArgumentParser(description="DNS Server Dashboard")
    parser.add_argument("--host",             default=os.getenv("DASHBOARD_HOST","127.0.0.1"))
    parser.add_argument("--port",       type=int, default=int(os.getenv("DASHBOARD_PORT","5000")))
    parser.add_argument("--valkey-host",      default=os.getenv("VALKEY_HOST","127.0.0.1"))
    parser.add_argument("--valkey-port", type=int, default=int(os.getenv("VALKEY_PORT","6379")))
    parser.add_argument("--valkey-pass",      default=os.getenv("VALKEY_PASS",""))
    parser.add_argument("--dns-host",         default=os.getenv("DNS_HOST","127.0.0.1"))
    parser.add_argument("--dns-metrics-port", type=int, default=int(os.getenv("DNS_METRICS_PORT","8053")))
    parser.add_argument("--secret-key",       default=os.getenv("FLASK_SECRET_KEY","change-in-production"))
    parser.add_argument("--gen-password-hash", metavar="PASSWORD",
                        help="print a password hash for DASHBOARD_PASSWORD_HASH / "
                             "config:dashboard_password_hash and exit")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # Provisioning helper: hash a password for out-of-band credential setup.
    if args.gen_password_hash:
        print(generate_password_hash(args.gen_password_hash))
        return

    DNS_HOST          = args.dns_host
    DNS_METRICS_PORT  = args.dns_metrics_port
    vk = ValkeyClient(args.valkey_host, args.valkey_port, args.valkey_pass)

    # Step 5: refuse to serve without authentication configured.
    err = configure_auth(args.secret_key)
    if err:
        print(f"[dns-dashboard] FATAL: {err}")
        print("[dns-dashboard] Provision one with:  "
              "python3 app.py --gen-password-hash 'yourpass'")
        raise SystemExit(1)

    if args.debug:
        print("[dns-dashboard] WARNING: --debug enables the Werkzeug debugger; "
              "never use it on an exposed instance.")
    print(f"[dns-dashboard] Auth    → user '{DASH_USER}'; "
          f"Explorer writes {'ENABLED' if EXPLORER_WRITE else 'disabled'}")
    print(f"[dns-dashboard] Valkey  → {args.valkey_host}:{args.valkey_port}")
    print(f"[dns-dashboard] Metrics → http://{DNS_HOST}:{DNS_METRICS_PORT}/metrics")
    print(f"[dns-dashboard] Serving → http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
