#!/usr/bin/env python3
"""CSA-WEB-002 regression (CLAUDE-low-fixes.md 8d): the dashboard login
throttle cannot be dodged by rotating X-Forwarded-For, honours the header
only behind a configured proxy, and its table stays bounded. Flask test
client against a real Valkey (DNS_VALKEY_HOST/PORT, default 127.0.0.1:6379).

Exit 0 = pass, 1 = fail, 77 = skipped (Flask not installed).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "dashboard"))

try:
    import app as dash  # noqa: E402
    from valkey_client import ValkeyClient  # noqa: E402
except ImportError as e:
    print(f"  SKIP  dashboard deps not installed ({e})")
    sys.exit(77)

fails = []


def check(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


os.environ["DASHBOARD_PASSWORD"] = "throttle-test-" + os.urandom(6).hex()
dash.vk = ValkeyClient(os.getenv("DNS_VALKEY_HOST", "127.0.0.1"),
                       int(os.getenv("DNS_VALKEY_PORT", "6379")), "")
if dash.configure_auth(""):
    print("  FAIL  configure_auth")
    sys.exit(1)
dash.app.config["TESTING"] = True
dash.time.sleep = lambda s: None  # skip the per-failure 0.5 s delay in tests


def attempt(peer, xff=None):
    """One failed login from `peer` (optionally with X-Forwarded-For)."""
    c = dash.app.test_client()
    env = {"REMOTE_ADDR": peer}
    page = c.get("/login", environ_base=env).get_data(as_text=True)
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    hdrs = {"X-Forwarded-For": xff} if xff else {}
    r = c.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": tok},
               environ_base=env, headers=hdrs)
    return r.status_code


def reset():
    dash._login_fails.clear()


# 1. Untrusted peer rotating X-Forwarded-For is still throttled by its address.
dash.TRUSTED_PROXIES = []
reset()
codes = [attempt("10.9.9.9", xff=f"203.0.113.{i}") for i in range(4)]
check(codes[:3] == [401, 401, 401] and codes[3] == 429,
      f"rotating X-Forwarded-For from an untrusted peer is still throttled ({codes})")

# 2. Behind a trusted proxy the header identifies the client.
dash.TRUSTED_PROXIES = dash._parse_proxies("127.0.0.1")
reset()
codes = [attempt("127.0.0.1", xff="198.51.100.7") for i in range(3)]
blocked = attempt("127.0.0.1", xff="198.51.100.7")
other = attempt("127.0.0.1", xff="198.51.100.8")
check(blocked == 429 and other == 401,
      f"behind a trusted proxy: throttled client={blocked}, a different client={other}")
spoof = attempt("127.0.0.1", xff="198.51.100.7, 127.0.0.1")
check(spoof == 429, f"right-most untrusted hop is used (proxy appended itself) -> {spoof}")

# 3. The table stays bounded.
dash.TRUSTED_PROXIES = []
reset()
dash.LOGIN_TABLE_MAX = 50
for i in range(200):
    attempt(f"10.1.{i // 256}.{i % 256}")
check(len(dash._login_fails) <= 50, f"table bounded: {len(dash._login_fails)} entries after 200 clients")

if fails:
    print(f"  FAIL  {len(fails)} throttle check(s) failed (CSA-WEB-002)")
    sys.exit(1)
print("  OK  login throttle keyed on the real client, bounded table")
