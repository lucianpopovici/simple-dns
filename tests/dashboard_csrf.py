#!/usr/bin/env python3
"""CSA-WEB-001 regression (CLAUDE-medium-fixes.md 7g): the dashboard rejects a
state-changing request without the per-session CSRF token, accepts it with
the token, and sets a hardened session cookie. Uses Flask's test client
against a real Valkey (DNS_VALKEY_HOST/PORT, default 127.0.0.1:6379).

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

PW = "csrf-test-" + os.urandom(6).hex()
KEY = "zone:example.local:TXT:csrftest.example.local"
fails = []


def check(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def token_from(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else None


os.environ["DASHBOARD_PASSWORD"] = PW
dash.vk = ValkeyClient(os.getenv("DNS_VALKEY_HOST", "127.0.0.1"),
                       int(os.getenv("DNS_VALKEY_PORT", "6379")), "")
err = dash.configure_auth("")
if err:
    print(f"  FAIL  configure_auth: {err}")
    sys.exit(1)
dash.app.config["TESTING"] = True

c = dash.app.test_client()

# Login form: carries a token; a login POST without it is refused (no login CSRF).
r = c.get("/login")
tok = token_from(r.get_data(as_text=True))
check(tok is not None, "login form carries a csrf_token field")
r = c.post("/login", data={"username": "admin", "password": PW})
check(r.status_code == 400, f"login POST without token -> {r.status_code} (want 400)")

r = c.post("/login", data={"username": "admin", "password": PW, "csrf_token": tok})
check(r.status_code == 302, f"login POST with token -> {r.status_code} (want 302)")
sc = r.headers.get("Set-Cookie", "")
check("SameSite=Strict" in sc, "session cookie SameSite=Strict")
check("HttpOnly" in sc, "session cookie HttpOnly")
check("Secure" in sc, "session cookie Secure by default")

# Every POST form on an authenticated page carries the token.
html = c.get("/records").get_data(as_text=True)
forms = re.findall(r'<form\b[^>]*method="POST"[^>]*>(.{0,200})', html, re.I | re.S)
check(len(forms) > 0 and all('name="csrf_token"' in f for f in forms),
      f"all {len(forms)} POST forms on /records carry the token")
tok = token_from(html)

# ...and so does every other page (each renders, and none has a bare form).
bare = []
pages = 0
for rule in dash.app.url_map.iter_rules():
    if "GET" not in rule.methods or rule.arguments or rule.endpoint in ("static", "logout"):
        continue
    if rule.rule.startswith("/api/"):
        continue
    r = c.get(rule.rule)
    if r.status_code != 200 or "text/html" not in r.content_type:
        continue
    pages += 1
    for f in re.findall(r'<form\b[^>]*method="POST"[^>]*>(.{0,200})', r.get_data(as_text=True),
                        re.I | re.S):
        if 'name="csrf_token"' not in f:
            bare.append(rule.rule)
check(pages >= 5 and not bare, f"{pages} pages render; POST forms without a token: {bare or 'none'}")

dash.vk.set(KEY, "300|csrf")
r = c.post("/records/delete", data={"key": KEY})
check(r.status_code == 400, f"state-changing POST without token -> {r.status_code} (want 400)")
check(dash.vk.get(KEY) is not None, "record survives the token-less POST")
r = c.post("/records/delete", data={"key": KEY, "csrf_token": "x" * len(tok)})
check(r.status_code == 400, f"POST with a wrong token -> {r.status_code} (want 400)")
r = c.post("/records/delete", data={"key": KEY, "csrf_token": tok})
check(r.status_code == 302, f"POST with token -> {r.status_code} (want 302)")
check(dash.vk.get(KEY) is None, "record deleted by the tokened POST")

# Logout is POST-only and token-checked (no forced logout via a link).
check(c.get("/logout").status_code == 405, "GET /logout not allowed")
check(c.post("/logout").status_code == 400, "POST /logout without token refused")
check(c.post("/logout", data={"csrf_token": tok}).status_code == 302, "POST /logout with token")

dash.vk.delete(KEY)
if fails:
    print(f"  FAIL  {len(fails)} CSRF check(s) failed (CSA-WEB-001)")
    sys.exit(1)
print("  OK  dashboard enforces CSRF tokens and hardened session cookies")
