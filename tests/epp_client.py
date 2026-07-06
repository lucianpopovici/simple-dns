#!/usr/bin/env python3
"""Minimal RFC 5730/5734 EPP client, for `make check-eppd` (eppd Phase 1 + 2).
No standard tool (dig/kdig) speaks EPP, so this hand-rolls just enough of
the wire format: RFC 5734's 4-byte big-endian length-prefixed framing
carrying RFC 5730 command/response XML. Runs a fixed scripted session
end-to-end — Phase 1: login, contact/host/domain create, info, duplicate-
create rejection, logout; Phase 2: update (NS/status/registrant/secDNS),
cross-registrar authorization, domain:transfer (request/query/approve),
delete into redemptionPeriod + rgp:restore, and host/contact delete blocked
by association — against a real eppd instance, printing one PASS/FAIL line
per step plus a final "ALL TESTS PASSED" / "SOME TESTS FAILED" sentinel
line the Makefile recipe greps for.

Usage: epp_client.py <host> <port> <ca_pem> \
           <cert1> <key1> <clid1> <pw1> <cert2> <key2> <clid2> <pw2>
"""
import re
import socket
import ssl
import struct
import sys

HOST, PORT, CA, CERT1, KEY1, CLID1, PW1, CERT2, KEY2, CLID2, PW2 = sys.argv[1:12]
PORT = int(PORT)


def send_frame(s, xml):
    d = xml.encode()
    s.sendall(struct.pack(">I", len(d) + 4) + d)


def recv_frame(s):
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise EOFError("connection closed reading frame header")
        hdr += chunk
    total = struct.unpack(">I", hdr)[0]
    body = b""
    need = total - 4
    while len(body) < need:
        chunk = s.recv(need - len(body))
        if not chunk:
            raise EOFError("connection closed reading frame body")
        body += chunk
    return body.decode()


def connect(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CA)
    ctx.load_cert_chain(cert, key)
    ctx.check_hostname = False
    raw = socket.create_connection((HOST, PORT), timeout=5)
    return ctx.wrap_socket(raw)


def login(s, clid, pw, trid):
    send_frame(
        s,
        '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
        f"<command><login><clID>{clid}</clID><pw>{pw}</pw>"
        "<options><version>1.0</version><lang>en</lang></options>"
        '<svcs><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI></svcs></login>'
        f"<clTRID>{trid}</clTRID></command></epp>",
    )
    return recv_frame(s)


_ok = True


def check(cond, label, extra=""):
    global _ok
    print(("PASS  " if cond else "FAIL  ") + label + (f"  [{extra}]" if extra else ""))
    if not cond:
        _ok = False


s = connect(CERT1, KEY1)
greeting = recv_frame(s)
check("<greeting>" in greeting and "<svID>eppd</svID>" in greeting, "unprompted greeting on connect")
check("urn:ietf:params:xml:ns:domain-1.0" in greeting, "greeting advertises domain objURI")

send_frame(s, '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><hello/></epp>')
check("<greeting>" in recv_frame(s), "hello -> greeting")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><check><domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    '<domain:name>presession.test</domain:name></domain:check></check>'
    '<clTRID>T-001</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="2201"' in r, "command before login -> 2201 authorization error")
check("<clTRID>T-001</clTRID>" in r, "clTRID echoed on error response")

check('code="2200"' in login(s, CLID1, f"wrong-{PW1}", "T-002"), "wrong password -> 2200 auth error")
check('code="1000"' in login(s, CLID1, PW1, "T-003"), "correct login -> 1000 success")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><create><contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">'
    "<contact:id>EPPTC1</contact:id><contact:name>Test Registrant</contact:name>"
    "<contact:email>test@example.invalid</contact:email></contact:create></create>"
    '<clTRID>T-004</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="1000"' in r, "contact:create", r)

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><create><host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0">'
    "<host:name>ns1.epptest.example.local</host:name>"
    '<host:addr ip="v4">192.0.2.77</host:addr></host:create></create>'
    '<clTRID>T-005</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="1000"' in r, "host:create", r)

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><create><domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    "<domain:ns><domain:hostObj>ns1.epptest.example.local</domain:hostObj></domain:ns>"
    "<domain:registrant>EPPTC1</domain:registrant></domain:create></create>"
    '<clTRID>T-006</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="1000"' in r, "domain:create", r)

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:info></info>"
    '<clTRID>T-007</clTRID></command></epp>',
)
r = recv_frame(s)
check(
    'code="1000"' in r and "ns1.epptest.example.local" in r and "<registrant>EPPTC1" in r,
    "domain:info round-trips NS + registrant",
    r,
)

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><create><domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:create></create>"
    '<clTRID>T-008</clTRID></command></epp>',
)
check('code="2302"' in recv_frame(s), "duplicate domain:create rejected")

# ── Phase 2: host:update ─────────────────────────────────────────────────
send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0">'
    "<host:name>ns1.epptest.example.local</host:name>"
    '<add><host:addr ip="v4">192.0.2.88</host:addr></add></host:update></update>'
    '<clTRID>T-010</clTRID></command></epp>',
)
check('code="1000"' in recv_frame(s), "host:update adds a second address")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><info><host:info xmlns:host="urn:ietf:params:xml:ns:host-1.0">'
    "<host:name>ns1.epptest.example.local</host:name></host:info></info>"
    '<clTRID>T-011</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="1000"' in r and "192.0.2.88" in r and "192.0.2.77" in r,
      "host:info reflects both addresses after update", r)

# ── Phase 2: domain:update — status, secDNS (RFC 5910) ───────────────────
DS_DIGEST = "0123456789abcdef" * 4  # 64 hex chars — a fabricated but well-formed SHA-256 digest
send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    '<add><domain:status s="clientHold"/></add>'
    "</domain:update></update>"
    '<extension><secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">'
    "<secDNS:add><secDNS:dsData><secDNS:keyTag>12345</secDNS:keyTag>"
    "<secDNS:alg>13</secDNS:alg><secDNS:digestType>2</secDNS:digestType>"
    f"<secDNS:digest>{DS_DIGEST}</secDNS:digest></secDNS:dsData></secDNS:add>"
    "</secDNS:update></extension>"
    '<clTRID>T-012</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="1000"' in r, "domain:update adds clientHold status + secDNS DS data", r)

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:info></info>"
    '<clTRID>T-013</clTRID></command></epp>',
)
r = recv_frame(s)
check(
    'code="1000"' in r and 's="clientHold"' in r and "<secDNS:keyTag>12345</secDNS:keyTag>" in r,
    "domain:info reflects the added status + secDNS:infData",
    r,
)
domain_authinfo = None
m = re.search(r"<authInfo><pw>([0-9a-f]+)</pw></authInfo>", r)
check(m is not None, "sponsor's own session sees domain authInfo (RFC 9154)", r)
if m:
    domain_authinfo = m.group(1)

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    '<rem><domain:status s="clientHold"/></rem>'
    "</domain:update></update>"
    '<clTRID>T-014</clTRID></command></epp>',
)
check('code="1000"' in recv_frame(s), "domain:update removes clientHold status")

# ── Phase 2: contact:update ───────────────────────────────────────────────
send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">'
    "<contact:id>EPPTC1</contact:id>"
    "<chg><contact:email>updated@example.invalid</contact:email></chg>"
    "</contact:update></update>"
    '<clTRID>T-015</clTRID></command></epp>',
)
check('code="1000"' in recv_frame(s), "contact:update changes email")

# ── Phase 2: cross-registrar authorization + transfer ────────────────────
s2 = connect(CERT2, KEY2)
recv_frame(s2)  # unprompted greeting
check('code="1000"' in login(s2, CLID2, PW2, "T-016"), "registrar2 login")

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    '<add><domain:status s="clientHold"/></add>'
    "</domain:update></update>"
    '<clTRID>T-017</clTRID></command></epp>',
)
check('code="2201"' in recv_frame(s2), "registrar2 (non-sponsor) domain:update rejected")

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><transfer op="request"><domain:transfer '
    'xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    f"<domain:authInfo><domain:pw>{domain_authinfo}</domain:pw></domain:authInfo>"
    "</domain:transfer></transfer>"
    '<clTRID>T-018</clTRID></command></epp>',
)
r = recv_frame(s2)
check('code="1001"' in r and "<trStatus>pending</trStatus>" in r,
      "registrar2 domain:transfer request (correct authInfo) -> pending", r)

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><transfer op="query"><domain:transfer '
    'xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    "</domain:transfer></transfer>"
    '<clTRID>T-019</clTRID></command></epp>',
)
check('<trStatus>pending</trStatus>' in recv_frame(s2), "transfer query shows pending")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><transfer op="approve"><domain:transfer '
    'xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    "</domain:transfer></transfer>"
    '<clTRID>T-020</clTRID></command></epp>',
)
r = recv_frame(s)
check('code="1000"' in r and "<trStatus>clientApproved</trStatus>" in r,
      "sponsor approves the transfer", r)

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:info></info>"
    '<clTRID>T-021</clTRID></command></epp>',
)
check(f"<clID>{CLID2}</clID>" in recv_frame(s2), "domain ownership moved to registrar2")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    '<add><domain:status s="clientHold"/></add>'
    "</domain:update></update>"
    '<clTRID>T-022</clTRID></command></epp>',
)
check('code="2201"' in recv_frame(s), "former sponsor (registrar1) can no longer update the domain")

# ── Phase 2: delete -> redemptionPeriod -> restore (RFC 3915) ────────────
# The Makefile recipe zeroes every grace-window config for this run so the
# just-created/just-transferred domain isn't still inside its add/transfer
# grace by the time this delete fires — that would immediate-purge instead
# of exercising the redemption path this section is here to test.
send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><delete><domain:delete xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:delete></delete>"
    '<clTRID>T-023</clTRID></command></epp>',
)
check('code="1001"' in recv_frame(s2), "domain:delete outside grace -> 1001 (redemptionPeriod)")

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:info></info>"
    '<clTRID>T-024</clTRID></command></epp>',
)
check('s="pendingDelete"' in recv_frame(s2), "domain:info shows pendingDelete during redemption")

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><update><domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name>"
    "</domain:update></update>"
    '<extension><rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">'
    '<rgp:restore op="request"/></rgp:update></extension>'
    '<clTRID>T-025</clTRID></command></epp>',
)
check('code="1000"' in recv_frame(s2), "rgp:restore request lifts the domain out of redemption")

send_frame(
    s2,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><info><domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>epptest.example.local</domain:name></domain:info></info>"
    '<clTRID>T-026</clTRID></command></epp>',
)
r = recv_frame(s2)
check('s="pendingDelete"' not in r and 's="ok"' in r, "domain:info shows ok again after restore", r)

# ── Phase 2: association guards on host/contact delete ───────────────────
send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><delete><host:delete xmlns:host="urn:ietf:params:xml:ns:host-1.0">'
    "<host:name>ns1.epptest.example.local</host:name></host:delete></delete>"
    '<clTRID>T-027</clTRID></command></epp>',
)
check('code="2305"' in recv_frame(s), "host:delete blocked: still a domain's NS (association exists)")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><delete><contact:delete xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">'
    "<contact:id>EPPTC1</contact:id></contact:delete></delete>"
    '<clTRID>T-028</clTRID></command></epp>',
)
check('code="2305"' in recv_frame(s),
      "contact:delete blocked: still the domain's registrant (association exists)")

send_frame(s2, '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
              '<command><logout/><clTRID>T-029</clTRID></command></epp>')
check('code="1500"' in recv_frame(s2), "registrar2 logout -> 1500")
s2.close()

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><logout/><clTRID>T-030</clTRID></command></epp>',
)
check('code="1500"' in recv_frame(s), "registrar1 logout -> 1500")
s.close()

print("ALL TESTS PASSED" if _ok else "SOME TESTS FAILED")
sys.exit(0 if _ok else 1)
