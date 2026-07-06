#!/usr/bin/env python3
"""Minimal RFC 5730/5734 EPP client, for `make check-eppd` (eppd Phase 1).
No standard tool (dig/kdig) speaks EPP, so this hand-rolls just enough of
the wire format: RFC 5734's 4-byte big-endian length-prefixed framing
carrying RFC 5730 command/response XML. Runs a fixed scripted session
end-to-end (login, contact/host/domain create, info, duplicate-create
rejection, logout) against a real eppd instance and prints one PASS/FAIL
line per step plus a final "ALL TESTS PASSED" / "SOME TESTS FAILED"
sentinel line the Makefile recipe greps for.

Usage: epp_client.py <host> <port> <ca_pem> <client_cert_pem> <client_key_pem> <clid> <pw>
"""
import socket
import ssl
import struct
import sys

HOST, PORT, CA, CERT, KEY, CLID, PW = sys.argv[1:8]
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


def connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CA)
    ctx.load_cert_chain(CERT, KEY)
    ctx.check_hostname = False
    raw = socket.create_connection((HOST, PORT), timeout=5)
    return ctx.wrap_socket(raw)


_ok = True


def check(cond, label, extra=""):
    global _ok
    print(("PASS  " if cond else "FAIL  ") + label + (f"  [{extra}]" if extra else ""))
    if not cond:
        _ok = False


s = connect()
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

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    f"<command><login><clID>{CLID}</clID><pw>wrong-{PW}</pw>"
    "<options><version>1.0</version><lang>en</lang></options>"
    '<svcs><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI></svcs></login>'
    '<clTRID>T-002</clTRID></command></epp>',
)
check('code="2200"' in recv_frame(s), "wrong password -> 2200 auth error")

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    f"<command><login><clID>{CLID}</clID><pw>{PW}</pw>"
    "<options><version>1.0</version><lang>en</lang></options>"
    '<svcs><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI></svcs></login>'
    '<clTRID>T-003</clTRID></command></epp>',
)
check('code="1000"' in recv_frame(s), "correct login -> 1000 success")

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

send_frame(
    s,
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0">'
    '<command><logout/><clTRID>T-009</clTRID></command></epp>',
)
check('code="1500"' in recv_frame(s), "logout -> 1500")
s.close()

print("ALL TESTS PASSED" if _ok else "SOME TESTS FAILED")
sys.exit(0 if _ok else 1)
