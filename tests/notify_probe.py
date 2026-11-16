#!/usr/bin/env python3
"""Send NOTIFY messages to a dnsd secondary (CLAUDE-low-fixes.md 8e).

usage: notify_probe.py <host> <port> <zone> <key_name> <secret_b64> <mode> [count]
  mode: unsigned | signed | wrongkey | burst  (burst = <count> signed NOTIFYs)
Prints one rcode name per NOTIFY sent.
"""
import base64
import socket
import sys

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring

host, port, zone, keyname, secret = sys.argv[1:6]
mode = sys.argv[6]
count = int(sys.argv[7]) if len(sys.argv) > 7 else 1


def notify(sign_with=None):
    m = dns.message.make_query(zone, dns.rdatatype.SOA, dns.rdataclass.IN)
    m.set_opcode(dns.opcode.NOTIFY)
    m.flags |= dns.flags.AA
    if sign_with is not None:
        ring = dns.tsigkeyring.from_text({keyname: sign_with})
        m.use_tsig(ring, keyname=keyname, algorithm=dns.tsig.HMAC_SHA256)
    # Raw exchange: dnsd's NOTIFY reply carries no question section, which
    # dns.query rejects as a mismatched response; only the rcode matters here.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(m.to_wire(), (host, int(port)))
        r = s.recv(4096)
    except socket.timeout:
        return "TIMEOUT"
    finally:
        s.close()
    return dns.rcode.to_text(r[3] & 0xF) if len(r) >= 4 else "SHORT"

if mode == "unsigned":
    print(notify())
elif mode == "signed":
    print(notify(secret))
elif mode == "wrongkey":
    print(notify(base64.b64encode(b"not-the-right-key-not-the-right").decode()))
elif mode == "burst":
    print(" ".join(notify(secret) for _ in range(count)))
