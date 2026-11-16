#!/usr/bin/env python3
"""Generate the seed corpus for fuzz/fuzz_dnsd.c (one wire message per file):
queries of several types with and without EDNS / DO / cookies, an UPDATE
(unsigned and TSIG-signed with the harness's key), a NOTIFY, and an IXFR
request with an authority SOA. Needs python3-dnspython.

usage: gen_corpus_dnsd.py <out_dir>
"""
import hashlib
import os
import sys

import dns.edns
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.tsigkeyring
import dns.update

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
ZONE = "example.local"
ring = dns.tsigkeyring.from_text({"tsig-key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="})
msgs = []

for name in (ZONE, "www." + ZONE, "nonexistent." + ZONE, "*." + ZONE, "outside.example"):
    for t in ("A", "AAAA", "SOA", "NS", "MX", "TXT", "DNSKEY", "DS", "ANY", "NSEC", "CAA"):
        msgs.append(dns.message.make_query(name, t, use_edns=False).to_wire())
for t in ("A", "SOA", "DNSKEY", "ANY"):
    q = dns.message.make_query("www." + ZONE, t, want_dnssec=True, payload=1232)
    msgs.append(q.to_wire())
    q = dns.message.make_query("www." + ZONE, t, use_edns=0,
                               options=[dns.edns.GenericOption(10, b"\x01\x02\x03\x04\x05\x06\x07\x08")])
    msgs.append(q.to_wire())
    q = dns.message.make_query("www." + ZONE, t, use_edns=0,
                               options=[dns.edns.GenericOption(3, b""), dns.edns.GenericOption(19, b"")])
    msgs.append(q.to_wire())
msgs.append(dns.message.make_query("version.bind", "TXT", rdclass="CH").to_wire())

u = dns.update.UpdateMessage(ZONE)
u.add("fuzz." + ZONE, 300, "A", "192.0.2.1")
u.delete("old." + ZONE)
msgs.append(u.to_wire())
u = dns.update.UpdateMessage(ZONE, keyring=ring, keyname="tsig-key",
                             keyalgorithm=dns.tsig.HMAC_SHA256)
u.add("fuzz." + ZONE, 300, "TXT", '"hello"')
msgs.append(u.to_wire())

n = dns.message.make_query(ZONE, "SOA", use_edns=False)
n.set_opcode(dns.opcode.NOTIFY)
n.flags |= dns.flags.AA
msgs.append(n.to_wire())
n.use_tsig(ring, keyname="tsig-key", algorithm=dns.tsig.HMAC_SHA256)
msgs.append(n.to_wire())

x = dns.message.make_query(ZONE, "IXFR", use_edns=False)
x.authority.append(dns.rrset.from_text(ZONE + ".", 0, "IN", "SOA",
                                       f"ns1.{ZONE}. hostmaster.{ZONE}. 1 3600 900 604800 300"))
msgs.append(x.to_wire())

for m in msgs:
    with open(os.path.join(out, hashlib.sha1(m).hexdigest()), "wb") as f:
        f.write(m)
print(f"{len(msgs)} seeds in {out}")
