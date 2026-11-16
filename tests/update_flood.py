#!/usr/bin/env python3
"""Send a stream of unsigned RFC 2136 UPDATEs (add, then delete, a TXT record
per iteration) to dnsd, for the ThreadSanitizer reload check
(check-reload-tsan). The caller allows unsigned UPDATE from 127.0.0.1 for the
duration. Every record it adds it deletes again.

usage: update_flood.py <host> <port> <zone> <count>
"""
import sys

import dns.query
import dns.rcode
import dns.update

host, port, zone, count = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
ok = 0
for i in range(count):
    name = f"tsan-flood-{i % 8}.{zone}."
    for op in ("add", "delete"):
        u = dns.update.UpdateMessage(zone)
        if op == "add":
            u.add(name, 60, "TXT", f'"{i}"')
        else:
            u.delete(name, "TXT")
        try:
            r = dns.query.udp(u, host, port=port, timeout=2)
            ok += r.rcode() == dns.rcode.NOERROR
        except Exception:
            pass
print(f"{ok}/{2 * count} UPDATEs answered NOERROR")
