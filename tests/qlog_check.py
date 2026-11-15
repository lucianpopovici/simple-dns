#!/usr/bin/env python3
"""Query-log escaping probe for `make check-qlog-escape` (CSA-INJ-002).

  qlog_check.py send SERVER PORT   send queries whose labels carry '"', '\\',
                                   a newline and a high byte
  qlog_check.py verify LOGFILE     every line must be one JSON object; the
                                   hostile names must round-trip; prints
                                   "OK ..." or "FAIL ..."
"""
import json
import socket
import sys

import dns.message
import dns.name

HOSTILE = [b'a"b', b"c\\d", b"e\nf", b"g\xffh", b'"},{"forged":1,"x":"']


def send(server, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    for lab in HOSTILE:
        name = dns.name.Name([lab, b"example", b"local", b""])
        q = dns.message.make_query(name, "A")
        s.sendto(q.to_wire(), (server, int(port)))
        try:
            s.recvfrom(4096)
        except socket.timeout:
            pass
    s.close()


def verify(path):
    lines = open(path, "rb").read().split(b"\n")
    lines = [ln for ln in lines if ln.strip()]
    names = []
    for ln in lines:
        try:
            rec = json.loads(ln.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"FAIL line is not one ASCII JSON object: {ln[:80]!r} ({e})")
            return 1
        if "forged" in rec:
            print("FAIL a qname injected a JSON field")
            return 1
        names.append(rec.get("qname", ""))
    want = [lab.decode("latin-1") + ".example.local" for lab in HOSTILE]
    missing = [w for w in want if w not in names]
    if missing:
        print(f"FAIL names not preserved: {missing!r} (logged {names!r})")
        return 1
    print(f"OK {len(lines)} lines parsed, {len(want)} hostile names round-tripped")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "send":
        send(sys.argv[2], sys.argv[3])
        sys.exit(0)
    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        sys.exit(verify(sys.argv[2]))
    print(__doc__, file=sys.stderr)
    sys.exit(2)
