#!/usr/bin/env python3
"""Client-identity probes for `make check-client-identity` (CLAUDE-client-identity.md:
CSA-NET-003, CSA-AUTH-006, CSA-DOS-004).

  client_probe.py update  SERVER PORT ZONE LABEL [--src ADDR] [--proxy CLAIMED]
      unsigned UPDATE adding LABEL.ZONE TXT; prints "RCODE n" (or "TIMEOUT").
      --proxy prepends a PROXY v2 header claiming CLAIMED as the client.
  client_probe.py doh-update HOST PORT ZONE LABEL [--src ADDR]
      the same UPDATE POSTed to http://HOST:PORT/dns-query (apid);
      prints "RCODE n" or "HTTP <status>".
  client_probe.py rrl SERVER PORT ZONE N [--src ADDR]
      N queries for distinct random names under ZONE (NXDOMAIN); prints
      "full=<answered without TC> tc=<truncated> none=<no reply>".

SERVER may be an IPv6 literal (e.g. ::1).
"""
import http.client
import ipaddress
import os
import socket
import struct
import sys

import dns.message
import dns.update

SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return default


def proxy_v2(claimed):
    ip = ipaddress.ip_address(claimed)
    if ip.version == 4:
        addrs = ip.packed + ipaddress.ip_address("127.0.0.1").packed + struct.pack("!HH", 4444, 0)
        return SIG + bytes([0x21, 0x12]) + struct.pack("!H", len(addrs)) + addrs
    addrs = ip.packed + ipaddress.ip_address("::1").packed + struct.pack("!HH", 4444, 0)
    return SIG + bytes([0x21, 0x22]) + struct.pack("!H", len(addrs)) + addrs


def udp(server, port, wire, src=None, timeout=2.0):
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if src:
        s.bind((src, 0))
    s.settimeout(timeout)
    try:
        s.sendto(wire, (server, int(port)))
        return s.recvfrom(65535)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


def update_wire(zone, label):
    u = dns.update.UpdateMessage(zone)
    u.add(f"{label}.{zone}.", 60, "TXT", "probe")
    return u.to_wire()


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    src = opt(args, "--src")
    claimed = opt(args, "--proxy")
    cmd = args[0]
    if cmd == "update":
        server, port, zone, label = args[1:5]
        wire = update_wire(zone, label)
        if claimed:
            wire = proxy_v2(claimed) + wire
        r = udp(server, port, wire, src)
        print("TIMEOUT" if r is None else f"RCODE {r[3] & 0x0F}")
        return 0
    if cmd == "doh-update":
        host, port, zone, label = args[1:5]
        c = http.client.HTTPConnection(host, int(port), timeout=5,
                                       source_address=(src, 0) if src else None)
        c.request("POST", "/dns-query", body=update_wire(zone, label),
                  headers={"Content-Type": "application/dns-message"})
        r = c.getresponse()
        body = r.read()
        print(f"RCODE {body[3] & 0x0F}" if r.status == 200 and len(body) >= 12
              else f"HTTP {r.status}")
        return 0
    if cmd == "rrl":
        server, port, zone, n = args[1:5]
        full = tc = none = 0
        for _ in range(int(n)):
            q = dns.message.make_query(f"r{os.urandom(4).hex()}.{zone}", "A")
            r = udp(server, port, q.to_wire(), src, timeout=0.3)
            if r is None:
                none += 1
            elif r[2] & 0x02:
                tc += 1
            else:
                full += 1
        print(f"full={full} tc={tc} none={none}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
