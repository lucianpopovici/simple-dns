#!/usr/bin/env python3
"""Fake mDNS responder for `make check-dp` (RFC 8766 Discovery Proxy in
mdnsd). Joins the mDNS multicast group and, on a query for
"_dpxtest9k2._tcp.local" PTR, replies (multicast) with:
  - PTR  _dpxtest9k2._tcp.local        -> myinst._dpxtest9k2._tcp.local
  - SRV  myinst._dpxtest9k2._tcp.local -> myhost.local:8080
  - TXT  myinst._dpxtest9k2._tcp.local -> "path=/"
  - A    myhost.local            -> 192.168.1.50
  - AAAA myhost.local             -> fe80::1 (link-local — must NOT be
    proxied to the unicast side; this is exactly the RFC 8766 §5.3/guardrail
    the test checks)

A made-up service name is used deliberately: a real device on the test
network answering the same generic service type (e.g. "_http._tcp.local")
would contaminate the result — this is exactly how this test was debugged.

Usage: dp_mdns_responder.py
"""
import socket
import struct
import sys

MCAST4 = "224.0.0.251"
PORT = 5353
QTYPE_PTR = 12
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_SRV = 33
QTYPE_TXT = 16


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_qname(query, off):
    labels = []
    while off < len(query):
        ln = query[off]
        if ln == 0:
            off += 1
            break
        off += 1
        labels.append(query[off:off + ln].decode("ascii", "replace"))
        off += ln
    else:
        return None, off
    return ".".join(labels), off


def rr(name, rtype, ttl, rdata):
    return encode_name(name) + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MCAST4), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print("READY", flush=True)
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        if len(data) < 12:
            continue
        flags = struct.unpack(">H", data[2:4])[0]
        if flags & 0x8000:
            continue  # ignore responses (including our own multicast loopback)
        qdcount = struct.unpack(">H", data[4:6])[0]
        if qdcount != 1:
            continue
        name, off = decode_qname(data, 12)
        if name is None or off + 4 > len(data):
            continue
        qtype = struct.unpack(">H", data[off:off + 2])[0]
        print("QUERY %s %d" % (name, qtype), flush=True)
        if name.lower() != "_dpxtest9k2._tcp.local" or qtype not in (QTYPE_PTR, 255):
            continue
        answers = rr("_dpxtest9k2._tcp.local", QTYPE_PTR, 4500, encode_name("myinst._dpxtest9k2._tcp.local"))
        srv_rdata = struct.pack(">HHH", 0, 0, 8080) + encode_name("myhost.local")
        additional = (
            rr("myinst._dpxtest9k2._tcp.local", QTYPE_SRV, 120, srv_rdata)
            + rr("myinst._dpxtest9k2._tcp.local", QTYPE_TXT, 4500, b"\x06path=/")
            + rr("myhost.local", QTYPE_A, 120, socket.inet_aton("192.168.1.50"))
            + rr("myhost.local", QTYPE_AAAA, 120, socket.inet_pton(socket.AF_INET6, "fe80::1"))
        )
        header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 4)
        msg = header + answers + additional
        s.sendto(msg, (MCAST4, PORT))
        print("REPLIED", flush=True)


if __name__ == "__main__":
    main()
