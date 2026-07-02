#!/usr/bin/env python3
"""Stub upstream for `make check-dns64` (RFC 6147 DNS64 AAAA synthesis in
resolverd).

Behavior, keyed by qname (case-insensitive):
  - "<v4only>": A -> <v4_ip>; AAAA -> genuine NOERROR/NODATA (no answer RRs).
    This is the case DNS64 must synthesize over.
  - "<dualstack>": A -> <v4_ip>; AAAA -> a real AAAA answer (::1234), which
    DNS64 must pass through unchanged (never overwrite a real AAAA).
  - anything else: NXDOMAIN.

Usage: dns64_upstream.py <bind_ip> <port> <v4only_name> <dualstack_name> <v4_ip>
"""
import socket
import struct
import sys

QTYPE_A = 1
QTYPE_AAAA = 28


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


def parse_question(query):
    if len(query) < 12:
        return None
    (qid, _flags, qdcount) = struct.unpack(">HHH", query[:6])
    if qdcount != 1:
        return None
    name, off = decode_qname(query, 12)
    if name is None or off + 4 > len(query):
        return None
    qtype = struct.unpack(">H", query[off:off + 2])[0]
    return qid, qtype, name, query[12:off + 4]


def a_record(ip, ttl=60):
    return struct.pack(">HHHIH", 0xC00C, QTYPE_A, 1, ttl, 4) + socket.inet_aton(ip)


def aaaa_record(ip6, ttl=60):
    return struct.pack(">HHHIH", 0xC00C, QTYPE_AAAA, 1, ttl, 16) + socket.inet_pton(
        socket.AF_INET6, ip6)


def main():
    bind_ip = sys.argv[1]
    port = int(sys.argv[2])
    v4only_name = sys.argv[3].lower()
    dualstack_name = sys.argv[4].lower()
    v4_ip = sys.argv[5]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        parsed = parse_question(data)
        if parsed is None:
            continue
        qid, qtype, name, question = parsed
        # resolverd 0x20-randomizes the outbound QNAME's case (RFC 5452
        # §2.2); compare case-insensitively.
        lname = name.lower()
        print("QUERY %s %d" % (name, qtype), flush=True)
        if lname == v4only_name and qtype == QTYPE_A:
            header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
            resp = header + question + a_record(v4_ip)
        elif lname == v4only_name and qtype == QTYPE_AAAA:
            header = struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0)  # NOERROR/NODATA
            resp = header + question
        elif lname == dualstack_name and qtype == QTYPE_A:
            header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
            resp = header + question + a_record(v4_ip)
        elif lname == dualstack_name and qtype == QTYPE_AAAA:
            header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
            resp = header + question + aaaa_record("::1234")
        else:
            header = struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0)  # NXDOMAIN
            resp = header + question
        s.sendto(resp, addr)


if __name__ == "__main__":
    main()
