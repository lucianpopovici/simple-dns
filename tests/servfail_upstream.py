#!/usr/bin/env python3
"""Stub upstream for `make check-serve-stale` (RFC 8767 serve-stale + RFC 9520
failure caching in resolverd).

Behavior:
  - The first query for <primed_name> gets a positive A answer with TTL
    <primed_ttl>, so the test can let it expire quickly.
  - Every query after that (any name, including <primed_name> again) gets an
    immediate SERVFAIL — simulating an upstream that has since gone bad,
    without needing to wait out a socket timeout.
  - Logs "QUERY <name> #<n>" for every query received, so the Makefile can
    grep how many times a given name was actually sent upstream (proves RFC
    9520 SERVFAIL caching suppressed a retry rather than resolverd just
    happening not to ask).

Usage: servfail_upstream.py <bind_ip> <port> <primed_name> <primed_ttl> <answer_ipv4>
"""
import socket
import struct
import sys

QTYPE_A = 1


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


def answer_record(answer_ip, ttl):
    rr = struct.pack(">HHHIH", 0xC00C, QTYPE_A, 1, ttl, 4)
    return rr + socket.inet_aton(answer_ip)


def main():
    bind_ip = sys.argv[1]
    port = int(sys.argv[2])
    primed_name = sys.argv[3]
    primed_ttl = int(sys.argv[4])
    answer_ip = sys.argv[5]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    counts = {}
    primed_served = False
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        parsed = parse_question(data)
        if parsed is None:
            continue
        qid, qtype, name, question = parsed
        counts[name] = counts.get(name, 0) + 1
        print("QUERY %s #%d" % (name, counts[name]), flush=True)
        # resolverd 0x20-randomizes the outbound QNAME's letter case (RFC 5452
        # §2.2); compare case-insensitively so priming isn't defeated by that.
        if not primed_served and name.lower() == primed_name.lower() and qtype == QTYPE_A:
            primed_served = True
            header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
            resp = header + question + answer_record(answer_ip, primed_ttl)
        else:
            header = struct.pack(">HHHHHH", qid, 0x8182, 1, 0, 0, 0)  # SERVFAIL
            resp = header + question
        s.sendto(resp, addr)


if __name__ == "__main__":
    main()
