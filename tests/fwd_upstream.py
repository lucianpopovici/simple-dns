#!/usr/bin/env python3
"""Minimal stub upstream resolver for `make check-forwarder`.

dnsd's out-of-zone forwarder relays a query verbatim to a configured upstream
and relays the reply back (setting RA). This stub is that upstream: it answers
every A query with a fixed address and copies the ID + question back so dnsd's
RFC 5452 reply validation (ID + byte-identical question) passes. It is NOT a
real resolver — it exists only so the forwarder has a deterministic, offline
peer to talk to.

Usage: fwd_upstream.py <bind_ip> <port> <answer_ipv4>
"""
import socket
import struct
import sys

QTYPE_A = 1


def build_response(query, answer_ip):
    """Echo the query's ID + question, append one A record. Returns wire bytes,
    or None if the packet is too short to parse a header + question."""
    if len(query) < 12:
        return None
    (qid, _flags, qdcount, _an, _ns, _ar) = struct.unpack(">HHHHHH", query[:12])
    if qdcount != 1:
        return None
    # Walk the QNAME labels to find the end of the question section.
    off = 12
    while off < len(query):
        ln = query[off]
        if ln == 0:
            off += 1
            break
        off += 1 + ln
    else:
        return None
    if off + 4 > len(query):
        return None
    qtype = struct.unpack(">H", query[off:off + 2])[0]
    question = query[12:off + 4]  # qname + qtype + qclass

    # QR=1, RD=1, RA=1, RCODE=0  -> 0x8180
    flags = 0x8180
    ancount = 1 if qtype == QTYPE_A else 0
    header = struct.pack(">HHHHHH", qid, flags, 1, ancount, 0, 0)
    resp = header + question
    if ancount:
        # Name = compression pointer to the question (offset 12 -> 0xC00C).
        rr = struct.pack(">HHHIH", 0xC00C, QTYPE_A, 1, 60, 4)
        rr += socket.inet_aton(answer_ip)
        resp += rr
    return resp


def main():
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5399
    answer_ip = sys.argv[3] if len(sys.argv) > 3 else "203.0.113.45"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        resp = build_response(data, answer_ip)
        if resp is not None:
            s.sendto(resp, addr)


if __name__ == "__main__":
    main()
