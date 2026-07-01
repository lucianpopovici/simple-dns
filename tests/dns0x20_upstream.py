#!/usr/bin/env python3
"""Stub upstream for `make check-dns0x20` (RFC 5452 §2.2 0x20 case
randomization in resolverd).

Two modes, selected on the command line:

  echo     Echoes the question section back byte-for-byte (a conforming
           server always does this) and answers with a fixed A record.
           Prints QNAME <bytes> for every query received, so the Makefile can
           confirm the case pattern actually varies across queries (proof
           resolverd is randomizing, not sending a fixed pattern).
  corrupt  Flips the case of the first alphabetic byte in the echoed question
           before answering — simulating a forger/misbehaving server that
           got the query's *content* right but not its exact case pattern.
           A resolver enforcing 0x20 must reject this and end up with no
           answer; one that doesn't enforce it must still resolve normally.

Usage: dns0x20_upstream.py <bind_ip> <port> <mode: echo|corrupt> <answer_ipv4>
"""
import socket
import struct
import sys

QTYPE_A = 1


def parse_question(query):
    if len(query) < 12:
        return None
    (qid, _flags, qdcount) = struct.unpack(">HHH", query[:6])
    if qdcount != 1:
        return None
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
    return qid, qtype, query[12:off + 4]


def flip_first_letter_case(question):
    q = bytearray(question)
    for i, b in enumerate(q):
        if 0x41 <= b <= 0x5A:  # 'A'-'Z'
            q[i] = b + 0x20
            return bytes(q)
        if 0x61 <= b <= 0x7A:  # 'a'-'z'
            q[i] = b - 0x20
            return bytes(q)
    return bytes(q)


def answer_record(answer_ip):
    rr = struct.pack(">HHHIH", 0xC00C, QTYPE_A, 1, 60, 4)
    return rr + socket.inet_aton(answer_ip)


def main():
    bind_ip, port, mode, answer_ip = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
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
        qid, qtype, question = parsed
        print("QNAME %s" % question[:-4].hex(), flush=True)
        echoed = question if mode == "echo" else flip_first_letter_case(question)
        ancount = 1 if qtype == QTYPE_A else 0
        header = struct.pack(">HHHHHH", qid, 0x8180, 1, ancount, 0, 0)
        resp = header + echoed
        if ancount:
            resp += answer_record(answer_ip)
        s.sendto(resp, addr)


if __name__ == "__main__":
    main()
