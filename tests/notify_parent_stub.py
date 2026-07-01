#!/usr/bin/env python3
"""Stub parent-side NOTIFY listener for `make check-parent-notify` (RFC 9859).

Listens on UDP for NOTIFY requests and, for each one, immediately ACKs it (QR=1,
same id/opcode) so dnsd's sender stops retrying quickly — the retry/backoff
behavior itself is already covered by `make check-notify`. Records the
question's QTYPE of every distinct NOTIFY received (dedup by qtype, since
dnsd may retransmit before the ACK lands) and prints them as a sorted,
comma-separated list of decimal type numbers, e.g. "QTYPES 59,60" for
CDS(59) + CDNSKEY(60).

Usage: notify_parent_stub.py <bind_ip> <port> [run_secs]
"""
import socket
import struct
import sys
import time


def qtype_of(msg):
    o = 12
    while o < len(msg) and msg[o] != 0:
        o += 1 + msg[o]
    o += 1
    return struct.unpack(">H", msg[o:o + 2])[0]


def main():
    bind_ip, port = sys.argv[1], int(sys.argv[2])
    run_secs = float(sys.argv[3]) if len(sys.argv) > 3 else 6.0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    s.settimeout(0.5)

    qtypes = set()
    deadline = time.time() + run_secs
    while time.time() < deadline:
        try:
            msg, peer = s.recvfrom(2048)
        except socket.timeout:
            continue
        if len(msg) < 12:
            continue
        qid = struct.unpack(">H", msg[0:2])[0]
        flags = struct.unpack(">H", msg[2:4])[0]
        opcode = (flags >> 11) & 0xF
        if opcode != 4 or (flags & 0x8000):
            continue  # not a NOTIFY request
        qtypes.add(qtype_of(msg))
        resp = struct.pack(">HHHHHH", qid, 0xA000, 0, 0, 0, 0)  # QR=1, opcode NOTIFY
        s.sendto(resp, peer)
    print("QTYPES %s" % ",".join(str(t) for t in sorted(qtypes)))


if __name__ == "__main__":
    main()
