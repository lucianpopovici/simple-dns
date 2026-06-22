#!/usr/bin/env python3
"""Stub upstream resolver for `make check-forwarder`.

dnsd's out-of-zone forwarder relays a query verbatim to a configured upstream
and relays the reply back (setting RA). This stub is that upstream: a
deterministic, offline peer the forwarder can talk to. It is NOT a real
resolver. It copies the ID + question back so dnsd's RFC 5452 reply validation
(ID + byte-identical question) passes on the legitimate paths, and supports a
few modes so the test can exercise failover, TC->TCP, and anti-spoofing.

Usage: fwd_upstream.py <bind_ip> <port> <answer_ipv4> [mode]

  mode = normal    (default) UDP answers a full A record (RA set).
       = truncate  UDP answers with TC set and no records (forces the client,
                   if on TCP, to retry the same upstream over TCP); the TCP
                   listener returns the full A record.
       = spoof     UDP answers with a corrupted transaction ID, which dnsd's
                   RFC 5452 ID check must reject (so the query SERVFAILs rather
                   than returning the forged answer).

The TCP listener (RFC 1035 length-prefixed framing) always returns the full A
record, so it doubles as the TC->TCP completion path.
"""
import socket
import struct
import sys
import threading

QTYPE_A = 1
MODE = "normal"
ANSWER_IP = "203.0.113.45"


def parse_question(query):
    """Return (qid, qtype, question_bytes) or None if unparseable."""
    if len(query) < 12:
        return None
    (qid, _flags, qdcount, _an, _ns, _ar) = struct.unpack(">HHHHHH", query[:12])
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
    return (qid, qtype, query[12:off + 4])


def answer_record():
    # Name = compression pointer to the question (offset 12 -> 0xC00C).
    rr = struct.pack(">HHHIH", 0xC00C, QTYPE_A, 1, 60, 4)
    return rr + socket.inet_aton(ANSWER_IP)


def build_udp_response(query):
    parsed = parse_question(query)
    if parsed is None:
        return None
    (qid, qtype, question) = parsed
    if MODE == "spoof":
        # Corrupt the ID so dnsd's RFC 5452 check rejects this as off-path.
        qid ^= 0xFFFF
    if MODE == "truncate":
        # QR=1, RD=1, RA=1, TC=1 (0x8380), no answer records.
        header = struct.pack(">HHHHHH", qid, 0x8380, 1, 0, 0, 0)
        return header + question
    ancount = 1 if qtype == QTYPE_A else 0
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, ancount, 0, 0)
    resp = header + question
    if ancount:
        resp += answer_record()
    return resp


def build_tcp_response(query):
    """TCP always returns the full record (the TC->TCP completion path)."""
    parsed = parse_question(query)
    if parsed is None:
        return None
    (qid, qtype, question) = parsed
    ancount = 1 if qtype == QTYPE_A else 0
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, ancount, 0, 0)
    resp = header + question
    if ancount:
        resp += answer_record()
    return resp


def tcp_server(bind_ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    s.listen(8)
    while True:
        try:
            conn, _ = s.accept()
        except OSError:
            break
        try:
            lb = conn.recv(2)
            if len(lb) == 2:
                n = (lb[0] << 8) | lb[1]
                msg = b""
                while len(msg) < n:
                    chunk = conn.recv(n - len(msg))
                    if not chunk:
                        break
                    msg += chunk
                resp = build_tcp_response(msg)
                if resp is not None:
                    conn.sendall(struct.pack(">H", len(resp)) + resp)
        finally:
            conn.close()


def main():
    global MODE, ANSWER_IP
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5399
    ANSWER_IP = sys.argv[3] if len(sys.argv) > 3 else "203.0.113.45"
    MODE = sys.argv[4] if len(sys.argv) > 4 else "normal"

    t = threading.Thread(target=tcp_server, args=(bind_ip, port), daemon=True)
    t.start()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        resp = build_udp_response(data)
        if resp is not None:
            s.sendto(resp, addr)


if __name__ == "__main__":
    main()
