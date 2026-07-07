#!/usr/bin/env python3
"""ADR-004 test helper for `make check-axfr-concurrency`.

A plain AXFR (RFC 5936) client, modeled on tests/ixfr_client.py's TCP framing,
but deliberately slow: it sleeps `delay` seconds between reading each
response message, widening the window for a concurrent write to land
mid-transfer. Collects every A record for names matching hostN.<zone> and
prints, for each, the "generation" encoded in the address's last octet (see
valkey_txn_flipper.py) — the Makefile target asserts every record captured
in one transfer shows the SAME generation, proving axfr_send_runtime's
per-type MULTI/EXEC batch (dns_server.c, ADR-004) fetched them all at one
consistent instant.

Usage: axfr_slow_client.py <host> <port> <zone> <delay_per_msg>
"""
import socket
import struct
import sys
import time


def enc_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def parse_name(msg, off):
    labels = []
    jumped = False
    next_off = off
    guard = 0
    while True:
        guard += 1
        if guard > 128 or off >= len(msg):
            break
        n = msg[off]
        if n == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if (n & 0xC0) == 0xC0:
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                next_off = off + 2
            jumped = True
            off = ptr
            continue
        labels.append(msg[off + 1:off + 1 + n].decode("latin1"))
        off += 1 + n
    return ".".join(labels), next_off


def build_axfr_query(zone):
    qid = 0xA1FA
    header = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0)
    q = enc_name(zone) + struct.pack(">HH", 252, 1)  # AXFR, IN
    return header + q


def read_msg(sock):
    lb = b""
    while len(lb) < 2:
        c = sock.recv(2 - len(lb))
        if not c:
            return None
        lb += c
    mlen = (lb[0] << 8) | lb[1]
    msg = b""
    while len(msg) < mlen:
        c = sock.recv(mlen - len(msg))
        if not c:
            return None
        msg += c
    return msg


def main():
    host, port, zone, delay = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    q = build_axfr_query(zone)
    s.sendall(struct.pack(">H", len(q)) + q)

    soa_count = 0
    generations = []  # (name, gen) for every hostN.<zone> A record seen
    done = False
    while not done:
        msg = read_msg(s)
        if msg is None or len(msg) < 12:
            break
        an = struct.unpack(">H", msg[6:8])[0]
        off = 12
        qd = struct.unpack(">H", msg[4:6])[0]
        for _ in range(qd):
            _, off = parse_name(msg, off)
            off += 4
        for _ in range(an):
            name, off = parse_name(msg, off)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
            off += 10
            rdoff = off
            off += rdlen
            if rtype == 6:
                soa_count += 1
                if soa_count >= 2:
                    done = True
                    break
            elif rtype == 1 and rdlen == 4 and name.startswith("host"):
                gen = msg[rdoff + 3]
                generations.append((name, gen))
        time.sleep(delay)
    s.close()

    distinct = sorted(set(g for _, g in generations))
    print("RECORDS %d" % len(generations))
    print("GENERATIONS %s" % ",".join(str(g) for g in distinct))
    if len(distinct) > 1:
        # Show a few examples of the mix for debugging.
        for name, g in generations[:10]:
            print("MIXED %s gen=%d" % (name, g))


if __name__ == "__main__":
    main()
