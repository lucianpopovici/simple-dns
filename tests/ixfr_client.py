#!/usr/bin/env python3
"""IXFR client for `make check-ixfr` — validates dnsd's *server-side* IXFR.

Sends an IXFR query (RFC 1995): question <zone> IXFR IN, plus an SOA carrying
the client's current serial in the authority section. Reads the multi-message
TCP response, reassembles the RR stream, and classifies it the same way a real
secondary does:

  - the response opens and closes with SOA(current);
  - a data RR right after the opening SOA  → AXFR-style full transfer;
  - an SOA right after the opening SOA      → incremental difference sequences
        [ SOA(old), deletions, SOA(new), additions ].

Prints, for the Makefile to assert on:
    TARGET <serial>
    MODE <axfr|incremental|uptodate>
    DEL <name> <type> <value>      (incremental, deletion section)
    ADD <name> <type> <value>      (incremental, addition section)
    REC <name> <type> <value>      (axfr, full-zone record)
    END <serial>

Usage: ixfr_client.py <host> <port> <zone> <client_serial>
"""
import socket
import struct
import sys


def enc_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def parse_name(msg, off):
    """Return (name, next_off) handling compression pointers."""
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


def soa_serial(msg, rdoff):
    _, off = parse_name(msg, rdoff)  # mname
    _, off = parse_name(msg, off)    # rname
    return struct.unpack(">I", msg[off:off + 4])[0]


def rdata_str(msg, rtype, rdoff, rdlen):
    if rtype == 1 and rdlen == 4:
        return ".".join(str(b) for b in msg[rdoff:rdoff + 4])
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, msg[rdoff:rdoff + 16])
    return "?"


def build_ixfr_query(zone, serial):
    qid = 0x4958  # "IX"
    header = struct.pack(">HHHHHH", qid, 0, 1, 0, 1, 0)  # qd=1, ns=1
    q = enc_name(zone) + struct.pack(">HH", 251, 1)       # IXFR, IN
    soa_rd = enc_name(zone) + enc_name(zone)
    soa_rd += struct.pack(">IIIII", serial, 3600, 900, 604800, 300)
    auth = enc_name(zone) + struct.pack(">HHIH", 6, 1, 0, len(soa_rd)) + soa_rd
    return header + q + auth


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


TYPENAMES = {1: "A", 6: "SOA", 28: "AAAA", 48: "DNSKEY", 16: "TXT", 5: "CNAME", 2: "NS"}


def main():
    host, port, zone, cserial = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    q = build_ixfr_query(zone, cserial)
    s.sendall(struct.pack(">H", len(q)) + q)

    # Flatten the RR stream (in order) across all response messages.
    rrs = []  # list of (name, rtype, value-or-serial)
    target = None
    soa_count = 0
    done = False
    while not done:
        msg = read_msg(s)
        if msg is None or len(msg) < 12:
            break
        qd = struct.unpack(">H", msg[4:6])[0]
        an = struct.unpack(">H", msg[6:8])[0]
        off = 12
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
                ser = soa_serial(msg, rdoff)
                soa_count += 1
                if target is None:
                    target = ser
                rrs.append((name, 6, ser))
                if soa_count >= 2 and soa_count % 2 == 0 and ser == target:
                    done = True
                    break
            else:
                rrs.append((name, rtype, rdata_str(msg, rtype, rdoff, rdlen)))
    s.close()

    # Classify using the same parity rule the C secondary uses.
    print("TARGET %s" % (target if target is not None else "?"))
    if target is None:
        print("MODE error")
        return
    if soa_count == 1:
        print("MODE uptodate")
        print("END %s" % target)
        return
    # Determine mode from the RR right after the opening SOA.
    mode = "incremental" if (len(rrs) >= 2 and rrs[1][1] == 6) else "axfr"
    print("MODE %s" % mode)
    n_soa = 0
    in_add = False
    for (name, rtype, val) in rrs:
        if rtype == 6:
            n_soa += 1
            if n_soa == 1:
                continue
            in_add = (n_soa % 2 == 1)  # odd: additions, even: deletions
            continue
        tn = TYPENAMES.get(rtype, str(rtype))
        if mode == "axfr":
            print("REC %s %s %s" % (name, tn, val))
        else:
            print("%s %s %s %s" % ("ADD" if in_add else "DEL", name, tn, val))
    print("END %s" % target)


if __name__ == "__main__":
    main()
