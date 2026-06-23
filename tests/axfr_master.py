#!/usr/bin/env python3
"""Stub AXFR master for `make check-xfr-client`.

A secondary dnsd (config:zone_role=secondary) pulls each zone from its master at
startup. This stub plays that master over plain TCP: on an AXFR query for the
one zone it owns it sends a complete transfer (SOA, a multi-address A, a TXT, a
CNAME, closing SOA); for any *other* zone it just closes the connection, so the
secondary's pull of that zone fails and its existing store is left untouched
(important — the test shares one Valkey with everything else).

It is NOT a real server and does no TSIG (the transfer-client's TSIG support is
a separate step). Usage: axfr_master.py <bind_ip> <port> <zone>
"""
import socket
import struct
import sys

ZONE = "xfrpull.test"
SERIAL = 424242


def enc_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def rr(name, rrtype, rdata, ttl=120):
    return enc_name(name) + struct.pack(">HHIH", rrtype, 1, ttl, len(rdata)) + rdata


def soa_rdata():
    body = enc_name("ns1." + ZONE) + enc_name("hostmaster." + ZONE)
    body += struct.pack(">IIIII", SERIAL, 3600, 900, 604800, 300)
    return body


def parse_qname(query):
    off = 12
    labels = []
    while off < len(query):
        n = query[off]
        if n == 0:
            break
        labels.append(query[off + 1:off + 1 + n].decode("latin1"))
        off += 1 + n
    return ".".join(labels)


def build_axfr(qid):
    """One message: SOA, www A x2, info TXT, alias CNAME, closing SOA."""
    records = b""
    n = 0
    records += rr(ZONE, 6, soa_rdata()); n += 1                       # SOA
    records += rr("www." + ZONE, 1, socket.inet_aton("10.10.0.1")); n += 1
    records += rr("www." + ZONE, 1, socket.inet_aton("10.10.0.2")); n += 1
    records += rr("info." + ZONE, 16, b"\x09hello-xfr"); n += 1       # TXT "hello-xfr"
    records += rr("alias." + ZONE, 5, enc_name("www." + ZONE)); n += 1  # CNAME
    records += rr(ZONE, 6, soa_rdata()); n += 1                       # closing SOA
    header = struct.pack(">HHHHHH", qid, 0x8400, 0, n, 0, 0)          # QR+AA
    return header + records


def main():
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5388
    global ZONE
    if len(sys.argv) > 3:
        ZONE = sys.argv[3]

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
            if len(lb) != 2:
                conn.close()
                continue
            qlen = (lb[0] << 8) | lb[1]
            query = b""
            while len(query) < qlen:
                chunk = conn.recv(qlen - len(query))
                if not chunk:
                    break
                query += chunk
            if len(query) < 12:
                conn.close()
                continue
            qid = (query[0] << 8) | query[1]
            qname = parse_qname(query)
            # Only serve our own zone; close on anything else so the secondary
            # leaves that zone's existing store untouched.
            if qname.lower() != ZONE.lower():
                conn.close()
                continue
            msg = build_axfr(qid)
            conn.sendall(struct.pack(">H", len(msg)) + msg)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
