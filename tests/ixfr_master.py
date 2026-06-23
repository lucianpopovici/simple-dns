#!/usr/bin/env python3
"""IXFR-capable stub master for `make check-ixfr-client`.

Drives the secondary dnsd's *client-side* incremental transfer. Behaviour:

  - AXFR (qtype 252), or IXFR with a serial we don't recognise → a full
    AXFR-style transfer at serial 100:
        SOA(100), keep.<zone> A 10.0.0.1, old.<zone> A 10.0.0.2, SOA(100)
  - IXFR (qtype 251) whose authority SOA serial == 100 → an incremental diff
    that deletes old.<zone> and adds new.<zone>, advancing the serial to 101:
        SOA(101), SOA(100), old A 10.0.0.2, SOA(101), new A 10.0.3.3, SOA(101)

So a secondary first AXFRs (serial 0 → 100), then on a NOTIFY re-pull sends
IXFR(100) and must apply the diff: old.<zone> gone, new.<zone> present,
keep.<zone> untouched, serial 101.

No TSIG. Usage: ixfr_master.py <bind_ip> <port> <zone>
"""
import socket
import struct
import sys

ZONE = "ixfrpull.test"


def enc_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def rr(name, rrtype, rdata, ttl=120):
    return enc_name(name) + struct.pack(">HHIH", rrtype, 1, ttl, len(rdata)) + rdata


def soa_rdata(serial):
    body = enc_name("ns1." + ZONE) + enc_name("hostmaster." + ZONE)
    body += struct.pack(">IIIII", serial, 3600, 900, 604800, 300)
    return body


def parse_name(msg, off):
    labels = []
    while off < len(msg):
        n = msg[off]
        if n == 0:
            off += 1
            break
        if (n & 0xC0) == 0xC0:
            off += 2
            break
        labels.append(msg[off + 1:off + 1 + n].decode("latin1"))
        off += 1 + n
    return ".".join(labels), off


def parse_query(q):
    """Return (qname, qtype, ixfr_serial_or_None)."""
    qname, off = parse_name(q, 12)
    qtype = struct.unpack(">H", q[off:off + 2])[0]
    off += 4  # qtype + qclass
    nscount = struct.unpack(">H", q[8:10])[0]
    serial = None
    ancount = struct.unpack(">H", q[6:8])[0]
    for _ in range(ancount):  # skip answer section (normally 0)
        _, off = parse_name(q, off)
        rdlen = struct.unpack(">H", q[off + 8:off + 10])[0]
        off += 10 + rdlen
    for _ in range(nscount):  # authority: look for the SOA carrying the serial
        _, off = parse_name(q, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", q[off:off + 10])
        rdoff = off + 10
        off = rdoff + rdlen
        if rtype == 6:
            _, p = parse_name(q, rdoff)
            _, p = parse_name(q, p)
            serial = struct.unpack(">I", q[p:p + 4])[0]
    return qname, qtype, serial


def build_full(qid):
    recs = b""
    n = 0
    recs += rr(ZONE, 6, soa_rdata(100)); n += 1
    recs += rr("keep." + ZONE, 1, socket.inet_aton("10.0.0.1")); n += 1
    recs += rr("old." + ZONE, 1, socket.inet_aton("10.0.0.2")); n += 1
    recs += rr(ZONE, 6, soa_rdata(100)); n += 1
    return struct.pack(">HHHHHH", qid, 0x8400, 0, n, 0, 0) + recs


def build_incremental(qid):
    recs = b""
    n = 0
    recs += rr(ZONE, 6, soa_rdata(101)); n += 1  # opening (current)
    recs += rr(ZONE, 6, soa_rdata(100)); n += 1  # SOA old → deletions
    recs += rr("old." + ZONE, 1, socket.inet_aton("10.0.0.2")); n += 1  # delete
    recs += rr(ZONE, 6, soa_rdata(101)); n += 1  # SOA new → additions
    recs += rr("new." + ZONE, 1, socket.inet_aton("10.0.3.3")); n += 1  # add
    recs += rr(ZONE, 6, soa_rdata(101)); n += 1  # closing (current)
    return struct.pack(">HHHHHH", qid, 0x8400, 0, n, 0, 0) + recs


def main():
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5391
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
            qname, qtype, serial = parse_query(query)
            if qname.lower() != ZONE.lower():
                conn.close()
                continue
            if qtype == 251 and serial == 100:
                msg = build_incremental(qid)
            else:
                msg = build_full(qid)
            conn.sendall(struct.pack(">H", len(msg)) + msg)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
