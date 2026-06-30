#!/usr/bin/env python3
"""Independent RFC 8976 ZONEMD verifier for `make check-zonemd`.

Performs an AXFR of <zone> from dnsd, then recomputes the SIMPLE-scheme
SHA-384 digest (RFC 8976 §3.3) over the transferred RRset — canonicalizing
each RR per RFC 4034 §6.2, ordering by §6.1/§6.3, de-duplicating, and EXCLUDING
the apex ZONEMD RRset from its own digest (§3.3.2) — and compares it against the
digest dnsd published in the apex ZONEMD record. This is a differential check:
the C path (zonemd_compute) enumerates Valkey directly, this path reads the live
AXFR, and the two must agree.

Usage: zonemd_verify.py <host> <port> <zone>
Prints "OK <hexdigest>" and exits 0 on match; "FAIL ..." + exit 1 otherwise.
"""
import hashlib
import socket
import struct
import sys

TYPE_SOA = 6
TYPE_ZONEMD = 63
TYPE_AXFR = 252
CLASS_IN = 1

# RR types whose rdata carries domain name(s) that RFC 4034 §6.2 lowercases /
# uncompresses for the canonical form. Mirrors libdnswire's canon_rdata().
NAME_RDATA = {2: "name", 5: "name", 12: "name", 39: "name",  # NS CNAME PTR DNAME
              15: "mx", 33: "srv", 6: "soa"}


def read_name(buf, off):
    """Return (list-of-lowercased-label-bytes, next_off) following pointers."""
    labels = []
    nxt = None
    while True:
        ln = buf[off]
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if nxt is None:
                nxt = off + 2
            off = ptr
            continue
        if ln == 0:
            if nxt is None:
                nxt = off + 1
            break
        labels.append(bytes(buf[off + 1:off + 1 + ln]).lower())
        off += 1 + ln
    return labels, nxt


def name_wire(labels):
    out = b""
    for lab in labels:
        out += bytes([len(lab)]) + lab
    return out + b"\x00"


def canon_rdata(buf, rdoff, rdlen, rtype):
    kind = NAME_RDATA.get(rtype)
    if kind == "name":
        labels, _ = read_name(buf, rdoff)
        return name_wire(labels)
    if kind == "mx":
        pref = bytes(buf[rdoff:rdoff + 2])
        labels, _ = read_name(buf, rdoff + 2)
        return pref + name_wire(labels)
    if kind == "srv":
        head = bytes(buf[rdoff:rdoff + 6])
        labels, _ = read_name(buf, rdoff + 6)
        return head + name_wire(labels)
    if kind == "soa":
        mn, o = read_name(buf, rdoff)
        rn, o = read_name(buf, o)
        return name_wire(mn) + name_wire(rn) + bytes(buf[o:o + 20])
    return bytes(buf[rdoff:rdoff + rdlen])


def name_cmp_key(labels):
    # RFC 4034 §6.1: order by labels from the right. Python tuple comparison of
    # the reversed label list reproduces "compare from the least significant
    # label, octet-wise, fewer labels first".
    return tuple(reversed(labels))


def axfr(host, port, zone):
    qname = name_wire([p.encode().lower() for p in zone.split(".") if p])
    q = struct.pack(">HHHHHH", 0x5151, 0, 1, 0, 0, 0)
    q += qname + struct.pack(">HH", TYPE_AXFR, CLASS_IN)
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(struct.pack(">H", len(q)) + q)
    data = b""

    def recv_msg():
        nonlocal data
        while len(data) < 2:
            chunk = s.recv(4096)
            if not chunk:
                return None
            data += chunk
        mlen = struct.unpack(">H", data[:2])[0]
        while len(data) < 2 + mlen:
            chunk = s.recv(4096)
            if not chunk:
                return None
            data += chunk
        msg = data[2:2 + mlen]
        data = data[2 + mlen:]
        return msg

    rrs = []
    soa_seen = 0
    while True:
        msg = recv_msg()
        if msg is None:
            break
        _, _, _, ancount, _, _ = struct.unpack(">HHHHHH", msg[:12])
        off = 12
        # Skip question section (only the first message carries one).
        # Heuristic: question present iff qdcount field set.
        qd = struct.unpack(">H", msg[4:6])[0]
        for _ in range(qd):
            _, off = read_name(msg, off)
            off += 4
        for _ in range(ancount):
            owner, off = read_name(msg, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
            off += 10
            cr = canon_rdata(msg, off, rdlen, rtype)
            off += rdlen
            rrs.append((owner, rtype, rclass, ttl, cr))
            if rtype == TYPE_SOA:
                soa_seen += 1
        if soa_seen >= 2:
            break
    s.close()
    return rrs


def main():
    host, port, zone = sys.argv[1], int(sys.argv[2]), sys.argv[3].rstrip(".")
    apex = [p.encode().lower() for p in zone.split(".") if p]
    rrs = axfr(host, port, zone)

    published = None  # (scheme, hashalg, digest_hex) from the apex ZONEMD RR
    canon = []
    for owner, rtype, rclass, ttl, cr in rrs:
        if owner == apex and rtype == TYPE_ZONEMD:
            # serial(4) scheme(1) hash(1) digest
            scheme, hashalg = cr[4], cr[5]
            published = (scheme, hashalg, cr[6:].hex())
            continue  # §3.3.2: exclude the apex ZONEMD from its own digest
        wire = name_wire(owner) + struct.pack(">HHIH", rtype, rclass, ttl, len(cr)) + cr
        canon.append((name_cmp_key(owner), rtype, cr, wire))

    if published is None:
        print("FAIL no apex ZONEMD record in the AXFR")
        return 1

    canon.sort(key=lambda x: (x[0], x[1], x[2]))
    h = hashlib.sha384()
    prev = None
    for _, _, _, wire in canon:
        if wire == prev:
            continue  # RFC 8976 §3.3.1: a duplicate RR contributes once
        h.update(wire)
        prev = wire
    computed = h.hexdigest()

    scheme, hashalg, pub_hex = published
    if scheme != 1:
        print(f"FAIL published scheme {scheme} != 1 (SIMPLE)")
        return 1
    if hashalg != 1:
        print(f"FAIL published hash {hashalg} != 1 (SHA-384)")
        return 1
    if pub_hex.lower() != computed.lower():
        print("FAIL digest mismatch")
        print(f"  published: {pub_hex}")
        print(f"  computed : {computed}")
        return 1
    print(f"OK {computed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
