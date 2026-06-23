#!/usr/bin/env python3
"""TSIG-capable stub AXFR master for `make check-xfr-tsig`.

Exercises the secondary's transfer-TSIG (RFC 8945, dns_server.c Gap 4):
 - verifies the client's *request* signature with the shared key (so a wrong
   client MAC is rejected here — proving the client signs correctly),
 - signs the AXFR *response* with the chained MAC seeded by the request MAC
   (so the client's chained-response verification has something to check).

Modes (argv[5]): "ok" (default) sign correctly; "badresp" sign the response
with a corrupted key (the client must reject); "unsigned" send no TSIG RR
(the client, with a key configured, must reject).

Usage: axfr_master_tsig.py <bind> <port> <zone> <secret_b64> [mode]
HMAC-SHA256 / hmac-sha256 only. One-message AXFR (first==last signed message).
"""
import base64
import hashlib
import hmac
import socket
import struct
import sys

ZONE = "xfrtsig.test"
SERIAL = 555001
ALG_WIRE = b"\x0bhmac-sha256\x00"


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
    return body + struct.pack(">IIIII", SERIAL, 3600, 900, 604800, 300)


def records():
    recs = b""
    n = 0
    recs += rr(ZONE, 6, soa_rdata()); n += 1
    recs += rr("www." + ZONE, 1, socket.inet_aton("10.20.0.1")); n += 1
    recs += rr("info." + ZONE, 16, b"\x08tsig-ok!"); n += 1
    recs += rr(ZONE, 6, soa_rdata()); n += 1
    return recs, n


def tsig_vars(keyname, time_signed, fudge, error=0):
    v = enc_name(keyname)
    v += struct.pack(">H", 255)   # class ANY
    v += struct.pack(">I", 0)     # ttl
    v += ALG_WIRE
    v += struct.pack(">H", time_signed >> 32) + struct.pack(">I", time_signed & 0xFFFFFFFF)
    v += struct.pack(">H", fudge)
    v += struct.pack(">H", error)
    v += struct.pack(">H", 0)     # other len
    return v


def parse_tsig(query):
    """Return (ok, minus_len, keyname, time_signed, fudge, mac). minus_len is the
    offset where the TSIG RR begins (message without TSIG)."""
    arcount = struct.unpack(">H", query[10:12])[0]
    if arcount < 1:
        return None
    # Walk to the additional section: skip qd/an/ns then find the last RR (TSIG).
    qd, an, ns = struct.unpack(">HHH", query[4:10])
    off = 12

    def skip_name(o):
        while o < len(query):
            n = query[o]
            if n & 0xC0 == 0xC0:
                return o + 2
            if n == 0:
                return o + 1
            o += 1 + n
        return o

    for _ in range(qd):
        off = skip_name(off) + 4
    for _ in range(an + ns):
        off = skip_name(off)
        rdlen = struct.unpack(">H", query[off + 8:off + 10])[0]
        off += 10 + rdlen
    # additional RRs: the TSIG is the one with type 250
    for _ in range(arcount):
        rr_start = off
        noff = skip_name(off)
        rtype = struct.unpack(">H", query[noff:noff + 2])[0]
        rdlen = struct.unpack(">H", query[noff + 8:noff + 10])[0]
        rdata = query[noff + 10:noff + 10 + rdlen]
        off = noff + 10 + rdlen
        if rtype == 250:
            # rdata: alg name, time(6), fudge(2), macsize(2), mac, origid(2), err(2), otherlen(2)
            p = 0
            while rdata[p] != 0:
                p += 1 + rdata[p]
            p += 1
            time_signed = (struct.unpack(">H", rdata[p:p + 2])[0] << 32) | \
                struct.unpack(">I", rdata[p + 2:p + 6])[0]
            fudge = struct.unpack(">H", rdata[p + 6:p + 8])[0]
            macsize = struct.unpack(">H", rdata[p + 8:p + 10])[0]
            mac = rdata[p + 10:p + 10 + macsize]
            kn = []
            o = rr_start
            while query[o] != 0:
                ln = query[o]
                kn.append(query[o + 1:o + 1 + ln].decode())
                o += 1 + ln
            return (rr_start, ".".join(kn), time_signed, fudge, mac)
    return None


def dec_arcount(msg):
    ar = struct.unpack(">H", msg[10:12])[0] - 1
    return msg[:10] + struct.pack(">H", ar) + msg[12:]


def tsig_rr(keyname, time_signed, fudge, mac, orig_id):
    rd = ALG_WIRE
    rd += struct.pack(">H", time_signed >> 32) + struct.pack(">I", time_signed & 0xFFFFFFFF)
    rd += struct.pack(">H", fudge)
    rd += struct.pack(">H", len(mac)) + mac
    rd += struct.pack(">H", orig_id) + struct.pack(">H", 0) + struct.pack(">H", 0)
    return enc_name(keyname) + struct.pack(">HHIH", 250, 255, 0, len(rd)) + rd


def main():
    global ZONE
    bind_ip, port = sys.argv[1], int(sys.argv[2])
    ZONE = sys.argv[3]
    secret = base64.b64decode(sys.argv[4])
    mode = sys.argv[5] if len(sys.argv) > 5 else "ok"

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
                conn.close(); continue
            qlen = (lb[0] << 8) | lb[1]
            query = b""
            while len(query) < qlen:
                c = conn.recv(qlen - len(query))
                if not c:
                    break
                query += c
            qid = struct.unpack(">H", query[0:2])[0]
            parsed = parse_tsig(query)
            if not parsed:
                conn.close(); continue
            minus, keyname, qtime, qfudge, qmac = parsed
            # Verify the client's request signature (proves the client signed right).
            reqvars = tsig_vars(keyname, qtime, qfudge)
            expect = hmac.new(secret, dec_arcount(query[:minus]) + reqvars, hashlib.sha256).digest()
            if expect != qmac:
                conn.close(); continue  # bad client MAC -> refuse

            recs, n = records()
            body = struct.pack(">HHHHHH", qid, 0x8400, 0, n, 0, 0) + recs
            if mode == "unsigned":
                conn.sendall(struct.pack(">H", len(body)) + body)
                conn.close(); continue
            import time as _t
            now = int(_t.time())
            fudge = 300
            respvars = tsig_vars(keyname, now, fudge)
            sign_key = secret if mode != "badresp" else (secret[::-1] or b"x")
            # chain: prepend the request MAC (2-byte len || mac), then msg, then vars
            mac_in = struct.pack(">H", len(qmac)) + qmac + body + respvars
            mac = hmac.new(sign_key, mac_in, hashlib.sha256).digest()
            signed = body + tsig_rr(keyname, now, fudge, mac, qid)
            signed = signed[:10] + struct.pack(">H", 1) + signed[12:]  # arcount = 1
            conn.sendall(struct.pack(">H", len(signed)) + signed)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
