#!/usr/bin/env python3
"""Stub secondary for `make check-notify` — exercises the master's hardened
NOTIFY sender (RFC 1996 §3.6 + RFC 8945).

Listens on UDP for NOTIFY requests from dnsd and, for each one:
  - checks it is a NOTIFY (opcode 4, QR=0) carrying the expected zone question;
  - verifies the TSIG RR: MAC = HMAC-SHA256(key, msg-without-TSIG[arcount-1] ||
    tsig-vars). A wrong/absent MAC is recorded as a TSIG failure.

To prove the sender *retries*, the stub deliberately withholds the response to
the first NOTIFY; from the second onward it answers with a NOTIFY response
(QR=1, opcode 4, same id) so the master stops retransmitting. After a fixed run
window it prints a summary the Makefile asserts on:

    COUNT <n>          total NOTIFYs received
    TSIG <ok|bad>      every received NOTIFY verified (ok) or any failed (bad)
    ACKED <yes|no>     whether the stub sent at least one response

Usage: notify_secondary.py <bind_ip> <port> <zone> <secret_b64> [run_secs]
HMAC-SHA256 / hmac-sha256 only.
"""
import base64
import hashlib
import hmac
import socket
import struct
import sys
import time

ALG_WIRE = b"\x0bhmac-sha256\x00"


def enc_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def tsig_vars(keyname, time_signed, fudge, error=0):
    v = enc_name(keyname)
    v += struct.pack(">H", 255)  # class ANY
    v += struct.pack(">I", 0)    # ttl
    v += ALG_WIRE
    v += struct.pack(">H", time_signed >> 32) + struct.pack(">I", time_signed & 0xFFFFFFFF)
    v += struct.pack(">H", fudge)
    v += struct.pack(">H", error)
    v += struct.pack(">H", 0)    # other len
    return v


def skip_name(msg, o):
    while o < len(msg):
        n = msg[o]
        if n & 0xC0 == 0xC0:
            return o + 2
        if n == 0:
            return o + 1
        o += 1 + n
    return o


def parse_tsig(msg):
    """Return (rr_start, keyname, time_signed, fudge, mac) or None."""
    arcount = struct.unpack(">H", msg[10:12])[0]
    if arcount < 1:
        return None
    qd, an, ns = struct.unpack(">HHH", msg[4:10])
    off = 12
    for _ in range(qd):
        off = skip_name(msg, off) + 4
    for _ in range(an + ns):
        off = skip_name(msg, off)
        rdlen = struct.unpack(">H", msg[off + 8:off + 10])[0]
        off += 10 + rdlen
    for _ in range(arcount):
        rr_start = off
        noff = skip_name(msg, off)
        rtype = struct.unpack(">H", msg[noff:noff + 2])[0]
        rdlen = struct.unpack(">H", msg[noff + 8:noff + 10])[0]
        rdata = msg[noff + 10:noff + 10 + rdlen]
        off = noff + 10 + rdlen
        if rtype == 250:
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
            while msg[o] != 0:
                ln = msg[o]
                kn.append(msg[o + 1:o + 1 + ln].decode())
                o += 1 + ln
            return (rr_start, ".".join(kn), time_signed, fudge, mac)
    return None


def dec_arcount(msg):
    ar = struct.unpack(">H", msg[10:12])[0] - 1
    return msg[:10] + struct.pack(">H", ar) + msg[12:]


def qname_of(msg):
    labels = []
    o = 12
    while o < len(msg) and msg[o] != 0:
        ln = msg[o]
        labels.append(msg[o + 1:o + 1 + ln].decode("latin1"))
        o += 1 + ln
    return ".".join(labels)


def main():
    bind_ip, port, zone, secret_b64 = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    run_secs = float(sys.argv[5]) if len(sys.argv) > 5 else 12.0
    secret = base64.b64decode(secret_b64)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    s.settimeout(0.5)

    count = 0
    tsig_ok = True
    acked = False
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
        count += 1
        # Validate the question zone.
        if qname_of(msg).lower().rstrip(".") != zone.lower().rstrip("."):
            tsig_ok = False
        # Validate the TSIG signature.
        parsed = parse_tsig(msg)
        if not parsed:
            tsig_ok = False
        else:
            rr_start, keyname, tsigned, fudge, mac = parsed
            stripped = dec_arcount(msg[:rr_start])
            expect = hmac.new(secret, stripped + tsig_vars(keyname, tsigned, fudge),
                              hashlib.sha256).digest()
            if not hmac.compare_digest(expect, mac):
                tsig_ok = False
        # Withhold the response to the first NOTIFY (force a retransmit); ack the rest.
        if count >= 2:
            resp = struct.pack(">HHHHHH", qid, 0xA000, 0, 0, 0, 0)  # QR=1, opcode NOTIFY
            s.sendto(resp, peer)
            acked = True
    print("COUNT %d" % count)
    print("TSIG %s" % ("ok" if tsig_ok else "bad"))
    print("ACKED %s" % ("yes" if acked else "no"))


if __name__ == "__main__":
    main()
