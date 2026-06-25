#!/usr/bin/env python3
"""Cookie-enforcing stub upstream for `make check-resolverd-cookie`.

Exercises resolverd's RFC 7873 client-side DNS Cookie exchange. This stub is a
deterministic offline upstream that REFUSES to answer until the client proves it
holds a valid Server Cookie:

  - A query with no COOKIE option, or with a wrong/absent Server Cookie, is
    answered with RCODE BADCOOKIE (23) and an OPT COOKIE carrying the Client
    Cookie echoed back plus a freshly minted Server Cookie. No answer records.
  - A query whose COOKIE option carries the correct Server Cookie (the one we
    minted for that Client Cookie) is answered with the A record.

So resolverd only ever gets an answer if it (a) learns the Server Cookie from the
BADCOOKIE reply and (b) retries carrying it — which is exactly the behaviour
under test. The Server Cookie is deterministic: SHA256(client_cookie || SECRET).

It prints one line per request so the Makefile can assert BOTH that a BADCOOKIE
was sent and that a cookie-validated answer was returned:

    BADCOOKIE   <reason>
    ANSWER      cookie-validated

Usage: cookie_upstream.py <bind_ip> <port> <answer_ipv4>
"""
import hashlib
import socket
import struct
import sys

QTYPE_A = 1
TYPE_OPT = 41
OPT_COOKIE = 10
RCODE_BADCOOKIE = 23
SECRET = b"cookie-stub-secret"
ANSWER_IP = "203.0.113.77"


def expected_server_cookie(client_cookie):
    return hashlib.sha256(client_cookie + SECRET).digest()[:16]


def parse_question(query):
    """Return (qid, qtype, question_bytes, off_after_question) or None."""
    if len(query) < 12:
        return None
    (qid, _flags, qdcount, _an, _ns, arcount) = struct.unpack(">HHHHHH", query[:12])
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
    return (qid, qtype, query[12:off + 4], off + 4, arcount)


def parse_cookie(query, off, arcount):
    """Walk additional RRs for an OPT COOKIE. Return (client, server) cookies
    (server may be b'') or (None, None) if no cookie option is present."""
    for _ in range(arcount):
        # owner name (root expected for OPT, but skip a real name defensively)
        while off < len(query):
            ln = query[off]
            if ln == 0:
                off += 1
                break
            if (ln & 0xC0) == 0xC0:
                off += 2
                break
            off += 1 + ln
        if off + 10 > len(query):
            return (None, None)
        (rtype, _cls, _ttl, rdlen) = struct.unpack(">HHIH", query[off:off + 10])
        rdata = query[off + 10:off + 10 + rdlen]
        off += 10 + rdlen
        if rtype != TYPE_OPT:
            continue
        rp = 0
        while rp + 4 <= len(rdata):
            (oc, ol) = struct.unpack(">HH", rdata[rp:rp + 4])
            rp += 4
            if rp + ol > len(rdata):
                break
            if oc == OPT_COOKIE and ol >= 8:
                client = rdata[rp:rp + 8]
                server = rdata[rp + 8:rp + ol]
                return (client, server)
            rp += ol
    return (None, None)


def opt_with_cookie(client, server):
    cookie = client + server
    rdata = struct.pack(">HH", OPT_COOKIE, len(cookie)) + cookie
    # name=root(0), type=OPT, class=udpsize, ttl=0, rdlen, rdata
    return struct.pack(">BHHIH", 0, TYPE_OPT, 1232, 0, len(rdata)) + rdata


def answer_record():
    rr = struct.pack(">HHHIH", 0xC00C, QTYPE_A, 1, 60, 4)
    return rr + socket.inet_aton(ANSWER_IP)


def make_badcookie(qid, question, client, server):
    # Header low nibble = 7; OPT TTL ext-RCODE high byte = 1 -> full RCODE 23.
    # 0x8187 = QR=1 RD=1 RA=1, rcode-low=7.
    header = struct.pack(">HHHHHH", qid, 0x8187, 1, 0, 0, 1)
    opt = bytearray(opt_with_cookie(client, server))
    opt[5] = 0x01  # TTL byte 0 = extended-RCODE high bits (BADCOOKIE)
    return header + question + bytes(opt)


def build_response(query):
    parsed = parse_question(query)
    if parsed is None:
        return None
    (qid, qtype, question, qend, arcount) = parsed
    (client, server) = parse_cookie(query, qend, arcount)
    if client is None:
        print("BADCOOKIE no-cookie-option", flush=True)
        client = b"\x00" * 8
        return make_badcookie(qid, question, client, expected_server_cookie(client))
    want = expected_server_cookie(client)
    if server != want:
        print("BADCOOKIE " + ("no-server-cookie" if not server else "wrong-server-cookie"),
              flush=True)
        return make_badcookie(qid, question, client, want)
    print("ANSWER cookie-validated", flush=True)
    ancount = 1 if qtype == QTYPE_A else 0
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, ancount, 0, 1)
    resp = header + question
    if ancount:
        resp += answer_record()
    resp += opt_with_cookie(client, want)
    return resp


def main():
    global ANSWER_IP
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5399
    if len(sys.argv) > 3:
        ANSWER_IP = sys.argv[3]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port))
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            break
        resp = build_response(data)
        if resp is not None:
            s.sendto(resp, addr)


if __name__ == "__main__":
    main()
