#!/usr/bin/env python3
"""Minimal RFC 8490 DSO + RFC 8765 DNS Push Notifications client, for
`make check-dso` (mdnsd's Add 2). No standard tool (dig/kdig) speaks DSO, so
this hand-rolls just enough of the wire format to SUBSCRIBE, read the initial
PUSH, then wait for one more PUSH (the change-detection poll firing after the
mDNS stub it's testing against goes away) and report what it saw.

Usage: dso_push_client.py <host> <port> <ca_pem> <server_hostname> <qname> <qtype> <wait_secs>
Prints one line per RR seen, tagged INIT (initial push right after SUBSCRIBE)
or LATER (any push after that): "RR <TAG> name=<name> type=<type> ttl=<ttl> rdata=<hex>"
Also prints "SUBSCRIBE_RCODE <n>" for the SUBSCRIBE response's RCODE.
"""
import socket
import ssl
import struct
import sys

DSO_OPCODE_FLAGS = 0x3000  # opcode 6 in bits 14-11, QR=0
DSO_TLV_SUBSCRIBE = 0x40
DSO_TLV_PUSH = 0x41


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_name(buf, off):
    """Sequential-label decode only (no compression pointers — the server
    never emits them inside a Push TLV's DATA)."""
    labels = []
    while off < len(buf):
        ln = buf[off]
        if ln & 0xC0:
            raise ValueError("unexpected compression pointer in PUSH RR name")
        off += 1
        if ln == 0:
            break
        labels.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), off


def send_msg(sock, body):
    sock.sendall(struct.pack(">H", len(body)) + body)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    lb = recv_exact(sock, 2)
    if lb is None:
        return None
    (mlen,) = struct.unpack(">H", lb)
    return recv_exact(sock, mlen)


def parse_push_rrs(data, tag):
    off = 0
    while off < len(data):
        name, off = decode_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        print("RR %s name=%s type=%d ttl=%d rdata=%s" % (tag, name, rtype, ttl, rdata.hex()))


def main():
    host, port, ca_pem, server_hostname, qname, qtype, wait_secs = sys.argv[1:8]
    port = int(port)
    qtype = int(qtype)
    wait_secs = float(wait_secs)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_pem)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw = socket.create_connection((host, port), timeout=5)
    sock = ctx.wrap_socket(raw, server_hostname=server_hostname)
    sock.settimeout(wait_secs)

    # SUBSCRIBE (Message ID must be nonzero)
    msg_id = 0x1234
    data = encode_name(qname) + struct.pack(">HH", qtype, 1)  # CLASS IN
    tlv = struct.pack(">HH", DSO_TLV_SUBSCRIBE, len(data)) + data
    header = struct.pack(">HHHHHH", msg_id, DSO_OPCODE_FLAGS, 0, 0, 0, 0)
    send_msg(sock, header + tlv)

    resp = recv_msg(sock)
    if resp is None:
        print("FAIL no SUBSCRIBE response")
        sys.exit(1)
    (rid, rflags) = struct.unpack(">HH", resp[0:4])
    rcode = rflags & 0x000F
    print("SUBSCRIBE_RCODE %d" % rcode)
    if rid != msg_id:
        print("FAIL SUBSCRIBE response Message ID mismatch")
        sys.exit(1)
    if rcode != 0:
        sys.exit(0)

    # Initial PUSH (spec: sent immediately following the response, if non-empty)
    try:
        push1 = recv_msg(sock)
    except socket.timeout:
        push1 = None
    if push1:
        (pid, pflags) = struct.unpack(">HH", push1[0:4])
        ptlv_type, ptlv_len = struct.unpack(">HH", push1[12:16])
        if pid == 0 and ptlv_type == DSO_TLV_PUSH:
            parse_push_rrs(push1[16:16 + ptlv_len], "INIT")

    # Wait for a later PUSH (change detection)
    try:
        push2 = recv_msg(sock)
    except socket.timeout:
        push2 = None
    if push2:
        (pid, pflags) = struct.unpack(">HH", push2[0:4])
        ptlv_type, ptlv_len = struct.unpack(">HH", push2[12:16])
        if pid == 0 and ptlv_type == DSO_TLV_PUSH:
            parse_push_rrs(push2[16:16 + ptlv_len], "LATER")
    else:
        print("NO_LATER_PUSH")

    sock.close()


if __name__ == "__main__":
    main()
