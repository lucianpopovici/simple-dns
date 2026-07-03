#!/usr/bin/env python3
"""RFC 2931 SIG(0) transaction-signature tooling, for `make check-sig0`.

nsupdate can't drive this (its `-k` SIG(0) support needs `dnssec-keygen`'s
on-disk key format, which isn't available in this test environment), so this
hand-builds and signs an RFC 2136 UPDATE the way RFC 2931 §3.1 specifies:
a trailing SIG RR (type 24, type-covered=0) whose signature covers the SIG
rdata prefix followed by the message with ARCOUNT patched to exclude the SIG
RR itself. The actual ECDSA math is delegated to `openssl dgst -sign` (no
Python crypto dependency) — this script only assembles/parses DNS wire bytes
and DER.

Usage:
  sig0_client.py provision <privkey.pem>
      Prints "<base64 pubkey X||Y> <keytag>" — what the Makefile recipe
      stores as zone:<zone>:KEY:<signer> = "0|3|13|<base64>" and cross-checks.
  sig0_client.py sign <host> <port> <zone> <privkey.pem> <signer_name>
                       <update_name> <corrupt_mode>
      corrupt_mode: none | flipsig | expired
      Sends a SIG(0)-signed UPDATE (add update_name A 10.9.9.9) and prints
      "RCODE <n>" for the response.
"""
import base64
import socket
import struct
import subprocess
import sys
import tempfile
import time

DNS_OPCODE_UPDATE = 5
DNS_TYPE_SIG = 24
DNS_TYPE_A = 1
DNS_CLASS_IN = 1
DNS_CLASS_ANY = 255


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def der_to_raw_ecdsa(der, size=32):
    assert der[0] == 0x30
    off = 1
    ln = der[off]
    off += 1
    if ln & 0x80:
        off += ln & 0x7F

    def read_int(buf, i):
        assert buf[i] == 0x02
        n = buf[i + 1]
        i += 2
        v = buf[i:i + n]
        i += n
        v = v.lstrip(b"\x00")
        v = v.rjust(size, b"\x00")
        return v, i

    r, off = read_int(der, off)
    s, off = read_int(der, off)
    return r + s


def sign(privkey_path, data):
    with tempfile.NamedTemporaryFile() as df:
        df.write(data)
        df.flush()
        der = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", privkey_path, df.name])
    return der_to_raw_ecdsa(der)


def pubkey_xy(privkey_path):
    """Raw 64-byte X||Y (uncompressed point minus the 0x04 prefix)."""
    pub_hex = subprocess.check_output(
        ["openssl", "ec", "-in", privkey_path, "-pubout", "-text", "-noout"],
        stderr=subprocess.DEVNULL).decode()
    pub_bytes = bytearray()
    in_pub = False
    for line in pub_hex.splitlines():
        if line.startswith("pub:"):
            in_pub = True
            continue
        if in_pub:
            toks = line.strip().rstrip(":").split(":")
            if not toks or not all(len(t) == 2 and all(c in "0123456789abcdefABCDEF" for c in t)
                                    for t in toks):
                break
            pub_bytes += bytes(int(t, 16) for t in toks)
    xy = bytes(pub_bytes[1:])
    assert len(xy) == 64, "unexpected pubkey length %d" % len(xy)
    return xy


def keytag_for(pubkey_xy_bytes):
    """RFC 4034 Appendix B keytag over a KEY/DNSKEY rdata blob (flags=0,
    protocol=3, algorithm=13 — matches what the Makefile recipe provisions)."""
    keyrd = struct.pack(">HBB", 0, 3, 13) + pubkey_xy_bytes
    ac = 0
    for i, b in enumerate(keyrd):
        ac += b << 8 if i % 2 == 0 else b
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def cmd_provision(argv):
    (privkey,) = argv
    xy = pubkey_xy(privkey)
    print("%s %d" % (base64.b64encode(xy).decode(), keytag_for(xy)))


def cmd_sign(argv):
    host, port, zone, privkey, signer, update_name, corrupt = argv
    port = int(port)

    msg_id = 0x5A5A
    header = struct.pack(">HHHHHH", msg_id, (DNS_OPCODE_UPDATE << 11), 1, 0, 1, 1)
    zone_section = encode_name(zone) + struct.pack(">HH", 6, DNS_CLASS_IN)  # SOA/IN
    update_rr = (encode_name(update_name) +
                 struct.pack(">HHIH", DNS_TYPE_A, DNS_CLASS_IN, 60, 4) +
                 socket.inet_aton("10.9.9.9"))
    prefix = header + zone_section + update_rr  # ARCOUNT=1 already baked in

    now = int(time.time())
    if corrupt == "expired":
        inception, expiration = now - 7200, now - 3600
    else:
        inception, expiration = now - 60, now + 3600

    xy = pubkey_xy(privkey)
    key_tag = keytag_for(xy)
    sig_rdata_prefix = (
        struct.pack(">H", 0) +          # type-covered = 0 (SIG(0))
        bytes([13]) +                   # algorithm: ECDSAP256SHA256
        bytes([0]) +                    # labels (unused for SIG(0))
        struct.pack(">I", 0) +          # original TTL (unused)
        struct.pack(">II", expiration, inception) +
        struct.pack(">H", key_tag) +
        encode_name(signer)
    )

    # Message-for-signing: prefix bytes with ARCOUNT patched to 0 (excludes
    # the not-yet-appended SIG RR) — mirrors dnsd's sig0_verify exactly.
    msg_for_signing = bytearray(prefix)
    struct.pack_into(">H", msg_for_signing, 10, 0)

    data_to_sign = sig_rdata_prefix + bytes(msg_for_signing)
    signature = sign(privkey, data_to_sign)
    if corrupt == "flipsig":
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    sig_rdata = sig_rdata_prefix + signature
    sig_rr = (b"\x00" +  # owner = root
              struct.pack(">HHIH", DNS_TYPE_SIG, DNS_CLASS_ANY, 0, len(sig_rdata)) +
              sig_rdata)

    packet = prefix + sig_rr
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(packet, (host, port))
    resp, _ = sock.recvfrom(4096)
    rflags = struct.unpack(">H", resp[2:4])[0]
    print("RCODE %d" % (rflags & 0x000F))


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("provision", "sign"):
        sys.exit(__doc__)
    if sys.argv[1] == "provision":
        cmd_provision(sys.argv[2:])
    else:
        cmd_sign(sys.argv[2:])


if __name__ == "__main__":
    main()
