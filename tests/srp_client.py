#!/usr/bin/env python3
"""RFC 9665 SRP (Service Registration Protocol) client, for `make check-srp`.

Builds and signs a full SRP-shaped UPDATE (Host Description + optional
Service Description + optional Service Discovery PTR instructions, plus the
RFC 9664 Update Lease EDNS option and an RFC 2931 SIG(0) signature covering
the whole message) by hand — no existing tool speaks SRP. Reuses
sig0_client.py's crypto helpers (openssl dgst -sign, DER-to-raw conversion,
pubkey extraction, keytag) rather than duplicating them.

Usage:
  srp_client.py register <host> <port> <zone> <privkey.pem> <hostname>
                 <ip> <lease> <key_lease> [instance_name service_type port txt]
      Registers hostname->ip, and if the four service args are given, also a
      service instance (SRV+TXT) plus a Service Discovery PTR under
      "<service_type>.<zone>" -> "<instance_name>.<service_type>.<zone>".
      Prints "RCODE <n>" and, on success, "LEASE <n> KEY_LEASE <n>".
"""
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sig0_client import encode_name, sign, pubkey_xy, keytag_for  # noqa: E402

DNS_OPCODE_UPDATE = 5
DNS_TYPE_A = 1
DNS_TYPE_TXT = 16
DNS_TYPE_KEY = 25
DNS_TYPE_PTR = 12
DNS_TYPE_SRV = 33
DNS_TYPE_SIG = 24
DNS_TYPE_ANY = 255
DNS_CLASS_IN = 1
DNS_CLASS_ANY = 255
EDNS_OPT_UPDATE_LEASE = 2


def rr(name, rtype, rclass, ttl, rdata):
    return encode_name(name) + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def delete_all(name):
    return rr(name, DNS_TYPE_ANY, DNS_CLASS_ANY, 0, b"")


def main():
    if sys.argv[1] != "register":
        sys.exit(__doc__)
    (host, port, zone, privkey, hostname, ip, lease, key_lease) = sys.argv[2:10]
    port = int(port)
    lease = int(lease)
    key_lease = int(key_lease)
    svc_args = sys.argv[10:]

    xy = pubkey_xy(privkey)
    key_tag = keytag_for(xy)

    update_rrs = b""
    nscount = 0
    update_rrs += delete_all(hostname)
    nscount += 1
    key_rdata = struct.pack(">HBB", 0, 3, 13) + xy  # flags=0, protocol=3, alg=13 (ECDSAP256SHA256)
    update_rrs += rr(hostname, DNS_TYPE_KEY, DNS_CLASS_IN, 0, key_rdata)
    nscount += 1
    if ip:
        update_rrs += rr(hostname, DNS_TYPE_A, DNS_CLASS_IN, 3600, socket.inet_aton(ip))
        nscount += 1

    if svc_args:
        instance, svc_type, svc_port, txt = svc_args
        instance_fqdn = "%s.%s.%s" % (instance, svc_type, zone)
        update_rrs += delete_all(instance_fqdn)
        nscount += 1
        srv_rdata = struct.pack(">HHH", 0, 0, int(svc_port)) + encode_name(hostname)
        update_rrs += rr(instance_fqdn, DNS_TYPE_SRV, DNS_CLASS_IN, 0, srv_rdata)
        nscount += 1
        txt_rdata = bytes([len(txt)]) + txt.encode()
        update_rrs += rr(instance_fqdn, DNS_TYPE_TXT, DNS_CLASS_IN, 0, txt_rdata)
        nscount += 1
        browse_name = "%s.%s" % (svc_type, zone)
        update_rrs += rr(browse_name, DNS_TYPE_PTR, DNS_CLASS_IN, 0, encode_name(instance_fqdn))
        nscount += 1

    msg_id = 0x0A0B
    header = struct.pack(">HHHHHH", msg_id, (DNS_OPCODE_UPDATE << 11), 1, 0, nscount, 2)
    zone_section = encode_name(zone) + struct.pack(">HH", 6, DNS_CLASS_IN)

    # EDNS Update Lease option (RFC 9664 §1, code 2, 8-byte LEASE+KEY-LEASE variant)
    ul_data = struct.pack(">HH", EDNS_OPT_UPDATE_LEASE, 8) + struct.pack(">II", lease, key_lease)
    opt_rr = (b"\x00" + struct.pack(">HHIH", 41, 1232, 0, len(ul_data)) + ul_data)

    prefix = header + zone_section + update_rrs + opt_rr  # ARCOUNT=2 (OPT + not-yet-appended SIG)

    now = int(time.time())
    sig_rdata_prefix = (
        struct.pack(">H", 0) +      # type-covered = 0 (SIG(0))
        bytes([13]) +               # algorithm
        bytes([0]) +                # labels (unused)
        struct.pack(">I", 0) +      # original TTL (unused)
        struct.pack(">II", now + 3600, now - 60) +  # expiration, inception
        struct.pack(">H", key_tag) +
        encode_name(hostname)       # signer name = the host being registered
    )

    msg_for_signing = bytearray(prefix)
    struct.pack_into(">H", msg_for_signing, 10, 1)  # ARCOUNT without the SIG RR = 1 (OPT only)

    data_to_sign = sig_rdata_prefix + bytes(msg_for_signing)
    signature = sign(privkey, data_to_sign)
    sig_rdata = sig_rdata_prefix + signature
    sig_rr = (b"\x00" + struct.pack(">HHIH", DNS_TYPE_SIG, DNS_CLASS_ANY, 0, len(sig_rdata)) +
              sig_rdata)

    packet = prefix + sig_rr
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(packet, (host, port))
    resp, _ = sock.recvfrom(4096)
    rflags = struct.unpack(">H", resp[2:4])[0]
    rcode = rflags & 0x000F
    print("RCODE %d" % rcode)
    if rcode == 0:
        arcount = struct.unpack(">H", resp[10:12])[0]
        if arcount >= 1 and len(resp) >= 12 + 11:
            rdlen = struct.unpack(">H", resp[12 + 9:12 + 11])[0]
            rdata = resp[12 + 11:12 + 11 + rdlen]
            off = 0
            while off + 4 <= len(rdata):
                oc, ol = struct.unpack(">HH", rdata[off:off + 4])
                off += 4
                if oc == EDNS_OPT_UPDATE_LEASE and ol >= 8:
                    g_lease, g_key_lease = struct.unpack(">II", rdata[off:off + 8])
                    print("LEASE %d KEY_LEASE %d" % (g_lease, g_key_lease))
                off += ol


if __name__ == "__main__":
    main()
