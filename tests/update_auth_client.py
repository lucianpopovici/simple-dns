#!/usr/bin/env python3
"""RFC 2136 UPDATE authentication probe for `make check-update-auth`
(CLAUDE-update-auth.md Fix 1 + Fix 2: CSA-AUTH-001 / CSA-AUTH-002).

Usage:
  update_auth_client.py MODE SERVER PORT ZONE LABEL [ARG]

MODE:
  unsigned          no TSIG
  signed            TSIG hmac-sha256 with key "tsig-key", current time
  signed-shift N    as signed, but Time Signed shifted by N seconds
  signed-fudge N F  as signed-shift N, with fudge F
  signed-key NAME   as signed, but with key name NAME (same secret)
  signed-alg ALG    as signed, but algorithm ALG (hmac-sha1 / hmac-md5)
  signed-flip       as signed, but one MAC byte flipped

Adds "<LABEL>.<ZONE> 60 TXT ua" and prints one line:
  "RCODE <n>"            response carried no TSIG error
  "RCODE <n> TSIG <e>"   response carried TSIG error e (16/17/18)
  "RCODE <n> TSIGOK"     response TSIG present and verified
The secret is the fixed test value the other check-* targets use; this file
holds no real key material.
"""
import socket
import struct
import sys
import time

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.update

SECRET = b"0123456789abcdef0123456789abcdef"
KEYNAME = "tsig-key"
ALGS = {
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-md5": dns.tsig.HMAC_MD5,
}


def send(wire, server, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(wire, (server, port))
    data, _ = s.recvfrom(65535)
    s.close()
    return data


def build(mode, zone, label, args):
    upd = dns.update.UpdateMessage(zone)
    upd.add(f"{label}.{zone}.", 60, "TXT", "ua")
    if mode == "unsigned":
        return upd, None, upd.to_wire()
    keyname = KEYNAME
    alg = dns.tsig.HMAC_SHA256
    shift = 0
    fudge = 300
    if mode == "signed-key":
        keyname = args[0]
    elif mode == "signed-alg":
        alg = ALGS[args[0]]
    elif mode == "signed-shift":
        shift = int(args[0])
    elif mode == "signed-fudge":
        shift = int(args[0])
        fudge = int(args[1])
    key = dns.tsig.Key(keyname, SECRET, algorithm=alg)
    upd.use_tsig(key, fudge=fudge)
    real = time.time
    try:
        time.time = lambda: real() + shift
        wire = bytearray(upd.to_wire())
    finally:
        time.time = real
    if mode == "signed-flip":
        # MAC sits at a fixed distance from the end of the TSIG RR:
        # ... mac(32) | orig_id(2) | error(2) | other_len(2)
        wire[-7] ^= 0x01
    return upd, key, bytes(wire)


def main():
    if len(sys.argv) < 6:
        print(__doc__, file=sys.stderr)
        return 2
    mode, server, port, zone, label = sys.argv[1:6]
    args = sys.argv[6:]
    upd, key, wire = build(mode, zone, label, args)
    data = send(wire, server, int(port))
    rcode = struct.unpack("!H", data[2:4])[0] & 0x000F
    if key is None:
        print(f"RCODE {rcode}")
        return 0
    try:
        dns.message.from_wire(
            data, keyring={dns.name.from_text(key.name.to_text()): key}, request_mac=upd.mac
        )
    except dns.tsig.PeerBadSignature:
        print(f"RCODE {rcode} TSIG 16")
        return 0
    except dns.tsig.PeerBadKey:
        print(f"RCODE {rcode} TSIG 17")
        return 0
    except dns.tsig.PeerBadTime:
        print(f"RCODE {rcode} TSIG 18")
        return 0
    except dns.message.UnknownTSIGKey:
        print(f"RCODE {rcode} TSIG unknown-key")
        return 0
    except dns.exception.DNSException as e:
        print(f"RCODE {rcode} TSIG invalid ({type(e).__name__})")
        return 0
    has_tsig = struct.unpack("!H", data[10:12])[0] > 0
    print(f"RCODE {rcode} TSIGOK" if has_tsig else f"RCODE {rcode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
