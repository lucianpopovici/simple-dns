#!/usr/bin/env python3
"""CSA-MEM-002 probes (CLAUDE-low-fixes.md 8c). Sends malformed messages that
used to make dnsd read past a field's end, and checks dnsd rejects them and
stays up.

  1. UPDATE with a TSIG whose algorithm-name label runs past the TSIG RDATA
     (the packet continues, so the old code parsed an algorithm name out of
     the next bytes). Expect FORMERR or NOTAUTH, never a processed UPDATE.
  2. IXFR over TCP whose authority section claims an RR but ends right after
     its owner name. Expect dnsd to answer or close, and to keep serving.
  3. A plain query afterwards must still be answered (liveness).

usage: oob_probe.py <host> <port> <zone>
"""
import socket
import struct
import sys

host, port, zone = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def wname(n):
    out = b""
    for lab in n.rstrip(".").split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def udp(msg, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, (host, port))
    try:
        return s.recv(4096)
    except socket.timeout:
        return b""
    finally:
        s.close()


def tcp(msg, timeout=3.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(struct.pack(">H", len(msg)) + msg)
        hdr = s.recv(2)
        if len(hdr) < 2:
            return b""
        n = struct.unpack(">H", hdr)[0]
        data = b""
        while len(data) < n:
            c = s.recv(n - len(data))
            if not c:
                break
            data += c
        return data
    except (socket.timeout, ConnectionError):
        return b""
    finally:
        s.close()


def rcode(resp):
    return (resp[3] & 0xF) if len(resp) >= 4 else None


fails = 0

# 1. UPDATE (opcode 5): zone section + one TSIG in additional. TSIG RDATA is
#    declared 4 bytes long, but its first label claims 20 bytes; 40 junk
#    bytes follow so the old parser found "enough" packet to keep going.
#    The RR declares RDLENGTH 4, but the bytes after it complete a well-formed
#    TSIG RDATA (alg "hmac-sha256", time, fudge, empty MAC, ...). The old
#    parser read the algorithm name and every fixed field from beyond the
#    declared RDATA and went on to verify a TSIG (-> NOTAUTH); the fixed one
#    rejects the RR as malformed, so the UPDATE counts as unsigned (-> REFUSED).
zsec = wname(zone) + struct.pack(">HH", 6, 1)
beyond = (bytes([11]) + b"hmac-sha256" + b"\x00" + struct.pack(">HIHHHHH", 0, 0, 300, 0, 0x4242, 0, 0))
tsig = wname("tsig-key") + struct.pack(">HHIH", 250, 255, 0, 4) + beyond
upd = struct.pack(">HHHHHH", 0x4242, 0x2800, 1, 0, 0, 1) + zsec + tsig
r1 = udp(upd)
rc1 = rcode(r1)
print(f"  1. UPDATE with TSIG alg name past its RDATA -> rcode={rc1} (5 = treated as unsigned)")
if rc1 != 5:
    print("     FAIL  TSIG fields were read from beyond the RR's RDATA (CSA-MEM-002)")
    fails += 1

# 2. IXFR (qtype 251) over TCP: NSCOUNT=1 but the message ends after the
#    authority RR's owner name — no type/class/ttl/rdlength.
q = wname(zone) + struct.pack(">HH", 251, 1)
ixfr = struct.pack(">HHHHHH", 0x4343, 0x0000, 1, 0, 1, 0) + q + wname(zone)
r2 = tcp(ixfr)
print(f"  2. IXFR with a truncated authority RR -> {len(r2)}-byte reply, rcode={rcode(r2)}")

# 3. dnsd still answers.
qry = struct.pack(">HHHHHH", 0x4444, 0x0100, 1, 0, 0, 0) + wname(zone) + struct.pack(">HH", 6, 1)
r3 = udp(qry)
print(f"  3. SOA query afterwards -> rcode={rcode(r3)}")
if rcode(r3) != 0:
    print("     FAIL  dnsd stopped answering")
    fails += 1

print("FAIL" if fails else "OK")
sys.exit(1 if fails else 0)
