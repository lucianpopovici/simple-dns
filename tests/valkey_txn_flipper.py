#!/usr/bin/env python3
"""ADR-004 test helper for `make check-axfr-concurrency`.

Repeatedly flips a set of zone:<zone>:A:hostN.<zone> keys between two
generations, using a single real Valkey MULTI/EXEC transaction per flip (so
the WRITE side is atomic by construction — every key transitions in one
instant, with no intermediate state where some keys are generation 1 and
others generation 2). This isolates the test from write-side atomicity
entirely: any mixed-generation observation by a reader can only be explained
by the READER (AXFR) not being atomic, which is exactly what
`axfr_send_runtime`'s per-type MULTI/EXEC batch (dns_server.c, ADR-004) is
supposed to prevent.

Encodes the generation in the last IP octet: gen 1 -> 10.0.<hi>.1,
gen 2 -> 10.0.<hi>.2 (hi = host index // 256, so more than 256 hosts still
fit in one /16).

Usage: valkey_txn_flipper.py <host> <port> <zone> <n_hosts> <duration_s> <interval_s>
"""
import socket
import sys
import time


def resp_encode(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        b = a.encode() if isinstance(a, str) else a
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out


def read_line(sock, buf):
    while b"\r\n" not in buf:
        c = sock.recv(4096)
        if not c:
            break
        buf += c
    line, _, rest = buf.partition(b"\r\n")
    return line, rest


def drain_replies(sock, buf, n):
    """Drain n RESP replies (simple-string/error/integer only — enough for
    MULTI/SET/EXEC), tolerating them arriving split across recv() calls."""
    got = 0
    while got < n:
        line, buf = read_line(sock, buf)
        if not line:
            break
        got += 1
    return buf


def main():
    host, port, zone, n_hosts, duration, interval = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
        float(sys.argv[5]), float(sys.argv[6]),
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    buf = b""
    gen = 1
    deadline = time.time() + duration
    flips = 0
    while time.time() < deadline:
        gen = 2 if gen == 1 else 1
        cmds = [resp_encode("MULTI")]
        for i in range(n_hosts):
            hi = i // 256
            val = "3600|10.0.%d.%d" % (hi, gen)
            key = "zone:%s:A:host%d.%s" % (zone, i, zone)
            cmds.append(resp_encode("SET", key, val))
        cmds.append(resp_encode("EXEC"))
        s.sendall(b"".join(cmds))
        # MULTI + n_hosts SETs + EXEC's own array header, then n_hosts more
        # simple replies inside the EXEC array.
        buf = drain_replies(s, buf, 1 + n_hosts + 1 + n_hosts)
        flips += 1
        time.sleep(interval)
    print("FLIPS %d" % flips)
    s.close()


if __name__ == "__main__":
    main()
