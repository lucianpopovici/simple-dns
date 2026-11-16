#!/usr/bin/env python3
"""Open N TCP connections that never send a byte and hold them up to HOLD
seconds, for `make check-tcp-plain` (CSA-DOS-002). Prints one line:

  opened=<n> closed_by_server=<n> first_close=<secs|-> last_close=<secs|->

A connection counts as closed by the server when recv() returns EOF or a
reset. Usage: tcp_idle_flood.py HOST PORT N HOLD
"""
import select
import socket
import sys
import time


def main():
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    host, port, n, hold = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
    socks = []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((host, port))
        except OSError:
            s.close()
            continue
        s.setblocking(False)
        socks.append(s)
    t0 = time.time()
    open_set = set(socks)
    closes = []
    while open_set and time.time() - t0 < hold:
        r, _, _ = select.select(list(open_set), [], [], 0.2)
        for s in r:
            try:
                data = s.recv(64)
            except (ConnectionResetError, OSError):
                data = b""
            if not data:
                closes.append(time.time() - t0)
                open_set.discard(s)
                s.close()
    for s in open_set:
        s.close()
    first = f"{min(closes):.1f}" if closes else "-"
    last = f"{max(closes):.1f}" if closes else "-"
    print(f"opened={len(socks)} closed_by_server={len(closes)} first_close={first} last_close={last}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
