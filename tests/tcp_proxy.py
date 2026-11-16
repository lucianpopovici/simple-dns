#!/usr/bin/env python3
"""Minimal TCP forwarder: listen on <listen_port>, relay each connection to
<target_host>:<target_port>. Killing it simulates a Valkey outage for a
daemon pointed at it (check-dnsd-serve-stale) without touching the real
Valkey other tests share.

usage: tcp_proxy.py <listen_port> <target_host> <target_port>
"""
import socket
import sys
import threading

lport, thost, tport = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", lport))
srv.listen(64)
while True:
    c, _ = srv.accept()
    try:
        u = socket.create_connection((thost, tport))
    except OSError:
        c.close()
        continue
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
