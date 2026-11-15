#!/usr/bin/env python3
"""Minimal RFC 7858 DoT stub for `make check-ddr`: query NAME A over TLS,
verifying the server certificate against CAFILE and the name HOSTNAME, and
print the A addresses (space-separated), or "ERROR <reason>".

Usage: dot_query.py SERVER PORT CAFILE HOSTNAME NAME

Replaces `dig +tls +tls-ca=... +tls-hostname=...`, which fails on the CI
runner's dig with "TLS context cannot be created" before it ever connects.
"""
import ssl
import sys

import dns.message
import dns.query
import dns.rdatatype


def main():
    if len(sys.argv) != 6:
        print(__doc__, file=sys.stderr)
        return 2
    server, port, cafile, hostname, name = sys.argv[1:]
    try:
        ctx = ssl.create_default_context(cafile=cafile)
        q = dns.message.make_query(name, "A")
        r = dns.query.tls(q, server, port=int(port), ssl_context=ctx, server_hostname=hostname,
                          timeout=3)
    except Exception as e:  # report, never traceback: the Makefile compares stdout
        print(f"ERROR {type(e).__name__}: {e}")
        return 1
    print(" ".join(rd.to_text() for rrset in r.answer if rrset.rdtype == dns.rdatatype.A
                   for rd in rrset))
    return 0


if __name__ == "__main__":
    sys.exit(main())
