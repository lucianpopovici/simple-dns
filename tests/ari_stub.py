#!/usr/bin/env python3
"""Minimal HTTPS stub ACME directory + RFC 9773 renewalInfo endpoint, for
`make check-ari` (certd's ARI-driven renewal, CLAUDE-certd.md Add 1).

Only serves what certd's directory fetch + ARI check need — not a full ACME
server (issuance itself still needs a real/staging CA per CLAUDE-certd.md's
own test section):

    GET /dir            -> ACME directory JSON; renewalInfo points back at
                            this server's /renewal-info.
    GET /renewal-info/*  -> {"suggestedWindow": {"start": ..., "end": ...}}
                            with the start/end timestamps given on the CLI, so
                            the same stub can serve a past window ("due now")
                            or a future window ("not yet due").

Usage: ari_stub.py <bind_ip> <port> <cert_pem> <key_pem> <start_rfc3339> <end_rfc3339> [run_secs]
"""
import http.server
import json
import ssl
import sys
import threading


def main():
    bind_ip, port = sys.argv[1], int(sys.argv[2])
    cert_pem, key_pem = sys.argv[3], sys.argv[4]
    start_s, end_s = sys.argv[5], sys.argv[6]
    run_secs = float(sys.argv[7]) if len(sys.argv) > 7 else 8.0
    base = "https://%s:%d" % (bind_ip, port)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            if self.path == "/dir":
                body = json.dumps({
                    "newNonce": base + "/new-nonce",
                    "newAccount": base + "/new-account",
                    "newOrder": base + "/new-order",
                    "renewalInfo": base + "/renewal-info",
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path.startswith("/renewal-info/"):
                body = json.dumps({
                    "suggestedWindow": {"start": start_s, "end": end_s},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

    srv = http.server.HTTPServer((bind_ip, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_pem, key_pem)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    import time
    time.sleep(run_secs)
    srv.shutdown()


if __name__ == "__main__":
    main()
