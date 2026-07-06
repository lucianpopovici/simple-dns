#!/usr/bin/env python3
"""Minimal HTTPS stub ACME server for `make check-star` (certd's RFC 8739
STAR support, CLAUDE-certd.md's Roadmap item).

Implements just enough of RFC 8555 to drive certd's acme_issue() through a
full dns-01 order/authz/challenge/finalize cycle, PLUS the RFC 8739
extension: a directory meta.auto-renewal object, a "star-certificate" field
on the finalized order (instead of "certificate"), and a fetch endpoint that
serves a different cert PEM on each call — so the test can prove a second
`certd --once` run fetches a NEW cert via ONLY that one endpoint, without
touching new-order/authz/chal/finalize again (the entire point of STAR:
one authorization, many short-lived certs). A third phase accepts an order
cancellation POST ({"status":"canceled"} as the JWS payload) to cover
RFC 8739 s5.

Not a real CA: does not verify JWS signatures, does not check the dns-01
TXT record was actually published, does not inspect the finalize CSR.
Matches the project's existing stub-server philosophy (ari_stub.py): drive
the client's state machine, don't re-implement CA-side validation.

  GET  /dir              -> directory JSON (meta.auto-renewal included)
  HEAD /new-nonce         -> 200 + Replay-Nonce header
  POST /new-account       -> 201 + Location (account URL)
  POST /new-order         -> 201 + Location (order URL) + {authorizations,finalize}
  POST /authz/1           -> {status:"valid", challenges:[{type:"dns-01",...}]}
  POST /chal/1            -> 200 (challenge trigger, ignored)
  POST /finalize/1        -> 200 (CSR ignored)
  POST /order/1           -> normal poll: {status:"valid","star-certificate":<url>}
                             cancel (payload {"status":"canceled"}): {status:"canceled"}
  POST /star-cert/1       -> PEM cert chain; alternates cert_a then cert_b (then
                             cert_b again) across successive calls
  GET  /__stats           -> {"<path>": <hit count>, ...} for test assertions

Usage: star_stub.py <bind_ip> <port> <cert_pem> <key_pem> <cert_a_pem> <cert_b_pem> [run_secs]
"""
import base64
import http.server
import json
import ssl
import sys
import threading
import time


def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def main():
    bind_ip, port = sys.argv[1], int(sys.argv[2])
    cert_pem, key_pem = sys.argv[3], sys.argv[4]
    cert_a_pem, cert_b_pem = sys.argv[5], sys.argv[6]
    run_secs = float(sys.argv[7]) if len(sys.argv) > 7 else 20.0
    base = "https://%s:%d" % (bind_ip, port)

    with open(cert_a_pem) as f:
        cert_a = f.read()
    with open(cert_b_pem) as f:
        cert_b = f.read()

    hits = {}
    star_cert_calls = [0]

    def bump(path):
        hits[path] = hits.get(path, 0) + 1

    def send_json(handler, code, obj, headers=None):
        body = json.dumps(obj).encode()
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        handler.wfile.write(body)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_HEAD(self):
            if self.path == "/new-nonce":
                bump("/new-nonce")
                self.send_response(200)
                self.send_header("Replay-Nonce", "testnonce")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_GET(self):
            if self.path == "/dir":
                bump("/dir")
                send_json(self, 200, {
                    "newNonce": base + "/new-nonce",
                    "newAccount": base + "/new-account",
                    "newOrder": base + "/new-order",
                    "meta": {
                        "auto-renewal": {
                            "min-lifetime": 60,
                            "max-duration": 31536000,
                            "allow-certificate-get": False,
                        },
                    },
                })
            elif self.path == "/__stats":
                send_json(self, 200, hits)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            payload = None
            if raw:
                try:
                    jws = json.loads(raw.decode())
                    if jws.get("payload"):
                        payload = json.loads(b64url_decode(jws["payload"]).decode())
                except Exception:
                    payload = None

            if self.path == "/new-account":
                bump("/new-account")
                self.send_response(201)
                self.send_header("Location", base + "/acct/1")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/new-order":
                bump("/new-order")
                send_json(self, 201, {
                    "status": "pending",
                    "authorizations": [base + "/authz/1"],
                    "finalize": base + "/finalize/1",
                }, {"Location": base + "/order/1"})
            elif self.path == "/authz/1":
                bump("/authz/1")
                send_json(self, 200, {
                    "status": "valid",
                    "challenges": [
                        {"type": "dns-01", "token": "startesttoken", "url": base + "/chal/1"},
                    ],
                })
            elif self.path == "/chal/1":
                bump("/chal/1")
                send_json(self, 200, {"status": "processing"})
            elif self.path == "/finalize/1":
                bump("/finalize/1")
                send_json(self, 200, {"status": "valid"})
            elif self.path == "/order/1":
                bump("/order/1")
                if payload is not None and payload.get("status") == "canceled":
                    send_json(self, 200, {"status": "canceled"})
                else:
                    send_json(self, 200, {
                        "status": "valid",
                        "star-certificate": base + "/star-cert/1",
                    })
            elif self.path == "/star-cert/1":
                bump("/star-cert/1")
                star_cert_calls[0] += 1
                body = (cert_a if star_cert_calls[0] == 1 else cert_b).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/pem-certificate-chain")
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
    time.sleep(run_secs)
    with open("/tmp/star_stub_stats.json", "w") as f:
        json.dump(hits, f)
    srv.shutdown()


if __name__ == "__main__":
    main()
