# dns_server.c — plain TCP vs DoT on the stream listeners

Fix spec for audit finding **CSA-PROTO-002** (High), with **CSA-DOS-002**
(Medium) as a complementary item because it edits the same lines. Source:
`SECURITY_AUDIT.md`, section 2026-11-15.

All line anchors are against commit `b0a6b32`. Re-anchor before editing:

```sh
grep -n "} dot_conn_t;\|static void \*dot_thread\|SSL_CTX \*ctx = g_dot_ctx;\|accept(tcp_dns_sock\|accept(dot_sock\|accept(dot6_sock\|dot_thread, c" dns_server.c
```

| Fix | Finding | Status |
|----:|---------|--------|
| 1 | CSA-PROTO-002 — plain TCP/53 speaks TLS once a certificate is loaded | **Done** 2026-11-15 (`make check-tcp-plain`) |
| 2 | CSA-DOS-002 — no connection cap, no handshake timeout, unchecked `pthread_create` | **Done** 2026-11-15 (`make check-tcp-plain`) |

Implementation notes: the three accept sites now call one `stream_accept()`
(cap check, 5 s RCV+SND timeouts before the thread starts, checked
`pthread_create`); `dot_thread` decrements the counter after
`dot_thread_body()` returns, which covers every exit including the AXFR
hand-off. The timeout moves to 30 s after the first full query. New metrics:
`dns_tcp_rejected_total`, `dns_tcp_connections`. The check fails every case
against the pre-fix dnsd (cleartext on the DoT port, plain TCP dead once a
cert loads, silent client never dropped, 60 idle connections → 60 threads).

---

## Fix 1: the accepting listener decides the transport (CSA-PROTO-002)

### What it is

Three listeners hand connections to the same `dot_thread`: plain TCP on the DNS
port, DoT on IPv4 and DoT on IPv6. `dot_thread` wraps the socket in TLS whenever
a TLS context exists, without knowing which listener accepted it. Consequences:

- with a certificate loaded, plain TCP/53 expects a TLS ClientHello —
  reproduced: the same TCP query that worked before the cert was loaded got a
  connection reset afterwards. Every TC=1 retry fails;
- with no certificate, the DoT port answers in cleartext.

### Exact location in current file

| Need | Existing code (`dns_server.c` @ `b0a6b32`) |
|------|--------------------------------------------|
| Connection struct (no transport field) | `:11088-11091` — `typedef struct { int fd; struct sockaddr_in addr; } dot_conn_t;` |
| The defect | `:11097-11103` — `SSL_CTX *ctx = g_dot_ctx; if (ctx) { ssl = SSL_new(ctx); ... }` |
| Handshake | `:11104-11109` — `if (ssl && SSL_accept(ssl) <= 0)` |
| Read timeout (set after the handshake) | `:11112-11113` |
| Plain TCP accept → `dot_thread` | `:12163-12178`; the comment at `:12171` says "dot_thread handles ssl==NULL via plain send/recv" |
| DoT IPv4 accept | `:12186-12200` |
| DoT IPv6 accept | `:12208-12226` |
| Transfer hand-off that copies fd/ssl/addr | `:11153-11157` — `axfr_conn_t` fill |
| Listen backlogs | `:11825` (TCP/53, 32), `:11917` (DoT, 32) |

### What to build

1. Add `int is_tls;` to `dot_conn_t`.
2. Set it at the three accept sites: `0` at `:12163` (plain TCP), `1` at
   `:12186` and `:12208` (DoT).
3. In `dot_thread`:

   ```
   if c.is_tls:
       lock g_tls_mutex; ctx = g_dot_ctx; ssl = ctx ? SSL_new(ctx) : NULL; unlock
       if !ssl:  close(c.fd); return        # DoT port with no certificate: refuse
       SSL_set_fd; handshake as today
   else:
       ssl = NULL                            # never TLS on the plain listener
   ```

4. Fix the comment at `:12171` to say the listener sets `is_tls = 0`.
5. Update the startup banner (`:11939` block) so the DoT line shows
   `----` when no certificate is loaded and the TCP line is always "plain".

### Guardrail (do NOT)

- **Do NOT** sniff the first byte to guess TLS vs plain. The listener knows.
- **Do NOT** serve cleartext on the DoT port when no certificate is loaded;
  close the connection. Before relying on this, check whether any `make`
  target reaches the DoT port without TLS and move it to the plain TCP port:

  ```sh
  grep -n "dot_port\|8853\|+tls\|-p \$\$DOT\|DOT_PORT" Makefile | head -40
  ```

- **Do NOT** change the framing loop, the AXFR/IXFR hand-off, or the mTLS
  logic in `tls_reload` (`:2754`).
- **Do NOT** add a plain-TCP IPv6 listener in this change (tracked separately
  with the IPv6 transport work).
- **Do NOT** hold `g_tls_mutex` across `SSL_accept`.

### Acceptance criteria

- No certificate: TCP query on the DNS port answers; a TCP connection to the
  DoT port is closed without a DNS answer.
- Certificate loaded: TCP query on the DNS port still answers in cleartext;
  DoT on the DoT port answers over TLS; a cleartext query to the DoT port
  fails.
- A UDP query that returns TC=1 can be retried over TCP on the same port and
  gets the full answer, with a certificate loaded.
- AXFR over plain TCP and over DoT (XoT) both still work:
  `check-axfr`, `check-ixfr`, `check-xot`, `check-dot-mtls`, `check-frag` pass.

### Test

New target `check-tcp-plain` (Valkey + dig + openssl):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /tmp/tp.key -out /tmp/tp.crt -subj /CN=ns1.example.local -days 2 2>/dev/null
SAVE_C=$($VC get config:tls_cert_pem); SAVE_K=$($VC get config:tls_key_pem)
$VC del config:tls_cert_pem config:tls_key_pem
LISTEN_PORT=$TPORT ./dns_server_debug & DNS=$!; sleep 2

# 1. no cert: plain TCP works
test "$(dig +tcp +short @127.0.0.1 -p $TPORT example.local A +time=2 +tries=1)" = "192.168.1.10"

# 2. load a cert live; plain TCP must keep working (this is the regression)
$VC -x set config:tls_cert_pem < /tmp/tp.crt; $VC -x set config:tls_key_pem < /tmp/tp.key; sleep 2
test "$(dig +tcp +short @127.0.0.1 -p $TPORT example.local A +time=2 +tries=1)" = "192.168.1.10"

# 3. TC retry path: 512-byte buffer + DO forces truncation, dig retries over TCP
dig +dnssec +bufsize=512 @127.0.0.1 -p $TPORT example.local DNSKEY +time=2 +tries=1 | grep -q 'RRSIG'

# 4. DoT still answers over TLS (dig +tls needs BIND 9.18+; skip with a message if absent)
DOT=$($VC get config:dot_port); DOT=${DOT:-853}
dig +tls +short @127.0.0.1 -p $DOT example.local A +time=2 +tries=1 | grep -q '192.168.1.10'

kill $DNS
# restore SAVE_C / SAVE_K as the other targets do
```

---

## Fix 2 (complementary): bound the stream listeners (CSA-DOS-002)

- **Anchors:** accept sites `:12163-12226` (one detached thread per
  connection, `pthread_create` return value ignored at `:12176`, `:12198`,
  `:12224` — on failure `c` and the fd leak); `SO_RCVTIMEO` set at `:11113`,
  after `SSL_accept` at `:11104`.
- **Observed:** 1,500 idle TCP connections produced 1,400 threads and took RSS
  from 10 MB to 268 MB.
- **Intent:**
  1. set `SO_RCVTIMEO` **and** `SO_SNDTIMEO` on the accepted fd before the
     thread starts (so the TLS handshake is bounded too); 5 s for the
     handshake / first query, then the existing 30 s idle value;
  2. a global connection counter with `config:tcp_max_conns` (default 256)
     checked before `pthread_create`, modelled on `doqd.c:548`; over the cap,
     close the fd immediately and count it in a new `g_stat_tcp_rejected`;
  3. check `pthread_create`; on failure free `c`, close the fd, decrement the
     counter;
  4. decrement the counter on every exit path of `dot_thread`, including the
     AXFR hand-off (`axfr_thread` returns through it at `:11195-11196`).
- **Do NOT** apply the cap to the metrics listener. **Do NOT** make the idle
  timeout shorter than a secondary's transfer needs — a transfer in progress
  is not idle. **Do NOT** change resolverd or eppd here; they have the same
  pattern (`resolverd.c:4903-4948`, `eppd.c:4220`) and get their own entries.
- **Acceptance:** with `config:tcp_max_conns=64`, opening 500 idle
  connections leaves the thread count below 100 and queries from a new client
  are still answered within the idle timeout; a client that connects to the
  DoT port and sends nothing is disconnected within 5 s.
