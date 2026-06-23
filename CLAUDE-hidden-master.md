# dns_server.c — hidden-master / public-secondary deployment: gap analysis

## Deployment goal

Run the same binary in two roles:

- **Hidden master** — not listed in NS, not reachable by clients.  Receives
  all provisioning (RFC 2136 UPDATE, management API, ACME DNS-01) and serves
  zone transfers to the public instances only, authenticated with
  **TSIG + mTLS**.
- **Public secondaries** — listed in NS, answer client queries (UDP/TCP/DoT/
  DoH).  Pull the zone from the hidden master via AXFR/IXFR over TLS,
  presenting a client certificate and signing requests with TSIG.  Accept no
  writes from anyone except the master.

Related work plans (independent of the two-role deployment):
`CLAUDE-loadbalance.md` (A/AAAA rotation + health checks),
`CLAUDE-forwarder.md` (out-of-zone forwarding to upstream resolvers) and
`CLAUDE-discovery.md` (automatic FQDN registration for VMs/containers).

## What already works (verified in source, 5173 lines)

| Feature | Where | Status |
|---------|-------|--------|
| AXFR over TCP and TLS (RFC 5936/7858) | `axfr_thread` 3323, `dot_thread` 3509 | transport done — DoT listener dispatches qtype 252/251 to `axfr_thread`, `tcp_send_msg` 3317 writes via `SSL_write` when TLS.  **Content incomplete:** only `static_zone[]` + DNSKEYs + SOA are sent (3415–3448); runtime `zone:*`/`ddns:*` records are missing — see `CLAUDE-discovery.md` Gap 1, fix before Gap 3 below |
| IXFR with journal + AXFR fallback (RFC 1995) | journal 3240–3293, IXFR path 3337 | done |
| TSIG multi-message MAC chaining (RFC 8945 §5.3.1) | `tsig_axfr_first/mid/last` 2061/2078/2090 | done (server side only) |
| TSIG verification of requests | `tsig_verify` 1876 | done (server side only) |
| mTLS client-cert verification machinery | `tls_ctx_from_pem` 1500 (`ca_pem`/`verify_client` args), CA loaded from `config:mtls_ca_pem` 1427 | done — but only wired to the mgmt/DoH context (`g_mgmt_ctx`, 1550), **not** to the DoT context |
| NOTIFY sender (RFC 1996) | `notify_send` 3465, targets from `config:notify_targets` | done (UDP, IPv4, unsigned, no retry) |
| NOTIFY receiver | `dns_process` 3496–3501 | **ACK-only — takes no action** |
| AXFR IP allowlist | `axfr_ip_allowed` 3299, `config:axfr_allow` | done |

Everything below is missing and is required for the two-role deployment.

---

> **Status (2026-06-22):** This file's "what works" table and line numbers are
> stale (pre multi-zone / forwarder); the gaps were re-verified open against
> current code. **Gap 1 is done** (branch `dot-mtls`): `config:dot_require_client_cert`
> (default 0); when 1 + `config:mtls_ca_pem` is set, `tls_reload` builds the DoT
> context with `SSL_VERIFY_PEER | FAIL_IF_NO_PEER_CERT`, so a transfer client
> without a CA-signed cert can't complete the handshake. Fail-safe: an empty CA
> never silently locks clients out (warns instead). Live-reloads on the config
> key. Guarded by `make check-dot-mtls`. **Discovery Gap 1 (AXFR completeness)
> shipped first (PR #10)** — a secondary now has real content to pull. Remaining
> HM gaps (2 role config, 3+4 transfer client + TSIG chain verify, 5 NOTIFY
> action, 6 refresh loop, 7 write-refusal, 8 key guard) are still open.
>
> **Gaps 2/7/8 done** (branch `zone-role-guards`): `config:zone_role`
> (`primary` default | `secondary`) → `g_zone_secondary`. On a secondary:
> `handle_update` returns NOTAUTH immediately (Gap 7); `dnssec_init_key`
> load-only — if a zone's keys are absent it logs loudly and serves unsigned
> rather than minting a divergent trust anchor (Gap 8). Guarded by
> `make check-role`. Scaffolding only for the transfer mesh — the `primary_host`
> / `xfr_*` config keys land with the transfer client (Gap 3). NOTE: the mgmt-API
> write 403 half of Gap 7 belongs to `apid` (not dnsd); `serial_bump` still runs
> for DNSSEC rollover/TLSA on a secondary (a secondary shouldn't run rollover —
> tie off with Gap 6).
>
> **Gap 3 done — AXFR client** (branch `xfr-client`): a secondary pulls every
> zone from `config:primary_host:port` at startup (`xfr_pull` in a detached
> thread). Plain TCP or TLS (`config:primary_tls` — server cert verified against
> `config:xfr_ca_pem`, optional client cert `config:xfr_client_{cert,key}_pem`).
> Parses the AXFR stream (A/AAAA/NS/CNAME/DNAME/MX/TXT/SRV → `xfr_rdata_to_store`)
> and replaces `zone:<zone>:*` only on a COMPLETE transfer (closing SOA), adopting
> the master's serial; a failed/partial pull leaves the store intact. Guarded by
> `make check-xfr-client` (stub master + no-clobber check). **Still open: Gap 4
> (request TSIG-sign + chained-response verify — until then run transfers over
> TLS), IXFR (currently always AXFR), and Gap 5/6 (NOTIFY-triggered + periodic
> refresh — currently a one-shot startup pull).**
>
> **Gap 6 + 5 done** (branch `xfr-refresh`): the startup pull became a
> maintenance loop (`xfr_refresh_thread`) that re-pulls each zone on its SOA
> refresh timer (retry timer after a failure). A NOTIFY from the configured
> master (source-verified, RFC 1996 §3.10) kicks an immediate re-pull via a
> condvar (Gap 5). A zone that cannot refresh within its SOA expire stops
> answering authoritatively (SERVFAIL, RFC 1035 §4.3.5); the expire clock seeds
> at boot and resets on every successful contact. Guarded by
> `make check-xfr-refresh`.
>
> **Gap 4 done — transfer TSIG** (branch `xfr-tsig`, RFC 8945): the client signs
> its AXFR request (`xfr_tsig_sign_query`, the request MAC seeds the chain) and
> verifies the master's chained response (`xfr_tsig_verify_msg`: per-message
> MAC = HMAC(prior ‖ msg-minus-TSIG ‖ vars); unsigned intermediates fold into
> the running MAC; >99 unsigned in a row rejected). When `config:tsig_secret_b64`
> is set the transfer MUST verify and the final message MUST be signed, else the
> pull is rejected and the store left intact — so transfers can now be
> authenticated over plain TCP, not only TLS. `xfr_tsig_vars_from_rr` mirrors the
> var layout in `tsig_verify`. Guarded by `make check-xfr-tsig` (valid applied;
> wrong-key + unsigned rejected; the stub also verifies the client's request
> signature). **All hidden-master gaps (1–8) are complete.** Follow-ups since
> shipped: **IXFR** (branch `ixfr-incremental`, refresh now does incremental
> diffs) and **master-side NOTIFY-sender hardening** (branch
> `notify-sender-hardening`: TSIG-signed NOTIFY + background retry until ACK —
> see Gap 5 sender section).

## Gap 1 — mTLS on the DoT/transfer listener (master side)

### What's wrong

`tls_reload` (line 1522) builds the DoT context **without** client-cert
verification:

```c
g_dot_ctx = tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem, NULL, 0);   /* 1526 */
```

while the mgmt context right below it (line 1550) gets the CA and
`verify_client=1`.  Any TLS client can therefore reach the AXFR/IXFR path;
the only gates are `axfr_allow` and TSIG.

### Fix overview

Add `config:dot_require_client_cert` (0/1, default 0).  When 1 and
`g_mtls_ca_pem` is non-empty, build the DoT context with verification:

```c
g_dot_ctx = tls_ctx_from_pem(g_tls_cert_pem, g_tls_key_pem,
                             g_dot_mtls ? g_mtls_ca_pem : NULL,
                             g_dot_mtls);
```

This must remain **off by default**: a public-facing instance uses the same
DoT port for regular client queries (RFC 7858 clients don't present certs).
On the hidden master it can be switched on globally because nothing but the
secondaries connects there.

Optional hardening: in `dot_thread` (3509), when a transfer is requested and
mTLS is on, log `SSL_get_peer_certificate` CN next to the `axfr_allow` check
(the mgmt path already does CN extraction at line 4854 — reuse that pattern).

Estimated change: ~20 lines + config plumbing in `load_config` (~1364).

### Test

```bash
# without client cert — handshake must fail when dot_require_client_cert=1
kdig +tls @master -p 8853 AXFR corp.local            # expect TLS failure
# with client cert + TSIG — transfer must succeed
kdig +tls +tls-keyfile=sec.key +tls-certfile=sec.crt \
     -y hmac-sha256:tsig-key:<b64> @master -p 8853 AXFR corp.local
```

---

## Gap 2 — role configuration

There is no concept of a role.  Add:

| Key | Meaning |
|-----|---------|
| `config:zone_role` | `primary` (default) or `secondary` |
| `config:primary_host` / `config:primary_port` | where a secondary pulls from |
| `config:primary_tls` | 0/1 — use TLS for the transfer connection |
| `config:xfr_client_cert_pem` / `config:xfr_client_key_pem` | client identity the secondary presents (mTLS) |
| `config:xfr_ca_pem` | CA to verify the master's server cert |
| `config:dot_require_client_cert` | Gap 1 |

Globals + `load_config` plumbing next to the existing TLS/TSIG keys
(1410–1427).  TSIG reuses the existing `config:tsig_secret_b64` /
`config:tsig_key_name` — same key on master and secondaries.

---

## Gap 3 — transfer client (secondary pulls AXFR/IXFR over TLS)

### What's wrong

There is **no client-side transfer code at all**.  The server can only be
the sending side of AXFR/IXFR.  A secondary needs `xfr_pull()`:

1. TCP connect to `primary_host:primary_port`; if `primary_tls`, wrap in
   OpenSSL with SNI, ALPN `dot`, server-cert verification against
   `xfr_ca_pem`, and the client cert/key from Gap 2.  The outbound-TLS
   pattern already exists in the rsyslog client (617–650) and the HTTPS/mTLS
   client (4080–4120) — reuse it.
2. Build an IXFR query (current serial in the authority-section SOA, as
   parsed today by the server at 3532–3539) or AXFR if no local zone yet.
3. TSIG-sign the **request** with `tsig_append` (1931).
4. Read length-prefixed messages in a loop; parse RRs; detect the closing
   SOA (second occurrence of the apex SOA for AXFR; RFC 1995 framing for
   IXFR, falling back to full-zone semantics when the response turns out to
   be an AXFR-style answer).
5. Apply to the local Valkey store using the existing schema
   (`zone:<TYPE>:<name>` with the value formats documented in the file
   header, lines 56–70), then set `config:zone_serial` to the master's
   serial — serials must never be generated locally on a secondary.
6. On any failure of IXFR semantics: retry as AXFR (RFC 1995 §4).

The RR-parsing side can reuse `name_from_wire`/`get16`/`get32`; rdata →
store-string conversion is the inverse of the per-type emit code in
`build_query_resp` (2645 ff.) and needs ~one case per supported type.

Estimated change: ~250–350 lines.  This is the largest single piece.

### Test

```bash
# secondary with empty store pulls full zone:
vk-cli set config:zone_role secondary; vk-cli set config:primary_host 10.0.0.1 ...
/tmp/dns_server &   # expect "[XFR] AXFR from 10.0.0.1 serial 0 -> N, M records"
dig @secondary corp.local SOA   # serial matches master
# incremental: update master, send NOTIFY, expect IXFR with only the diff
```

---

## Gap 4 — client-side TSIG verification of the chained response

`tsig_verify` (1876) verifies a single signed message.  A transfer response
is a **chain**: TSIG RR on first and last message only, intermediate
messages covered by the running HMAC (RFC 8945 §5.3.1).  The secondary must
verify what `tsig_axfr_first/mid/last` (2061/2078/2090) produce — same
hashing rules, verify side:

- seed the digest with the **request** MAC (length-prefixed),
- fold every intermediate message into the accumulator,
- on each received TSIG RR, compare the computed MAC and re-seed the chain
  with the received MAC,
- reject the whole transfer if the final message carries no TSIG RR, if any
  MAC mismatches, or if more than 99 unsigned messages arrive in a row
  (RFC 8945 §5.3.1 limit).

Mirror-image of the three existing functions, sharing `tsig_hmac_ctx_init`
(1998).  Estimated ~80 lines.

---

## Gap 5 — NOTIFY must trigger a refresh on the secondary

### What's wrong

The receiver at `dns_process` 3496–3501 acknowledges and does nothing:

```c
if(op==DNS_OPCODE_NOTIFY){
    /* Accept and acknowledge NOTIFY */
    ...
    dns_log(LOG_NOTICE,"[NOTIFY] Received NOTIFY\n");return 12;}
```

It does not check the source, does not verify TSIG, does not compare
serials, and does not schedule a transfer (RFC 1996 §3.11, §4.7).

### Fix overview

When `zone_role=secondary`:
1. verify TSIG if present (`tsig_verify` already handles this — just call it
   on the NOTIFY path; today only UPDATE goes through it);
2. accept only from `primary_host` (RFC 1996 §3.10);
3. signal the refresh thread (Gap 6) to do an immediate SOA check / IXFR
   instead of waiting for the refresh timer — `pthread_cond_signal` on a
   condition the refresh loop waits on with a timeout.

Sender side (`notify_send`) hardening for master→secondary auth — **done**
(branch `notify-sender-hardening`): NOTIFY is no longer fire-and-forget. A zone
change enqueues one job per (zone, target) onto a background `notify_thread`,
which TSIG-signs the NOTIFY (`notify_build_packet` → `xfr_tsig_sign_query`, so a
secondary configured with the key can authenticate the sender) and retransmits
with exponential backoff (2→16 s, `NOTIFY_MAX_TRIES` 5) until the secondary's
NOTIFY response is seen (`notify_got_ack`: matching id, QR set, opcode NOTIFY) or
the cap is hit. Retrying off-thread means a slow/down secondary never blocks the
request handler that triggered the change; re-arming an already-pending
(zone,target) collapses rapid changes into one in-flight NOTIFY (§3.5).
Guarded by `make check-notify` (TSIG verified, retransmit forced by a withheld
ACK, retransmission stops on ACK). Still IPv4-only targets (matches the receiver
and `notify_zone`'s parse).

---

## Gap 6 — SOA refresh / retry / expire loop (secondary maintenance)

No periodic zone-maintenance thread exists.  The SOA timer values are
already parsed and stored (`g_soa_refresh/retry/expire`, 434–436) but are
only ever *served*, never *obeyed*.

Add `xfr_refresh_thread` (started from `main` next to `pki_renewal_thread`,
4912) running only when `zone_role=secondary`:

```c
for(;;){
    timedwait(notify_cond, g_soa_refresh);
    uint32_t master_serial = soa_query(primary);       /* plain SOA query  */
    if(serial_gt(master_serial, g_soa_serial))         /* RFC 1982 compare */
        if(xfr_pull() != 0) sleep_retry(g_soa_retry);
    if(now - last_success > g_soa_expire) zone_expired = 1;  /* answer
        SERVFAIL, stop answering authoritatively, RFC 1035 §5 */
}
```

`serial_gt` must be RFC 1982 serial-space arithmetic, not plain `>`:
`(int32_t)(a - b) > 0`.  Estimated ~80 lines.

---

## Gap 7 — refuse writes on the secondary

`handle_update` (3119) applies RFC 2136 UPDATE directly to the store on any
instance, and the management API write endpoints (4724, 4732) bump the
serial and send NOTIFY.  On a secondary this would fork the zone from the
master and corrupt IXFR history.

When `zone_role=secondary`:
- `handle_update` returns RCODE NOTAUTH (9) immediately (optionally: forward
  to the primary per RFC 2136 §6 — out of scope for the first pass; document
  that ACME/DDNS clients must point at the hidden master);
- mgmt-API zone-write endpoints return 403;
- `serial_bump` (1495) must never run — the master's serial is authoritative.

Estimated ~25 lines.

---

## Gap 8 — DNSSEC key distribution (operational, plus a guard)

This server does **online signing**: every instance signs responses with
the ZSK/KSK held in its own Valkey (`dnssec:zsk`, `dnssec:zsk_ed25519`,
`dnssec:ksk`, `dnssec:ksk_ed25519` — generated on first boot if absent,
`dnssec_init_key` 1660).  A freshly booted secondary would therefore invent
**its own keys**, the DNSKEY/DS it serves would not match the DS published
at the parent, and validation would fail for clients hitting that secondary.

AXFR carries the DNSKEY RRs (3435–3447) but — correctly — not private keys,
so transfers cannot fix this.

Two pieces:
1. **Operational (document in README / provisioning script):** replicate the
   four `dnssec:*` PEM values from the master's Valkey into each secondary's
   Valkey *before first start*.
2. **Code guard:** on `zone_role=secondary`, `dnssec_init` (1690) must
   **load-only, never generate** — if the keys are absent, log LOUDLY and
   serve unsigned rather than minting a divergent trust anchor.
   ~10 lines in `dnssec_init_key`.

The same consideration applies to `config:tls_cert_pem`/`key` (each instance
can have its own cert — secondaries verify the master via `xfr_ca_pem`, the
master verifies secondaries via `config:mtls_ca_pem`; one private CA for the
transfer mesh is the simplest setup).

---

## Suggested implementation order

1. Gap 1 (mTLS on DoT) — small, independently testable against `kdig`.
2. Gap 2 (role config) — scaffolding for everything else.
3. Gap 3 + Gap 4 (transfer client + chain verification) — the core; test
   secondary-pull against this same server as master.
4. Gap 6 then Gap 5 (refresh loop, then NOTIFY hooks into it).
5. Gap 7 + Gap 8 guards.

End-to-end test: master + two secondaries on one host (distinct ports +
Valkey DBs); provision a record on the master via RFC 2136; verify both
secondaries serve it within one NOTIFY round-trip, with `dig +dnssec`
validating against the shared keys, and that a third TLS client without a
cert cannot even complete a handshake to the master's DoT port.

---

## Build command

```bash
gcc -O2 -Wall \
    -Wno-missing-field-initializers -Wno-misleading-indentation \
    -Wno-unused-result -Wno-unused-function -Wno-format-truncation \
    -Wno-stringop-truncation -Wno-unused-variable -Wno-implicit-fallthrough \
    -Wno-deprecated-declarations \
    -I/tmp/ossl-inc \
    -o /tmp/dns_server dns_server.c \
    -L/usr/local/lib -lssl -lcrypto -lpthread \
    -Wl,-rpath,/usr/local/lib
```

Current source is 5173 lines.  The build must produce zero errors; warnings
suppressed by the flags above are pre-existing and intentional.
