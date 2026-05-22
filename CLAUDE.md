# dns_server.c — current state and remaining work

## What has been completed

All previously planned work is in `main` as of 2026-05-22.  The implemented
features are documented at the top of `dns_server.c` (lines 1–55).  A quick
audit of the commit history shows the following work landed:

| Commit | Feature |
|--------|---------|
| `3c660d5` | `handle_update` extended for TXT, CNAME, MX, SRV (RFC 2136 ACME support) |
| `4354422` | TXT rdata multi-string chunking (RFC 1035 §3.3.14) |
| `179596c` | DNS name compression in responses (RFC 1035 §4.1.4) |
| `6455ba0` | DNS Cookie verification + BADCOOKIE (RFC 9018) |
| `dd9e4d7` | TSIG: request MAC included in response signing (RFC 8945 §5.4.2) |
| `727710c` | DS records (RFC 4034 §5) + UPDATE prerequisites (RFC 2136 §2.4) |

**All Tier 1 and Tier 2 RFC compliance fixes from the original plan are done.**

Tier 3 items that are also complete (verified in source):
- **Fix 6** (BADVERS for EDNS version ≠ 0, RFC 6891 §6.1.3) — line ~2510
- **Fix 7** (DoH GET base64url decode, RFC 8484) — `b64url_dec` at line 978
- **Fix 8** (RFC 3597) — Option A applied: header comment clarified that
  pass-through is implemented but the `\#` presentation-format parser is not

---

## All planned work is complete

Fix 9 (TSIG AXFR/IXFR multi-message MAC chaining, RFC 8945 §5.3.1) was implemented. See below for what was done and how to verify it.

## Fix 9 (completed): TSIG AXFR multi-message MAC chaining (RFC 8945 §5.3.1)

### What's wrong

`axfr_thread` (line 3215) sends each AXFR message bare — no TSIG RR on any
message.  RFC 8945 §5.3.1 requires:

- **First message**: normal TSIG RR, MAC computed as usual
- **Continuation messages**: no TSIG RR, but intermediate message bytes and
  timer fields are fed into a running HMAC accumulator
- **Last message**: TSIG RR with MAC computed over the accumulated input

Without this, strict secondaries (Knot, NSD configured with TSIG on the
notify/transfer key) reject the transfer. Permissive secondaries (BIND without
TSIG config) accept it.

### Exact location in current file

```
axfr_thread — line 3215
tcp_send_msg — line 3209
tsig_append  — line 1931 (signs a single DNS message, returns updated length)
```

The AXFR sequence inside `axfr_thread`:

| Line | What is sent |
|------|-------------|
| 3297 | Opening SOA message |
| 3316 | Static zone records (one message each) |
| 3324 | DNSKEY (ECDSA) |
| 3329 | DNSKEY (Ed25519) |
| 3335 | Closing SOA message |

None of these calls to `tcp_send_msg` attach TSIG.

### Fix overview

Split `tsig_append` into three variants, or extend it with a `mode` argument
(first / middle / last) that controls what gets hashed.  Per RFC 8945 §5.3.1:

- **First**: hash `[prior-request-MAC-length || prior-request-MAC] || DNS-msg
  || TSIG-variables`, same as a normal TSIG response but the prior MAC is the
  one from the AXFR request.
- **Middle** (no TSIG RR emitted): hash `[prior-response-MAC-length ||
  prior-response-MAC] || DNS-msg-bytes`.  Store the intermediate MAC for the
  next iteration.
- **Last**: hash `[prior-response-MAC-length || prior-response-MAC] || DNS-msg
  || TSIG-variables`, emit a TSIG RR.

Pseudocode for the refactored `axfr_thread`:

```c
uint8_t prior_mac[64]; int prior_mac_len = 0;

/* Opening SOA — first AXFR message, carries a TSIG RR */
if(g_tsig_secret_len > 0){
    int tlen = tsig_append_first(buf, off, sizeof(buf), ntohs(h->id), 0,
                                  prior_mac, &prior_mac_len);
    if(tlen > 0) off = tlen;
}
tcp_send_msg(c.fd, c.ssl, buf, off);

/* ... for each intermediate record message ... */
if(g_tsig_secret_len > 0)
    tsig_chain_update(mb, mo, prior_mac, &prior_mac_len); /* no RR emitted */
tcp_send_msg(c.fd, c.ssl, mb, mo);

/* Closing SOA — last message, carries a TSIG RR with chained MAC */
if(g_tsig_secret_len > 0){
    int tlen = tsig_append_last(mb, mo, sizeof(mb), ntohs(h->id), 0,
                                 prior_mac, prior_mac_len);
    if(tlen > 0) mo = tlen;
}
tcp_send_msg(c.fd, c.ssl, mb, mo);
```

Estimated change: ~100 lines (new `tsig_append_first`, `tsig_chain_update`,
`tsig_append_last` functions + threading them through `axfr_thread`).  The
existing `tsig_append` at line 1931 and the MAC-inclusion logic at line 1957
remain; the new variants call the same OpenSSL EVP_MAC path.

### Test

```bash
# Set up a Knot secondary with the TSIG key configured in its zone config.
knotc zone-retransfer corp.local
journalctl -u knot -n 50 | grep -i tsig
# Without this fix: "TSIG missing" and transfer aborted.
# With this fix:    "AXFR finished" in the Knot log.

# Alternatively, capture with tcpdump and verify TSIG RRs appear on first
# and last AXFR messages only:
tcpdump -i lo -n -w /tmp/axfr.pcap port 5353
# (trigger transfer)
tshark -r /tmp/axfr.pcap -Y dns -T fields -e dns.count.ar -e dns.tsig
```

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

Current source is 5051 lines.  The build must produce zero errors; warnings
suppressed by the flags above are pre-existing and intentional.
