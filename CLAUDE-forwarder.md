# dns_server.c — forwarder for out-of-zone queries: work plan

Companion to `CLAUDE.md` (hidden-master/secondary gap analysis).  Same
conventions: line numbers refer to the current 5173-line source, build
command at the bottom of `CLAUDE.md` applies unchanged.

## Goal

Optionally forward queries this server is not authoritative for to one or
more upstream resolvers, so internal clients can use a single DNS endpoint.
**Off by default and gated by a client ACL** — a public-facing instance
with forwarding on would be an open resolver (abuse + amplification
target).  This feature is for internal deployments; the public secondaries
from `CLAUDE.md` must keep it disabled.

## Current state (verified in source)

| Fact | Where |
|------|-------|
| Out-of-zone queries are answered REFUSED with EDE "Not authoritative" | 2638–2665 |
| RFC 6303 locally-served zones are exempt and answered locally | 2651 (`is_local_zone`), 2670 ff. |
| `DNS_RD` is defined but never read; RA is never set in responses | 193 |
| **No upstream client code exists** for DNS (only NOTIFY's fire-and-forget UDP sender, 3465–3484) | — |
| UDP queries are processed **synchronously inside the main select loop** (5037 ff., IPv4 ~5066–5082, IPv6 5084–5106) — blocking upstream I/O there stalls every listener | — |
| TCP/DoT run one detached thread per connection (`dot_thread` 3509) — inline blocking is acceptable there | 5108–5144 |
| CIDR/IP allowlist parser already exists (`axfr_ip_allowed`, 3299) | — |
| Valkey `vk_set` supports per-key TTL (for the optional cache) | 1157 |

---

## Gap 1 — config and ACL

| Key | Meaning |
|-----|---------|
| `config:forward_enabled` | 0 (default) / 1 |
| `config:forwarders` | `ip[:port],...` — tried in order (default port 53) |
| `config:forward_allow` | IPs/CIDRs allowed to get recursion.  **Empty list = feature disabled** regardless of `forward_enabled` — fail closed |
| `config:forward_timeout_ms` | per-upstream wait (default 1500) |

Plumbing in `load_config` (~1364).  Generalise `axfr_ip_allowed` (3299)
into `ip_list_allowed(const char *list, const struct in_addr *ip)` and make
both the AXFR check and the forward ACL call it (~15 lines refactor).

---

## Gap 2 — the forward path

### Decision point

In `build_query_resp`, the existing out-of-zone branch (2638–2665) becomes:

```c
if(!in_zone && !is_local_zone(qname)){
    if(g_forward_enabled && (flags & DNS_RD)
       && ip_list_allowed(g_forward_allow, cip))
        return forward_query(query,qlen,resp,resp_len,is_tcp);
    /* existing REFUSED path unchanged */
```

No-RD queries and disallowed clients keep getting REFUSED exactly as today.

### `forward_query()` — the upstream exchange

1. Per query: fresh UDP socket (OS picks a random ephemeral source port —
   the standard anti-spoofing measure), send the **original query bytes
   unchanged** (EDNS/DO pass through untouched), `poll()` with
   `forward_timeout_ms`.
2. Validate the reply: source address == the forwarder queried, ID matches,
   question section matches (anti-spoof, RFC 5452).
3. On timeout/SERVFAIL: try the next forwarder in the list.
4. If the reply has TC set and the client context can carry more
   (`is_tcp`), redo the exchange over TCP to the same forwarder
   (length-prefixed framing as in `tcp_send_msg`, 3317).
5. Set RA (0x0080) in the flags of the relayed response; everything else is
   returned verbatim.  Authoritative answers from this server continue to
   **not** set RA.

### Threading — the critical constraint

`dns_process` is called synchronously from the select loop for UDP
(~5066–5106); a 1.5 s upstream wait there freezes DoT/HTTP accepts and all
other UDP clients.  Therefore:

- **UDP listeners:** decide *before* calling `dns_process`.  If the query
  would forward (cheap checks: RD bit + out-of-zone + ACL), hand the packet
  plus client sockaddr to a detached worker thread (same
  `pthread_create`+`PTHREAD_CREATE_DETACHED` pattern as the DoT accept path,
  5117–5119).  The worker runs `forward_query` and replies with `sendto` on
  the shared listener fd — concurrent `sendto` on a UDP socket is safe.
  Cap in-flight workers (counter + drop-with-SERVFAIL) so a dead upstream
  can't accumulate threads.
- **TCP / DoT / DoH:** already one thread per connection — `forward_query`
  runs inline; the dispatch inside `build_query_resp` is sufficient.

Estimated: ~150 lines (exchange + UDP worker + ACL refactor).

### Observability

`g_stat_forwarded` / `g_stat_forward_fail` next to the existing counters
(870–878), exported in the Prometheus block (4620 ff.); `qlog_write` proto
string `"fwd"`.

---

## Gap 3 — guard rails

- **Fail closed:** empty `forward_allow` disables forwarding (Gap 1).
- **Startup warning:** if `forward_enabled=1` log a LOUD notice listing the
  allowed ranges, so an open resolver can't happen silently.
- **Role interaction (`CLAUDE.md` Gap 2):** when `zone_role=secondary` the
  instance is by definition public-facing — log an extra warning if
  forwarding is enabled there; do not hard-refuse (an internal-only
  secondary is legitimate).
- **RRL:** the existing response-rate-limiting machinery
  (`config:rrl_enabled`, 1405–1408) must also cover forwarded responses —
  apply the same check in the UDP worker before `sendto`.

---

## Gap 4 — response cache (phase 2, optional)

Without a cache every client query costs one upstream round-trip.  If
needed:

- Key `fwd:<qtype>:<qname>` in Valkey, value = full wire response minus
  header ID, stored with `vk_set(..., ttl)` where ttl = the minimum TTL in
  the answer (1157 already supports per-key TTL — expiry is automatic).
- Lookup before forwarding; on hit, rewrite the ID, set RA, reply.
- Skip caching: TC responses, RCODE != NOERROR/NXDOMAIN, answers with TTL 0,
  and anything when the query carried EDNS options that affect the answer
  (client cookie is fine — it lives in OPT, strip/re-add).

Estimated ~60 lines.  Note this is a *forwarder* cache, not a validating
resolver: DO-bit queries pass through unsigned-verified; clients do their
own validation.

---

## Tests

```bash
# allowed client, RD set → forwarded answer, RA set
dig @server -b 10.0.0.5 example.com A          # expect NOERROR + flags ra
# RD clear → REFUSED (unchanged behaviour)
dig +norecurse @server example.com A           # expect REFUSED
# client outside forward_allow → REFUSED
dig @server -b 192.0.2.99 example.com A        # expect REFUSED
# first forwarder blackholed → answered by second within timeout
# TC over UDP → server retries upstream via TCP, client gets full answer
dig @server bigtxt.example.com TXT
# in-zone queries are still answered locally and never forwarded
dig @server corp.local SOA                     # flags aa, no ra
```

## Suggested order

1. Gap 1 (config + ACL refactor).
2. Gap 2 UDP-worker + exchange (the core).
3. Gap 3 guard rails (same commit as Gap 2 ideally).
4. Gap 4 cache only if upstream latency/load demands it.
