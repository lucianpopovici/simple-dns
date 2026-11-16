# PERF-001..007 + the `vkc_` repoint of dnsd / resolverd

The performance observations of the 2026-11-15 audit (`SECURITY_AUDIT.md`,
PERF-001..007) and the deferred repoint of `dns_server.c` and `resolverd.c`
onto the shared Valkey client in libdnswire (`vkc_*`). The roadmap folds
PERF-001/002 into the repoint: both live in the private RESP client copies the
repoint deletes.

Baseline (production `dns_server`, 4 UDP workers, `bench/run_perf.sh`,
dnsperf 10 s, 8 clients × 200 outstanding, this machine):

| Query set | qps |
|---|---|
| positive, one name (`hot.txt`) | 34.8k |
| positive, 10k names (`spread.txt`) | 28.4k |
| NXDOMAIN, random names | 17.4k |
| NXDOMAIN + DO | 14.3k |
| mixed | 26.1k |

| # | Item | Status |
|--:|------|--------|
| P1 | Shared client: no PING per command (PERF-001), lean reply reset (PERF-002), close on drop, retry-once helper, large commands, reconnect back-off | **Done** 2026-11-16 — `check-valkey-reconnect` |
| P2 | dnsd + resolverd use `vkc_*`; their private copies are deleted | **Done** 2026-11-16 |
| P3 | PERF-005 — TCP/DoT/other threads read through a small connection pool, not the one `vk` under `g_vk_mutex` | **Done** 2026-11-16 |
| P4 | PERF-003 — per-query reads issued as one pipelined round trip | **Done** 2026-11-16 |
| P5 | PERF-006 — forwarded queries run on a fixed worker pool | **Done** 2026-11-16 — `check-forwarder` |
| P6 | PERF-007 — serve-stale from an in-process store; fail fast while Valkey is down | **Done** 2026-11-16 — `check-dnsd-serve-stale` |
| P7 | PERF-004 — signed-negative caching | Not done — decision below |

## Results (2026-11-16)

Same harness and machine as the baseline; before = the commit this work
started from, run back to back with the new build. Response-code mixes are
identical between the two builds (`bench/run_perf.sh` prints dnsperf's
counts), so the gain is throughput with the same answers. Runs vary by about
±20 % here; two runs of each:

| Query set | Before (qps) | After (qps) |
|---|---|---|
| positive, one name | 34–40k | 161–197k |
| positive, 10k names | 28–41k | 132–191k |
| NXDOMAIN, random names | 14–18k | 51–64k |
| NXDOMAIN + DO | 11–14k | 16–26k |
| mixed | 25–26k | 91–95k |
| positive over TCP (`-m tcp`) | 16–17k | 228–237k |

P1+P2 alone took the positive set from ~35k to ~80k; the pipelined reads (P4)
and the TCP read pool (P3) account for the rest. NXDOMAIN + DO stays bound by
two online signatures per answer (P7).

### Implementation notes

- **Dead connections without a PING.** `vkc_ensure_to` does a zero-timeout
  `poll` on the idle socket: readable (EOF or stray bytes) or HUP/ERR means
  the server dropped it, so it reconnects before sending; `vkc_call_to`
  retries once after an I/O failure on a reused connection.
  `check-valkey-reconnect` (5 restarts × 4 queries) sees 0 failures. It also
  passes on the baseline, which paid a PING per command for the same result;
  it guards against regressing that without the PING.
- **Descriptor leaks.** Every Valkey failure path in dnsd and the sidecars set
  `fd = -1` without closing the socket. `vkc_drop` closes it;
  `check-valkey-reconnect` compares the open-descriptor count.
- **`stale:*` keys polluted Valkey.** One benchmark left ~9,300 7-day keys,
  enough to slow Valkey's active expiry so that `check-ent`'s 2-second DDNS
  lease was not expired in time. dnsd writes no `stale:*` keys any more;
  existing ones expire on their own (7-day TTL).
- **Serve-stale never worked before**: `check-dnsd-serve-stale` fails on the
  baseline (it read the shadow from the Valkey that was down).
- The prefetch table is per thread, cleared when `dns_process` returns, and
  covers A/AAAA queries only; other types read key by key as before.
- UDP workers keep their private connections; the pool (P3) serves every other
  thread's reads. Writes and transactions are unchanged (`vk` + `g_vk_mutex`).
- **Two latent races exposed by the speed-up**, fixed: the ZONEVERSION option
  read a zone's serial without `g_soa_mutex` (every writer holds it), and the
  RRL settings were rewritten on every config reload instead of only on change
  (missed by CONC-002's write-on-change pass). `check-reload-tsan` reported
  both once queries ran ~5× faster; 0 races in three runs after the fix.

## P1 — shared client (`dns_wire.c`)

- `vkc_ensure_to` connects only when there is no connection; it no longer
  sends `PING` first (PERF-001: 5 of a positive query's 10 round trips).
- `vkc_call_to(c, host, port, pass, retry, r, argc, ...)`: ensure, send,
  read; on an I/O failure close the connection and — only when `retry` is set
  and the connection was not freshly opened — reconnect and send once more.
  `retry` is for idempotent commands (GET, SET, DEL, EXISTS, TTL, SCAN…);
  INCR and transactions never retry (a lost reply may mean it ran).
- `vkc_parse` resets the scalar fields and `str[0]` instead of `memset`ing the
  64 KB reply (PERF-002).
- `vkc_drop` closes the socket; every former `c->fd = -1` leaked a
  descriptor.
- Commands longer than 8 KB are encoded into a heap buffer instead of failing.
- After a failed connect the connection waits 1 s before trying again
  (callers see an immediate failure meanwhile), and the connect itself times
  out after 1 s instead of 4 s.

## P2 — repoint

`dns_server.c` and `resolverd.c` drop `resp_conn_t`/`resp_reply_t`/
`resp_parse`/`resp_cmd`/`resp_txn_*`/`valkey_connect_to` in favour of the
`vkc_*` equivalents (identical semantics); their `vk_*` wrappers keep their
signatures and use `vkc_call_to`. dnsd's keyspace subscriber and
`resp_txn_commit_compact` keep their own logic on top of `vkc_*`.

## P3 — read pool (PERF-005)

Threads without a private connection (TCP/DoT, keyspace, rollover, NOTIFY…)
take one of `VK_POOL` (8) pooled connections for each read instead of
serialising on `vk`. Writes and transactions stay on `vk` + `g_vk_mutex`
(their ordering guarantees depend on it).

## P4 — pipelined reads (PERF-003)

Before resolving a query, dnsd issues the GETs the resolution may need (NS at
the name, ddns/zone/srp address, CNAME, wildcard) as one pipelined batch into
a per-thread, per-request table; `vk_get` consults it first. Values are
dropped at the end of the request, so nothing is served staler than one
request.

## P5 — forwarder pool (PERF-006)

A fixed set of forwarder threads takes queries from a bounded queue (the
current in-flight cap); a full queue answers SERVFAIL as today.

## P6 — serve-stale (PERF-007)

The `stale:` shadow keys lived in the Valkey whose outage they were meant to
cover, and every query then blocked on two 4 s connect attempts. Successful
zone/ddns reads are copied (sampled, as before) into a bounded in-process
stale table; when Valkey is unreachable, `vk_get` answers from it (RFC 8767).
No more `stale:*` writes to Valkey. With P1's back-off a query during an
outage fails over in microseconds instead of seconds.

## P7 — PERF-004 decision

RFC 9824 compact denial (CSA-DNSSEC-002) signs a record owned by the query
name itself, so every random name needs its own signature: there is no
covering range to cache, and random-name floods cannot be served from a
cache by construction. Repeated negative names can be cached per
(name, type, DO, CO); that is what `rcache` misses do today for the Valkey
reads, and the signing cost is the remainder. Not implemented; RRL bounds the
flood case. Recorded here so it is not re-opened as an oversight.
