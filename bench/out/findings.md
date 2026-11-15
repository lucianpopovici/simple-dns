# Performance baseline — findings & methodology notes

Date: 2026-06-17. Box: 32-core, Fedora 44. Server pinned core 2; loadgen cores 4-7.
Server build: `bench/out/dns_server_prof` (`-O2 -g -fno-omit-frame-pointer`, real
source set `dns_server.c dns_wire.c sandbox.c`, OpenSSL + libseccomp).

## Runbook (CLAUDE-performance.md) was stale vs the decomposed codebase — fixed

1. **Build command** assumed the pre-split monolith (`gcc dns_server.c -lssl
   -lcrypto`). dnsd now links `dns_wire.c` (libdnswire) + `sandbox.c`
   (libsandbox) and needs pkg-config OpenSSL/seccomp flags. Fixed §4.
2. **Server CLI** — dnsd takes **no arguments** (`--listen/--port` are fictional).
   Env-var driven; port via `config:dns_port` / default 5353. Fixed §5.
3. **Valkey schema** — real key is `zone:<zone>:<TYPE>:<name>` with value
   `TTL|data` (e.g. `zone:example.local:A:www… = 300|10.0.0.1`). The runbook's
   `SET zone:A:<name> <ip>` would never match → 100% NXDOMAIN baseline. Fixed §6/§7.

## Measurement hazards discovered (cost real time — documented for re-runs)

- **`pkill -f dns_server_prof` self-kills the Bash shell** (the command line
  contains the pattern) → exit 144. Use the bracket trick `'[d]ns_server_prof'`
  or kill by saved PID. Same hazard nuked a background job via `pkill -f resperf`.
- **Background server must survive across tool calls** — plain `&` works; do NOT
  use `setsid` (new-session creation is sandbox-flagged → exit 144).
- **resperf does not loop its query file** (dnsperf does). Use `-R` (reopen on
  EOF) or it dies "ran out of query data". Our query files are 10k–40k lines.
- **resperf "Maximum throughput: 0"** happens with `-L 5` when back-to-back runs
  give the single-threaded server no time to drain its backlog (65k queued) — the
  next run starts already >5% loss. Add a recovery `sleep` between runs.

## SERVER ISSUES that confound a naive baseline (and are real findings)

### F1 — Unconditional per-query `fflush` under a global mutex (likely #1 ceiling)
`dns_log()` (dns_server.c:957-967) writes stdout/stderr with `fprintf`+**`fflush`**
**unconditionally** — the level only gates syslog/remote (lines 970/974), never
the console. The per-query handler logs `dns_log(LOG_DEBUG,"[DNS ]…")`
(dns_server.c:6994/7025) for *every* UDP query. So every query = one serialized
`fflush` through `g_log_mutex`. At ~20k qps this is 20k flushes/s and is the prime
suspect for the ~20k ceiling — masking the loop/mutex/Valkey/signing attribution
the runbook actually targets. Flame graph (§9.2) to confirm.
- Operational symptom: a DEBUG run filled **16 GB** of stdout in minutes
  (~500k log lines/s when combined with the mDNS flood below).
- Mitigation for the baseline: stdout→/dev/null (keeps fprintf+mutex cost, drops
  disk I/O). A proper "after" run gating the per-query log behind a flag is the
  obvious first optimization to measure (runbook §13).

### F2 — dnsd binds the mDNS port (5353) on ALL interfaces → avahi collision
`g_dns_port` defaults to **5353**, the mDNS port, bound on `INADDR_ANY`/`in6addr_any`
(dns_server.c:6776/6829). The box runs `avahi-daemon` + `systemd-resolved` (own
5353 mDNS). dnsd received the box's own mDNS multicast as malformed `? ?` queries
from its own interface IPs (192.168.1.184/.178 + IPv6) — heavy benchmark
pollution + log flood.
- Fix (no sudo, no code change): `valkey-cli set config:dns_port 5399`
  (the `GI` macro reads `config:dns_port` at startup). Re-run on 5399 → clean.
- Deployment note: shipping default 5353 collides with system mDNS; production
  should bind a real DNS port and ideally not `INADDR_ANY` on a multicast port.

## Invalidated runs
- All numbers measured on 5353 with DEBUG stdout→file are INVALID (logging + mDNS
  flood dominated). The clean baseline is measured on 5399 with stdout→/dev/null.

## DNSSEC row
- `dnssec:example.local:{zsk,ksk}` keys exist, so signing should work. An early
  `+dnssec` returned 0 RRSIGs — re-verify on 5399 before recording the row;
  if still 0, investigate (DO-bit handling) or mark N/A.

---

# RESULTS (clean baseline — port 5399, stdout→/dev/null, server pinned core 2)

Profiling build `-O2 -g -fno-omit-frame-pointer`. Loadgen `dnsperf`/`resperf`
on cores 4-7. NOTE: governor/turbo NOT pinned (no cpupower) — numbers are for
*attribution* (relative gaps), not absolute records. perf used the `cpu-clock`
software event (works at perf_event_paranoid=2; no sudo needed).

## Max sustainable QPS — resperf -m100000 -r30 -L5, median of 3 runs
| Scenario              | Median knee qps | Notes                                  |
|-----------------------|-----------------|----------------------------------------|
| cache-hit (hot)       | 21,546          | ≈ cache-miss → no in-proc cache benefit |
| cache-miss (spread)   | 21,834          | per-query Valkey GET, yet == cache-hit  |
| nxdomain              | 17,292          | negative path is the slowest            |
| mixed                 | 19,096          |                                         |
| dnssec-on             | N/A             | signing DISABLED in this Valkey config (0 RRSIGs) |
| static-only           | N/A             | no DB-bypass build mode exists          |
| cookies on/off        | not isolated    | dnsperf has no cookie knob; server answers w/o |

## Latency @ 15,000 qps (dnsperf -T4 -c16, 0% loss). avg (min..max)
| Scenario | avg     | max     |
|----------|---------|---------|
| hot      | 120 µs  | 3.6 ms  |
| spread   | 115 µs  | 5.7 ms  |
| nxdomain | 352 µs  | 14.8 ms |
| mixed    | 251 µs  | 31 ms   |
At saturation (~22.6k qps, offered 40k): avg 4.37 ms, max 12 ms.

> p50/p90/p99/p99.9 are NOT reported: dnsperf/resperf summaries give only
> avg/min/max/stddev, not percentiles. A histogram-capable generator
> (flamethrower, dnsblast, or a custom harness) is needed for true tail
> percentiles. Reported avg+max are honest substitutes.

## Saturation / core utilization (mpstat during offered 50k, -T4)
- Server core 2: ~60% busy (usr ~10%, sys ~32%, softirq ~18%), **~40% idle**.
- Loadgen cores 4-7: ~90% idle → loadgen is NOT the limit.
- **No core pegged at 100%.** The throughput ceiling (~22-23k) is hit with the
  server core 40% idle → the server is **serialization/blocking-bound, not
  CPU-bound.**

## Flame graph (bench/out/flame_spread.svg) — on-CPU, cache-miss under load
- Only **~3% of one core** is userspace on-CPU (430 samples / 15s @ 999Hz vs
  ~15000 if busy). Most core-2 time is kernel (per-packet recvfrom/sendto
  softirq + syscall) and blocked I/O wait — neither attributable to userspace
  stacks at paranoid=2.
- Top userspace leaves (proportional): `__memset_avx512` (#1 — large per-query
  buffer zero), syscall wrappers, `resp_fill`/`resp_readline`/`resp_parse` (RESP
  Valkey client), `strncpy`/`memchr`/`strlower`, `__printf_buffer` (per-query log).

## Supporting measurements
- Valkey RTT floor: intrinsic 34.9 ns; live PING ~0.25 ms avg (idle).
- UDP drops: **none** (snmp InErrors=0, RcvbufErrors=0; InDatagrams≈OutDatagrams).

# ATTRIBUTION (the runbook's actual question, answered)
The ceiling is NOT any single suspect in isolation:
1. **Single-threaded select() loop, one packet in flight** — dominant. The
   thread blocks on each synchronous, `g_vk_mutex`-serialized Valkey GET; while
   blocked it serves no other query. QPS ≈ 1/(serial per-query round-trip).
   Evidence: cache-hit==cache-miss, core 40% idle at the cap, latency explodes
   55µs→4.4ms past ~20k.
2. **Per-packet syscall overhead** — recvfrom+sendto per query, no
   recvmmsg/sendmmsg batching; most core time is kernel-side.
3. **Per-query unconditional fflush** (F1) — adds serialized cost on the hot path
   (`__printf_buffer` visible even in the tiny userspace slice).
NOT bottlenecks here: Valkey RTT (cache-hit==miss), DNSSEC signing (disabled),
userspace CPU (~3%).

# RECOMMENDED LEVERS (in impact order — to measure in "after" runs per §13)
1. **SO_REUSEPORT N-worker model** (or a thread pool draining one socket) — break
   the one-in-flight serialization. Biggest expected win.
2. **Per-worker Valkey connection** — remove `g_vk_mutex` serialization (and an
   in-process record cache to drop the GET entirely; cache-miss==hit shows the
   GET is on every query).
3. **recvmmsg/sendmmsg batching** — amortize per-packet syscall cost.
4. **Gate the per-query DEBUG fflush** (F1) behind a level check — cheap, removes
   hot-path serialized I/O.

---

# F1 FIX & RE-MEASUREMENT (2026-06-18) — gate the per-query fflush

**Change** (dns_server.c, uncommitted): added `config:console_level` / env
`CONSOLE_LEVEL` (default `info`) and a hot-path short-circuit at the top of
`dns_log()` — if a message is below every enabled sink's level it does no
vsnprintf, takes no `g_log_mutex`, and does no I/O. The per-query `[DNS ]` log is
DEBUG, so by default it is now free. Verified: clean `make debug`, `make check`
passes, per-query DEBUG suppressed by default and restored with
`CONSOLE_LEVEL=debug`; live-reloads via the existing config:* keyspace watch.
Binary: `bench/out/dns_server_prof_gated`.

**Method**: identical matrix, only the binary changed. BOTH baseline and gated
runs used stdout→/dev/null, so the delta isolates the per-query
vsnprintf+mutex+fprintf+flush(/dev/null) cost — NOT disk I/O.

## Knee (resperf -L5, median of 3) — baseline vs gated
| Scenario   | Baseline qps | Gated qps | Δ      |
|------------|--------------|-----------|--------|
| cache-hit  | 21,546       | 22,092    | +2.5%  |
| cache-miss | 21,834       | 24,090    | +10.3% |
| nxdomain   | 17,292       | 17,282    | ~0%    |
| mixed      | 19,096       | 19,076    | ~0%    |

(Per-run variance is ~±3k on spread, so the cache-miss +10% is real but partly
noise; positive-path gain is single-digit-to-~10%, negative/mixed within noise.)

## On-CPU profile (perf cpu-clock, ~23k under load): 430→411 samples, ~unchanged
- Logging `fprintf`/`fflush` no longer a leaf. Remaining `__printf_buffer` is
  now `snprintf` (Valkey key build in `zone_key()` dns_server.c:438), not logging.
- Top leaves still: `__memset_avx512` (#1), `__strncpy_evex`, syscall wrappers,
  `resp_*` (RESP client). Server stays serialization/syscall/kernel-bound.
- Flame graphs: baseline `flame_spread.svg`, gated `flame_gated.svg`.

## Conclusion
Gating the per-query log is a correct, cheap fix and a real but **modest** win
(~2-10% on the positive path) — it does NOT move the ~22k ceiling. This confirms
the attribution: F1 was a contributor, but the dominant ceiling is the
single-threaded, one-packet-in-flight serial design + per-packet syscalls.
The high-leverage levers remain SO_REUSEPORT workers, per-worker Valkey
connection / in-proc cache, and recvmmsg/sendmmsg batching.

---

# SO_REUSEPORT WORKER PROTOTYPE (2026-06-18) — the throughput lever

**Change** (dns_server.c, committed on branch perf-reuseport-workers, stacked on
the F1 console-gating commit): opt-in `config:udp_workers` / env `UDP_WORKERS`
(default 1 = unchanged select loop). When >1: N IPv4 UDP sockets bound with
SO_REUSEPORT pre-sandbox, N worker threads spawned post-sandbox, each with its
own Valkey connection (`__thread t_vk_conn` → lock-free `vk_get`). vk_get
refactored into a connection-parameterized `vk_get_conn()`. IPv6/TCP/DoT/metrics
stay on the main loop. Binary: `bench/out/dns_server_workers`.

## Scaling (cache-miss/spread, dnsperf -T8 -c32, server pinned to W cores)
| Workers | Achieved qps | avg lat | vs 1 |
|---------|--------------|---------|------|
| 1       | 26,812       | 3.7 ms  | 1.00x |
| 2       | 55,029       | 1.8 ms  | 2.05x |
| 4       | 62,652       | 1.6 ms  | 2.34x |
| 8       | 70,650       | 1.4 ms  | 2.63x |

1->2 is linear (2.05x): the single-thread serialization is gone. The curve then
approaches a ~69-70k plateau.

## Where the new ceiling is (workers=8, pushed with -c128 and 2 parallel gens)
- Throughput holds ~69k with 0% loss regardless of client concurrency or number
  of generators → not a single-generator artifact.
- **dnsd uses only ~1.1 of its 8 cores** at 69k → dnsd is NOT the bottleneck; the
  worker design has large headroom.
- **Valkey: ~345k ops/s** at 69k qps ≈ **~5 Valkey round-trips per query**
  (zone select + record + SOA/DNSSEC config + the stale-SET-per-GET). 345k/5 ≈
  69k — the shared single-threaded Valkey, hit ~5x/query, is the new ceiling.
- Caveat: dnsperf stayed closed-loop (0% loss throughout), so the exact open-loop
  max isn't pinned — but dnsd's idle cores rule it out as the limiter either way.

## Conclusion & next levers
The worker model is the right lever: it removes the dnsd single-thread
serialization (2x at 2 workers) and pushes the bottleneck onto shared Valkey.
To go past ~70k, cut Valkey work per query (in impact order):
1. **In-process record cache** — the baseline cache-hit==cache-miss proved there
   is none; caching hot records eliminates most of the ~5 RTTs/query.
2. **MGET / pipeline** the per-query lookups into one round-trip.
3. **Drop the stale-SET-on-every-GET** (RFC 8767 shadow) or throttle it — it
   doubles write load on the hot path for marginal benefit.
4. Scale Valkey (cluster / per-worker shards) if still needed.

---

# IN-PROCESS RECORD CACHE (2026-06-18) — past the Valkey ceiling

**Change** (dns_server.c, committed on branch perf-record-cache, stacked on the
worker prototype): shared, sharded (64 locks), direct-mapped cache at the
`vk_get()` seam for the hot per-query reads (`zone:`/`ddns:` keys, hits AND
misses). Opt-in: `config:record_cache_ttl` / env `RECORD_CACHE_TTL` (seconds,
default 0 = disabled, vk_get unchanged) and `config:record_cache_size` /
`RECORD_CACHE_SIZE` (entries, default 16384). Binary: `bench/out/dns_server_cache`.

Correctness: entries expire after the TTL AND the keyspace subscriber calls
`rcache_invalidate()` on every `zone:`/`ddns:` write (it subscribes to those
prefixes only while the cache is active). `config:`/`cert:`/`dnssec:` stay strictly
live (not cached). Verified live: a record edit (10.0.0.1->9.9.9.9) and a newly
added name both took effect on the next query (positive + negative invalidation),
no stale answers. make check / check-cds / check-catalog / check-dnssec all pass
(cache off by default).

## Results (cache-miss/spread, 8 workers, dnsperf -T8)
| Config | qps | avg lat | Valkey ops/query |
|--------|-----|---------|------------------|
| no cache (workers=8) | 70,650 | 1.4 ms | ~5 (~345k ops/s) |
| cache size 16384     | 95,060 | 1.05 ms | thrash: 16384 slots vs 10k names -> ~50% collide |
| cache size 65536     | **155,170** | **0.63 ms** | ~2 (~300k ops/s) |

- size 16384 was collision-bound (direct-mapped, 10k names in 16384 slots ->
  ~half thrash); size 65536 (load ~0.15) gives a high hit rate.
- Throughput **2.2x** over no-cache (and ~5.7x over the ~27k single-thread
  baseline); latency more than halved.
- Valkey ops/query dropped ~5 -> ~2: the cache eliminated the record GET(+stale
  SET); the remaining ~2 ops/query are **uncached `config:zone:*` per-query reads**
  (NSEC3 params / SOA serial) — the next lever.

## Caveats / next levers
- Direct-mapped → size the cache well above the working set (rule of thumb: >=4x
  hot names) or collisions cap the hit rate. A set-associative or LRU variant
  would tolerate smaller tables.
- NXDOMAIN flood would churn negative entries (bounded memory, no growth) — a
  pollution concern under attack; acceptable for now.
- Next: cache `config:zone:*` per-query reads (rarely change; already covered by
  the config:* keyspace watch) to remove the last ~2 Valkey ops/query; consider
  dropping/throttling the stale-SET-per-GET.

## Cumulative arc (single core/thread baseline -> here)
~22-27k (1 thread, Valkey-serialized) -> 70k (8 SO_REUSEPORT workers, Valkey-
bound at ~5 ops/q) -> 155k (workers + record cache, ~2 ops/q). The bottleneck
walked from the dnsd loop -> the shared Valkey record reads -> (now) the uncached
per-query config reads.

---

# NEXT LEVER: set-associative cache (2026-06-19) — corrects the prior analysis

**Correction:** the earlier note "remaining ~2 ops/query are uncached config:zone:*
reads" was WRONG. `valkey-cli MONITOR` proved a warm/cached query does **0 Valkey
ops**; an uncached query does **3**: `GET ddns:<name>` (dynamic check, misses) +
`GET zone:<name>` + `SET stale:zone:<name>` (the RFC 8767 shadow write). There are
no per-query config reads. The residual Valkey traffic at the "warm" ceiling was
**cache misses**, not config.

**Root cause of the misses:** a query caches BOTH the ddns: negative and the
zone: positive → ~20k entries for 10k names. In a direct-mapped 65536-slot table
(load ~0.3) ~26% of entries collided and evicted each other → ~34% miss rate even
warm (MONITOR: 879 zone GET + 879 stale SET + 764 ddns GET per ~2.5k queries).

**Fix:** 4-way set-associative table (hash→bucket, 4 ways/bucket, approx-LRU
eviction within the set). Colliding keys coexist.

| Cache (8 workers, size 65536) | qps | avg lat | Valkey ops/s | miss |
|---|---|---|---|---|
| none | 70,650 | 1.4 ms | ~345k | — |
| direct-mapped | 158,670 | 588 µs | ~305k | ~34% |
| **4-way set-associative** | **294,580** | **31 µs** | **~22k** | ~2.4% |

~1.9x throughput over direct-mapped, ~19x lower latency, ~14x less Valkey load.
At 294k qps Valkey is near-idle (~22k ops/s) and avg latency is 31 µs (essentially
in-memory serving) → the bottleneck is no longer Valkey; it's now dnsd CPU across
the 8 workers and/or the load generator (0% loss = still closed-loop).

## Cumulative arc
~22-27k (1 thread, Valkey-serialized) → 70k (8 SO_REUSEPORT workers, Valkey-bound
~5 ops/q) → 158k (workers + direct-mapped cache, collision-bound) → **294k
(workers + 4-way set-associative cache, ~2.4% miss)** — ~11x the single-thread
baseline, latency 1.4ms → 31µs.

## Remaining levers (smaller now)
- stale-SET-per-GET still fires on every miss (~1/3 of miss-path ops, and a
  WRITE) — throttle it (refresh the shadow at most every N s/key) to shrink cold-
  cache and miss-path Valkey load further.
- recvmmsg/sendmmsg batching to cut per-packet syscalls (now that Valkey is no
  longer the limiter, syscall/CPU is the next ceiling).
- Confirm the true open-loop ceiling with a stronger generator (multiple dnsperf
  hosts) — the 294k figure is closed-loop and likely understates dnsd.

---

# LEVER: throttle the stale-shadow write (2026-06-19)

`vk_get_conn()` rewrote `stale:<key>` (7-day TTL) on EVERY successful GET — a
Valkey write per read. Throttled to ~1/N via `config:stale_refresh_sample` /
`STALE_REFRESH_SAMPLE` (1 = legacy every-GET, default 16, 0 = off); per-thread
counter. Read-side serve-stale (GET stale:<key> on Valkey-unreachable) unchanged.

MONITOR (no cache, ~4k queries): sample=1 → 3994 stale SETs; sample=16 → 250
(16x fewer). Uncached hot path Valkey ops/query: 3 (2 GET + 1 SET) → ~2.06; write
load 16x lower. Tradeoff: shadow may lag a changed record by up to ~N reads of
that key — acceptable for best-effort serve-stale (set sample=1 to restore).

Note: with the record cache warm this is a minor add-on (writes already only fire
on the ~2.4% misses); its main value is the default no-cache path and cutting
Valkey *write* amplification generally.

---

# LEVER: recvmmsg/sendmmsg batching (2026-06-19) — modest/situational

Opt-in batched worker loop: recvmmsg drains up to N datagrams/syscall
(MSG_WAITFORONE → no added latency), one sendmmsg replies. config:udp_rx_batch /
UDP_RX_BATCH (default 1 = per-packet). sandbox.c: moved recvmmsg/sendmmsg into the
base seccomp allowlist (dnsd hit EPERM otherwise — they were resolverd-only).

Two regimes measured (8 workers + cache unless noted):
- **Server keeps up** (the normal case with the cache): two dnsperf instances
  reach ~790k qps and batch=1/16/32 are identical (792k/788k/777k — batching
  slightly *hurts*). The limiter is the LOAD GENERATOR, not server syscalls — the
  earlier "294k" was a single-dnsperf artifact; the true server ceiling is higher
  than we can drive here. recvmmsg returns 1-2 datagrams when the queue is empty,
  so there's nothing to amortize, only mmsghdr setup overhead.
- **Server CPU/syscall-bound** (2 workers/2 cores, overloaded ~91% CPU): batch=32
  ~+7% drain (482k → 516k qps). Batching engages only when the socket queue backs
  up.

Verdict: a real but small (~7%), situational win — off by default. Far below the
worker (2x) and cache (2.2x) levers. Kept as an option for syscall-bound
deployments (tiny fully-cached zones, many cores, slow per-syscall paths).

## Honest open item
The cache+workers ceiling was NOT pinned: at ~790k qps the bottleneck was the
load generators (2x dnsperf on 8 cores), not dnsd. Finding the true open-loop
server ceiling needs a stronger/distributed generator (e.g. multiple hosts) — the
single-box closed-loop setup tops out before the server does.

## Final arc (cache-miss/spread)
~22-27k (1 thread) -> 70k (8 workers) -> 158k (workers + direct-mapped cache) ->
294k (workers + 4-way cache, single dnsperf) -> ~790k (workers + cache, 2
dnsperf; server still not saturated). Latency 1.4ms -> 31us. Batching adds ~7%
only when CPU-bound. Per-query Valkey ops ~5 -> ~0 warm; stale-write load -16x.
