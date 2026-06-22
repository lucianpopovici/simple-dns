# dns_server.c — server-side load balancing for A/AAAA records: work plan

Companion to `CLAUDE.md` (hidden-master/secondary gap analysis).  Same
conventions: line numbers refer to the current 5173-line source, build
command at the bottom of `CLAUDE.md` applies unchanged.

## Goal

Distribute load across multiple address records server-side instead of
relying on resolver behaviour:

1. **Rotation** — vary the order of A/AAAA RRsets per response
   (round-robin or random).
2. **Health checks (phase 2)** — stop emitting addresses whose backing
   service is down.

## Implementation status (2026-06-22)

Gap 1 (rotation) is **implemented** on branch `loadbalance-rotation`. The plan's
line numbers below are stale (pre multi-zone / pre forwarder) but its premise
held: A/AAAA multi-IP RRsets (`zone:<zone>:A|AAAA:<name>` = `ttl|ip|ip|...`)
were emitted in stored order with no rotation.

- **Gap 1 (rotation): done.** `config:lb_mode` = `none` (default) | `rr` | `random`.
  New `emit_addr_rrset()` collects the addresses, picks a start offset (atomic
  shared round-robin cursor for `rr`, `rand()` for `random`), and emits each via
  `emit_rr`. Replaced the two real multi-IP sites (`zone:A`, `zone:AAAA`); the
  wildcard-Valkey path is single-address in the current code, and `ddns:*` /
  `static_zone[]` are single-record — left as-is. Rotation is signature-neutral:
  `emit_rr` signs each address RR independently (verified: `+dnssec` returns all
  RRSIGs, alg 13 + 15, regardless of order). `config:lb_mode` is local serving
  policy, read via the live-reload config path; documented in the dns_server.c
  schema header and shown in the startup banner.
- **Gap 2 (health checks): deferred** — explicitly phase-2 / optional ("only if
  needed; rotation alone covers the common case"). Not built.

Test: `make check-lb` (wired into CI) provisions a 3-address A RRset and asserts
`rr` rotates the emission order (≥2 distinct first-addresses) while keeping all 3
addresses and intact RRSIGs, and that `none` is stable. Depends on the live
DNSSEC fix in PR #8 for the RRSIG assertion.

> Note: this work surfaced — via the RRSIG assertion — that live DNSSEC was
> entirely broken (DO-bit misparse + Ed25519 signing crash); fixed separately in
> PR #8 and landed before this.

## Current state (verified in source)

| Fact | Where |
|------|-------|
| Multiple addresses per name already work: `zone:A:<name>` value is `ttl\|ip1\|ip2\|...`, every IP emitted | 2790–2797 (`strtok` loop) |
| Same for AAAA | 2805 ff. |
| Two more emission sites repeat the pattern: CNAME-chase hops and wildcard match | 2925/2940, 3005/3014 |
| Single-value `ddns:A:<name>` records (TTL from key expiry) | 2786–2789 |
| Compile-time `static_zone[]` array (one RR per entry; multiple entries with the same name = multiple RRs) | 887–896, emitted at 2767 ff. and 2979 ff. (wildcard) |
| **No rotation anywhere** — emission order is exactly the stored order; the only `rand()` calls are NOTIFY message IDs (3477) and retry jitter (4068) | — |
| DNSSEC: `emit_rr` (2551) signs **per RR** via `make_rrsig` (1605) — one RRSIG immediately after each address record | 2551–2569 |

The per-RR signing model means **rotation cannot invalidate signatures**:
each RR carries its own RRSIG and there is no canonical-RRset-order
constraint on the emission side.  (Validators that recompute a digest over
the *whole* RRset are a pre-existing concern of the per-RR model, unchanged
by this feature.)

---

## Gap 1 — rotation

### Config

| Key | Meaning |
|-----|---------|
| `config:lb_mode` | `none` (default) \| `rr` (round-robin) \| `random` |

Plumbing in `load_config` (~1364), reload via existing SIGHUP path (5052).

### Fix overview

The four Valkey emission sites all do *parse-one-IP → emit → next*.
Refactor into one helper that first collects, then emits:

```c
/* Gather all addresses from a ttl|ip|ip|... value, apply rotation,
 * emit each RR (+per-RR RRSIG via emit_rr). */
static int emit_addr_rrset(uint8_t *resp,int off,int resp_len,
                           const char *name,uint16_t type,   /* A or AAAA */
                           char *val,                        /* mutable copy */
                           int dnssec_ok,int *answers){
    char *ips[LB_MAX_ADDRS];int n=0;          /* 1. collect */
    uint32_t ttl=...;                          /*    (ttl| prefix as today) */
    for(char *ip=strtok(...);ip&&n<LB_MAX_ADDRS;ip=strtok(NULL,"|"))ips[n++]=ip;
    int start=0;                               /* 2. pick start offset */
    if(g_lb_mode==LB_RR)     start=atomic_fetch_add(&g_lb_counter,1)%n;
    else if(g_lb_mode==LB_RANDOM) start=rand()%n;
    for(int i=0;i<n;i++){                      /* 3. emit rotated */
        const char *ip=ips[(start+i)%n];
        ...inet_pton + emit_rr as today...}
    return off;}
```

- Counter: one global `_Atomic uint32_t g_lb_counter` is enough — a shared
  counter across names still yields uniform per-name distribution.
- Call sites to convert: 2790 (A), 2805 (AAAA), 2925/2940 (CNAME chase),
  3005/3014 (wildcard).  `ddns:A` (2786) and `static_zone[]` are
  single-record paths — leave them.
- `LB_MAX_ADDRS` 32 is plenty (value buffers are 128–256 bytes anyway).

Estimated ~60 lines net.

### Operational note (put in README)

Rotation is only as effective as the TTL: resolvers cache one ordering for
the record's TTL.  Balanced names should carry a short TTL (30–60 s).  TTL
comes from the stored `ttl|` prefix — no code change needed.

### Test

```bash
for i in $(seq 6); do dig +short @localhost lb.corp.local A; echo --; done
# expect the address list to start at a different IP each query (rr mode)
dig +dnssec @localhost lb.corp.local A   # RRSIGs must still validate
```

---

## Gap 2 — health checks (phase 2, optional)

### Config

| Key | Meaning |
|-----|---------|
| `config:lb_health_enabled` | 0 (default) / 1 |
| `config:lb_health_targets` | `name[:port],...` — names whose A/AAAA targets get probed (port default 80) |
| `config:lb_health_interval` | seconds between probe rounds (default 10) |
| `config:lb_health_timeout_ms` | per-probe TCP connect timeout (default 1000) |

### Fix overview

- `lb_health_thread`, started from `main` next to `pki_renewal_thread`
  (4912): every interval, read `zone:A:`/`zone:AAAA:` for each configured
  name, non-blocking `connect()` to each `ip:port` with the timeout, record
  state in an in-memory table guarded by a mutex (no Valkey round-trip on
  the query path).
- `emit_addr_rrset` consults the table and skips addresses marked down —
  **unless all are down**, in which case emit everything (a degraded answer
  beats an empty NOERROR that resolvers will negative-cache).
- State transitions logged at LOG_NOTICE; counters
  (`g_stat_lb_down_skips`) added to the stats block (870–878) and the
  Prometheus endpoint (4620 ff.).

Estimated ~120 lines.

### Test

```bash
# two targets, stop the service on one:
dig +short @localhost lb.corp.local A      # only the healthy IP after <=interval
# stop both:
dig +short @localhost lb.corp.local A      # both IPs again (fail-open)
```

---

## Interaction with the hidden-master/secondary plan (CLAUDE.md)

- `config:lb_mode` is **local serving policy**, not zone data — it does not
  travel in AXFR/IXFR and may differ per instance.  Set it on the public
  secondaries; the hidden master doesn't answer clients.
- Health-check state is likewise local and must never feed back into zone
  writes on a secondary (CLAUDE.md Gap 7): the table only filters emission.

## Suggested order

1. Gap 1 (rotation) — small, self-contained, immediately testable.
2. Gap 2 (health checks) — only if needed; rotation alone covers the
   common case.
