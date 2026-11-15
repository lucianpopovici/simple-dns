# resolverd.c — cache and LRU locking

Fix spec for audit finding **CSA-CONC-001** (High). Source:
`SECURITY_AUDIT.md`, section 2026-11-15.

All line anchors are against commit `b0a6b32`. Re-anchor before editing:

```sh
grep -n "g_lru_mutex\|g_cache_count_mutex\|g_cache\[.*\]\.lock\|lru_touch(\|lru_insert(\|cache_evict_one(\|cache_entry_free(" resolverd.c
```

| Fix | Finding | Status |
|----:|---------|--------|
| 1 | CSA-CONC-001 — cache/LRU use-after-free under concurrent queries | **Done** 2026-11-15 (Option A, single `g_cache_mutex`) |
| 2 | TSan build + stress target so this class of bug is caught in CI | **Done** 2026-11-15 (`check-resolverd-stress`, `check-resolverd-tsan`, blocking in CI) |

## Implementation notes (2026-11-15)

- **Reproduced first.** The harness as written (random names, 60 s TTL on
  the hot name) did not reproduce on this machine in 30 s: random names never
  repeat, so no two workers ever insert the same key, and the hot name never
  re-inserts. `udp_stress nx` now draws from 64 names and the hot record has
  TTL 1, so concurrent misses of one name race their replaces. With that,
  the pre-fix ASan build hit `heap-use-after-free` within 45 s, and the
  pre-fix TSan build reported the `cache_insert` race at once.
- **After the fix:** 120 s ASan stress — no report, process alive and
  answering; 60 s TSan stress — no report in project code. The `-DDEBUG`
  invariant (`cache_check_invariant_locked`) runs on every insert and flush.
- `lru_unlink_locked` only clears head/tail when the entry really is the
  head/tail, so unlinking an entry not on the list is harmless.
- The `make` recipes run the two load generators by PID (`wait $P1 $P2`);
  waiting on all jobs would block on the background dnsd/resolverd.

## TSan findings (filed, per the Fix 2 guardrail)

1. **OpenSSL RCU hashtable — suppressed (third-party, uninstrumented).**
   `race:ossl_ht_get` in `tests/tsan.supp`, the only entry. Report:
   ```
   WARNING: ThreadSanitizer: data race
     Read of size 5 ... by thread T9:
       #0 memcmp  #1 ossl_ht_get (libcrypto.so.4)
       #2 dnssec_verify_rrset resolverd.c:1436 ... udp_worker
     Previous write of size 8 ... by thread T8 (mutexes: write M0, write M1):
       #0 malloc  #1 CRYPTO_malloc (libcrypto.so.4)
       #2 dnssec_verify_rrset resolverd.c:1436 ... udp_worker
   ```
   OpenSSL >= 3.3 looks algorithm names up in a lock-free (RCU) hashtable;
   libcrypto is not built with `-fsanitize=thread`, so TSan cannot see the
   RCU publication. Not a resolverd defect; `--no-dnssec` could not be used to
   sidestep it because that flag is still a no-op (CSA-AUTH-007).
2. **dnsd (`dns_server_tsan`, non-blocking, recorded):** a 15 s load run
   reports 12 races, all in the config/zone reload path —
   `config_load_from_valkey` (`:2597`, `:2601`) and `zone_upsert`
   (`:625-629`) writing globals / zone entries while UDP workers read them
   (`forward_should :6731`, `strncpy` from readers). This is CSA-CONC-002,
   roadmap step 8; not addressed here.

---

## Fix 1: one lock for the cache index and the LRU (CSA-CONC-001)

### What it is

The in-memory cache is guarded by three independent locks — a per-bucket
rwlock for the hash chain, `g_lru_mutex` for the LRU list, and
`g_cache_count_mutex` for the counter — and several functions touch an entry
after releasing the lock that keeps it alive:

1. `cache_insert` links the entry into its hash bucket, **releases the bucket
   lock**, then calls `lru_insert`. In that window another worker inserting the
   same name finds the entry in the bucket, "unlinks" it from an LRU list it is
   not on yet (which sets `g_lru_head`/`g_lru_tail` to NULL and drops the whole
   list), and frees it. The first worker then links freed memory into the LRU.
2. `cache_lookup` copies the entry under the bucket read lock, **releases it**,
   then calls `lru_touch(e)` on the original pointer, which may have been
   evicted or replaced.
3. `cache_evict_one` unlinks the victim from the LRU under `g_lru_mutex`,
   releases it, and only then takes the bucket lock to unlink it from the hash.
   A concurrent replace of the same key frees the entry first → double free,
   and the bucket count is decremented twice.

Reproduced on the ASan build with `--cache-size 8` and 12 client threads
(6 querying one name, 6 querying random names): `heap-use-after-free`, WRITE
of size 8 in `lru_insert` (`resolverd.c:3188`), freed by `cache_insert`
(`:3258`), within 20 seconds. The process exits.

### Exact location in current file

| Need | Existing code (`resolverd.c` @ `b0a6b32`) |
|------|-------------------------------------------|
| Entry and bucket types | `:180-196` `cache_entry_t` (LRU + hash links), `:199-203` `cache_bucket_t` (`head`, `lock`, `count`) |
| The three locks | `:323` `g_cache[]` (per-bucket `pthread_rwlock_t`), `:325` `g_cache_count_mutex`, `:328` `g_lru_mutex` |
| LRU primitives (each takes `g_lru_mutex` itself) | `:3161-3181` `lru_touch`, `:3183-3193` `lru_insert` |
| Eviction (race 3) | `:3204-3232` `cache_evict_one` |
| Insert (race 1: `lru_insert` after unlock at `:3270-3271`; unlocked read of `g_cache_total` at `:3276`) | `:3238-3278` `cache_insert` |
| Lookup (race 2: `lru_touch(e)` at `:3340` after unlock at `:3339`) | `:3288-3342` `cache_lookup` |
| Flush (same two-lock unlink pattern, twice) | `:3475-3545` `cache_flush` |
| Dump (bucket read lock only) | `:5404-5432` `dump_cache` |
| Stats (unlocked read of `g_cache_total`) | `:5352` |
| Lock init | `:5295-5300` `cache_init` |
| Callers of `cache_insert` | `:3820`, `:3853`, `:3996`, `:4123` |
| Callers of `cache_lookup` (both free the returned copy) | `:4058`, `:4093` |

### What to build

Option A is specified. Option B is recorded so the choice is visible.

- **Option A (chosen): a single `g_cache_mutex`** protects the hash chains,
  the LRU list and `g_cache_total`. The cache holds at most
  `g_cfg.cache_size` (default 8192) entries and every critical section is a
  short chain walk plus pointer updates or one deep copy; upstream round
  trips dominate resolverd's latency by orders of magnitude.
- **Option B (not chosen): keep per-bucket locks with a strict lock order and
  entry refcounts.** Eviction must then find the victim through the LRU and
  lock its bucket in the opposite order, which needs trylock/retry. More
  code and more ways to get it wrong, for throughput this daemon does not
  need.

Steps for Option A:

1. Add `static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;`
   beside `:328`. Remove `g_lru_mutex` and `g_cache_count_mutex`. Remove the
   `lock` member from `cache_bucket_t` and its init at `:5299`.
2. Make the LRU primitives lock-free helpers that **require the caller to
   hold `g_cache_mutex`**; rename them `lru_touch_locked`,
   `lru_insert_locked`, and add `lru_unlink_locked(e)` so the unlink
   sequence that is open-coded four times (`:3248-3257`, `:3484-3493`,
   `:3523-3532`, and in `cache_evict_one`) exists once. `lru_unlink_locked`
   must also set `e->lru_prev = e->lru_next = NULL`.
3. `cache_insert`: take `g_cache_mutex` once; replace-if-present
   (hash unlink + `lru_unlink_locked` + free), hash link,
   `lru_insert_locked`, `g_cache_total++`, and — still under the lock — evict
   from the tail while `g_cache_total > g_cfg.cache_size`. Then unlock.
4. `cache_evict_one` becomes `cache_evict_one_locked`: victim = `g_lru_tail`;
   `lru_unlink_locked`; unlink from its hash chain; `count--`;
   `g_cache_total--`; free.
5. `cache_lookup`: take `g_cache_mutex`; find; TTL/stale decision; deep copy
   (as today); `lru_touch_locked(e)`; unlock; return the copy.
6. `cache_flush` (both branches) and `dump_cache`: same lock, same helpers.
   In the flush-all branch release the lock **before** the persistent-tier
   work at `:3505-3513` (Valkey SCAN/DEL, objectdb flush).
7. `print_stats` (`:5352`): read `g_cache_total` under the lock.
8. Add a debug-build invariant check, compiled under `#ifdef DEBUG`, called
   at the end of `cache_insert` and `cache_flush` while the lock is held:
   walking the LRU from head reaches tail, visits exactly `g_cache_total`
   entries, and the sum of bucket `count` equals `g_cache_total`. `abort()`
   with a message on violation.

### Guardrail (do NOT)

- **Do NOT** dereference a `cache_entry_t *` obtained from the index after
  releasing `g_cache_mutex`. `cache_lookup` returns a deep copy for exactly
  this reason; keep it that way.
- **Do NOT** call anything that can block while holding `g_cache_mutex`: no
  Valkey or objectdb calls (`cache_store_persist`, `cache_load_persist`,
  `vk_*`, `pog_*`), no upstream query, no `dns_log` to a remote sink. Allocate
  the deep copy inside the lock (as today) but do persistence outside it.
- **Do NOT** keep `g_lru_mutex` "for compatibility" or leave any call to the
  old self-locking `lru_touch`/`lru_insert`; the mixed scheme is the bug.
- **Do NOT** change the public shape used by the tests and the fuzz harness
  (`fuzz/fuzz_response.c` and `tests/test_*.c` `#include "resolverd.c"`):
  `cache_insert(e)`, `cache_lookup(qname, qtype, allow_stale)`,
  `cache_flush(qname, qtype)`, `cache_entry_free(e)` keep their signatures.
- **Do NOT** touch the aggressive-NSEC store or the DNSKEY cache in this
  change unless the TSan run in Fix 2 reports them; they have their own locks.
- **Do NOT** switch to a reader-writer lock: every lookup writes the LRU.

### Acceptance criteria

- The stress recipe below runs for 120 s on the ASan build with no sanitizer
  report and the process still answers afterwards.
- The same recipe on the TSan build (Fix 2) reports no data race in
  `cache_*`/`lru_*`.
- The debug invariant never fires during `check-resolverd`,
  `check-resolverd-cache`, `check-resolverd-pog`, `check-serve-stale`,
  `check-aggressive-nsec`, `check-dnssec`, `check-ede`.
- At the end of the stress run the debug invariant holds and
  `g_cache_total` ≤ `--cache-size` (assert it in the invariant check).
- No measurable throughput loss on cache hits versus `b0a6b32` with 8
  workers (compare with the generator below, `a` mode, 10 s).

### Test

New file `tests/udp_stress.c` — a closed-loop UDP query generator. Modes:
`a` (one fixed name) and `nx` (random labels under the zone).

```c
// cc -O2 -o udp_stress tests/udp_stress.c -lpthread
// usage: udp_stress <port> <threads> <seconds> <a|nx> <zone-label-1> <zone-label-2>
//   e.g. udp_stress 5354 6 120 nx stress test   (queries r<hex>.stress.test A)
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
static int port, secs; static const char *mode, *l1, *l2; static long ok[64], to[64];
static int mk(unsigned char *b, unsigned id, unsigned r) {
    memset(b, 0, 12); b[0] = id >> 8; b[1] = id; b[2] = 1; b[5] = 1; int o = 12; char lab[32];
    int n = mode[0] == 'a' ? sprintf(lab, "www") : sprintf(lab, "r%08x", r);
    b[o++] = n; memcpy(b + o, lab, n); o += n;
    n = strlen(l1); b[o++] = n; memcpy(b + o, l1, n); o += n;
    n = strlen(l2); b[o++] = n; memcpy(b + o, l2, n); o += n;
    b[o++] = 0; b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1; return o;
}
static void *run(void *a) {
    long i = (long) a; int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    sa.sin_addr.s_addr = htonl(0x7f000001); connect(s, (void *) &sa, sizeof sa);
    struct timeval tv = {1, 0}; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char b[512], r[4096]; time_t end = time(0) + secs; unsigned seed = i * 7919 + 1;
    while (time(0) < end) { int n = mk(b, rand_r(&seed), rand_r(&seed)); send(s, b, n, 0);
        if (recv(s, r, sizeof r, 0) > 0) ok[i]++; else to[i]++; }
    return 0;
}
int main(int c, char **v) {
    if (c < 7) return 2;
    port = atoi(v[1]); int t = atoi(v[2]); secs = atoi(v[3]); mode = v[4]; l1 = v[5]; l2 = v[6];
    pthread_t th[64]; if (t > 64) t = 64;
    for (long i = 0; i < t; i++) pthread_create(&th[i], 0, run, (void *) i);
    long tot = 0, f = 0; for (int i = 0; i < t; i++) { pthread_join(th[i], 0); tot += ok[i]; f += to[i]; }
    printf("%s %.0f qps timeouts=%ld\n", mode, (double) tot / secs, f); return 0;
}
```

New target `check-resolverd-stress` (Valkey for dnsd only; resolverd runs
with `--no-valkey`):

```sh
# a non-.local zone: resolverd sends .local names to mDNS first
$VC set zone_table:stress.test "ns1.stress.test|hostmaster.stress.test|1|3600|900|604800|300||"
$VC set zone:stress.test:A:www.stress.test "60|10.0.0.1"
LISTEN_PORT=$TPORT UDP_WORKERS=2 ./dns_server_debug > /tmp/st_dnsd.log 2>&1 & DNS=$!; sleep 2
ASAN_OPTIONS=detect_leaks=0 LISTEN_PORT=5354 ./resolverd_debug \
    --upstream 127.0.0.1:$TPORT --no-valkey --cache-size 8 > /tmp/st_rd.log 2>&1 & RD=$!; sleep 2

./udp_stress 5354 6 120 nx stress test & ./udp_stress 5354 6 120 a stress test & wait

! grep -q "ERROR: AddressSanitizer\|runtime error\|cache invariant" /tmp/st_rd.log
kill -0 $RD                                   # still alive
dig +short @127.0.0.1 -p 5354 www.stress.test A +time=3 +tries=1 | grep -q 10.0.0.1
kill $DNS $RD; $VC del zone_table:stress.test zone:stress.test:A:www.stress.test
```

On `b0a6b32` this recipe fails within about 20 seconds; that is the
regression baseline. Run it once before the fix to confirm the harness
reproduces the defect on your machine.

---

## Fix 2: TSan build and CI job

### What it is

ASan found this bug only because the race happened to produce a
use-after-free quickly. A ThreadSanitizer build reports the unsynchronised
accesses directly, including ones that do not crash.

### Exact location

| Need | Existing code |
|------|---------------|
| Debug target to mirror | `Makefile:280-286` — `resolverd_debug` |
| Debug flags | `Makefile:115-118` — `DEBUG_FLAGS` (`-fsanitize=address,undefined`) |
| CI job list | `.github/workflows/ci.yml` — the blocking jobs after `:28` |

### What to build

1. `TSAN_FLAGS := -O1 -g -fsanitize=thread -fno-omit-frame-pointer -DDEBUG`.
2. Targets `resolverd_tsan` and `dns_server_tsan`, built like the `_debug`
   targets but with `TSAN_FLAGS` (TSan cannot be combined with ASan).
3. Target `check-resolverd-tsan`: the stress recipe above against
   `resolverd_tsan` for 60 s with `TSAN_OPTIONS=halt_on_error=1`; fail on any
   `WARNING: ThreadSanitizer`.
4. A blocking CI job that runs `check-resolverd-stress` and
   `check-resolverd-tsan`.

### Guardrail (do NOT)

- **Do NOT** add TSan suppressions to make the job green. A report in code
  outside the cache (stats counters, cookie store, config reload) is a
  finding: fix it or file it, with the report text, before suppressing
  anything.
- **Do NOT** run TSan and ASan in one binary.
- **Do NOT** make the dnsd TSan target blocking in this change; dnsd's live
  config reload is a known reader/writer race (CSA-CONC-002) and gets its own
  fix. Build the target, run it, record what it reports.

### Acceptance criteria

- `make resolverd_tsan dns_server_tsan` build warning-clean under
  `EXTRA_WARN=-Werror`.
- `make check-resolverd-tsan` passes after Fix 1 and fails on `b0a6b32`.
- The CI job is blocking and green.
