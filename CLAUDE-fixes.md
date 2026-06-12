# CLAUDE.md — Fix tasks for the dns_server project

This file lists concrete defects found in a code review, in priority order.
Work through them top to bottom. Each task names the file, the function, the
problem, and the required fix. After each task, rebuild and run the smoke test.

## Project context

- Authoritative DNS server in C: `dns_server.c`
- Recursive/proxy client with DNSSEC validation: `dns_client.c`
- Simplified variant: `simple_dns.c`
- Build system: `Makefile` (production build is stripped + GPG-signed)
- Runtime config lives in Valkey under `config:*`; the server is multithreaded
  (one worker thread per request, pthreads throughout).

## Build / verify after every change

```
make debug        # ASan + UBSan build — use this while iterating
make              # production build (stripped, signed)
make check        # smoke test, requires Valkey on 127.0.0.1:6379
```

Run the debug binary under sanitizers for the concurrency and parsing fixes:

```
ASAN_OPTIONS=detect_leaks=1 ./dns_server_debug
```

Do not weaken or remove existing bounds checks while refactoring. Preserve the
existing return-value conventions (`-1` on overflow/error) for all wire helpers.

---

## Task 1 (CRITICAL) — DNSSEC validates only the RRSIG header, not the RRset

**File:** `dns_client.c`
**Function:** `dnssec_verify_rrset` (and its callers `verify_ecdsa_p256`,
`verify_ed25519`)

**Problem:** The data handed to the signature-verify routines is only the RRSIG
RDATA up to `hdr_len` (the fields through the signer's name). The actual RRset
bytes are never appended, so the signature does not cover the answer records.
An attacker can rewrite the A/AAAA/etc. rdata and verification still succeeds.
A `DNSSEC_SECURE` result is currently meaningless. The code comment admits this
("we verify the header only as a structural check").

**Required fix:** Build the correct signing input per RFC 4034 §3.1.8.1:

1. Start with the RRSIG RDATA from the `type covered` field through the
   signer's name (inclusive), exactly as already extracted into `hdr_len`.
2. Append the RRset in canonical form, for each RR in the set:
   - Owner name: fully expanded (decompressed), lowercased, in wire format,
     using the original owner name — not a compression pointer.
   - `type` (2) `class` (2) `original TTL` (4, from the RRSIG, not the packet)
     `rdlength` (2) `rdata`.
   - Canonicalize rdata where the RR type requires it (lowercase embedded
     domain names for the types listed in RFC 4034 §6.2).
3. Sort the RRs into canonical order (RFC 4034 §6.3) before concatenation.
4. Pass `hdr || canonical_rrset` as the `data`/`dlen` argument to
   `verify_ecdsa_p256` / `verify_ed25519`.

`dnssec_verify_rrset` must therefore receive the packet plus the RRset offset
and count (the signature comment block already documents `pkt`, `rr_off`,
`rr_count` parameters that the current implementation ignores — wire them up).

**Acceptance:** A response whose RRSIG header is intact but whose A-record rdata
has been altered by one byte must verify as `DNSSEC_BOGUS`, not `DNSSEC_SECURE`.
Add a test that flips a byte in the answer rdata and asserts BOGUS.

---

## Task 2 (HIGH) — `strtok` is not thread-safe; replace with `strtok_r`

**Files:** `dns_server.c`, `dns_client.c`, `simple_dns.c`
**Functions (non-exhaustive):** `name_to_wire`, `name_to_wire_c`,
`mdns_put_name`, the TSIG key-name encoders, `config_load_env`, and the cache
(de)serializers.

**Problem:** `strtok` stores its iteration state in a hidden static variable.
The server runs concurrent worker threads, so two threads tokenizing names at
the same time corrupt each other's state — intermittent malformed names and
crashes that will not reproduce single-threaded.

**Required fix:** Replace every `strtok(s, d)` / `strtok(NULL, d)` pair with
`strtok_r` using a local `char *saveptr;`. Example:

```c
char *saveptr;
for (char *lbl = strtok_r(work, ".", &saveptr);
     lbl;
     lbl = strtok_r(NULL, ".", &saveptr)) { ... }
```

Audit the whole tree (`grep -n 'strtok(' *.c`) and convert all sites. Do not
leave a single bare `strtok`.

**Acceptance:** `grep -rn '\bstrtok(' *.c` returns nothing. The debug build runs
clean under a multithreaded load test (e.g. several concurrent `dig` loops)
with no ASan reports.

---

## Task 3 (MEDIUM) — TSIG fudge is encoded as 5, not 300

**File:** `simple_dns.c`
**Location:** TSIG variables block and the TSIG RDATA block (both have
`buf/vars[...]=0; ...=5; /* fudge=300 */`).

**Problem:** The two-byte fudge is written as `0x00, 0x05` (= 5) but the comment
says 300. A 5-second window makes TSIG hypersensitive to clock skew and causes
spurious BADTIME failures.

**Required fix:** Encode 300 as `0x01, 0x2C`. Replace both occurrences:

```c
vars[vp++] = 0x01; vars[vp++] = 0x2C;   /* fudge = 300s */
```

Better: define `#define TSIG_FUDGE 300` and emit `(TSIG_FUDGE >> 8)` and
`(TSIG_FUDGE & 0xFF)` at both sites so they cannot drift apart again. Check
`dns_server.c` for the same constant and keep them consistent.

**Acceptance:** Both the variables digest input and the emitted RDATA carry
0x012C. A TSIG round-trip between two hosts with up to a few minutes of skew
still validates.

---

## Task 4 (MEDIUM) — Makefile defaults an include path to world-writable /tmp

**File:** `Makefile`
**Line:** `OSSL_INC ?= /tmp/ossl-inc`

**Problem:** Searching a world-writable directory for headers is a build-integrity
risk: any local user can plant headers there.

**Required fix:** Change the default to a normal location, e.g.
`OSSL_INC ?= /usr/include`, or leave it empty and require it be set explicitly,
failing the build with a clear message if OpenSSL headers are not found. Keep
the existing override mechanism (`make OSSL_INC=/opt/openssl/include`) intact.
Do the same sanity check for `OSSL_LIB` if it can be empty.

---

## Task 5 (LOW–MEDIUM) — Harden `name_from_wire` compression handling

**Files:** `dns_server.c`, `dns_client.c`, `simple_dns.c` (three copies of
`name_from_wire`)

**Problem:** The function is bounded by `steps++ < 128`, which does prevent
pointer loops, but it does not enforce that a compression pointer targets an
offset strictly *before* the pointer itself (RFC 1035 §4.1.4).

**Required fix:** When following a pointer, reject the packet (`return -1`) if
the target offset is not strictly less than the offset of the pointer being
followed. This turns the loose step cap into a hard no-loop guarantee and
rejects malformed packets earlier. Keep the existing `steps` cap as a backstop.
Apply the identical change to all three copies (or better, factor them into one
shared helper).

---

## Task 6 (LOW) — String truncation / termination robustness

**Files:** all three `.c` files

**Problems:**
- `streq_ci` (`dns_server.c`) copies both inputs into 256-byte buffers with
  `strncpy(...,255)`; names longer than 255 truncate and can compare equal.
- Several `strncpy(dst, src, 255)` calls rely on the destination already being
  zero-initialized for null termination (e.g. upstream host parsing in
  `config_load_env`). Where that is not guaranteed, an exactly-255-char source
  leaves the buffer unterminated.

**Required fix:** Add a single helper and use it everywhere a bounded copy is
needed:

```c
static void safe_strcpy(char *dst, const char *src, size_t dstsz) {
    if (dstsz == 0) return;
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
}
```

Replace the ad-hoc `strncpy(...,255)` sites with `safe_strcpy(dst, src,
sizeof dst)` (using the real array size, not a hardcoded 255). For `streq_ci`,
this only bounds the buffer; note in a comment that DNS names are capped at 255
so truncation of legitimate input cannot occur.

---

## Final checklist

- [x] Task 1: tampered-rdata test returns DNSSEC_BOGUS (`make check-dnssec`,
      12/12 incl. negative tests for alg 13 + 15)
- [x] Task 2: no bare `strtok` remains; clean under ASan + concurrent load
      (6 parallel `dig` loops, 960 queries UDP+TCP, zero sanitizer reports)
- [x] Task 3: fudge encodes 0x012C at all sites via shared `TSIG_FUDGE` define
      (both digest input and RDATA, all three files)
- [x] Task 4: no world-writable default include path — `pkg-config`-derived
      defaults + `ossl-sanity` fail-fast check; bare `make debug` works
- [x] Task 5: backward-pointer check in all `name_from_wire` copies
      (`make check-wire`, 11/11 incl. forward/self/loop rejection)
- [x] Task 6: `safe_strcpy` helper used for bounded copies (163 `strncpy`
      sites converted across the three files, sizes audited against
      declarations; only the helper's internal `strncpy` remains)
- [x] `make debug` and `make` both succeed with no new warnings
      (warning counts identical to pre-change baseline per file; note: the
      final GPG `sign` step of `make` needs a secret key this machine does
      not have — `make dns_server` builds the production binary clean)
- [x] `make check` passes (smoke query answered: 192.168.1.10)
