---
name: c-security-audit
description: >
  Conduct a security-focused audit of a C codebase: memory safety, integer/type
  errors, untrusted-input parsing, resource and error-path handling, concurrency,
  OS/filesystem/process interaction, crypto and secret handling, and build-time
  hardening. Use this skill whenever the user asks to audit, security-review,
  harden, or find vulnerabilities in C (or C/C++) code, asks "is this safe?",
  asks for a threat model of a C component, or wants a periodic/diff security
  pass on a daemon, parser, network service, or filesystem-backed server — even
  if they don't say the word "audit". Prefer this skill over an ad-hoc review for
  any non-trivial C security request.
---

# C Security Audit

A repeatable, defensive security review for C code. The goal is to find
exploitable weaknesses before an attacker does and to produce a report that is
**diffable across runs**, so the same project can be re-audited periodically and
you can see what's new, fixed, or regressed.

This skill is for reviewing code you own or are authorized to review. It does not
produce exploits — it produces findings, root-cause explanations, and fixes.

---

## 1. How to run an audit

Before reviewing code, settle three things (ask the user only if unclear):

1. **Scope** — whole repo, one module/daemon, or a diff/PR? Default to whole repo
   on first run, diff-only on later runs.
2. **Trust boundaries** — where does *untrusted* data enter? Network sockets,
   files, IPC, env vars, CLI args, config, shared memory. Everything crossing a
   boundary is attacker-influenced until validated.
3. **Privilege & deployment** — does it run as root / setuid? Network-facing?
   Parsing attacker-controlled formats? This sets severity weighting.

Two modes:

- **Full audit** — every pass below, every translation unit. Use on first run or
  after large changes.
- **Incremental audit** — run passes only against changed files/functions
  (`git diff`), but always re-check whether a change touches an existing trust
  boundary or weakens a prior mitigation.

Always combine **manual review** (the passes in §3) with **tooling** (§4). Tools
catch the mechanical bugs; manual review catches logic, trust, and design flaws
tools cannot see.

---

## 2. Pass 0 — Map the attack surface

Do this first; it directs everything else.

- Enumerate every entry point for external data: `recv`/`read` on sockets,
  `fread`/`read` on files, `getenv`, `argv`, `scanf` family, IPC, deserializers,
  config/format parsers.
- For each, trace the data flow inward: where is length validated, where is it
  copied, where is it used as an index/size/offset, where does it reach
  `malloc`, `memcpy`, array subscript, or a syscall.
- Mark all code that runs at elevated privilege or before privilege drop.
- Note any in-house parser of a binary/network format — these are the highest-yield
  targets and deserve the deepest review (relevant for routers, DNS, S3/object,
  and any custom protocol).

Produce a short "trust map" you can reference in findings.

---

## 3. Manual review passes

Each pass is a checklist. For every hit, record location, why it's reachable from
untrusted input, impact, and a concrete fix (see report format in §6).

### Pass 1 — Memory safety
- Unbounded copies: `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`,
  `vsprintf`. Replace with bounded forms **and** verify the bound is correct
  (off-by-one on NUL terminator is the classic mistake).
- `memcpy`/`memmove`/`memset` with attacker-influenced length or a length derived
  from a different buffer than the destination.
- Off-by-one / fencepost in loops and index math; `<=` where `<` was meant.
- Use-after-free and double-free: pointer used after `free`, freed on multiple
  paths, freed then re-entered via error/goto cleanup.
- Dangling pointer after `realloc` (old pointer kept and reused).
- Uninitialized reads: stack buffers/structs used before being fully written,
  especially partial reads from sockets/files.
- NULL deref: unchecked return of allocators, `fopen`, `getenv`, lookups,
  accessor functions.
- Out-of-bounds **reads** (info leak): copying/serializing more than was filled;
  trusting a length field instead of bytes actually received.
- Format string: `printf(user)`, `syslog(prio, user)`, `fprintf(f, user)` — the
  format argument must be a literal.
- Returning or storing pointers to stack memory that outlives its scope.

### Pass 2 — Integers & types
- Allocation-size overflow: `malloc(n * size)`, `a + b`, `count << shift` where
  the product/sum wraps, yielding an undersized buffer then a heap overflow.
  Prefer overflow-checked allocation (`calloc`, `__builtin_mul_overflow`, or an
  explicit pre-check).
- Signed/unsigned confusion: a negative `int` length passed to a `size_t`
  parameter becomes huge; comparisons that flip when one side is unsigned.
- Truncation: assigning `size_t`/`ssize_t` into `int`/`short`; `(int)strlen(...)`.
- `ssize_t` returns (`read`, `recv`, `getline`) treated as unsigned without
  checking for `-1`.
- Untrusted length fields used directly as sizes/counts without an upper bound.
- `strtol`/`strtoul` without checking `errno`/`endptr`, and range clamping.
- Pointer arithmetic that can overflow or run past the object.

### Pass 3 — Untrusted input & parsing
- Every field from a network packet / file format validated for length and range
  **before** use; no "trust the header's claimed size".
- Bounds check **before** indexing, not after.
- Path/key handling: canonicalize and reject `..`, absolute paths, symlink
  escapes, NUL bytes, and embedded separators before mapping a request to a
  filesystem path (critical for object/file servers — never let an external key
  escape the data root).
- Command/SQL/log injection: untrusted data reaching `system`, `popen`, `exec*`
  with a shell, or unsanitized into logs (log forging / format).
- Recursive or unbounded parsing → stack exhaustion or quadratic blowups (DoS).
- State machines: malformed/truncated/partial input handled without UB; reject
  cleanly rather than continuing in an undefined state.
- For request/response network protocols (DNS, resolvers, RPC), also work
  `references/network-parsers.md`: response↔query correlation (transaction
  ID + question match), CSPRNG for IDs/ports/cookies, and wire-format bounds.

### Pass 4 — Resources & error paths
- Every allocator return checked before use.
- No leaks on error paths (memory, `FILE*`, fds, sockets, locks, mmap) — a single
  cleanup path via `goto` is fine and preferred over scattered returns.
- Partial-write / short-read handling: loop on `write`/`send`; handle `EINTR`,
  `EAGAIN`, and `ENOSPC` explicitly rather than assuming full completion.
- No reuse of a pointer after a failed `realloc`.
- Error returns actually propagated, not swallowed; failure leaves no
  half-initialized object reachable.
- Resource-exhaustion DoS: caps on connections, request sizes, allocation totals,
  and recursion depth for anything network-facing.

### Pass 5 — Concurrency
- Data races on shared state: every shared mutable object protected by a lock or
  atomics; check with TSan (§4).
- TOCTOU within the program: check-then-act on shared state without holding the
  lock across both.
- Lock ordering consistent (deadlock); locks released on every path including
  errors.
- Signal handlers call only async-signal-safe functions and touch only
  `volatile sig_atomic_t` (or self-pipe).
- Reentrancy / use of non-thread-safe libc (`strtok`, `gmtime`, `getenv` writes,
  static return buffers) across threads.

### Pass 6 — OS / filesystem / process
- Filesystem TOCTOU: `access()`/`stat()` then `open()` — prefer `openat` + `O_*`
  flags and fstat on the fd.
- Symlink attacks: `O_NOFOLLOW` where appropriate; don't follow links out of a
  trusted root.
- Temp files: `mkstemp`/`mkdtemp`, never `tmpnam`/`mktemp`; correct mode.
- File permissions & `umask`: created files/dirs not world-readable/writable when
  they hold sensitive data; share/object permissions enforced on the real
  target, not just at the API layer.
- Privilege: drop privileges correctly and in order (`setgroups` →
  `setgid` → `setuid`), **check every return value**, drop before touching
  untrusted input; verify drop actually took effect.
- Environment trust: `PATH`, `LD_*`, `IFS` and other env not trusted in
  privileged context; use absolute paths for `exec`.
- `chroot`/sandbox/seccomp applied where claimed and not trivially escapable.

### Pass 7 — Crypto & secrets
- No hardcoded keys, passwords, tokens, or default credentials in source or
  shipped config (grep for these explicitly; check derived-from-MAC or other
  predictable secret schemes).
- CSPRNG for anything security-relevant: `getrandom`/`/dev/urandom`, **never**
  `rand()`/`random()`/`srand(time(NULL))` for keys, tokens, nonces, IVs.
- Constant-time comparison for secrets/MACs/tokens (no `memcmp`/`strcmp` that
  short-circuits and leaks timing).
- Secret material zeroed after use (`explicit_bzero` / `memset_s`, not plain
  `memset` which the compiler may elide).
- TLS — modern protocol versions only; certificate **and** hostname verification
  enabled. With OpenSSL, check each of these separately — every one is a
  real-world miss seen in the field:
- `SSL_set_tlsext_host_name()` sets the **SNI extension only** — it does **not**
    verify the cert matches the host. Hostname checking requires
    `SSL_set1_host()` / `X509_VERIFY_PARAM_set1_host()` / `X509_check_host()`.
    If SNI is set but no `set1_host`/`check_host` appears anywhere → MITM with any
    CA-valid cert for any name. (`grep -rE 'set1_host|check_host'` returning empty
    on a client that does TLS is itself the finding.)
- `SSL_CTX_set_verify(…, SSL_VERIFY_PEER, …)` set on only **one branch** of the
    CA-config logic (e.g. inside `if (ca_pem)` but not the system-trust `else`) →
    the other path silently runs at `SSL_VERIFY_NONE`.
- At `SSL_VERIFY_NONE`, a client handshake succeeds regardless of the cert;
    verification then depends on a manual `SSL_get_verify_result()` check. Confirm
    that check exists, or that `SSL_VERIFY_PEER` is set unconditionally.
- Any explicit no-verify toggle (`SSL_VERIFY_NONE` behind a config flag) is a
    finding — flag it and report its default.
- No pinned-to-accept-all callback.
- No home-grown crypto; correct nonce/IV uniqueness; AEAD or
  encrypt-then-MAC rather than ad-hoc constructions.

### Pass 8 — Build & toolchain hardening
Confirm the build enables protections and that warnings are clean:
- Warnings as signal: `-Wall -Wextra -Wconversion -Wsign-conversion -Wshadow
  -Wformat=2 -Wnull-dereference`; ideally `-Werror` in CI.
- `-D_FORTIFY_SOURCE=3` (or `=2`) with optimization on.
- Stack protection: `-fstack-protector-strong` (or `-strong`/`-all`).
- PIE/ASLR: `-fPIE -pie`. Full RELRO: `-Wl,-z,relro,-z,now`.
- Non-exec stack: `-Wl,-z,noexecstack`. Consider `-fstack-clash-protection`,
  `-fcf-protection`, `-ftrivial-auto-var-init=zero`.
- Verify the shipped binary actually has these (`checksec`, `readelf -l`,
  `scanelf`) — flags can be silently dropped by a wrapper or package step.

---

## 4. Tooling to run

Run these and fold the results into the report. Manual review interprets what the
tools flag; many tool hits are reachable only from specific inputs.

**Static analysis**
```sh
# Clang static analyzer
scan-build make
# clang-tidy (focus on bugprone/security/cert checks)
clang-tidy -checks='bugprone-*,cert-*,clang-analyzer-*,concurrency-*' src/*.c
# cppcheck
cppcheck --enable=all --inconclusive --std=c11 --quiet src/
# (if available) semgrep with C rulesets, CodeQL for deeper dataflow
```

**Dynamic / sanitizers** (build separate instrumented binaries; run the test
suite and any reproducers under each)
```sh
# Address + Undefined behavior
cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer ...
# Threads (concurrency bugs) — separate build, can't combine with ASan
cc -g -O1 -fsanitize=thread ...
# Uninitialized memory (clang only) — separate build
clang -g -O1 -fsanitize=memory -fno-omit-frame-pointer ...
```

**Fuzzing** — for every parser of untrusted input, a fuzz harness is the highest-
value test. libFuzzer or AFL++ with ASan+UBSan; seed from real inputs; keep the
corpus in-repo so periodic runs extend coverage rather than starting cold.
```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined harness.c parser.c -o fuzz
```

**Binary hardening check**
```sh
checksec --file=./build/binary   # or: readelf -l / scanelf -e
```

**If a tool is unavailable, fall back rather than skip — and say so in the report.**
- No `checksec` → `readelf -lW <bin> | grep -E 'GNU_RELRO|GNU_STACK'`,
  `readelf -dW <bin> | grep -E 'BIND_NOW|FLAGS'`,
  `readelf -hW <bin> | grep Type` (Type `DYN` = PIE; `EXEC` = not PIE).
- Production binary not built / stripped → confirm hardening from the **build
  system** (`Makefile`/CI) instead, and note the shipped artifact was not
  independently verified.
- No `scan-build`/`cppcheck` → run `clang-tidy` (above) and lean on the manual
  passes; record the reduced tool coverage in the report's caveat.

---

## 5. Severity rubric

Rate each finding so the report is triageable and stable across runs.

- **Critical** — remote/unauthenticated memory corruption, RCE, auth bypass, or
  privilege escalation reachable from untrusted input.
- **High** — memory corruption or secret exposure needing some precondition
  (local, authenticated, or non-default config); hardcoded credentials.
- **Medium** — exploitable only with significant constraints; DoS on a
  network-facing path; missing-but-defense-in-depth mitigation that real bugs
  would otherwise be caught by.
- **Low** — weak hardening, risky pattern not currently reachable, info leak of
  non-sensitive data.
- **Info** — style/robustness notes, latent bugs not security-relevant today.

Weight up for: network-facing, runs as root/setuid, parses attacker-controlled
formats. Always state *reachability* — a `strcpy` behind three validations is not
the same as one on `recv` output.

---

## 6. Report format

Write findings to `SECURITY_AUDIT.md` (or append a dated section on re-runs).
Use **stable IDs** so a finding keeps its identity across audits and you can track
status over time. Suggested ID scheme: `CSA-<area>-<NNN>` (e.g. `CSA-MEM-001`,
`CSA-INT-004`, `CSA-CRYPTO-002`).

```
# Security Audit — <project> — <date> (<full | incremental @ commit>)

## Summary
Scope: ...
Trust map: <entry points and boundaries>
Counts: Critical N · High N · Medium N · Low N · Info N
New since last run: ...   Fixed since last run: ...   Regressed: ...

## Findings

### CSA-MEM-001 — <one-line title>  [Critical] [Open]
- Location: path/to/file.c:120  (function `foo`)
- Reachability: how untrusted input reaches this point
- Issue: what is wrong and why it is exploitable
- Impact: memory corruption / info leak / DoS / privesc / ...
- Fix: concrete change (and a safer pattern if relevant)
- Tooling: <flagged by ASan / cppcheck / manual>

### CSA-INT-004 — ...  [High] [Fixed in <commit>]
...
```

Keep finding text in your own words and self-contained; don't paste large source
blocks — cite location and the minimal relevant snippet.

---

## 7. Periodic / incremental re-runs

For "run this from time to time":

1. Pull the previous `SECURITY_AUDIT.md`. Carry forward IDs.
2. Audit the diff since the last audited commit; also re-check any finding whose
   surrounding code changed.
3. Re-run sanitizer test suite and fuzz corpus; note new crashes.
4. Mark each prior finding **Open / Fixed / Regressed**; add new ones with fresh
   IDs.
5. Lead the summary with what changed, so the human reads deltas first.

---

## Notes for growth

If this checklist grows project-specific depth, split deep material into
`references/` (e.g. `references/network-parsers.md`,
`references/privilege-drop.md`) and keep this file as the methodology + pointers —
the body stays small and the references load only when that pass runs.
