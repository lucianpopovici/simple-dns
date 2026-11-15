# Proposed improvements to the `c-security-audit` skill

Grounded in the 2026-06-23 simple-dns audit. Apply via **Settings → Capabilities**
(the skill can't be edited from a session). Three changes; the first two are the
high-value ones.

---

## 1. Expand Pass 7 with OpenSSL TLS-verification gotchas

The current Pass 7 bullet ("certificate **and** hostname verification enabled;
no disabled verify") was directionally right but too coarse — the audit's two
High findings (CSA-TLS-001/002) hid behind OpenSSL-specific traps that a generic
bullet doesn't prompt for. Replace the TLS bullet with:

> - **TLS (OpenSSL specifics — each is a separate, real-world miss):**
>   - `SSL_set_tlsext_host_name()` sets **SNI only** — it does **not** verify the
>     cert matches the host. Hostname verification requires
>     `SSL_set1_host()` / `X509_VERIFY_PARAM_set1_host()` / `X509_check_host()`.
>     Grep: SNI set but no `set1_host`/`check_host` anywhere → MITM with any valid
>     cert.
>   - `SSL_CTX_set_verify(…, SSL_VERIFY_PEER, …)` set on only **one branch** of
>     the CA-config logic (e.g. inside `if (ca_pem)` but not the `else`/system-
>     trust path) → the default path silently runs at `SSL_VERIFY_NONE`.
>   - For a client at `SSL_VERIFY_NONE`, the handshake succeeds regardless of the
>     cert; verification then depends on a manual `SSL_get_verify_result()` check.
>     Confirm that check exists, or that `SSL_VERIFY_PEER` is set unconditionally.
>   - Any explicit no-verify toggle (`SSL_VERIFY_NONE` behind a config flag) is a
>     finding even if "optional" — flag it and its default.

Why: a single grep for `set1_host|check_host` returning empty was the fastest
signal in the whole audit; and the "verify only in one branch" pattern is invisible
to "is verify enabled?" framing.

---

## 2. Add `references/network-parsers.md` (the skill's own "Notes for growth" path)

The methodology covers binary parsers generically but missed a DNS/resolver-
specific class that produced a High finding (CSA-NET-001): a recursive resolver
that never matched the response to its query. Create the reference file the skill
already anticipates:

```markdown
# references/network-parsers.md — DNS / resolver / request-response parsers

Load during Pass 3 when the target speaks a request/response protocol.

## Response/request correlation (off-path spoofing)
- Does the client verify the **response transaction ID == the query ID**?
  Grep the response path for a comparison against the sent ID; its absence is a
  finding even on a connect()ed UDP socket (kernel filters addr:port only).
- Does it verify the **question/echoed request matches** what was asked
  (QNAME/QTYPE for DNS)? Accepting any answer on the socket halves the spoofer's
  search space.
- Transaction IDs, source ports, cookies, nonces: must come from a **CSPRNG**
  (`RAND_bytes`/`getrandom`), never `rand()`/`srand(time())`. These are the
  primary anti-spoofing entropy; predictable → cache poisoning.
- Consider 0x20 query-name case randomisation as defense-in-depth (DNS).

## DNS wire specifics
- Name decompression: pointers must target a **strictly prior** offset; a
  visited-pointer or step cap must bound loops; every label-copy bounds-checked
  against both packet end and output buffer.
- EDNS/OPT option walk: each option header (`code`+`len`) and its payload bounds-
  checked against `min(rdlen end, packet end)` before any copy.
- QDCOUNT/ANCOUNT/etc. are attacker-supplied counts — never trust them as loop
  bounds without a per-iteration `off < plen` guard.

## TSIG / MAC / cookie
- Verify the MAC covers the **correct byte range** (a verifier that compiles and
  passes on valid input may cover the wrong bytes — add a flipped-byte negative
  test).
- Compare MACs/cookies/secrets with `CRYPTO_memcmp`, not `memcmp`/`strcmp`.
```

And add a pointer to it from Pass 3 in the main file:
> For DNS/resolver/request-response protocols, also work
> `references/network-parsers.md`.

---

## 3. Tooling: record fallbacks when the standard tools are absent

In this run `cppcheck`, `scan-build`, `valgrind`, and `checksec` were **not
installed**; `clang-tidy`, `gcc/clang`, and `readelf` were. The skill should not
stall on missing tools. Add to §4:

> **If a tool is unavailable, fall back rather than skip:**
> - No `checksec` → `readelf -lW <bin> | grep GNU_RELRO|GNU_STACK`,
>   `readelf -dW <bin> | grep BIND_NOW|FLAGS`, `readelf -hW <bin> | grep Type`
>   (Type `DYN` = PIE; `EXEC` = not).
> - Production binary not built / stripped → confirm hardening flags from the
>   **build system** (`Makefile`/CI) instead, and note that the shipped artifact
>   was not independently verified.
> - No `scan-build`/`cppcheck` → run `clang-tidy -checks='bugprone-*,cert-*,
>   clang-analyzer-*,concurrency-*'` and lean harder on the manual passes; state
>   the reduced tool coverage in the report's caveat.

---

## Minor

- The report's **coverage caveat** (honest statement of what was *not* line-by-
  line reviewed) worked well on a 23K-line repo. Consider promoting it from
  implicit to a required section in §6's template, so large-repo audits always
  state residual risk.
