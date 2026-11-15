# Copy-paste patch for the `c-security-audit` skill

Five edits against the current `SKILL.md`. Each is an exact **FIND** → **REPLACE**
(the FIND block is verbatim from the current file). Edit #4 is a new file. Apply
in Settings → Capabilities.

---

## Edit 1 — Pass 7 TLS bullet (the high-value one)

**FIND** (Pass 7, the single TLS bullet):

```
- TLS: certificate **and** hostname verification enabled; no disabled verify, no
  pinned-to-accept-all; modern protocol versions only.
```

**REPLACE WITH:**

```
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
```

---

## Edit 2 — Pass 3 pointer to the new reference

**FIND** (end of Pass 3):

```
- State machines: malformed/truncated/partial input handled without UB; reject
  cleanly rather than continuing in an undefined state.
```

**REPLACE WITH:**

```
- State machines: malformed/truncated/partial input handled without UB; reject
  cleanly rather than continuing in an undefined state.
- For request/response network protocols (DNS, resolvers, RPC), also work
  `references/network-parsers.md`: response↔query correlation (transaction
  ID + question match), CSPRNG for IDs/ports/cookies, and wire-format bounds.
```

---

## Edit 3 — §4 binary-hardening check + tool fallbacks

**FIND:**

```
**Binary hardening check**
```sh
checksec --file=./build/binary   # or: readelf -l / scanelf -e
```
```

**REPLACE WITH:**

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
```

---

## Edit 4 — New file: `references/network-parsers.md`

Create this file alongside `SKILL.md` (in a `references/` subfolder):

```markdown
# references/network-parsers.md — DNS / resolver / request-response parsers

Load during Pass 3 when the target speaks a request/response protocol.

## Response/request correlation (off-path spoofing)
- Does the client verify the **response transaction ID == the query ID**? Grep
  the response path for a comparison against the sent ID. Its absence is a finding
  even on a connect()ed UDP socket — the kernel filters addr:port only, so an
  unchecked ID halves the off-path spoofer's search space.
- Does it verify the **question / echoed request matches** what was asked
  (QNAME/QTYPE for DNS)? Accepting any answer that arrives on the socket is the
  classic cache-poisoning enabler.
- Transaction IDs, source ports, cookies, nonces must come from a **CSPRNG**
  (`RAND_bytes`/`getrandom`), never `rand()`/`srand(time())`. For a resolver these
  are the primary anti-spoofing entropy; predictable → poisoning.
- Consider 0x20 query-name case randomisation as defense-in-depth (DNS).

## DNS wire specifics
- Name decompression: pointers must target a **strictly prior** offset; a
  visited-set or step cap must bound loops; every label copy bounds-checked
  against both packet end and output buffer.
- EDNS/OPT option walk: each option header (code+len) and its payload
  bounds-checked against min(rdlen-end, packet-end) before any copy.
- QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT are attacker-supplied counts — never use them
  as loop bounds without a per-iteration `off < plen` guard.

## TSIG / MAC / cookie
- Verify the MAC covers the **correct byte range** — a verifier that compiles and
  passes on valid input may cover the wrong bytes. Require a flipped-byte negative
  test, not just a known-answer test.
- Compare MACs / cookies / shared secrets with `CRYPTO_memcmp`, never
  `memcmp`/`strcmp` (timing oracle).
```

---

## Edit 5 — Make the coverage caveat a required report section

**FIND** (§6, end of the report template block):

```
Keep finding text in your own words and self-contained; don't paste large source
blocks — cite location and the minimal relevant snippet.
```

**REPLACE WITH:**

```
Keep finding text in your own words and self-contained; don't paste large source
blocks — cite location and the minimal relevant snippet.

End every report with a **Coverage caveat** section: on a large codebase, state
plainly what was reviewed line-by-line vs. sampled/grepped, which tools were
unavailable, and the highest-value next step (often a fuzz harness over a specific
parser). An honest residual-risk statement is part of the deliverable.
```
