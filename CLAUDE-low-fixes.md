# Phase 0b step 8 — Low findings

Fix spec for the Low findings of the 2026-11-15 audit (`SECURITY_AUDIT.md`)
plus the Phase-0 residual `csprng_u16` fallback. Roadmap: Phase 0b step 8.
Each item is independent and gets its own regression check.

| # | Finding | Daemon | Status |
|--:|---------|--------|--------|
| 8a | CSA-MEM-001 — double free on the EST 202 retry path | certd | **Done** 2026-11-16 — scan-build (now covers certd) |
| 8b | Phase-0 residual — `csprng_u16` falls back to `rand()` | dnsd, resolverd | **Done** 2026-11-16 — `check-wire` |
| 8c | CSA-MEM-002 — three small out-of-bounds reads | dnsd | **Done** 2026-11-16 — `check-oob-reads` |
| 8d | CSA-WEB-002 — login throttle trusts `X-Forwarded-For`; unbounded table | dashboard | **Done** 2026-11-16 — `check-dashboard-throttle` |
| 8e | CSA-DOS-006 — secondary NOTIFY: blocking `getaddrinfo`, no TSIG, no rate limit | dnsd | **Done** 2026-11-16 — `check-notify-secondary` |
| 8f | CSA-CRYPTO-001 — EPP credentials: plaintext, `strcmp`, no lockout, clID not bound to cert | eppd | **Done** 2026-11-16 — `check-eppd` (unit + live) |
| 8g | CSA-CONC-002 — config reload races request threads; full reload on every serial bump | dnsd | **Done** 2026-11-16 — `check-reload-serial`, `check-reload-tsan` |

---

## 8a — certd EST 202 double free (CSA-MEM-001)

On HTTP 202, `est_issue` frees `body`, sleeps, and retries. If the retry
buffer allocation or the second CSR fails, `body` still points at the freed
reply and is freed again on the failure path. Fix: `body = NULL` right after
the first free. Also size the retry's base64 buffer from the second CSR's
length (an ECDSA signature varies by a byte or two), not the first's.
Test: unit test of the retry path with the CSR builder forced to fail
(ASan reports the double free before the fix); `clang --analyze` clean.

## 8b — `csprng_u16` fails closed

`csprng_u16` returns `rand()` when `RAND_bytes` fails, giving predictable
DNS IDs / source ports (cache-poisoning surface for resolverd). Change it to
`int csprng_u16(uint16_t *out)` returning -1 on failure; callers fail closed:
resolverd fails the upstream query (SERVFAIL), dnsd skips that NOTIFY. Test:
unit test with `RAND_bytes` failure injected (a test-only hook) — the caller
returns an error, never a value.

## 8c — out-of-bounds reads (CSA-MEM-002)

- TSIG algorithm name (`tsig_find`): each label must lie within the TSIG
  RDATA (`rp + 1 + len <= rd_end`) and be a plain label (`len <= 63`, no
  compression) — else the TSIG is malformed.
- IXFR request authority scan (`dot_thread_body`): stop if the question name
  does not parse, and require `ra + 10 <= ml` before reading type/rdlength.
- Forwarder RRL truncation: require `rlen >= 12` to rewrite the header, and
  cut at the question end only if `qa + 4 <= rlen`.
Test: crafted packets for each (TSIG alg label running past the RDATA,
IXFR with a truncated authority RR) answered FORMERR/refused under ASan
without a read past the buffer; existing TSIG/IXFR checks unchanged.

## 8d — dashboard login throttle (CSA-WEB-002)

`_client_ip` takes the first `X-Forwarded-For` hop from anyone, so a client
rotates the header to dodge the back-off, and `_login_fails` grows without
bound. Fix: honour `X-Forwarded-For` only when the direct peer is listed in
`DASHBOARD_TRUSTED_PROXIES` (comma-separated IPs; empty = never), and then
take the right-most untrusted hop. Bound the table (`LOGIN_TABLE_MAX`, 10000)
and expire entries idle for an hour; when full, evict the oldest. Test
(Flask test client): rotating the header from an untrusted peer stays
throttled; behind a trusted proxy the header is used; the table never
exceeds the bound.

## 8e — NOTIFY on a secondary (CSA-DOS-006)

- Resolve `config:primary_host` once at config load (and on change) into a
  cached address list; the NOTIFY path compares against it — no
  `getaddrinfo` on the query thread.
- With a TSIG key configured, a NOTIFY must carry a TSIG that verifies;
  otherwise it is answered NOTAUTH and does not trigger a refresh (same
  handling as UPDATE/AXFR).
- `xfr_refresh_kick` runs at most once per second; extra NOTIFYs are
  acknowledged but coalesced.
Test: `check-notify-secondary` — key set: unsigned NOTIFY from the master's
address → NOTAUTH, no pull; signed NOTIFY → pull; a burst of 20 signed
NOTIFYs → one pull.

## 8f — EPP credentials (CSA-CRYPTO-001)

- `config:eppd_registrar_pw:<clID>` may hold
  `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`; `eppd --hash-password`
  reads a password on stdin and prints that form. A plaintext value is still
  accepted (existing deployments) but logs a warning on every login.
- All secret comparisons (password, domain authInfo) compare SHA-256 digests
  with `CRYPTO_memcmp` — constant time, independent of length.
- Optional `config:eppd_registrar_cert:<clID>` = SHA-256 fingerprint of the
  registrar's client certificate (hex, colons allowed). When set, a login for
  that clID over a session with a different certificate is refused. When
  unset, eppd logs that the clID is not bound to a certificate.
- Per-clID lockout: after 5 consecutive failures, further logins for that
  clID are refused for 2^(n-5) s (cap 300 s); a success resets the count.
  The refusal is 2200 "Authentication error: too many failures, retry
  later" (2502 would announce that the server closes the session, which it
  does not).
Test: unit tests (hash verify, plaintext compat, wrong pw, lockout schedule,
fingerprint match/mismatch) + `check-eppd` extended: registrar2 logs in with
a hashed password; a bound clID from the wrong certificate is refused.

## 8g — config reload vs. request threads (CSA-CONC-002)

`keyspace_apply` runs the full `config_load_from_valkey` for every
`config:*` event — including `config:zone_serial` and
`config:zone:<z>:serial`, written on every UPDATE / apid write — and many
globals are reset to their default and then refilled, so request threads
can see the default (an empty forwarder list, TSIG off, the ACL emptied) in
between.

- Serial keys get a dedicated path: read the new value, set that zone's
  serial under `g_soa_mutex`, re-run the catalog scan (a catalog's membership
  changes arrive as a serial bump). No full reload.
- `config_load_from_valkey` computes every value first and writes each
  global once, and a string only when it changed (no reset-then-refill), so
  a reload never exposes an intermediate default.

Not done here: a full config-struct pointer swap (RCU). Real config edits
(rare, operator-driven) can still tear a string read concurrently with its
rewrite; that is recorded as residual risk, not hidden.
Test: `check-reload-serial` — during a burst of UPDATEs the log shows no
"config applied after config:zone_serial" reload and queries for a
forwarded / ACL-gated name never see the default; TSan run of dnsd under
UPDATE load reports no race on the config globals touched by reload.

---

## Implementation notes (2026-11-16)

Every new check was run against a baseline build (the previous commit) and
fails there, except where noted.

- **8a** — `clang --analyze` (scan-build) reports the double free on the
  baseline and nothing on the fix. CI's blocking scan-build step analysed
  only `dns_server`; it now covers `certd`, `apid`, `mdnsd` and `eppd` too
  (four dead stores fixed to get there). `resolverd` stays out: its remaining
  reports are all in the vendored `object_graph.c` (fix upstream only).
  certd does not build against the local OpenSSL 4; verified in an
  ubuntu:24.04 container.
- **8a, found while verifying** — `check-star` crashed (SIGSEGV, a call
  through address 0) in an ubuntu:24.04 container, also on the commit before
  step 7, while it passed on the CI runner. Three pre-existing certd bugs on
  the STAR refresh/cancel path of a fresh `certd --once`, all fixed:
  - `acme_post` signed with the account key without loading it (only
    `acme_issue` did): `g_acme_key` was NULL, `EVP_DigestSignInit`'s failure
    was ignored and `EVP_DigestSignUpdate` called an unset method. `acme_post`
    now loads/creates the key itself (`acme_account_key_ensure`), and
    `acme_jws` fails closed on any signing error (it also used to send a
    literal `{}` instead of a JWS when the signature length was 0).
  - `acme_nonce_fetch` did not pass `config:acme_ca_pem` / the ACME client
    certificate, so against a private ACME CA every nonce fetch failed TLS
    verification and every request carried an empty nonce.
  - The refresh path never read the ACME directory, so it had no newNonce URL.
    `acme_post` now reads it when missing and refuses to send without a
    nonce.
  `tests/star_stub.py` now rejects a JWS without the nonce it issued
  (RFC 8555 §6.5), so `check-star` fails on the old code.
- **8b** — unit test in `check-wire` (resolverd's copy, via a `UNIT_TEST`
  failure hook). dnsd's copy is identical and only its one caller changed
  (the NOTIFY job is dropped); no harness includes `dns_server.c`.
- **8c** — `check-oob-reads`: the TSIG probe puts a well-formed algorithm
  name and fixed fields *after* the RR's declared RDATA. Baseline parsed
  them and answered NOTAUTH (TSIG processed); the fix answers REFUSED (the
  malformed TSIG makes the UPDATE unsigned). The IXFR over-read stays inside
  the receive buffer, so its probe is a liveness check only. The forwarder
  RRL truncation fix is defence in depth: `fwd_reply_valid` (RFC 5452)
  already rejects any reply that does not echo the full question, so the
  short reply cannot reach the truncation path today.
- **8d** — baseline: four failed logins with a rotating header were never
  throttled.
- **8e** — baseline: unsigned and wrong-key NOTIFYs triggered pulls. The rate
  limit does not drop NOTIFYs: the refresh thread waits ≥ 1 s between
  passes and kicks that arrive meanwhile are served by the next pass. The
  signed success ACK now carries a TSIG (RFC 8945); dnsd's NOTIFY sender does
  not verify ACK signatures, so primaries are unaffected.
- **8f** — `check-eppd` now runs registrar1 on a plaintext password (warning
  logged), registrar2 on a hash from `eppd --hash-password`, binds
  registrar1 to its certificate, and refuses registrar1's correct password
  over registrar2's certificate. Unit tests cover hash/plaintext/malformed
  stores, fingerprint parsing and the lockout schedule.
- **8g** — two further findings fixed with it:
  - **Cookie secret regenerated on every reload.** With
    `config:cookie_secret` unset, `config_load_from_valkey` drew a new random
    secret each time, and the reload ran on every serial bump, so after any
    UPDATE a client's server cookie stopped validating (BADCOOKIE; dig
    retries this silently). Now generated once per process.
    `check-reload-serial` shows BADCOOKIE on the baseline.
  - **`zone_upsert` rewrote every field** of the primary zone on each reload,
    racing query threads that read them unlocked. It now writes only fields
    that changed.
  Under TSan (query load + 50 serial bumps + one real config edit) the
  baseline reports 11 data races, 10 through `config_load_from_valkey`; the
  fix reports none (`check-reload-tsan`, in CI). Not done: a config-struct
  pointer swap. A real config edit that changes a string can still race a
  concurrent reader of that string; reloads no longer run on serial bumps
  and no longer rewrite unchanged values, so that window opens only on an
  actual operator change.
