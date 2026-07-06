# certd — PKI daemon (ACME + EST + renewal)

`certd` owns certificate lifecycle: ACME issuance (RFC 8555, DNS-01/tls-alpn-01,
DNS/IP identifiers, STAR recurrent orders), EST enrollment (RFC 7030), and
renewal. It is the smallest decomposition target — mostly extraction of code
that already works in the monolith — plus ARI (Add 1), the two optional
challenge/identifier adds (Add 2/Add 3), the CAA pre-flight integration item,
and the RFC 8739 STAR roadmap item. All of it is now done — this file's
entire tracked checklist is closed.

## What's already there (monolith)

`acme_issue` (DNS-01), `est_issue`, the unified `pki_renewal_thread`,
`acme_needs_renewal`, and `tls_reload`. Certs land in Valkey and `dnsd` reads
them via `tls_reload`. mTLS management API is in place.

## Decomposition note — the DNS-01 cross-daemon hop

In the monolith, ACME DNS-01 writes the `_acme-challenge` TXT directly into the
zone. Once split, `certd` does **not** serve DNS — it must publish the challenge
into `dnsd`'s zone over the **Valkey bus** (`zone:TXT:_acme-challenge.<name>`)
or the `dnsd` management API, then poll for propagation before telling the CA to
validate. This is the one new coupling the split introduces; everything else is
Valkey-mediated cert handoff (`certd` writes `tls:cert`/`tls:key`, `dnsd`
reloads).

## Tracked checklist

- [x] Extract `acme_*`, `est_*`, `pki_renewal_thread`, `tls_reload` into `certd`
      (migration Step 2, done — see `CLAUDE.md`)
- [x] DNS-01 challenge publish via Valkey/`dnsd` API + propagation poll (done
      — `zone:TXT:_acme-challenge.<domain>`, deleted after validation)
- [x] **Add 1** — RFC 9773 ACME Renewal Information (ARI) (done 2026-07-01,
      `make check-ari`)
- [x] **Add 2** — RFC 8737 TLS-ALPN-01 challenge (optional) (done 2026-07-06,
      `make check-acme-challenges`)
- [x] **Add 3** — RFC 8738 ACME for IP identifiers (optional) (done 2026-07-06,
      same target — the two shipped together since dns-01 has no defined
      meaning for the "ip" identifier type, so IP-identifier issuance needs
      tls-alpn-01 to actually complete validation)
- [x] **Integration** — publish TLSA/DANE (6698/7671) for issued certs into `dnsd`
      (was already done, just mistracked here — `dnsd`'s own `cert_publish_tlsa`,
      called on every `cert:current` change, see `CLAUDE.md`'s `certd` section)
- [x] **Integration** — honor CAA (8659) before requesting issuance (done
      2026-07-06, `make check-caa`)
- [x] **Roadmap** — RFC 8739 STAR short-term auto-renewed certs (done
      2026-07-06, `make check-star`)

---

## Add 1: RFC 9773 — ACME Renewal Information (ARI) — DONE 2026-07-01

### What it is

ARI lets the CA tell the client *when* to renew, via a `renewalInfo` resource
carrying a suggested renewal window. Renewal becomes **CA-driven** instead of a
fixed timer, which lets a CA stagger renewals and request early renewal during a
mass-revocation event. For an auto-renewing `certd` this is the single most
valuable modern addition.

### What was built

- `ari_cert_id(X509 *cert, char *out, size_t outsz)` computes the RFC 9773
  §4.1 CertID: `base64url(AKI keyIdentifier) + "." + base64url(serial value
  bytes)`, both unpadded (`b64url_enc` from libdnswire already omits padding).
  Returns -1 for certs without an AKI extension (ARI is simply not offered
  for those — self-signed/non-ACME certs).
- `rfc3339_to_epoch` parses the `suggestedWindow` `start`/`end` timestamps
  with `timegm` (not `mktime` — the window is always UTC).
- `ari_fetch_window(const char *cert_id, time_t *win_start, time_t *win_end)`
  does the unauthenticated GET `{renewalInfo}/{certID}` (§4.2), parses
  `suggestedWindow` via the existing flat-scan `json_str` helper (works fine
  even though the field is nested — key names are unambiguous), and logs
  `Retry-After` for visibility (the existing daily `RENEW_CHECK_SECS` tick is
  already within the RFC's own "over one day is fine" guidance, so no
  separate poll scheduler was added).
- `acme_needs_renewal` refreshes the ACME directory first (`acme_directory`)
  so a freshly started certd — which has never run `acme_issue` and so never
  populated `g_acme_dir_renewalinfo` — still gets ARI on its very first
  check, then tries the ARI branch and renews at a randomized point inside
  the window (never exactly at the start, §4.1), falling back to the
  existing fixed-threshold check whenever ARI is absent/unreachable/
  malformed.

### Guardrail (respected)

- Never renews exactly at the window start — randomized (`rand()`-scaled)
  point inside `[start, end]`.
- Never blocks renewal on ARI availability — any failure in the ARI path
  (`ari_cert_id` or `ari_fetch_window` returning non-zero) falls through to
  the fixed-threshold check unconditionally.
- `Retry-After` is logged (informational); not separately enforced, since the
  daily tick already sits inside the RFC's stated acceptable range.

### Test

`make check-ari`: a local CA + a minimal Python HTTPS stub serve just an ACME
directory (so `acme_directory()` succeeds) and `/renewal-info` — not full
issuance, which still needs a real/staging CA (e.g. Pebble) as this section
originally specified. Confirms a future `suggestedWindow` logs "not yet due"
and a past one logs "renewing", both via the `[ACME] ARI window …` log line.

---

## Add 2: RFC 8737 — ACME TLS-ALPN-01 (optional) — DONE 2026-07-06

### What it is

A second challenge type validated over a TLS handshake with the `acme-tls/1`
ALPN protocol on port 443, instead of a DNS-01 TXT record. DNS-01 remains the
default (no inbound port needed); tls-alpn-01 is for identifiers DNS-01 can't
validate — chiefly RFC 8738 IP identifiers (Add 3), since dns-01 has no
defined meaning for the "ip" type.

### What was built

- `config:acme_challenge_type` (`dns-01` default, or `tls-alpn-01`) and
  `config:acme_tls_alpn_port` (default 443, overridable for a private CA or a
  NAT/port-forward setup — the real Let's Encrypt requires exactly 443, a
  private ACME server need not).
- `tlsalpn01_make_cert()` builds an ephemeral, self-signed EC P-256 cert per
  validation attempt: a SAN matching the identifier (shared `make_san_ext()`
  helper, also used by the real CSR — Add 3) plus the critical
  `id-pe-acmeIdentifier` extension (OID `1.3.6.1.5.5.7.1.31`, RFC 8737 §3)
  wrapping the SHA-256(keyAuthorization) digest — the exact same digest
  dns-01 base64url-encodes into its TXT record, computed once in
  `acme_issue` and passed in raw for this path. The key and cert are
  discarded the moment the challenge window closes; they never touch
  `cert:current` or the real server identity.
- `tlsalpn01_start()`/`tlsalpn01_stop()`: a real inbound TLS listener
  (dual-stack IPv6 bind falling back to IPv4-only), an `SSL_CTX_set_
  alpn_select_cb` that can only ever negotiate `acme-tls/1` (its server
  preference list contains nothing else, so a client that doesn't offer it
  gets a fatal `no_application_protocol` alert — RFC 8737 §3's "MUST NOT
  negotiate" requirement falls out of the API for free rather than needing
  a manual check), and a low-concurrency accept-and-close loop: per RFC
  8737 §3 the validator proves possession purely by completing the
  handshake, so the server sends no application data and closes right
  after — adequate for a private/internal registry's validation traffic,
  not meant to survive a flood.
- `acme_issue()` picks the challenge type per identifier (forcing
  tls-alpn-01 for an "ip" identifier regardless of config, logging when it
  overrides an explicit `dns-01` setting), starts the listener before
  POSTing to the challenge URL, and tears it down right after the authz
  poll loop — mirroring the dns-01 TXT publish/delete lifecycle exactly.

### Guardrail (respected)

- **First inbound listener certd has ever had.** Previously purely an
  outbound HTTPS client (to the CA/EST server); this add gives it a brief,
  narrow internet-facing input surface during a challenge only. Added
  `signal(SIGPIPE, SIG_IGN)` to `main()` for the same reason every other
  listening daemon (`dnsd`/`apid`/`mdnsd`/`resolverd`/`eppd`) already has it
  — a validator resetting the connection mid-handshake must not SIGPIPE-kill
  the daemon.
- Never reuses the real server key/cert for the challenge — always a fresh
  ephemeral EC key, discarded after the window closes.
- Never negotiates anything but `acme-tls/1` on this listener (see above).

### Test

`make check-acme-challenges` (`tests/test_certd_challenges.c`, `#define
UNIT_TEST 1; #include "certd.c"` — same convention as `tests/test_eppd.c`):
KATs for the SAN builder (IP vs. DNS) and the acmeIdentifier extension
encoding, plus a **live** handshake test against the real
`tlsalpn01_start` listener — a client offering `acme-tls/1` completes the
handshake and receives a cert with the correct SAN + digest; a client
offering a different protocol (`http/1.1`) is refused. Matches `check-ari`'s
own precedent of testing the new isolated piece directly rather than
standing up a full mock ACME server (still needs a real/staging CA for that).

## Add 3: RFC 8738 — ACME for IP Identifiers (optional) — DONE 2026-07-06

### What it is

Issue certs for IP addresses (`iPAddress` identifier) instead of a DNS name —
useful for internal service endpoints and the management API's own cert.

### What was built

- `is_ip_literal()` (via `inet_pton`) drives the split everywhere an
  identifier value is used: the ACME order request now sends
  `{"type":"ip","value":"..."}` instead of `{"type":"dns",...}` when the
  configured `config:acme_domain` is actually an IP literal; `make_san_ext()`
  (shared with the TLS-ALPN-01 challenge cert, Add 2) builds an `IP:` SAN
  instead of `DNS:`; `make_csr_der`/`acme_gen_csr` take an `is_ip` flag
  through to the final issued cert's CSR.
- Because dns-01 has no defined meaning for the "ip" identifier type
  (RFC 8555 §8.4 only defines it for `dns`), an IP identifier **forces**
  `tls-alpn-01` (Add 2) as the challenge type regardless of
  `config:acme_challenge_type` — logged when it overrides an explicit
  `dns-01` setting. The two adds shipped together for this reason: Add 3 in
  isolation would build a valid order/CSR but could never complete
  validation.

### Test

Covered by the same `make check-acme-challenges` run as Add 2: the CSR-SAN
KAT explicitly checks both an IP-identifier CSR (SAN is `IP:192.0.2.55`) and
a DNS-identifier CSR (SAN is still `DNS:www.example.local`, proving the
existing dns-01 path is untouched).

---

## Integration items (glue, not new protocols)

### Publish DANE/TLSA for issued certs (6698/7671) — already done, elsewhere

This was tracked here as open but is actually already satisfied: `dnsd` itself
(not `certd`) computes the TLSA record (`3 1 1` = DANE-EE, SHA-256 of the
SubjectPublicKeyInfo, owner from the cert's SAN/CN) and publishes it whenever
`cert:current` changes (`cert_publish_tlsa` in `dns_server.c`, called from the
same watcher that hot-reloads TLS), then bumps the SOA serial and NOTIFYs.
`certd`'s only job is writing `cert:current` — the loop closes on `dnsd`'s
side, which already owns TLSA-on-cert-change per `CLAUDE.md`'s Valkey
ownership table. Left as a checklist item pointing here so a future reader
doesn't rediscover the same "is this done?" question from `certd`'s side.

### Honor CAA before issuance (8659) — DONE 2026-07-06

`certd` reads `zone:<zone>:CAA:<name>` directly off Valkey (rather than
making a real DNS query — `dnsd` already owns/serves this data, and Valkey is
the integration bus per this project's design principle #2) before ever
contacting the ACME CA. `find_owning_zone` mirrors `eppd`'s own
`find_parent_zone` (longest-suffix match against `zone_table:*`, falling back
to `config:zone_name` for the primary zone); `caa_authorizes` then walks up
one label at a time from the identifier (RFC 8659 §5.3 tree-climbing) until
it finds a CAA RRset or reaches the zone apex with none. A found RRset's
`issue` property is matched against the configured ACME endpoint's hostname
(exact match or the endpoint being a subdomain of it — e.g. Let's Encrypt's
`acme-v02.api.letsencrypt.org` correctly matches an operator-published
`issue "letsencrypt.org"`); no CAA RRset anywhere in the chain defaults to
allow, per the RFC. Only IP identifiers (RFC 8738) skip the check — CAA is
name-based and has no defined meaning for an `ip` type identifier.

This is a fast-fail pre-flight, not a substitute for the CA's own mandatory
CAA check: if the owning zone can't be determined (e.g. Valkey down), `certd`
proceeds rather than blocking every renewal on an infra hiccup — the same
permissive-on-failure posture ARI already uses when its fetch fails. Only an
explicit, successfully-read CAA denial refuses the request.

Test: `make check-caa` — no stub ACME server needed, since a denial is
provable purely from the log before certd ever contacts the CA; the two
"should proceed" cases point `config:acme_ca` at `127.0.0.1:1` (a
guaranteed-closed port) so the subsequent directory fetch fails fast and
distinctly (`Directory failed`) instead of hanging on a real network call.
Covers: a mismatched `issue` value refusing (with tree-climbing from a
subdomain up to the apex's CAA record), a matching `issue` value proceeding,
and an absent CAA record defaulting to allow.

---

## Roadmap: RFC 8739 — STAR (Short-Term, Automatically Renewed) certs — DONE 2026-07-06

### What it is

Short-lived certs auto-renewed by the CA without per-renewal client action:
one authorization/order yields a stream of certs over the order's lifetime,
each fetched from a fixed URL rather than reissued from scratch. Reduces
reliance on revocation entirely. This is a genuinely different renewal
*model* from the rest of `certd` (fixed-cadence full reissuance), not a
variant of it — opted into per-domain via `config:acme_star_enabled`.

### What was built

- Directory capability discovery: `acme_directory()` now also parses
  `meta.auto-renewal.{min-lifetime,max-duration,allow-certificate-get}` via
  two new tiny scanners, `json_int`/`json_bool` (added because the existing
  `json_str` only reads quoted-string values — these directory fields are
  bare JSON integers/booleans). `g_acme_star_supported` gates the rest.
- Order construction: when enabled, supported, and the identifier isn't an
  IP (RFC 8739 doesn't address `ip` identifiers), `acme_issue()` adds a
  sibling `"auto-renewal":{"end-date":...,"lifetime":...,"lifetime-adjust":...}`
  object to the newOrder payload — `end-date` computed from
  `config:acme_star_duration_secs` (clamped to the CA's `max-duration`),
  `lifetime` from `config:acme_star_lifetime_secs` (clamped up to the CA's
  `min-lifetime`).
- Once the order polls `"valid"`, `acme_issue()` checks for a
  `"star-certificate"` field (instead of the normal `"certificate"` field).
  If present: this is a recurrent order. The CSR's private key — reused for
  *every* future fetch, since STAR has no per-refresh CSR/finalize step — is
  persisted to `acme:star_key_pem`, alongside `acme:star_order_url`/
  `acme:star_cert_url`/`acme:star_end_epoch`/`acme:star_allow_get`, then the
  first cert is fetched immediately rather than waiting for the next tick.
- `acme_star_tick()` (called from `renewal_check()` instead of the normal
  `acme_needs_renewal()`/`acme_issue()` pair, for any domain that is either
  STAR-enabled or still has a recorded recurrent order) has three outcomes:
  establish a new order (no active/unexpired one — reuses `acme_issue()`
  wholesale, CAA pre-flight included), a lightweight refresh
  (`acme_star_needs_refresh()` says the current cert is within
  `config:acme_star_renew_before_secs`, default half the configured
  lifetime, of expiry — fetches via `acme_star_fetch_cert` and pairs the new
  chain with the *persisted* key, no authorization touched at all), or
  cancel-and-clear (feature turned off while an order is still active —
  `acme_star_cancel` POSTs `{"status":"canceled"}` to the order URL per RFC
  8739 §5, then all `acme:star_*` keys are deleted so a future re-enable
  starts clean).
- `acme_star_fetch_cert()` fetches via unauthenticated GET if the CA granted
  `allow-certificate-get`, else an authenticated POST-as-GET — reusing
  `acme_post`'s existing empty-payload convention, the same primitive
  already used to poll authz/order status.

### Test

`make check-star` (`tests/star_stub.py`) implements just enough ACME to
drive one full dns-01 order/authz/challenge/finalize cycle, plus the STAR
directory meta and a `star-certificate` fetch endpoint that alternates
between two distinct pre-generated certs (`star-cert-a` then `star-cert-b`)
and a per-path hit counter exposed at `/__stats`. Three phases, one Valkey +
one running stub, all against the real `certd_debug --once`:

1. **Establish** — `cert:current` ends up as `star-cert-a`; `/new-order`,
   `/authz/1`, `/chal/1`, `/finalize/1` each hit exactly once.
2. **Refresh** — a second `--once` run (with `config:acme_star_renew_before_secs`
   set high enough that the 1-day-valid cert A already qualifies) ends with
   `cert:current` as `star-cert-b`, while `/new-order`/`/authz/1`/`/chal/1`/
   `/finalize/1` hit-counts are **unchanged** from phase 1 and only
   `/star-cert/1` incremented — the test's actual proof that a refresh never
   re-authorizes.
3. **Cancel** — `config:acme_star_enabled` flipped off, a third `--once` run
   POSTs the cancellation (`/order/1`'s hit-count increases) and
   `acme:star_order_url` is gone from Valkey afterward.

Re-ran `make check-caa`, `make check-acme-challenges`, and `make check-ari`
afterward — all still pass; STAR's new `renewal_check()` branch is
completely inert for a domain that never sets `config:acme_star_enabled`
and has no recorded recurrent order, so the existing fixed-cadence tests are
unaffected.

## Guardrails (whole daemon)

- **Do NOT** let `certd` serve DNS — challenges go through `dnsd` over Valkey/API.
- **Do NOT** switch the live cert before its DANE TLSA is published.
- **Do NOT** run cert renewal in two places — when split, only `certd` renews;
  `dnsd` is read-only on `tls:cert`/`tls:key` (the `enable_pki_renewal` toggle
  from `CLAUDE-ENUM.md` keeps any second instance out of the renewal business).
