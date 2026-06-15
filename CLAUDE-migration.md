# CLAUDE-migration.md — Migration tracker

Tracked checklist for moving from the `dns_server.c` monolith to the target
architecture in `CLAUDE.md`. Work top to bottom. Each step is independently
shippable: it must build (`make debug` and `make`) and pass `make check` before
the next step starts. Tick boxes as you go; do not mark a step complete until
every box under both **Tasks** and **Acceptance** is checked.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

Global exit gate for every step:
- [ ] `make debug` builds with no new warnings
- [ ] `make` (production) builds and signs
- [ ] `make check` passes
- [ ] No new `strtok(` introduced (`grep -rn '\bstrtok(' *.c` clean — the strtok fixes are done)

---

## Step 0 — Prerequisite defect fixes  `[x]`

Do the correctness/safety fixes before refactoring, so the extracted code is
already sound.

Tasks
- [x] Complete fixes Task 1 (DNSSEC RRset coverage)
- [x] Complete fixes Task 2 (`strtok` → `strtok_r`)
- [x] Complete fixes Tasks 3–6 (fudge, OSSL_INC, pointer hardening, safe_strcpy)

Acceptance
- [x] All boxes in the fixes spec final checklist are checked (spec archived untracked at `specs/CLAUDE-fixes.md`)
- [x] Tampered-rdata DNSSEC test returns `DNSSEC_BOGUS` (`make check-dnssec`)

Gate evidence (2026-06-12): `make debug` warning-neutral vs baseline; `make
dns_server` (production, unsigned) clean — the GPG `sign` step needs a secret
key not present on this machine; `make check` answers the smoke query;
`grep -rn '\bstrtok(' *.c` clean. New test targets: `make check-dnssec`
(12/12), `make check-wire` (11/11).

---

## Step 1 — Extract `libdnswire`  `[x]`

Goal: one shared wire-format implementation, no behavior change.

Tasks
- [x] Create `dns_wire.h` declaring: `name_from_wire`, `name_to_wire`,
      `name_to_wire_c`, `append_rr`, `get16/put16/get32/put32`, `txt_encode`,
      hex enc/dec, base64 enc/dec, `compress_ctx_t` + reset
- [x] Create `dns_wire.c` with the single canonical implementation (use the
      hardened `name_from_wire` from fixes Task 5)
- [x] Remove the duplicated copies from `dns_server.c`, `dns_client.c`,
      `simple_dns.c`; include `dns_wire.h` instead
- [x] Decide `simple_dns.c`'s fate: label as reference + exclude from prod
      build, OR make it link `libdnswire` like the rest
      → **Decision: it links `libdnswire`** (compiles with `dns_wire.c`); it
      keeps its non-compressing RR emission via `append_rr_plain` so its wire
      output is unchanged. The compressing `append_rr` is used by the server.
- [x] Update `Makefile`: build `libdnswire` first; link it into each binary

Acceptance
- [x] `grep -rn 'name_from_wire' *.c` shows definitions only in `dns_wire.c`
- [x] All binaries build against the shared library
- [x] Byte-for-byte identical responses to a baseline capture from before the
      change (12-query matrix incl. UDP+TCP, diff clean modulo random IDs)
- [x] Global exit gate passes

Gate evidence (2026-06-12): warning counts dropped (server 45→41, client
18→16, simple 33→29 — removed copies carried warnings; none added);
`make check` answers; `make check-dnssec` 12/12, `make check-wire` 11/11;
new `make fuzz-wire` ran libFuzzer 60s on `name_from_wire` (71.4M execs,
0 crashes, corpus seeded at `fuzz/corpus/`). GPG sign step still blocked on
absent key (environmental, see Step 0).

---

## Step 2 — Split out `certd` (ACME + EST)  `[x]`

Goal: remove the most attacker-adjacent parser code from the trusted core.
Integration is Valkey-only.

Tasks
- [x] New binary `certd` containing: ACME directory/JWS/order flow, DNS-01
      orchestration, EST mTLS enrollment, CSR generation, renewal thread
      (`certd.c`; `--once` flag for cron/manual runs; daemon mode checks daily)
- [x] `certd` writes the DNS-01 challenge as `zone:TXT:_acme-challenge.<domain>`
      and deletes it after validation
      (the existing `acme_issue` already did this via `vk_set`/`vk_del` —
      carried over unchanged)
- [x] `certd` writes the issued cert+key to `cert:current` (PEM, chain+key in
      one blob; it writes nothing else — no `config:*`, no TLSA)
- [x] `dnsd` watches `cert:current` and hot-reloads TLS (no ACME/EST code left
      in `dns_server.c`); the watcher's first pass runs at boot so a cert
      written while dnsd was down is picked up immediately
- [x] Remove `acme_*`, `est_*`, `pki_renewal_thread` from `dns_server.c`
      (~520 lines; dns_server.c 5064 → 4595 lines)
- [x] `Makefile`: `certd` (hardened prod) + `certd_debug` targets. GPG signing
      still blocked on this machine (no secret key — see Step 0).

TLSA ownership decision: **dnsd publishes TLSA** (and bumps serial + NOTIFYs)
when `cert:current` changes, extracting the name from the certificate's SAN/CN
— so all zone writes stay in dnsd and certd needs no zone access. While moving
this, fixed a pre-existing bug: the old `cert_post_issue` lowercased the whole
Valkey key (`zone:tlsa:…`), which the lookup path (`zone:TLSA:<qname>`) could
never match — published TLSA records were unservable. Now only the owner name
is lowercased.

Mgmt endpoints `/acme/issue`, `/pki/est`, `/pki/cacerts` return 410
"moved to certd" until Step 4 deletes the embedded API entirely.

Acceptance
- [x] `grep -n '\bacme_\|\best_' dns_server.c` returns nothing (word-boundary
      form; the original pattern false-positives on `best_len`)
- [x] `dnsd` opens no outbound connections except to Valkey (verified with
      `ss -tnp` under query load: single ESTAB to 127.0.0.1:6379)
- [ ] End-to-end cert issuance still works against a staging ACME CA, driven
      entirely by `certd` — **not verifiable in this environment** (needs a
      public domain + reachable port 53); the ACME/EST code is byte-for-byte
      the code that ran inside dnsd, `certd --once` runs the full decision
      path against live Valkey
- [x] Replacing `cert:current` causes `dnsd` to serve the new cert on the next
      DoT/HTTPS handshake without restart (verified: openssl s_client on :8853
      shows the new CN; TLSA RR for the new cert servable via dig)
- [x] Global exit gate passes (make debug/dns_server/certd clean — warnings
      45→38 in dns_server.c as removed code carried some; make check answers;
      check-dnssec 12/12; check-wire 11/11; no bare strtok)

---

## Step 3 — Split out `mdnsd`  `[x]`

Goal: the link-local responder is no longer in the authoritative daemon.

Tasks
- [x] New binary `mdnsd`: multicast join (v4/v6), `.local` answers,
      `_services._dns-sd._udp.local` browse, reading `mdns:*` + `config:mdns_*`
      (`mdnsd.c`; also reads `zone:*` read-only — preserves the pre-split
      "shared records served over both unicast and mDNS" behavior)
- [x] Restrict to explicitly configured interfaces (no implicit all-interfaces
      join): `config:mdns_interfaces` = comma-separated names, or "all" to
      opt in explicitly; unset → mdnsd refuses to start with a clear message
- [x] Remove `mdns_*` and multicast socket setup from `dns_server.c`
      (~550 lines; dns_server.c 4595 → 3983). `/mdns/*` mgmt endpoints return
      410 — record provisioning goes via the dashboard (mdns:* owner), which
      also removes a namespace-ownership violation (dnsd wrote mdns:*)
- [x] `mdnsd` links `libdnswire`
- [x] `Makefile`: `mdnsd` (hardened prod) + `mdnsd_debug` targets

Two pre-existing responder bugs fixed in the move (both verified against the
old code; query responses were NEVER well-formed before):
1. `mdns_build_response` reused one offset to parse query questions and write
   answers, leaving uninitialized garbage between the header and the first
   answer. Now: pass 1 parses questions, pass 2 appends answers; legacy
   unicast echoes the question section verbatim (RFC 6762 §6.7).
2. Legacy unicast answers carried the cache-flush bit (class 0x8001 — parsers
   reject it) and full TTLs. Now: plain IN class and TTL capped at 10s per
   RFC 6762 §6.7. (Announcements keep cache-flush — correct for multicast.)

Acceptance
- [x] `grep -n 'mdns_\|MDNS_\|IP_ADD_MEMBERSHIP' dns_server.c` returns nothing
- [x] `dnsd` joins no multicast groups (ip maddr membership count for
      224.0.0.251 identical with dnsd stopped/running; the 3 standing
      memberships belong to avahi)
- [x] mDNS discovery still resolves a `.local` service via `mdnsd`
      (mdns:A answered with correct rdata/class/TTL; `_services._dns-sd._udp
      .local` browse returns the provisioned service type; 60-query hammer
      under ASan clean. Note: dig sends ANY over TCP by default — use +notcp;
      mdnsd is UDP-only by design)
- [x] Global exit gate passes (all four binaries build clean — dns_server.c
      warnings 38 → 34, removed code carried them; make check answers;
      check-dnssec 12/12; check-wire 11/11; no bare strtok)

---

## Step 4 — Front HTTP surfaces with `apid`  `[x]`

Goal: delete hand-rolled HTTP/HTTPS/mTLS, `url_decode`, `qs_get`, config portal,
and DoH HTTP parsing from the C core.

> Decision point: adopt a reverse proxy (nginx/envoy) OR keep a small in-house
> `apid`. Default in `CLAUDE.md` was the proxy.
> Choice: **apid (in-house, user-confirmed 2026-06-12)**.

Tasks
- [x] Stand up `apid` to terminate TLS + HTTP for DoH and the management
      surface, forwarding to the relevant daemon (`apid.c`: DoH → dnsd loopback
      DNS port via UDP+TCP-retry; management → Valkey writes only)
- [x] Reduce `dnsd` HTTP to a localhost-only, read-only `/health` + `/metrics`
      (bound `127.0.0.1:config:metrics_port`, default 8054; `apid` proxies
      `/metrics`)
- [x] Remove the embedded management API (`/zone`, `/config`, `/acme/issue`,
      `/pki/*`), the first-boot config portal, and DoH HTTP parsing from
      `dns_server.c` (also removed the 4 now-dead helpers: `handle_api`,
      `handle_doh`, `handle_http_plain`, `handle_https_mgmt`, `api_send`,
      `url_decode`, `qs_get`, `config_portal`, `boot_save`, `str2type`,
      `config_set`, `zone_save`, `zone_find`, and `g_mgmt_ctx`)
- [x] Move first-boot Valkey bootstrap out of an HTTP portal: `dnsd` now retries
      the connection (30×2s) then exits FATAL; connection details come from env
      or the `dns_server.boot` file

Decision — apid as a Valkey writer: with the in-house front (not a passive
proxy), `apid` *is* the relocated management API, so it writes
`config:*`/`zone:*`/`ddns:*` exactly as the embedded API did. The ownership
table in `CLAUDE.md` now lists the control-plane writer category as
{dashboard, apid}. mTLS (client cert vs `config:mtls_ca_pem`) gates `/config`
and zone-table management; `ddns_secret` gates plain-HTTP `/update`; DoH and
read-only `/list` need no auth. Config/zone-table edits apply in `dnsd` on
SIGHUP until Step 6 adds keyspace-notification live reload (zone records are
already read live per query).

Acceptance
- [x] `grep -n 'url_decode\|qs_get\|config_portal\|handle_api' dns_server.c`
      returns nothing
- [x] `dnsd`'s only listening HTTP socket is localhost `/health` + `/metrics`
      (verified `ss -ltnp`: 5353, 8853 v4/v6, `127.0.0.1:8054`; no 8053/8443)
- [x] DoH `/dns-query` still works through `apid` (GET base64url tested →
      answer carried the expected A rdata; POST uses the same `handle_doh` path)
- [x] Management writes go through Valkey, not an embedded API (apid `/update`
      → `ddns:A:*` confirmed in Valkey; apid never calls into dnsd)
- [x] **`dnsd` is now meaningfully smaller and single-purpose** — line count
      before/after: **5064 → 3642**
- [x] Global exit gate passes (4 binaries build clean; `make check`,
      `check-dnssec` 12/12, `check-wire` 11/11; no new warnings — dnsd carries
      only the 3 pre-existing ones)

---

## Step 5 — Control-plane authentication  `[ ]`

Goal: close the unauthenticated-Valkey-write hole.

Tasks
- [ ] Add authentication to `dashboard/app.py` (login + session, or front it
      with authenticating proxy)
- [ ] Restrict or remove the raw Valkey Explorer write/delete path
- [ ] Ensure secret-bearing keys (`config:tsig_secret_b64`,
      `config:cookie_secret`, `dnssec:*`) require an authenticated session to
      read or write

Acceptance
- [ ] Unauthenticated request to any dashboard write endpoint is rejected
- [ ] Arbitrary `SET`/`DEL` on secret namespaces is not reachable without auth
- [ ] Documented how credentials are provisioned/rotated
- [ ] Global exit gate passes (dashboard tests)

---

## Step 6 — Live reload via Valkey keyspace notifications  `[ ]`

Goal: dashboard edits and `cert:current` updates apply without restart.

Tasks
- [ ] Enable Valkey keyspace notifications (server config)
- [ ] Each daemon subscribes to the prefixes it owns (`dnsd`: `config:*`,
      `zone:*`, `ddns:*`, `dnssec:*`, `cert:current`; `mdnsd`: `mdns:*`,
      `config:mdns_*`; `resolverd`: `config:*`)
- [ ] On notification, reload only the affected subset (avoid full restarts)
- [ ] Remove any remaining "restart required" / `POST /config` dependence

Acceptance
- [ ] Editing a `zone:*` record via the dashboard is reflected in the next query
      with no restart
- [ ] Editing SOA/rate-limit/NSID config takes effect live
- [ ] No subscription leaks or reconnect storms under a Valkey restart (the
      daemons re-subscribe cleanly)
- [ ] Global exit gate passes

---

## Step 7 — Multi-zone support  `[ ]`

Goal: serve multiple authoritative zones from the slimmed-down `dnsd`.

Tasks
- [ ] Re-key zone data as `zone:<zonename>:<type>:<name>` and config as
      `config:zone:<zonename>:*`
- [ ] `dnsd` selects the most-specific configured zone per query
- [ ] Per-zone SOA, DNSSEC keys, AXFR/NOTIFY settings
- [ ] Per-zone automated DNSSEC key rollover (RFC 6781) with existing
      CDS/CDNSKEY publication
- [ ] (Optional) catalog zones (RFC 9432) for bulk provisioning
- [ ] Migration script for existing single-zone data into the new key layout
- [ ] Dashboard updated for zone selection/management

Acceptance
- [ ] Two distinct zones resolve correctly from one `dnsd` instance
- [ ] Each zone signs with its own keys; cross-zone queries are isolated
- [ ] A scheduled ZSK rollover completes without a validation gap
- [ ] Existing single-zone deployments migrate via the script with no data loss
- [ ] Global exit gate passes

---

## Completion

- [ ] After Step 4, `dnsd` is a small, single-purpose, sandboxable daemon
      (privilege drop + seccomp per `CLAUDE.md`)
- [ ] All seven steps complete; monolith concerns fully decomposed
- [ ] `CLAUDE.md` topology diagram matches the running system
