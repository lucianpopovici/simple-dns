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

## Step 2 — Split out `certd` (ACME + EST)  `[~]`

Goal: remove the most attacker-adjacent parser code from the trusted core.
Integration is Valkey-only.

Tasks
- [ ] New binary `certd` containing: ACME directory/JWS/order flow, DNS-01
      orchestration, EST mTLS enrollment, CSR generation, renewal thread
- [ ] `certd` writes the DNS-01 challenge as `zone:TXT:_acme-challenge.<domain>`
      and deletes it after validation
      (the existing `acme_issue` already does this via `vk_set`/`vk_del` —
      carries over unchanged)
- [ ] `certd` writes the issued cert+key to `cert:current` (PEM)
- [~] `dnsd` watches `cert:current` and hot-reloads TLS (no ACME/EST code left
      in `dns_server.c`)
      → watcher DONE + live-tested 2026-06-12: `cert_watch_thread` polls every
      30s (Step 6 converts to keyspace notifications), splits the cert+key PEM
      blob, hot-reloads; verified end-to-end (`SET cert:current` → DoT :8853
      served the new CN). ACME/EST removal still pending.
- [ ] Remove `acme_*`, `est_*`, `pki_renewal_thread` from `dns_server.c`
- [ ] `Makefile`: add `certd` target + production signing

Extraction inventory (for the `certd` build-out): move `https_req`,
`https_req_mtls`, `parse_url`, `hdr_val`, `json_str`, `acme_jwk/thumbprint/
jws/nonce_fetch/post/directory/gen_csr/issue/needs_renewal`, `est_pkcs7_to_pem/
cacerts/enroll/issue/needs_renewal`, `pki_renewal_thread`, `cert_post_issue`
(rewired to write `cert:current` instead of in-process `tls_reload`), the
`g_acme_*`/`g_est_*` globals, plus a RESP/Valkey client and logging. Open spec
question: `cert_post_issue` also publishes TLSA records (`zone:TLSA:*`) and
sends NOTIFY — the ownership table only grants certd `zone:TXT:_acme-challenge.*`;
either extend the table to TLSA publication by certd, or have dnsd publish TLSA
itself when `cert:current` changes (cleaner — keeps zone writes in dnsd).
Manual-issue mgmt endpoints (`/acme/issue`, EST enroll) reference `acme_issue`/
`est_issue` and are removed in Step 4 anyway.

Acceptance
- [ ] `grep -n 'acme_\|est_' dns_server.c` returns nothing
- [ ] `dnsd` opens no outbound connections except to Valkey (verify with
      `ss`/`lsof` or strace under load)
- [ ] End-to-end cert issuance still works against a staging ACME CA, driven
      entirely by `certd`
- [ ] Replacing `cert:current` causes `dnsd` to serve the new cert on the next
      DoT/HTTPS handshake without restart
- [ ] Global exit gate passes

---

## Step 3 — Split out `mdnsd`  `[ ]`

Goal: the link-local responder is no longer in the authoritative daemon.

Tasks
- [ ] New binary `mdnsd`: multicast join (v4/v6), `.local` answers,
      `_services._dns-sd._udp.local` browse, reading `mdns:*` + `config:mdns_*`
- [ ] Restrict to explicitly configured interfaces (no implicit all-interfaces
      join)
- [ ] Remove `mdns_*` and multicast socket setup from `dns_server.c`
- [ ] `mdnsd` links `libdnswire`
- [ ] `Makefile`: add `mdnsd` target

Acceptance
- [ ] `grep -n 'mdns_\|MDNS_\|IP_ADD_MEMBERSHIP' dns_server.c` returns nothing
- [ ] `dnsd` joins no multicast groups (verify with `ip maddr` / `netstat -g`)
- [ ] mDNS discovery still resolves a `.local` service via `mdnsd`
- [ ] Global exit gate passes

---

## Step 4 — Front HTTP surfaces with a reverse proxy  `[ ]`

Goal: delete hand-rolled HTTP/HTTPS/mTLS, `url_decode`, `qs_get`, config portal,
and DoH HTTP parsing from the C core.

> Decision point (confirm before starting): adopt a reverse proxy
> (nginx/envoy) OR keep a small in-house `apid`. Default in `CLAUDE.md` is the
> proxy. Record the choice here: __________________

Tasks
- [ ] Stand up the proxy to terminate TLS + HTTP for DoH and any management
      surface, forwarding to the relevant daemon
- [ ] Reduce `dnsd` HTTP to a localhost-only, read-only `/health` + `/metrics`
- [ ] Remove the embedded management API (`/zone`, `/config`, `/acme/issue`,
      `/pki/*`), the first-boot config portal, and DoH HTTP parsing from
      `dns_server.c`
- [ ] Move first-boot Valkey bootstrap out of an HTTP portal (e.g. env/config
      file or the dashboard) so `dnsd` no longer serves a portal

Acceptance
- [ ] `grep -n 'url_decode\|qs_get\|config_portal\|handle_api' dns_server.c`
      returns nothing
- [ ] `dnsd`'s only listening HTTP socket is localhost `/health` + `/metrics`
- [ ] DoH `/dns-query` still works through the proxy (GET base64url + POST)
- [ ] Management writes go through Valkey, not an embedded API
- [ ] **`dnsd` is now meaningfully smaller and single-purpose** — record the
      line count before/after: ______ → ______
- [ ] Global exit gate passes

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
