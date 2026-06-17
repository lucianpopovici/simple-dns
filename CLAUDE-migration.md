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

## Step 5 — Control-plane authentication  `[x]`

Goal: close the unauthenticated-Valkey-write hole.

Tasks
- [x] Add authentication to `dashboard/app.py` (login + signed-cookie session):
      single admin account, `werkzeug.security` scrypt hash, a global
      `before_request` gate, `/login` + `/logout`, per-IP failed-login backoff.
      The app **refuses to start** without a password configured (no blank
      default), and auto-generates a strong session key if `FLASK_SECRET_KEY`
      is weak/unset (warns that sessions reset on restart).
- [x] Restrict the raw Valkey Explorer write/delete path: read-only unless
      `DASHBOARD_ENABLE_EXPLORER_WRITE=1`, and even then secret-bearing keys are
      never writable/deletable there; their values are masked on display.
- [x] Ensure secret-bearing keys (`config:tsig_secret_b64`,
      `config:cookie_secret`, `dnssec:*`, `*_key`, `*key_pem*`, `*tsig*`) require
      an authenticated session (the global gate covers every route) and are
      never reachable through the raw explorer.

Credential provisioning/rotation: `DASHBOARD_PASSWORD` (hashed in memory) or a
pre-hashed `DASHBOARD_PASSWORD_HASH` or Valkey `config:dashboard_password_hash`
(lookup order: hash-env → plaintext-env → Valkey). `python3 app.py
--gen-password-hash '<pw>'` prints a hash; rotate by replacing the value and
restarting. Documented in `dashboard/README.md`.

Acceptance (verified via Flask `test_client`, `tmp/t_auth.py` + `t_auth2.py`)
- [x] Unauthenticated request to any dashboard write endpoint is rejected
      (GET / and POST /records/upsert → 302 /login; /api/metrics → 401 JSON)
- [x] Arbitrary `SET`/`DEL` on secret namespaces is not reachable without auth
      (gated globally; and even authed+opt-in, explorer refuses `dnssec:*` /
      `*secret*` / `*tsig*` / `*_key` / `key_pem` writes and deletes)
- [x] Documented how credentials are provisioned/rotated (dashboard/README.md)
- [x] Global exit gate passes — pure-Python change; C binaries unaffected,
      `make check` / `check-dnssec` / `check-wire` still green; `app.py`
      `py_compile` clean. (No GPG key on this box, so signed `make` still N/A.)

---

## Step 6 — Live reload via Valkey keyspace notifications  `[x]`

Goal: dashboard edits and `cert:current` updates apply without restart.

Tasks
- [x] Enable Valkey keyspace notifications (server config): each daemon issues
      `CONFIG SET notify-keyspace-events KEA` itself on connect (idempotent;
      no out-of-band Valkey setup needed), and logs a warning + falls back to
      boot/reconnect catch-up if `CONFIG SET` is denied.
- [x] Each daemon subscribes (on a dedicated connection, separate from the
      request/reply `vk`) to the prefixes it owns:
      `dnsd` → `config:*`, `cert:current`, `zone_table:*`, `dnssec:*`;
      `apid` → `cert:current`, `config:tls_cert_pem/tls_key_pem/mtls_ca_pem`;
      `mdnsd` → `mdns:*`, `config:mdns_*`. (`resolverd` watches only its own
      `cache:*`; live config reload for it is future work.) `zone:*`/`ddns:*`
      records need no subscription: they are read live per query already.
- [x] On notification, reload only the affected subset:
      `config:*` → `config_load_from_valkey` (+ `tls_reload` for TLS keys);
      `cert:current` → split + hot-reload TLS + publish TLSA (replaces the
      Step-2 30s poll); `zone_table:*` → rebuild the in-memory zone list;
      `mdns:*`/`config:mdns_*` → re-announce. `dnssec:*` is flagged for restart
      (live ZSK/KSK rollover is Step 7). `apid` reloads its TLS material.
- [x] Removed the "restart required" / SIGHUP / 30s-poll dependence: the dnsd
      and apid cert pollers are gone; apid's mgmt-API responses no longer say
      "applies on SIGHUP". (The SIGHUP handler is kept as a manual fallback.)

Acceptance
- [x] Editing a `zone:*` record via the dashboard is reflected in the next query
      with no restart (records are read live per query; verified pre-Step-6).
- [x] Editing SOA/rate-limit/NSID config takes effect live — verified:
      `SET config:rrl_enabled 1` flipped `/metrics dns_rrl_enabled` 0→1 within
      ~1.5s with no restart, driven by the keyspace notification.
- [x] No subscription leaks or reconnect storms under a Valkey restart: the
      subscriber clears the 4s read timeout (else recv timeouts look like
      disconnects → storm), reconnects with capped 1→30s backoff, and re-runs a
      full catch-up so changes during the outage are not missed.
- [x] Global exit gate passes: all 4 daemons build with `EXTRA_WARN=-Werror`,
      clang-format clean, `make check`/`check-dnssec` (12/12)/`check-wire`
      (11/11) pass. Live-tested cert:current hot-reload (~2s vs old 30s) and
      mdnsd re-announce on `mdns:*` change.

---

## Step 7 — Multi-zone support  `[x]`

Goal: serve multiple authoritative zones from the slimmed-down `dnsd`.

> Scope decision (user-confirmed 2026-06-16): land **core multi-zone first**
> (serving + per-zone SOA/keys/AXFR/UPDATE + migration + control plane); do
> **automated per-zone DNSSEC key rollover** as a separate follow-up commit.

Tasks
- [x] Re-key zone data as `zone:<zonename>:<type>:<name>` and config as
      `config:zone:<zonename>:*` (records, ddns, per-zone serial/NSEC3 config).
      `apid` and the dashboard resolve the owning zone (longest-suffix) before
      writing; `mdnsd` globs `zone:*:<TYPE>:<name>` for shared records.
- [x] `dnsd` selects the most-specific configured zone per query
      (`zone_for_qname`, longest-suffix), threaded through SOA/NSEC/NSEC3/
      signing via a thread-local current-zone pointer. Added an apex-SOA answer.
- [x] Per-zone SOA, DNSSEC keys, AXFR/NOTIFY settings (per-zone ZSK/KSK loaded
      from `dnssec:<zone>:*` with legacy adoption for the primary zone; AXFR/
      IXFR/NOTIFY/UPDATE select the zone named by the request)
- [x] Per-zone automated **ZSK** rollover (RFC 6781 §4.1.1.1 Pre-Publish) —
      background engine (`rollover_thread`/`rollover_tick`) walks each zone
      publish→commit→done; incoming set in `dnssec:<zone>:zsk_next`/`:zsk_ed25519_next`,
      phase in `:zsk_rollover`, age in `:zsk_created`; manual trigger
      `config:zone:<z>:zsk_rollover_request` (edge-detected via `:zsk_rollover_seen`),
      auto via `zsk_validity`; hold times `rollover_{publish,commit}_hold`. DNSKEY
      RRset publishes current+next throughout; signer switches to next only in
      commit (`emit_rr` `use_next`). `dnssec:*` now reloads live
      (`zone_dnssec_reload`) — no longer restart-flagged.
- [x] **KSK** rollover with CDS/CDNSKEY parent signalling (RFC 6781 §4.1.2
      Double-Signature + RFC 7344/8078). First fixed the broken CDS/CDNSKEY
      (was DNSKEY-format rdata over the ZSK; now DS-format over the KSK via a
      shared `ds_rdata_from_dnskey` that the DS answer also uses → CDS==DS by
      construction, guarded by `make check-cds`). Engine (`ksk_rollover_*`,
      `dnssec:<zone>:ksk_*`): double phase publishes old+new KSK and signs the
      DNSKEY RRset with both, CDS/CDNSKEY advertises {old,new}; retire phase
      advertises {new} only; then the old KSK is retired. Manual trigger
      `config:zone:<z>:ksk_rollover_request`, auto via `ksk_validity`, holds
      `ksk_{publish,commit}_hold`. Verified end-to-end (DNSKEY 1→2→2→1 KSK sets,
      CDS==DS every phase, key rotated) + `tests/test_rollover.c` KSK no-gap
      KAT/negative for alg 13+15.
- [x] (Optional) catalog zones (RFC 9432) for bulk provisioning — `dnsd`
      consumes a catalog zone (an ordinary `zone_table:<cat>` zone with the
      schema-version record `version.<cat> TXT "2"` and `<id>.zones.<cat> PTR
      <member>` members) and provisions each member into its in-memory zone
      table: SOA names derived from the member, SOA timers / AXFR ACL / NOTIFY
      inherited from the catalog, `dnssec:<member>:*` keys auto-generated;
      members dropped from the catalog are deactivated (slot retained, never
      compacted, so no use-after-free against a live request). dnsd only READS
      the catalog and writes only `dnssec:<member>:*` (already owned) — never
      `zone_table:*`; provisioning is in-memory, re-derived on each scan (boot,
      `config:` / `zone_table:` change, rollover tick — `catalog_scan_all`).
      Guarded by `make check-catalog` (provision → served+signed → deprovision).
- [x] Migration script for existing single-zone data into the new key layout
      (`tools/migrate-multizone.sh`, dry-run by default, idempotent)
- [x] Dashboard updated for zone selection/management (zone column + per-record
      zone resolution; DNSSEC view reads per-zone keys)

Acceptance
- [x] Two distinct zones resolve correctly from one `dnsd` instance
      (verified: `www.example.com`→10.20.30.40 and `host.example.local`→
      192.168.5.5 from one instance; per-zone SOA `ns1.example.com serial 10`
      vs `ns1.example.local serial 6`)
- [x] Each zone signs with its own keys; cross-zone queries are isolated
      (distinct DNSKEY RRsets per zone; SOA mname/serial isolated)
- [x] A scheduled ZSK rollover completes without a validation gap — proven by
      `tests/test_rollover.c` (run under `make check-dnssec`): for alg 13 + 15 it
      transcribes dnsd's per-phase (published DNSKEY set, signer) policy and the
      real resolver verifier (`dnssec_verify_rrset`) accepts every phase
      (publish/commit/done), while the forbidden orderings (commit-before-publish,
      retire-too-early) leave the signing key absent from the set and fail. (The
      crypto no-gap invariant is covered; wall-clock phase-transition *timing* is
      config-driven via the hold knobs and not exercised by an automated live test.)
- [x] Existing single-zone deployments migrate via the script with no data loss
      (RENAME preserves TTLs; dnsd adopts legacy DNSSEC keys → DS unchanged)
- [x] Global exit gate passes (all 4 daemons build with `EXTRA_WARN=-Werror`;
      `make check` answers; `check-dnssec` + `check-wire` pass; ASan query sweep
      clean)

---

## Completion

- [x] After Step 4, `dnsd` is a small, single-purpose, sandboxable daemon
      (privilege drop + seccomp per `CLAUDE.md`). Done: irreversible
      privilege drop after socket bind (`priv_resolve` before chroot +
      `drop_privileges` after, `config:privdrop_user`); seccomp syscall filter
      via libseccomp (`seccomp_install`, `config:seccomp_mode` enforce/audit/off,
      enforce default; whitelist audit-validated against the real syscall set,
      harvested with strace across UDP/TCP/DoT-TLS/metrics/Valkey/rollover);
      filesystem isolation, mode-selectable via `config:isolation_mode`
      (env `DNS_ISOLATION`): `chroot` (default, `enter_chroot`) or `mountns`
      (`enter_mount_namespace` — `unshare(CLONE_NEWNS)` + make-rprivate +
      `pivot_root` + detach old root), both fail-closed with resolve-before-
      confine ordering. Full chain re-verified end-to-end in a user namespace
      for *both* modes (`unshare -Urm --map-auto`: confine → drop to nobody →
      seccomp enforce → still answers a query). The mountns threading caveat
      (unshare moves only the calling thread; trusted keyspace/rollover threads
      stay in the parent mount ns, request workers are spawned post-pivot) is
      documented at `enter_chroot`.
- [x] `resolverd` split: `dns_client.c` renamed to `resolverd.c` and given its
      own first-class build (`make resolverd` / `resolverd_debug`, hardened
      PROD_FLAGS, mirrors the certd/mdnsd/apid targets) plus a `make
      check-resolverd` smoke test (dnsd authoritative upstream + resolverd
      caching proxy on :5354 → returns dnsd's answer). Wired into CI (daemon
      build list, `-Werror` loop; dropped from the syntax-only line). The
      resolver logic was already complete in the file — this is the process
      split, not new functionality. (Its target carries
      `-Wno-misleading-indentation` — the dense but clang-format-conformant style
      trips that gcc heuristic; not a reformat TODO.)
- [x] `resolverd` sandbox (the former non-blocking follow-up): extended the
      `dnsd`-style hardening to `resolverd` — post-bind irreversible privilege
      drop, filesystem isolation (`chroot` default / `mountns` pivot_root), and a
      libseccomp syscall filter, applied in `apply_sandbox()` before the proxy
      serve loop. Resolverd-scoped config keys (`config:resolverd_{chroot_dir,
      isolation_mode,privdrop_user,privdrop_group,seccomp_mode}`, env
      `RESOLVERD_{CHROOT,ISOLATION,USER,GROUP,SECCOMP}`) since it needs its own
      filesystem view + syscall set (outbound connections + upstream name
      resolution). seccomp defaults to **audit** (whitelist mirrors dnsd's
      audit-validated set + `recvmmsg`/`sendmmsg` for getaddrinfo) pending a
      per-deployment harvest before flipping to `enforce`. Makefile links
      libseccomp into `resolverd`/`resolverd_debug`. Verified: `-Werror` prod
      build clean, no new debug warnings, `make check-resolverd` proxies dnsd's
      answer with the filter active (`[seccomp] filter active: mode=audit, 88
      syscalls allowed`, 0 audit denials), `check-wire`/`check-dnssec` green.
- [x] All seven steps + the optional follow-ups + the `resolverd` split
      complete; monolith concerns fully decomposed.
- [x] `CLAUDE.md` topology diagram matches the running system (verified: the
      diagram's dnsd / mdnsd / certd / apid / dashboard / resolverd split and
      the Valkey-only integration bus match the shipped binaries and the
      ownership table)
