# Phase 0b step 7 — remaining Medium findings

Fix spec for the Medium findings of the 2026-11-15 audit (`SECURITY_AUDIT.md`)
that no other spec covers, plus the open half of CSA-AUTH-005. Roadmap: Phase
0b step 7. Each item is small and independent; they are grouped by daemon so
each group can be built, tested and committed on its own.

| # | Finding | Daemon | Status |
|--:|---------|--------|--------|
| 7a | CSA-AUTH-005 (rest) — transfers do not require TSIG when a key is configured | dnsd | **Done** 2026-11-15 — `check-xfr-tsig-required` |
| 7b | CSA-INJ-002 — raw qname in the JSON query log | dnsd | **Done** 2026-11-15 — `check-qlog-escape` |
| 7c | CSA-SBX-001 — seccomp not applied to threads started before it | dnsd, resolverd, libsandbox | **Done** 2026-11-15 — `check-sandbox-threads` |
| 7d | CSA-AUTH-007 — resolverd answers anyone; `--no-dnssec`/`--no-mdns` do nothing | resolverd | **Done** 2026-11-15 — `check-resolverd-acl` |
| 7e | CSA-DOS-003 — apid serves one connection at a time | apid | **Done** 2026-11-15 — `check-apid-concurrency` |
| 7f | CSA-DOS-005 + CSA-INJ-001 — mdnsd SCANs the keyspace per query with the qname as a glob; sleeps in the receive loop; answers off-link | mdnsd | **Done** 2026-11-15 — `check-mdnsd-lookup` |
| 7g | CSA-WEB-001 — dashboard has no CSRF protection | dashboard | **Done** 2026-11-15 — `check-dashboard-csrf` |
| 7h | CSA-SBX-002 — apid, certd, mdnsd, doqd run unsandboxed | apid, certd, mdnsd, doqd | **Done** 2026-11-15 — `check-sidecar-sandbox` |

---

## 7a — transfers require TSIG when a key is configured (CSA-AUTH-005)

With `config:tsig_secret_b64` set, an AXFR/IXFR request whose `tsig_verify`
result is not `TSIG_OK` is answered NOTAUTH (header) with the TSIG error in an
unsigned TSIG RR (BADKEY/BADSIG) or a signed BADTIME response — the same
handling as UPDATE — and `axfr_thread` never runs. Without a key the IP ACL
alone decides (unchanged). Never drop the IP ACL: TSIG is required *in
addition*. Test: `check-xfr-tsig-required` — key set: unsigned AXFR from an
allowed address refused; signed AXFR transfers; wrong-key AXFR refused.

## 7b — escape the query log (CSA-INJ-002)

`qlog_write` writes the qname into a JSON string verbatim, so `"`, `\` and
control bytes in a label forge or break records. Escape per RFC 8259
(`\"`, `\\`, `\uXXXX` for bytes < 0x20 and 0x7f, and for bytes >= 0x80 so the
line stays ASCII). The same helper renders qnames in `dns_log` lines that
carry them. Test: a query for a name with `"`, newline and `\` labels yields a
query-log line that parses as JSON and round-trips the name.

## 7c — every thread under the sandbox (CSA-SBX-001)

- libsandbox: load the filter with `SCMP_FLTATR_CTL_TSYNC` so it applies to
  every existing thread; in enforce mode a TSYNC failure is fatal.
- dnsd: start the keyspace, rollover, NOTIFY, sweeper, health and XFR threads
  **after** `sandbox_apply`, so in `mountns` mode they also get the pivoted
  root (unshare moves only the calling thread).
- resolverd: same for any thread started before its sandbox.
- Test: `check-sandbox-threads` — for dnsd and resolverd, every task under
  `/proc/<pid>/task/*/status` reports `Seccomp: 2` (seccomp filter mode).

## 7d — resolverd client ACL and the two dead flags (CSA-AUTH-007)

- `RESOLVERD_ALLOW` / `--allow <list>` / `config:resolverd_allow`: client
  allow-list (IPv4/IPv6 addresses and prefixes), default loopback + RFC 1918
  + RFC 4193 (`127.0.0.0/8, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  fc00::/7`). Other clients get REFUSED (UDP and TCP/DoT).
- `--no-dnssec` disables validation (status stays UNCHECKED, nothing is
  marked BOGUS/SECURE); `--no-mdns` sends `.local` names to the upstream
  instead of mDNS.
- Test: `check-resolverd-acl` — allowed source answered, a source outside the
  list refused; `--no-mdns` resolves `.local` via the upstream.

## 7e — apid serves connections concurrently (CSA-DOS-003)

Thread per connection with a cap (`config:apid_max_conns`, default 128;
over the cap the connection is closed), a 5 s read deadline per request
(already), checked `pthread_create`. Test: an idle connection does not delay
`/health` from a second client (< 1 s).

## 7f — mdnsd: direct lookups, no sleep, link-local only (CSA-DOS-005, CSA-INJ-001)

- Replace the `zone:*:<type>:<name>` SCAN with direct `GET`s of
  `zone:<zone>:<type>:<name>` for each configured zone that contains the name
  (no glob — the qname never reaches a pattern).
- No `usleep` in the receive loop: RFC 6762 §6 delayed responses are
  scheduled and sent from the loop's timeout instead.
- RFC 6762 §11: drop queries whose source is not on-link (IPv4 not in a
  local interface's subnet, IPv6 not link-local) and legacy-unicast replies
  to off-link sources.
- Test: unit test of the lookup-key builder (glob characters are literal);
  a query whose name contains `*` does not match another record.

## 7g — dashboard CSRF (CSA-WEB-001)

Per-session CSRF token checked on every state-changing request (POST/PUT/
DELETE) by a `before_request` hook, injected into every form by a template
context processor; `SESSION_COOKIE_SAMESITE="Strict"`,
`SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE` unless explicitly
disabled for plain-HTTP local use. Test: a POST without the token gets 400;
with it, the action works.

## 7h — sandbox apid, certd, mdnsd, doqd (CSA-SBX-002)

Call `sandbox_apply` in each after its listeners are bound: privilege drop,
optional chroot/mountns (each daemon's own `config:<daemon>_*` keys, as
resolverd/eppd), and seccomp. Seccomp defaults to **audit** for these four
until a syscall harvest validates an enforce profile on the target platform
(the same rollout resolverd and eppd followed); the Valkey-ACL-per-daemon
part of the finding is an operator task and is documented, not coded.
Test: each daemon starts, drops privileges when run as root, and logs its
sandbox state; the existing per-daemon checks still pass.

---

## Implementation notes (2026-11-15)

- **7c** — `sandbox.c` sets `SCMP_FLTATR_CTL_TSYNC` (fatal in enforce mode if
  the kernel refuses), and dnsd/resolverd start every background thread after
  `sandbox_apply()`. Before: dnsd had 6 and resolverd 2 threads with
  `Seccomp: 0`.
- **7d** — the client ACL is the dnsd one, moved to libdnswire
  (`acl_entry_parse` / `acl_allows`, IPv4 + IPv6 prefixes) so both daemons
  share it. resolverd default: `127.0.0.0/8, ::1, 10.0.0.0/8, 172.16.0.0/12,
  192.168.0.0/16, fc00::/7`; `--allow <list>` / `RESOLVERD_ALLOW` override.
- **7e** — over `config:apid_max_conns` (default 128) a new connection is
  closed at once rather than queued.
- **7g** — `with_csrf()` adds the hidden field to every `<form method="POST">`
  of every template at render time, so a new form cannot be added without
  it; the check runs before the auth gate (covers login). Sign-out is now a
  POST form (no forced logout via a link). `DASHBOARD_INSECURE_COOKIE=1`
  drops the `Secure` cookie flag for plain-HTTP use off localhost.
  Found while testing: `dashboard/valkey_client.py` read a bulk reply with
  `sock.recv()` while ignoring bytes `_read_line` had already buffered, so a
  GET of any value that arrived in the same segment as its `$n` header hung
  until the 5 s socket timeout and failed. Fixed (consume the buffer first).
- **7h** — new `sandbox_config_load()` reads the five per-daemon knobs
  (`config:<d>_{chroot_dir,isolation_mode,privdrop_user,privdrop_group,
  seccomp_mode}`, env `<D>_{CHROOT,ISOLATION,USER,GROUP,SECCOMP}`) for apid,
  certd, mdnsd, doqd. Listeners that used to be bound inside their threads
  (apid HTTP/HTTPS, mdnsd Discovery Proxy + DSO, doqd) are now bound in
  `main()` before the sandbox; every thread starts after it. certd keeps
  `CAP_NET_BIND_SERVICE` only (new `keep_net_bind_service` in
  `sandbox_config_t`) because the tls-alpn-01 listener binds port 443 on
  demand, after confinement. All four default seccomp to **audit**; switch to
  `enforce` per daemon after a clean audit log. A chroot is opt-in; certd's
  must carry `resolv.conf`/`nsswitch.conf` and the CA bundle.
  Valkey per-daemon ACLs (the other half of the finding) are an operator
  task: give each daemon its own Valkey user limited to the key patterns in
  the CLAUDE.md ownership table (`ACL SETUSER certd on >… ~cert:current
  ~acme:* ~zone:*:TXT:_acme-challenge.* %R~config:* %R~zone:*:CAA:* …`).
