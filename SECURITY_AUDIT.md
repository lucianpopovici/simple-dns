# Security Audit — simple-dns

> Per-run sections below, **newest first**. Finding IDs (`CSA-<area>-NNN`) are
> stable across runs so status can be tracked over time.

---

## 2026-11-15 — Full audit: security, protocol correctness, performance (@ commit b0a6b32)

**Scope:** whole repository at `b0a6b32` (2026-07-07): `dns_server.c` (dnsd),
`resolverd.c`, `apid.c`, `eppd.c`, `certd.c`, `mdnsd.c`, `doqd.c`, `dns_wire.c`,
`sandbox.c`, `dashboard/app.py`, Makefile and CI. `simple_dns.c` (no build
target) and `object_graph.c` were not reviewed.

**Method:** Pass-0 attack-surface map; manual review of the request, auth,
transfer, cache and sandbox paths; `clang --analyze` on every TU; ASan/UBSan
debug builds of dnsd, apid, resolverd run against a local Redis-compatible
server; a 4-minute black-box mutation fuzz of dnsd's UDP path (QUERY, UPDATE
signed and unsigned, NOTIFY, IXFR seeds; 15M packets sent, an unknown share
processed — no sanitizer report); independent DNSSEC validation of dnsd's
answers with dnspython; a closed-loop UDP load generator for throughput.
**Not available:** cppcheck, scan-build, TSan run, libseccomp (so the seccomp
layer was reviewed by reading only), OpenSSL ≥ 3.5 (doqd was read, not built).

**Evidence labels:** *Reproduced* = triggered on a running build in this audit.
*By inspection* = read in source, not executed.

**Deltas first:**
- **Prior 12 findings (2026-06-23/25): all still Fixed, none regressed**
  (signature greps: `tls_verify_peer_name` on every outbound TLS path,
  `SSL_VERIFY_PEER` unconditional in certd, `response_matches_query` gating
  resolverd replies, `CRYPTO_memcmp` on TSIG/cookie/DDNS secret, `csprng_u16`
  for IDs, label cap in `name_to_wire`). Residual note: `csprng_u16` still
  falls back to `rand()` if `RAND_bytes` fails (`dns_server.c:1054`,
  `resolverd.c:2281`).
- **28 new findings.** The earlier audits concentrated on TLS and resolver
  anti-spoofing; this run covered the areas their coverage caveat deferred
  (dynamic UPDATE, AXFR/IXFR, resolverd cache concurrency, mdnsd) plus protocol
  correctness and the non-dnsd daemons.

**Counts (new, this run):** Critical 1 · High 9 · Medium 12 · Low 6 · Info 0

### Status table

| ID | Sev | Status | Evidence | One-line |
|---|---|---|---|---|
| CSA-AUTH-001 | Critical | Open | Reproduced | Unsigned RFC 2136 UPDATE accepted when no TSIG secret is set (the default) |
| CSA-AUTH-002 | High | Open | Reproduced | TSIG time/fudge never checked — signed messages replayable indefinitely |
| CSA-AUTH-003 | High | Open | Reproduced | apid `/list` dumps `zone:*`/`ddns:*` with no authentication |
| CSA-AUTH-004 | High | Open | Reproduced | apid `/zone` write accepts the DDNS shared secret (any type, any name) |
| CSA-DNSSEC-001 | High | Open | Reproduced | KSK key tag computed with ZSK flags — RRSIG(DNSKEY)/DS tag off by one |
| CSA-DNSSEC-002 | High | Open | Reproduced | NXDOMAIN "proof" is one NSEC3 matching the qname — not a valid denial |
| CSA-PROTO-001 | High | Open | Reproduced | NODATA answered as NXDOMAIN (existence tracked per type, not per name) |
| CSA-PROTO-002 | High | Open | Reproduced | Plain TCP/53 speaks TLS as soon as a certificate is loaded |
| CSA-CONC-001 | High | Open | Reproduced | resolverd cache/LRU use-after-free under concurrent UDP load |
| CSA-NET-003 | High | Open | By inspection | IPv6 client address collapses to 0.0.0.0 (RRL, cookies, ACLs) |
| CSA-AUTH-005 | Medium | Open | Reproduced | AXFR/IXFR does not require TSIG; malformed CIDR in ACL matches all |
| CSA-AUTH-006 | Medium | Open | By inspection | DoH/DoQ clients reach dnsd as 127.0.0.1 (identity lost across the proxy hop) |
| CSA-AUTH-007 | Medium | Open | By inspection | resolverd has no client ACL; `--no-dnssec`/`--no-mdns` are no-ops |
| CSA-DOS-002 | Medium | Open | Reproduced | No TCP/DoT connection cap; TLS handshake has no timeout |
| CSA-DOS-003 | Medium | Open | Reproduced | apid handles one connection at a time per listener |
| CSA-DOS-004 | Medium | Open | By inspection | RRL keyed on qname — random-subdomain floods bypass it |
| CSA-DOS-005 | Medium | Open | By inspection | mdnsd runs a full-keyspace SCAN per query; 20–120 ms sleep in the recv loop |
| CSA-INJ-001 | Medium | Open | By inspection | mdnsd puts the qname into a SCAN MATCH glob |
| CSA-INJ-002 | Medium | Open | By inspection | Raw qname written into the JSON query log |
| CSA-SBX-001 | Medium | Open | By inspection | seccomp filter loaded without TSYNC; background threads start before it |
| CSA-SBX-002 | Medium | Open | By inspection | apid, certd, mdnsd, doqd run with no sandbox |
| CSA-WEB-001 | Medium | Open | By inspection | Dashboard has no CSRF protection on state-changing POSTs |
| CSA-CONC-002 | Low | Open | By inspection | Live config reload rewrites globals while workers read them |
| CSA-MEM-001 | Low | Open | By inspection | certd double free on the EST 202 retry path |
| CSA-MEM-002 | Low | Open | By inspection | Small out-of-bounds reads in TSIG alg-name copy, IXFR authority scan, forwarder RRL truncation |
| CSA-DOS-006 | Low | Open | By inspection | NOTIFY on a secondary: blocking `getaddrinfo` per packet, no TSIG |
| CSA-WEB-002 | Low | Open | By inspection | Dashboard login throttle trusts `X-Forwarded-For`; table unbounded |
| CSA-CRYPTO-001 | Low | Open | By inspection | EPP registrar password and authInfo: plaintext storage, `strcmp` |

Already tracked elsewhere and unchanged at this commit: DNSSEC private keys as
plaintext PEM in Valkey (ADR-006).

---

### Findings — Critical / High

#### CSA-AUTH-001 — Unsigned dynamic UPDATE accepted by default  [Critical] [Open]
- Location: `dns_server.c:8068` (`handle_update`); secret load `dns_server.c:2485`.
- Reachability: any host that can send UDP to the DNS port; source spoofable.
- Issue: the gate is `!has_sig0 && g_tsig_secret_len > 0 && !tsig_verify(...)`.
  With no `config:tsig_secret_b64` the length is 0 and the gate is skipped.
  `ddns_allow_suffix` is empty by default, so no name restriction applies
  either. A secret that fails base64 decoding yields length 0 and silently
  turns authentication off.
- Reproduced: default config, unsigned UDP UPDATE → rcode 0;
  `_acme-challenge.example.local TXT` and an extra `www` A record were then
  served.
- Impact: anyone can rewrite zone data — including the DNS-01 challenge name,
  which is enough to obtain certificates for the zone.
- Fix: fail closed. Refuse UPDATE (REFUSED) unless a TSIG secret or a SIG(0)
  trust anchor is configured. Treat an undecodable secret as a startup/reload
  error, not as "disabled". Do NOT make this a config toggle that defaults to
  open.

#### CSA-AUTH-002 — TSIG time window never checked  [High] [Open]
- Location: `dns_server.c:4675-4772` (`tsig_verify`); time/fudge are parsed at
  `:4632-4635` and fed into the MAC, never compared with the clock. Same gap in
  the XFR client's verifier (`:9456` onward).
- Reachability: anyone who can observe one signed UPDATE (DNS/UDP is cleartext).
- Reproduced: an UPDATE signed with a timestamp one year old → rcode 0, record
  written.
- Impact: indefinite replay of captured signed updates (re-adding deleted
  records, reverting an address).
- Fix: reject when `|now − time_signed| > fudge` with BADTIME (RFC 8945 §5.2.3).
  Also bind the key name to `g_tsig_key_name`, and stop choosing the digest from
  the client-supplied algorithm name (`tsig_alg_to_digest` accepts MD5/SHA-1).
  Side note: BADSIG (16) is written into the 4-bit header rcode at `:8069`, so
  the client sees a different rcode.

#### CSA-AUTH-003 — apid `/list` is unauthenticated  [High] [Open]
- Location: `apid.c:701` (handler) sits above the auth check at `apid.c:730`.
- Reachability: any client of the plain-HTTP listener.
- Reproduced: `GET /list` with no credentials returned every `ddns:*` and
  `zone:*` key and value.
- Impact: full zone enumeration, bypassing the AXFR ACL and NSEC3.
- Fix: move the handler below the auth gate and require mgmt (mTLS).

#### CSA-AUTH-004 — DDNS secret authorises arbitrary zone writes  [High] [Open]
- Location: `apid.c:826` (`/zone` POST/PUT) and the DELETE branch below it —
  neither checks `is_mgmt`; auth at `apid.c:730` accepts `?key=<ddns_secret>`.
- Reachability: any holder of the DDNS secret, which travels in a URL over
  plain HTTP.
- Reproduced: `POST /zone?key=<ddns_secret>` wrote `NS` at the apex and
  `TXT` at `_acme-challenge`.
- Impact: a credential meant for "update my A record" can delegate the zone
  away. `ddns_allow_suffix` is not enforced in apid at all.
- Fix: gate `/zone` on `is_mgmt`; enforce `ddns_allow_suffix` in `/update` and
  `/delete`; reject `|` and control characters in `value`/`name` (pipe-format
  injection). `qs_get` uses `strstr`, so `xkey=` matches `key=` — parse on
  `&` boundaries.

#### CSA-DNSSEC-001 — KSK key tag off by one  [High] [Open]
- Location: `dns_server.c:3472-3476` (`dnssec_init_key` always uses the ZSK
  rdata encoders, flags 256). `dnssec_load_existing` (`:3510`) does it
  correctly.
- Reproduced: `example.local` publishes KSKs with tags 20791 / 25129;
  RRSIG(DNSKEY) and the DS answer carry 20790 / 25128. Same on a `zone_table`
  zone.
- Impact: validators select the verifying key by tag and algorithm; no
  published DNSKEY has the advertised tag, so the DNSKEY RRset cannot be
  verified and the zone is treated as bogus. A DS built from the server's own
  answer also carries the wrong tag.
- Fix: pass `is_ksk` into `dnssec_init_key` and use the KSK encoder for the
  tag. Note for the release: the advertised KSK tags change by +1; any DS
  already published at a parent from this server's DS answer must be
  regenerated.
- Test gap: `check-dnssec-live` checks for RRSIG presence only.

#### CSA-DNSSEC-002 — Signed NXDOMAIN is not a valid denial  [High] [Open]
- Location: `dns_server.c:5866-5888` (`add_nsec3_denial`), called from `:7110`.
- Reproduced: NXDOMAIN for `nope.example.test` returned one NSEC3 whose owner
  is H(`nope.example.test`), next = H(apex), bitmap `A`. No closest-encloser
  proof, no wildcard denial. No NSEC3PARAM at the apex.
- Impact: RFC 5155 §7.2.2 requires a closest-encloser proof; an NSEC3 that
  *matches* the qname asserts the name exists. resolverd logs dnsd's negative
  answers as `DNSSEC BOGUS`. (The individual signatures do verify once the key
  is known.)
- Fix: for an online signer, Compact Denial of Existence (RFC 9824: NOERROR +
  NSEC with the NXNAME type) is the simplest correct scheme; otherwise emit
  the three-record white-lies proof. Publish NSEC3PARAM if NSEC3 stays.

#### CSA-PROTO-001 — NODATA answered as NXDOMAIN  [High] [Open]
- Location: `dns_server.c:7100` — rcode is chosen from `found`, which records
  whether the *queried type* was found.
- Reproduced: on a `zone_table` zone with `www A`, `www AAAA` → NXDOMAIN;
  apex `AAAA` → NXDOMAIN. (The primary zone's `www` returned NOERROR.)
- Impact: resolvers cache NXDOMAIN for the whole name (RFC 2308) and subtree
  (RFC 8020). Dual-stack clients lose the A record after the AAAA query;
  QNAME-minimising resolvers stop at an empty non-terminal.
- Fix: decide existence per name — any type at the name, or any name beneath
  it, means NODATA. The apex always exists.

#### CSA-PROTO-002 — Plain TCP/53 becomes TLS once a certificate is loaded  [High] [Open]
- Location: `dns_server.c:11092-11104` (`dot_thread` wraps the socket whenever
  `g_dot_ctx` is non-NULL); the plain-TCP accept at `:12171` passes no
  transport flag in `dot_conn_t`.
- Reproduced: TCP/53 query answered with no cert; after loading a cert the
  same query got a connection reset.
- Impact: every TC=1 retry fails on a deployment with DoT enabled — large
  signed answers become unreachable for clients with a 512-byte buffer.
- Fix: add an `is_tls` field to `dot_conn_t`, set by the accepting listener.

#### CSA-CONC-001 — resolverd cache/LRU use-after-free  [High] [Open]
- Location: `resolverd.c:3238-3277` (`cache_insert` links the entry into the
  hash bucket, releases the bucket lock, and only then calls `lru_insert` at
  `:3271`); `resolverd.c:3340` (`cache_lookup` calls `lru_touch(e)` after
  releasing the bucket lock); `cache_evict_one` (`:3204`) unlinks from the LRU
  and the hash under separate locks.
- Reachability: ordinary UDP queries from any client, 8 workers by default.
- Reproduced: `--cache-size 8`, 12 client threads mixing one repeated name and
  random names → ASan `heap-use-after-free` WRITE in `lru_insert`
  (`resolverd.c:3188`) within 20 s; process died.
- Impact: remote crash; heap corruption in a production build.
- Fix: make the hash and LRU updates one critical section (a single cache
  mutex is enough at this size), or give entries a refcount held across the
  unlock. Do NOT touch an entry pointer after releasing the lock that
  protects its lifetime.
- Test gap: no TSan job in CI.

#### CSA-NET-003 — IPv6 clients collapse to 0.0.0.0  [High] [Open]
- Location: `dns_server.c:11840`, `:11857` (`IPV6_V6ONLY`), `:12139` and
  `:12217` (dead `IN6_IS_ADDR_V4MAPPED` branches).
- Impact: all IPv6 clients share one RRL bucket and one cookie identity, and
  match ACLs only through a `0.0.0.0` entry. Already known as Add A; recorded
  here because it is still present at this commit.
- Fix: carry `sockaddr_storage` through `dns_process`; key RRL on /56 for v6.

---

### Findings — Medium

#### CSA-AUTH-005 — Transfers do not require TSIG; ACL parser fails open  [Medium] [Open]
- Location: `dns_server.c:11194` (result of `tsig_verify` discarded before
  `axfr_thread`); ACL check `:9961`; CIDR parse `:1441-1470`.
- Reproduced: with a TSIG secret configured, an unsigned AXFR from an
  ACL-listed address transferred the zone.
- Issue: authorisation is source-IP only. `atoi` on the prefix turns
  `10.0.0.0/x` into `/0`, which matches everything.
- Fix: when a TSIG secret is configured, refuse unsigned transfers. Reject
  ACL entries whose prefix is not a number in 0–32.

#### CSA-AUTH-006 — Client identity lost across the apid/doqd → dnsd hop  [Medium] [Open]
- Location: `apid.c` `dns_forward` and `doqd.c` `dns_forward` (loopback UDP/TCP
  to dnsd).
- Issue: dnsd sees 127.0.0.1 for every DoH/DoQ client. RRL and cookies are
  shared across all of them, and a forwarder ACL that lists loopback opens the
  forwarder to the internet through DoH.
- Fix: pass the client address on the internal hop (PROXY protocol v2 or a
  private EDNS option accepted only from loopback), or apply the client
  policy in the front-end daemon.

#### CSA-AUTH-007 — resolverd answers anyone; two documented flags do nothing  [Medium] [Open]
- Location: listeners bind `INADDR_ANY` (`resolverd.c:4694` onward) with no
  client ACL or rate limit anywhere in the file; `resolverd.c:5688-5689`.
- Issue: an open recursive resolver is a reflection source. `--no-dnssec` and
  `--no-mdns` are parsed and ignored although `usage()` documents them; with
  `--no-mdns` ignored, every `.local` name still goes to mDNS first.
- Fix: add an allow-list defaulting to loopback + RFC 1918; implement or
  remove the two flags (the Makefile's `check-resolverd` passes `--no-mdns`).

#### CSA-DOS-002 — No connection cap; TLS handshake without timeout  [Medium] [Open]
- Location: `dns_server.c:12160-12225` (one detached thread per accepted
  connection, `pthread_create` result unchecked — `c` and the fd leak on
  failure); `SO_RCVTIMEO` is set at `:11113`, after `SSL_accept` at `:11104`.
  Same pattern in `resolverd.c:4903-4948` and `eppd.c:4220`.
- Reproduced: 1,500 idle TCP connections → 1,400 threads, RSS 10 MB → 268 MB.
- Fix: cap concurrent connections (doqd already does, `doqd.c:548`), set the
  socket timeouts before the handshake, check `pthread_create`.

#### CSA-DOS-003 — apid serves one connection at a time  [Medium] [Open]
- Location: `apid.c:1290` and `:1309` (accept → handle → close, inline, 10 s
  timeout).
- Reproduced: one idle connection delayed `/health` by 9.9 s.
- Fix: worker pool or thread-per-connection with a cap.

#### CSA-DOS-004 — RRL keyed on qname  [Medium] [Open]
- Location: `dns_server.c:5154-5190`; direct-mapped 4,096-entry table where a
  collision resets the bucket; one global mutex.
- Issue: every random subdomain gets a fresh bucket, so the NXDOMAIN flood RRL
  exists to stop is never limited. Signed NXDOMAIN is ~13× the query size.
  RRL is off by default.
- Fix: key negative answers on (client prefix, zone), positive on (client
  prefix, qname, qtype); run the check before building the response.

#### CSA-DOS-005 — mdnsd: keyspace SCAN and a sleep per query  [Medium] [Open]
- Location: `mdnsd.c:182-195` (`zone_glob_get`), `mdnsd.c:2003` (`usleep`
  inside the single-threaded receive loop).
- Issue: up to 10 questions × 6 types per packet, each a full SCAN of the
  shared Valkey. Legacy-unicast replies go to any source with no on-link
  check (RFC 6762 §11).
- Fix: look up `zone:<zone>:<type>:<name>` directly for the configured
  zones; schedule delayed responses instead of sleeping; drop off-link
  sources.

#### CSA-INJ-001 — mdnsd glob injection into SCAN MATCH  [Medium] [Open]
- Location: `mdnsd.c:184` (`"zone:*:%s:%s"` with the wire qname).
- Issue: `name_from_wire` copies label bytes verbatim; `*`, `?`, `[` in a
  `.local` qname become pattern characters, returning the first matching
  record from any zone.
- Fix: as CSA-DOS-005 (no glob); otherwise escape glob metacharacters.

#### CSA-INJ-002 — Query-log JSON injection  [Medium] [Open]
- Location: `dns_server.c:779-795` (`qlog_write`); also `%s` of qnames in
  `dns_log` calls.
- Issue: labels may contain `"`, newlines and control bytes; they are written
  unescaped, so a client can forge log records.
- Fix: escape per RFC 8259 / RFC 4343 presentation format at the logging
  boundary.

#### CSA-SBX-001 — seccomp does not cover threads started before it  [Medium] [Open]
- Location: `sandbox.c:397` (`seccomp_load` with no
  `SCMP_FLTATR_CTL_TSYNC`; the comment at `sandbox.c:223` says TSYNC is used,
  the comment in `eppd.c` above `accept_loop` says it is not);
  `dns_server.c:11744-11810` start the keyspace, rollover, NOTIFY, sweeper,
  health and XFR threads before `sandbox_apply` at `:12011`; resolverd starts
  `vkw_worker` and `prefetch_worker` before `apply_sandbox`.
- Issue: those threads run unfiltered, and several parse network input
  (NOTIFY replies, XFR data, prefetched upstream answers). In `mountns` mode
  they also keep the original filesystem view.
- Fix: set TSYNC on the filter, or create every thread after `sandbox_apply`.
  Not verified at runtime (libseccomp unavailable here).

#### CSA-SBX-002 — Four daemons have no sandbox  [Medium] [Open]
- Location: `apid.c`, `certd.c`, `mdnsd.c`, `doqd.c` never call
  `sandbox_apply`.
- Issue: apid parses HTTP from the internet and holds a Valkey connection
  that can write `config:*`. All daemons share one Valkey credential, so a
  compromise of any one is a compromise of the bus.
- Fix: apply libsandbox in each; create one Valkey ACL user per daemon that
  mirrors the data-ownership table.

#### CSA-WEB-001 — Dashboard lacks CSRF protection  [Medium] [Open]
- Location: `dashboard/app.py` — every POST route (`/config/save`,
  `/dnssec/delete-key`, `/pki/upload-pem`, …); no token anywhere in the file.
- Fix: per-session token on every form; set `SESSION_COOKIE_SAMESITE=Strict`
  and `SESSION_COOKIE_SECURE`.

---

### Findings — Low

#### CSA-CONC-002 — Config reload races with readers  [Low] [Open]
- Location: `keyspace_apply` (`dns_server.c:2939`) → `config_load_from_valkey`
  (`:2280`); also SIGHUP at `:12066`.
- Issue: globals are reset to defaults and rewritten while worker threads read
  them. Every serial bump triggers a full reload (seen in the log on each
  UPDATE).
- Fix: build a new config struct and swap a pointer; do not reload on
  `config:zone_serial`.

#### CSA-MEM-001 — certd double free on EST 202 retry  [Low] [Open]
- Location: `certd.c:1792` frees `body`; if the retry allocation or CSR build
  fails, `body` is not reassigned and is freed again at `:1815`.
- Fix: set `body = NULL` after the first free. (Flagged by `clang --analyze`.)

#### CSA-MEM-002 — Small out-of-bounds reads  [Low] [Open]
- `dns_server.c:4618`: TSIG algorithm-name label copied with only `rp < plen`
  checked, not `rp + c`.
- `dns_server.c:11175`: IXFR authority scan reads type/rdlen at `ra`..`ra+9`
  without checking against `ml`.
- `dns_server.c:11456`: forwarder RRL truncation sets `rlen = qa + 4` without
  checking the upstream reply is that long — up to 4 stale stack bytes sent.
- All read within or just past a stack buffer; none was hit by the fuzz run.
  Fix: bounds-check before each read.

#### CSA-DOS-006 — NOTIFY handling on a secondary  [Low] [Open]
- Location: `dns_server.c:11059` — a blocking `getaddrinfo` per NOTIFY on the
  query thread; NOTIFY is not TSIG-verified and the UDP source is spoofable.
- Fix: resolve the primary once at config load; require TSIG when configured;
  rate-limit `xfr_refresh_kick`.

#### CSA-WEB-002 — Login throttle trusts X-Forwarded-For  [Low] [Open]
- Location: `dashboard/app.py:63` (`_client_ip`), `_login_fails` dict.
- Issue: a client rotates the header to avoid the back-off; the dict grows
  without bound.
- Fix: honour the header only behind a configured proxy; bound and expire the
  table.

#### CSA-CRYPTO-001 — EPP credentials  [Low] [Open]
- Location: `eppd.c:911` (registrar password: plaintext in
  `config:eppd_registrar_pw:<clID>`, compared with `strcmp`), `eppd.c:3729`
  (authInfo `strcmp`).
- Issue: no hashing, variable-time compare, no failed-login limit, and the
  clID is not bound to the client certificate.
- Fix: store a password hash, compare in constant time, bind clID to the
  certificate subject, limit failures per clID.

---

### Performance observations (not security findings)

Measured with the prod build on a 2-core sandbox with the key-value server on
the same host — use the ratios, not the absolute numbers.

| Query | HEAD, 1 thread | HEAD, 4 workers | Patched, 4 workers | HEAD + rcache, 4 workers |
|---|---|---|---|---|
| Positive A | 3.4k qps | 10.4k | 20.5k | 34.9k |
| NXDOMAIN (random names) | 2.6k | 8.0k | 17.5k | 9.1k |
| NXDOMAIN + DO | 1.9k | 4.7k | 7.0k | 4.7k |

"Patched" = the two edits below, nothing else.

- **PERF-001** `valkey_ensure` (`dns_server.c:1911-1919`) sends `PING` before
  every command. A positive A query costs 10 round-trips (4 GET, 1 TTL, 5
  PING), an NXDOMAIN 12. Drop the PING; reconnect when a command fails.
- **PERF-002** `resp_parse` (`dns_server.c:1690`) zeroes a `resp_reply_t`
  holding `char str[MAX_PEM]` (64 KB) per reply. Reset the scalar fields and
  `str[0]` only.
- **PERF-003** Six sequential GETs per miss (NS, ddns A, zone A, srp A, CNAME,
  wildcard). Pipeline them, or serve from an in-process zone image refreshed
  by keyspace notifications (ADR-005).
- **PERF-004** Negative answers are signed online with two algorithms on every
  query; random names defeat `rcache`. Cache signed negative responses per
  covering range once CSA-DNSSEC-002 is fixed.
- **PERF-005** TCP/DoT threads share the global `vk` connection under
  `g_vk_mutex`; only UDP workers have private connections.
- **PERF-006** One thread spawned per forwarded UDP query (`:11515`).
- **PERF-007** Serve-stale cannot work: the `stale:` shadow keys live in the
  Valkey whose outage they are meant to cover (`dns_server.c:2098-2112`), and
  each query then blocks on up to 4 s connect attempts.

### Notes / non-findings (verified this run)

- dnsd UDP request path: 4-minute mutation fuzz under ASan/UBSan, no report.
- No memory growth in the prod dnsd across the load runs (RSS flat at 10 MB).
- UDP truncation honours the advertised EDNS size and sets TC.
- Forwarder validates reply source, ID and question (`fwd_reply_valid`).
- Positive answers, SOA and NSEC3 RRSIGs verify with dnspython for both
  algorithms.
- Production ELF: PIE, full RELRO, BIND_NOW, non-exec stack, stack protector,
  fortified calls present.
- Dashboard: password hashing, constant-time username compare, session reset
  on login, secret-bearing keys hidden in the explorer.

### Coverage caveat and next steps

Not line-by-line: `build_query_resp` record-emission branches, SRP, catalog
zones, the rollover engine, eppd object handlers and `object_graph.c` were
skimmed or skipped. Highest-value follow-ups: a libFuzzer harness over
`dns_process` (QUERY + UPDATE + `tsig_find`/`sig0_find`), a TSan CI job for
resolverd and dnsd, and a CI step that validates dnsd's positive and negative
answers with an independent validator (it would have caught CSA-DNSSEC-001,
CSA-DNSSEC-002 and CSA-PROTO-001).

---

## 2026-06-25 — Incremental re-audit (@ commit 42a8ce5)

**Scope:** the trust-boundary code changed since the 2026-06-23 full audit —
resolverd's new RFC 7873 client DNS-cookie exchange (`response_opt_parse`,
`edns_append`, the per-upstream cookie store), the Valkey cache-load path
(`cache_load_valkey` / `entry_remaining_ttl` / `cache_entry_free`), the `--proto`
CLI handler, and the resolverd seccomp default — plus re-verification of all 11
prior findings. Method: manual review of the new parser/auth code (Passes 1–3, 5,
7) and pattern greps for each prior finding's signature.

**Deltas first:**
- **All 11 prior findings remain OPEN** — none fixed, none regressed. Line numbers
  shifted; current locations in the table below.
- **Mitigation strengthened:** `resolverd` seccomp now defaults to **enforce**
  (was `audit` at the last audit; whitelist harvest-validated across all upstream
  transports). `dnsd` was already enforce.
- **Security defects fixed this session** (were not separate findings before, but
  are security-relevant — recorded for the diff):
  - *resolverd Valkey cache-load NULL-deref* — a remotely-triggerable crash (DoS)
    on the first cache hit after an in-memory miss (restarted resolverd). Fixed
    (ordering + NULL guards); regression `make check-resolverd-cache`. This sits
    in the "resolverd cache concurrency" area the prior audit deferred.
  - *resolverd `--proto dot/tcp/doh` silent downgrade* — the CLI flag set
    `g_cfg.proto` but not `upstream_proto[0]`, so a CLI-configured DoT/DoH upstream
    silently sent **plaintext UDP** (confidentiality downgrade). Fixed. (env path
    was always correct.)
- **New code audited clean for memory safety:** `response_opt_parse`
  (`resolverd.c`, parses untrusted upstream responses) bounds-checks every field
  read and clamps the server-cookie copy to the 32-byte destination; the
  per-upstream cookie store is `g_cookie_mutex`-guarded (no race); the Client
  Cookie derives from a `RAND_bytes` secret (CSPRNG). No memory-safety finding.
- **One new finding:** `CSA-NET-002` (cookie learned from an unvalidated response)
  — Low, and a direct facet of the still-open `CSA-NET-001`.

**Counts (this run):** Critical 0 · High 3 · Medium 2 · Low 5 · Info 2
(prior 11 carried + 1 new Low). **All 12 were FIXED in this working tree during
this session** — see the status table and "Fixes applied" below.

### Finding status (carried IDs)

| ID | Sev | Status | Fix |
|---|---|---|---|
| CSA-TLS-001 | High | **Fixed** | `certd.c`: `SSL_VERIFY_PEER` hoisted out of the `if`, now set on both CA paths |
| CSA-TLS-002 | High | **Fixed** | `tls_verify_peer_name()` (set1_host / set1_ip for IP literals) on resolverd DoT+DoH, certd, dnsd XFR |
| CSA-NET-001 | High | **Fixed** | `resolverd.c` `response_matches_query()` — drop any reply whose ID/QR/question ≠ the query, before accept/cache/cookie-learn |
| CSA-NET-002 | Low | **Fixed** | closed by CSA-NET-001 (cookie learned only from a validated response) |
| CSA-RAND-001 | Medium | **Fixed** | `resolverd.c` `csprng_u16()` (RAND_bytes) for txn IDs + source ports, incl. cookie-retry ID |
| CSA-TIME-001 | Medium | **Fixed** | `apid.c`: DDNS secret via `CRYPTO_memcmp` after length check |
| CSA-TIME-002 | Low | **Fixed** | `dns_server.c`: TSIG MAC compares via `CRYPTO_memcmp` (verify + XFR) |
| CSA-TIME-003 | Low | **Fixed** | `dns_server.c`: server-cookie compare via `CRYPTO_memcmp` |
| CSA-TLS-003 | Low | **Fixed** | rsyslog already defaulted verify-on; added hostname verify on both rsyslog and pinned-CA XFR |
| CSA-DOS-001 | Low | **Fixed** | `apid.c` `http_read_request()` — loop to CRLFCRLF + Content-Length, bounded by buffer + `SO_RCVTIMEO` |
| CSA-WIRE-001 | Info | **Fixed** | `dns_wire.c`: `name_to_wire`/`name_to_wire_c` reject labels > 63 (test added) |
| CSA-RAND-002 | Info | **Fixed** | `dns_server.c`: outbound NOTIFY IDs via `csprng_u16()` |

Not addressed (out of scope): `simple_dns.c` mirrors of TLS/strcmp findings — it
is a reference artifact with **no build target** (not shipped), so its copies are
dead code; left as-is and noted here.

### Fixes applied — verification

- Builds: all daemons compile clean (`-Werror` warning set); clang-format clean.
- Tests (all green): `check`, `check-resolverd{,-cache,-cookie}`, `check-xfr-tsig`,
  `check-notify`, `check-ddns-acl`, `check-dot-mtls`, `check-forwarder`,
  `check-ptr`, `check-axfr`, `check-ixfr`, `check-wire` (new label-cap case),
  `check-dnssec`.
- TLS: DoT verified live against 1.1.1.1 **by IP** (set1_ip path) and by hostname
  (set1_host path) — both still resolve; identity is now bound to the cert.
- Anti-spoofing: real resolution through `response_matches_query` still works
  (A/AAAA/MX via 8.8.8.8); the cookie handshake test still passes.

### New finding (now fixed)

#### CSA-NET-002 — resolverd learns/stores the Server Cookie from an unvalidated response  [Low] [Fixed]
- Location: `resolverd.c` `upstream_query_one` (cookie-learning + BADCOOKIE retry),
  `cookie_store_server`, `response_opt_parse`.
- Reachability: any upstream answer; an off-path spoofer (same precondition as
  CSA-NET-001 — the transaction ID and question are still not validated).
- Issue: the RFC 7873 client exchange copies the Server Cookie out of the first
  response that parses and stores it per-upstream, then replays it on later
  queries. Because the response is not ID/question-validated, a spoofed response
  can plant a bogus Server Cookie.
- Impact: low and self-correcting — replaying a wrong Server Cookie to the real
  upstream yields BADCOOKIE, which triggers a re-learn; no memory unsafety. It
  does add a second unvalidated-response code path, so it is bounded by the same
  fix as CSA-NET-001.
- Fix: validate the response transaction ID + question before trusting *any* of
  its contents (closes CSA-NET-001 and this together); only update the stored
  cookie from a response that also answers the asked question.
- Tooling: manual.

> The 2026-06-23 full-audit findings (unchanged text) follow.

---

## 2026-06-23 — Full audit

## Summary

**Scope:** Whole repository, all C translation units: `dns_wire.c`/`dns_wire.h`
(libdnswire), `sandbox.c`/`sandbox.h` (libsandbox), `dns_server.c` (dnsd),
`resolverd.c`, `apid.c`, `certd.c`, `mdnsd.c`, `simple_dns.c` (reference impl).
Method: Pass-0 attack-surface mapping, targeted manual review of the
untrusted-input parsers / crypto / TLS / privilege paths, and pattern greps
(dangerous copies, weak RNG, non-constant-time compares, TLS verify config,
allocation overflow) across every TU. Tooling available in the sandbox was
limited (`clang-tidy`, `gcc`/`clang`, `readelf`; **no** cppcheck / scan-build /
valgrind / checksec). Binary-hardening was confirmed from the Makefile rather
than the production ELF (the production binary was not built at audit time).

**Trust map (entry points / boundaries):**

| Surface | Component | Trust |
|---|---|---|
| DNS wire (UDP/TCP 53, DoT 853) | dnsd | Internet, untrusted |
| Upstream responses (UDP/TCP/DoT/DoH) | resolverd | Internet, untrusted |
| HTTP/HTTPS, DoH, mgmt API | apid | Internet, untrusted (mTLS-gated writes) |
| ACME/EST to CA | certd | Outbound to semi-trusted CA, on-path attacker possible |
| mDNS multicast | mdnsd | Link-local |
| Valkey bus | all daemons | Trusted infrastructure (integration contract) |
| AXFR/IXFR to primary | dnsd (secondary role) | Outbound, TSIG-authenticated |

**Counts:** Critical 0 · High 3 · Medium 3 · Low 4 · Info 2

**New since last run:** all (first audit — no prior `SECURITY_AUDIT.md`).
**Fixed since last run:** n/a. **Regressed:** n/a.

The codebase is, on the whole, defensively written: `libdnswire` enforces the
`-1`-on-overflow convention with consistent call-site checks; the DNS message /
EDNS-OPT parser in `dnsd` bounds every field read; `libsandbox` drops privilege
in the correct order (`setgroups`→`setgid`→`setuid`), verifies the drop is
irreversible, sets `PR_SET_DUMPABLE 0`, and its seccomp allowlist excludes
`execve`/`ptrace`. Two historically-noted bugs (the `fudge` constant and the
EDNS DO-bit offset) are confirmed fixed. The findings below concentrate in the
**TLS peer-authentication** and **resolver anti-spoofing** paths.

---

## Findings

### CSA-TLS-001 — certd performs no TLS server-cert verification on the default (system-trust) path  [High] [Open]
- Location: `certd.c:535-544` (`https_connect`-style setup), no `SSL_get_verify_result` anywhere in `certd.c`.
- Reachability: Every ACME (directory/order/finalize) and EST connection certd
  makes when **no explicit CA PEM is configured** — the normal deployment that
  relies on the public/system trust store for a public ACME CA.
- Issue: `SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, …)` is called **only inside
  the `if (ca_pem)` branch**. The `else` branch calls
  `SSL_CTX_set_default_verify_paths()` but leaves the verify mode at its default
  `SSL_VERIFY_NONE`, and certd never calls `SSL_get_verify_result()`. Result:
  the handshake completes against **any** certificate, including self-signed.
- Impact: A man-in-the-middle between certd and the CA can impersonate the
  ACME/EST server — feed forged challenge instructions, capture EST mTLS client
  credentials, or hand back attacker-chosen "issued" certs that then land in
  `cert:current` and are served by dnsd/apid. CA impersonation / credential
  exposure.
- Fix: Always `SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL)` (move it out of
  the `if`), and add hostname verification (see CSA-TLS-002 fix). In `else`,
  verify `set_default_verify_paths` succeeds; fail closed if the chain or
  hostname does not verify.
- Tooling: manual.

### CSA-TLS-002 — No TLS hostname verification on any outbound connection (DoT MITM)  [High] [Open]
- Location: `resolverd.c:1620, 1755` (DoT/`dot_connect`), `certd.c:573`,
  `dns_server.c:952` (rsyslog), `dns_server.c:7490` (XFR client),
  `simple_dns.c:3644`. No `SSL_set1_host` / `X509_VERIFY_PARAM_set1_host` /
  `X509_check_host` exists anywhere in the tree.
- Reachability: resolverd's DoT path to every upstream; an on-path attacker
  between resolverd and the upstream resolver.
- Issue: The code calls `SSL_set_tlsext_host_name()`, which only sets the **SNI**
  extension in the ClientHello — it does **not** validate that the presented
  certificate matches the expected hostname. With `SSL_VERIFY_PEER` the chain is
  checked, but **any** CA-valid certificate for **any** name is accepted.
- Impact: An attacker holding any legitimately-issued certificate (trivial via a
  public CA for a domain they control) who is on-path can MITM resolverd's DoT
  sessions — defeating DoT confidentiality and forging responses for unsigned
  zones. (DNSSEC validation mitigates forgery for *signed* zones only;
  confidentiality is lost regardless.)
- Fix: After `SSL_new`, call
  `SSL_set1_host(ssl, expected_hostname)` (and optionally
  `SSL_set_hostflags(…, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)`) so the handshake
  fails on a name mismatch. Apply to resolverd DoT, certd, and the dnsd XFR
  client.
- Tooling: manual + grep (no host-check API present).

### CSA-NET-001 — resolverd does not validate the response transaction ID or question section  [High] [Open]
- Location: `resolverd.c:1995-2120` (`upstream_query_one` / `upstream_query`);
  `build_query` sets `h->id` at `resolverd.c:1576` but nothing ever reads the
  response ID back.
- Reachability: Every UDP/TCP/DoT/DoH answer from an upstream; an off-path
  attacker spoofing the upstream's source address.
- Issue: After `recv()`, the response is returned/cached without checking that
  `id(response) == id(query)` or that the answered question matches the asked
  question (QNAME/QTYPE; also no 0x20 case randomisation). The UDP socket *is*
  `connect()`ed, so the kernel filters on the local ephemeral port + remote
  addr:port — but with the transaction ID unchecked, the only secret an off-path
  spoofer must guess is the source port (16 bits), halving the search space that
  normally also includes the 16-bit ID.
- Impact: Markedly easier off-path cache poisoning, compounded by CSA-RAND-001
  (the source port is drawn from a predictable PRNG). DNSSEC validation limits
  the damage to unsigned zones, which are the majority of the namespace.
- Fix: Reject any response whose header ID ≠ the query ID and whose question
  section does not byte-match (case-insensitively) the query; on mismatch, keep
  reading / time out rather than accepting. Consider 0x20 query-name
  randomisation as defense-in-depth.
- Tooling: manual (grep confirmed no ID comparison exists).

### CSA-RAND-001 — Predictable PRNG for resolver transaction IDs and source ports  [Medium] [Open]
- Location: `resolverd.c:1997` (`id = rand() & 0xFFFF`), `resolverd.c:2036`
  (`sp = 1024 + rand() % 64511`), seeded `srand(time(NULL))` at
  `resolverd.c:3834`. Same pattern: `dns_server.c:8814/8164`,
  `simple_dns.c:4583/3460`.
- Reachability: Off-path spoofer attacking resolverd's cache.
- Issue: `rand()`/`srand(time(NULL))` is a non-cryptographic PRNG seeded from
  wall-clock seconds. Once the seed is guessed (a small range around process
  start) the ID and source-port streams are reconstructable. These two fields
  are the resolver's primary anti-spoofing entropy.
- Impact: Combined with CSA-NET-001, off-path poisoning of unsigned zones
  becomes practical.
- Fix: Use a CSPRNG (`RAND_bytes` — already linked via OpenSSL — or
  `getrandom()`) for transaction IDs and source-port selection. `getrandom` is
  already in the seccomp allowlist.
- Tooling: grep + manual.

### CSA-TIME-001 — DDNS shared secret compared with non-constant-time strcmp  [Medium] [Open]
- Location: `apid.c:1041` (`strcmp(akey, secret)`), mirrored at
  `simple_dns.c:4336`.
- Reachability: Unauthenticated HTTP `/update` request (the `?key=` DDNS path)
  on apid's plain-HTTP listener; gates zone-record writes.
- Issue: `strcmp` short-circuits on the first differing byte, leaking a timing
  oracle on the secret. The secret authorises `zone:*`/`ddns:*` writes.
- Impact: Byte-by-byte recovery of the DDNS secret over the network (harder over
  WAN jitter, but it is an authentication secret and should not be compared in
  variable time), leading to unauthorised dynamic-record injection.
- Fix: Compare with `CRYPTO_memcmp()` over a fixed length after confirming equal
  lengths (or hash both sides and compare digests). Rate-limit failures.
- Tooling: grep + manual.

### CSA-TIME-002 — TSIG MAC verified with non-constant-time memcmp  [Low] [Open]
- Location: `dns_server.c:4238`, `dns_server.c:7445` (XFR), `simple_dns.c:2204`.
- Reachability: Any TSIG-signed request (UPDATE, AXFR/IXFR) from a client that
  knows a key name.
- Issue: `memcmp(mac, t.mac, mlen)` short-circuits; comparing a secret-derived
  HMAC in variable time is a timing side-channel. TSIG also binds a time/fudge
  window, which raises the bar, but constant-time comparison is the standard.
- Impact: Theoretical MAC-forgery assist via timing; low practical risk over a
  network but easy to fix.
- Fix: Use `CRYPTO_memcmp()`.
- Tooling: grep + manual.

### CSA-TIME-003 — DNS cookie compared with non-constant-time memcmp  [Low] [Open]
- Location: `dns_server.c:5024` (`memcmp(expected, ei->server_cookie, …)`).
- Reachability: Any query echoing a server cookie (RFC 7873/9018).
- Issue: Non-constant-time comparison of the server cookie (a keyed anti-spoof
  token).
- Impact: Minor timing leak on the cookie; low impact since cookies are an
  anti-amplification/anti-spoof aid, not a primary auth secret.
- Fix: `CRYPTO_memcmp()`.
- Tooling: grep + manual.

### CSA-TLS-003 — Outbound TLS allows verification-disabled / unpinned modes (rsyslog, XFR)  [Low] [Open]
- Location: `dns_server.c:941` (rsyslog `SSL_VERIFY_NONE` when
  `g_rsyslog_tls_verify` off), `dns_server.c:7300-7308, 7493` (XFR client only
  enables `SSL_VERIFY_PEER` / checks `SSL_get_verify_result` when an XFR CA PEM
  is configured).
- Reachability: Operator-configurable; rsyslog log shipping and secondary→primary
  zone transfer.
- Issue: rsyslog has an explicit no-verify toggle; the XFR client performs no
  cert verification when no CA is pinned. Both also lack hostname verification
  (CSA-TLS-002).
- Impact: Log disclosure / injection (rsyslog) and transfer-channel MITM (XFR).
  Lower than CSA-TLS-001/002 because rsyslog is opt-in and AXFR/IXFR data
  integrity is independently protected by TSIG (recently added).
- Fix: Default rsyslog verify on; for the XFR client, require chain + hostname
  verification (TSIG covers integrity but TLS should still authenticate the
  endpoint). Document the no-verify mode as insecure.
- Tooling: manual.

### CSA-DOS-001 — apid reads the HTTP request with a single recv(); large/slow bodies are truncated  [Low] [Open]
- Location: `apid.c:945-988` (`handle_api`): one `SSL_read`/`recv` of
  `HTTP_BUF-1`, then `blen = n - (bdy - buf)` for the DoH POST body.
- Reachability: Any HTTP(S) client.
- Issue: The request (including a DoH POST DNS message) is not read in a loop to
  the declared `Content-Length`; a body split across TCP segments is silently
  truncated, and there is no header/body size cap or slow-loris timeout shown
  here. No memory-safety bug (the copied length is derived from bytes actually
  read), but a correctness/availability gap.
- Impact: Dropped/garbled DoH queries; potential for slow-client resource
  pinning.
- Fix: Loop until headers are complete, then read exactly `Content-Length`
  bytes (bounded by a max); apply a per-request read deadline.
- Tooling: manual.

### CSA-WIRE-001 — name_to_wire does not reject labels > 63 octets  [Info] [Open]
- Location: `dns_wire.c:185-204` (`name_to_wire`).
- Reachability: Name emission for records sourced from config/zone data.
- Issue: A label longer than 63 bytes is written with a length octet ≥ 0x40,
  whose top bits collide with the compression-pointer marker on re-parse. No
  buffer overflow (the `pos+ll+1 >= blen` check holds), but it can emit a
  malformed name.
- Impact: Correctness/robustness only; not currently a memory-safety issue.
- Fix: Reject (return -1) any label with `ll > 63`.
- Tooling: manual.

### CSA-RAND-002 — Outbound NOTIFY/query IDs use rand()  [Info] [Open]
- Location: `dns_server.c:8164` (`h->id = htons((uint16_t) rand())`).
- Reachability: dnsd's outbound NOTIFY / probe messages to secondaries.
- Issue: Predictable IDs as in CSA-RAND-001, but for the authoritative server's
  outbound notifications, where the recipient authenticates via TSIG/SOA, so the
  ID's unpredictability matters far less.
- Impact: Negligible in current use; flagged for consistency with the CSPRNG fix.
- Fix: Same CSPRNG migration as CSA-RAND-001.
- Tooling: grep.

---

## Notes / non-findings (verified safe)

- **libdnswire parsers** (`name_from_wire`, `b64*_dec`, `txt_encode`,
  `append_rr*`): bounds-checked; compression pointers must target strictly prior
  offsets and a 128-step cap backstops loops; output indices guarded before
  every write.
- **dnsd DNS/EDNS-OPT parser** (`dns_server.c:4793-4889`): every field read is
  guarded by `off+10 <= plen` / `rp+4 <= …`; cookie copies are length-checked.
  The `fudge` constant (`TSIG_FUDGE 300`) and the EDNS DO-bit offset are
  confirmed correct (both were historical bugs).
- **libsandbox** (`sandbox.c`): correct privilege-drop order, irreversibility
  check, `getpwnam` before chroot, `PR_SET_DUMPABLE 0`, seccomp allowlist with
  no `execve`/`ptrace`; mountns/pivot_root fail-closed.
- **Committed key material:** `bootstrap.key`/`.pem`/`.crt`, `*-ca.pem`,
  `chain.p7` exist in the working tree but are **gitignored and untracked**
  (`git ls-files` confirms) — local fixtures, not a repository secret leak.
- **apid RESP/Valkey client** (`apid.c:105-215`): bulk-string reads are capped
  to the destination buffer with the excess drained; no overflow.
- **No** `system`/`popen`/`exec*` usage anywhere; the `strcpy`/`sprintf` hits in
  certd/simple_dns are constant-string assignments (`strcpy(path,"/")` etc.).

## Coverage caveat

This was a focused, high-yield pass over the parsers, crypto, TLS, privilege,
and authentication surfaces plus a pattern sweep across all ~23K lines — not a
line-by-line audit of every function. Areas worth a dedicated follow-up:
resolverd cache concurrency (rwlock/UAF under reload), dnsd dynamic-UPDATE and
AXFR/IXFR memory handling, and the mdnsd multicast parser.

**Done (2026-06-26):** the audit's stated highest-value next step — a libFuzzer
harness over the resolver's *response* parser (not just `name_from_wire`) under
ASan+UBSan, seeded from real upstream replies — is shipped:
`fuzz/fuzz_response.c` (`make fuzz-response`, CI job *Fuzz smoke (resolverd
response parser)*) drives `response_opt_parse`, `response_matches_query`, and
`parse_response_to_entry` by #including resolverd.c. Seed corpus in
`fuzz/corpus_response/` (5 hand-built replies: A, AAAA, NXDOMAIN+SOA, NODATA+SOA,
A+EDNS-cookie); first 60s run (≈7M execs) found no crash/leak. This closes the
Definition-of-Done fuzz requirement for the CSA-NET-001 response-validation
change. Remaining follow-ups above are still open.
