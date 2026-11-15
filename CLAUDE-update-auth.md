# dns_server.c — dynamic UPDATE authentication and TSIG hardening

Fix spec for audit findings **CSA-AUTH-001** (Critical), **CSA-AUTH-002** (High)
and, as a complementary item, **CSA-AUTH-005** (Medium). Source of the findings:
`SECURITY_AUDIT.md`, section 2026-11-15.

All line anchors are against commit `b0a6b32`. Re-anchor before editing:

```sh
grep -n "static int handle_update\|static int tsig_verify\|return handle_update(\|config:tsig_secret_b64\|tsig_verify(pkt, ml)" dns_server.c
```

Numbering: items here are **Fix 1–3** (per file), keyed by finding ID. They are
not part of the dnsd "Add" sequence.

| Fix | Finding | Status |
|----:|---------|--------|
| 1 | CSA-AUTH-001 — unsigned UPDATE accepted by default | Specced |
| 2 | CSA-AUTH-002 — TSIG time window, key name and algorithm not enforced | Specced |
| 3 | CSA-AUTH-005 — transfers do not require TSIG; CIDR parser fails open | Complementary |

---

## Fix 1: UPDATE fails closed (CSA-AUTH-001)

### What it is

`handle_update` only calls `tsig_verify` when a TSIG secret is configured. With
no `config:tsig_secret_b64` — the default — an unsigned UPDATE from any source
is applied. Reproduced: an unsigned UDP UPDATE wrote
`_acme-challenge.example.local TXT` and it was served.

After this fix an UPDATE is applied only when one of these holds:

1. it carries a TSIG that verifies (Fix 2), or
2. it carries a SIG(0) that verifies (existing `sig0_verify`), or
3. it is an SRP registration and `config:srp_enabled` is set (existing path), or
4. it is unsigned **and** the client address matches the new, default-empty
   `config:update_unsigned_allow` list.

Everything else gets REFUSED.

### Exact location in current file

| Need | Existing code (`dns_server.c` @ `b0a6b32`) |
|------|--------------------------------------------|
| The gate to replace | `:8067-8071` — `if (!has_sig0 && g_tsig_secret_len > 0 && !tsig_verify(pkt, plen))` |
| Function signature (no client address today) | `:8047` — `static int handle_update(const uint8_t *pkt, int plen, uint8_t *resp)` |
| The only caller | `:11043` — `return handle_update(pkt, plen, resp);` inside `dns_process`, which already has `cip` |
| SRP routing (must stay reachable) | `:8101-8109` — `if (srp_ei.has_update_lease)` |
| SIG(0) gate (unchanged) | `:8110-8120` — `if (has_sig0 && !sig0_verify(pkt, plen))` |
| Secret load that fails open | `:2485-2486` — `g_tsig_secret_len = b64std_dec(...)`; a value that does not decode yields 0 |
| ACL matcher to reuse | `:1441` — `ip_list_allowed(const char *list, const struct in_addr *ip)` |
| Config macro pattern for a string key | `:2298` (`g_ddns_allow_suffix[0] = 0;` then `G(...)`) |
| Startup banner line for TSIG | `:11969-11970` |

### Key schema

```
config:update_unsigned_allow   Comma-separated IPv4 addresses / CIDRs whose
                               UNSIGNED UPDATEs are accepted. Default: empty
                               (no unsigned UPDATE is ever accepted).
                               Intended for loopback test rigs and closed
                               management networks only.
```

Register the key in the `CLAUDE.md` format registry (ADR-003: additive, no
schema major bump). Add it to the dashboard `CONFIG_SCHEMA`
(`dashboard/app.py:121` onward) in the `security` group.

### What to build

1. Add `static char g_update_unsigned_allow[1024] = "";` next to
   `g_ddns_allow_suffix` (`:651`). Load it in `config_load_from_valkey` with the
   reset-then-`G()` pattern used at `:2298`.
2. Change the signature to
   `handle_update(const uint8_t *pkt, int plen, uint8_t *resp, const struct in_addr *cip)`
   and pass `cip` at `:11043`.
3. Replace the gate at `:8067-8071` with this decision (pseudocode):

   ```
   has_sig0 = sig0_present(pkt, plen)
   has_tsig = tsig_find(pkt, plen, &t) != NULL

   if has_sig0:
       # unchanged: SRP routing, then sig0_verify, both below
   elif has_tsig:
       if g_tsig_secret_len <= 0:        -> rcode NOTAUTH + log, return
       rc = tsig_verify(pkt, plen)       # Fix 2 return codes
       if rc != TSIG_OK:                 -> NOTAUTH (+ TSIG error per Fix 2), return
   else:                                  # unsigned
       allowed = cip && cip->s_addr != 0
                 && ip_list_allowed(g_update_unsigned_allow, cip)
       if !allowed:
           log WARNING "[UPDATE] REFUSED unsigned update (no TSIG/SIG(0); "
                       "client not in config:update_unsigned_allow)"
           -> rcode REFUSED, return 12
   ```

4. Secret load (`:2485`): if the key is present and non-empty but
   `b64std_dec` returns `<= 0`, log at `LOG_ERR`, set a new flag
   `g_tsig_secret_invalid = 1` and keep `g_tsig_secret_len = 0`. While the
   flag is set, treat every UPDATE and every transfer as unauthenticated-
   and-refused (do not fall through to the unsigned allow-list). Clear the
   flag on a later successful load.
5. Banner (`:11969`): print `enabled`, `disabled` or `INVALID SECRET`, and a
   second line showing whether unsigned updates are allowed and from where.
6. Update every `make` target that sends an unsigned UPDATE so it sets
   `config:update_unsigned_allow 127.0.0.1` for the run and restores the
   previous value afterwards, following the save/restore pattern already used
   for `config:tsig_secret_b64` at `Makefile:1400-1425`. Targets that send
   UPDATEs today: `check-notify`, `check-ptr`, `check-ddns-acl`, `check-role`,
   `check-eppd`, `check-txn-atomicity`, `check-xfr-client`. Re-derive the list:

   ```sh
   awk '/^check[a-z0-9-]*:/{t=$1} /nsupdate/{c[t]++} END{for(k in c) print k, c[k]}' Makefile
   ```

### Guardrail (do NOT)

- **Do NOT** add a "disable authentication" switch, and do NOT give
  `config:update_unsigned_allow` a non-empty default. Empty means closed.
- **Do NOT** accept an unsigned UPDATE when `cip` is NULL or `0.0.0.0`. Every
  IPv6 client currently arrives as `0.0.0.0` (CSA-NET-003); an entry such as
  `0.0.0.0/0` must not turn that into "allow all of IPv6".
- **Do NOT** move the secondary check (`:8059-8063`) below the new gate — a
  secondary must still answer NOTAUTH first (`check-role` depends on it).
- **Do NOT** route SRP through the TSIG gate. SRP messages carry SIG(0) and
  must still reach `srp_handle_update`; `check-srp` must pass unchanged.
- **Do NOT** let a verified TSIG bypass `ddns_name_allowed` (`:8171`).
- **Do NOT** write the 5-bit value BADSIG (16) into the 4-bit header rcode as
  `:8069` does today; it corrupts the flags word. Use NOTAUTH in the header.
- **Do NOT** touch `simple_dns.c`.

### Acceptance criteria

- Default config (no TSIG secret, empty allow-list): unsigned UPDATE → REFUSED;
  no `zone:*`/`ddns:*` key written; serial unchanged.
- `config:update_unsigned_allow=127.0.0.1`: unsigned UPDATE from loopback →
  NOERROR and applied.
- TSIG secret set: correctly signed UPDATE → NOERROR; unsigned UPDATE from a
  non-listed address → REFUSED.
- `config:tsig_secret_b64` set to a non-base64 string: signed and unsigned
  UPDATEs are both refused, and `LOG_ERR` names the key.
- `check-srp`, `check-sig0`, `check-role`, `check-ddns-acl`, `check-ptr`,
  `check-notify`, `check-txn-atomicity`, `check-xfr-client`, `check-eppd` pass.

### Test

New target `check-update-auth` (needs Valkey + python3 with dnspython; skip
with a message when dnspython is missing, like the `nsupdate` skip at
`Makefile:1540`). New file `tests/update_auth_client.py`:

```sh
VC="valkey-cli"   # or redis-cli, as the other targets resolve it
$VC del config:tsig_secret_b64 config:update_unsigned_allow
LISTEN_PORT=$TPORT ./dns_server_debug & DNS=$!; sleep 1

# 1. default: unsigned must be refused and nothing written
python3 tests/update_auth_client.py unsigned 127.0.0.1 $TPORT example.local ua1   # expect REFUSED
test -z "$($VC --scan --pattern 'zone:example.local:TXT:ua1.*')"

# 2. allow-list opens loopback only
$VC set config:update_unsigned_allow 127.0.0.1; sleep 1
python3 tests/update_auth_client.py unsigned 127.0.0.1 $TPORT example.local ua2   # expect NOERROR

# 3. with a secret: signed ok, unsigned refused once the allow-list is cleared
$VC del config:update_unsigned_allow
$VC set config:tsig_secret_b64 "$(printf '0123456789abcdef0123456789abcdef' | base64)"; sleep 1
python3 tests/update_auth_client.py signed   127.0.0.1 $TPORT example.local ua3   # expect NOERROR
python3 tests/update_auth_client.py unsigned 127.0.0.1 $TPORT example.local ua4   # expect REFUSED

# 4. undecodable secret must not disable authentication
$VC set config:tsig_secret_b64 '!!!not-base64!!!'; sleep 1
python3 tests/update_auth_client.py unsigned 127.0.0.1 $TPORT example.local ua5   # expect REFUSED
kill $DNS
```

---

## Fix 2: TSIG time window, key name and algorithm (CSA-AUTH-002)

### What it is

`tsig_verify` puts the request's time-signed and fudge into the MAC input but
never compares them with the clock. Reproduced: an UPDATE signed with a
timestamp one year old was accepted. The verifier also never checks the key
name, and it picks the digest from the algorithm name the *client* sent while
hard-coding `hmac-sha256` in the MAC variables.

### Exact location in current file

| Need | Existing code (`dns_server.c` @ `b0a6b32`) |
|------|--------------------------------------------|
| Server-side verifier | `:4675-4772` — `static int tsig_verify(const uint8_t *pkt, int plen)` |
| Parsed fields available after `tsig_find` | `:4486-4496` — `tsig_rr_t` (`key_name`, `alg_name`, `time_high`, `time_low`, `fudge`, `error`) |
| MAC compare (time check goes after this, not before) | `:4766` |
| Client-chosen digest | `:4754` — `tsig_alg_to_digest(t.alg_name)`; table at `:4659-4673` accepts `md5` and `sha1` |
| Hard-coded algorithm in MAC variables | `:4723-4725` (verify), `:4803-4805` (sign) |
| Digest chosen from the *key name* when signing | `:4824`, `:4918` — `tsig_alg_to_digest(g_tsig_key_name)` |
| Configured key name | `:847`, loaded `:2396` |
| Fudge constant | `dns_wire.h:155` — `TSIG_FUDGE 300` |
| Callers | `:8068` (UPDATE), `:11194` (transfer; result discarded — Fix 3) |
| XFR client verifier (same gap, responses from the master) | `:9521-9575` — `xfr_tsig_verify_msg` |
| Response TSIG writer | `:4775` — `tsig_append(buf, off, blen, orig_id, error)` |

### What to build

1. Give `tsig_verify` distinct results:

   ```c
   enum { TSIG_OK = 1, TSIG_ABSENT = 0, TSIG_BADSIG = -16, TSIG_BADKEY = -17, TSIG_BADTIME = -18 };
   ```

   Keep "non-zero positive = accepted" so the call shape at `:8068` changes
   minimally, but every caller must compare against `TSIG_OK` explicitly.
2. Order of checks (RFC 8945 §5.2):
   1. key name equals `g_tsig_key_name` (case-insensitive, ignore one trailing
      dot) — else `TSIG_BADKEY`;
   2. algorithm name is `hmac-sha256.` — else `TSIG_BADKEY`;
   3. MAC compare with `CRYPTO_memcmp` (existing) — else `TSIG_BADSIG`;
   4. **only after the MAC is valid**: `now` within `time_signed ± fudge`,
      where `time_signed = ((uint64_t) time_high << 32) | time_low` — else
      `TSIG_BADTIME`. Cap the accepted fudge at `TSIG_FUDGE` so a client
      cannot widen its own window with a large fudge value.
3. Use SHA-256 unconditionally at `:4754`, `:4824` and `:4918`. Delete the
   `md5`/`sha1` rows from `tsig_alg_to_digest` or remove the function if no
   caller remains.
4. On `TSIG_BADTIME` the response carries a TSIG RR with error 18 and the
   server's current time in "other data" (RFC 8945 §5.2.3). `tsig_append`
   takes an `error` argument already; extend it to emit the 6-octet other-data
   when `error == 18`. Header rcode is NOTAUTH (9) for all three failures.
5. Apply the same time check in `xfr_tsig_verify_msg` (`:9521`) for signed
   messages received from the master.

### Guardrail (do NOT)

- **Do NOT** check the time before the MAC. An unauthenticated time value must
  not influence the response (RFC 8945 §5.2.3).
- **Do NOT** accept a truncated MAC; the existing length equality at `:4766`
  stays.
- **Do NOT** stash the request MAC into `g_tsig_req_mac` unless the result is
  `TSIG_OK` or `TSIG_BADTIME` (a BADTIME response is signed with the request
  MAC; BADSIG/BADKEY responses are unsigned).
- **Do NOT** add algorithm negotiation. One configured algorithm; anything
  else is BADKEY.
- **Do NOT** change the wire format produced by `tsig_append` for the
  success path — `check-xfr-tsig`, `check-notify` and `check-ixfr-client`
  depend on it.

### Acceptance criteria

- Fresh, correctly signed UPDATE → NOERROR, response TSIG verifies.
- Same message with `time_signed` 1 year in the past → NOTAUTH, TSIG error 18,
  nothing written.
- `time_signed` 10 minutes in the future → same.
- Wrong key name, right secret → NOTAUTH, TSIG error 17.
- Algorithm `hmac-sha1.` or `hmac-md5.sig-alg.reg.int.` → NOTAUTH, error 17.
- Fudge 65535 with a timestamp 1 hour old → NOTAUTH, error 18.
- `check-xfr-tsig`, `check-notify`, `check-ixfr-client` pass.

### Test

Extend `check-update-auth` (same client script; it patches `time.time` while
serialising to produce an old or future timestamp):

```sh
$VC set config:tsig_secret_b64 "$(printf '0123456789abcdef0123456789abcdef' | base64)"; sleep 1
python3 tests/update_auth_client.py signed        127.0.0.1 $TPORT example.local t1                # NOERROR
python3 tests/update_auth_client.py signed-shift  127.0.0.1 $TPORT example.local t2 -31536000      # NOTAUTH/18
python3 tests/update_auth_client.py signed-shift  127.0.0.1 $TPORT example.local t3 600            # NOTAUTH/18
python3 tests/update_auth_client.py signed-key    127.0.0.1 $TPORT example.local t4 other-key      # NOTAUTH/17
python3 tests/update_auth_client.py signed-alg    127.0.0.1 $TPORT example.local t5 hmac-sha1      # NOTAUTH/17
test -z "$($VC --scan --pattern 'zone:example.local:TXT:t[2-5].*')"
```

---

## Fix 3 (complementary): transfers require TSIG when configured; strict CIDR (CSA-AUTH-005)

- **Anchor:** `:11194` — `tsig_verify(pkt, ml);` result discarded before
  `axfr_thread(ac)`; ACL decision at `:9961`; CIDR parse at `:1441-1470`.
- **Intent:** when `g_tsig_secret_len > 0`, an AXFR/IXFR request whose
  `tsig_verify` result is not `TSIG_OK` is answered REFUSED before
  `axfr_thread` runs. In `ip_list_allowed`, a prefix that is not all digits
  or is outside 0–32 makes that list entry match nothing, with one `LOG_ERR`
  per reload.
- **Do NOT** drop the IP ACL; TSIG is required *in addition* to it.
- **Acceptance:** with a secret set, unsigned AXFR from an ACL-listed address
  → REFUSED; signed → transfers. `config:axfr_allow=10.0.0.0/x` allows
  nobody. `check-axfr`, `check-ixfr`, `check-xfr-tsig` pass.

---

## Release note (required)

Fix 1 is a behaviour change: deployments that relied on unsigned UPDATE (DDNS
clients, ACME DNS-01 hooks using `nsupdate` without a key) stop working until
they configure a TSIG key or list their address in
`config:update_unsigned_allow`. Fix 2 rejects `hmac-sha1`/`hmac-md5` clients.
