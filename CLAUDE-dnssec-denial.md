# dns_server.c — KSK key tag, name existence, and authenticated denial

Fix spec for audit findings **CSA-DNSSEC-001**, **CSA-PROTO-001** and
**CSA-DNSSEC-002** (all High). Source: `SECURITY_AUDIT.md`, section 2026-11-15.
Fix 3 **promotes dnsd Add 11 (RFC 9824 compact denial)** from Follow-on to
Specced; update `CLAUDE-index.md` accordingly.

All line anchors are against commit `b0a6b32`. Re-anchor before editing:

```sh
grep -n "static void dnssec_init_key\|static int nsec_rdata\|static int add_nsec_denial\|static int add_nsec3_denial\|static int prereq_name_exists\|if (!found) {$\|add_nsec3_denial(resp\|add_nsec_denial(resp" dns_server.c
```

| Fix | Finding | Status |
|----:|---------|--------|
| 1 | CSA-DNSSEC-001 — KSK key tag computed with ZSK flags | Specced |
| 2 | CSA-PROTO-001 — NODATA answered as NXDOMAIN | Specced (2a) / Conditional (2b, needs an owner decision) |
| 3 | CSA-DNSSEC-002 — signed negative answers are not a valid proof | Specced; one owner decision (D1) |

Build order: 1 → 2a → 3. Fix 3 depends on the helper Fix 2a introduces.

**What was observed (so the agent can reproduce before changing anything):**

```
example.local DNSKEY: KSK tags 20791 (alg 13), 25129 (alg 15)
RRSIG(DNSKEY) key tags: 20790, 25128        DS answer key tags: 20790, 25128
www.example.test A exists; www.example.test AAAA -> NXDOMAIN; example.test AAAA -> NXDOMAIN
nope.example.test A +DO -> NXDOMAIN with ONE NSEC3: owner = H(nope.example.test), bitmap "A"
```

---

## Fix 1: KSK key tag (CSA-DNSSEC-001)

### What it is

`dnssec_init_key` computes every key's tag from the ZSK DNSKEY rdata encoding
(flags 256). For a KSK the published DNSKEY has flags 257, so the stored tag is
exactly one less than the tag of the published key. That stored tag is what
goes into RRSIG(DNSKEY), DS and CDS. Validators pick the verifying key by
(algorithm, key tag); no published key has the advertised tag.

### Exact location in current file

| Need | Existing code (`dns_server.c` @ `b0a6b32`) |
|------|--------------------------------------------|
| The defect | `:3472-3476` — tag always from `dnskey_rdata_ed25519` / `dnskey_rdata_ecdsa` |
| Function signature | `:3420` — `dnssec_init_key(vk_key, legacy_key, out, tag, alg, label)` |
| The four call sites | `:3483-3503` in `zone_dnssec_init` (ZSK-P256, ZSK-Ed25519, KSK-P256, KSK-Ed25519) |
| The correct pattern to copy | `:3509-3534` — `dnssec_load_existing(..., int is_ksk)` selects the KSK encoders |
| KSK encoders | `:3134` `dnskey_rdata_ksk_ecdsa`, `:3145` `dnskey_rdata_ksk_ed25519` |
| Consumers of the tag (no change needed once the tag is right) | `:6493`, `:6584`, `:6622` |

### What to build

1. Add an `int is_ksk` parameter to `dnssec_init_key`; select the encoder
   exactly as `dnssec_load_existing` does at `:3525-3530`.
2. Pass `0` for the two ZSK calls and `1` for the two KSK calls in
   `zone_dnssec_init`.
3. Factor the encoder selection into one helper used by both functions so the
   two paths cannot diverge again.

### Guardrail (do NOT)

- **Do NOT** change the key material, the Valkey key names, or the DNSKEY
  rdata that is published. Only the computed tag changes.
- **Do NOT** "fix" this by publishing KSKs with flags 256.
- **Do NOT** touch `keytag()` (`:3158`); it is correct.

### Acceptance criteria

- For every zone, each RRSIG(DNSKEY) key tag equals the RFC 4034 Appendix B
  tag of a published DNSKEY with flags 257 and the same algorithm.
- DS and CDS answers carry the same tags.
- An independent validator verifies the DNSKEY RRset (test below).
- `check-dnssec`, `check-cds`, `check-rollover-txn`, `check-rrsig-signer` pass.

### Test

New `tests/dnssec_validate.py` (dnspython) and target `check-dnssec-validate`.
It fetches DNSKEY over TCP with DO, then validates each RRset it is given with
`dns.dnssec.validate`, one RRSIG at a time so both algorithms are checked.

```sh
LISTEN_PORT=$TPORT ./dns_server_debug & DNS=$!; sleep 2
python3 tests/dnssec_validate.py 127.0.0.1 $TPORT example.local dnskey     # DNSKEY RRset validates, both algs
python3 tests/dnssec_validate.py 127.0.0.1 $TPORT example.local ds-tags    # DS key tags == published KSK tags
kill $DNS
```

### Release note (required)

Advertised KSK key tags change by +1. A DS record that was created at a parent
by copying this server's DS/CDS answer carries the old tag and must be
regenerated. A DS computed by a registrar from the DNSKEY itself is already
correct.

---

## Fix 2: name existence decides NODATA vs NXDOMAIN (CSA-PROTO-001)

### What it is

The rcode is chosen from `found`, which means "the queried type was found at
this name". When the name exists with other types — or is the zone apex — the
answer is NXDOMAIN. Resolvers cache NXDOMAIN for the whole name (RFC 2308) and
everything beneath it (RFC 8020).

### Exact location in current file

| Need | Existing code (`dns_server.c` @ `b0a6b32`) |
|------|--------------------------------------------|
| The decision | `:7098-7106` — `if (!found) { ... NXDOMAIN } else { ... NOERROR }` |
| Existing per-name probe (too slow for the query path, incomplete type list) | `:7150-7167` — `prereq_name_exists`: up to 24 sequential GETs over 12 types |
| Static records table | `:1389-1398` — `static_zone[]`, `static_zone_sz` |
| Key builders | `:503` `zkey`, `:508` `dkey`, `:513` `skey` |
| Connection selection to mirror (worker-private vs shared + mutex) | `:2133-2156` — `vk_get` |
| Pipelining primitive | `:1773` — `resp_send_cmd` (send without reading); `:1686` `resp_parse` (read one reply) |
| Locally-served zones (RFC 6303) keep their own path | `:6322-6340` |

### Fix 2a — What to build (Specced)

1. One table, `served_types[]`, listing every RR type the server can answer
   from Valkey together with the prefixes it is read from (`zone:`, `ddns:`,
   `srp:`). Derive it from the code, not from memory:

   ```sh
   grep -oE '(zkey|dkey|skey)\([a-z0-9_]+, sizeof\([a-z0-9_]+\), "[A-Z0-9]+"' dns_server.c | sort -u
   grep -n "case DNS_TYPE_" dns_server.c | sed -n '/stored_rdata/,$p' | head -40
   ```

2. `static int name_types_present(const char *name, uint16_t *types, int max)`:
   - builds every `<prefix>:<zone>:<TYPE>:<name>` key from `served_types[]`;
   - sends one `EXISTS <key>` per key with `resp_send_cmd`, **then** reads the
     replies in order with `resp_parse` — one write burst, one read burst, on
     the same connection `vk_get` would use (`t_vk_conn`, else `vk` under
     `g_vk_mutex`);
   - adds types found in `static_zone[]`;
   - adds SOA, NS and DNSKEY when `name` is the apex of `t_zone`;
   - returns the number of distinct types present, filling `types[]`.
3. In the negative branch at `:7098`:

   ```
   if answers == 0 && !is_referral:
       n = found ? 1 : name_types_present(qname, types, MAX)
       if n > 0 or qname is the apex of t_zone:   -> NOERROR (NODATA)
       else:                                      -> NXDOMAIN
   ```

   Keep the `types[]` result in scope — Fix 3 uses it for the NSEC bitmap.
4. Replace the body of `prereq_name_exists` with a call to the new helper so
   UPDATE prerequisites and queries agree.

### Fix 2a — Guardrail (do NOT)

- **Do NOT** call the helper on the positive path. It runs only when
  `answers == 0`.
- **Do NOT** issue the `EXISTS` commands as separate request/response round
  trips; the point is one round trip. Do NOT put them in one multi-key
  `EXISTS` either — that returns a count, and Fix 3 needs to know which types.
- **Do NOT** build keys with `resp_cmd`'s 8 KB command buffer in mind as
  "enough for all keys at once" (`:1748`); one command per key avoids the
  limit.
- **Do NOT** cache positive existence in `rcache` under a new key shape; the
  existing per-key negative/positive entries already cover repeats.
- **Do NOT** change the RFC 6303 locally-served path (`:6322`).

### Fix 2a — Acceptance criteria

- `www.<zone> A` exists → `www.<zone> AAAA` is NOERROR with SOA in authority.
- Apex of a `zone_table` zone, any absent type → NOERROR.
- A name with no records of any type → NXDOMAIN.
- A name that exists only as `ddns:` or only as `srp:` → NODATA for other types.
- NXDOMAIN costs one extra Valkey round trip compared with today, not one per
  type (verify with `MONITOR`: the `EXISTS` commands arrive back-to-back).

### Fix 2b — Empty non-terminals (Conditional — owner decision D2)

`a.b.<zone>` exists and `b.<zone>` has no records: `b.<zone>` must be NODATA.
Detecting that needs "does any key exist below this name", which the current
schema can only answer with a keyspace SCAN.

- **Option A (recommended):** a per-zone name index, `zidx:<zone>` (a Valkey
  set of owner names plus their ancestors up to the apex), maintained in the
  same MULTI/EXEC as every record write. One `SISMEMBER` answers both "name
  exists" and "is an empty non-terminal". This is a schema change (ADR-003
  minor bump) and touches every writer: dnsd UPDATE/SRP/XFR apply, apid, eppd,
  certd's challenge writer and the dashboard.
- **Option B:** accept the limitation and document it; after Fix 3, DO-bit
  queries no longer receive an NXDOMAIN rcode for these names, so the impact
  is limited to non-validating resolvers.

Do not implement 2b until D2 is decided.

### Test (Fix 2a)

Add to `check-dnssec-validate` or a new `check-nodata`:

```sh
$VC set zone_table:nd.test "ns1.nd.test|hostmaster.nd.test|1|3600|900|604800|300||"
$VC set zone:nd.test:A:www.nd.test "60|10.0.0.1"; sleep 2
dig +noall +comments @127.0.0.1 -p $TPORT www.nd.test AAAA  | grep -q 'status: NOERROR'
dig +noall +comments @127.0.0.1 -p $TPORT nd.test AAAA      | grep -q 'status: NOERROR'
dig +noall +comments @127.0.0.1 -p $TPORT nope.nd.test A    | grep -q 'status: NXDOMAIN'
$VC del zone_table:nd.test zone:nd.test:A:www.nd.test
```

---

## Fix 3: valid authenticated denial — RFC 9824 compact denial (CSA-DNSSEC-002)

### What it is

Both denial builders emit records that do not prove what the rcode says:

- NSEC3 mode (`:5866`): one NSEC3 whose owner is the hash of the *queried*
  name with a bitmap containing the queried type's neighbours. An NSEC3 that
  matches the qname states the name exists. RFC 5155 §7.2.2 needs a
  closest-encloser proof (up to three records).
- NSEC mode (`:5351`): next name is always the apex and the bitmap is a fixed
  list (A, NS, CNAME, SOA, MX, …) regardless of what exists.

For a server that signs on the fly, RFC 9824 defines the correct minimal
scheme: answer NOERROR with a single NSEC at the queried name whose next name
is the immediate successor, and signal non-existence with the NXNAME
meta-type (128) in the bitmap.

### Exact location in current file

| Need | Existing code @ `b0a6b32` |
|------|---------------------------|
| NSEC rdata builder to rewrite | `dns_server.c:5351-5377` — `nsec_rdata` (fixed next name, fixed bitmap) |
| NSEC emitter | `dns_server.c:5379-5388` — `add_nsec_denial` |
| NSEC3 builder / emitter to retire from the query path | `dns_server.c:4406` `nsec3_rdata`, `:5866-5888` `add_nsec3_denial` |
| Call sites | `dns_server.c:6329-6332` (locally-served zones), `:7109-7112` (main path) |
| rcode decision (shared with Fix 2) | `dns_server.c:7098-7106` |
| Signing | `dns_server.c:5393` `emit_rr` → `:3240` `make_rrsig` |
| Negative TTL | `zone_negative_ttl()` (used at `dns_server.c:5385`) |
| EDNS flags parse (add the CO flag here) | `dns_wire.c:1201` — `ei->do_bit = (pkt[off + 6] & 0x80)`; struct at `dns_wire.h:165-172` |
| Type constants | `dns_wire.h:42` (`DNS_TYPE_NSEC 47`) — add `DNS_TYPE_NXNAME 128` |
| EDE codes | `dns_wire.h:114-132` — add `EDE_INVALID_QUERY_TYPE 30` |
| Per-zone denial mode | `dns_server.c:1350`, `:4136`, `:4148` — `dnssec_use_nsec3` |
| Resolver side that must accept the result | `resolverd.c:1684` `nsec_bitmap_has_type`, `resolverd.c:3379-3472` aggressive NSEC |

### Owner decision D1 (settle before building)

- **Option A (recommended):** compact denial with NSEC for every signed zone.
  `config:dnssec_nsec_mode=nsec3` is accepted but logs one NOTICE that online
  NSEC3 is no longer produced. Smallest correct change.
- **Option B:** keep NSEC3 and implement the RFC 9824 §4 NSEC3 variant. More
  code, larger responses, no enumeration benefit for an online signer (the
  NSEC successor reveals nothing about other names).

The rest of this spec assumes Option A.

### What to build

1. `dns_wire.h`: `DNS_TYPE_NXNAME 128`, `EDE_INVALID_QUERY_TYPE 30`, and an
   `int co_bit;` in `edns_info_t`. `dns_wire.c:1201`: parse the Compact
   Answers OK flag, `(pkt[off + 6] & 0x40)` (EDNS flags value `0x4000`).
2. A bitmap encoder that takes a list of types and emits RFC 4034 §4.1.2
   window blocks (the current code only writes window 0; CAA 257 and URI 256
   live in window 1). Put it in `dns_wire.c` so resolverd's tests can reuse it.
3. Rewrite `nsec_rdata(qname, types, ntypes, nxname, rd, rdlen)`:
   - Next Domain Name = the immediate successor of `qname`: a one-octet label
     `\000` prepended to `qname` (wire: `01 00` followed by qname's wire form).
   - Bitmap = `types[]` ∪ {RRSIG, NSEC}; when `nxname` is set, bitmap =
     {RRSIG, NSEC, NXNAME}.
4. Negative branch at `dns_server.c:7098`, for signed zones with `dnssec_ok`:

   ```
   name exists (Fix 2a n > 0, or apex):
       rcode NOERROR; authority = SOA + RRSIG, NSEC(qname; types present) + RRSIG
   name does not exist:
       rcode = ei.co_bit ? NXDOMAIN : NOERROR
       authority = SOA + RRSIG, NSEC(qname; RRSIG NSEC NXNAME) + RRSIG
   ```

   Without `dnssec_ok` nothing changes: NXDOMAIN/NODATA + unsigned SOA.
5. A query whose QTYPE is NXNAME (128) is answered FORMERR with EDE 30
   (RFC 9824 §3.5) before any lookup.
6. The locally-served path (`dns_server.c:6329-6332`) uses the same NSEC
   builder with `nxname = 1`.
7. Remove `add_nsec3_denial` from both call sites. Keep `nsec3_rdata` only if
   another caller remains; otherwise delete it and the NSEC3 hash helpers that
   become unused.
8. resolverd: confirm that a NOERROR answer with an NSEC at the qname whose
   bitmap lacks the qtype validates as secure NODATA, and that an NSEC
   carrying NXNAME is not inserted into the aggressive-NSEC cache as a
   range covering other names (`resolverd.c:3379`). Add a unit case to
   `tests/test_aggressive_nsec.c`.

### Guardrail (do NOT)

- **Read RFC 9824 §3 and §5 before coding.** In particular take from the RFC,
  not from this spec: whether the CO flag is echoed in responses, and the
  rule when prepending `\000` would exceed the 255-octet name limit.
- **Do NOT** return NXDOMAIN to a DO-bit client that did not set CO. A
  validator would look for an NXDOMAIN proof that compact denial does not
  provide.
- **Do NOT** set the NXNAME bit for a name that exists (NODATA) or for an
  empty non-terminal once Fix 2b lands.
- **Do NOT** include the queried type, or CNAME (unless a CNAME really exists
  there), in a NODATA bitmap.
- **Do NOT** list types that are not at the name "to be safe". The bitmap is
  signed data; the fixed list at `:5359-5361` is the bug.
- **Do NOT** sign with a different signer name or TTL than other authority
  data: signer is the zone apex (`check-rrsig-signer`), TTL is
  `zone_negative_ttl()`.
- **Do NOT** change wildcard synthesis here. Whether wildcard answers carry a
  valid proof is a separate question and is out of scope for this fix.
- **Do NOT** add a Valkey lookup beyond the single pipelined burst from
  Fix 2a.

### Acceptance criteria

- `nope.<zone> A +dnssec` → NOERROR, one NSEC owned by `nope.<zone>` with next
  name `\000.nope.<zone>` and bitmap exactly `RRSIG NSEC NXNAME`, plus SOA;
  every RRSIG validates with an independent validator.
- Same query with EDNS flags `0x4000` → rcode NXDOMAIN, same records.
- `www.<zone> AAAA +dnssec` (A exists) → NOERROR, NSEC bitmap `A RRSIG NSEC`.
- Apex absent type → bitmap includes `NS SOA DNSKEY RRSIG NSEC`.
- QTYPE 128 → FORMERR with EDE 30.
- Without DO: unchanged rcodes, no NSEC, no RRSIG.
- resolverd in front of dnsd logs no `DNSSEC BOGUS` for these answers.
- No NSEC3 record appears in any response.
- `check-negttl`, `check-aggressive-nsec`, `check-dnssec`, `check-dnssec-live`,
  `check-conformance` pass.

### Test

Extend `tests/dnssec_validate.py` and `check-dnssec-validate`:

```sh
LISTEN_PORT=$TPORT ./dns_server_debug & DNS=$!; sleep 2
python3 tests/dnssec_validate.py 127.0.0.1 $TPORT example.local nxname  nope      # NOERROR + NSEC{RRSIG NSEC NXNAME}, sigs valid
python3 tests/dnssec_validate.py 127.0.0.1 $TPORT example.local nxname-co nope    # rcode NXDOMAIN when CO set
python3 tests/dnssec_validate.py 127.0.0.1 $TPORT example.local nodata  www AAAA  # bitmap has A, not AAAA; sigs valid
python3 tests/dnssec_validate.py 127.0.0.1 $TPORT example.local qtype128          # FORMERR + EDE 30

# end-to-end through the project's own validator
LISTEN_PORT=5354 ./resolverd_debug --upstream 127.0.0.1:$TPORT > /tmp/rd.log 2>&1 & RD=$!; sleep 2
dig @127.0.0.1 -p 5354 nope.dv.test A +time=3 +tries=1 >/dev/null
! grep -q 'DNSSEC BOGUS' /tmp/rd.log
kill $DNS $RD
```

Use a non-`.local` test zone for the resolverd leg: resolverd sends `.local`
names to mDNS first.

Add the validator run to CI as a blocking job; `check-dnssec-live` only counts
RRSIG records and did not catch any of the three defects in this file.
