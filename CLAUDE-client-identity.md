# dns_server.c / apid.c / doqd.c — who is the client?

Fix spec for audit findings **CSA-NET-003** (High), **CSA-AUTH-006** (Medium)
and **CSA-DOS-004** (Medium). Source: `SECURITY_AUDIT.md`, section
2026-11-15. Roadmap: Phase 0b step 6. All three change what dnsd treats as
"the client", which RRL, DNS cookies and every ACL (`axfr_allow`,
`forward_allow`, `update_unsigned_allow`) key on, so they land together.

| Fix | Finding | Status |
|----:|---------|--------|
| 1 | CSA-NET-003 — every IPv6 client is `0.0.0.0` | **Done** 2026-11-15 |
| 2 | CSA-AUTH-006 — every DoH/DoQ client is `127.0.0.1` | **Done** 2026-11-15 (Option A, PROXY v2) |
| 3 | CSA-DOS-004 — RRL keyed on qname; collisions reset buckets | **Done** 2026-11-15 |

Implementation notes: `client_addr_t`, `client_from_sockaddr`,
`client_is_loopback`, `proxy_v2_build/parse` and `dns_relay_loopback` live in
libdnswire (PROXY v2 has table tests in `make check-wire`); apid and doqd
each dropped their own `dns_forward` copy for the shared relay. dnsd accepts
the header on its UDP listeners (v4 + v6) and on the plain-TCP listener
(peeked, then consumed) only from 127.0.0.0/8 or ::1; the DoT listener never
reads it. ACL lists take IPv6 entries. `make check-client-identity` (in CI)
fails every case against the pre-change dnsd/apid (IPv6 allow-list
ignored, PROXY header rejected as FORMERR, DoH from 127.1.0.1 accepted via a
127.0.0.1 allow-list, 40/40 random-name NXDOMAINs answered) and passes after
(5/40 answered in full, the rest TC or dropped; another client unaffected).
Not covered end to end: DoQ (needs a QUIC client in CI) — doqd uses the
same relay and `SSL_get_peer_addr`.

---

## Fix 1: carry the real address, v4 or v6 (CSA-NET-003)

### What it is

`dns_process` and everything below it take `const struct in_addr *cip`. The
IPv6 UDP and DoT listeners (`IPV6_V6ONLY`, so never v4-mapped) pass a
`0.0.0.0` placeholder: all IPv6 clients share one RRL bucket and one cookie
identity, and match an ACL only through a `0.0.0.0`-covering entry.

### What to build

1. `client_addr_t { int family; union { struct in_addr v4; struct in6_addr v6; } }`
   with `client_from_sockaddr()` (v4-mapped v6 → v4) and
   `client_ntop()`; replace `const struct in_addr *cip` in `dns_process`,
   `build_query_resp`, `handle_update`, `forward_should`,
   `forward_dispatch_udp`, `dnsd_edns_opt`, `cookie_verify`,
   `compute_server_cookie`, `rrl_check`, `ip_list_allowed`, the NOTIFY
   source check, and `dot_conn_t` / `axfr_conn_t` / `fwd_work_t`.
2. ACL lists accept IPv6 addresses and prefixes (`2001:db8::/32`, `::1`)
   alongside IPv4; an entry only matches its own family; a malformed entry
   (including a prefix > 32 / > 128) matches nothing (fail closed, as Fix 3
   of CSA-AUTH-005 already does for v4).
3. Server cookies hash the full client address (4 or 16 octets) plus the
   family, so a v4 and a v6 client never share a cookie.
4. The `cip->s_addr != 0` "unknown client" guard on the unsigned-UPDATE
   allow-list becomes `family != 0`.

### Guardrail (do NOT)

- **Do NOT** map IPv6 clients into IPv4 space (hashing, truncating) to keep
  the old type.
- **Do NOT** let an IPv4 ACL entry match an IPv6 client or vice versa,
  except v4-mapped v6, which is normalised to v4 first.

---

## Fix 2: front-ends pass the client address (CSA-AUTH-006)

### What it is

apid (DoH) and doqd (DoQ) relay to dnsd over loopback UDP (TCP on TC), so
dnsd sees `127.0.0.1` for all of them: one RRL bucket and cookie identity,
and any ACL that lists loopback (`update_unsigned_allow`, `forward_allow`)
is open to every DoH/DoQ client on the internet.

### Options

- **A (chosen): PROXY protocol v2 header on the loopback hop.** The relay
  prepends a binary PROXY v2 header (HAProxy spec §2.2: 12-octet signature,
  `0x21` = v2 PROXY, family `0x12` UDP4 / `0x22` UDP6 / `0x11` TCP4 /
  `0x21` TCP6, length, addresses) to each UDP datagram and to the start of
  the TCP connection. dnsd accepts it **only from a loopback source**
  (`127.0.0.0/8`, `::1`), strips it and uses the carried source address as
  the client. A DNS message cannot start with the signature (its QDCOUNT
  would be 13), so there is no ambiguity. The front-ends still never parse
  DNS — they prepend fixed bytes.
- B: private EDNS option — needs the front-ends to parse and rewrite the
  OPT RR, against their "never parse DNS" design.
- C: apply client policy in the front-ends — duplicates RRL/ACL/cookies.

### What to build

1. libdnswire: `proxy_v2_build()`, `proxy_v2_parse()` (bounds-checked,
   fail closed, skips TLVs) and `dns_relay_loopback(port, client, …)` —
   the UDP-then-TCP-on-TC relay that apid and doqd each had a copy of,
   now in one place, prepending the header.
2. apid passes the HTTP client's address (`getpeername`); doqd the QUIC
   peer address (`SSL_get_peer_addr`).
3. dnsd: on the UDP listeners and the plain-TCP listener, if the source is
   loopback and the payload starts with the signature, parse; a malformed
   header from loopback drops the datagram / closes the connection. Never
   honoured on the DoT listener or from a non-loopback source.

### Guardrail (do NOT)

- **Do NOT** accept the header from a non-loopback source — it would let
  anyone choose their own client address.
- **Do NOT** honour `LOCAL` (command `0x20`) as anything but "no client
  address": keep the loopback source.

---

## Fix 3: RRL keyed on the client prefix (CSA-DOS-004)

### What it is

`rrl_check` (`dns_server.c:5725`) keys on `/24 XOR hash(qname)` in a
4,096-entry direct-mapped table where a key mismatch resets the bucket.
Random subdomains get a fresh bucket each, so the NXDOMAIN flood RRL exists
for is never limited, and an attacker can reset a victim's bucket by
colliding with it. The check also runs before the response is classified.

### What to build

1. Client prefix: IPv4 /24, IPv6 /56.
2. Key: negative answers (NXDOMAIN, NODATA) on `(prefix, zone)`; positive
   answers on `(prefix, qname, qtype)`; referrals on `(prefix, zone)`.
3. Run the check after the response is classified (after the negative
   branch), before truncation / EDNS.
4. A key mismatch no longer resets the bucket while the occupant's window is
   live: the newcomer shares (and is limited by) the occupant's tokens; the
   bucket is taken over only after its window has elapsed.

### Guardrail (do NOT)

- **Do NOT** turn RRL on by default here.
- **Do NOT** rate-limit TCP (unchanged: TCP is the escape hatch).

---

## Test

`make check-client-identity` (Valkey + dig + curl + python3-dnspython):

- IPv6: `config:update_unsigned_allow=::1` → unsigned UPDATE over `::1`
  accepted; `=127.0.0.1` → the same UPDATE over `::1` refused. A cookie
  exchange over `::1` validates.
- ACL v6 parse: a malformed v6 entry matches nothing.
- PROXY v2: an UPDATE wrapped in a header claiming `127.1.0.1`, sent from
  loopback, is judged as `127.1.0.1`; the same header from a non-loopback
  source is ignored (not reachable in a single-host test: covered by unit
  test of the gate).
- DoH: with `update_unsigned_allow=127.0.0.1`, an unsigned UPDATE POSTed to
  apid's `/dns-query` from `127.1.0.1` is refused (before the fix apid's
  loopback address made it pass).
- RRL (`rrl_rate=5`): 60 random-name NXDOMAIN queries from one client are
  mostly dropped or truncated; a second client (`127.1.0.1`) is still
  answered; positive answers for distinct names are unaffected.
- `check-wire`: PROXY v2 build/parse round trip, truncated / bad-version /
  bad-length headers rejected, TLVs skipped.
