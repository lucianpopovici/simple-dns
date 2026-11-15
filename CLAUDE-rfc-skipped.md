# RFC triage — skipped list and reasons

This records the RFCs from the StatDNS DNS index (~250 entries) that were
**not** specced, with the reason, so the triage is durable and exclusions are
not re-litigated. It excludes:

- **Already implemented** — see the `dns_server.c` header comment (1034/1035,
  1876, 1995, 1996, 2136, 2181, 2308, 2782, 2931, 3007, 3596, 3597,
  4033–4035, 4255/6594, 4592, 5001, 5155, 5936, 6303, 6672, 6698/7671, 6891,
  7344/8078, 7553, 7828, 7830/8467, 7858, 8080, 8482, 8484, 8659, 8914, 8945,
  9018, 9364, 9619, 6762, 6763, 8555, 7030, 3402/3403).
- **Already specced** — batches 1–3 (`CLAUDE-rfc-additions*.md`: 1794, 5782,
  9460, 9077, 7477, 8976, 9471, 1982, 9715, 9824/4470, 9103, 9859, 9660, 9567),
  the daemons (`CLAUDE-{mdnsd,certd,resolverd,libdnswire}.md`: 8766, 8490, 8765,
  9665, 9664, 9773, 8737, 8738, 9156, 8198, 8767, 9520, 5452, 9462, 9463, 9267,
  8906; Option-B roadmap 8109, 8806, 5011), ENUM (`CLAUDE-ENUM.md`: 6116, 6117,
  6118, 5067, 4769, 4114, 5076), and registry (`CLAUDE-eppd.md`: 5730–5734,
  5910, 3915, 9154, 8748, 8543, 8590, 8909, 9022, 9082/9083).
- **Noted as reference** (no code): 9199, 9210, 8624, 6781, 7583, 9905, 9906,
  9499, 9076, 3833, 7626, 8499, 1912, 2182, 1536, 3425, 7129, 8552, 8553, 8882,
  7558, 6471.

Everything below is **skipped**, grouped by reason.

---

## 1. Internationalized Domain Names (IDN) — out of scope

Label encoding/normalization is a client/registry concern; the server serves
bytes and is case-insensitive (4343). No IDN processing belongs in `dnsd`.

`3492` (Punycode), `5890`–`5895` (IDNA 2008 set), `6452`, `5564`, `5992`,
`4690`, `4713`, `4290`, `4185`, `3743`, `6912`, `6927`, `6055`, `6912`.

## 2. Resolver-internal, not in Option A (some on Option B roadmap)

Recursion/validation internals beyond the forwarding+validating cache scope.

`6840` (DNSSEC clarifications — **candidate** for resolverd validation),
`8310` (DoT/DTLS usage profiles — **candidate** for resolverd),
`5358` (reflector-attack prevention — **candidate** for resolverd),
`8027` (roadblock avoidance), `7646` (negative trust anchors),
`8145`/`8509` (root-KSK signaling/sentinel), `6731` (server selection),
`8106`/`4339`/`9463`-host-side (host/RA config), `9156`-already, `9230`
(Oblivious DoH), `9539` (opportunistic auth↔recursive), `9704` (split-horizon
authority), `4697`/`4074` (resolver misbehavior BCPs).

## 3. Registry/provisioning beyond `eppd` scope; legacy registry protocols

Pre-EPP or adjacent registry tech superseded by the `eppd` plan.

`3632` (VeriSign RRP), `2832` (NSI RRP), `3375` (registry-registrar reqs),
`9803` (EPP TTL mapping — minor), `5144`/`3982`/`4698` (IRIS), `3707` (CRISP),
`3663` (LDAP admin data), `5731`-already, `9615` (automatic DNSSEC
bootstrapping — **candidate** for eppd parent-side DS).

## 4. DNSSEC algorithm variants not used (you use alg 13 + 15)

`5933`/`9558` (GOST), `5702`/`3110` (RSA/SHA-1/SHA-2), `2536` (DSA),
`6605`-already(ECDSA), `5074`/`4431`/`8749` (DLV — historic),
`4956`/`4955` (opt-in/experiments), `6014`/`6725`/`9157`/`9904`/`4986`
(IANA/process/requirements docs), `2539` (Diffie-Hellman keys).

## 5. Root-server / arpa / reverse-zone infrastructure operations

Not your server's role (you are authoritative for your own zones, not a root or
arpa operator).

`9718`/`7958` (root trust-anchor publication), `9120`/`3172` (arpa NS),
`7720`/`7108`/`8806`-roadmap (root service),
`8501`/`5855`/`3681`/`5158` (reverse-zone ops),
`8777` (AMT discovery), `8880`/`8375` (special-use names ipv4only/home.arpa).
`2317` (classless IN-ADDR) and `3258` (anycast deployment) are **done** — see
the table below, batch 4.

## 6. Host / DHCP / router-advertisement client configuration

Client/CPE side, not a server feature.

`8106`/`4339` (IPv6 RA/host DNS config), `3646`/`3397` (DHCPv6/DHCP search),
`4701` (DHCID RR), `9526` (residential public names), `7393` (PCP dynamic DNS).

*(6147 DNS64 was previously skipped here as a NAT64 resolver feature; it is now
specced in `CLAUDE-resolverd.md` Add 7.)*

## 7. Informational / BCP / architectural essays (no wire to implement)

`6950` (app features in DNS), `5507` (design choices), `3467`/`3071`/`3364`/
`3363` (role/reflections/IPv6 tradeoffs), `8324` ("time for another look"),
`4367` (false assumptions), `4472`/`3901`/`4183` (IPv6/network ops),
`9726` (IoT considerations), `8932` (privacy operators), `8901` (multi-signer —
niche), `6168` (NS management reqs), `5625` (proxy guidelines), `2219` (alias
conventions), `6394` (DANE use cases), `7218` (DANE acronyms), `5535`-n/a,
`3026` (ENUM liaison), `1591`/`1535` (structure/security historic).

## 8. Application-specific SRV / record uses

`6641` (NFSv4), `5864` (AFS), `6186` (email submission), `3832`/`3958`/`4848`
(SLP/DDDS app), `5679` (802.21 mobility), `2163` (MIXER/X.400).

## 9. MIB / SNMP / YANG / capture & data formats

Management/telemetry modeling, not DNS serving.

`9108` (YANG types), `3197`/`1611`/`1612` (DNS MIBs), `8618` (C-DNS capture),
`8427` (DNS-in-JSON), `7745` (reverse-DNS XML schemas).

## 10. Legacy / historic / obsoleted records & mechanisms

`2874`/`3363` (A6 — historic), `1712` (GPOS — superseded by LOC),
`1706` (NSAP), `2230` (KX), `4408` (SPF record — use TXT), `2694` (DNS_ALG NAT),
`4159` (ip6.int), `2540` (detached DNS), `2517` (directory from DNS),
`1788` (ICMP name msgs), `1383` (DNS-based IP routing), `1279` (X.500),
`1101`/`1183` (network names / RP·AFSDB·X25·ISDN·RT legacy RRs),
`974` (mail routing origins), `952`/`921`/`920`/`897`/`881`/`819`/`799`
(pre-DNS host tables / schedules), `2053`/`1956`/`1480`/`2146` (specific
domains), `2352`/`2345` (legal/company names), `1401`/`1394` (IAB/telex),
`3675` (".sex"), `8567` (1-April joke RFC).

## 11. Niche record types (low value for this deployment)

`4025` (IPSECKEY), `7043` (EUI48/EUI64), `3123` (APL), `8005` (HIP),
`4398` (CERT — **borderline**, you do PKI), `6742` (ILNP), `2230` (KX).

## 12. Transport variants superseded or abandoned

`8094` (DNS over DTLS — DoT/DoQ won), `9102` (TLS DNSSEC chain extension —
largely abandoned), `3226` (A6/DNSSEC message size — partly obsolete).

---

## Borderline — deferred but defensible to add later

These are the honest "a reasonable person might add this" exclusions. Each was
left out on purpose, but is a credible future item:

| RFC | What | Where it would go |
|-----|------|-------------------|
| 6840 | DNSSEC clarifications & implementation notes | resolverd validation correctness |
| 5011 | Automated trust-anchor (root KSK) rollover | resolverd (Option B) / dns_client |
| 8310 | DoT/DTLS usage profiles (strict vs opportunistic) | resolverd encrypted upstreams |
| 5358 | Preventing recursive reflector attacks | resolverd hardening |
| 9615 | Automatic DNSSEC bootstrapping (parent from child) | eppd parent-side DS |
| 2931 | SIG(0) verification | **done** 2026-07-03 — dnsd, the SRP prerequisite (`make check-sig0`) |
| 3645 | GSS-TSIG (Kerberos/AD-integrated TSIG) | dnsd, if AD integration is wanted |
| 2930 | TKEY (key establishment) | dnsd, prerequisite for GSS-TSIG |
| 2317 | Classless IN-ADDR.ARPA delegation | **done** — batch 4, Add 12 (`make check-2317`) |
| 3258 | Authoritative NS via shared unicast (anycast) | **done** — batch 4, deployment note (`make check-id-server`) |
| 7479 | Ed25519 SSHFP | dnsd, small SSHFP extension |
| 6604 | xNAME RCODE/status clarification | dnsd CNAME/DNAME correctness |
| 7314 | EDNS EXPIRE option | dnsd, complements AXFR/IXFR |
| 7871 | EDNS Client Subnet (ECS) | dnsd/resolverd — privacy-fraught; pairs with 1794 |
| 8162 | SMIMEA (DANE for S/MIME) | dnsd, DANE sibling record |
| 7929 | OPENPGPKEY (DANE for PGP) | dnsd, DANE sibling record |
| 4398 | CERT records | dnsd, ties to certd PKI |
| 7043 | EUI48/EUI64 records | dnsd, niche record type |
| 9432 | Catalog Zones | **done** — multi-zone provisioning (`make check-catalog`) |
| 9276 | NSEC3 parameter guidance (iterations=0) | dnsd, small DNSSEC compliance |
| 8020 | NXDOMAIN cut | dnsd, denial consistency |
| 7766 | DNS-over-TCP implementation requirements | dnsd, baseline robustness |
| 9250 | DNS over QUIC (DoQ) | dedicated `doqd` sidecar (not dnsd/resolverd) — see `CLAUDE-DoQ.md` |

The remaining five (9276, 8020, 7766, 9250, plus 7314) were discussed in earlier
batches and parked rather than skipped outright — they remain the most likely
"next" additions if scope expands. (9432 was in this group too but has since
shipped as Catalog Zones, row updated above.)
