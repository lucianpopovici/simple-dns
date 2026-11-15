# Module 1 — Research Landscape Map

Corpus: 32 items (papers/P001–P032), see `../corpus.csv` for full metadata.

## Research Topic

How the DNS protocol's trust model breaks down in practice — at the
cryptographic layer (DNSSEC), the transport-confidentiality layer (encrypted
DNS), the cache-integrity layer (poisoning/hijacking), and the availability
layer (amplification, resource-exhaustion, implementation bugs) — and what
measurement studies say about real-world deployment of the defenses meant to
fix each layer.

## Paper Groups (by subtopic)

| Group | Papers | Count |
|---|---|---|
| DNSSEC deployment & validation | P001, P002, P003, P004, P029, P030 | 6 |
| Encrypted DNS (DoH/DoT/DoQ/ODoH) | P005, P006, P007, P008, P017, P018, P019, P020, P021 | 9 |
| Cache poisoning / hijacking | P009, P010, P022, P024, P025, P032 | 6 |
| Tunneling / DGA / malicious-domain detection | P011, P026 | 2 |
| Amplification / reflective DDoS | P012, P013 | 2 |
| Infrastructure measurement (centralization, dependency DoS) | P014, P015, P023 | 3 |
| Survey (cross-cutting) | P016 | 1 |
| Measurement datasets/tooling (not threats themselves) | P027, P028 | 2 |
| Implementation-bug advisories | P031 | 1 |

(P032 counted under cache-poisoning but is also an implementation-bug
advisory — dnsmasq's overflow and its poisoning weakness are reported in the
same CVE batch.)

## Major Themes

1. **DNSSEC is specified but not delivered.** P001/P002 show signing and
   validation adoption stalls on registrar incentives and chain-of-trust
   misconfiguration, not crypto weakness. P029/P030 (KeyTrap) then show that
   even where validation *is* turned on, the spec itself permits an
   algorithmic-complexity DoS — so "deploy DNSSEC" and "DNSSEC is safe to
   deploy" are separate, both-still-open claims.
2. **Encryption ≠ privacy.** The largest theme by paper count (9). The
   standards (P018–P021) define confidential transports, but the evaluation
   papers (P005–P008, P017) repeatedly find the confidentiality is partial:
   traffic analysis re-identifies domains through DoH/DoT (P005), padding
   defenses don't work (P005), DoH is fingerprintable from traffic shape
   alone (P007), and even ODoH's identity/query decoupling depends on a
   non-collusion trust assumption (P008). QNAME minimization (P017, spec
   P020) addresses a different leak (upstream-recursive exposure) than
   traffic analysis does (on-path/network exposure) — two privacy threats,
   not one.
3. **Cache poisoning never stayed solved.** Source-port randomization (the
   post-Kaminsky fix) is repeatedly defeated by side channels: SAD DNS
   (P009) via ICMP rate-limit state, its 2021 follow-up (P010) with new
   channels, and independently, fragmentation-based off-path attacks (P025).
   P022 (MaginotDNS) and P032 (DNSpooq) show the same failure mode recurring
   at a different layer — forwarder/recursive boundary trust and
   implementation-level query/reply matching — i.e., the *protocol* fix
   (randomization) and the *implementation* fix (correct bailiwick/matching)
   are both incomplete on their own.
4. **Availability attacks exploit operational, not protocol, choices.**
   Amplification (P012, P013) abuses open/misconfigured resolvers; TsuNAME
   (P023) abuses cyclic NS dependency misconfiguration to turn ordinary
   resolver behavior into a DDoS amplifier against authoritatives. Neither
   requires a protocol break — they are misconfiguration + amplification
   physics.
5. **The DNS ecosystem is centralizing**, independent of any specific
   attack: P014 (cloud-provider query share) and P015 (shared authoritative
   infrastructure) both find a small number of providers underlie a large
   fraction of the system, which changes the blast radius of any of the
   above failure classes (a poisoning/DoS/outage at one of those providers
   has system-wide reach).
6. **Implementation bugs are a parallel, software-specific failure mode**
   distinct from protocol design: P031 (SIGRed, a parser heap overflow) and
   the parsing half of P032 show that the same bounds-checking discipline
   this project's CLAUDE.md mandates for wire parsing is exactly the lesson
   these incidents teach — DNS response parsing is hostile-input parsing.

## Core Concepts

- **Chain of trust** (DNSSEC: DS → DNSKEY → RRSIG) and where it breaks
  (registrar non-support, misconfigured DS, non-validating resolvers).
- **Off-path attacker model**: shared inference channels (ICMP, fragmentation)
  that substitute for an on-path vantage point — the common thread across
  P009/P010/P025.
- **Trust-boundary confusion**: separating roles that should not share state
  (validation/recursive caching boundary, forwarder bailiwick checks).
- **Traffic-analysis threat model for encryption**: confidentiality of
  *content* (the query) vs. observability of *shape* (timing/size patterns)
  — encryption defeats the former, not necessarily the latter.
- **Algorithmic-complexity DoS**: a spec-conformant validator can be forced
  into worst-case work by a crafted but valid-looking input (KeyTrap).
- **Centralization / single point of failure**: concentration of either
  query origin (P014) or hosting infrastructure (P015) as a structural risk
  multiplier, not an attack in itself.
- **Misconfiguration as an attack surface**: cyclic NS dependencies (P023),
  weak bailiwick checks (P022) — both are "correct" protocol behavior
  applied to a configuration the protocol didn't anticipate.

## Areas Of Agreement

- DNSSEC's *design* is sound but its *deployment* is the weak point — every
  DNSSEC-deployment paper here (P001, P002) and the survey (P016) converge on
  registrar/operator incentive and configuration failure, not cryptography,
  as the blocker.
- Source-port randomization alone is not sufficient cache-poisoning defense;
  every poisoning paper in the corpus (P009, P010, P022, P025, P032) finds a
  way around it or around an adjacent assumption (forwarder/recursive
  separation, query/reply matching).
- Encrypted-DNS standards solve confidentiality-in-transit but were never
  claimed to solve traffic-analysis privacy or detectability — the
  evaluation papers' findings are consistent with, not contradicting, the
  standards' own stated scope.
- Measurement at Internet scale is the dominant method in this literature:
  almost every peer-reviewed entry (P001, P002, P014, P015, P017, P022,
  P023, P029) is a large-scale active or passive measurement study, not a
  lab experiment — this is an empirically-grounded field.

## Areas Of Debate

- **Does encrypted DNS meaningfully help against censorship?** P006 finds a
  partial, contested benefit — circumvention works for the DNS lookup step
  but censors retain other blocking levers (SNI/IP), so the *practical*
  privacy/circumvention gain is debated rather than settled.
- **How real is the amplification "decline"?** P013 explicitly flags a
  reported 2021–22 drop in amplification attacks as something to interrogate
  for measurement-methodology bias rather than accept as a real trend —
  open question, not consensus.
- **Scope of "fixed" for SAD DNS**: P009's mitigations were treated as
  closing the issue; P010 reopens it with new channels — the literature has
  not converged on whether the side-channel class is patchable in general or
  whether it recurs structurally (shared kernel/network state will keep
  producing new channels).
- **Severity attribution for off-path attacks**: P025's fragmentation attack
  and P022's CDNS attack both claim wide real-world exposure, but exposure
  estimates in this kind of work are scan-methodology-dependent (e.g. P022's
  41.8% CDNS prevalence figure is a probe-based estimate, not a census) —
  treat headline percentages as orientation, not precise population figures.

## Research Landscape Summary

The field treats DNS as a system whose original trust assumptions
(authenticated zone data is unnecessary because no one would bother to lie,
and an off-path attacker can't guess a 16-bit transaction ID) have been
progressively patched (DNSSEC, source-port randomization, encrypted
transports, bailiwick checking) and then progressively un-patched by new
side channels, new measurement showing the patch wasn't actually deployed, or
new attack classes the patch didn't anticipate. Four mostly-independent
failure surfaces recur: (1) DNSSEC deployment/validation gaps and the
validator's own algorithmic-complexity exposure, (2) encrypted-DNS transports
that protect content but not traffic shape, (3) cache-poisoning side
channels that keep resurfacing after each round of mitigation, and (4)
availability attacks that exploit misconfiguration and centralization rather
than protocol flaws. For this project's authoritative/recursive server
(`dnsd`/`resolverd`), the most directly actionable clusters are the
cache-poisoning/forwarder-boundary papers (P022, P032 — bailiwick and
query/reply matching are exactly the `dnsd`/`resolverd` boundary), the
parser-hardening lesson (P031), and the KeyTrap algorithmic-complexity class
(P029/P030, relevant to `resolverd`'s DNSSEC validation path); the
encrypted-DNS privacy papers are most relevant to evaluating `apid`'s DoH
surface and the planned `doqd` (see `CLAUDE-DoQ.md`).
