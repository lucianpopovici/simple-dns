#!/usr/bin/env python3
"""Independent DNSSEC validation of dnsd's answers (dnspython + cryptography),
for `make check-dnssec-validate` (CLAUDE-dnssec-denial.md: CSA-DNSSEC-001,
CSA-PROTO-001, CSA-DNSSEC-002).

Usage:
  dnssec_validate.py SERVER PORT ZONE DENIAL CHECK [ARGS...]

DENIAL is the zone's configured mode, "nsec" or "nsec3" (asserted).
CHECK:
  dnskey                  DNSKEY RRset validates under every RRSIG; each
                          RRSIG(DNSKEY) key tag is a published flags-257 key
  ds-tags                 DS and CDS key tags == the published KSK tags
  nxname LABEL            LABEL.ZONE A, DO, no CO: NOERROR + one compact
                          denial record for a nonexistent name; sigs valid
  nxname-co LABEL         same with Compact Answers OK: NXDOMAIN, CO echoed
  nodata LABEL TYPE T,..  NOERROR + compact NODATA whose bitmap is exactly
                          T,.. (+ RRSIG [+ NSEC]); TYPE absent; sigs valid
                          (LABEL "@" = the apex)
  rcode LABEL TYPE RCODE  without DO: that rcode, no NSEC/NSEC3/RRSIG
  qtype128                QTYPE NXNAME -> FORMERR with EDE 30

Prints "OK <check> ..." and exits 0, or "FAIL <reason>" and exits 1.
"""
import base64
import hashlib
import sys

import dns.dnssec
import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

NXNAME = 128
CO = 0x4000


def fail(msg):
    print(f"FAIL {msg}")
    sys.exit(1)


def ask(server, port, qname, qtype, do=True, co=False, tcp=False):
    q = dns.message.make_query(qname, qtype, want_dnssec=do, use_edns=0)
    if co:
        q.ednsflags |= CO
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, server, port=port, timeout=4)


def dnskeys(server, port, zone):
    r = ask(server, port, zone, "DNSKEY", tcp=True)
    zn = dns.name.from_text(zone)
    rrset = r.find_rrset(r.answer, zn, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    sigs = r.find_rrset(r.answer, zn, dns.rdataclass.IN, dns.rdatatype.RRSIG,
                        dns.rdatatype.DNSKEY)
    return rrset, sigs


def validate_section(section, zone, keyset, what):
    """Validate every non-RRSIG RRset in `section`, one RRSIG at a time."""
    zn = dns.name.from_text(zone)
    keys = {zn: keyset}
    n = 0
    for rrset in section:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            continue
        sigs = [s for s in section if s.rdtype == dns.rdatatype.RRSIG and s.name == rrset.name
                and s.covers == rrset.rdtype]
        if not sigs:
            fail(f"{what}: {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)} has no RRSIG")
        for sigset in sigs:
            for sig in sigset:
                try:
                    dns.dnssec.validate_rrsig(rrset, sig, keys)
                except dns.dnssec.ValidationFailure as e:
                    fail(f"{what}: RRSIG alg {sig.algorithm} tag {sig.key_tag} over "
                         f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: {e}")
                n += 1
    return n


def bitmap_types(rd):
    out = set()
    for window, bitmap in rd.windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    out.add(window * 256 + i * 8 + bit)
    return out


def nsec3_hash(name, salt, iters):
    wire = dns.name.from_text(name).canonicalize().to_wire()
    h = hashlib.sha1(wire + salt).digest()
    for _ in range(iters):
        h = hashlib.sha1(h + salt).digest()
    return h


def b32hex(h):
    std = base64.b32encode(h).decode()
    return std.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                                       "0123456789ABCDEFGHIJKLMNOPQRSTUV")).lower()


def denial_record(resp, zone, qname, denial):
    """Return (owner, rdata) of the single compact-denial record."""
    nsec = [r for r in resp.authority if r.rdtype == dns.rdatatype.NSEC]
    nsec3 = [r for r in resp.authority if r.rdtype == dns.rdatatype.NSEC3]
    if denial == "nsec":
        if nsec3 or len(nsec) != 1 or len(nsec[0]) != 1:
            fail(f"expected exactly one NSEC (got {len(nsec)} NSEC, {len(nsec3)} NSEC3)")
        rr = nsec[0]
        if rr.name != dns.name.from_text(qname):
            fail(f"NSEC owner {rr.name} != qname {qname}")
        nxt = rr[0].next
        want = dns.name.Name((b"\x00",) + dns.name.from_text(qname).labels)
        if nxt != want:
            fail(f"NSEC next {nxt!r} is not the immediate successor \\000.{qname}")
        return rr, rr[0]
    if nsec or len(nsec3) != 1 or len(nsec3[0]) != 1:
        fail(f"expected exactly one NSEC3 (got {len(nsec3)} NSEC3, {len(nsec)} NSEC)")
    rr = nsec3[0]
    rd = rr[0]
    h = nsec3_hash(qname, rd.salt, rd.iterations)
    want_owner = dns.name.from_text(f"{b32hex(h)}.{zone}")
    if rr.name != want_owner:
        fail(f"NSEC3 owner {rr.name} != H(qname) {want_owner}")
    nxt = (int.from_bytes(h, "big") + 1) % (1 << 160)
    if int.from_bytes(rd.next, "big") != nxt:
        fail("NSEC3 next hashed owner is not H(qname)+1")
    if rd.flags != 0:
        fail(f"NSEC3 flags {rd.flags} != 0")
    return rr, rd


def main():
    if len(sys.argv) < 6:
        print(__doc__, file=sys.stderr)
        return 2
    server, port, zone, denial, check = sys.argv[1:6]
    port = int(port)
    args = sys.argv[6:]
    if denial not in ("nsec", "nsec3"):
        fail("DENIAL must be nsec or nsec3")

    if check == "qtype128":
        q = dns.message.make_query(f"x.{zone}", NXNAME, use_edns=0)
        r = dns.query.udp(q, server, port=port, timeout=4)
        ede = [o for o in r.options if o.otype == dns.edns.EDE]
        if r.rcode() != dns.rcode.FORMERR:
            fail(f"QTYPE 128 rcode {dns.rcode.to_text(r.rcode())} != FORMERR")
        if not ede or ede[0].code != 30:
            fail("QTYPE 128 without EDE 30")
        print("OK qtype128 FORMERR EDE 30")
        return 0

    if check == "rcode":
        label, qtype, want = args
        qname = zone if label == "@" else f"{label}.{zone}"
        r = ask(server, port, qname, qtype, do=False)
        if dns.rcode.to_text(r.rcode()) != want:
            fail(f"{qname} {qtype} (no DO) rcode {dns.rcode.to_text(r.rcode())} != {want}")
        bad = [x for x in r.authority if x.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3,
                                                      dns.rdatatype.RRSIG)]
        if bad:
            fail(f"{qname} {qtype} (no DO) carries DNSSEC records")
        print(f"OK rcode {qname} {qtype} {want}")
        return 0

    keyset, keysigs = dnskeys(server, port, zone)
    ksk_tags = {(k.algorithm, dns.dnssec.key_id(k)) for k in keyset if k.flags == 257}
    if not ksk_tags:
        fail("no flags-257 DNSKEY published")

    if check == "dnskey":
        n = validate_section([keyset, keysigs], zone, keyset, "DNSKEY")
        for sig in keysigs:
            if (sig.algorithm, sig.key_tag) not in ksk_tags:
                fail(f"RRSIG(DNSKEY) alg {sig.algorithm} tag {sig.key_tag} matches no published "
                     f"KSK {sorted(ksk_tags)}")
        algs = {s.algorithm for s in keysigs}
        if len(algs) < 2:
            fail(f"RRSIG(DNSKEY) covers only algorithms {algs}")
        print(f"OK dnskey {n} signatures valid; RRSIG(DNSKEY) tags {sorted(ksk_tags)} = KSKs")
        return 0

    if check == "ds-tags":
        out = []
        for t in ("DS", "CDS"):
            r = ask(server, port, zone, t, tcp=True)
            rs = [x for x in r.answer if x.rdtype == dns.rdatatype.from_text(t)]
            if not rs:
                fail(f"no {t} answer")
            tags = {(d.algorithm, d.key_tag) for d in rs[0]}
            if not tags <= ksk_tags:
                fail(f"{t} tags {sorted(tags)} not all published KSKs {sorted(ksk_tags)}")
            out.append(f"{t}={sorted(tags)}")
        print("OK ds-tags " + " ".join(out))
        return 0

    if check in ("nxname", "nxname-co"):
        qname = f"{args[0]}.{zone}"
        co = check == "nxname-co"
        r = ask(server, port, qname, "A", co=co)
        want = dns.rcode.NXDOMAIN if co else dns.rcode.NOERROR
        if r.rcode() != want:
            fail(f"{qname} A rcode {dns.rcode.to_text(r.rcode())} != {dns.rcode.to_text(want)}")
        if co and not (r.ednsflags & CO):
            fail("CO flag not echoed in the response")
        if r.answer:
            fail("answer section not empty")
        rr, rd = denial_record(r, zone, qname, denial)
        bm = bitmap_types(rd)
        want_bm = {NXNAME} if denial == "nsec3" else {dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                                                       NXNAME}
        if bm != want_bm:
            fail(f"bitmap {sorted(bm)} != {sorted(want_bm)}")
        soa = [x for x in r.authority if x.rdtype == dns.rdatatype.SOA]
        if not soa:
            fail("no SOA in authority")
        n = validate_section(r.authority, zone, keyset, qname)
        print(f"OK {check} {qname} rcode={dns.rcode.to_text(r.rcode())} bitmap={sorted(bm)} "
              f"{n} signatures valid")
        return 0

    if check == "nodata":
        label, qtype, tlist = args
        qname = zone if label == "@" else f"{label}.{zone}"
        r = ask(server, port, qname, qtype)
        if r.rcode() != dns.rcode.NOERROR or r.answer:
            fail(f"{qname} {qtype} rcode {dns.rcode.to_text(r.rcode())} answers {len(r.answer)} "
                 "(want NOERROR, no answer)")
        rr, rd = denial_record(r, zone, qname, denial)
        bm = bitmap_types(rd)
        want_bm = {dns.rdatatype.from_text(t) for t in tlist.split(",")}
        want_bm.add(dns.rdatatype.RRSIG)
        if denial == "nsec":
            want_bm.add(dns.rdatatype.NSEC)
        if bm != want_bm:
            fail(f"bitmap {[dns.rdatatype.to_text(t) for t in sorted(bm)]} != "
                 f"{[dns.rdatatype.to_text(t) for t in sorted(want_bm)]}")
        if dns.rdatatype.from_text(qtype) in bm or NXNAME in bm:
            fail("NODATA bitmap contains the queried type or NXNAME")
        n = validate_section(r.authority, zone, keyset, qname)
        print(f"OK nodata {qname} {qtype} bitmap={[dns.rdatatype.to_text(t) for t in sorted(bm)]}"
              f" {n} signatures valid")
        return 0

    fail(f"unknown check {check}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
