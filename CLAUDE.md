# Extending `handle_update` for TXT, CNAME, MX, SRV (and the PTR/NAPTR question)

## Context

`dns_server.c` implements RFC 2136 DNS UPDATE in `handle_update()` (around line 2768).
The current implementation only processes `A` (type 1) and `AAAA` (type 28) records and
silently drops everything else. The server returns `NOERROR` regardless, which makes the
partial support easy to miss — clients think the update succeeded when in fact the RR
was discarded.

This task extends `handle_update` to accept four additional types (`TXT`, `CNAME`, `MX`,
`SRV`) so external ACME clients using RFC 2136 `nsupdate` can write the
`_acme-challenge.<domain>` TXT records that DNS-01 validation requires.

`PTR` and `NAPTR` are discussed at the end with honest caveats — do not add them
until you have read that section.

---

## Storage contract (CRITICAL — read before writing any code)

`handle_update` writes to Valkey. The query builder in `build_query_resp` reads from
Valkey. The storage format is a **per-type pipe-separated string prefixed by TTL**. The
query path lives around lines 2490–2570 of `dns_server.c` and that format is the
contract — the update handler MUST produce strings the query path can parse back.

For the Valkey-stored types, the key format is always:

```
zone:<TYPE>:<fqdn>        e.g. zone:TXT:_acme-challenge.dns.corp.local
```

and the value format (note the leading TTL, then `|`-separated fields) is:

| Type  | Valkey value format                              | Notes |
|-------|--------------------------------------------------|-------|
| TXT   | `<ttl>\|<text>`                                  | text is a single character string (wire TXT rdata format is `<len><bytes>`); max 255 bytes |
| CNAME | `<ttl>\|<target-fqdn>`                           | target is stored as a text FQDN — **not wire format** |
| MX    | `<ttl>\|<pref>\|<target-fqdn>`                   | preference is a decimal integer |
| SRV   | `<ttl>\|<prio>\|<weight>\|<port>\|<target-fqdn>` | all decimal |

The query path's parser uses `strtok(pipe, "|")` in field order. Your update handler
must write values in exactly that order with exactly those separators.

---

## What the update handler receives on the wire

In `handle_update()`, the loop over `h->nscount` processes update RRs. For each RR you
already have the parsed wire data in scope:

```c
const uint8_t *rd  = pkt + off;   /* rdata bytes */
uint16_t       rdlen;              /* rdata length */
uint32_t       uttl;               /* RR TTL */
uint16_t       ut;                 /* RR type */
uint16_t       uc;                 /* RR class (IN / ANY / NONE) */
char           un[256];            /* owner name, lowercased FQDN */
```

The existing A/AAAA branches show the pattern. Three RFC 2136 classes matter:

| Class                | Meaning (RFC 2136 §2.5)                    | rdlen |
|----------------------|--------------------------------------------|-------|
| `DNS_CLASS_IN` (1)   | Add RR (or replace, for single-valued types) | > 0  |
| `DNS_CLASS_ANY` (255)| Delete all RRs at name (if type is ANY) or of the given type | 0 |
| `DNS_CLASS_NONE`(254)| Delete specific RR matching rdata | > 0 |

The current code treats ANY and NONE identically (delete all of that type). Keep that
simplification — RFC 2136 compliance for NONE's "delete specific RR" is only required
for clients that intend to remove exactly one value from a multi-valued RRset. ACME
clients always write then (after validation) delete all, so ANY-class deletion is
sufficient.

---

## Wire parsing you need to implement

### TXT (RFC 1035 §3.3.14)

Wire format: one or more `<len><string>` character strings back-to-back. For ACME
DNS-01 there is always exactly one string. The simplest correct implementation reads
only the first string — that matches every real ACME client:

```c
else if(ut==DNS_TYPE_TXT && uc==DNS_CLASS_IN && rdlen>=1){
    /* rd[0] is the length prefix; rd[1..] is the text */
    uint8_t sl = rd[0];
    if(sl > rdlen-1 || sl > 255) goto formerr;
    char txt[256];
    memcpy(txt, rd+1, sl);
    txt[sl] = 0;
    char val[320];
    snprintf(val, sizeof(val), "%u|%s", uttl?uttl:DEFAULT_TTL, txt);
    snprintf(k, sizeof(k), "zone:TXT:%s", un);
    vk_set(k, val, 0);   /* 0 = persist; do not set an EX on zone records */
    serial_bump();
    dns_log(LOG_NOTICE, "[UPDATE] TXT %s = %.60s%s\n",
            un, txt, sl>60?"...":"");
}
```

Note the TTL in the Valkey value (stored) is independent of the Valkey key TTL
(expiration). Zone records should persist — pass `0` as the `vk_set` TTL argument.
ACME TXT records are cleaned up by the client when validation completes via a
subsequent UPDATE with class ANY.

### CNAME (RFC 1035 §3.3.1)

Wire format: a compressed domain name. Use the existing `name_from_wire` helper —
it already handles compression pointers.

```c
else if(ut==DNS_TYPE_CNAME && uc==DNS_CLASS_IN && rdlen>=1){
    char target[256];
    /* name_from_wire needs the full packet for compression pointer resolution */
    int consumed = name_from_wire(pkt, plen, (int)(rd - pkt), target, sizeof(target));
    if(consumed < 0) goto formerr;
    char val[320];
    snprintf(val, sizeof(val), "%u|%s", uttl?uttl:DEFAULT_TTL, target);
    snprintf(k, sizeof(k), "zone:CNAME:%s", un);
    vk_set(k, val, 0);
    serial_bump();
    dns_log(LOG_NOTICE, "[UPDATE] CNAME %s -> %s\n", un, target);
}
```

The offset passed to `name_from_wire` must be the absolute offset into `pkt`, not a
relative offset into `rd`. That's why we use `(int)(rd - pkt)`.

### MX (RFC 1035 §3.3.9)

Wire format: 16-bit preference followed by a compressed domain name (exchange).

```c
else if(ut==DNS_TYPE_MX && uc==DNS_CLASS_IN && rdlen>=3){
    uint16_t pref = (rd[0]<<8) | rd[1];
    char target[256];
    int consumed = name_from_wire(pkt, plen, (int)(rd - pkt) + 2, target, sizeof(target));
    if(consumed < 0) goto formerr;
    char val[384];
    snprintf(val, sizeof(val), "%u|%u|%s", uttl?uttl:DEFAULT_TTL, pref, target);
    snprintf(k, sizeof(k), "zone:MX:%s", un);
    vk_set(k, val, 0);
    serial_bump();
    dns_log(LOG_NOTICE, "[UPDATE] MX %s -> %u %s\n", un, pref, target);
}
```

### SRV (RFC 2782)

Wire format: priority (u16), weight (u16), port (u16), target (compressed name).

```c
else if(ut==DNS_TYPE_SRV && uc==DNS_CLASS_IN && rdlen>=7){
    uint16_t prio   = (rd[0]<<8) | rd[1];
    uint16_t weight = (rd[2]<<8) | rd[3];
    uint16_t port   = (rd[4]<<8) | rd[5];
    char target[256];
    int consumed = name_from_wire(pkt, plen, (int)(rd - pkt) + 6, target, sizeof(target));
    if(consumed < 0) goto formerr;
    char val[384];
    snprintf(val, sizeof(val), "%u|%u|%u|%u|%s",
             uttl?uttl:DEFAULT_TTL, prio, weight, port, target);
    snprintf(k, sizeof(k), "zone:SRV:%s", un);
    vk_set(k, val, 0);
    serial_bump();
    dns_log(LOG_NOTICE, "[UPDATE] SRV %s -> %u %u %u %s\n",
            un, prio, weight, port, target);
}
```

---

## Deletion branch

In the existing `else if((uc==DNS_CLASS_ANY||uc==DNS_CLASS_NONE)&&rdlen==0)` block,
extend it to delete the new types as well:

```c
if(ut==DNS_TYPE_TXT   || ut==DNS_TYPE_ANY){ snprintf(k,sizeof(k),"zone:TXT:%s",un);   vk_del(k); }
if(ut==DNS_TYPE_CNAME || ut==DNS_TYPE_ANY){ snprintf(k,sizeof(k),"zone:CNAME:%s",un); vk_del(k); }
if(ut==DNS_TYPE_MX    || ut==DNS_TYPE_ANY){ snprintf(k,sizeof(k),"zone:MX:%s",un);    vk_del(k); }
if(ut==DNS_TYPE_SRV   || ut==DNS_TYPE_ANY){ snprintf(k,sizeof(k),"zone:SRV:%s",un);   vk_del(k); }
```

---

## TSIG and zone authority

Do not touch the TSIG verification block at the top of `handle_update`. Do not touch
the RFC 2136 §3.1 zone-authority check — if the update is not for our zone, reject it
with `DNS_RCODE_NOTZONE` as the existing code does. Your new branches go inside the
`h->nscount` loop, alongside the existing A/AAAA branches.

---

## Testing

After building, test the TXT path that ACME DNS-01 uses:

```bash
# Write a TSIG key into Valkey first
KEY_B64=$(openssl rand -base64 32)
valkey-cli SET config:tsig_key_name   "tsig-key"
valkey-cli SET config:tsig_secret_b64 "$KEY_B64"
kill -HUP $(pidof dns_server)

# Write the key to a file for nsupdate
cat > /tmp/tsig.key <<EOF
key "tsig-key" {
    algorithm hmac-sha256;
    secret "$KEY_B64";
};
EOF

# Send an UPDATE adding a TXT record
nsupdate -k /tmp/tsig.key <<EOF
server 127.0.0.1 5353
zone corp.local
update add _acme-challenge.test.corp.local 60 TXT "test-challenge-value"
send
EOF

# Verify it's in Valkey
valkey-cli GET "zone:TXT:_acme-challenge.test.corp.local"
# Expected: "60|test-challenge-value"

# Verify it resolves over DNS
dig @127.0.0.1 -p 5353 _acme-challenge.test.corp.local TXT +short
# Expected: "test-challenge-value"

# Delete it
nsupdate -k /tmp/tsig.key <<EOF
server 127.0.0.1 5353
zone corp.local
update delete _acme-challenge.test.corp.local TXT
send
EOF

# Verify it's gone
valkey-cli GET "zone:TXT:_acme-challenge.test.corp.local"
# Expected: (nil)
```

Repeat the test with `CNAME`, `MX 10 mail.corp.local.`, and
`SRV 10 20 443 target.corp.local.` to exercise all four types.

---

# The PTR and NAPTR question — an honest answer

## PTR — only add it if you actually need dynamic reverse DNS

### What PTR is for

PTR records are used exclusively for reverse DNS (PTR queries against
`X.X.X.X.in-addr.arpa` or `X.X…X.ip6.arpa` zones to get a hostname). PTR has
nothing to do with ACME validation — ACME DNS-01 uses TXT records only.

### The complications

PTR records live in **separate zones** — `in-addr.arpa` and `ip6.arpa`. Your
`dns_server` is currently configured for a single forward zone (`g_zone_name`, e.g.
`corp.local`). An update for `10.0.1.5.in-addr.arpa.` would be rejected by the
existing zone-authority check with `NOTZONE` because that name is not under
`corp.local`.

To support PTR updates you'd need to either:

1. Relax the zone-authority check to accept `*.in-addr.arpa` and `*.ip6.arpa`,
2. Or add those reverse zones to the multi-zone table (feature 7 in the server),
3. And extend the forward-zone query path (line ~2490) to include PTR in the
   `pts[]` array — currently it's mDNS-only, so even if you wrote `zone:PTR:...`
   via UPDATE, the forward DNS query path wouldn't serve it.

### Recommendation

**Do not add PTR to `handle_update` in this task.** It's a meaningful feature, but
it requires three coordinated changes (multi-zone registration for arpa zones,
UPDATE handler, query path) and has no connection to the ACME problem this task
is solving. File it as a separate task if reverse DNS updates become a
requirement.

### If you must add it

Wire format is a single compressed domain name. Storage would be
`zone:PTR:<ptr-name>` with value `<ttl>|<target-fqdn>`. You'd then have to add
`DNS_TYPE_PTR` to the `pts[]` array around line 2493 with a parser that looks
exactly like the CNAME branch.

## NAPTR — don't add it

### What NAPTR is for

NAPTR (RFC 2915/3403) is used for telephony URI resolution (SIP, ENUM), S-NAPTR
service discovery, and some legacy URN applications. Real-world use outside
those niches is rare.

### Why it's a bad fit for UPDATE

NAPTR rdata is the most complex of any common record type: `order (u16) |
preference (u16) | flags (length-prefixed string) | services (length-prefixed
string) | regexp (length-prefixed string) | replacement (compressed domain
name)`. Six fields, three of them variable-length byte strings with
length-prefix framing, one of them a compressed name. Parsing this correctly
from the wire requires ~40 lines of careful bounds-checked code, and getting
length-prefix framing wrong is a security issue (buffer over-read).

### The scale question

NAPTR records are almost always provisioned by hand or by a template generator,
not pushed via RFC 2136 UPDATE. The server already supports NAPTR via the
management HTTP API (`POST /zone` with `type=NAPTR`), which uses the simpler
pipe-separated storage format and avoids the wire-format parsing problem
entirely.

### Recommendation

**Do not add NAPTR to `handle_update`.** If you ever need programmatic NAPTR
provisioning, use the HTTP management API. The effort-to-value ratio for a
NAPTR UPDATE parser is very poor, and the security risk of getting the
length-prefix parsing subtly wrong is not worth taking for a feature nobody's
asking for.

---

# Summary of the task

**Add to `handle_update` in `dns_server.c`:**

1. TXT branch — write `zone:TXT:<name>` = `<ttl>|<text>` to Valkey
2. CNAME branch — write `zone:CNAME:<name>` = `<ttl>|<target>` to Valkey
3. MX branch — write `zone:MX:<name>` = `<ttl>|<pref>|<target>` to Valkey
4. SRV branch — write `zone:SRV:<name>` = `<ttl>|<prio>|<weight>|<port>|<target>` to Valkey
5. Extend the existing DELETE branch to cover all four new types

**Do not add:**

- PTR (requires multi-zone infrastructure; out of scope)
- NAPTR (rarely UPDATE-provisioned; wire parsing is error-prone)

**Test with** `nsupdate` using TSIG for all four types, verify both the Valkey
key and the `dig` resolution.

---

# Part 2 — RFC compliance fixes

The server header claims support for ~40 RFCs. Most are correctly implemented,
but nine have real gaps that range from silent data truncation to claimed
features that are stubs. This section describes each gap, why it matters, the
exact location of the problem, and the fix. They are ordered by priority: work
through them top-to-bottom and stop whenever you've addressed the ones you
care about.

Each fix lists the **exact file location** (line numbers as of the
4756-line reference version — verify against current file with `grep` before
editing). Each fix also includes a test procedure. After any fix, run the
full feature-verification grep block (see the project notes) before moving on.

---

## Tier 1 — correctness bugs that break real interop

### Fix 1 — TXT rdata chunking (RFC 1035 §3.3.14)

**What's wrong.** TXT values longer than 255 bytes are silently truncated. RFC
1035 defines TXT rdata as one-or-more `<length><string>` character strings,
each up to 255 bytes. A 300-byte value must be emitted as
`<255><first 255 bytes><45><last 45 bytes>`. The current code cuts at 255.

**Real-world impact.** DKIM public keys (~220–400 bytes base64), large SPF
records with many `include:` entries, Google/Microsoft domain verification
tokens, some ACME account-key thumbprint payloads. Any of these silently
become invalid as soon as they exceed 255 bytes.

**Where.** Six sites, all the same pattern:

```
line 2455 — static_zone A record emitter
line 2508 — zone:TXT:%s provisioned-records emitter
line 2672 — wildcard synthesis emitter
line 3000 — second copy in AXFR emission
line 3347 — mDNS TXT emitter
line 3499 — more mDNS
```

Current code at each site:
```c
case DNS_TYPE_TXT:{int sl=(int)strlen(r->rdata_str);if(sl>255)sl=255;
    rd[0]=(uint8_t)sl;memcpy(rd+1,r->rdata_str,sl);rdlen=(uint16_t)(1+sl);break;}
```

**Fix.** Replace each occurrence with a chunking loop. The cleanest way is to
extract a helper once and call it from all six sites:

```c
/* Encode a TXT string into wire rdata as one or more <len><bytes> character
 * strings, per RFC 1035 §3.3.14.  Returns rdata length, or -1 on overflow. */
static int txt_encode(const char *s, uint8_t *rd, int maxlen){
    int slen = (int)strlen(s), out = 0;
    while(slen > 0){
        int chunk = slen > 255 ? 255 : slen;
        if(out + 1 + chunk > maxlen) return -1;
        rd[out++] = (uint8_t)chunk;
        memcpy(rd + out, s, chunk);
        out += chunk;
        s += chunk;
        slen -= chunk;
    }
    return out;
}
```

Put this helper near `name_to_wire` (around line 1939). Then at each of the
six TXT sites replace the body with:
```c
case DNS_TYPE_TXT:{
    int tl = txt_encode(r->rdata_str, rd, (int)sizeof(rd));
    if(tl < 0) continue;
    rdlen = (uint16_t)tl; break;}
```

(Substitute `pipe` or `vptr` for `r->rdata_str` depending on the site.)

**Test:**
```bash
valkey-cli SET 'zone:TXT:big.corp.local' \
  '300|v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890...'
# (make the value total >255 bytes)
dig @127.0.0.1 -p 5353 big.corp.local TXT
# Expected: the TXT is returned as multiple quoted chunks, reassembled
# by dig into the full value — no truncation.
```

---

### Fix 2 — DNS name compression in responses (RFC 1035 §4.1.4)

**What's wrong.** `name_to_wire` always writes names in full. No compression
pointers are ever emitted. This works, but wastes 30–50% of response bytes on
zones with repetitive names, and causes premature TC=1 on UDP responses that
would otherwise fit.

**Real-world impact.** A response to `ANY example.local` carrying 6 RRs all
under `example.local` emits the 14-byte suffix six times in the answer
section, then again in each RRSIG's signer's-name field. Compression reduces
this to one occurrence plus five 2-byte back-references. On UDP this can be
the difference between a 480-byte response (fits) and a 580-byte response
(truncated, forcing TCP).

**Where.** `name_to_wire` at line 1939, used throughout `append_rr`,
`emit_rr`, and all the rdata builders for CNAME, NS, MX, SRV, SOA, DNAME,
PTR. The `name_from_wire` function at line 1945 already correctly resolves
compression pointers inbound — only the outbound path needs work.

**Fix overview.** This is the largest fix in this document (~60 lines) but
also the one with the most end-user-visible benefit. The strategy is
well-known:

1. Maintain a small per-response table of `(suffix name → byte offset)`
   entries. Suffixes are tracked as pointers to the already-written
   positions in the response buffer.
2. When `name_to_wire_compressed` is asked to emit a name, walk the name
   label-by-label. For each suffix (the current position to the end of the
   name), look up the table. If present, emit a 2-byte back-reference
   (`0xC000 | offset`) and stop. If absent, emit the label normally and
   register the suffix-to-current-offset mapping.
3. Pointer offsets are limited to 14 bits (0x3FFF = 16383 bytes), so the
   table only tracks the first ~16KB of the response. Not a real limitation
   for DNS responses which max out at 16KB UDP or 64KB TCP.

**Implementation.** Introduce a compression context passed through the emit
chain:

```c
typedef struct {
    int      count;
    uint16_t offsets[128];
    char     names[128][256];
} compress_ctx_t;

static void compress_init(compress_ctx_t *cc){ cc->count = 0; }

/* Emit `name` to `buf` starting at `pos`, using `cc` for suffix lookup and
 * updating `cc` with the new suffix offsets we just wrote.
 * `abs_off` is the absolute offset inside the response buffer where the
 * name starts — required so registered pointers are correct.
 * Returns number of bytes written, or -1 on overflow.  */
static int name_to_wire_c(const char *name, uint8_t *buf, int pos, int blen,
                          compress_ctx_t *cc, int abs_off){
    char work[256]; strncpy(work, name, 255); work[255] = 0;
    char *labels[64]; int nlabels = 0;
    for(char *lbl = strtok(work, "."); lbl && nlabels < 64;
        lbl = strtok(NULL, "."))
        labels[nlabels++] = lbl;
    int start = pos;
    for(int i = 0; i < nlabels; i++){
        /* Compose the suffix from label i onward */
        char suffix[256]; int sp = 0;
        for(int j = i; j < nlabels; j++){
            int ll = (int)strlen(labels[j]);
            if(sp + ll + 1 >= (int)sizeof(suffix)) break;
            if(j > i) suffix[sp++] = '.';
            memcpy(suffix + sp, labels[j], ll); sp += ll;
        }
        suffix[sp] = 0;
        /* Lookup existing offset */
        for(int k = 0; k < cc->count; k++){
            if(strcasecmp(cc->names[k], suffix) == 0){
                /* Emit 2-byte pointer */
                if(pos + 2 > blen) return -1;
                buf[pos++] = 0xC0 | (cc->offsets[k] >> 8);
                buf[pos++] = cc->offsets[k] & 0xFF;
                return pos - start;
            }
        }
        /* Register this suffix */
        int suffix_abs = abs_off + (pos - start);
        if(cc->count < 128 && suffix_abs < 0x4000){
            cc->offsets[cc->count] = (uint16_t)suffix_abs;
            strncpy(cc->names[cc->count], suffix, 255);
            cc->count++;
        }
        /* Emit this label */
        int ll = (int)strlen(labels[i]);
        if(pos + ll + 1 >= blen) return -1;
        buf[pos++] = (uint8_t)ll;
        memcpy(buf + pos, labels[i], ll);
        pos += ll;
    }
    if(pos >= blen) return -1;
    buf[pos++] = 0;
    return pos - start;
}
```

Thread `compress_ctx_t *cc` through `append_rr` and `emit_rr` so names inside
rdata (CNAME target, NS target, MX exchange, SRV target, SOA mname/rname,
DNAME target, PTR) can also be compressed. Initialise the context at the top
of `build_query_resp`, register the owner name from the question section,
and pass it downward.

**Warning.** Be careful in rdata where the wire standard says the field is
*not* compressible. For RRSIG the signer's name is written uncompressed
(RFC 4034 §3.1.7). When in doubt, pass `NULL` for the context to disable
compression on a specific name.

**Test:**
```bash
# Create a zone with many repeated suffixes
for i in $(seq 1 20); do
  valkey-cli SET "zone:A:host$i.example.local" "300|10.0.0.$i"
done

# Before the fix:
dig @127.0.0.1 -p 5353 example.local ANY +noedns +nostats | wc -c

# After the fix should be ~30-50% smaller.  Also verify with tcpdump:
tcpdump -i lo -n -s 0 -w /tmp/dns.pcap port 5353 &
dig @127.0.0.1 -p 5353 host1.example.local
# kill tcpdump, then:
tshark -r /tmp/dns.pcap -V | grep -c "compressed"
# Expected: non-zero count of compressed names
```

---

### Fix 3 — DNS Cookie verification + BADCOOKIE (RFC 9018)

**What's wrong.** `cookie_verify` at line 2224 is a stub that always returns 1.
Client cookies are parsed into `ei->client_cookie` but never validated.
Server cookies are never computed, stored, or echoed back. BADCOOKIE (rcode
23) is never emitted. The SipHash-2-4 implementation exists (line 1011) and
the cookie secret is initialised (line 827) — the infrastructure is all there
but unused.

**Real-world impact.** The server is advertised as cookie-capable but
provides zero amplification/spoofing protection. Any attacker can spoof a
source IP and get full amplification. Claiming the RFC while doing nothing
is worse than not claiming it.

**Where.**
- `g_cookie_secret[16]` — line 827 (the 16-byte server secret, `RAND_bytes`
  initialised at startup, line 1385)
- `siphash24()` — line 1011 (already correct)
- `edns_parse` cookie extraction — line 2136
- `cookie_verify` stub — line 2224 (the function we need to actually
  implement)
- Cookie emission in response — line 2171 (this already copies client
  cookie plus server cookie back, but the server cookie computation is
  trivial, not RFC-compliant)

**Fix.** Implement the server-cookie algorithm from RFC 9018 §4.2:

```
server_cookie = SipHash-2-4(
    server_secret,
    client_cookie || version || reserved || timestamp || client_ip
)
```

with version=1, reserved=0, timestamp=32-bit Unix time. Store the server
cookie along with the fresh timestamp in the response. Accept server cookies
from subsequent queries whose timestamp is within the last hour.

Replace `cookie_verify`:

```c
/* RFC 9018 §4.2: Compute expected server cookie.  Output is 16 bytes:
 *   version(1) | reserved(3) | timestamp(4) | hash(8)
 */
static void server_cookie_compute(const uint8_t *client_cookie,
                                  const struct in_addr *cip,
                                  uint32_t timestamp,
                                  uint8_t out[16]){
    out[0] = 1;                                 /* version */
    out[1] = out[2] = out[3] = 0;               /* reserved */
    out[4] = (timestamp>>24)&0xFF; out[5] = (timestamp>>16)&0xFF;
    out[6] = (timestamp>>8)&0xFF;  out[7] = timestamp&0xFF;
    /* Input to hash: client_cookie(8) || out[0..7] || client_ip(4) */
    uint8_t hin[8+8+4];
    memcpy(hin,    client_cookie,  8);
    memcpy(hin+8,  out,            8);
    memcpy(hin+16, &cip->s_addr,   4);
    uint64_t h = siphash24(hin, sizeof(hin), g_cookie_secret);
    memcpy(out + 8, &h, 8);
}

/* Verify cookie from an incoming query.  Returns:
 *   1  = cookie valid (or not present — unenforced)
 *   0  = BADCOOKIE — caller must emit rcode 23 with a fresh server cookie */
static int cookie_verify(const edns_info_t *ei, const struct in_addr *cip){
    if(!ei->has_client_cookie) return 1;
    if(!ei->has_server_cookie) return 0;        /* client sent only C — ask again */
    if(ei->server_cookie_len != 16)   return 0;
    uint32_t ts =
        ((uint32_t)ei->server_cookie[4]<<24) |
        ((uint32_t)ei->server_cookie[5]<<16) |
        ((uint32_t)ei->server_cookie[6]<<8)  |
                   ei->server_cookie[7];
    uint32_t now = (uint32_t)time(NULL);
    if(ts > now || now - ts > 3600) return 0;    /* stale */
    uint8_t expected[16];
    server_cookie_compute(ei->client_cookie, cip, ts, expected);
    return memcmp(expected, ei->server_cookie, 16) == 0;
}
```

Required changes elsewhere:

1. Extend `edns_info_t` (struct near line 2098) to carry `has_server_cookie`,
   `server_cookie[16]`, `server_cookie_len` (you may already have a subset).
2. In `edns_parse` (line 2105), when parsing the COOKIE option, recognise
   the 24-byte form (8 client + 16 server) in addition to the 8-byte
   client-only form.
3. At the call site (line 2340) change `cookie_verify(&ei,cip);` (currently
   discards return value) to:
   ```c
   if(!cookie_verify(&ei, cip)) {
       /* RFC 9018: emit BADCOOKIE with a fresh server cookie, stop processing */
       uint8_t fresh[16];
       server_cookie_compute(ei.client_cookie, cip, (uint32_t)time(NULL), fresh);
       return make_badcookie_response(query, qlen, fresh, resp);
   }
   ```
   You'll need to add `make_badcookie_response` (~30 lines — constructs a
   response with QR=1, rcode=23, OPT RR carrying the 8+16 cookie).
4. Update the outbound cookie emission at line 2171 to write the fresh
   16-byte server cookie (the one just computed) alongside echoing the
   client's 8-byte cookie.

**Test:**
```bash
# 1. Query with no cookie — should succeed normally (cookies aren't required)
dig @127.0.0.1 -p 5353 +nocookie example.local A

# 2. Query with cookie — should receive a server cookie
dig @127.0.0.1 -p 5353 +cookie example.local A
# Inspect output: should see "COOKIE: <16 hex bytes>" in additional section

# 3. Send a deliberately malformed server cookie — should get BADCOOKIE
kdig @127.0.0.1 -p 5353 +cookie=1234567890abcdef1111111122222222333333334444444455555555 \
     example.local A
# Expected: rcode 23 (BADCOOKIE) and a fresh server cookie in the response.
```

---

## Tier 2 — missing functionality real clients and validators exercise

### Fix 4 — DS record type (RFC 4034 §5)

**What's wrong.** The server has no `DNS_TYPE_DS` branch in `build_query_resp`.
A validating resolver or parent-zone operator querying for DS gets NODATA or
REFUSED rather than a computed DS rdata. CDS/CDNSKEY are already synthesised
but those are child-to-parent signals — the parent zone actually wants the
DS record itself.

**Real-world impact.** Any DNSSEC validator walking the chain of trust at a
delegation boundary that lands on this server cannot find a DS to validate
against. For a single-authoritative setup where there is no delegation, this
is moot — but as soon as this server acts as the parent to any subzone (or
you want to publish DS in a parent zone for your own keys), it fails.

**Where.** The DNSKEY/CDS emission block is at line 2391–2420. Add a parallel
DS block immediately after it.

**Fix.** DS rdata per RFC 4034 §5.1:
```
keytag (u16) | algorithm (u8) | digest_type (u8=2 for SHA-256) |
    digest (32 bytes for SHA-256 over DNSKEY rdata)
```

Where the digest input is the owner name (canonical wire) followed by the
DNSKEY rdata (flags + protocol + algorithm + public key).

```c
/* DS (RFC 4034 §5) — serve DS over our KSK(s).  Add right after the
 * DNSKEY/CDS emission block at line ~2420. */
if(qtype == DNS_TYPE_DS || qtype == DNS_TYPE_ANY){
    uint8_t dkrd[68];
    /* P-256 KSK DS */
    if(g_ksk && dnskey_rdata_ksk_ecdsa(g_ksk, dkrd, sizeof(dkrd)) > 0){
        uint8_t dsrd[4 + 32];
        dsrd[0] = g_ksk_tag >> 8;  dsrd[1] = g_ksk_tag & 0xFF;
        dsrd[2] = DNS_ALG_ECDSAP256SHA256;
        dsrd[3] = 2;  /* SHA-256 */
        uint8_t hi[512]; int hp = 0;
        hp += name_to_wire(qname, hi + hp, sizeof(hi) - hp);
        memcpy(hi + hp, dkrd, 68); hp += 68;
        sha256(hi, hp, dsrd + 4);
        int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DS,
                            DNS_CLASS_IN, 3600, dsrd, 4 + 32);
        if(n2 > 0){ off = n2; answers++; found = 1; }
    }
    /* Ed25519 KSK DS — same pattern with rdata length 36 */
    if(g_ksk_ed && dnskey_rdata_ksk_ed25519(g_ksk_ed, dkrd, sizeof(dkrd)) > 0){
        uint8_t dsrd[4 + 32];
        dsrd[0] = g_ksk_ed_tag >> 8;  dsrd[1] = g_ksk_ed_tag & 0xFF;
        dsrd[2] = DNS_ALG_ED25519;
        dsrd[3] = 2;
        uint8_t hi[512]; int hp = 0;
        hp += name_to_wire(qname, hi + hp, sizeof(hi) - hp);
        memcpy(hi + hp, dkrd, 36); hp += 36;
        sha256(hi, hp, dsrd + 4);
        int n2 = append_rr(resp, off, resp_len, qname, DNS_TYPE_DS,
                            DNS_CLASS_IN, 3600, dsrd, 4 + 32);
        if(n2 > 0){ off = n2; answers++; found = 1; }
    }
}
```

Also add `DNS_TYPE_DS` to the `types[]` array around line 2250 so an ANY
query returns it along with DNSKEY.

**Test:**
```bash
dig @127.0.0.1 -p 5353 corp.local DS +dnssec
# Expected: returns DS records, one per KSK, with the SHA-256 digest.
# Cross-verify:
dig @127.0.0.1 -p 5353 corp.local DNSKEY +short | head -1 > /tmp/key
ldns-key2ds -n -2 /tmp/key
# The DS value printed should match what the server returned above.
```

---

### Fix 5 — UPDATE prerequisites (RFC 2136 §2.4)

**What's wrong.** The prerequisite section (answers in the UPDATE message) is
parsed past but never evaluated. Clients that send conditional updates
(e.g. "set A record only if A doesn't already exist") can't get race-safe
behaviour.

**Real-world impact.** Small. Most scripted DDNS clients don't use
prerequisites. The RFC requires them, so for strict compliance they must be
implemented.

**Where.** `handle_update` at line 2768, the `ancount` loop at line 2788.

**Fix.** The prerequisite classes per RFC 2136 §2.4:

| rclass | rtype | rdata | meaning |
|---|---|---|---|
| ANY (255) | ANY | empty | Name exists |
| ANY (255) | != ANY | empty | RRset of that type exists |
| NONE (254) | ANY | empty | Name does not exist |
| NONE (254) | != ANY | empty | RRset of that type does not exist |
| IN (1) | != ANY | non-empty | RRset exactly matches rdata (complex, skip) |

Replace the existing `ancount` loop at line 2788:

```c
for(int i = 0; i < ntohs(h->ancount); i++){
    char nm[256];
    int a = name_from_wire(pkt, plen, off, nm, sizeof(nm));
    if(a < 0 || a + 10 > plen) goto formerr;
    uint16_t rtype  = get16(pkt, a);
    uint16_t rclass = get16(pkt, a + 2);
    uint16_t rdlen  = get16(pkt, a + 8);
    off = a + 10 + rdlen;
    if(off > plen) goto formerr;

    char vkey[512];
    int exists_any = 0;
    if(rclass == 255 || rclass == 254){
        const char *types[] = {"A","AAAA","CNAME","MX","TXT","NS",
                               "SRV","CAA","SSHFP","TLSA","DNAME","LOC",NULL};
        for(int ti = 0; types[ti]; ti++){
            snprintf(vkey, sizeof(vkey), "zone:%s:%s", types[ti], nm);
            char tmp[8];
            if(vk_get(vkey, tmp, sizeof(tmp))){ exists_any = 1; break; }
        }
    }
    if(rclass == 255 && rtype == DNS_TYPE_ANY && !exists_any){
        rh->flags = htons(DNS_QR|DNS_OPCODE_UPDATE|DNS_RCODE_NXDOMAIN);
        return 12;
    }
    if(rclass == 254 && rtype == DNS_TYPE_ANY && exists_any){
        rh->flags = htons(DNS_QR|DNS_OPCODE_UPDATE|DNS_RCODE_YXDOMAIN);
        return 12;
    }
    if(rclass == 255 && rtype != DNS_TYPE_ANY){
        snprintf(vkey, sizeof(vkey), "zone:%s:%s", type2str(rtype), nm);
        char tmp[8];
        if(!vk_get(vkey, tmp, sizeof(tmp))){
            rh->flags = htons(DNS_QR|DNS_OPCODE_UPDATE|DNS_RCODE_NXRRSET);
            return 12;
        }
    }
    if(rclass == 254 && rtype != DNS_TYPE_ANY){
        snprintf(vkey, sizeof(vkey), "zone:%s:%s", type2str(rtype), nm);
        char tmp[8];
        if(vk_get(vkey, tmp, sizeof(tmp))){
            rh->flags = htons(DNS_QR|DNS_OPCODE_UPDATE|DNS_RCODE_YXRRSET);
            return 12;
        }
    }
    /* rclass=IN with non-empty rdata (exact rrset match) — skip for now;
     * requires canonical-form rdata comparison.  Known limitation. */
}
```

Also define the three new rcodes near the existing `DNS_RCODE_NOTZONE`:

```c
#define DNS_RCODE_YXDOMAIN  6
#define DNS_RCODE_YXRRSET   7
#define DNS_RCODE_NXRRSET   8
```

**Test:**
```bash
# "Name must exist" — should fail if name absent
nsupdate -k /tmp/tsig.key <<EOF
server 127.0.0.1 5353
zone corp.local
prereq yxdomain nonexistent.corp.local
update add nonexistent.corp.local 60 A 10.0.0.42
send
EOF
# Expected: NXDOMAIN response.

# "RRset must not exist"
nsupdate -k /tmp/tsig.key <<EOF
server 127.0.0.1 5353
zone corp.local
prereq nxrrset test.corp.local A
update add test.corp.local 60 A 10.0.0.42
send
EOF
# If an A record already exists: YXRRSET.
```

---

## Tier 3 — minor / cosmetic

### Fix 6 — BADVERS for unsupported EDNS version (RFC 6891 §6.1.3)

**What's wrong.** The server parses `ei->version` at line 2129 but never
checks it. The constant `DNS_RCODE_BADVERS 16` is defined at line 205 but
never used.

**Fix.** At the call site where `edns_parse` returns (line 2339), add:

```c
if(ei.present && ei.version != 0){
    /* RFC 6891: response with BADVERS (extended rcode 1 = 16 total).
     * Short response, question echoed, OPT RR carries extended rcode. */
    return make_badvers_response(query, qlen, ei.version, resp);
}
```

The helper builds a minimal response: QR=1, copy ID, echo question, rcode=0
in header, OPT RR in additional section with the extended RCODE field =
`(16 >> 4) & 0xFF` = 1 in the upper 8 bits. ~15 lines.

---

### Fix 7 — DoH GET base64url decode (RFC 8484 §4.1.1)

**What's wrong.** Line 4170 calls `b64std_dec` on the `dns` query parameter.
RFC 8484 requires `base64url` (URL-safe alphabet: `-_` instead of `+/`,
no padding). Standard base64 decoders fail on URL-safe input.

**Where.** Line 4170 in the DoH GET handler.

**Fix.** Add a `b64url_dec` helper (mirror of `b64std_dec`) and use it:

```c
static int b64url_dec(const char *in, uint8_t *out, int olen){
    /* Translate -_ back to +/ and add padding before calling b64std_dec */
    char tmp[4096]; int n = (int)strlen(in);
    if(n >= (int)sizeof(tmp) - 4) return -1;
    for(int i = 0; i < n; i++){
        char c = in[i];
        if(c == '-') tmp[i] = '+';
        else if(c == '_') tmp[i] = '/';
        else tmp[i] = c;
    }
    while(n % 4 != 0) tmp[n++] = '=';
    tmp[n] = 0;
    return b64std_dec(tmp, out, olen);
}
```

Then change line 4170:

```c
uint8_t pkt[BUF_SIZE]; int plen = b64url_dec(dns_b64, pkt, sizeof(pkt));
```

**Test:**
```bash
# Build a DoH GET-form query with proper base64url encoding
DNS=$(printf '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x05local\x00\x00\x01\x00\x01' \
      | base64 | tr '/+' '_-' | tr -d '=')
curl -k "https://127.0.0.1:4443/dns-query?dns=$DNS" \
     -H "accept: application/dns-message" -o /tmp/r.bin
# /tmp/r.bin should be a valid DNS response message
```

---

### Fix 8 — RFC 3597 unknown-RR presentation format

**What's wrong.** The header advertises RFC 3597 but there is no parser for
the `\#` presentation format. The management API takes already-formatted
pipe values, and the query-time emitter for LOC/URI uses type-specific
logic, not the generic `\#` form.

**Two options.**

**Option A (recommended): remove the claim.** Change the header comment to
remove RFC 3597. The server does handle unknown types pass-through (any
key stored in Valkey under `zone:TYPE:fqdn` gets served), which covers the
spirit of RFC 3597 but not the presentation format parsing.

**Option B: implement `\#` parsing.** Add a handler to the `POST /zone`
endpoint that accepts a value of the form `\# 10 00112233445566778899`
(length in decimal followed by hex bytes) and converts to raw rdata.
~40 lines. Only worth doing if you have a real use case.

---

### Fix 9 — TSIG AXFR multi-message MAC chaining (RFC 8945 §5.3.1)

**What's wrong.** For AXFR responses sent as multiple DNS messages, only the
first and last SHOULD carry TSIG RRs. The last message's MAC SHOULD be
computed over the running hash of all previous MACs. The current code (line
2905, `axfr_thread`) does not call `tsig_append` on any AXFR message,
meaning the transfer is unauthenticated from a strict secondary's
perspective.

**Real-world impact.** Strict secondaries (knot, NSD) that require TSIG on
AXFR will reject the transfer. Permissive secondaries (BIND with no TSIG
config) accept it.

**Where.** `axfr_thread` at line 2905. Every `tcp_send_msg` inside the
function should get TSIG on the final message and MAC-chaining on
continuation messages.

**Fix overview.** This is the largest Tier-3 fix because MAC state must
persist across messages. Pseudocode:

```c
uint8_t prior_mac[64]; int prior_mac_len = 0;

/* First AXFR message: normal TSIG, compute + store MAC for chaining */
if(g_tsig_secret_len > 0){
    int tlen = tsig_append_first(mb, mo, sizeof(mb), ntohs(h->id),
                                  0, prior_mac, &prior_mac_len);
    if(tlen > 0) mo = tlen;
}
tcp_send_msg(c.fd, c.ssl, mb, mo);

/* Continuation messages: no TSIG RR, but feed message bytes + timers
 * into the running MAC.  RFC 8945 §5.3.1. */

/* Last AXFR message: TSIG RR attached with chained MAC */
if(g_tsig_secret_len > 0){
    int tlen = tsig_append_last(buf, off, sizeof(buf), ntohs(h->id),
                                 0, prior_mac, prior_mac_len);
    if(tlen > 0) off = tlen;
}
tcp_send_msg(c.fd, c.ssl, buf, off);
```

You'll need to split `tsig_append` (line 1879) into `_first`, `_continuation`,
and `_last` variants that each hash slightly different inputs per RFC 8945
§5.3.1. ~100-line change.

**Test:**
```bash
# Set up a knot secondary pointing at this server with TSIG
# On secondary:
knotc reload
knotc zone-retransfer corp.local
journalctl -u knot -n 50 | grep -i tsig
# Without this fix: "TSIG missing" and abort.
# With this fix:    transfer completes successfully.
```

---

## Build & verification after all fixes

After applying fixes, run the standard build:

```bash
gcc -O2 -Wall \
    -Wno-missing-field-initializers -Wno-misleading-indentation \
    -Wno-unused-result -Wno-unused-function -Wno-format-truncation \
    -Wno-stringop-truncation -Wno-unused-variable -Wno-implicit-fallthrough \
    -Wno-deprecated-declarations \
    -I/tmp/ossl-inc \
    -o /tmp/dns_server /path/to/dns_server.c \
    -L/usr/local/lib -lssl -lcrypto -lpthread \
    -Wl,-rpath,/usr/local/lib
```

Then run the eight-feature verification grep block and confirm counts are
unchanged. The fixes should not break any existing feature.

---

## Summary table

| # | Fix | Priority | LoC | File location |
|---|-----|---|---|---|
| 1 | TXT multi-string chunking | Tier 1 | ~15 | lines 2455, 2508, 2672, 3000, 3347, 3499 |
| 2 | DNS name compression | Tier 1 | ~60 | line 1939 + all emit paths |
| 3 | Cookie verification + BADCOOKIE | Tier 1 | ~60 | lines 2224 (stub), 2340 (call site) |
| 4 | DS record serving | Tier 2 | ~30 | after line 2420 |
| 5 | UPDATE prerequisites | Tier 2 | ~50 | line 2788 |
| 6 | BADVERS on EDNS version != 0 | Tier 3 | ~15 | line 2339 |
| 7 | DoH GET base64url | Tier 3 | ~10 | line 4170 |
| 8 | RFC 3597 presentation format | Tier 3 | 0 or ~40 | header / `POST /zone` |
| 9 | TSIG AXFR multi-message chaining | Tier 3 | ~100 | line 2905 |

**If you only have time for three**: Fix 1 (TXT chunking — breaks DKIM
silently), Fix 2 (compression — biggest efficiency win), Fix 3 (cookies —
claimed but non-functional).
