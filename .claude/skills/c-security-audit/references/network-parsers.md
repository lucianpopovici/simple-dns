# references/network-parsers.md — DNS / resolver / request-response parsers

Load during Pass 3 when the target speaks a request/response protocol.

## Response/request correlation (off-path spoofing)
- Does the client verify the **response transaction ID == the query ID**? Grep
  the response path for a comparison against the sent ID. Its absence is a finding
  even on a connect()ed UDP socket — the kernel filters addr:port only, so an
  unchecked ID halves the off-path spoofer's search space.
- Does it verify the **question / echoed request matches** what was asked
  (QNAME/QTYPE for DNS)? Accepting any answer that arrives on the socket is the
  classic cache-poisoning enabler.
- Transaction IDs, source ports, cookies, nonces must come from a **CSPRNG**
  (`RAND_bytes`/`getrandom`), never `rand()`/`srand(time())`. For a resolver these
  are the primary anti-spoofing entropy; predictable → poisoning.
- Consider 0x20 query-name case randomisation as defense-in-depth (DNS).

## DNS wire specifics
- Name decompression: pointers must target a **strictly prior** offset; a
  visited-set or step cap must bound loops; every label copy bounds-checked
  against both packet end and output buffer.
- EDNS/OPT option walk: each option header (code+len) and its payload
  bounds-checked against min(rdlen-end, packet-end) before any copy.
- QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT are attacker-supplied counts — never use them
  as loop bounds without a per-iteration `off < plen` guard.

## TSIG / MAC / cookie
- Verify the MAC covers the **correct byte range** — a verifier that compiles and
  passes on valid input may cover the wrong bytes. Require a flipped-byte negative
  test, not just a known-answer test.
- Compare MACs / cookies / shared secrets with `CRYPTO_memcmp`, never
  `memcmp`/`strcmp` (timing oracle).
