# DNS Security Research — Index (memory entry point)

> Read this file first. It is the map. Load detail files only when needed.
> Keep this file SHORT (≤ ~150 lines). Counts and one-line pointers only —
> never paste full summaries or tables here.

## Layout
- `corpus.csv` — every item, one row. Single source of truth for metadata.
- `papers/P###.md` — one short note per item (summary, method, findings, limits).
- `modules/*.md` — outputs of analysis modules 1–9 (landscape, gaps, matrix, …).
- `../../CLAUDE-sec.md` — the prompts that produce all of the above.

## How to load (cheapest → most expensive)
1. This index for orientation and counts.
2. `corpus.csv` to pick relevant IDs (compact; metadata only).
3. The specific `papers/P###.md` for those IDs.
4. A `modules/*.md` file only when working that synthesis.

## Status
- Corpus size: 32 items
- By type: peer-reviewed 18 · preprint 5 · standard 4 · dataset 2 · advisory 3 · tool 0 · grey 0
- Last gather pass: 2026-06-17 — Pass 2, window 2016–2026
- Full text obtained: 0 / 32 (metadata only; PDFs not yet pulled)

## Subtopics (tag → count)
dnssec 6 · encrypted-dns 9 · cache-poisoning 6 · tunneling-dga 2 · amplification 2 · measurement 5 · survey 1 · implementation 1

## Module outputs (status + file)
| # | Module | Status | File |
|---|---|---|---|
| 1 | Landscape map | done | modules/01-landscape.md |
| 2 | Per-paper summaries | done (26 verified, 6 abstract-only) | papers/ (per item) |
| 3 | Research gaps | not started | modules/03-gaps.md |
| 4 | Method comparison | not started | modules/04-methods.md |
| 5 | Strongest arguments | not started | modules/05-arguments.md |
| 6 | Lit-review outline | not started | modules/06-litreview-outline.md |
| 7 | Comparison matrix | not started | modules/07-matrix.md |
| 8 | Plain-English insights | not started | modules/08-plain-english.md |
| 9 | Final synthesis | not started | modules/09-synthesis.md |

## Open threads
- Pass 3 (later): extend window before 2016; the Khormali survey (P016) refs are the fastest source.
- Verify flagged in corpus: P012 (venue of "far side of DNS amplification"), P025 (USENIX'21 vs arXiv URL).
- Still thin: amplification (2), tunneling-dga (2) — add more if these matter to the project.
- Datasets added: OpenINTEL (P027), Tranco (P028). Still missing: DNS-OARC DITL, RIPE Atlas, CIC-Bell-DNS.
- Tools (BIND/Unbound/Knot/PowerDNS source) not yet catalogued as `tool` items.
- Pull full-text PDFs for open-access items (all arXiv + RFC + USENIX links are free).
- Module 2 done: 26 summaries verified-grade, 6 abstract-only need full-text check (P003, P004, P007, P012, P024, P025).
- Module 1 done: 9 groups, 6 major themes, 4 agreement points, 4 debate points. Most project-relevant clusters: cache-poisoning/forwarder-boundary (P022, P032), parser-hardening (P031), KeyTrap algorithmic-complexity (P029/P030), encrypted-DNS privacy (P005-P008, relevant to apid DoH + planned doqd).
- Next analysis step: Module 7 (comparison matrix) — builds directly on Module 1's groups and Module 2's summaries.
