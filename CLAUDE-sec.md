# DNS Security Research — Discovery, Summarization & Review Playbook

Purpose: find, gather, summarize, and review all DNS-security-related research
papers for this project, then synthesize them into a usable literature review.

## How to use this file

Run the modules roughly in order. **Module 0 builds the corpus** (the step the
original version of this file was missing — it assumed papers already existed).
Modules 1–9 analyze that corpus.

- If a paper corpus already exists (a folder of PDFs, a `.bib` file, or a list
  of titles/DOIs), point the relevant module at it instead of re-running
  Module 0.
- "Papers" below means: title + authors + year + venue + abstract at minimum;
  full-text PDF or DOI where available.
- Maintain a single running corpus so every module reads from and writes to the
  same source of truth (see Output Organization below).

## Output organization (memory-efficient — read before writing any output)

All outputs live under `research/dns-security/`, structured so Claude loads
context in layers and never re-reads a giant blob:

```
research/dns-security/
  INDEX.md          # entry point — read FIRST. Map + counts + pointers only.
  corpus.csv        # one row per item. Single source of truth for metadata.
  papers/P###.md    # one short note per item (summary/method/findings/limits).
  modules/NN-*.md   # output of each analysis module (landscape, gaps, matrix…).
```

Rules that keep it memory-efficient:
- **Layered loading.** `INDEX.md` is the only file always read; it stays short
  (≤ ~150 lines) and points to everything else. Open `corpus.csv` to pick IDs,
  then load just the `papers/P###.md` and `modules/*.md` you actually need.
- **Stable IDs.** Each item gets a permanent ID (`P001`, `P002`, …). Everything
  references items by ID.
- **One source of truth, no duplication.** Metadata lives only in `corpus.csv`;
  the per-item summary lives only in `papers/P###.md`; module outputs reference
  items by ID and never re-paste their metadata or summaries.
- **Small, single-purpose files** over one long document, so a task touches the
  minimum context. Use the `_TEMPLATE.md` files as the shape.
- **Update `INDEX.md` after every pass** (counts, subtopic tags, module status,
  open threads) so it stays an accurate, cheap map of the whole corpus.

## Scope — what counts as "DNS security" (use to include/exclude)

Include papers on: DNSSEC (signing, validation, key/algorithm rollover, NSEC/
NSEC3 zone-walking), DNS cache poisoning and spoofing (Kaminsky-class, fragment/
side-channel attacks e.g. SAD DNS), DNS encryption and privacy (DoT, DoH, DoQ,
DNSCrypt, ODoH, QNAME minimization, padding, traffic analysis), DNS-based
threats (tunneling, fast-flux, domain generation algorithms/DGA, typosquatting,
DNS-based malware C2, amplification/DDoS), authentication and integrity (TSIG,
SIG(0), DNS cookies, RPKI-adjacent work), measurement studies of DNS deployment
and misconfiguration, dependency/centralization and resilience, registrar/
registry and domain abuse, encrypted-DNS censorship and circumvention, and
formal/empirical analysis of DNS protocols and resolvers.

Exclude only: material with no DNS-security angle at all (pure performance/
latency tuning, generic networking). Otherwise **include broadly** — see the
resource types below.

### Resource types to gather (include anything that helps the research)

Don't limit the corpus to journal/conference papers. Collect, and tag by type:

- **Peer-reviewed papers** — journals and conferences (primary signal).
- **Preprints & theses** — arXiv, university repositories, PhD/MSc dissertations
  (often the most thorough literature reviews already exist here).
- **Standards & specs** — IETF RFCs and active drafts, ICANN/IANA documents.
  These are the ground truth your project implements against; cite them.
- **Vulnerability & threat data** — CVEs, CERT/CISA advisories, exploit
  write-ups, conference security talks (DEF CON, Black Hat, OARC).
- **Datasets & measurement infrastructure** — OpenINTEL, DNS-OARC DITL,
  Farsight/DNSDB, RIPE Atlas, Censys/Rapid7 scans, CAIDA, Tranco lists. Note
  access terms. These enable your own experiments and let you reproduce others'.
- **Tools & software** — open-source resolvers/servers (BIND, Unbound, Knot,
  PowerDNS), validators, fuzzers, and any research-released code/artifacts.
- **Operator & vendor reports** — Cloudflare, Google, Verisign, APNIC,
  Akamai engineering blogs and measurement posts (label as grey literature).
- **Surveys & SoKs** — systematization-of-knowledge papers and survey articles;
  mine their reference lists first (fastest path to a complete corpus).

Mark every item with a credibility tag: `peer-reviewed`, `preprint`,
`standard`, `grey-literature`, `dataset`, `tool`, or `advisory`. Keep everything;
weight by credibility during synthesis rather than excluding up front.

---

## 0/ DISCOVER & GATHER THE PAPERS  *(run this first)*
<role>
Act as an academic research librarian and systematic-review specialist who can
exhaustively locate research papers on a defined topic across all major sources.
</role>
<task>
Find as many relevant DNS-security resources as possible — papers, standards,
preprints, datasets, tools, advisories, and operator/vendor reports — then
deduplicate, screen, and produce a clean, structured corpus I can feed into the
analysis modules below.
</task>
<steps>
1. Confirm scope with me: time window (e.g. last 10 years vs. all-time) and any
   resource types to exclude. Default: include everything in the Resource Types
   list above, weighting by credibility rather than excluding.
2. Build a search-term set from the Scope section above (DNSSEC, DoH, DoT, DoQ,
   cache poisoning, SAD DNS, DNS tunneling, DGA, fast-flux, amplification, QNAME
   minimization, NSEC3 zone-walking, TSIG, DNS privacy, encrypted DNS, etc.) and
   their synonyms/acronyms.
3. Search across these source types and record where each hit came from:
   - Scholarly indexes: Google Scholar, Semantic Scholar, arXiv, DBLP, ACM DL,
     IEEE Xplore, USENIX, Springer, ScienceDirect.
   - Top security/networking venues to sweep directly: USENIX Security, IEEE
     S&P, ACM CCS, NDSS, PETS/PoPETs, IMC, PAM, SIGCOMM, NSDI, DSN, ESORICS,
     RAID, ACSAC, TMA.
   - Standards: IETF datatracker (RFCs + active drafts), ICANN/IANA documents.
   - Vulnerability/threat: CVE/NVD, CERT/CISA advisories, DNS-OARC, security
     conference talks (DEF CON, Black Hat).
   - Datasets & tools: OpenINTEL, DNS-OARC DITL, RIPE Atlas, CAIDA, Censys,
     Tranco; open-source DNS software repos and research artifact releases.
   - Operator/vendor research: Cloudflare, Google, Verisign, APNIC, Akamai.
4. Start from surveys/SoKs and mine their reference lists, then snowball: for the
   strongest hits, follow forward citations (who cited this) and backward
   citations (its references) to catch items keyword search misses.
5. Deduplicate (same work across arXiv + venue, different versions) and keep the
   most authoritative version.
6. Screen each candidate against the Scope rules; record a one-line relevance
   reason, a subtopic tag, and a credibility/type tag.
7. For each kept item capture metadata: title, authors/org, year, venue/source,
   DOI/URL, citation count (if available), open-access link, type tag, subtopic.
8. Write results into the structure above: append rows to `corpus.csv`, create a
   `papers/P###.md` stub per item, and update `INDEX.md` counts. Flag which items
   still need full text/access (e.g. paywalled papers, gated datasets).
</steps>
<rules>
- Include broadly; clearly label each item's type and credibility rather than
  dropping non-peer-reviewed material.
- Do not invent papers, DOIs, citation counts, venues, RFC numbers, or CVE IDs.
  If a detail can't be verified, mark it "unverified" rather than guessing.
- Note coverage gaps: subtopics, years, or resource types with few/no hits.
- Deduplicate aggressively but never silently drop a distinct item.
- Test: is this corpus broad enough that a DNS-security expert wouldn't say
  "you missed the obvious ones"?
</rules>
<output>
Search Scope → Search Terms Used → Sources Searched → Corpus Table (ID, Title,
Authors/Org, Year, Venue/Source, DOI/URL, Type, Subtopic, Status) → Coverage
Gaps → Items Still To Obtain
</output>

---

## 1/ MAP THE RESEARCH LANDSCAPE
<role>
Act as a top-tier academic researcher who can analyze multiple papers and map the full research landscape clearly.
</role>
<task>
Review the DNS-security papers in the corpus and create a structured overview of the research field.
</task>
<steps>
1. Use the corpus from Module 0 (or ask me to provide papers/titles/abstracts/PDFs if no corpus exists yet)
2. Identify the main research topic across all papers
3. Group the papers into major themes, schools of thought, methods, or subtopics (e.g. DNSSEC, encrypted DNS, cache poisoning, DNS-based threats, measurement)
4. Identify what each group of papers is trying to explain or prove
5. Identify the most cited or most important concepts
6. Identify where researchers agree and disagree
7. Summarize the research landscape in plain language
</steps>
<rules>
- Do not summarize each paper randomly
- Organize the field into clear themes
- Separate major findings from minor details
- Do not invent claims not supported by the papers
- Flag missing context or weak evidence
- Test: would this help me understand the entire field faster
</rules>
<output>
Research Topic → Paper Groups → Major Themes → Core Concepts → Areas Of Agreement → Areas Of Debate → Research Landscape Summary
</output>

## 2/ SUMMARIZE EACH PAPER LIKE A RESEARCHER
<role>
Act as an academic paper summarizer who extracts the purpose, method, findings, limitations, and usefulness of each paper.
</role>
<task>
Summarize each DNS-security paper in the corpus in a clear research-ready format.
</task>
<steps>
1. Use the corpus from Module 0 (or ask me to provide the papers if no corpus exists yet)
2. For each paper, identify the research question
3. Identify the methodology used
4. Extract the main findings
5. Identify the key evidence supporting the findings
6. Identify the limitations of the study
7. Explain how the paper is useful for my DNS-security project
8. Create a clean summary table across all papers
</steps>
<rules>
- Do not over-summarize into vague bullets
- Preserve important methodological details
- Clearly separate findings from interpretations
- Mention limitations honestly
- Keep the summary useful for literature review writing
- Test: could I use this to decide which papers matter most
</rules>
<output>
Paper Title → Research Question → Method → Main Findings → Evidence → Limitations → Usefulness For My Research → Summary Table
</output>

## 3/ FIND THE RESEARCH GAP
<role>
Act as a research gap analyst who identifies what is missing, underexplored, weakly proven, or unresolved in the existing literature.
</role>
<task>
Analyze the corpus and find strong DNS-security research gaps I can build a thesis, dissertation, article, or study around.
</task>
<steps>
1. Confirm my project goal, academic/engineering level, and the corpus to analyze
2. Identify what the current literature already explains well
3. Identify repeated limitations mentioned across the papers
4. Identify populations, contexts, methods, variables, or timeframes that are underexplored
5. Identify contradictions or unresolved debates
6. Create 5 possible research gaps
7. Rank the gaps by originality, feasibility, relevance, and academic value
8. Turn the strongest gap into a research problem statement
</steps>
<rules>
- Do not invent fake gaps
- Gaps must be supported by patterns in the literature
- Avoid gaps that are too broad or impossible to study
- Focus on gaps that can become a real research question
- Explain why each gap matters
- Test: would an academic supervisor take this gap seriously
</rules>
<output>
What Literature Covers → Repeated Limitations → Underexplored Areas → Unresolved Debates → 5 Research Gaps → Gap Ranking → Strongest Research Problem
</output>

## 4/ COMPARE METHODS ACROSS PAPERS
<role>
Act as a research methodology expert who compares how different academic papers study the same topic.
</role>
<task>
Compare the research methods used across the corpus and explain which approaches are strongest, weakest, and most relevant for my own DNS-security study.
</task>
<steps>
1. Confirm my study goal and the corpus to analyze
2. Identify the methodology used in each paper: internet measurement, protocol/formal analysis, experimental testbed, ML-based detection, survey, case study, systematic review, or other
3. Identify dataset/data source, scale, instruments, variables, and analysis method where available
4. Compare the strengths of each methodology
5. Compare the weaknesses and limitations
6. Identify which methods are most common in DNS-security research
7. Recommend the best methodology for my own research question
</steps>
<rules>
- Do not recommend a method without explaining why
- Consider feasibility, data access, time, and level
- Separate methodological quality from topic relevance
- Flag weak datasets or unclear methods
- Keep the comparison structured
- Test: would this help me defend my methodology choice
</rules>
<output>
Paper Method Table → Method Strengths → Method Weaknesses → Common Field Methods → Best Method For My Study → Justification
</output>

## 5/ EXTRACT THE STRONGEST ARGUMENTS
<role>
Act as an academic argument builder who turns research papers into strong, evidence-backed arguments.
</role>
<task>
Extract the strongest arguments from the corpus and organize them into a clear academic argument structure.
</task>
<steps>
1. Confirm my topic, thesis angle, and the corpus
2. Identify the major claims made across the literature
3. Match each claim with supporting evidence
4. Identify counterarguments or opposing findings
5. Identify which arguments are strongest and why
6. Build a logical argument flow from problem to evidence to conclusion
7. Create paragraph-level argument points I can use in my literature review or essay
</steps>
<rules>
- Do not cherry-pick only supportive evidence
- Include counterarguments where relevant
- Claims must be supported by the papers
- Avoid vague academic filler
- Make the argument flow logical
- Test: would this help me write a stronger research paper
</rules>
<output>
Major Claims → Supporting Evidence → Counterarguments → Strongest Arguments → Argument Flow → Paragraph-Level Points
</output>

## 6/ BUILD A LITERATURE REVIEW OUTLINE
<role>
Act as an academic literature review strategist who organizes research into a clear, logical, and publishable structure.
</role>
<task>
Create a literature review outline from the DNS-security corpus.
</task>
<steps>
1. Confirm my research question, level, required word count, and the corpus
2. Identify the main themes in the literature
3. Organize the themes into a logical order
4. Add key papers under each theme
5. Explain what each section should argue
6. Identify where to discuss debates, limitations, and gaps
7. Create a full literature review outline with headings and subheadings
8. Suggest a strong closing section that leads into my research gap
</steps>
<rules>
- Do not organize the review paper-by-paper unless requested
- Use theme-based structure
- Make each section build toward the research gap
- Include debates and limitations
- Keep the outline academically useful
- Test: could I write the literature review directly from this outline
</rules>
<output>
Research Question → Main Themes → Literature Review Structure → Key Papers Per Section → Section Arguments → Debates → Gaps → Final Outline
</output>

## 7/ CREATE A PAPER COMPARISON MATRIX
<role>
Act as a research synthesis specialist who creates comparison matrices for academic papers.
</role>
<task>
Turn the corpus into a structured comparison matrix so I can see patterns, gaps, and differences quickly.
</task>
<steps>
1. Use the corpus from Module 0 (or ask me to provide the papers)
2. Create a matrix with columns for author/year, subtopic, research question, method, dataset/scale, threat model, findings, limitations, and relevance
3. Fill the matrix accurately for each paper
4. Highlight similarities across studies
5. Highlight major differences across studies
6. Identify which papers are strongest and weakest
7. Explain what the matrix reveals about the field
</steps>
<rules>
- Do not leave important cells vague if the information exists
- Use "not stated" when the paper does not provide the information
- Do not invent sample sizes, methods, or findings
- Keep the table clean and readable
- Add interpretation after the matrix
- Test: would this save me hours of manual paper comparison
</rules>
<output>
Research Matrix → Similarities → Differences → Strongest Papers → Weakest Papers → Field-Level Insights
</output>

## 8/ TURN PAPERS INTO PLAIN ENGLISH INSIGHTS
<role>
Act as a research translator who turns dense academic papers into simple, clear insights without losing accuracy.
</role>
<task>
Explain what the corpus papers actually mean in plain English and why they matter.
</task>
<steps>
1. Confirm the corpus, topic, and my current level of understanding
2. Identify the most important findings
3. Translate technical language into simple language
4. Explain why each finding matters
5. Give real-world examples or applications
6. Identify what I should remember from each paper
7. Create a final "so what?" summary
</steps>
<rules>
- Do not dumb down the research incorrectly
- Explain necessary terms clearly
- Focus on meaning, not just summary
- Avoid academic jargon where possible
- Keep insights practical and memorable
- Test: would someone outside the field understand the point
</rules>
<output>
Key Findings → Plain English Explanation → Why It Matters → Real-World Example → What To Remember → So What Summary
</output>

## 9/ CREATE THE FINAL RESEARCH SYNTHESIS
<role>
Act as a senior academic researcher who synthesizes multiple papers into a coherent final research brief.
</role>
<task>
Create a complete research synthesis from the DNS-security corpus, combining themes, findings, debates, gaps, and implications.
</task>
<steps>
1. Confirm my project purpose, level, and the corpus
2. Identify the central question the literature is answering
3. Group findings into major themes
4. Compare agreement and disagreement across studies
5. Identify methodological strengths and weaknesses
6. Identify research gaps and unanswered questions
7. Explain the practical and theoretical implications (including for an authoritative DNS server implementation)
8. Create a final structured research brief
9. Suggest next research directions
</steps>
<rules>
- Synthesize, do not just summarize
- Connect papers to each other
- Include both strong and weak evidence
- Do not make claims beyond the literature
- Clearly flag uncertainty
- Test: would this sound like a serious researcher reviewed the field
</rules>
<output>
Central Research Question → Major Themes → Synthesized Findings → Agreements/Disagreements → Methodological Notes → Research Gaps → Implications → Final Research Brief → Next Research Directions
</output>
