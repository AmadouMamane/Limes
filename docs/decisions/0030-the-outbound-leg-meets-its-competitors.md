# 30. The outbound leg meets its competitors, and a tool is held to the formats it claims

Date: 2026-09-06

## Status

Accepted. Extends ADR 0020 (a comparison on ground nobody here owns) from the
injection detectors to the two data detectors, `pii-egress` and
`secrets-egress`, on the external corpora ADR 0021 vendored. Adds one tool to
ADR 0020's own table. Amends two of ADR 0020's rules where the new ground showed
them to be approximations: the third operating point is *limes's precision*, not
*zero false positives*; and a tool with no score has one operating point per
configuration. Adds to the head-to-head perimeter of `tests/unit/test_frontier.py`
one harness, two matrices and this record. Nothing here changes a verdict.

## Context

ADR 0020 measured limes's injection rules against llm-guard, rebuff and two
bare classifiers, on garak's corpus, and published limes losing where it lost.
The two data detectors had no such table. Their external matrices (ADR 0021)
compared limes to a null control, a block-everything control and — for PII —
the output guard limes grew out of. A reader who asked *"and against the tools
people actually use for this?"* had prose: the README named Presidio and
gitleaks as sources of corpora, never as contestants.

Three things had to be settled before those tools could be scored, and each is
a rule below.

**The corpus author is a contestant.** The secrets corpus is gitleaks' own
catalogue, materialised from gitleaks' regexes; the PII sentences are
presidio-research's, the Presidio project's evaluation templates. Scoring the
author of the ground on the ground is not a comparison, and pretending otherwise
would be the exact failure ADR 0020 exists to avoid — a table that reads like a
measurement and is not one.

**The census and the perimeter are different questions.** Against gitleaks'
218 formats limes has always said it reads a small, named set: eight vendor
prefixes, PEM, JWT, and the keyword-anchored AWS secret. `external_secrets.md`
measures how much of the industry's list that is (7 %). A competitor with a
longer list wins that column by having a longer list. The fairer question — *on
the formats limes claims, who reads them?* — had never been asked, and it is
the question on which limes's own misses become visible instead of averaged
into a small number that already looked bad.

**Rules on the new ground.** ADR 0020's third operating point held every
competitor to *zero* false positives because limes killed none of garak's
matched controls. On the PII decoys limes is not at zero: six IBAN-shaped
decoys carry a digit run that happens to pass Luhn, and `pii:pan` fires on it —
a trade ADR 0021 Amendment 2 measured and kept. Holding a competitor to zero
would hold it to a precision limes does not have. And two of the new contestants
have no score at all: a regex matches or it does not. Youden's J over a {0, 1}
score either keeps the tool as it is or switches it off, and "switched off" was
about to be published as an operating point with a threshold of 1.

**mcp-firewall.** The README has cited it since v0.1 as prior art — the MCP
gateway limes shares the single-seam idea with — and never measured it. It ships
a pattern-based injection detector that reads a tool call's arguments, a PII
detector and a secret scanner, all regular expressions, all offline. Unlike
mcp-scan, which ADR 0020 left out for *shape*, it produces exactly the boolean
the grader needs. It joins all three tables.

## Decision

**Every detector limes ships is measured against the tools that claim the same
detection, on the external corpus its leg already has, under ADR 0020's ten
rules — and these five more.**

**11 — Home ground is marked, in the row, and quoted by nobody.** A contestant
whose material the corpus is made of — gitleaks on gitleaks' catalogue, Presidio
on presidio-research's sentences — carries a flag (⚑) and a note in the matrix.
Its row is a ceiling and a check that the corpus is what it claims to be; no
sentence in this repository may quote it as a comparison. The check is worth
having: gitleaks' own binary locates 194 of the 218 instances generated from its
own regexes, because a rule is more than its regex — an entropy floor, required
keywords, an allowlist — and the generator satisfied the regex alone. That
shortfall is a property of the corpus, stated beside the flag, and it costs
every contestant alike.

**12 — The perimeter is asked beside the census.** For secrets, a table *Held to
the formats limes claims* lists the 19 catalogue rules that name a format limes
says it reads (`CLAIMED_FORMATS`, one line per rule, with the limes rule it maps
to), and marks per contestant whether the instance was located. Every miss of
limes's on its own perimeter carries a one-sentence note saying whether it is a
gap in the rule or a shape-only instance the rule refuses by design; a test
holds the notes to exactly the set of misses, so a note cannot outlive its miss
and a miss cannot go unexplained. For PII the same service is the per-category
table over the four categories both sides claim; a competitor's detections of
names, dates and places in the same sentences are neither credited nor charged.

**13 — Located, not flagged, and only on what both sides claim.** A PII hit is a
finding of an in-scope category whose span reproduces the value exactly; a
control is killed by an in-scope finding. A secret hit is a finding wholly
inside the vendored token, whatever the tool calls it; a negative is killed by
any finding. A tool that fires on the whole message locates nothing — the same
grader every egress matrix has used since ADR 0003.

**14 — The floor is limes's precision, measured, not zero.** The third
operating point for a scored tool is the lowest cut at which it kills no more
`dev` controls than limes does on the same controls, chosen on `dev` and frozen.
On garak's controls that count is zero and the rule reduces to ADR 0020's; on
the PII decoys it is two, and the matrix says so in the row's own detail.

**15 — A tool with no score has one operating point per configuration.** Its
vendor default is a row. A tuned row appears only when `dev` prefers another of
its *shipped* configurations (a sensitivity, a scan mode). A cut that flags
nothing is the tool switched off and is never a row; a cut that changes no
verdict is never a second row, whatever number it is written as. Such a tool has
no ROC curve either, and the AUC table says so rather than printing a coin.

**The ground, per bench.** PII: presidio-research's 42 templates carrying
limes's own already-cleared vectors (ADR 0009 forbids a real value at any price),
with the checksum-invalid decoy and the value-removed control per sentence,
split by template and reported per split so a tuned row's false-positive column
is not its own selection set. Secrets: gitleaks' 218 materialised formats and
339 hard negatives, the negatives split by their own content hash for the same
reason. Cases are content-addressed and every competitor is scored on the same
enumeration, as in ADR 0020.

**The machinery.** `scripts/bench_competitors.py --bench pii|secrets --tool …`
runs a competitor in a throwaway environment and writes one findings file per
tool into `eval/matrices/comparison/<bench>/`; `limes.eval.egress_comparison_harness`
renders the two matrices from those files plus limes and the ported baseline
computed live. The dependency frontier is untouched: spaCy, Presidio and
detect-secrets never enter this repository. gitleaks runs as a binary with
`--config` pinned to the catalogue at the vendored commit, which the bench
fetches and refuses to use unless its sha256 is the one the corpus records.
Every adapter carries a fidelity check against the tool's own public path
(Presidio's `analyze()` at a non-default cut; mcp-firewall's `scan()`; the
`detect-secrets` command line, with `--no-verify` so a synthetic Slack token is
not dropped because Slack said it is not real; a per-payload `gitleaks stdin`),
and a test refuses any file whose check did not fully agree.

### The field, and what each row honestly is

| contestant | bench | what is measured | what is not |
|---|---|---|---|
| **limes** | all | `pii-egress` / `secrets-egress` / both injection legs, computed live | its spans as evidence, its replay, `CannotSay` |
| **Presidio analyzer** (Microsoft) | PII | `analyze()` with every shipped recogniser and `en_core_web_lg`; four entity types read as the four claimed categories | its other fifteen entity types; **home ground for the prose** |
| **gitleaks** | secrets | the binary over one file per case, catalogue pinned to the vendored commit | anything about gitleaks against an attacker — **home ground** |
| **detect-secrets** (Yelp) | secrets | every default plugin, `file` mode and the `--string` path | its verification against vendor APIs, disabled so the number is offline |
| **mcp-firewall** (Robert Ressl, 0.1.0) | all three | `InjectionDetector` at low/medium/high; `PIIDetector` (switched on: it ships disabled); `SecretScanner` | its policy engine, threat feed, chain detector, audit trail |

### What the tables say, on the day of this record

The matrices are the source; these are the readings that decided the record.

- **PII.** limes and Presidio both locate every value (289/289). Presidio at
  its default kills 61 of the 289 checksum-invalid decoys — 55 of them phone
  decoys, eight-digit runs limes's E.164 digit-count gate rejects — against
  limes's 6, which are the Luhn coincidences. Held to limes's precision, Presidio
  gives up its phone recogniser entirely (0/99 phones) and locates 61 % / 74 %.
  mcp-firewall's seven regexes locate 31 % and kill 107 decoys: a credit-card
  pattern with no Luhn and a phone pattern that accepts anything. The ported
  Tessera guard, for scale: 74 % / 76 % located, 171 decoys killed.
- **Secrets, census.** gitleaks (home ground) 194/218; detect-secrets as
  shipped 31/218 with 53 of 339 negatives killed; limes 16/218 with 33;
  mcp-firewall 14/218 with 46. detect-secrets' `--string` path locates 218/218
  by flagging 317 of 339 negatives — the row the matrix marks as blocking
  everything.
- **Secrets, held to the formats limes claims (19).** gitleaks 16, limes 14,
  detect-secrets 12, mcp-firewall 11. limes's five misses: two real gaps in its
  rules (`A3T…` AWS key-id prefixes; `github_pat_…`), one disagreement about a
  10-character Stripe body, and two shape-only instances (a PEM armour no real
  key carries, a JWT whose header is not JSON) that limes refuses by design and
  the shape-only tools accept. Two of the five are limes's to fix.
- **Injection.** mcp-firewall's shipped `medium` sensitivity catches 10 of 280
  held-out attacks, none of the 131 blind hijacks (its override pattern requires
  *previous instructions* to be adjacent; garak's says *previous and following*),
  and kills no control. Its `high` sensitivity kills more controls than it
  catches attacks on `dev` and is not published (rule 15).
- **Latency.** limes 0.01–0.02 ms per case on the data legs; mcp-firewall the
  same order; detect-secrets 0.7 ms; Presidio 5 ms; gitleaks 27 ms as one
  process per payload.

## Consequences

- The README's comparison section gains the two legs it lacked, and the prior-art
  entry for mcp-firewall becomes a measurement. For PII the reading is that a
  checksum beats a confidence score at the precision a guard runs at; for
  secrets it is that limes's perimeter is small and stated, that it holds 14 of
  its 19 claimed formats on somebody else's instances, and that two of the five
  misses are its own to fix. Neither table is a win to quote; both are numbers
  where there were sentences.
- Two rule gaps are named for the detector, not for this record: the AWS key-id
  prefix family and GitHub's fine-grained token format. Fixing them is a policy
  edit under ADR 0003's admission rule, with its own measurement, and the
  `CLAIMED_FORMAT_NOTES` test will demand the notes come out when the misses do.
- `make eval` regenerates two more matrices, and the byte-for-byte matrix test
  covers them with latency masked. Results files are committed; the environments
  are not, and the recipe in `eval/matrices/comparison/PROVENANCE.md` reproduces
  them.
- ADR 0020's own table changed under rule 15: a score-less tool no longer gets a
  "dev-tuned at zero false positives" row that flags nothing, and the AUC table
  no longer prints a coin for it. No number in an existing row moved.
