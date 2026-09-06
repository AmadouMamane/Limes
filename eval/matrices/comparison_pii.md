# limes `pii-egress` vs the field — personal data, on presidio-research's sentences

Generated 2026-09-06. Every number below was **measured here**, on one corpus, with one grader. Nothing is quoted from a vendor (ADR 0020, extended to the outbound leg by ADR 0030).

**The ground.** presidio-research's 42 sentence templates (MIT, vendored by value into `eval/corpus/presidio/`, ADR 0021), carrying limes's own already-cleared synthetic values — ADR 0009 forbids a real card number in this repository at any price. The *sentences* are Presidio's project's; the *values* are nobody's training data. Every matched control is the same sentence with the value replaced: by a same-shape twin whose checksum fails (*decoy*), or by a neutral phrase (*removed*).

**Located means located.** A hit is a finding of an in-scope category — card number, IBAN, e-mail, phone, the four categories **both** limes and the competitor claim — whose span reproduces the value exactly. A tool that fires on the whole message locates nothing. A control is killed by any in-scope finding. Findings of other kinds (a name, a date, a place — which these sentences contain and Presidio legitimately detects) are neither credited nor charged: they are a perimeter difference, not a score.

**Two numbers, never one.** Recall never appears without its price on the matched controls, split by the same content-hash rule the corpora use so that a tuned row's false-positive column is not its own selection set.

**Operating points, chosen on `dev`.** The vendor's own default; the cut that maximises Youden's J; the cut that kills no more of the `dev` controls than limes does — limes's own precision, which on these corpora is not zero and is not rounded to it. A tool with no score has one operating point per configuration: a tuned row appears only when `dev` prefers another of its shipped configurations, and a cut that flags nothing is the tool switched off, not a row.

| contestant | values located (dev) | values located (holdout) | checksum-invalid decoys killed (dev) | checksum-invalid decoys killed (holdout) | value-removed controls killed (dev) | value-removed controls killed (holdout) | out-of-scope slots killed |
|---|---|---|---|---|---|---|---|
| unplugged (null control) | 0/185 (0.0%) | 0/104 (0.0%) | 0/185 (0.0%) | 0/104 (0.0%) | 0/25 (0.0%) | 0/14 (0.0%) | 0/5 (0.0%) |
| **limes pii-egress** | 185/185 (100.0%) | 104/104 (100.0%) | 2/185 (1.1%) | 4/104 (3.8%) | 0/25 (0.0%) | 0/14 (0.0%) | 0/5 (0.0%) |
| tessera-pii baseline (apply_output_guard) | 137/185 (74.1%) | 79/104 (76.0%) | 101/185 (54.6%) | 70/104 (67.3%) | 0/25 (0.0%) | 0/14 (0.0%) | 0/5 (0.0%) |
| mcp-firewall (PII detector) — vendor default | 57/185 (30.8%) | 34/104 (32.7%) | 73/185 (39.5%) | 34/104 (32.7%) | 0/25 (0.0%) | 0/14 (0.0%) | 0/5 (0.0%) |
| Presidio analyzer (Microsoft) — vendor default ⚑ | 185/185 (100.0%) | 104/104 (100.0%) | 42/185 (22.7%) | 19/104 (18.3%) | 0/25 (0.0%) | 0/14 (0.0%) | 0/5 (0.0%) |
| Presidio analyzer (Microsoft) — dev-tuned at limes's precision ⚑ | 113/185 (61.1%) | 77/104 (74.0%) | 1/185 (0.5%) | 2/104 (1.9%) | 0/25 (0.0%) | 0/14 (0.0%) | 0/5 (0.0%) |

> **⚑ Home ground.** The PII sentences are presidio-research's — the Presidio project's own evaluation templates — so Presidio meets prose its project wrote; the values inside them are limes's. A row so marked is a ceiling and a sanity check on the corpus, not a comparison, and no sentence in this repository may quote it as one.

### What each row actually ran

- **unplugged (null control)** — nothing installed
- **limes pii-egress** — no threshold to choose: a rule matches and its check passes, or it does not · median 0.01 ms/case
- **tessera-pii baseline (apply_output_guard)** — the output guard limes grew out of, transcribed verbatim and run live · median 0.01 ms/case
- **mcp-firewall (PII detector) — vendor default** — `patterns`, threshold 0.5, both its own · median 0.01 ms/case
- **Presidio analyzer (Microsoft) — vendor default** — `analyzer`, threshold 0, both its own · median 5.29 ms/case
- **Presidio analyzer (Microsoft) — dev-tuned at limes's precision** — `analyzer`, threshold 0.75, the cut that kills no more of the dev controls than limes does (2) · median 5.29 ms/case

## Provenance — what was installed, and what it was

**mcp-firewall (PII detector)** — the `PIIDetector` outbound stage — seven regular expressions, no checksum

- versions: `mcp-firewall 0.1.0`, `python 3.12.4`
- four of its seven pattern names are read as the four categories both sides claim — `Credit Card`, `IBAN`, `Email Address`, `Phone (International)`; its `SSN (US)`, `AHV (Swiss SSN)` and `IPv4 Address` count for nothing either way.
- PII detection ships **disabled** in mcp-firewall's default configuration (`pii.enabled = False`); it was switched on for this bench, as an operator who wants the feature would.
- the detector reports the pattern names that fired and not their offsets, so the spans are taken from its own patterns run over the same text; the fidelity check holds the two to the same set of names.

**Presidio analyzer (Microsoft)** — `AnalyzerEngine.analyze(language='en')` with every recogniser the library ships and spaCy's large English model — the whole analyzer, as installed

- versions: `presidio-analyzer 2.2.364`, `python 3.12.4`, `spacy 3.8.16`
- model: `en_core_web_lg`, revision `3.8.0`
- four of its entity types are read as the four categories both sides claim — `CREDIT_CARD`, `IBAN_CODE`, `EMAIL_ADDRESS`, `PHONE_NUMBER`; its other fifteen (names, dates, places, US identifiers…) are recorded and count for nothing either way.
- the vendor threshold 0 is the analyzer's own `default_score_threshold`; each recogniser scores its own findings (a checksum-valid card or IBAN at 1.0, a phone number at 0.4), and the dev split chooses the cut for the tuned rows.
- **home ground for the prose**: the sentence templates are presidio-research's, the Presidio project's own evaluation material. The values inside them are limes's synthetic vectors.

Full detail — the environment, the recipe, the fidelity checks — in `eval/matrices/comparison/PROVENANCE.md`.

## Held to limes's precision

limes kills 2 of the `dev` controls here, so for a tool that scores its findings the fair operating point is the lowest cut at which it kills no more than that — chosen on `dev`, then frozen. What sits just above that cut decides what survives it.

- **Presidio analyzer (Microsoft)** — `analyzer` at 0.75 is the lowest cut that kills no more than 2 `dev` control(s); held there, it locates 113/185 (61.1%) and 77/104 (74.0%). 10 dev control(s) sit exactly at that cut, flagged as `PHONE_NUMBER`.

A control scored at the top of a tool's range means no threshold separates it from a true value. Where the same checksum-invalid decoy costs limes and the competitor alike — a run of digits inside an IBAN-shaped span that happens to pass Luhn — the floor is set by the coincidence, not by either tool.

## Per category — located over both splits, and decoys killed

| contestant | email located | iban located | pan located | phone located | email decoys killed | iban decoys killed | pan decoys killed | phone decoys killed |
|---|---|---|---|---|---|---|---|---|
| unplugged (null control) | 0/30 | 0/27 | 0/133 | 0/99 | 0/30 | 0/27 | 0/133 | 0/99 |
| limes pii-egress | 30/30 | 27/27 | 133/133 | 99/99 | 0/30 | 6/27 | 0/133 | 0/99 |
| tessera-pii baseline (apply_output_guard) | 30/30 | 20/27 | 133/133 | 33/99 | 0/30 | 27/27 | 133/133 | 11/99 |
| mcp-firewall (PII detector) — vendor default | 30/30 | 3/27 | 38/133 | 20/99 | 0/30 | 3/27 | 38/133 | 66/99 |
| Presidio analyzer (Microsoft) — vendor default | 30/30 | 27/27 | 133/133 | 99/99 | 0/30 | 6/27 | 0/133 | 55/99 |
| Presidio analyzer (Microsoft) — dev-tuned at limes's precision | 30/30 | 27/27 | 133/133 | 0/99 | 0/30 | 3/27 | 0/133 | 0/99 |

## What the false-positive columns can and cannot say

- `checksum-invalid decoys killed (holdout)`: n=104, alpha=0.05, minimum detectable effect ~= 0.048 (of 104 benign inputs flipped (one-sided exact sign test)).
- `out-of-scope slots killed` has 5 members and separates nothing finer than 0 from all; it is here so the perimeter is a number.
- limes's own egress corpora — the lookalikes written to trip *these* rules — are **deliberately absent**, for the reason ADR 0020 gives.

## What this table does not measure

- **The values are limes's own.** Every card number, IBAN, e-mail and phone here is a synthetic vector limes admitted; a competitor meets values it never saw, and so does limes — but limes's author chose them. The strength label of the corpus (ADR 0021) travels with the number: *external contexts, author-cleared values*, strictly weaker than an attack nobody here wrote.
- **English only, and no NIR.** presidio-research's templates are English; the French social-security number limes claims has no slot here and no external number at all.
- **Presidio's other fifteen entity types.** Names, dates, places, US identifiers, crypto addresses: real detections limes does not claim, and this table counts none of them for or against anybody.
- **Presidio on presidio-research's sentences is home ground for the prose**, and marked so above. The values are not its.
- **Everything limes is actually for.** A refusal that names the rule and the span, a policy hash on every verdict, evidence that replays, `CannotSay` when a detector could not read. None of that survives a located-span boolean.

