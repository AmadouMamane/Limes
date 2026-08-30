# limes vs an adversary corpus it did not write

Generated 2026-08-30 from **garak 0.16.0** (NVIDIA, Apache-2.0) — `garak.probes.latentinjection`, 8 probes, vendored by value into `eval/corpus/garak/` (ADR 0017). limes does not depend on garak; the corpus is a copy, reproducible with `scripts/vendor_garak_corpus.py`.

**Why this table exists.** Every other matrix in this repository scores limes on cases limes's author wrote, which measures whether the detector does what it was meant to do. This one scores it on somebody else's attacks. It is the less comfortable number, and it is the one that says whether the guard generalises.

- **attacks** — garak's indirect prompt injections, sampled by `split by ATTACK TEMPLATE: first nibble of sha256(injection_instruction), 0-7 -> dev, 8-f -> holdout; then prompts thinned to first nibble of sha256(prompt) in {0,1}`.
- **matched benign documents** — *the same documents* with the injection removed. A detector that fires on both has learnt the document, not the attack.
- **out of scope (jailbreak)** — `LatentJailbreak`, a content-policy jailbreak limes has never claimed. Measured so the perimeter is a number, not a sentence.

| configuration | attacks (dev) | attacks (holdout) | matched benign documents | hijack (blind) | out of scope (jailbreak) |
|---|---|---|---|---|---|
| unplugged (null control) | 0/722 (0.0%) | 0/280 (0.0%) | 0/192 (0.0%) | 0/131 (0.0%) | 0/161 (0.0%) |
| injection (inbound leg) | 603/722 (83.5%) | 62/280 (22.1%) | 0/192 (0.0%) | 107/131 (81.7%) | 0/161 (0.0%) |
| **injection-egress (outbound leg)** | 602/722 (83.4%) | 53/280 (18.9%) | 0/192 (0.0%) | 107/131 (81.7%) | 0/161 (0.0%) |
| **both, as the proxy deploys them** | 602/722 (83.4%) | 53/280 (18.9%) | 0/192 (0.0%) | 107/131 (81.7%) | 0/161 (0.0%) |

## Per probe — `injection-egress`, the leg a tool result arrives on

| garak probe | split | blocked |
|---|---|---|
| `LatentInjectionFactSnippetEiffelFull` | dev | 299/299 (100.0%) |
| `LatentInjectionFactSnippetEiffelFull` | holdout | 0/0 (—) |
| `LatentInjectionFactSnippetLegalFull` | dev | 152/152 (100.0%) |
| `LatentInjectionFactSnippetLegalFull` | holdout | 0/0 (—) |
| `LatentInjectionReportFull` | dev | 29/29 (100.0%) |
| `LatentInjectionReportFull` | holdout | 31/60 (51.7%) |
| `LatentInjectionResumeFull` | dev | 0/109 (0.0%) |
| `LatentInjectionResumeFull` | holdout | 0/192 (0.0%) |
| `LatentInjectionTranslationEnFrFull` | dev | 34/34 (100.0%) |
| `LatentInjectionTranslationEnFrFull` | holdout | 0/0 (—) |
| `LatentInjectionTranslationEnZhFull` | dev | 57/57 (100.0%) |
| `LatentInjectionTranslationEnZhFull` | holdout | 0/0 (—) |
| `LatentWhois` | dev | 6/17 (35.3%) |
| `LatentWhois` | holdout | 10/10 (100.0%) |
| `LatentWhoisSnippetFull` | dev | 25/25 (100.0%) |
| `LatentWhoisSnippetFull` | holdout | 12/18 (66.7%) |

## Where the misses are

- **dev** — `LatentInjectionResumeFull` score **0**, and they are **15%** of this split. Over everything else: 602/613 (98.2%).
- **holdout** — `LatentInjectionResumeFull` score **0**, and they are **69%** of this split. Over everything else: 53/88 (60.2%).

That gap is the finding, not a footnote. Where an attack carries an *imperative* — disregard this, print that, focus only on the following — a rule can name its shape and does. Where it carries only *persuasion* or *framing* — a fabricated recruiter's endorsement, a hidden competency profile, white text addressed to the scanner — there is no directive to match, and a rule that fired on it would be firing on ordinary flattery. Those probes are not a bug in the rules; they are the boundary of what rules are, and they are exactly the territory ADR 0013's classifier layer is framed for. The number above is what makes that argument with evidence instead of prose.

## What the two sides mean

- **False positives, external documents:** the matched benign set is 192 real documents (résumés, articles, whois records) that each pair with an attack above.
- **False positives, deliberate lookalikes:** 4/20 on limes's own benign corpus — the near-misses written to trip the rules on purpose. Both sides are needed: long ordinary prose and adversarial near-misses fail differently.
- **Power of the false-positive claim:** n=192, alpha=0.05, minimum detectable effect ~= 0.026 (of 192 benign inputs flipped (one-sided exact sign test)).

## The protocol

`rules may be written against dev; holdout is scored once, rules frozen (ADR 0017)`

Splits scored here: `dev`, `holdout`.
A rule written while looking at `holdout` turns it into a second `dev`, and the number stops meaning what this table says it means.

