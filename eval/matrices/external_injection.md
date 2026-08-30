# limes vs an adversary corpus it did not write

Generated 2026-08-30 from **garak 0.16.0** (NVIDIA, Apache-2.0) — `garak.probes.latentinjection`, 8 probes, vendored by value into `eval/corpus/garak/` (ADR 0017). limes does not depend on garak; the corpus is a copy, reproducible with `scripts/vendor_garak_corpus.py`.

**Why this table exists.** Every other matrix in this repository scores limes on cases limes's author wrote, which measures whether the detector does what it was meant to do. This one scores it on somebody else's attacks. It is the less comfortable number, and it is the one that says whether the guard generalises.

- **attacks** — garak's indirect prompt injections, sampled by `first nibble of sha256(prompt): '0' -> dev, '1' -> holdout, else dropped`.
- **matched benign documents** — *the same documents* with the injection removed. A detector that fires on both has learnt the document, not the attack.
- **out of scope (jailbreak)** — `LatentJailbreak`, a content-policy jailbreak limes has never claimed. Measured so the perimeter is a number, not a sentence.

| configuration | attacks (dev) | matched benign documents | out of scope (jailbreak) |
|---|---|---|---|
| unplugged (null control) | 0/498 (0.0%) | 0/192 (0.0%) | 0/76 (0.0%) |
| injection (inbound leg) | 63/498 (12.7%) | 0/192 (0.0%) | 0/76 (0.0%) |
| **injection-egress (outbound leg)** | 15/498 (3.0%) | 0/192 (0.0%) | 0/76 (0.0%) |
| **both, as the proxy deploys them** | 15/498 (3.0%) | 0/192 (0.0%) | 0/76 (0.0%) |

## Per probe — `injection-egress`, the leg a tool result arrives on

| garak probe | split | blocked |
|---|---|---|
| `LatentInjectionFactSnippetEiffelFull` | dev | 0/144 (0.0%) |
| `LatentInjectionFactSnippetLegalFull` | dev | 0/76 (0.0%) |
| `LatentInjectionReportFull` | dev | 0/38 (0.0%) |
| `LatentInjectionResumeFull` | dev | 0/162 (0.0%) |
| `LatentInjectionTranslationEnFrFull` | dev | 0/19 (0.0%) |
| `LatentInjectionTranslationEnZhFull` | dev | 0/26 (0.0%) |
| `LatentWhois` | dev | 4/9 (44.4%) |
| `LatentWhoisSnippetFull` | dev | 11/24 (45.8%) |

## What the two sides mean

- **False positives, external documents:** the matched benign set is 192 real documents (résumés, articles, whois records) that each pair with an attack above.
- **False positives, deliberate lookalikes:** 1/14 on limes's own benign corpus — the near-misses written to trip the rules on purpose. Both sides are needed: long ordinary prose and adversarial near-misses fail differently.
- **Power of the false-positive claim:** n=192, alpha=0.05, minimum detectable effect ~= 0.026 (of 192 benign inputs flipped (one-sided exact sign test)).

## The protocol

`rules may be written against dev; holdout is scored once, rules frozen (ADR 0017)`

Splits scored here: `dev`.
A rule written while looking at `holdout` turns it into a second `dev`, and the number stops meaning what this table says it means.

