# Corpus provenance — document contexts limes did not write

`pii-egress` was admitted on 32 cases across five categories, in sentences its
author wrote, and it scores 32/32 on them. That measures *"does the detector do
what I meant it to do"*. It cannot measure *"does it find PII in documents
somebody else wrote"* — and ADR 0017 already showed what the difference costs:
`injection` scored 76% on the author's corpus and **24%** on garak's.

This file is **copied**, by value, from a corpus somebody else wrote.

## Source

| | |
|---|---|
| tool | **presidio-research** — PII detection evaluation and data generation |
| vendor | **data-privacy-stack** (formerly Microsoft) |
| licence | **MIT** (asserted by GitHub's licence detection on the repository) |
| repository | <https://github.com/data-privacy-stack/presidio-research> |
| former repository | <https://github.com/microsoft/presidio-research> |
| file | `presidio_evaluator/data_generator/raw_data/templates.txt` |
| commit | `70ff860bed296cc1ce9383d76ec9dcbd44a3e9c6` (2024-10-12) |
| sha256 | `f8b04ff8c5c24d17fcac2e666767f6ba80841b69ee2ea3c1cfe089a676a766ef` |
| copied | 2026-08-31 |

The repository moved after these templates were written. Both names are recorded:
provenance that silently follows a rename is provenance a reader cannot check.

MIT permits this copy into an Apache-2.0 repository; attribution is the condition,
and this page plus the `source` block inside `pii_templates.json` is it.

**limes does not depend on presidio-research** — not at runtime, not in the gate,
not in an extra. The dependency runs one way and only at vendoring time (ADR
0004). Regenerate with `scripts/vendor_presidio_corpus.py`, which refuses to write
anything if the upstream file's sha256 has moved.

## Strength of the number this corpus produces — read this before quoting it

**External contexts, author-cleared synthetic values.**

The 209 upstream templates are customer-support and banking prose written by
somebody else: *"I have lost my card {{credit_card_number}}. Could you please
block my credit card ASAP?"*. 42 of them carry a placeholder for a category limes
claims or has explicitly declared out of scope; the rest are kept out and counted.

The **values** substituted into them are limes's own already-admitted vectors,
read straight out of `src/limes/corpus/egress/pii_positive.json`. Two reasons, and
neither is convenience:

- ADR 0009 forbids a real PII value in this repository, at all, for ever;
- a freshly generated value would put a second moving part in the experiment. With
  the vectors held fixed, the **document** is the only thing that varies, which is
  precisely the question this corpus exists to ask.

So this is **weaker than garak**, where the attack itself is foreign, and it is
labelled so in the matrix, in the README and here. It is a measurement of context
robustness, not of adversarial coverage.

## What was taken, and what deliberately was not

| upstream placeholder | limes category | in this corpus |
|---|---|---|
| `{{credit_card_number}}` | `pan` | yes |
| `{{iban}}` | `iban` | yes |
| `{{email}}` | `email` | yes |
| `{{phone_number}}` | `phone` | yes |
| `{{ssn}}`, `{{us_driver_license}}`, `{{ip_address}}` | — | scored on their own row |
| `{{person}}`, `{{address}}`, `{{organization}}`, … | — | filled with fixed non-PII text |

`nir` — the French social-security number — is claimed by limes and has **no
upstream placeholder**. It is therefore not measured here, and that is a blind
spot named rather than a category quietly scored at zero (ADR 0015).

The out-of-scope placeholders are vendored and scored anyway, on their own row,
because a declared non-capability deserves a number too — the treatment ADR 0017
gave `LatentJailbreak`.

Every other placeholder is replaced by a fixed, non-PII filler, so each
materialised sentence carries **exactly one** detectable value: the one under
test. A filler that itself tripped a rule would put a second variable inside a
matched pair.

## One thing the copy had to fix, and it cost a wrong number first

Upstream stores every template on one physical line and writes its internal line
breaks as the two characters `\` and `n` — 89 of them across the file. The first
version of this vendoring copied them verbatim.

That is not cosmetic. A literal backslash-n where a newline belongs glues a stray
`n` onto the front of the next token, so `pii:email` spans one character too many
and `pii:phone`'s `(?<![A-Za-z0-9+])` lookbehind never fires at all. The first run
of this bench reported **89.8%**, and every one of its 17 misses was that, not the
detector. Unescaped, the same corpus reports **100%**.

It is recorded here rather than quietly fixed because it is this repository's
recurring lesson in one line: a corpus that copies an escape sequence verbatim
measures its own encoding (ADR 0026).

## The split — by TEMPLATE, and why that is not a detail

Each template's own sha256 decides its side: first nibble `0-7` → `dev`, `8-f` →
`holdout`. 25 dev, 17 holdout at the pinned commit.

The unit matters more than the rule. One template becomes as many scored cases as
its category has vectors, so splitting the **cases** would put the same template on
both sides — and a rule written against `dev` would then score on `holdout` by
identity rather than by generalisation. That is not hypothetical: it is exactly
what happened to the hijack family, whose thinning by prompt hash let every attack
template survive into every bucket, so its "held out" number could not have told
memorisation from generalisation (ADR 0021).

`tests/unit/egress/test_external_egress_corpus.py` asserts no template appears on
both sides.

> **The protocol: rules may be written against `dev`. `holdout` is scored once,
> with the rules frozen.**

The harness helps rather than trusts: `python -m limes.eval.external_egress_harness
pii` reports **dev only** by default, and the held-out number exists only when
somebody deliberately passes `--split all`.

## The matched controls — derived, never written

For every attack there are two controls built from the same sentence:

- **value removed** — the value replaced by a neutral phrase. A detector that
  fires here has learnt the sentence rather than the value.
- **checksum-invalid decoy** — the value replaced by a same-shape twin whose Luhn,
  MOD 97-10, E.164 length or domain-label check fails. limes says its precision
  comes from the checksum; this is where that claim is paid for.

Both are derived from the attack's own data, so neither can drift out of step with
it — which a second, maintained file would, eventually.

Two decoys were **wrong in the first version and are recorded as such**: appending
digits to a telephone number leaves the whole valid number standing as a prefix,
and `rsplit(".", 1)` on `sub.example.co.uk` yields `sub.example.co`, which is a
perfectly good address. Both "false positives" were the decoy's fault, not the
detector's. Corrected, the decoy column went from 20.7% to **3.5%**.

## What this corpus is not

It is not a benchmark limes may tune against, and 42 templates from one generator
are not the distribution of the world's documents. It is one outside source, at
one commit, over four categories, in **English only** — limes's PII rules are
fr/de/en and this corpus exercises one of the three. What it buys is the one thing
an author cannot buy from their own corpus: prose they did not choose.
