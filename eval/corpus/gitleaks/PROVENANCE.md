# Corpus provenance — the credential census limes did not take

`secrets-egress` was admitted on 15 cases across 8 categories, and scores 15/15
with 0/20 benign killed: F1 **1.00**. That number is true, and it answers *"do my
eight rules find my eight formats"*. A reader will take it for something else —
*"limes finds credentials"* — and nothing in the internal matrix stops them.

This file is **copied**, by value, from the closest thing the field has to a
published census of what a credential looks like.

## Source

| | |
|---|---|
| tool | **gitleaks** — secret scanner for git repositories and files |
| vendor | **Zachary Rice / gitleaks** |
| licence | **MIT** (asserted by GitHub's licence detection on the repository) |
| repository | <https://github.com/gitleaks/gitleaks> |
| commit | `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (2026-07-22) |
| catalogue | `config/gitleaks.toml`, sha256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf` |
| hard negatives | `cmd/generate/config/rules/*.go`, the `fps` lists |
| tarball sha256 | `d0b61e27e78a0abcf5af367d6a30a23dc635ad7a8c708e9db3e196b185884bc7` |
| copied | 2026-08-31 |

MIT permits this copy into an Apache-2.0 repository; attribution is the condition,
and this page plus the `source` block inside `secret_formats.json` is it.

**limes does not depend on gitleaks** — not at runtime, not in the gate, not in an
extra. One tarball, at one pinned commit, at vendoring time only (ADR 0004).
Regenerate with `scripts/vendor_gitleaks_corpus.py`, which refuses to write
anything if either sha256 has moved.

## Strength of the number this corpus produces — read this before quoting it

**External catalogue, external negatives, locally materialised positives.**

Three parts, and they do not have the same strength:

- the **taxonomy** — which 222 formats count as a credential, and the regex for
  each — is entirely gitleaks';
- the **hard negatives** — 339 strings that look like a credential and must not
  fire — are entirely gitleaks', copied verbatim (then fragmented, below);
- the **positive bytes** are generated here, by walking each rule's own parsed
  regex, and **self-verified**: the instance is fed back through the pattern that
  produced it, and a rule whose instance does not match its own regex is recorded
  as a blind spot rather than scored.

The values must be local: ADR 0009 forbids a real credential in this repository,
and gitleaks itself generates its test vectors the same way. So the *formats* and
the *negatives* are foreign; the bytes of each positive are not.

## The four blind spots

| gitleaks rule | why it could not be materialised |
|---|---|
| `kubernetes-secret-yaml` | generated instance does not match its own rule |
| `openshift-user-token` | generated instance does not match its own rule |
| `pkcs12-file` | the rule matches on path, not content |
| `sentry-org-token` | character class admits nothing printable |

218 of 222 materialise. The four above are **excluded from the denominator** and
named here: a format nobody could instantiate is not a format the detector missed
(ADR 0015). Scoring them as zeros would have made the published number look worse
than the evidence supports, which is the same dishonesty as making it look better.

## Nothing here is a contiguous credential literal (ADR 0010)

The positive corpus of a secrets detector is, by construction, a set of strings
shaped exactly like credentials — and a host scanner cannot tell synthetic from
real. GitHub push protection blocked the *first* push of the internal corpus for
exactly this reason.

So every token is stored as **`token_parts`**, and every hard negative as
**`text_parts`**, joined by the loader. Fragments are a uniform **8 characters** —
short and uniform on purpose, never "split at the vendor prefix", because a
per-vendor split point is a bet that you know where every scanner's pattern
starts, and ADR 0010 forbids that bet. JSON writes `", "` between fragments and no
vendor pattern admits a quote, so no shape can re-form in the stored bytes while
the joined value stays byte-identical to what the detector must find.

The negatives are fragmented **too**, and for the same reason: a hard negative is
a credential *lookalike*, so it is exactly as likely to trip a host scanner as a
positive. The first version stored them literally and put 44 contiguous
credential-shaped strings into the file; the witness caught it.

`tests/unit/egress/test_external_egress_corpus.py` runs limes's own secrets rules
over the raw bytes of `secret_formats.json` and refuses any match.

## The split — by RULE ID, which is this corpus's template

Each rule id's own sha256 decides its side: first nibble `0-7` → `dev`, `8-f` →
`holdout`. 110 dev, 108 holdout.

A rule id names a **format**, and a format is what a detector meets. Splitting the
materialised instances would split instances of one format across both sides, and
a rule written on `dev` would then score on `holdout` by identity rather than by
generalisation — the failure ADR 0021 records for the hijack family. A test
asserts no rule id appears on both sides.

> **The protocol: rules may be written against `dev`. `holdout` is scored once,
> with the rules frozen.**

`python -m limes.eval.external_egress_harness secrets` reports **dev only** by
default; the held-out number exists only when somebody passes `--split all`.

## How a hit is counted here, and why it is not the internal rule

The internal matrix grades on an **exact span**: a finding counts only when its
`[start, end)` reproduces the declared substring. That rule is what keeps
`block-everything` at zero, and it is kept wherever it can be.

It cannot be kept here. gitleaks' patterns frequently include their own context
keywords, so a materialised instance may read `apikey = <secret>` rather than the
bare credential — and an exact-span rule would score a *correct* finding on the
credential as a miss. So a hit is a finding falling **wholly inside** the vendored
instance. `block-everything` still scores zero, because it spans the carrier line
around the token as well; the control keeps its teeth.

## What this corpus is not

It is not a claim that gitleaks' 222 rules are the whole of what a credential is,
and it is not a benchmark limes may tune against. It is one outside census, at one
version. What it buys is a **size** for a perimeter that until now was only ever
described in prose.
