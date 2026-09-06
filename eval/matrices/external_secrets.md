# limes `secrets-egress` — against the industry's credential catalogue

Generated 2026-09-06 from **gitleaks** (MIT, commit `b58d3f102cf3`, <https://github.com/gitleaks/gitleaks>) — 222 catalogue rules, of which **218** materialise into a self-verified instance, vendored by value into `eval/corpus/gitleaks/` (ADR 0021). limes does not depend on gitleaks; the corpus is a copy, reproducible with `scripts/vendor_gitleaks_corpus.py`.

**Strength of this number.** external catalogue and external hard negatives; the positive VALUES are materialised here from each rule's own regex and self-verified against it (ADR 0009 forbids a real credential, and gitleaks generates its own the same way). So the FORMATS and the NEGATIVES are third-party; the bytes of each positive instance are this repository's. Labelled wherever published.

**What this table is asking.** Not *do my eight rules find my eight formats* — the internal matrix answers that, 15/15. This asks how much of what the industry calls a credential limes sees at all.

| configuration | formats located (dev) | formats located (holdout) | gitleaks' own hard negatives |
|---|---|---|---|
| unplugged (null control) | 0/110 (0.0%) | 0/108 (0.0%) | 0/339 (0.0%) |
| block-everything | 0/110 (0.0%) | 0/108 (0.0%) | 339/339 (100.0%) |
| **limes secrets-egress** | 12/110 (10.9%) | 4/108 (3.7%) | 33/339 (9.7%) |

- **formats located** — a finding falling wholly inside the vendored instance. gitleaks' patterns often carry their own context keywords, so the instance may read `apikey = <secret>` rather than the bare credential and an exact-span rule would score a correct finding as a miss. `block-everything` still scores zero: it spans the carrier line too.
- **hard negatives** — gitleaks' *own* false-positive vectors: placeholder runs, wrong-length keys, a Finnish sentence, a DNA fragment. Precision measured on ground limes did not choose.

## What limes catches, and what it does not

**Located (16 of 218):** `anthropic-admin-api-key`, `anthropic-api-key`, `gcp-api-key`, `github-app-token`, `github-oauth`, `github-pat`, `github-refresh-token`, `openai-api-key`, `slack-app-token`, `slack-bot-token`, `slack-config-access-token`, `slack-config-refresh-token`, `slack-legacy-bot-token`, `slack-legacy-token`, `slack-legacy-workspace-token`, `slack-user-token`

The remaining 202 are formats limes ships no rule for. That is not a bug being reported here — the README has always said the perimeter is eight vendor prefixes plus PEM and JWT, and that generic high-entropy scanning is a declared non-capability. What this table adds is the **size** of that perimeter, measured against somebody else's census instead of asserted in prose.

## Blind spots — formats nobody could materialise

A rule this harness could not instantiate is **not** a rule the detector missed, and is excluded from the denominator above (ADR 0015).

| gitleaks rule | why |
|---|---|
| `kubernetes-secret-yaml` | generated instance does not match its own rule |
| `openshift-user-token` | generated instance does not match its own rule |
| `pkcs12-file` | the rule matches on path, not content |
| `sentry-org-token` | character class admits nothing printable |

## Declared unreadable

6 vector(s) the detector declared it could not read — mostly opaque encoded runs its rules cannot see into (ADR 0028). Under a proxy that is a `CannotSay`, blocked by default; here it is neither a hit nor a false positive, and it is named rather than folded into either column: `1password-service-account-token`, `cloudflare-origin-ca-key`, `microsoft-teams-webhook`, `fp025_aws`, `fp038_azure`, `fp058_curl`.

## The two numbers

- **Formats located (dev):** 12/110 (10.9%).
- **Formats located (holdout):** 4/108 (3.7%).
- **gitleaks' own hard negatives killed:** 33/339 (9.7%).
  Named: `fp005_anthropic`, `fp006_anthropic`, `fp007_anthropic`, `fp008_anthropic`, `fp009_anthropic`, `fp010_anthropic`, `fp028_aws`, `fp031_aws`, `fp061_curl`, `fp096_gcp`, `fp097_gcp`, `fp098_gcp`
- **Power of the false-positive claim:** n=339, alpha=0.05, minimum detectable effect ~= 0.015 (of 339 benign inputs flipped (one-sided exact sign test)).

## The protocol

Split by **rule id**, which is this corpus's template: a rule id names a format, and a format is what a detector meets. A test asserts no rule id appears on both sides.

Splits scored here: `dev`, `holdout`.

