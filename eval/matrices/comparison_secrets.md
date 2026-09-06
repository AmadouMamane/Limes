# limes `secrets-egress` vs the field — credentials, on gitleaks' catalogue

Generated 2026-09-06. Every number below was **measured here**, on one corpus, with one grader. Nothing is quoted from a vendor (ADR 0020, extended to the outbound leg by ADR 0030).

**The ground.** gitleaks' catalogue of 222 credential formats (MIT, vendored by value into `eval/corpus/gitleaks/`, ADR 0021), 218 of them materialised into an instance generated from the rule's own regex and self-verified against it, plus 339 of gitleaks' own false-positive vectors as hard negatives. The formats and the negatives are third-party; the bytes of each positive are this repository's.

**Located means located.** A hit is a finding falling wholly inside the vendored token, whatever the tool calls it; a negative is killed by any finding at all. A tool that fires on the whole line locates nothing.

**Two numbers, never one.** Recall never appears without its price on the matched controls, split by the same content-hash rule the corpora use so that a tuned row's false-positive column is not its own selection set.

**Operating points, chosen on `dev`.** The vendor's own default; the cut that maximises Youden's J; the cut that kills no more of the `dev` controls than limes does — limes's own precision, which on these corpora is not zero and is not rounded to it. A tool with no score has one operating point per configuration: a tuned row appears only when `dev` prefers another of its shipped configurations, and a cut that flags nothing is the tool switched off, not a row.

| contestant | formats located (dev) | formats located (holdout) | gitleaks' hard negatives killed (dev) | gitleaks' hard negatives killed (holdout) |
|---|---|---|---|---|
| unplugged (null control) | 0/110 (0.0%) | 0/108 (0.0%) | 0/166 (0.0%) | 0/173 (0.0%) |
| **limes secrets-egress** | 12/110 (10.9%) | 4/108 (3.7%) | 16/166 (9.6%) | 17/173 (9.8%) |
| detect-secrets (Yelp) — vendor default | 21/110 (19.1%) | 10/108 (9.3%) | 25/166 (15.1%) | 28/173 (16.2%) |
| detect-secrets (Yelp) — dev-tuned | 110/110 (100.0%) | 108/108 (100.0%) | 154/166 (92.8%) | 163/173 (94.2%) |
| gitleaks — vendor default ⚑ | 98/110 (89.1%) | 96/108 (88.9%) | 4/166 (2.4%) | 12/173 (6.9%) |
| mcp-firewall (secret scanner) — vendor default | 12/110 (10.9%) | 2/108 (1.9%) | 20/166 (12.0%) | 26/173 (15.0%) |

> **⚑ Home ground.** The secrets corpus is gitleaks' own catalogue: every positive was generated from a gitleaks regex and every negative is a vector its allowlists were written to pass. A row so marked is a ceiling and a sanity check on the corpus, not a comparison, and no sentence in this repository may quote it as one.
> The ceiling is not 100 %: *gitleaks — vendor default* locates 194/218 of the instances generated from its own rules. A rule is more than its regex — an entropy floor, required keywords, an allowlist — and the generator satisfied the regex alone, so some instances fall under their own rule's floor. That is a limit of the corpus, carried by the census column for every contestant alike.

> **Rows that block nearly everything.** *detect-secrets (Yelp) — dev-tuned* kills at least 90% of a control population. Its recall column is arithmetic, not detection.

### What each row actually ran

- **unplugged (null control)** — nothing installed
- **limes secrets-egress** — no threshold to choose: a rule matches and its check passes, or it does not · median 0.02 ms/case
- **detect-secrets (Yelp) — vendor default** — `file`, threshold 0.5, both its own · median 0.67 ms/case
- **detect-secrets (Yelp) — dev-tuned** — `adhoc`, threshold 0, chosen on dev only by Youden's J, then frozen · median 0.67 ms/case
- **gitleaks — vendor default** — `dir`, threshold 0.5, both its own · median 26.51 ms/case
- **mcp-firewall (secret scanner) — vendor default** — `patterns`, threshold 0.5, both its own · median 0.01 ms/case

## Provenance — what was installed, and what it was

**detect-secrets (Yelp)** — every default plugin, over a file per case (`file`) and over the bare string (`adhoc`)

- versions: `detect-secrets 1.5.0`, `python 3.12.4`
- `file` is the tool as shipped: a file scanned by its default plugins, whose high-entropy plugins read quoted strings and leave prose alone. `adhoc` is its `--string` path, which searches every token eagerly and flags ordinary words as high-entropy; both are recorded and the dev split chose between them.
- a plugin reports the secret value it matched, and the span is that value's position in the text; the GitHub plugin reports only the token's prefix, which still sits inside the token and is credited as located.
- the command line verifies some findings against the vendor's API by default — a Slack token is checked with Slack — and drops a token the vendor rejects; the fidelity check runs it with `--no-verify`, so the number is offline and does not depend on a third party's answer about a synthetic token. The library path the adapter calls does not verify.
- a source-code scanner, not a text guard: nothing here is a criticism of the tool on the ground it was built for.

**gitleaks** — the `gitleaks` binary over one file per case, with the catalogue configuration at the vendored commit `b58d3f102cf3` passed as `--config`

- versions: `config b58d3f102cf3 (sha256 e163e53b9e7e…)`, `gitleaks 8.30.1`
- **home ground**: every positive here was generated from a gitleaks regex and verified against it, and every negative is a vector gitleaks' own allowlists were written to pass. This row is a ceiling and a check on the corpus, not a comparison.
- the configuration is the catalogue at the commit the corpus was vendored from, checked against the sha256 the corpus records, so the binary scores the corpus's own rules and not a newer catalogue's.
- a rule matches or it does not: the recorded score is 1, and there is no threshold to choose.
- latency is one `gitleaks stdin` process per payload, the path a deployer would run on each tool result, process start included.

**mcp-firewall (secret scanner)** — the `SecretScanner` outbound stage — seventeen regular expressions, no validator

- versions: `mcp-firewall 0.1.0`, `python 3.12.4`
- secret scanning ships enabled, action `redact`; the scan's decision carries the names of the patterns that fired, which the fidelity check compares against the adapter's spans.
- the scanner reports pattern names and not offsets, so the spans are taken from its own patterns run over the same text.

Full detail — the environment, the recipe, the fidelity checks — in `eval/matrices/comparison/PROVENANCE.md`.

## Held to the formats limes claims

The census above asks how much of gitleaks' 218-format catalogue each tool sees. This asks the fairer question — **on the formats limes says it reads, who reads them?** — over the 19 catalogue rules that name a format limes claims (eight vendor prefixes, PEM, JWT; the AWS *secret* access key has no gitleaks rule to be measured on). A ✓ is a finding wholly inside the vendored instance; every miss of limes's is explained below, and a test holds those notes to exactly the set of misses.

| gitleaks rule | limes rule | limes secrets-egress | detect-secrets (Yelp) — vendor default | detect-secrets (Yelp) — dev-tuned | gitleaks — vendor default | mcp-firewall (secret scanner) — vendor default |
|---|---|---|---|---|---|---|
| `aws-access-token` | `secret:aws-access-key-id` | — | ✓ | ✓ | ✓ | — |
| `openai-api-key` | `secret:openai-key` | ✓ | ✓ | ✓ | ✓ | — |
| `github-pat` | `secret:github-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `github-oauth` | `secret:github-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `github-app-token` | `secret:github-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `github-refresh-token` | `secret:github-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `github-fine-grained-pat` | `secret:github-token` | — | — | ✓ | — | ✓ |
| `stripe-access-token` | `secret:stripe-key` | — | — | ✓ | ✓ | — |
| `gcp-api-key` | `secret:google-api-key` | ✓ | — | ✓ | — | ✓ |
| `slack-app-token` | `secret:slack-token` | ✓ | — | ✓ | ✓ | — |
| `slack-bot-token` | `secret:slack-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `slack-config-access-token` | `secret:slack-token` | ✓ | ✓ | ✓ | — | ✓ |
| `slack-config-refresh-token` | `secret:slack-token` | ✓ | — | ✓ | ✓ | — |
| `slack-legacy-bot-token` | `secret:slack-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `slack-legacy-token` | `secret:slack-token` | ✓ | ✓ | ✓ | ✓ | — |
| `slack-legacy-workspace-token` | `secret:slack-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `slack-user-token` | `secret:slack-token` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `private-key` | `secret:private-key-pem` | — | — | ✓ | ✓ | — |
| `jwt` | `secret:jwt` | — | — | ✓ | ✓ | — |

- **limes secrets-egress** — 14/19 claimed formats located
- **detect-secrets (Yelp) — vendor default** — 12/19 claimed formats located
- **detect-secrets (Yelp) — dev-tuned** — 19/19 claimed formats located
- **gitleaks — vendor default** — 16/19 claimed formats located
- **mcp-firewall (secret scanner) — vendor default** — 11/19 claimed formats located

**limes's misses on its own perimeter, one by one:**

- `aws-access-token` — gitleaks' format admits the `A3T…` prefix family and this instance draws `A3TR`; limes's rule lists AWS's documented key-id prefixes (`AKIA`, `ASIA`, `ABIA`, `ACCA`, …) and not that one. A real gap in limes's rule.
- `github-fine-grained-pat` — `github_pat_…` is a format limes's GitHub rule (`gh[pousr]_`) does not cover. A real gap in limes's rule.
- `stripe-access-token` — the generated body is 10 characters; gitleaks' regex admits 10 to 99, limes's requires at least 24, the shortest body Stripe documents. Whether a 10-character `sk_test_` is a credential or a shape is exactly where the two rules disagree.
- `private-key` — the generated armour is `-----BEGINPPRIVATE KEY BLOCK-----` — no space after `BEGIN`, a `BLOCK` suffix — a shape gitleaks' regex admits and no real PEM carries. limes reads PEM armour as written; it also does not cover PGP's `PRIVATE KEY BLOCK` armour, which is a real format and a real gap.
- `jwt` — the generated first segment does not decode to a JSON header. limes's JWT rule is *only* its validator — the three-segment shape is shared with file names and version strings, so limes refuses the shape alone by design — and a shape-only instance is invisible to it. Counted as a miss; explained as a choice.

## What the false-positive columns can and cannot say

- `gitleaks' hard negatives killed (holdout)`: n=173, alpha=0.05, minimum detectable effect ~= 0.029 (of 173 benign inputs flipped (one-sided exact sign test)).
- limes's own egress corpora — the lookalikes written to trip *these* rules — are **deliberately absent**, for the reason ADR 0020 gives.

## What this table does not measure

- **gitleaks on gitleaks' catalogue is home ground**, marked so above: every positive was generated from its own regex and verified against it, and every negative is a vector its allowlists were written to pass. Its row says the corpus is what it claims to be; it says nothing about gitleaks against an attacker.
- **A shape-only instance favours a shape-only rule.** Two of limes's claimed formats (PEM, JWT) are read by *content* — key material under the armour, a JSON header that decodes — and the generator produces shape-valid, content-random instances. Those misses are named in the perimeter section, not averaged.
- **detect-secrets is a source-code scanner.** Its entropy plugins read quoted strings, which prose rarely has; its `file` mode is how it ships and its `adhoc` mode is its `--string` path. Both are recorded; `dev` chose between them.
- **mcp-firewall is at 0.1.0.** Seventeen regexes with no validator, run as shipped; a young project's floor, not its ceiling.
- **The AWS secret access key has no row.** gitleaks covers that format only through an entropy gate limes measured itself out of (ADR 0021 Am. 2, ADR 0022), so the catalogue has no instance to score anybody on.
- **Everything limes is actually for.** A refusal that names the rule and the span, a policy hash on every verdict, evidence that replays, `CannotSay` when a detector could not read. None of that survives a located-span boolean.

