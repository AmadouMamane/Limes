# 22. An unprefixed secret is caught by its name, or not at all

Date: 2026-08-31

## Status

Accepted. Applies the constraint ADR 0021 Amendment 2 established (no entropy
gate can exist here) to the one format that gate was wanted for, and lands the
half a measurement supports. Extends the rule schema by one field
(`value_group`) and the validator registry by one check (`not_pure_hex`).

## Context

The AWS *secret* access key is the last credential in the README's own threat
sketches with no rule at all: forty base64 characters, no vendor prefix, missed
even when its context keyword sits right next to it, because the detector's
docstring declared the whole species out of scope. The obvious fix — some
threshold on the body — is the one this repository has already refused **on
evidence**: ADR 0009 makes limes's own positives placeholders, so any body gate
strict enough to reject `gho_xxxx…` rejects the corpus, and
`AKIAIOSFODNN7EXAMPLE` is a limes positive and a gitleaks negative at once (ADR
0021 Am. 2). Context and length/charset are the only tools left on the table.

The field's three existing answers were fetched and measured rather than
described (sha256 of each fetched source recorded below):

| tool | its rule | measured here |
|---|---|---|
| **gitleaks** (MIT) | no AWS-secret rule at all; the format is left to `generic-api-key`, which is gated on entropy ≥ 3.5 — the gate limes cannot have | its catalogue materialises **no** exactly-40 AWS-secret instance |
| **detect-secrets** (Apache-2.0, Yelp) | `aws` + a secret keyword + a *quoted* 40-char body, all within 20 chars (`plugins/aws.py`, `6500335d08f0…`) | locates **2/12** of the realistic assignment carriers — the quoting requirement starves it |
| **git-secrets** (Apache-2.0, AWS's own) | keyword + operator + 40-char body — with **every context group optional** (`775e3f0d2f2f…`) | degenerates to a bare-body rule: 12/12 recall, and **64/339** of gitleaks' hard negatives killed, 17/20 of the hard benign corpus, 4 of limes's own lookalikes |

So the industry offers: a refusal (entropy-gated generic), a rule too starved to
see the leak shapes, and a rule that fires on everything. None is adoptable as
is, and the honest question was never "which one to copy" — it was **does the
context keyword separate, and where exactly does it stop?** That question was
put to corpora built to break it, expecting a split answer, and a split answer
is what came back.

## Decision

**The keyword-present case lands; the bodyless case is declared impossible, with
the measurement that proves it.**

### The measurement protocol

Three populations were built for this decision, plus two that already existed:

- **positives** — the AWS secret in realistic carriers, values being AWS's two
  *published documentation secrets* (`wJalrXUtnFEMI/…EXAMPLEKEY` is in
  git-secrets' own shipped allowlist, verified at source): env lines,
  `~/.aws/credentials`, STS JSON (`SecretAccessKey`, CamelCase, no "aws" in
  reach), YAML, TOML, PHP `=>`, fr/de prose, Terraform's bare `secret_key`,
  `MINIO_SECRET_KEY`. Families are labelled: `assignment` (an operator is
  present — the claim), and `spaced` / `bracketed` / `positional` /
  `prose_l10n` (probes of the declared limits, not claims).
- **hard benign** — the corpus the claim is paid for: exactly-forty
  `[A-Za-z0-9/+]` bodies that are *not* secrets, in the same kind of context.
  Git SHA-1 pins, a `password_sha1`, a rotation log, a cache key, a base64
  session blob, an ETag, a Secrets Manager **ARN** whose resource tail is forty
  slashed characters after the word `secret:`, the fingerprint-of-the-secret
  (`aws_secret_access_key_hash = <40 hex>`), prose with a SHA near the word
  *secret* in three languages.
- **holdout** — fresh values, fresh carriers, sealed in a separate file before
  any variant was scored, read once, at the end, with the rule frozen.
- gitleaks' **339 hard negatives** and limes's **51 internal lookalikes**
  (secrets + pii), unchanged.

### The separation table that decided it

Dev populations, every variant a grammar × keyword-set pair; `[nonhex]` refuses
a body that is one unbroken hex run:

| variant | assignment located | hard benign killed | gitleaks negatives | internal benigns |
|---|---|---|---|---|
| bare body, no keyword (**the bodyless case**) | 12/12 | **17/20** | **15/339** | **3/51** |
| git-secrets verbatim (all context optional) | 12/12 | 17/20 | **64/339** | 4/51 |
| proximity: any secret keyword within 40 chars | 12/12 | **14/20** | 4/339 | 0/51 |
| assignment grammar + generic keyword list | 12/12 | **11/20** | 3/339 | 0/51 |
| assignment grammar + generic list [nonhex] | 12/12 | 5/20 | 1/339 | 0/51 |
| detect-secrets verbatim | 2/12 | 0/20 | 0/339 | 0/51 |
| **assignment grammar + AWS vocabulary [nonhex]** | **12/12** | **0/20** | **0/339** | **0/51** |

The bodyless row is the 4b evidence, measured rather than assumed: with no
keyword, the only separators left are the ones ADR 0009 forbids. The proximity
row is the mission's literal question ("a keyword within N chars") and it does
**not** separate — prose like *« Le secret a été déplacé ; voir le commit
`0f1e…` »* and *"Der Token wurde widerrufen, Commit `9a8b…`"* is exactly where
it dies. The generic keyword list dies on a password hash, a cache key, an
upload token and the ARN. What separates is the conjunction: **AWS's own
vocabulary, in value position of an assignment**.

### The rule that lands

- **Grammar**: gitleaks' semi-generic assignment machinery, *transcribed* from
  the vendored catalogue (`cloudflare-api-key`, `gitter-access-token` carry it
  verbatim): keyword, up to twenty identifier characters, an assignment
  operator (`=`, `:`, `=>`, `:=`, `||`, `?=`, `,`, `>`), up to five characters
  of quoting, the body, a terminator. ADR 0021 Am. 2 already measured what
  happens when this repository re-derives a grammar instead of transcribing it:
  four real formats lost. The operator is the discriminant proximity lacks — a
  SHA *near* the word secret never sits in value position of one.
- **Keywords**: AWS's own vocabulary, three alternatives — `aws…secret…key` as
  one identifier run (`aws_secret_access_key`, `aws.secretKey`,
  `cloud.aws.credentials.secretKey`), `secret access key` with any separator
  including spaces (the words AWS itself uses: `SecretAccessKey` is the STS
  response field, "secret access key" the prose form), and bare `secret_key`
  (Terraform's provider argument, MinIO) — identifier-only, because "secret
  key" in prose is generic English. The generic list (`access|api|key|token|…`)
  is **refused** at the price above.
- **Body**: exactly forty of `[A-Za-z0-9/+]` — detect-secrets' class, which is
  the faithful one (a real secret is unpadded base64 of thirty bytes;
  git-secrets' `=` is slack). Bracketed by the grammar so a 64-char SHA-256 or
  a 41-char run can never shorten itself into a hit.
- **`value_group`** (new rule field): the finding spans the named group — the
  credential — never the carrier line. The keyword and operator are how the
  value was recognised, not part of it; the mask must cover the value and the
  exact-span grader scores it there. The loader refuses a group the pattern
  does not define, and refuses the combination with `retry_trim` (no measured
  meaning).
- **`not_pure_hex`** (new validator): refuses a body that is one unbroken hex
  run. This is a **charset property, not an entropy threshold**: a real secret
  is base64 over thirty random bytes, all-hex with probability (16/64)^40 ≈
  2⁻⁸⁰, while the family that actually collides behind these keywords at forty
  characters — SHA-1 pins, digests, fingerprints of the very key — is hex *by
  construction*. Same species as the PEM material floor: derived from the
  format, not fitted to a corpus. It buys the last two dev false positives
  (`aws_secret_access_key_hash = <sha1>`, `secret_key_rotation_log: <sha1>`)
  at a recall cost that is not a number a corpus can even exhibit.

### The bodyless declaration (the other half)

A bare forty-character `[A-Za-z0-9/+]` run with no keyword in reach is **out of
scope, and cannot come into scope under this repository's rules**: the
measurement above prices the bare-body rule at 17/20, 15/339 and 3/51, and
every remaining discriminant is a body-content threshold ADR 0009 forbids this
repository from tuning or validating (its own positives are placeholders by
law). The same reasoning covers the genuinely formless credentials — a database
password, an arbitrary `client_secret` — which have no length or alphabet to
anchor on at all; they are the README's declared non-capability, now with a
measured price tag instead of a sentence. `tests/unit/egress/
test_aws_secret_context_rule.py` pins the refusal: deleting that test means
shipping git-secrets' 64/339, and must bring the measurement that licenses it.

## The numbers

Dated 2026-08-31, rules frozen, holdout scored once.

**Internal admission matrix** (`eval/matrices/secrets_egress.md`):

| | before | after |
|---|---|---|
| located | 15/15 | **20/20** (new category `aws_secret` 5/5) |
| benign killed | 0/25 | **0/32** (7 new hard lookalikes, all held) |

**Sealed holdout, one pass**: assignment carriers **6/6 located** — docker
`run -e`, single-quoted `.env`, kubernetes `stringData` with the hyphenated
key, JS SDK camelCase, a spaced STS JSON, a German-commented YAML — none of
which appeared in tuning. Hard benign holdout **0/12 killed** (fresh ARN,
`secret_key_base_digest`, base64 `auth_state`, a bare mixed run, an ETag). The
four probe families missed exactly as declared: `prose_l10n` 0/1, `bracketed`
0/1, `spaced` 0/1, `positional` 0/1 — misses that were *written down before
they were scored*.

**External bench** (`eval/matrices/external_secrets.md`, `--split all`, once):
**12/110 dev, 4/108 holdout, 33/339 negatives — identical to the digit** with
the rule in place. Two readings, both stated: the rule adds **zero false
positives on the vendor's own hard-negative ground**, and it adds zero external
recall, because gitleaks *has no AWS-secret rule* for the corpus to have
materialised — the format the industry's biggest catalogue covers only through
an entropy gate is precisely the one limes now covers without one. The external
witnesses for this rule are the negatives and the transcribed grammar itself.

## What was probed by hand, because no corpus could hold it

Insight 515's discipline (a blank sheet on a population that cannot host the
failure is not a blank sheet), both directions:

- **Recall**: compact `key:value` with no space, Ruby `=>`, bare
  `SECRET_ACCESS_KEY=`, Windows `set`, compact camelCase JSON, two secrets on
  one line — all located. French typography (`secret access key :` with a
  no-break space) **fires**, contrary to the prediction: Python's Unicode `\s`
  in the vendor grammar's quoting run absorbs the NBSP. Pinned as a test so it
  stays true.
- **Named residual false-positive classes, measured and left**: a *clean* path
  of exactly forty characters in value position
  (`aws_secret_access_key_file = /run/secrets/aws/currentSecretKeyV2/main`)
  fires — it must be dot-, dash- and underscore-free and land on exactly forty,
  and it cannot be suppressed without dropping `/` from the body class, which
  real secrets contain. And `secret_key_id: <forty mixed>` fires — a
  credential-shaped value behind a secret-named key is a leak signal by this
  repository's declared policy (the `AKIAIOSFODNN7EXAMPLE` position, ADR 0021
  Am. 2), whichever record it names.
- **Declared misses, pinned red-on-fix**: `ENV AWS_SECRET_ACCESS_KEY <v>`
  (no operator), `aws configure set … <v>` (no operator),
  `os.environ["…"] = "<v>"` (the `]` is outside every class of the vendor
  grammar — gitleaks misses it identically), `Aws::Credentials.new('…', '<v>')`
  (a positional argument has no keyword at all — the bodyless gap wearing a
  method name), and prose whose only vocabulary is non-English (`clé secrète
  AWS : <v>`). Each is real, each is measured, each is written in the policy
  comment and pinned by a test that a lifting change must delete — with its
  measurement.

## Consequences

- The detector's perimeter sentence changes for the first time since v0.6:
  eight vendor prefixes plus PEM and JWT **plus one context-anchored format**.
  The README table's "unprefixed credentials" non-goal is rewritten to say
  which half landed and which half is impossible, with the numbers.
- The engine grew one honest notion: a rule may declare that its shape includes
  context and its value is a group. Exactly one shipped rule uses it, and a
  test enumerates that list so the next one arrives by the same gate.
- `prompt_hijack` discipline applies unchanged: nothing here was validated on
  that family.
- The corpus enforcers held throughout and one fired during this work:
  a German benign SHA carried a nineteen-digit Luhn-valid prefix and was
  **refused by the synthetic-corpus ratchet** until the digits were broken up —
  the ADR 0009 machinery policing this very ADR's additions.
- Everything touched is inside `DETECTOR_PERIMETER` (rules, corpus, harnesses,
  matrices, their tests). No re-pin, none claimed.
- The measurement bench and the sealed holdout live outside the repository (a
  session scratchpad); what ships is what they admitted: the rule, the corpus
  cases that reproduce every load-bearing number, and the tests that pin the
  refusals. The dev/holdout corpora themselves are reproducible from this ADR's
  tables.
