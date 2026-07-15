# Contributing to limes

Thank you for your interest in limes. This is a young project with a small,
load-bearing set of decisions; the fastest path to a merged change is to work
*with* those decisions rather than around them. Please skim the four founding
ADRs (`docs/decisions/0001`–`0004`) before a substantial change — they are short.

## The one rule that is not negotiable: the admission rule

**No detector lands without its two numbers** (ADR 0003). A detector that reports
only how many attacks it blocks is a decoration: the trivial "block everything"
guard blocks 100% of attacks *and* 100% of legitimate traffic. So every detector
ships with **four** things, or it does not ship:

1. a **positive corpus** — the attacks it is meant to catch;
2. a **benign corpus** — legitimate traffic it must *not* kill;
3. a **null control** — measured against doing nothing (the unplugged guard that
   blocks 0) **and** against block-everything (which blocks all);
4. a **published, dated confusion matrix** — precision / recall / F1, checked in
   under `eval/matrices/`.

The two numbers, always together: **attacks blocked _and_ legitimate traffic
killed.** A "no regression" claim carries its statistical power — the benign-set
size that licenses it (see `limes.eval.power`; a set too small to reject the null
is reported as `CannotSay`, never as "ok"). The enforcer is
`tests/unit/test_admission_rule.py`; it is mutation-tested, so a detector that
skips any of the four turns the suite red.

## Where your change goes (ADR 0004)

limes has three layers, and **the core never grows**:

- **Core** (`src/limes/`: `verdict.py`, `record.py`, `detector.py`, `guard.py`)
  — the verdict algebra and the evidence chain. A change here needs a very good
  reason and probably a new ADR.
- **Detectors** (`src/limes/detectors/`) — new detection capability lands here,
  behind the `Detector` protocol, discovered by entry point. Rules live in YAML
  (`policy.yaml`), never hardcoded in Python, and are hashed into every
  `Evidence`.
- **Transports** (`src/limes/transports/`) — new integration surface (MCP, HTTP,
  …) lands here.

"Add a feature" should mean "add a plugin", never "edit the core". If your change
seems to need a core edit, it is either mis-scoped or it is a new ADR that
supersedes 0004 — open that ADR in the same change.

## Development

```sh
make sync    # uv sync — install deps into .venv
make fmt     # ruff format + ruff check --fix
make gate    # ruff + ruff format --check + mypy --strict + pytest — must be green
make eval    # regenerate the confusion matrix
```

- Python 3.12, managed with **uv** (no pip, no poetry, no `requirements.txt`).
- `mypy --strict` and `ruff` are enforced. `make gate` is the same set of checks
  CI runs; a PR that is not green locally will not be green in CI.
- Tests split into `tests/unit/` (fast) and `tests/integration/`. Ratchets under
  `tests/unit/ratchets/` are mutation-tested — a ratchet that is never seen red is
  not a ratchet.

## The corpus, and what may never re-enter it

The default corpus is copied from Tessera (Apache-2.0; see
`src/limes/corpus/PROVENANCE.md`). One invariant is enforced by
`tests/unit/test_corpus_provenance.py` and must be preserved: **no refusal marker
in `must_contain_any` may be a word the attacker can make the model say.** A token
that appears in a case's own attack text is not evidence of refusal. Adding such a
token turns the suite red — do not work around it.

## Commits and pull requests

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `chore:`, `ci:`, `perf:`).
- Keep PRs small and focused. Fill in the PR template.
- Structural changes reference (or add) an ADR.

## The CLA — required before your first merge

limes is Apache-2.0 for the engine, with a separate license planned for the
curated detection corpus (ADR 0004). To keep that option open, **no external
contribution is merged without a signed Contributor License Agreement.** See
[`CLA.md`](CLA.md). It is a one-time step, and it protects the project's ability
to offer the dual license it was designed around — without it, that option dies
the day the first external patch lands.

By contributing, you agree that your contributions are licensed under Apache-2.0
and covered by the CLA.

## Reporting security issues

Please do **not** open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
