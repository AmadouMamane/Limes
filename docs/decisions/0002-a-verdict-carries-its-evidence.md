# 2. A verdict carries its evidence

Date: 2026-07-15

## Status

Accepted. This is the contract everything else depends on; freeze it first.

## Context

A guard's answer is not a boolean. "Allowed" that cannot say *what it looked at*
is indistinguishable from "did not look" — and the second is the more common
failure. Tessera paid the full price for learning this and wrote it down: a
witness that cannot see may never report "ok" (ADR 0026); a verdict carries its
evidence and a role is not a writer (ADR 0027); no governed act carries a
default that names its author (ADR 0024). limes is that doctrine made
load-bearing at a security boundary, where a false "allow" is an incident.

Tessera keeps two things apart that limes must fuse: its guard records a
`DecisionKind` *string* (`allow` / `deny` / `transform`) next to a *separate*
`Verdict` algebra used elsewhere. A decision string cannot prove what it
examined. In limes the guard's decision **is** a verdict, and the verdict
carries its evidence.

## Decision

**The algebra.** A closed, exhaustively matched union:

```
Verdict = Allow(evidence) | Deny(reason, evidence) | CannotSay(blind_spot)
```

- **`Allow` is unconstructible without `Evidence`** — no default, no convenience
  constructor. Enforced at the type level: `Allow()` is a mypy error. A ratchet
  (`tests/unit/ratchets/test_allow_needs_evidence_mypy.py`) asserts mypy rejects
  it, and that ratchet goes red *exactly* when someone gives evidence a default —
  the moment `Allow()` type-checks (mypy returncode 0) is the red we are
  watching for.
- **`__bool__` raises.** There is no `if verdict:`. Every Python object is
  truthy, so a bare truthiness test would read a `Deny` — and a `CannotSay`! —
  as success. That is the bug this type exists to make unrepresentable. Callers
  pattern-match.
- **A detector that cannot see yields `CannotSay`, never `Allow`.** Dependency
  absent, content unreadable, timeout — a blind spot is a fact to publish, not a
  pass. When any detector is blind and none denied, the verdict is `CannotSay`;
  a genuine detection still `Deny`s (a found attack is found regardless of a
  neighbour's blind spot).

**Evidence** is a frozen dataclass: the detector's id and version, the hash of
the active policy, the redacted matched spans (offset + rule label + a hash of
the matched text — *never* the raw payload), and `observed_at`, supplied by the
caller. `observed_at` is **not** defaulted to `now()`: the chain must re-derive,
and a wall-clock default would make replay non-deterministic (Tessera's
`GuardDecisionRecord.occurred_at` defaults to `now()` — correct for it, wrong
for a replayable ledger).

**The chain.** Each decision, whatever its verdict, produces a `DecisionRecord`
carrying `prev_hash` and a `digest` — sha256 over canonical, sorted-key,
whitespace-free JSON; genesis is 64 zeros; verification recomputes and compares
(Tessera `audit.py`'s scheme). Linkage lives on the *record*, not on `Evidence`,
because `CannotSay` carries no evidence yet a blind spot must still be in the
ledger. Replay a recorded session and the digests re-derive identically; an
integration test proves it.

**Identity.** No identity field carries a default that names someone.
`actor: str | None` — `None` is honest; `"system"` is a lie that reads complete
(ADR 0024 lineage). The actor is asserted by the calling session.

## Consequences

- A `Deny` carries both a human-readable reason **and** its evidence: a refusal
  is auditable and contestable. This is the tagline made mechanical — "the guard
  that can prove what it refused."
- Measurement is a *different* algebra and lives in the eval layer, not this
  union: `NoEffect(claim, power)` (ADR 0003) reports a null result with its
  statistical power. A guard decision is never "no effect", so `NoEffect` is not
  a `Verdict`.
- The core carries no I/O, no transport, no wall clock. It is data and total
  functions over data — which is what makes it replayable and what lets the core
  stay small (ADR 0004).
