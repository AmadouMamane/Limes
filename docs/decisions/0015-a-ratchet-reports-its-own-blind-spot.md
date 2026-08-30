# 15. A ratchet reports its own blind spot, and never an assertion the missing tool satisfies

Date: 2026-08-30

## Status

Accepted. Amends ADR 0004's frontier for exactly one file
(`tests/unit/ratchets/test_allow_needs_evidence_mypy.py`), by the mechanism ADR
0011 established. Generalises to every ratchet in this repository.

## Context

Two of this project's ratchets do not judge the code directly. They ask
something outside themselves — git, for the bytes of the v0.1 commit; mypy, for
whether a type error is raised — and then judge the answer. That dependency has
a third possible outcome the ratchets did not have a word for: **the thing was
never asked**.

It cost six weeks, in the open, unnoticed.

`tests/unit/test_frontier.py` compares today's bytes against the v0.1 commit,
read out of git history. `actions/checkout` fetches **depth 1** by default, and a
shallow checkout cannot produce that commit's tree. So from v0.1 to v0.8 the
frontier ratchet — the witness that ADR 0004's promise rests on — never ran on
CI: **16 red runs out of 17**, always the same cause, and the single green run
was the v0.1 commit itself, where the comparison was trivially true. `make gate`
was green throughout, because a developer's clone has the history. The badge at
the top of the README, about to be printed on a package index, pointed at a
workflow that had been red since the day it was written.

The same file already knew the right shape and did not apply it consistently:
`_git()` answered "I could not look" with `pytest.skip`, while `_v0_1_bytes()`
answered it with `assert result.returncode == 0`. Run from an unpacked sdist —
which ships `tests/` and no `.git`, and which is exactly what a downstream
packager (conda-forge, Debian) runs — `pytest` printed **27 reds that said
nothing about the code**.

The type-level ratchet has the sharper version of the same defect, and it points
the other way:

```python
proc = subprocess.run([sys.executable, "-m", "mypy", "--strict", ..., snippet])
assert proc.returncode != 0, "mypy ACCEPTED Allow() with no evidence — the ratchet is broken"
```

`python -m mypy` exits non-zero when mypy is **not installed**. So the assertion
that means *"mypy rejected `Allow()`"* is satisfied by mypy's own absence. Today
a second assertion on the message text catches it — the author saw the risk and
wrote `"mypy failed for the wrong reason"` — but that leaves the ratchet one
refactor, one reordering, one loosened matcher away from reporting **success over
a hole**. A guard whose primary assertion is satisfied by its own blindness is
not a guard; it is a coin that lands heads either way.

## Decision

Wherever a ratchet depends on something outside itself, it distinguishes **three**
states, and it decides which one it is in **before** interpreting any result.

1. **It could not look, and that is a fact of the environment.** An sdist ships
   no git history; a runtime may not have mypy. The test reports a **blind
   spot** — skipped, with a reason naming exactly what was missing. Never green,
   never red: both would be claims about code nobody examined (ADR 0026 of
   Tessera, inherited — *a witness that cannot see may never report "ok"*, and
   by the same argument may never report a failure either).
2. **It could look, and the thing is wrong.** Red, as before.
3. **It could not look, and that is a misconfiguration rather than a fact.** A
   *truncated* git history is not an sdist: somebody asked for a shallow clone,
   or accepted a default that produces one. This gets a **single, dedicated red**
   that names the fix. Its purpose is structural: it makes it impossible for the
   skips of state 1 to quietly disarm a suite. A skip is only ever safe when
   something else would go red if the skipping became the normal case.

And the rule that would have caught the mypy ratchet on its first day:

> **No assertion may be satisfiable by the absence of the tool it depends on.**
> Presence is established first, by asking for the tool, not by reading an exit
> code that conflates "the tool disagreed with you" with "there was no tool".

Concretely, `test_allow_needs_evidence_mypy` resolves mypy's presence with
`importlib.util.find_spec` before running anything, and skips with a reason that
states the trap in full, so the next reader cannot re-introduce it by accident.

The environment is fixed to match: CI checks out the **full** history
(`fetch-depth: 0`), so the frontier ratchet actually runs where it was always
supposed to, on every supported Python.

## Consequences

- The frontier ratchet runs on CI for the first time since v0.1, on 3.12, 3.13
  and 3.14.
- From an unpacked sdist, `pytest` goes from **27 reds to 0**, with 30 skips that
  each name what was missing. A downstream packager sees a suite that describes
  its own limits instead of a wall of failures about a checkout.
- On a shallow clone: exactly one red, naming `fetch-depth: 0`.
- `tests/unit/ratchets/test_allow_needs_evidence_mypy.py` is in `CORE`. It leaves
  byte-identity to v0.1 and is pinned in `AMENDED` to the sha256 of its post-ADR
  bytes — the second authorised amendment, and the same mechanism as the first.
  Every other `CORE` entry remains pinned to v0.1.
- The `mutation` marker's contract is unaffected: the ratchet must still be seen
  red under the named source mutation (`Allow.evidence` given a default). A
  ratchet never seen red is not a ratchet — and, this ADR adds, a ratchet that
  cannot say when it did not look is not one either.
