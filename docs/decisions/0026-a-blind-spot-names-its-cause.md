# 26. A blind spot names its cause

Date: 2026-09-06

## Status

Accepted. Amends ADR 0002's algebra for the first time since v0.1: `CannotSay`
gains a field. Amends ADR 0004's frontier for `src/limes/verdict.py`,
`src/limes/guard.py`, `src/limes/detector.py` (prose and one optional protocol,
see ADR 0027) and the two contract tests that construct a `CannotSay`
(`tests/unit/test_verdict.py`, `tests/unit/test_record_chain.py`), each re-pinned
in `tests/unit/test_frontier.py`. Supersedes nothing: ADR 0002's three verdicts
stand, and ADR 0006's refusal of a fourth stands with them.

## Context

`CannotSay` says "nobody could look". By 0.13.0 four different things said it
with the same type and the same shape:

- a detector **declaring a limit** of its own coverage — content over its
  `max_content_chars`, or not encodable to UTF-8 (`DetectorBlind`, ADR 0023);
- a detector that **crashed** — any other exception, rendered as a blind spot
  since ADR 0011 Amendment 2 so that a guard would not die mid-verdict;
- the relay **refusing** to take a request on because its table of unanswered
  guarded requests was full (ADR 0024);
- and, in prose only, the things the guard never reads at all.

An operator reads them differently. A declared limit is deterministic,
reproducible and the operator's own policy choice; accepting it knowingly is a
legitimate deployment decision, and `on_cannot_say: allow` exists for exactly
that. A crash is a bug, transient or provoked, and a crash an attacker can
provoke on purpose — a validator with an edge case, a pattern that throws on
some input — is, under `allow`, a bypass. A refusal is not about the content at
all: nothing was looked at, and the setting has nothing to say about it.

The code already treated them differently, but by construction site rather
than by type: the relay's table-full refusal built its `Ruling` directly and
never passed through `rule()`, so it blocked under `allow` while a crashed
detector's `CannotSay` went through `rule()` and *forwarded* under `allow`. Two
blind spots, two behaviours, chosen by where the object was made. And ADR 0011
Amendment 2 had widened the exposure without noticing: before it, a crash killed
the session, so nothing was ever forwarded; after it, a crash became a
`CannotSay` that `allow` opened.

An audit proposed a fourth verdict. The diagnosis was right and the remedy is
refused here for the reason ADR 0006 refused `Redact`: the algebra states an
*observation* — found something, found nothing after looking at everything, did
not get to look — and *why* nobody got to look is a property of the third state,
not a fourth state. A new variant would also make every `match` in every caller
silently incomplete, since Python's `match` falls through without
`assert_never`, which is the opposite of what a security type is for.

## Decision

**`CannotSay` carries its cause.** `CannotSay(blind_spot, cause)`, where `cause`
is one of three values of a closed enum, `BlindCause`:

- `DECLARED` — a witness declared a limit of its own coverage, or no witness is
  wired for the leg at all (ADR 0027), or the caller declared a part of its
  payload it could derive no text from (ADR 0028);
- `FAULT` — a witness fell over instead of answering;
- `REFUSED` — nobody was asked: the transport refused to take the content on.

The field has **no default**, for ADR 0002's reason: a cause the type guessed on
the caller's behalf would be a lie that reads complete, and the transport policy
turns on it. A string is refused (`TypeError`); the enum is a `StrEnum`, so a
caller that compares `cause == "fault"` still reads correctly.

**The core assigns it.** In `decide()`, `DetectorBlind` is `DECLARED` and any
other exception is `FAULT`; when both occur in one decision the verdict carries
`FAULT`, because the operator who accepted declared limits has not accepted a
crashed guard. A finding still dominates every blind spot, as before.

**The fingerprint seals it.** `fingerprint()` adds `"cause"` to a `CannotSay`'s
canonical JSON, so two blind spots that differ only in cause are different
records and a cause cannot be edited after the fact. `render()` shows it in
parentheses. Every `CannotSay` digest changes; `Allow` and `Deny` digests do not.

**The ruling opens one cause and nothing else.** `rule()` forwards a `CannotSay`
under `on_cannot_say: allow` **only when its cause is `DECLARED`**. A fault and a
refusal block under either setting, and the refusal text the host reads says
which causes no setting opens. `_meta.limes` gains a `cause` key (`null` when
somebody looked).

**Every refusal goes through the ruling.** The relay's table-full refusal is a
`CannotSay` with cause `REFUSED` passed to `rule()` like any verdict, not a
`Ruling` assembled by hand. And a frame the relay cannot parse — from either
peer — which was dropped with a line on stderr, is now also a `CannotSay` with
cause `REFUSED` on the chain, disposition `block`, with the failure's *type*
only: a parser's message quotes the input it choked on, and the chain never
carries a payload.

**The in-process guard changes nothing about its disposition.** `check_egress`
blocks every `CannotSay` whatever its cause, as it did; its reason line and
`Blocked`'s message name the cause. `limes check` exits `3` for every cause: a
scanner takes no disposition, so it opens nothing.

## Consequences

- An operator who sets `on_cannot_say: allow` now gets what the setting says:
  the guard's declared limits are accepted, a crashed guard is not. The
  regression ADR 0011 Amendment 2 introduced for that setting is closed; a
  ratchet (`tests/unit/ratchets/test_a_blind_spot_names_its_cause.py`) holds a
  crashing detector at *block* under `allow`, and was seen red on the 0.13.0
  tree.
- The journal answers "how many faults this week" with a query over
  `verdict_fingerprint`, not by reading prose.
- `CannotSay("...")` with one argument no longer constructs. The change is
  breaking for code that builds a `CannotSay` by hand — in this repository, one
  relay method and a handful of tests; outside it, nothing the project knows of,
  the package not being on PyPI. `case CannotSay(blind_spot):` keeps matching:
  `__match_args__` is `("blind_spot", "cause")` and a shorter pattern is legal.
- `BlindCause` is imported from `limes.verdict`, not re-exported from `limes`:
  `limes/__init__.py` is a prose-only module whose code may move only by a
  declared delta (ADR 0014), and a string comparison against the `StrEnum`
  serves the caller who does not want the import.
- Every recorded `CannotSay` digest changes at 0.14.0; ledgers are per session
  and no chain spans a version.
