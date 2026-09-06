# 27. A witness names its leg, and a guard with no witness says so

Date: 2026-09-06

## Status

Accepted. Amends ADR 0004's frontier for `src/limes/detector.py` (one optional
protocol), `src/limes/guard.py`, `src/limes/detectors/injection.py` (one class
attribute) and `tests/unit/test_detector_protocol.py`, each re-pinned in
`tests/unit/test_frontier.py`. Supersedes one consequence of ADR 0011 — "with
zero detectors wired ... an `Allow` whose evidence names every detector that
ran: none" — and the special case in the relay that existed to avoid it.

## Context

Every admitted detector reads one leg and answers `[]` on the other. The core
did not know that: it asked every detector about every leg and counted every
one that returned without raising as a **witness** — somebody who looked and
found nothing. An in-process `Guard` wired with the four admitted detectors
therefore reported four witnesses on every inbound call, three of which had not
read a character; `limes check --direction outbound` until v0.10 reported a
clean `Allow` witnessed by the one detector that never inspects that leg (ADR
0018 closed that instance by selecting detectors per leg, in every transport,
by the `-egress` suffix of their ids). For a project whose tagline is "the guard
that can prove what it looked at", evidence that overstates who looked is the
wrong kind of wrong.

A leg with **no** detector at all was the limiting case: `decide()` over `()`
returned an `Allow` whose evidence listed nobody — a pass that reads like a
verdict. ADR 0011 recorded that as the intended semantics ("the core does not
invent a witness"), and the relay avoided it by not constructing an outbound
guard when no egress detector was wired, forwarding those responses untouched
and unrecorded. The core and the transport disagreed about what an empty leg
means, and the transport was right.

## Decision

**A detector may name the legs it reads.** A second, optional, runtime-checkable
protocol, `DeclaresDirections`, with one attribute: `directions:
frozenset[Direction]`. The `Detector` protocol itself is unchanged, so every
v0.1-style detector — the eval harnesses' `_BlockEverything`, the ported
baselines, a third party's plugin — keeps working as it did: a detector that
declares nothing is asked on every leg and its `[]` is taken at its word. All
four admitted detectors declare, and a ratchet holds them to it and to
agreement with the `-egress` convention the transports select by.

**The core asks a declaring detector only on its legs**, and counts it as a
witness only there. On the other leg it is not asked and not listed: the
evidence names exactly who read the content.

**A leg nobody reads is `CannotSay`, cause `DECLARED`**, with the blind spot
"no detector reads the *leg* leg: nobody looked, and an Allow with no witness
would be a pass that reads like a verdict". The core no longer returns an
`Allow` with an empty witness list under any input.

**The relay keeps its pass-through for a deliberately empty outbound leg** —
an embedder that passes `outbound=()` asked for it, and the transparency tests
prove exact pass-through with it — but no longer in silence: the first time
each guarded kind of response crosses that empty leg, the chain records a
declared blind spot saying so (the mechanism is ADR 0028's).

## Consequences

- An in-process guard wired with both legs' detectors now names only the
  detector that read the leg. A guard wired with the wrong leg's detector
  blocks on egress (`CannotSay`, nothing leaves) where it used to pass.
- `decide(..., ())` is `CannotSay`. Every harness already counted only `Deny`,
  so no matrix moves; the null-control rows are unchanged in number and in
  meaning ("nothing looked, nothing was blocked").
- The `-egress` suffix stays the transports' selection rule (ADR 0018); the
  declaration is the core's. A test asserts the two agree for the admitted set,
  so neither can lie about the other.
- Adding the attribute to the `Detector` protocol itself was considered and
  refused: it would have broken mypy on two frozen core modules that define
  v0.1-style detectors (`eval/harness.py`, `baselines/tessera_regex.py`) for a
  purely declarative gain, at the price of two more core pins.
