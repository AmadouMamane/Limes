# 6. Egress redaction is a transport behaviour, not a verdict

Date: 2026-07-24

## Status

Accepted. Extends ADR 0004 (core / detectors / transports) and ADR 0002 (a
verdict carries its evidence). Applies to both shipped transports.

## Context

A detector that fires on the way *out* — on a tool result, on a resource — puts
the transport in front of a choice the core cannot make for it. The core answers
one question, *is this content clean?*, and it answers `Deny`. Whether the right
consequence is "the host loses the whole response" or "the host gets the response
with three regions overwritten" is not a property of the content. It is a
property of the deployment: a leaked API key is worth losing an answer over; a
customer's e-mail address in an otherwise useful account summary usually is not.

Encoding that choice in the core would mean one of two things, and both are
refused here:

- a fourth verdict (`Redact`), which would make every existing `match` statement
  in every caller silently incomplete, and would put a *remediation* inside a
  type whose whole job is to state an *observation*;
- a detector that returns masked content, which would make detectors responsible
  for rewriting payloads they were only ever asked to look at, and would put
  content-mutation behind the plugin boundary.

The masking itself needs nothing new. `Evidence` already carries, for every
match, a `RedactedSpan` with `start`, `end`, the rule label and the SHA-256 of
what matched. The transport is holding the content — it has not forwarded it yet.
So it can overwrite exactly the named offsets. **The prerequisite the task
description anticipated ("if the finding does not carry its offsets, add them")
turned out to be already satisfied**: v0.1 put them there, for evidence, and they
are exactly what a masker needs. No field was added to the core.

## Decision

**1. Redaction is implemented in `limes/transports/redaction.py`, shared by both
transports.** It is pure: policy, plan, and the application of a plan to a
string. It imports `limes.spans` and `limes.verdict` and nothing else of the
core; it imports no SDK, so it stays on the light side of the `limes[mcp]` extra.

**2. The policy is `on_egress_finding`, per kind, and its default is `block`.**
Read from the same YAML file the transport already reads `on_cannot_say` from, in
either of two shapes:

```yaml
on_egress_finding: redact          # shorthand: sets the default

on_egress_finding:
  default: block
  by_kind:
    pii: redact
    secret: block
```

The **kind** is the half of a rule label before the first colon: `pii:pan` is
kind `pii`. An unnamed kind gets the default, and the default is closed. A
transport that masked by default would fail open on every kind nobody thought
about.

An unreadable value is a usage error, not a fallback: an operator who typed
`mask` is told, rather than quietly given `block`. An unrecognised key inside
`on_egress_finding` is refused for the same reason — `bykind:` would have read
like "mask PII" and meant "block everything".

**3. One blocking kind blocks the whole message.** Masking the maskable half of a
response would forward the unmaskable half alongside it.

**4. The token is fixed: `[REDACTED:<kind>]`.** It carries the kind and nothing
else — not the length, not the shape, not a fragment. Explicitly out of scope,
and this is the anti-scope of this ADR: reversible tokenisation (an encoding is
not a redaction), format-preserving masking (preserving the shape leaks the
shape), and partial reveals like `••••4242` (four digits are four digits).

**5. A masked forward is a normal result.** In MCP it is a `CallToolResult`
without `isError`: the host's tool call *succeeded*, and the regions it may not
see read `[REDACTED:pii]`. `_meta` carries the machine-readable annotation — what
was masked, at which offsets, under which chain record. The token is the in-band
annotation an agent reads; `_meta` is the one a program reads. A refusal that
cannot be masked stays what ADR 0005 made it: an `isError` result for a
`tools/call`, a JSON-RPC error for a method with no `isError` affordance.

**6. The chain still records a `Deny`.** Content left the process, so the
strongest thing an audit can be given is the truth: the pipeline refused, and the
transport masked. The record's `mcp.action` reads `redact`, and its
`mcp.redaction` names the kinds, the offsets and the tokens. It never carries the
masked text — a decision log that quotes what it hid has not hidden it.

**7. The masking is verified before it is sent, and blocks if it cannot be.**
This is the one piece of real machinery. In MCP the offsets index the *derived*
text (`payload.inspected_content`: the string leaves, in canonical key order,
joined by newlines), while the thing to rewrite is the *payload*. So
`payload.redact_payload` walks the payload in exactly the same order, masks each
leaf's share of each planned region, and rebuilds — restoring the wire's own key
order on the way out. The bridge then re-derives the sanitised payload and
compares it to the plan applied to the flat content. They agree when every masked
region sat inside one string; they disagree if a match straddled two strings, or
if the two walks ever drift apart. A disagreement blocks: an unverified redaction
is not a redaction.

The same fail-closed rule covers the other ways a plan can be unusable — a
refusal that located no span, or a span that does not fit the content. Offsets
that do not describe the content are not clamped, because a clamped mask covers a
region nobody located.

## Consequences

**limes still ships no egress detector, so nothing exercises this out of the
box.** ADR 0003 forbids shipping a detector without an eval corpus and a null
control, and a PII regex that finds a card number in a fixture has measured
nothing. The behaviour is machinery waiting for a detector; the proofs use
doubles that live in `tests/`, and `serve()` takes an `outbound=` parameter so an
embedder — or an end-to-end test — can install their own. When the shipped proxy
is told `on_egress_finding: redact` while its outbound leg is empty, it says so
on stderr at startup: a setting that governs nothing must say so.

**The core did not move.** `tests/unit/test_frontier.py` asserts it against the
v0.1 commit, by bytes, for a named list of core, pipeline and detector files —
and asserts that list is not covered by the transport allowlist, so the ratchet
cannot be defeated by widening the allowlist. Six mutations were each seen red
(touch the core; widen the allowlist over it; land a file outside the perimeter;
import the SDK from the core; change code in a prose-only file; name a path that
does not exist).

**One deviation from the task description, recorded rather than glossed:** it
asked for this ADR to be numbered 0008. The repository's decision records run
0001–0005 with no gaps, and 0006 is the next free number; a gap in an ADR
sequence reads as a decision somebody lost. This is 0006. Renumbering later costs
one `git mv` and two links.
