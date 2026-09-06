# 25. The chain seals the disposition, and the witness names its build

Date: 2026-09-06

## Status

Accepted. Amends ADR 0004's frontier for one core file (`src/limes/record.py`)
by the mechanism ADR 0011 established, and changes what every shipped detector
reports as its version. Every digest ever produced changes; nothing was published
before this record, so no chain in the field is invalidated.

## Context

Two things the evidence could not say, found by reading what a record actually
seals.

**A record proved a refusal and not what followed it.** The hashed core of a
`DecisionRecord` was `{seq, direction, actor, verdict, prev_hash}`. Under a
redacting egress policy the verdict is a `Deny` whether the response then left
masked or did not leave at all; the difference — the thing a deployment actually
did — travelled in the proxy's `mcp.action` annotation, which is outside the
digest, and for the in-process guard it travelled nowhere. An auditor holding a
chain could prove that content was refused and could not prove whether it left.

**Every witness said "0.1.0".** Each detector carried a hand-maintained
`version = "0.1.0"`, and it never moved: not for the three override families
added to `injection`, not for `value_group` and `not_pure_hex`, not for the PEM
material floor or the Slack grammar. The `Witness` in every piece of evidence
named a detector that no longer existed. The policy hash covers the YAML; it
does not cover `checksums.py` or `egress_scan.py`, which is where half of those
changes live.

## Decision

**1. The record seals a `disposition`.** The hashed core becomes
`{seq, direction, actor, disposition, verdict, prev_hash}`, where `disposition`
is `"forward"`, `"redact"`, `"block"`, or `null` when the recording transport
takes no disposition of its own. A record cannot then claim a response was
blocked when it left, without breaking every later link.

Who writes it: the MCP relay seals the action it took on every decision, on both
legs and both transports; the in-process `check_egress` seals `forward`,
`redact` or `block`; the in-process `check` and the CLI seal `null`, because a
caller who receives a bare verdict decides what to do with it and the ledger
does not guess, and because `limes check`'s exit code *is* its verdict.

To make that possible the in-process guard exposes the two halves `check` was
made of: `Guard.verdict()` decides without recording, `Guard.record()` seals a
verdict with a disposition. A transport decides, disposes, then records — so the
masked forward that fails its re-derivation check and falls back to a block is
sealed as the block it became, not the redaction it was going to be.

**2. A detector's version is the package's.** Every admitted detector reports
`limes.__version__` — the string `limes --version` prints, read from the
installed distribution's metadata (ADR 0014). The witness in a verdict then
names a build an auditor can reinstall, with exactly the rules and the code that
produced it. A hand-maintained version was a number nobody moved; this one moves
with every release, which is what a version is for.

## Consequences

- `src/limes/record.py` leaves byte-identity to v0.1 and is pinned to the sha256
  of its post-ADR bytes; the ratchet's strength is intact.
- The proxy's JSONL gains a `disposition` field beside `mcp.action`; the two
  agree, and a test says so. `mcp.action` stays, as the annotation it always
  was.
- `limes check --json` prints `"disposition": null` under `record`.
- `docs/audit-trail.md` describes seven fields, not six.
- A chain written by 0.12.0 or earlier does not verify under 0.13.0, because the
  canonical core changed. No such chain exists outside this repository's own
  tests.
- `Witness.detector_version` reads `0.13.0` from an installed 0.13.0 and
  `0+unknown` from a bare source tree, which is ADR 0014's rule for the package
  itself and is exactly as honest here.
