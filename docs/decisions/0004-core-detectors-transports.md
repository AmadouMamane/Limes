# 4. Core, detectors, transports — and the core never grows

Date: 2026-07-15

## Status

Accepted.

## Context

A guard accretes features until its core is unauditable and every change risks
the decision path. The discipline that prevents that is structural, not
aspirational: the shape of the codebase must make "add a feature" mean
"add a plugin", never "edit the core".

## Decision

**Three layers.**

1. A **transport-agnostic decision core** (target: a few hundred lines) — the
   `Verdict` algebra, `Evidence`, the `DecisionRecord` chain, the pipeline that
   turns detector findings into a verdict. No I/O, no transport, no wall clock.
2. **Detectors as plugins**, behind one Protocol, discovered by entry point:

   ```python
   class Detector(Protocol):
       id: str
       version: str
       def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]: ...
   ```

   Two legs: `inbound` (before the tool or LLM sees the content) and `outbound`
   (before a response leaves). v0.1 ships one detector, `injection` (inbound).
3. **Transports as adapters.** v0.1 is **in-process only** — a `guard()` call
   plus a decorator / context manager. The MCP stdio proxy is v0.2 (the adoption
   wedge: any MCP host puts limes between itself and its servers without adopting
   Tessera), and it becomes a transport *because that path actually speaks MCP* —
   not because of a name (the mistake Tessera ADR 0028 dissects). HTTP is later,
   with no anticipatory skeleton.

**The core never grows.** A new capability is a detector, a policy, or a
transport — never an edit to the core. The ~200-feature roadmap lands entirely
in those three buckets; none touches the core. A request that seems to need a
core edit is either mis-scoped or it is a new ADR that supersedes this one — it
is never a quiet growth of the core.

**Policy in YAML**, versioned, and hashed into every `Evidence`. No rule is ever
hardcoded in Python; an auditor reads the policy without reading Python.

## Licence (the lean; ratification is Amadou's, before any publication)

Per Tessera ADR 0028 ("what this does not decide"), the split is a separate
decision, but the founding lean is:

- **Engine — core + plugin interface + transports — Apache-2.0.** The adoption
  wedge: a mechanism anyone can implement and embed.
- **Detection corpus + calibration — a separate data licence, kept closed.** The
  edge no fork captures. v0.1 ships a *functional default corpus* (the Tessera
  injection cases, themselves Apache-2.0, copied with provenance) so the library
  works out of the box; the curated / calibrated / EU corpus stays proprietary
  and is **not** in this repository. No external contribution is merged without a
  CLA in place first — without it, the dual-licence option dies the day one
  external patch lands.

## Consequences

- A feature request is answered by naming its layer. The core's line count is a
  reviewable invariant, not a hope.
- Detectors are independently testable and independently admissible (ADR 0003).
  The in-process transport and a future MCP transport exercise the *same* core,
  so "it guards an in-process agent today, any MCP host tomorrow" is one code
  path, measured once.
