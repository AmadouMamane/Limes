# 13. A classifier layer for inbound injection enters by the same gate, or not at all

Date: 2026-08-28

## Status

Accepted as a **frame**: it authorises the attempt and fixes its rules. The
detector itself ships only if its measurement earns admission (ADR 0003) — an
outcome this ADR deliberately does not presume.

## Context

The rule-based `injection` detector blocks 25/33 corpus attacks at 0/8 benign
killed, and the 8 residual misses are documented in the README: social
coercion with no injection syntax, adversarial rewording. That is the class a
pattern cannot see and a trained classifier can. In 2026 the layered shape —
deterministic rules as the always-on floor, a small specialised classifier
above them, an LLM judge only on escalation — is the state of the art for
inbound injection defence; rules alone are the honest floor, not the ceiling.

Two standing constraints make this an ADR rather than a feature branch:

1. **`pip install limes` stays at one dependency.** A model runtime (torch +
   transformers, hundreds of megabytes) can never be a core dependency; the
   MCP SDK set the precedent as an extra (ADR 0004 frontier, `limes[mcp]`).
2. **No capability without its eval** (ADR 0003). "An ML layer would catch
   more" is exactly the kind of claim this project refuses to ship unmeasured.
   The README's Rebuff entry has said since v0.1: *an LLM layer is out of
   scope until it is measured.* This ADR is the measurement plan.

## Decision

- **Extra `limes[ml]`**, never core: `transformers` + `torch`, versions
  pinned. The model is **pinned by name and revision** —
  `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0, ungated,
  ~86M-class DeBERTa) — because an unpinned model is an unpinned policy.
- **Detector `injection-ml`**, inbound leg, same `Detector` protocol. With the
  extra absent or the model unloadable it raises `DetectorBlind` — dependency
  absent is a blind spot to publish, never a silent pass (the CannotSay rule
  the README already states). A classifier names no offsets, so its finding
  spans the **whole content** and its label says so (`injection:ml`); the
  grader must therefore hold it to `flagged` with the span stated as total,
  not pretend a located span it cannot have.
- **Admission on the existing corpus** — the same 33 attacks and 8 benign
  inputs the rules were measured on, plus the null control. The numbers that
  decide: how many of the **8 documented residual misses** it converts, at
  what benign cost, at what latency. A classifier that catches nothing the
  rules miss, or that starts killing benign traffic, is **not admitted**, and
  the measurement is published either way.
- **The gate must keep running without the model.** The admission enforcer
  learns one honest branch: an ADMITTED detector whose extra is not installed
  is measured from its **committed, dated matrix** and the pinned model
  identity — never skipped silently, never simulated. Regenerating the matrix
  (`make eval-ml`) requires the extra and the pinned revision.
- Rules stay the floor: `injection-ml` runs **after** the rule detector, and a
  rule `Deny` never waits on the model.

## Consequences

- The dependency frontier test gains the same assertion `mcp` has: `torch`
  and `transformers` never appear in core dependencies.
- If admitted, the README gains a fourth detector with its own two numbers
  and its latency, stated next to the rules' 0.6 ms so nobody mistakes the
  layers. If refused, the README states the refusal and its numbers — a
  measured "not yet" is a result, not a failure.
- The eval corpus keeps its role as the single arbiter: growing it
  adversarially (ADR 0003) sharpens both layers at once.
