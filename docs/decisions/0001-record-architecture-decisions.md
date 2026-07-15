# 1. Record architecture decisions

Date: 2026-07-15

## Status

Accepted.

## Context

limes is founded as a separate package extracted from Tessera's first-party
guard (Tessera ADR 0028, "The firewall that never ran"). Its value is a small
set of load-bearing decisions — what a verdict is, what a detector must prove
before it ships, and why the core never grows. Those decisions must be legible
to someone who has never read the code, and they must be hard to reverse by
accident.

## Decision

We record every architecture-shaping decision as an Architecture Decision
Record (ADR), in the style of Michael Nygard, as a numbered Markdown file under
`docs/decisions/`. An ADR has: a title, a date, a status
(Proposed / Accepted / Superseded), the context that forced the decision, the
decision itself, and its consequences.

A change that deviates from an accepted ADR does not proceed silently: it either
respects the ADR or it opens a new one that supersedes it, in the same change
that makes the deviation.

## Consequences

- The founding contract is four ADRs, written before the first line of code:
  0002 (a verdict carries its evidence), 0003 (no detector without eval cases
  and a null control), 0004 (core / detectors / transports; the core never
  grows). This file is 0001.
- The record is the source of truth for structure. `README.md` may summarise;
  it may not contradict an accepted ADR.
