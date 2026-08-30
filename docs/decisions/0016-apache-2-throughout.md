# 16. Apache-2.0 throughout: ADR 0004's licence lean is settled

Date: 2026-08-30

## Status

Accepted. Settles the section of ADR 0004 titled "Licence (the lean; ratification
is Amadou's, before any publication)". ADR 0004 is not edited: per ADR 0001, a
decision that moves opens a new record rather than rewriting the old one, so
0004 stays the dated statement of the lean and this is where the decision lives.

## Context

ADR 0004 stated a founding *lean*, and said in its own heading that it was not a
ratification: engine under Apache-2.0, detection corpus and calibration under a
separate closed data licence, the split to be settled "before any publication".

Publication is now the thing happening. That converts the lean into a question
that must have exactly one answer, because a distribution declares its licence
**once**, in metadata, for everything inside it. The wheel ships
`src/limes/corpus/**`. So "engine Apache-2.0, corpus closed" is not something the
packaging can express about *this* artifact: either the corpus in the wheel is
Apache-2.0, or the wheel is mislabelled.

What is actually in the repository answers it, and has all along:

- `LICENSE` is the Apache-2.0 text, Copyright 2026 Amadou Mamane.
- `src/limes/corpus/PROVENANCE.md` records that the default corpus was **copied**
  from Tessera's own Apache-2.0 repository, with the tree it came from and the
  date.
- The curated / calibrated / EU corpus is **not in this repository** and never
  has been. ADR 0009 keeps the egress corpus synthetic; ADR 0010 keeps even
  vendor-key vectors stored as fragments. Nothing proprietary was ever checked
  in to be encumbered.

So the lean's two halves were never in tension here. One of them simply describes
an artifact that does not exist yet.

## Decision

**Everything in this repository, and everything in the published distribution, is
Apache-2.0** — the engine (core, plugin interface, transports, CLI) and the
default detection corpus it ships.

- The separate data licence of ADR 0004's lean applies to an artifact that is
  **not here**. If a curated corpus is ever published, it ships as its own
  distribution, under its own licence, with its own ADR. It does not
  retroactively encumber anything released under this one, and no release made
  under this ADR can be walked back by a later decision about a different
  artifact.
- **The licence is declared once.** `pyproject.toml` carries the PEP 639
  expression `license = "Apache-2.0"` and no `License :: OSI Approved ::`
  classifier: PEP 639 makes the two mutually exclusive, and — the reason that
  matters here rather than the rule — a licence stated twice in two vocabularies
  is a licence that can drift, with nothing to say which half is authoritative.
- **The CLA stays.** `CLA.md` keeps a future dual-licence option open for code
  contributed by others; settling *this* record does not spend it. What it does
  is remove the pretence that the option is still open for what has already
  shipped.

## Consequences

- `pip install limes` gives one licence, stated once, and that statement matches
  `LICENSE`, the README's *License* section, and `PROVENANCE.md`.
- The published metadata carries `License-Expression: Apache-2.0` and a
  `License-File`, with no licence classifier.
- ADR 0004's licence section is now read as history: a lean, dated, and
  superseded on this point only. Its architectural decision — three layers, and
  the core never grows — is untouched and remains in force, as amended by ADR
  0011, ADR 0014 and ADR 0015.
