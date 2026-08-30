# 19. One override family, on both legs

Date: 2026-08-30

## Status

Accepted. Amends ADR 0004's frontier for one file
(`src/limes/detectors/policy.yaml`), by the mechanism ADR 0011 established.

## Context

ADR 0017 bought a number the author did not choose, and the first thing it bought
was an embarrassment: on garak's PromptInject family — goal hijacking by a rogue
string appended to a task, the *canonical inbound attack* — the inbound
`injection` detector scored

```
0 / 131
```

while the outbound `injection-egress` detector, carrying the three rule families
added the same day, scored **107 / 131** on the same texts.

Two legs of one guard disagreeing that completely about what an override looks
like is not a calibration difference. One of them was simply out of date: the
inbound rules were the Tessera port plus three case-08 additions, and the
override family had been generalised on the other side only.

The internal corpus could not have found this. It moved by **one case** — 25/33
to 26/33 — while the external blind measure went from **0 % to 82 %**. A corpus
written by the author of the rules covers what the author thought of; that is
exactly the limit ADR 0017 exists to work around, and this is the first time the
two measurements have disagreed loudly enough to prove it.

## Decision

**The two legs carry the same override family.** The three shapes admitted to the
outbound leg — `override-and-substitute`, `injected-dialogue-turn`,
`session-boundary-marker` — are ported **verbatim** to the inbound policy, with
`origin: limes`.

Verbatim matters. They were not re-derived, re-tuned, or adjusted for the inbound
leg, and no hijack prompt was read while porting them. The only thing the blind
corpus contributed was a single aggregate observation — *this leg scores zero* —
which is enough to decide to act and carries nothing about what to write. The
inbound number obtained afterwards is therefore **not blind**, and the matrix
labels it so.

`origin: limes` is the policy file's own extension point (`origin: tessera` marks
the verbatim Tessera port, and the Tessera-regex baseline reads only those). So
the baseline is untouched by construction, and the delta between baseline and
detector stays data rather than a second policy file — which is what that field
was designed for.

**The frontier keeps its ratchet, with one named amendment.**
`src/limes/detectors/policy.yaml` leaves byte-identity to v0.1 and is pinned in
`AMENDED` to the sha256 of its post-ADR bytes, beside a reference to this record.

## Consequences

- `injection` on garak's blind hijack family: **0/131 → 107/131**. Zero false
  positives over the 192 matched benign documents, and still 0/8 on the internal
  benign corpus, so the no-regression claim against the Tessera baseline holds.
- Internal matrix: 25/33 → 26/33 attacks blocked, recall 0.76 → 0.79, benign
  killed unchanged at 0/8.
- The Tessera-regex baseline is unchanged — it reads `origin: tessera` only — so
  the published gap between the two remains a measurement of the same thing it
  measured before.
- The precision cost the outbound leg paid is now paid on both legs: the four
  named lookalikes in `injection_benign.json`, three of them mention-versus-use
  and one a support transcript. That is published, not rounded away (ADR 0003).
- A rule family added to one leg from now on is a question about the other. There
  is no mechanism enforcing that, and this ADR is not pretending otherwise; what
  there is, is a measurement that will say so within one `make eval`.
