# 11. A crash is not a verdict: the content digest is total

Date: 2026-08-28

## Status

Accepted. Amends ADR 0004's frontier for exactly one file (`src/limes/guard.py`)
and closes the debt pinned since v0.5 by
`tests/unit/egress/test_pii_detector.py`.

## Context

`limes.guard.decide` hashes the content into the verdict's evidence *after*
running the detectors: `sha256(content.encode("utf-8"))`. A Python `str`
carrying unpaired surrogates cannot be encoded to UTF-8, so on such input the
core raises `UnicodeEncodeError` before it can return anything at all.

The detector layer already answers this input correctly: `refuse_unreadable`
raises `DetectorBlind` ("I would be guessing about the bytes that actually
leave"), which the core turns into `CannotSay`, which the egress leg turns into
*block*. The crash sits **downstream** of that correct answer and destroys it —
the caller gets a stack trace where the architecture promised a verdict. It
fails loudly, never open (nothing is forwarded), but a crash is unfalsifiable
where a `CannotSay` is auditable: it names no blind spot, carries no evidence,
and cannot be journalled by a transport.

Fixing it means editing `guard.py`, which is in the frontier ratchet's `CORE` —
byte-identical to v0.1 by `tests/unit/test_frontier.py`, and ADR 0004 forbids
the edit from a detector. That prohibition is the reason the debt stayed open
from v0.5 to v0.6: it was the correct refusal of an *unauthorised* core edit,
not a judgement that the crash was acceptable. This ADR is the authorisation.

## Decision

**The content digest becomes total over `str`.** `_content_sha` encodes with
`errors="surrogatepass"`:

- for every string that encodes to UTF-8 — every payload that can actually
  cross a transport — the bytes, and therefore the digest, are **unchanged**;
- for a string carrying unpaired surrogates, `surrogatepass` produces the
  CESU-8-style byte form of each surrogate, so the digest exists, is
  deterministic, and remains injective over `str` (the encoding is reversible).

No control flow in `decide` changes. The already-correct aggregation now runs to
completion: a blind detector renders `CannotSay` naming its blind spot; a
detector that *did* find something on such input keeps its `Deny` (a found
attack dominates — the aggregation rule is preserved, where catching the
exception and short-circuiting to `CannotSay` would have demoted it).

**The frontier stays a ratchet, with one named amendment.** `guard.py` leaves
byte-identity-to-v0.1 and is pinned instead, in `tests/unit/test_frontier.py`,
to the **sha256 of its post-ADR bytes**, recorded next to a reference to this
ADR. Any further drift of the file is red, exactly as before; what changed is
the reference bytes, once, with its authorisation written down. Every other
`CORE` entry remains pinned to v0.1.

## Consequences

- `decide` never raises on any `str`: unencodable content yields `CannotSay →
  BLOCK` on the egress leg, with the blind spot named by the detector that
  refused to guess.
- With zero detectors wired, unencodable content follows the same semantics as
  any other content with zero detectors (an `Allow` whose evidence names every
  detector that ran: none). Scannability is the detectors' concern, and both
  egress detectors refuse it; the core does not invent a witness.
- Digests already recorded in any ledger are unaffected: `surrogatepass` is
  byte-identical to strict UTF-8 on every encodable string.
- The pin tests that documented the crash now document the verdict, in the same
  file, so nobody has to rediscover either state.
- The README's "one honest limit found by this work" paragraph is rewritten as
  a closed one.
