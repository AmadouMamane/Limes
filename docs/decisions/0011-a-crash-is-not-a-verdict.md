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

## Amendment 1 — the SPAN digest is total too (2026-08-31)

"`decide` never raises on any `str`" — the first consequence above — was not
yet true when it was written. The same bare `encode("utf-8")` this ADR removed
from `_content_sha` survived in `spans.redact()`, a few lines of
evidence-building downstream, and the **inbound** leg reaches it with no
unreadability screen in front — by design: an injection is judged on whatever
bytes arrived. So a matched span containing a lone surrogate still crashed the
guard mid-verdict (`UnicodeEncodeError` from `spans.py:47`), on exactly the
input class this ADR declared closed. The crash had not been eliminated; it
had moved. The egress leg never reaches the site — `refuse_unreadable`
renders the content `CannotSay` first — which is why every surrogate pin
beside the egress detectors stayed green over the hole: those witnesses asked
the egress leg and reported on the guard (ADR 0026).

The repair is this ADR's own repair, applied to the second site:
`spans.redact()` encodes with `errors="surrogatepass"`, so the span digest is
total over `str` exactly as the content digest is — byte-identical to strict
UTF-8 on every encodable string, and a found attack keeps its `Deny` with its
evidence intact. `src/limes/spans.py` leaves byte-identity to v0.1 and is
pinned to the sha256 of its post-amendment bytes in
`tests/unit/test_frontier.py`, beside `guard.py`'s pin. The behaviour is held
by `tests/unit/ratchets/test_span_digest_is_total.py`, run and seen RED (both
tests, `UnicodeEncodeError` at `spans.py:47`) before the one-line fix landed.

## Amendment 2 — a detector that crashes is a blind spot (2026-09-06)

`decide` turned `DetectorBlind` into `CannotSay` and let every other exception
escape. A detector that raised anything else — a bug in a validator, a plugin
that failed to import its own dependency lazily, a `RuntimeError` — killed the
proxy session mid-verdict. Closed, since nothing was forwarded; but not a
verdict: nothing was journalled, no blind spot was named, and the host saw its
server disappear. The same reasoning this record applied to the digest applies
to the pipeline: a witness that fell over did not look, and the honest rendering
of "did not look" is `CannotSay`, naming the exception.

`decide` now catches `Exception` from a detector and records it as a blind spot
(`<id> crashed instead of answering (<type>: <message>)`). A finding from another
detector still dominates, as it does for any blind neighbour; `BaseException`
(a keyboard interrupt, an exit) still escapes. `src/limes/guard.py` is re-pinned
to its post-amendment bytes; `tests/unit/ratchets/test_a_crash_is_not_a_verdict.py`
was seen red — `RuntimeError` out of `decide` — before the two-line change.
