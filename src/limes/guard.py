"""The transport-agnostic decision core: detectors -> Verdict (ADR 0002/0004).

This is the whole decision, and it is pure: no I/O, no transport, no wall clock.
It runs each detector, aggregates findings, and returns exactly one verdict:

* any finding -> ``Deny`` (a found attack dominates, even if another detector was
  blind);
* else any blind spot -> ``CannotSay``, naming its cause (ADR 0026): a *fault* if
  any detector fell over, otherwise a *declared* limit — a detector's, the
  caller's, or the leg's;
* else -> ``Allow``, whose evidence names every detector that ran.

A detector that *crashes* — raises anything other than :class:`DetectorBlind` —
is a detector that did not observe, and it is rendered the same way: a blind
spot naming the exception, never a traceback out of the guard and never a pass
(ADR 0011 Amendment 2). A crash is not a verdict, and a guard that dies takes
the session it was guarding down with it. What ADR 0026 adds is that the crash
is a blind spot of a different *cause* than a declared budget: the transport's
``on_cannot_say: allow`` opens the declared kind and never a fault.

Two more things the core says rather than lets pass (ADR 0027):

* a detector that names its legs (:class:`~limes.detector.DeclaresDirections`)
  is only asked on them, and is a witness only there;
* a leg nobody reads answers ``CannotSay`` — "nobody looked" — never an
  ``Allow`` whose evidence lists no witness, which is a pass that reads like a
  verdict.

And the caller may declare blind spots of its own (ADR 0028): the parts of a
payload it could derive no text from — an image, an audio clip, a binary
resource — which the transport hands over as ``blind_spots`` and the core
aggregates exactly like a detector's declared limit.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from limes.detector import (
    Context,
    DeclaresDirections,
    Detector,
    DetectorBlind,
    Direction,
    Finding,
)
from limes.spans import RedactedSpan
from limes.verdict import Allow, BlindCause, CannotSay, Deny, Evidence, Verdict, Witness

__all__ = ["decide"]


def _content_sha(content: str) -> str:
    # ``surrogatepass`` makes the digest total over ``str`` (ADR 0011): on every
    # string that encodes to UTF-8 the bytes are identical to strict encoding,
    # and unpaired surrogates get their reversible CESU-8-style form instead of
    # raising before a verdict could be rendered. A crash is not a verdict.
    return hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()


def _reads(detector: Detector, direction: Direction) -> bool:
    """Whether ``detector`` is to be asked about ``direction`` at all (ADR 0027)."""
    if isinstance(detector, DeclaresDirections):
        return direction in detector.directions
    return True


def decide(
    direction: Direction,
    content: str,
    ctx: Context,
    detectors: Sequence[Detector],
    *,
    observed_at: str,
    blind_spots: Sequence[str] = (),
) -> Verdict:
    """Run ``detectors`` over ``content`` and return one verdict.

    Args:
        direction: The leg being inspected.
        content: The content to inspect.
        ctx: The decision context (policy hash, actor, locale).
        detectors: The detectors to run, in order. One that declares its legs
            is skipped on a leg it does not read (ADR 0027).
        observed_at: ISO-8601 timestamp recorded into evidence (caller-supplied,
            never ``now()``, so the chain can re-derive).
        blind_spots: Limits the caller declares about what it handed over — the
            parts of its payload it could derive no text from (ADR 0028). They
            are aggregated like a detector's declared blind spot: a finding
            still dominates them, and otherwise they make the verdict
            ``CannotSay`` with cause ``DECLARED``.

    Returns:
        ``Deny`` if any detector found something; otherwise ``CannotSay`` if any
        detector fell over (cause ``FAULT``), or if any detector, the caller or
        the leg itself declared a blind spot (cause ``DECLARED``); otherwise
        ``Allow``.
    """
    witnesses: list[Witness] = []
    spans: list[RedactedSpan] = []
    labels: list[str] = []
    declared: list[str] = []
    faults: list[str] = []
    asked = 0

    for detector in detectors:
        if not _reads(detector, direction):
            continue
        asked += 1
        try:
            findings: list[Finding] = detector.inspect(direction, content, ctx)
        except DetectorBlind as exc:
            declared.append(f"{detector.id}: {exc}")
            continue
        except Exception as exc:
            # Not a silence to read as "clean", and not a crash to hand the
            # transport: a witness that fell over did not look (ADR 0011 Am. 2).
            faults.append(
                f"{detector.id} crashed instead of answering ({type(exc).__name__}: {exc}); "
                "a detector that did not run is a blind spot, not a pass"
            )
            continue
        witnesses.append(Witness(detector_id=detector.id, detector_version=detector.version))
        for finding in findings:
            spans.extend(finding.spans)
            labels.append(finding.label)

    declared.extend(blind_spots)
    if asked == 0:
        declared.append(
            f"no detector reads the {direction.value} leg: nobody looked, and an Allow with no "
            "witness would be a pass that reads like a verdict"
        )

    content_sha = _content_sha(content)

    if spans:
        evidence = Evidence(
            witnesses=tuple(witnesses),
            policy_hash=ctx.policy_hash,
            content_sha=content_sha,
            matched_spans=tuple(spans),
            observed_at=observed_at,
        )
        reason = f"{len(spans)} rule match(es) on {direction.value} content: " + ", ".join(
            sorted(set(labels))
        )
        return Deny(reason=reason, evidence=evidence)

    if faults:
        # A fault outranks a declared limit: the operator who accepts declared
        # limits (`on_cannot_say: allow`) has not accepted a crashed guard.
        return CannotSay(blind_spot="; ".join([*faults, *declared]), cause=BlindCause.FAULT)
    if declared:
        return CannotSay(blind_spot="; ".join(declared), cause=BlindCause.DECLARED)

    evidence = Evidence(
        witnesses=tuple(witnesses),
        policy_hash=ctx.policy_hash,
        content_sha=content_sha,
        matched_spans=(),
        observed_at=observed_at,
    )
    return Allow(evidence=evidence)
