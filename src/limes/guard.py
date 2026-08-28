"""The transport-agnostic decision core: detectors -> Verdict (ADR 0002/0004).

This is the whole decision, and it is pure: no I/O, no transport, no wall clock.
It runs each detector, aggregates findings, and returns exactly one verdict:

* any finding -> ``Deny`` (a found attack dominates, even if another detector was
  blind);
* else any blind detector -> ``CannotSay`` (a witness that could not see may
  never report "ok");
* else -> ``Allow``, whose evidence names every detector that ran.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from limes.detector import Context, Detector, DetectorBlind, Direction, Finding
from limes.spans import RedactedSpan
from limes.verdict import Allow, CannotSay, Deny, Evidence, Verdict, Witness

__all__ = ["decide"]


def _content_sha(content: str) -> str:
    # ``surrogatepass`` makes the digest total over ``str`` (ADR 0011): on every
    # string that encodes to UTF-8 the bytes are identical to strict encoding,
    # and unpaired surrogates get their reversible CESU-8-style form instead of
    # raising before a verdict could be rendered. A crash is not a verdict.
    return hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()


def decide(
    direction: Direction,
    content: str,
    ctx: Context,
    detectors: Sequence[Detector],
    *,
    observed_at: str,
) -> Verdict:
    """Run ``detectors`` over ``content`` and return one verdict.

    Args:
        direction: The leg being inspected.
        content: The content to inspect.
        ctx: The decision context (policy hash, actor, locale).
        detectors: The detectors to run, in order.
        observed_at: ISO-8601 timestamp recorded into evidence (caller-supplied,
            never ``now()``, so the chain can re-derive).

    Returns:
        ``Deny`` if any detector found something, ``CannotSay`` if none found
        anything but at least one was blind, otherwise ``Allow``.
    """
    witnesses: list[Witness] = []
    spans: list[RedactedSpan] = []
    labels: list[str] = []
    blind: list[str] = []

    for detector in detectors:
        try:
            findings: list[Finding] = detector.inspect(direction, content, ctx)
        except DetectorBlind as exc:
            blind.append(f"{detector.id}: {exc}")
            continue
        witnesses.append(Witness(detector_id=detector.id, detector_version=detector.version))
        for finding in findings:
            spans.extend(finding.spans)
            labels.append(finding.label)

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

    if blind:
        return CannotSay(blind_spot="; ".join(blind))

    evidence = Evidence(
        witnesses=tuple(witnesses),
        policy_hash=ctx.policy_hash,
        content_sha=content_sha,
        matched_spans=(),
        observed_at=observed_at,
    )
    return Allow(evidence=evidence)
