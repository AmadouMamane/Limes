"""The scan both egress detectors share: shape → check → exact span.

One loop, written once, because ``pii-egress`` and ``secrets-egress`` differ only
in the rules they are handed (ADR 0004: a feature is a detector, not an edit to
anything else). Three properties are worth naming, because each is load-bearing
somewhere else in the system:

**The span is the validated value, exactly.** Not the sentence, not the line, not
the greedy match that failed its check — the substring that actually passed. The
transport masks by those offsets (ADR 0006) and the eval grades by them
(:mod:`limes.eval.egress_harness`), so a detector that reported a span it did not
verify would hand the masker the wrong bytes *and* score a true positive for it.

**A failing candidate may only be shortened.** ``retry_trim`` drops the trailing
group and re-checks; it never widens, never relaxes the validator, and never
reports a candidate that did not pass. It exists because a greedy shape swallows
the word after an IBAN, and losing a real account number to a stray ``EUR`` is a
false negative nobody would find by reading the regex.

**A detector that cannot read the content says so.** Two blind spots, both
raised as :class:`~limes.detector.DetectorBlind` — which the core turns into
``CannotSay``, which the egress leg turns into *block*. Never a quiet "nothing
found":

* **over budget** — beyond the ``max_content_chars`` its policy declares, the
  detector does not sweep. An unbounded regex pass with a trimming retry over an
  unbounded tool result is a denial-of-service surface, and "I stopped looking"
  has to be sayable, auditable and closed rather than silent.
* **unencodable** — content carrying unpaired surrogates cannot be encoded to
  UTF-8, so it is not the bytes that will leave the process. Found by this
  work: the core used to hash the content *after* running the detectors and
  raised ``UnicodeEncodeError`` before it could render this blind spot as
  ``CannotSay`` — a crash, not a verdict. Not fixable from a detector (ADR 0004
  forbids the edit), it stayed pinned as debt until ADR 0011 made the core's
  digest total: :func:`limes.guard.decide` now renders the refusal as
  ``CannotSay``, which the egress leg turns into *block*.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from typing import Final

from limes.detector import DetectorBlind, Finding
from limes.detectors.egress_policy import EgressRule
from limes.spans import redact

__all__ = ["refuse_unreadable", "scan"]

#: One trailing group and the separator that introduced it — what ``retry_trim``
#: removes. Anchored right, so trimming can only ever shorten the candidate.
_TRAILING_GROUP: Final = re.compile(r"[ \xa0.\-/]+[A-Za-z0-9]+$")


def refuse_unreadable(content: str, *, detector_id: str, budget: int) -> None:
    """Raise :class:`~limes.detector.DetectorBlind` if ``content`` is unscannable.

    Args:
        content: The content about to be inspected.
        detector_id: The detector's id, named in the blind spot.
        budget: The declared ``max_content_chars`` for this detector.

    Raises:
        DetectorBlind: If the content is longer than ``budget``, or cannot be
            encoded to UTF-8 — in either case the detector did not observe, and
            its silence must not read as "clean".
    """
    if len(content) > budget:
        raise DetectorBlind(
            f"{detector_id} did not scan {len(content)} characters of outbound content: its "
            f"declared budget is {budget} (max_content_chars). It is refusing to answer, not "
            f"answering that the content is clean"
        )
    try:
        content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DetectorBlind(
            f"{detector_id} cannot scan content that does not encode to UTF-8 "
            f"({exc.reason} at offset {exc.start}); it would be guessing about the "
            f"bytes that actually leave"
        ) from exc


def _candidates(matched: str, *, retry_trim: bool) -> Iterator[str]:
    """Yield the matched text, then its progressively trimmed prefixes."""
    yield matched
    if not retry_trim:
        return
    current = matched
    while True:
        trimmed = _TRAILING_GROUP.sub("", current)
        if trimmed == current or not trimmed:
            return
        current = trimmed
        yield current


def _validated(matched: str, rule: EgressRule) -> str | None:
    """Return the longest prefix of ``matched`` that passes ``rule``'s check."""
    check = rule.check
    for candidate in _candidates(matched, retry_trim=rule.retry_trim):
        if check(candidate):
            return candidate
    return None


def scan(content: str, rules: Sequence[EgressRule], *, detector_id: str) -> list[Finding]:
    """Return one finding per validated match of ``rules`` over ``content``.

    Args:
        content: The outbound content to inspect.
        rules: The rules this detector owns, in declaration order.
        detector_id: The detector's id, carried in every finding.

    Returns:
        A finding per match that passed its rule's validator, each carrying a
        redacted span over exactly the validated substring.
    """
    findings: list[Finding] = []
    for rule in rules:
        for match in rule.pattern.finditer(content):
            validated = _validated(match.group(0), rule)
            if validated is None:
                continue
            start = match.start()
            end = start + len(validated)
            findings.append(
                Finding(
                    detector_id=detector_id,
                    label=rule.label,
                    spans=(redact(content, start, end, rule.label),),
                )
            )
    return findings
