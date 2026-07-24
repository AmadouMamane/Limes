"""The Tessera output-guard baseline — the comparison point for ``pii-egress``.

Tessera already masks PII on the way out: ``tessera.guard.redaction`` applies the
five ``pii.redact_patterns`` of its ``guard/policy.yaml`` to the final response,
classifies each hit (``_mask_for``) and replaces it. That function is what
``pii-egress`` has to beat, and "beat" has to mean a number, not a feeling — so
the baseline is reproduced here and run over the *same* corpus, graded by the
*same* grader (ADR 0003).

**Copied, never imported.** limes does not depend on Tessera; the dependency runs
one way and one way only (ADR 0004). The patterns below are transcribed verbatim
from Tessera ``src/tessera/guard/policy.yaml`` §``pii.redact_patterns``, and the
classification reproduces ``_mask_for`` from ``src/tessera/guard/redaction.py``,
both at Tessera tree ``823b0c71`` (read 2026-07-24).

Two properties of the original are reproduced deliberately, because they are what
the comparison is *about*:

* there is **no checksum anywhere** — a sixteen-digit order reference classifies
  as ``pan`` and gets masked;
* an unclassified hit is masked as generic ``pii`` when it is digit-heavy
  (``>= 8`` digits) and left alone otherwise, which is how the original keeps its
  broad IBAN shape from mangling prose.

The span reported is the match with surrounding whitespace stripped, which is the
region the original actually replaces (it preserves the lead and trail).
"""

from __future__ import annotations

import re
from typing import Final

from limes.detector import Context, Direction, Finding
from limes.spans import redact

__all__ = ["TesseraPiiBaseline"]

#: Transcribed verbatim from Tessera guard/policy.yaml §pii.redact_patterns
#: (tree 823b0c71): e-mail, IBAN shape, PAN shape, French phone, German phone.
_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"(?i)[A-Z]{2}[0-9]{2}[A-Z0-9 ]{11,30}"),
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    re.compile(r"\b(?:\+33|0)[1-9](?:[ .-]?[0-9]{2}){4}\b"),
    re.compile(r"\b(?:\+49|0)[1-9][0-9]{1,4}[ /-]?[0-9]{3,10}\b"),
)

_IBAN_COMPACT: Final = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$")
_SEPARATORS: Final = re.compile("[ \\xa0./-]")
_NON_DIGIT: Final = re.compile(r"\D")

#: Below this many digits, an unclassified hit is a prose graze, not data.
_GENERIC_MIN_DIGITS: Final = 8
_PAN_DIGITS: Final = (13, 19)
_PHONE_DIGITS: Final = (9, 13)


def _kind_for(matched: str) -> str | None:
    """Classify one pattern hit, reproducing Tessera's ``_mask_for``.

    Args:
        matched: The matched text, already stripped.

    Returns:
        The kind Tessera would mask it as, or ``None`` for a hit it leaves
        untouched (a prose false positive of the broad IBAN shape).
    """
    if "@" in matched:
        return "email"
    compact = _SEPARATORS.sub("", matched)
    if _IBAN_COMPACT.fullmatch(compact):
        return "iban"
    digits = _NON_DIGIT.sub("", matched)
    if compact.removeprefix("+").isdigit():
        phone_min, phone_max = _PHONE_DIGITS
        if matched.lstrip().startswith(("+", "0")) and phone_min <= len(digits) <= phone_max:
            return "phone"
        pan_min, pan_max = _PAN_DIGITS
        if pan_min <= len(digits) <= pan_max:
            return "pan"
    if len(digits) >= _GENERIC_MIN_DIGITS:
        return "generic"
    return None


class TesseraPiiBaseline:
    """Outbound PII detection as Tessera's ``apply_output_guard`` performs it."""

    id = "tessera-pii-baseline"
    version = "tessera-823b0c71"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return one finding per hit Tessera's output guard would have masked.

        Args:
            direction: Only ``OUTBOUND`` is inspected; Tessera's output guard has
                no inbound leg of this kind.
            content: The outbound content.
            ctx: Unused.

        Returns:
            A finding per classified hit, spanning the region Tessera replaces.
        """
        del ctx
        if direction is not Direction.OUTBOUND:
            return []
        findings: list[Finding] = []
        for pattern in _PATTERNS:
            for match in pattern.finditer(content):
                raw = match.group(0)
                stripped = raw.strip()
                kind = _kind_for(stripped)
                if kind is None:
                    continue
                start = match.start() + (len(raw) - len(raw.lstrip()))
                label = f"pii:{kind}"
                findings.append(
                    Finding(
                        detector_id=self.id,
                        label=label,
                        spans=(redact(content, start, start + len(stripped), label),),
                    )
                )
        return findings
