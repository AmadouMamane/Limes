"""Outbound detector doubles. limes ships **no** egress detector, and these are not one.

They exist because egress redaction is transport machinery: it masks the offsets
a finding hands it, and it is indifferent to which detector produced them. To
prove the machinery, a test needs findings on the outbound leg — so these doubles
manufacture them, with real :class:`~limes.spans.RedactedSpan` offsets over the
real content, and nothing else.

Why they stay in ``tests/`` rather than becoming ``limes.detectors.pii``: ADR 0003
— no detector ships without an eval corpus and a null control. A regex that finds
a card number in a fixture proves nothing about finding one in the wild, and
shipping it would let the README claim a capability that was never measured. The
kinds they emit (``pii``, ``secret``) are the ones an egress policy is *about*,
which is exactly what makes them useful here and inadmissible in ``src/``.
"""

from __future__ import annotations

import re
from typing import Final

from limes.detector import Context, Direction, Finding
from limes.spans import redact

#: Not a PAN validator — a fixed shape, matched over fixture text.
PAN: Final = re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b")
EMAIL: Final = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
API_KEY: Final = re.compile(r"\bsk-live-[A-Za-z0-9]{6,}\b")


class PiiDouble:
    """Locates a card-shaped number and an e-mail address on the outbound leg."""

    id = "pii-double"
    version = "0.0.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return one finding per match, each carrying its offsets."""
        if direction is not Direction.OUTBOUND:
            return []
        found: list[Finding] = []
        for pattern, label in ((PAN, "pii:pan"), (EMAIL, "pii:email")):
            found.extend(
                Finding(
                    detector_id=self.id,
                    label=label,
                    spans=(redact(content, match.start(), match.end(), label),),
                )
                for match in pattern.finditer(content)
            )
        return found


class SecretDouble:
    """Locates an API-key-shaped string on the outbound leg, under kind ``secret``."""

    id = "secret-double"
    version = "0.0.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return one finding per match, each carrying its offsets."""
        if direction is not Direction.OUTBOUND:
            return []
        return [
            Finding(
                detector_id=self.id,
                label="secret:api-key",
                spans=(redact(content, match.start(), match.end(), "secret:api-key"),),
            )
            for match in API_KEY.finditer(content)
        ]


class WholeContentDouble:
    """Fires on a fixed marker, and reports a span that straddles whatever it must.

    Used to reach the paths where the offsets a finding hands the transport are
    not usable as they stand — the transport's answer there is *block*, and that
    answer is worth a test.
    """

    id = "whole-content-double"
    version = "0.0.0"

    def __init__(self, marker: str, label: str, *, stretch: int = 0) -> None:
        """Match ``marker``, reporting a span ``stretch`` characters too long."""
        self._marker = marker
        self._label = label
        self._stretch = stretch

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return one finding over the marker, stretched past the content if asked."""
        if direction is not Direction.OUTBOUND:
            return []
        start = content.find(self._marker)
        if start < 0:
            return []
        end = start + len(self._marker)
        span = redact(content, start, min(end, len(content)), self._label)
        if self._stretch:
            span = type(span)(
                start=span.start,
                end=end + self._stretch,
                label=span.label,
                matched_sha=span.matched_sha,
            )
        return [Finding(detector_id=self.id, label=self._label, spans=(span,))]
