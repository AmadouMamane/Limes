"""Redacted spans — evidence of *what matched*, never the raw payload.

A guard that logs the attack it caught leaks the attack. Evidence therefore
carries the *location* and a *hash* of a match, not its text: enough to prove
what fired and to confirm it on replay, nothing an auditor could read the
payload back out of.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = ["RedactedSpan", "redact"]


@dataclass(frozen=True, slots=True)
class RedactedSpan:
    """A matched region of inspected content, carried in evidence without the content.

    Attributes:
        start: Start offset of the match in the inspected content.
        end: End offset (exclusive) of the match.
        label: The rule that fired, e.g. ``"injection:embedded-system-directive"``.
        matched_sha: SHA-256 of the matched substring — proves *what* matched
            (and lets a replay confirm it) without storing the raw payload.
    """

    start: int
    end: int
    label: str
    matched_sha: str


def redact(content: str, start: int, end: int, label: str) -> RedactedSpan:
    """Build a :class:`RedactedSpan` for ``content[start:end]`` under ``label``.

    Args:
        content: The full inspected content.
        start: Start offset of the match.
        end: End offset (exclusive) of the match.
        label: The rule that fired.

    Returns:
        A span carrying offsets, the label, and a SHA-256 of the matched text.
    """
    fragment = content[start:end].encode("utf-8")
    return RedactedSpan(
        start=start,
        end=end,
        label=label,
        matched_sha=hashlib.sha256(fragment).hexdigest(),
    )
