"""The detector plugin contract (ADR 0004).

A detector inspects content on one leg — ``inbound`` (before a tool or LLM sees
it) or ``outbound`` (before a response leaves) — and returns findings. It never
decides the verdict; the core (:mod:`limes.guard`) turns findings into a
:class:`~limes.verdict.Verdict`. A detector that cannot see raises
:class:`DetectorBlind`, which the core turns into ``CannotSay`` — never ``Allow``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from limes.spans import RedactedSpan

__all__ = ["Context", "Detector", "DetectorBlind", "Direction", "Finding"]


class Direction(StrEnum):
    """The leg a detector inspects."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


@dataclass(frozen=True, slots=True)
class Context:
    """The decision context. The actor is asserted by the calling session.

    Attributes:
        policy_hash: SHA-256 of the active policy (recorded into evidence).
        actor: The caller's asserted identity — ``None`` is honest for an
            anonymous session; no default is provided, because a default that
            named someone would be a lie that reads complete (ADR 0002/0024).
        locale: Optional locale hint for the content.
    """

    policy_hash: str
    actor: str | None
    locale: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a detector found.

    Attributes:
        detector_id: The id of the detector that produced this finding.
        label: The rule that fired.
        spans: Redacted spans of the match (never the raw payload).
        severity: Informational severity label.
    """

    detector_id: str
    label: str
    spans: tuple[RedactedSpan, ...]
    severity: str = "high"


class DetectorBlind(Exception):
    """Raised by a detector that cannot see — the core turns it into ``CannotSay``.

    A dependency is absent, the content is unreadable, a timeout fired: the
    detector did not observe, so it must not let its silence read as "clean".
    """


@runtime_checkable
class Detector(Protocol):
    """A pluggable content inspector (ADR 0004).

    Implementations declare ``id`` and ``version`` as attributes and implement
    :meth:`inspect`. They are discovered via the ``limes.detectors`` entry-point
    group; the canonical admitted set is the code tuple
    :data:`limes.detectors.ADMITTED`.
    """

    id: str
    version: str

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Inspect ``content`` on ``direction`` and return any findings.

        Raises:
            DetectorBlind: If the detector could not inspect the content.
        """
        ...
