"""The detector plugin contract (ADR 0004).

A detector inspects content on one leg — ``inbound`` (before a tool or LLM sees
it) or ``outbound`` (before a response leaves) — and returns findings. It never
decides the verdict; the core (:mod:`limes.guard`) turns findings into a
:class:`~limes.verdict.Verdict`. A detector that cannot see raises
:class:`DetectorBlind`, which the core turns into ``CannotSay`` — never ``Allow``.

A detector may also *name the legs it reads* (:class:`DeclaresDirections`, ADR
0027). The core asks it only there and counts it as a witness only there: a
detector that answers ``[]`` on a leg it never reads is not somebody who looked
and found nothing, and evidence that listed it as one would overstate who looked.

And a declared limit names its *family* (ADR 0029): ``DetectorBlind`` carries a
:class:`~limes.verdict.BlindKind` — over budget, an encoding, an opaque payload,
another script — so that the operator who accepts one family of limit knowingly
has not accepted them all. A detector that names none has said ``UNSPECIFIED``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from limes.spans import RedactedSpan
from limes.verdict import BlindKind

__all__ = [
    "Context",
    "DeclaresDirections",
    "Detector",
    "DetectorBlind",
    "Direction",
    "Finding",
]


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
        locale: Optional locale hint for the content. A word-reading detector
            whose policy declares the languages its rules cover compares the
            hint against them, and declares itself blind on a language it does
            not read (ADR 0028). ``None`` says nothing, and nothing is inferred.
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

    A dependency is absent, the content is unreadable, over budget, in a script
    or language the rules do not read: the detector did not observe, so it must
    not let its silence read as "clean". Raising this is a *declared* limit, and
    the core records it as one (``BlindCause.DECLARED``, ADR 0026). Any other
    exception out of :meth:`Detector.inspect` is a *fault*: also a blind spot,
    never a pass, but one no setting may open.

    The limit names its family (ADR 0029): ``DetectorBlind("...", kind=BlindKind.BUDGET)``.
    The core seals it into the verdict, and the transport policy opens declared
    limits a family at a time. A detector that names none has declared
    ``BlindKind.UNSPECIFIED`` — a family of its own, which an operator opens
    knowingly or not at all — rather than borrowed a family it did not measure.

    Attributes:
        kind: The family of this limit.
    """

    def __init__(self, message: str, *, kind: BlindKind | None = None) -> None:
        super().__init__(message)
        # ``BlindKind(kind)`` is the identity on a member and the conversion on
        # its string value; an unknown name raises ``ValueError`` out of the
        # detector, which the core then renders as a FAULT — a detector naming a
        # family that does not exist is a bug, not a limit.
        self.kind: BlindKind = BlindKind.UNSPECIFIED if kind is None else BlindKind(kind)


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


@runtime_checkable
class DeclaresDirections(Protocol):
    """A detector that names the legs it reads (ADR 0027).

    Optional, and read by the core: a detector declaring ``directions`` is asked
    only on those legs and is a witness only there. A detector that declares
    nothing is asked on every leg, exactly as every v0.1 detector was, and its
    ``[]`` on a leg it does not read is taken at its word — it looked and found
    nothing. Every admitted detector declares; a ratchet holds it to that.
    """

    directions: frozenset[Direction]
