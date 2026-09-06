"""The limes verdict algebra — a verdict carries its evidence (ADR 0002).

``Verdict = Allow(evidence) | Deny(reason, evidence) | CannotSay(blind_spot, cause, kinds)``

Three invariants this module makes load-bearing:

* **``Allow`` cannot be constructed without its :class:`Evidence`.** No default,
  no convenience constructor. Enforced at the type level; a ratchet asserts mypy
  rejects ``Allow()`` and goes red the moment ``evidence`` gains a default.
* **A verdict may not be used as a boolean.** ``bool(verdict)`` raises. Every
  Python object is truthy, so ``if guard(...):`` would read a ``Deny`` — and a
  ``CannotSay``! — as success. Callers pattern-match.
* **``CannotSay`` is a first-class state, and it names its cause.** A detector
  that could not look says so, and never says ``Allow``: a witness that cannot
  see may never report "ok". *Why* nobody could look is a fact of the verdict,
  sealed into its fingerprint (ADR 0026): a limit the witness declared, a witness
  that fell over, or a transport that refused to take the content on. The three
  are not the same thing to an operator, and a policy that opens one must not
  silently open the others. And a *declared* limit names its **family** (ADR
  0029) — an image, an encoded payload, another script, a budget — so that an
  operator who accepts one of them knowingly has not accepted them all.

The doctrine is inherited from Tessera (ADR 0026/0027) and re-stated here for a
guard, where a false "allow" is an incident.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, final

from limes.spans import RedactedSpan

__all__ = [
    "Allow",
    "BlindCause",
    "BlindKind",
    "CannotSay",
    "Deny",
    "Evidence",
    "Verdict",
    "Witness",
    "blind_label",
    "fingerprint",
    "render",
]


class BlindCause(StrEnum):
    """Why a ``CannotSay`` could not say (ADR 0026).

    Attributes:
        DECLARED: A witness declared a limit of its own coverage — the content is
            over its budget, is not text its rules read, is in a language they
            were not written for, or no witness is wired for the leg at all.
            Deterministic and reproducible; an operator may accept it knowingly.
        FAULT: A witness fell over instead of answering. A bug, and possibly one
            an attacker provoked on purpose; no setting turns it into a pass.
        REFUSED: Nobody was asked. The transport refused to take the content on —
            a frame it could not parse, a table it could not grow — and nothing
            about the content itself is known.
    """

    DECLARED = "declared"
    FAULT = "fault"
    REFUSED = "refused"


class BlindKind(StrEnum):
    """The family of a declared limit — *what*, exactly, could not be read (ADR 0029).

    A ``CannotSay`` with cause ``DECLARED`` carries one or more of these, sealed
    into its fingerprint, and the transport's ``on_cannot_say`` policy opens a
    family at a time: an operator whose tools return screenshots accepts
    ``binary`` and nothing else. The vocabulary is closed so that a policy
    naming a family that does not exist is a load error, never a setting that
    quietly governs nothing.

    Attributes:
        BUDGET: The content is over the size the detector declared it scans.
        ENCODING: The content does not encode to UTF-8.
        OPAQUE: Most of the content is opaque encoded runs — base64, hex, a
            serialised blob — that no text rule reads.
        INVISIBLE: A format character is wedged inside a word or a number, where
            it splits what the rules would otherwise read.
        SCRIPT: Most of the letters are in a script the word-reading rules were
            not written for.
        LOCALE: The caller declared a language the detector's policy does not
            list.
        BINARY: A block the payload walk could derive no text from — an image,
            an audio clip, a binary resource.
        UNWITNESSED: Nobody read it: a leg with no detector wired, or a kind of
            message the relay forwards unread by design.
        UNSPECIFIED: A detector declared a limit and named no family for it.
    """

    BUDGET = "budget"
    ENCODING = "encoding"
    OPAQUE = "opaque"
    INVISIBLE = "invisible"
    SCRIPT = "script"
    LOCALE = "locale"
    BINARY = "binary"
    UNWITNESSED = "unwitnessed"
    UNSPECIFIED = "unspecified"


@final
@dataclass(frozen=True, slots=True)
class Witness:
    """A detector that ran over the content — i.e. that actually observed it."""

    detector_id: str
    detector_version: str


@final
@dataclass(frozen=True, slots=True)
class Evidence:
    """What a verdict looked at. Every field is required — no evidence field has a default.

    Attributes:
        witnesses: The detectors that ran (observed the content).
        policy_hash: SHA-256 of the active policy the detectors ran under.
        content_sha: SHA-256 of the inspected content.
        matched_spans: Redacted spans of what fired; empty for a clean ``Allow``.
        observed_at: ISO-8601 timestamp supplied by the caller — never ``now()``,
            because the decision chain must re-derive on replay.
    """

    witnesses: tuple[Witness, ...]
    policy_hash: str
    content_sha: str
    matched_spans: tuple[RedactedSpan, ...]
    observed_at: str


class _Verdict:
    """Base of the verdicts. It exists for one reason: to forbid ``bool(verdict)``."""

    __slots__ = ()

    def __bool__(self) -> NoReturn:
        raise TypeError(
            f"{type(self).__name__} is a Verdict, not a boolean. Every object is truthy, so "
            "`if guard(...):` would read a Deny — and a CannotSay! — as ALLOW, the exact bug this "
            "type makes unrepresentable (ADR 0002). Match on it:\n"
            "    match guard(...):\n"
            "        case Allow(evidence): ...\n"
            "        case Deny(reason, evidence): ...\n"
            "        case CannotSay(blind_spot, cause, kinds): ..."
        )


@final
@dataclass(frozen=True, slots=True)
class Allow(_Verdict):
    """The detectors ran and found nothing. ``evidence`` names who looked, and at what."""

    evidence: Evidence


@final
@dataclass(frozen=True, slots=True)
class Deny(_Verdict):
    """A detector refused. ``reason`` is human-readable; ``evidence`` proves the refusal."""

    reason: str
    evidence: Evidence

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("Deny('') tells the reader nothing. Say what was refused.")


@final
@dataclass(frozen=True, slots=True)
class CannotSay(_Verdict):
    """Nobody could look. A blind spot to publish, never a reason to pass.

    Attributes:
        blind_spot: What could not be seen, in words.
        cause: Why (ADR 0026) — a declared limit, a fault, or a refusal. No
            default: a cause the type guessed on the caller's behalf would be a
            lie that reads complete, and the transport policy turns on it.
        kinds: The families of the declared limits this blind spot carries (ADR
            0029). Never empty when the cause is ``DECLARED`` — a limit that
            names no family is ``UNSPECIFIED``, out loud — and the transport
            policy opens the verdict only if it opens every family in it. Empty
            for a refusal, which declared nothing about the content; a fault may
            carry the families declared beside it, and no policy reads them.
            No default either, for the same reason as ``cause``.
    """

    blind_spot: str
    cause: BlindCause
    kinds: frozenset[BlindKind]

    def __post_init__(self) -> None:
        if not self.blind_spot.strip():
            raise ValueError(
                "CannotSay('') is a blind spot about a blind spot. Name what you could not see."
            )
        if not isinstance(self.cause, BlindCause):
            raise TypeError(
                f"CannotSay.cause must be a BlindCause, not {type(self.cause).__name__}: the "
                "transport decides on it, so it may not be a string somebody typed."
            )
        if not isinstance(self.kinds, frozenset) or not all(
            isinstance(kind, BlindKind) for kind in self.kinds
        ):
            raise TypeError(
                "CannotSay.kinds must be a frozenset of BlindKind: the transport opens a "
                "family by name, so a family may not be a string somebody typed."
            )
        if self.cause is BlindCause.DECLARED and not self.kinds:
            raise ValueError(
                "a declared limit names its family (ADR 0029); one that has none is "
                "BlindKind.UNSPECIFIED, said out loud rather than left blank."
            )


Verdict = Allow | Deny | CannotSay


def _span_repr(span: RedactedSpan) -> dict[str, object]:
    return {"start": span.start, "end": span.end, "label": span.label, "sha": span.matched_sha}


def _evidence_repr(evidence: Evidence) -> dict[str, object]:
    return {
        "witnesses": [
            {"id": w.detector_id, "version": w.detector_version} for w in evidence.witnesses
        ],
        "policy_hash": evidence.policy_hash,
        "content_sha": evidence.content_sha,
        "spans": [_span_repr(s) for s in evidence.matched_spans],
        "observed_at": evidence.observed_at,
    }


def fingerprint(verdict: Verdict) -> str:
    """Return a canonical, deterministic JSON fingerprint of a verdict.

    The fingerprint covers the verdict's full content (reason / blind spot, its
    cause and its families / evidence), so the decision chain's digest changes
    if any of it changes, and a replay of the same decision re-derives the same
    fingerprint.

    Args:
        verdict: The verdict to fingerprint.

    Returns:
        Compact, sorted-key JSON — the same bytes for the same verdict content.
    """
    if isinstance(verdict, Allow):
        core: dict[str, object] = {"kind": "allow", "evidence": _evidence_repr(verdict.evidence)}
    elif isinstance(verdict, Deny):
        core = {
            "kind": "deny",
            "reason": verdict.reason,
            "evidence": _evidence_repr(verdict.evidence),
        }
    else:
        core = {
            "kind": "cannot_say",
            "blind_spot": verdict.blind_spot,
            "cause": verdict.cause.value,
            "kinds": sorted(kind.value for kind in verdict.kinds),
        }
    return json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def blind_label(verdict: CannotSay) -> str:
    """The cause of a blind spot and, for a declared one, its families, as one label.

    ``"declared: binary, script"``, ``"fault"``, ``"refused"`` — the phrase every
    surface that names a ``CannotSay`` to a human uses, so the refusal an agent
    reads, the CLI's line and the journal's rendering say the same thing.

    Args:
        verdict: The blind spot to label.

    Returns:
        The cause's value, followed by the sorted families when there are any.
    """
    if not verdict.kinds:
        return verdict.cause.value
    return f"{verdict.cause.value}: " + ", ".join(sorted(kind.value for kind in verdict.kinds))


def render(verdict: Verdict) -> str:
    """Render a verdict for human display (never for control flow)."""
    if isinstance(verdict, Allow):
        return f"[ALLOW] observed by {len(verdict.evidence.witnesses)} detector(s), 0 findings"
    if isinstance(verdict, Deny):
        return f"[DENY] {verdict.reason}"
    return f"[CANNOT SAY] ({blind_label(verdict)}) {verdict.blind_spot}"
