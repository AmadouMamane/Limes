"""The limes verdict algebra — a verdict carries its evidence (ADR 0002).

``Verdict = Allow(evidence) | Deny(reason, evidence) | CannotSay(blind_spot)``

Three invariants this module makes load-bearing:

* **``Allow`` cannot be constructed without its :class:`Evidence`.** No default,
  no convenience constructor. Enforced at the type level; a ratchet asserts mypy
  rejects ``Allow()`` and goes red the moment ``evidence`` gains a default.
* **A verdict may not be used as a boolean.** ``bool(verdict)`` raises. Every
  Python object is truthy, so ``if guard(...):`` would read a ``Deny`` — and a
  ``CannotSay``! — as success. Callers pattern-match.
* **``CannotSay`` is a first-class state.** A detector that could not look says
  so, and never says ``Allow``: a witness that cannot see may never report "ok".

The doctrine is inherited from Tessera (ADR 0026/0027) and re-stated here for a
guard, where a false "allow" is an incident.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import NoReturn, final

from limes.spans import RedactedSpan

__all__ = [
    "Allow",
    "CannotSay",
    "Deny",
    "Evidence",
    "Verdict",
    "Witness",
    "fingerprint",
    "render",
]


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
            "        case CannotSay(blind_spot): ..."
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
    """A detector could not look. A blind spot to publish, never a reason to pass."""

    blind_spot: str

    def __post_init__(self) -> None:
        if not self.blind_spot.strip():
            raise ValueError(
                "CannotSay('') is a blind spot about a blind spot. Name what you could not see."
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

    The fingerprint covers the verdict's full content (reason / blind spot /
    evidence), so the decision chain's digest changes if any of it changes, and
    a replay of the same decision re-derives the same fingerprint.

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
        core = {"kind": "cannot_say", "blind_spot": verdict.blind_spot}
    return json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def render(verdict: Verdict) -> str:
    """Render a verdict for human display (never for control flow)."""
    if isinstance(verdict, Allow):
        return f"[ALLOW] observed by {len(verdict.evidence.witnesses)} detector(s), 0 findings"
    if isinstance(verdict, Deny):
        return f"[DENY] {verdict.reason}"
    return f"[CANNOT SAY] {verdict.blind_spot}"
