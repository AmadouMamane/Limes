"""From a core verdict to a proxy action, and to the refusal the host reads.

Three rules. They are the whole policy surface of this transport (ADR 0005):

* ``Allow``     → forward;
* ``Deny``      → block;
* ``CannotSay`` → block **by default**, and forward only if an operator has
  explicitly declared ``on_cannot_say: allow``. A witness that cannot see may
  never report "ok" (ADR 0002).

A blocked ``tools/call`` comes back to the host as a **normal tool result marked
``isError``** — never a JSON-RPC transport error. The reason is behavioural: an
agent that receives a failed tool result degrades gracefully (it reads the text,
explains, tries something else), whereas a transport error reads as a crash and
takes the session down with it. The refusal carries the reason *and* the
evidence: the chain digest that indexes the decision, the policy hash, the hash
of the inspected content, and the redacted spans that fired — never the payload.

A fourth outcome exists on the **outbound** leg only, and it is not a fourth
verdict: under a redacting egress policy a ``Deny`` becomes a *masked forward*
(ADR 0006). The host then gets a **normal** result — no ``isError`` — whose
matched regions read ``[REDACTED:<kind>]``, annotated in ``_meta`` with what was
masked and where. The token is the in-band annotation an agent reads; ``_meta``
is the machine-readable one. The decision is still a ``Deny`` on the chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, final

from limes.record import DecisionRecord
from limes.transports.mcp.config import OnCannotSay
from limes.transports.redaction import Action, Redaction
from limes.verdict import Allow, CannotSay, Deny, Verdict

__all__ = ["Action", "Ruling", "redaction_meta", "refusal_meta", "refusal_text", "rule"]


@final
@dataclass(frozen=True, slots=True)
class Ruling:
    """A verdict, read through the transport's fail-closed policy.

    Attributes:
        action: What the bridge does with the message.
        verdict: The core's verdict, unchanged.
        reason: One human-readable line, suitable for the host.
    """

    action: Action
    verdict: Verdict
    reason: str


def rule(verdict: Verdict, *, on_cannot_say: OnCannotSay) -> Ruling:
    """Turn a core verdict into a transport action.

    Args:
        verdict: The verdict returned by the pipeline.
        on_cannot_say: What to do about a blind detector. ``DENY`` is the
            default everywhere it is not explicitly overridden.

    Returns:
        The ruling: the action, the verdict it came from, and the reason line.
    """
    if isinstance(verdict, Allow):
        return Ruling(action=Action.FORWARD, verdict=verdict, reason="allowed")
    if isinstance(verdict, Deny):
        return Ruling(action=Action.BLOCK, verdict=verdict, reason=verdict.reason)
    reason = f"the guard could not look: {verdict.blind_spot}"
    if on_cannot_say is OnCannotSay.ALLOW:
        return Ruling(action=Action.FORWARD, verdict=verdict, reason=reason)
    return Ruling(action=Action.BLOCK, verdict=verdict, reason=reason)


def refusal_text(ruling: Ruling, record: DecisionRecord, *, subject: str) -> str:
    """Render the refusal an agent reads inside the failed tool result.

    Args:
        ruling: The blocking ruling.
        record: The chain record this decision produced — its digest is the
            evidence id an auditor looks the decision up by.
        subject: What was refused, e.g. ``"tool call"`` or ``"tool result"``.

    Returns:
        A multi-line, human-readable refusal carrying the reason and the
        redacted evidence. The matched text is never reproduced.
    """
    lines = [
        f"limes blocked this {subject}.",
        f"reason: {ruling.reason}",
        f"decision: seq {record.seq}, record {record.digest}",
    ]
    verdict = ruling.verdict
    if isinstance(verdict, CannotSay):
        lines.append(
            "evidence: none — a detector could not look, and limes fails closed "
            "(set on_cannot_say: allow to change that, knowingly)."
        )
    else:
        evidence = verdict.evidence
        lines.append(f"policy: sha256 {evidence.policy_hash}")
        lines.append(f"inspected content: sha256 {evidence.content_sha}")
        lines.extend(
            f"matched: {span.label} at [{span.start},{span.end}) sha256 {span.matched_sha}"
            for span in evidence.matched_spans
        )
        lines.append("(evidence carries hashes and offsets, never the payload)")
    return "\n".join(lines)


def refusal_meta(ruling: Ruling, record: DecisionRecord) -> dict[str, Any]:
    """Render the same refusal as structured data, for the result's ``_meta``.

    ``_meta`` is MCP's extension point, which is where a proxy's annotation
    belongs; ``structuredContent`` is not, because it is contracted by the
    wrapped tool's own output schema.

    Args:
        ruling: The blocking ruling.
        record: The chain record this decision produced.

    Returns:
        A ``{"limes": {...}}`` mapping carrying the reason, the chain linkage,
        and the redacted evidence (``None`` for a ``CannotSay``).
    """
    return {
        "limes": {
            "blocked": True,
            "redacted": False,
            "reason": ruling.reason,
            "record": _record_meta(record),
            "evidence": _evidence_meta(ruling.verdict),
        }
    }


def _record_meta(record: DecisionRecord) -> dict[str, Any]:
    """The chain linkage an auditor looks the decision up by."""
    return {
        "seq": record.seq,
        "direction": record.direction,
        "digest": record.digest,
        "prev_hash": record.prev_hash,
    }


def _evidence_meta(verdict: Verdict) -> dict[str, Any] | None:
    """The evidence as data — hashes and offsets, never the payload.

    Returns ``None`` for a ``CannotSay``, which has no evidence by construction:
    the detector did not observe, so there is nothing to publish but the blind spot.
    """
    if isinstance(verdict, CannotSay):
        return None
    return {
        "policy_hash": verdict.evidence.policy_hash,
        "content_sha": verdict.evidence.content_sha,
        "witnesses": [
            {"id": witness.detector_id, "version": witness.detector_version}
            for witness in verdict.evidence.witnesses
        ],
        "matched_spans": [
            {
                "label": span.label,
                "start": span.start,
                "end": span.end,
                "matched_sha": span.matched_sha,
            }
            for span in verdict.evidence.matched_spans
        ],
        "observed_at": verdict.evidence.observed_at,
    }


def redaction_meta(
    verdict: Verdict, record: DecisionRecord, redaction: Redaction, *, reason: str
) -> dict[str, Any]:
    """Render the annotation a *masked* result carries in its ``_meta`` (ADR 0006).

    The host is told, in machine-readable form, that this result is not what the
    wrapped server sent: which kinds were masked, at which offsets, and under
    which chain record. It is told **what was removed, never what it was** — the
    annotation carries the same coordinates the evidence does, and no fragment of
    the masked text.

    Args:
        verdict: The outbound ``Deny`` the masking came from.
        record: The chain record this decision produced.
        redaction: The masking plan that was applied.
        reason: The one-line reason, as the egress ruling phrased it.

    Returns:
        A ``{"limes": {...}}`` mapping to merge into the result's ``_meta``.
    """
    return {
        "limes": {
            "blocked": False,
            "redacted": True,
            "reason": reason,
            "record": _record_meta(record),
            "redaction": redaction.annotation(),
            "evidence": _evidence_meta(verdict),
        }
    }
