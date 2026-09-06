"""From a core verdict to a proxy action, and to the refusal the host reads.

Three rules. They are the whole policy surface of this transport (ADR 0005):

* ``Allow``     → forward;
* ``Deny``      → block;
* ``CannotSay`` → block **by default**, and forward only if the blind spot is
  a *declared* limit (ADR 0026) — a budget, an unreadable encoding, a language
  the rules do not cover, a leg nobody reads — **and** the operator's
  ``on_cannot_say`` policy opens **every family** it carries (ADR 0029): an
  image is ``binary``, a base64 dump is ``opaque``, Cyrillic prose is
  ``script``, and the operator who accepts screenshots has said nothing about
  the other two. A witness that cannot see may never report "ok" (ADR 0002);
  and a witness that *fell over*, or a relay that *refused* to take the content
  on, is opened by no policy at all. An operator who accepts the guard's
  declared limits has not accepted a crashed guard.

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
from limes.transports.mcp.config import CannotSayPolicy
from limes.transports.redaction import Action, Redaction
from limes.verdict import Allow, BlindCause, CannotSay, Deny, Verdict, blind_label

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


def rule(verdict: Verdict, *, on_cannot_say: CannotSayPolicy) -> Ruling:
    """Turn a core verdict into a transport action.

    Args:
        verdict: The verdict returned by the pipeline.
        on_cannot_say: What to do about a *declared* blind spot, by family (ADR
            0029). Denying everything is the default wherever nothing is
            explicitly declared; a policy opens only ``BlindCause.DECLARED``
            verdicts whose every family it allows (ADR 0026): a fault and a
            refusal block under every policy.

    Returns:
        The ruling: the action, the verdict it came from, and the reason line —
        which, for a blocked declared blind spot, names the families that closed
        it.
    """
    if isinstance(verdict, Allow):
        return Ruling(action=Action.FORWARD, verdict=verdict, reason="allowed")
    if isinstance(verdict, Deny):
        return Ruling(action=Action.BLOCK, verdict=verdict, reason=verdict.reason)
    reason = f"the guard could not look ({blind_label(verdict)}): {verdict.blind_spot}"
    if on_cannot_say.opens(verdict):
        return Ruling(action=Action.FORWARD, verdict=verdict, reason=reason)
    closed = on_cannot_say.closed_kinds(verdict)
    if verdict.cause is BlindCause.DECLARED and closed:
        names = ", ".join(kind.value for kind in closed)
        reason = f"{reason} [closed by on_cannot_say for: {names}]"
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
        lines.append(_blind_line(verdict))
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


def _blind_line(verdict: CannotSay) -> str:
    """The evidence line of a refusal nobody could look at, by cause (ADR 0026)."""
    if verdict.cause is BlindCause.DECLARED:
        opening = ", ".join(f"{kind.value}: allow" for kind in sorted(verdict.kinds))
        return (
            "evidence: none — a detector declared it could not look, and limes fails closed "
            f"(accept exactly these families knowingly with on_cannot_say: {{by_kind: "
            f"{{{opening}}}}}; ADR 0029)."
        )
    if verdict.cause is BlindCause.FAULT:
        return (
            "evidence: none — a detector fell over instead of answering, and limes fails "
            "closed; no setting forwards a fault."
        )
    return (
        "evidence: none — the relay refused to take this on, and limes fails closed; no "
        "setting forwards a refusal."
    )


def _cause_meta(verdict: Verdict) -> str | None:
    """The blind spot's cause as data, or ``None`` when somebody looked."""
    return verdict.cause.value if isinstance(verdict, CannotSay) else None


def _kinds_meta(verdict: Verdict) -> list[str] | None:
    """The blind spot's families as data (ADR 0029), or ``None`` when somebody looked."""
    if not isinstance(verdict, CannotSay):
        return None
    return sorted(kind.value for kind in verdict.kinds)


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
        the redacted evidence (``None`` for a ``CannotSay``) and, for a
        ``CannotSay``, the cause of the blind spot (ADR 0026) and the families
        of its declared limits (ADR 0029).
    """
    return {
        "limes": {
            "blocked": True,
            "redacted": False,
            "reason": ruling.reason,
            "cause": _cause_meta(ruling.verdict),
            "kinds": _kinds_meta(ruling.verdict),
            "record": _record_meta(record),
            "evidence": _evidence_meta(ruling.verdict),
        }
    }


def _record_meta(record: DecisionRecord) -> dict[str, Any]:
    """The chain linkage an auditor looks the decision up by."""
    return {
        "seq": record.seq,
        "direction": record.direction,
        "disposition": record.disposition,
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
            "cause": None,
            "kinds": None,
            "record": _record_meta(record),
            "redaction": redaction.annotation(),
            "evidence": _evidence_meta(verdict),
        }
    }
