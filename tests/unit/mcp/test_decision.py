"""The verdict → action mapping, and the refusal the host reads."""

from __future__ import annotations

import pytest

from limes.detector import Direction
from limes.record import Ledger
from limes.spans import RedactedSpan
from limes.transports.mcp.config import OnCannotSay
from limes.transports.mcp.decision import Action, refusal_meta, refusal_text, rule
from limes.verdict import Allow, CannotSay, Deny, Evidence, Witness

_SPAN = RedactedSpan(start=3, end=9, label="injection:disable-control", matched_sha="a" * 64)


def _evidence(spans=()):
    return Evidence(
        witnesses=(Witness(detector_id="injection", detector_version="0.1.0"),),
        policy_hash="p" * 64,
        content_sha="c" * 64,
        matched_spans=spans,
        observed_at="2026-07-23T00:00:00Z",
    )


def _record(verdict):
    return Ledger().append(Direction.INBOUND, verdict, "session-under-test")


def test_allow_forwards():
    ruling = rule(Allow(evidence=_evidence()), on_cannot_say=OnCannotSay.DENY)
    assert ruling.action is Action.FORWARD


def test_deny_blocks_and_keeps_the_reason():
    verdict = Deny(reason="1 rule match(es)", evidence=_evidence((_SPAN,)))
    ruling = rule(verdict, on_cannot_say=OnCannotSay.ALLOW)
    assert ruling.action is Action.BLOCK, "on_cannot_say never softens a real detection"
    assert ruling.reason == "1 rule match(es)"


@pytest.mark.parametrize(
    ("policy", "expected"),
    [(OnCannotSay.DENY, Action.BLOCK), (OnCannotSay.ALLOW, Action.FORWARD)],
)
def test_cannot_say_follows_the_declared_policy_and_defaults_to_blocking(policy, expected):
    ruling = rule(CannotSay(blind_spot="detector timed out"), on_cannot_say=policy)
    assert ruling.action is expected
    assert "could not look" in ruling.reason
    assert OnCannotSay.DENY is OnCannotSay("deny"), "the default is the fail-closed one"


def test_a_refusal_names_the_reason_the_record_and_the_spans():
    verdict = Deny(reason="1 rule match(es)", evidence=_evidence((_SPAN,)))
    ruling = rule(verdict, on_cannot_say=OnCannotSay.DENY)
    record = _record(verdict)
    text = refusal_text(ruling, record, subject="tool call")

    assert "limes blocked this tool call." in text
    assert "1 rule match(es)" in text
    assert record.digest in text
    assert "injection:disable-control at [3,9)" in text
    assert _SPAN.matched_sha in text
    assert "never the payload" in text


def test_a_cannot_say_refusal_says_there_is_no_evidence_rather_than_inventing_some():
    verdict = CannotSay(blind_spot="policy file unreadable")
    ruling = rule(verdict, on_cannot_say=OnCannotSay.DENY)
    record = _record(verdict)

    text = refusal_text(ruling, record, subject="tool call")
    assert "evidence: none" in text
    assert "policy file unreadable" in text
    assert refusal_meta(ruling, record)["limes"]["evidence"] is None


def test_the_structured_meta_mirrors_the_text():
    verdict = Deny(reason="1 rule match(es)", evidence=_evidence((_SPAN,)))
    ruling = rule(verdict, on_cannot_say=OnCannotSay.DENY)
    record = _record(verdict)
    meta = refusal_meta(ruling, record)["limes"]

    assert meta["blocked"] is True
    assert meta["record"]["digest"] == record.digest
    assert meta["record"]["prev_hash"] == record.prev_hash
    assert meta["evidence"]["policy_hash"] == "p" * 64
    assert meta["evidence"]["witnesses"] == [{"id": "injection", "version": "0.1.0"}]
    assert meta["evidence"]["matched_spans"] == [
        {
            "label": "injection:disable-control",
            "start": 3,
            "end": 9,
            "matched_sha": "a" * 64,
        }
    ]
