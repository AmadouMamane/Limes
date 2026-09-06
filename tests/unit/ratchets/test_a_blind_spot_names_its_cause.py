"""A blind spot names its cause, and the transport rules on it (ADR 0026).

Before ADR 0026 every ``CannotSay`` was the same ``CannotSay``: a detector over
its declared budget, a detector that crashed, and a relay whose pending table
was full all rendered as one string, and ``on_cannot_say: allow`` forwarded all
three. An operator who accepted the guard's *declared limits* had, without
knowing it, accepted a crashed guard — and a crash an attacker can provoke is a
bypass under that setting. Seen red on the tree before the change: ``CannotSay``
had no ``cause`` field, ``rule()`` forwarded a fault under ``allow``, the relay's
refusal bypassed ``rule()``, and a frame that did not parse left no record.
"""

from __future__ import annotations

from typing import Any

import mcp.types as types
import pytest

from limes.detector import Context, Direction, Finding
from limes.detectors.injection import InjectionDetector
from limes.guard import decide
from limes.record import Ledger
from limes.transports.mcp import bridge
from limes.transports.mcp.config import CannotSayPolicy, OnCannotSay
from limes.transports.mcp.decision import Action, refusal_meta, refusal_text, rule
from limes.verdict import BlindCause, BlindKind, CannotSay, fingerprint
from tests.unit.mcp.harness import BlindDetector, as_error, as_response, drive, make_relay

pytestmark = pytest.mark.mutation

_CONTEXT = Context(policy_hash="cause", actor=None)
_OBSERVED_AT = "2026-09-06T00:00:00Z"
_CLEAN = "Quel est le solde de mon compte courant ?"
_DENY = CannotSayPolicy.denying()
_ALLOW = CannotSayPolicy.allowing()
_UNSPECIFIED = frozenset({BlindKind.UNSPECIFIED})
_NONE: frozenset[BlindKind] = frozenset()


class _Crashing:
    id = "crashing-double"
    version = "0.0.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        raise RuntimeError("a bug, not a blind spot")


def _relay(records: list[dict[str, Any]], *, inbound, on_cannot_say=OnCannotSay.DENY, outbound=()):
    detector = InjectionDetector()
    return make_relay(
        inbound=inbound,
        outbound=outbound,
        policy_hash=detector.policy_hash,
        on_cannot_say=on_cannot_say,
        records=records,
    )


def _call(request_id, text):
    return types.JSONRPCRequest(
        jsonrpc="2.0",
        id=request_id,
        method="tools/call",
        params={"name": "echo", "arguments": {"text": text}},
    )


# --- the core names the cause -------------------------------------------------


def test_a_declared_limit_is_a_declared_cause():
    verdict = decide(
        Direction.INBOUND, _CLEAN, _CONTEXT, [BlindDetector()], observed_at=_OBSERVED_AT
    )
    assert isinstance(verdict, CannotSay)
    assert verdict.cause is BlindCause.DECLARED


def test_a_crash_is_a_fault():
    verdict = decide(Direction.INBOUND, _CLEAN, _CONTEXT, [_Crashing()], observed_at=_OBSERVED_AT)
    assert isinstance(verdict, CannotSay)
    assert verdict.cause is BlindCause.FAULT


def test_a_fault_outranks_a_declared_limit():
    # The operator who accepts declared limits has not accepted a crashed guard,
    # so when both happen the verdict carries the cause no setting opens.
    verdict = decide(
        Direction.INBOUND,
        _CLEAN,
        _CONTEXT,
        [BlindDetector(), _Crashing()],
        observed_at=_OBSERVED_AT,
    )
    assert isinstance(verdict, CannotSay)
    assert verdict.cause is BlindCause.FAULT
    assert "blind-double" in verdict.blind_spot, "the declared limit is still named"
    assert "crashing-double" in verdict.blind_spot


def test_a_callers_blind_spot_is_a_declared_cause():
    verdict = decide(
        Direction.INBOUND,
        _CLEAN,
        _CONTEXT,
        [InjectionDetector()],
        observed_at=_OBSERVED_AT,
        blind_spots=((BlindKind.BINARY, "an image block (image/png) was not inspected"),),
    )
    assert isinstance(verdict, CannotSay)
    assert verdict.cause is BlindCause.DECLARED
    assert "image/png" in verdict.blind_spot


def test_the_chain_seals_the_cause():
    text = "x"
    declared = Ledger().append(
        Direction.INBOUND,
        CannotSay(blind_spot=text, cause=BlindCause.DECLARED, kinds=_UNSPECIFIED),
        None,
    )
    fault = Ledger().append(
        Direction.INBOUND, CannotSay(blind_spot=text, cause=BlindCause.FAULT, kinds=_NONE), None
    )
    assert declared.digest != fault.digest, "same words, different cause, different record"
    assert '"cause":"declared"' in fingerprint(
        CannotSay(blind_spot=text, cause=BlindCause.DECLARED, kinds=_UNSPECIFIED)
    )


# --- the ruling opens the declared cause and nothing else ---------------------


@pytest.mark.parametrize(
    ("cause", "under_allow"),
    [
        (BlindCause.DECLARED, Action.FORWARD),
        (BlindCause.FAULT, Action.BLOCK),
        (BlindCause.REFUSED, Action.BLOCK),
    ],
)
def test_on_cannot_say_allow_opens_only_a_declared_limit(cause, under_allow):
    kinds = _UNSPECIFIED if cause is BlindCause.DECLARED else _NONE
    verdict = CannotSay(blind_spot="x", cause=cause, kinds=kinds)
    assert rule(verdict, on_cannot_say=_DENY).action is Action.BLOCK
    assert rule(verdict, on_cannot_say=_ALLOW).action is under_allow
    assert f"({cause.value}" in rule(verdict, on_cannot_say=_ALLOW).reason


def test_the_refusal_tells_the_host_which_causes_no_setting_opens():
    verdict = CannotSay(blind_spot="x", cause=BlindCause.FAULT, kinds=_NONE)
    record = Ledger().append(Direction.INBOUND, verdict, None)
    ruling = rule(verdict, on_cannot_say=_ALLOW)
    text = refusal_text(ruling, record, subject="tool call")
    assert "fell over" in text
    assert "no setting forwards a fault" in text
    assert refusal_meta(ruling, record)["limes"]["cause"] == "fault"


# --- the relay: a crashed guard is never a pass, whatever the setting ----------


def test_under_on_cannot_say_allow_a_crashed_detector_still_blocks():
    # The regression ADR 0026 closes. Before it, `allow` forwarded this call.
    records: list[dict[str, Any]] = []
    relay = _relay(records, inbound=(_Crashing(),), on_cannot_say=OnCannotSay.ALLOW)

    session = drive(relay, [_call(1, "hello")], records=records, expect_to_host=1)

    assert session.to_server == [], "a crashed guard must not forward under any setting"
    reply = as_response(session.to_host[0])
    assert reply.result["isError"] is True
    assert reply.result["_meta"]["limes"]["cause"] == "fault"
    assert records[0]["mcp"]["action"] == "block"
    assert '"cause":"fault"' in records[0]["verdict_fingerprint"]


def test_under_on_cannot_say_allow_a_declared_limit_still_forwards():
    records: list[dict[str, Any]] = []
    relay = _relay(records, inbound=(BlindDetector(),), on_cannot_say=OnCannotSay.ALLOW)

    session = drive(relay, [_call(2, "hello")], records=records, expect_to_host=1)

    assert len(session.to_server) == 1, "the setting still means what it says for declared limits"
    assert records[0]["mcp"]["action"] == "forward"
    assert '"cause":"declared"' in records[0]["verdict_fingerprint"]


def test_a_full_pending_table_refuses_even_under_allow(monkeypatch):
    monkeypatch.setattr(bridge, "PENDING_LIMIT", 1)
    records: list[dict[str, Any]] = []
    relay = _relay(
        records, inbound=(InjectionDetector(),), on_cannot_say=OnCannotSay.ALLOW, outbound=()
    )
    first = types.JSONRPCRequest(jsonrpc="2.0", id=91, method="tools/list", params={})
    second = types.JSONRPCRequest(jsonrpc="2.0", id=92, method="tools/list", params={})

    session = drive(
        relay, [first, second], records=records, responder=lambda _: None, expect_to_host=1
    )

    refusal = as_error(session.to_host[0])
    assert refusal.id == 92
    refused = next(e for e in records if '"cause":"refused"' in e["verdict_fingerprint"])
    assert refused["mcp"]["action"] == "block", "a refusal goes through rule() and is never opened"


def test_a_frame_the_relay_cannot_parse_is_journalled_as_a_refusal():
    records: list[dict[str, Any]] = []
    relay = _relay(records, inbound=(InjectionDetector(),))

    # The SDK pushes a parse failure through the stream as an Exception. It is
    # dropped — closed — and, since ADR 0026, the chain says a frame crossed the
    # threshold that nobody read. Only the failure's type is recorded: a parser's
    # message quotes the input it choked on, and the chain never carries a payload.
    session = drive(
        relay,
        [ValueError('Invalid JSON: {"secret": "AKIA-not-for-the-journal"}')],
        records=records,
        expect_to_host=0,
    )

    assert session.to_server == []
    assert len(records) == 1
    entry = records[0]
    assert entry["direction"] == "inbound"
    assert entry["disposition"] == "block"
    assert entry["mcp"] == {
        "method": None,
        "tool": None,
        "request_id": None,
        "action": "block",
        "redaction": None,
    }
    assert '"cause":"refused"' in entry["verdict_fingerprint"]
    assert "ValueError" in entry["verdict_fingerprint"]
    assert "AKIA-not-for-the-journal" not in entry["verdict_fingerprint"], "never the payload"
    assert relay.ledger.verify().verified
