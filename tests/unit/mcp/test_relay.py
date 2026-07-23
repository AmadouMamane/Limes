"""The relay's four load-bearing properties (v0.2 definition of done, ADR 0005).

Transparency, blocking, fail-closed, replayability — each proven by holding both
ends of the relay and looking at what actually crossed.
"""

from __future__ import annotations

from typing import Any

import mcp.types as types
import pytest

from limes.detectors.injection import InjectionDetector
from limes.eval.corpus import CASE_08, load_attacks
from limes.transports.mcp.config import OnCannotSay
from tests.unit.mcp.harness import (
    BlindDetector,
    EgressDouble,
    as_error,
    as_response,
    drive,
    echo_responder,
    make_relay,
)


def _relay(records, *, inbound=None, outbound=(), on_cannot_say=OnCannotSay.DENY):
    detector = InjectionDetector()
    return make_relay(
        inbound=(detector,) if inbound is None else inbound,
        outbound=outbound,
        policy_hash=detector.policy_hash,
        on_cannot_say=on_cannot_say,
        records=records,
    )


def _raw(text: str):
    return types.JSONRPCMessage.model_validate_json(text).root


def _call(request_id, name, arguments):
    return types.JSONRPCRequest(
        jsonrpc="2.0",
        id=request_id,
        method="tools/call",
        params={"name": name, "arguments": arguments},
    )


def _case_08_text() -> str:
    attacks = [attack for attack in load_attacks() if attack.case_id == CASE_08]
    assert attacks, "the corpus must still carry case 08"
    return attacks[0].text


# --- transparency -----------------------------------------------------------


def test_every_other_method_crosses_unchanged_in_both_directions():
    records: list[dict[str, Any]] = []
    relay = _relay(records)
    initialize = _raw(
        '{"jsonrpc":"2.0","id":1,"method":"initialize",'
        '"params":{"protocolVersion":"2025-11-25","capabilities":{},'
        '"clientInfo":{"name":"host","version":"1"}},"vendorExtension":{"keep":"me"}}'
    )
    listing = _raw('{"jsonrpc":"2.0","id":"two","method":"tools/list","params":{"cursor":null}}')
    unknown = _raw('{"jsonrpc":"2.0","id":3,"method":"vendor/experimental","params":{"a":[1,2]}}')
    initialized = _raw('{"jsonrpc":"2.0","method":"notifications/initialized"}')

    session = drive(
        relay,
        [initialize, listing, unknown, initialized],
        records=records,
        expect_to_host=3,
    )

    forwarded = [
        message.model_dump(by_alias=True, exclude_none=True) for message in session.to_server
    ]
    original = [
        message.model_dump(by_alias=True, exclude_none=True)
        for message in (initialize, listing, unknown, initialized)
    ]
    assert forwarded == original, "the proxy must not rewrite messages it does not guard"
    assert forwarded[0]["vendorExtension"] == {"keep": "me"}, "unknown fields must survive"
    assert [as_response(message).id for message in session.to_host] == [1, "two", 3], (
        "ids must be preserved"
    )
    assert records == [], "only guarded messages produce a decision"


def test_a_benign_tool_call_reaches_the_server_and_is_recorded_as_forwarded():
    records: list[dict[str, Any]] = []
    relay = _relay(records)

    session = drive(
        relay,
        [_call(7, "echo", {"text": "Quel est le solde de mon compte courant ?"})],
        records=records,
        expect_to_host=1,
    )

    assert session.server_saw_tool_call("echo")
    assert len(records) == 1
    assert records[0]["mcp"] == {
        "method": "tools/call",
        "tool": "echo",
        "request_id": 7,
        "action": "forward",
        "redaction": None,
    }
    assert records[0]["direction"] == "inbound"
    assert records[0]["actor"] == "session-under-test"


# --- blocking ---------------------------------------------------------------


def test_an_injection_in_an_argument_is_refused_and_never_reaches_the_server():
    records: list[dict[str, Any]] = []
    relay = _relay(records)

    session = drive(
        relay,
        [_call(11, "add_payee", {"name": _case_08_text()})],
        records=records,
        expect_to_host=1,
    )

    assert session.to_server == [], "the real server must never have seen the blocked call"
    assert not session.server_saw_tool_call("add_payee")

    reply = as_response(session.to_host[0])  # a refusal is a RESULT, not a JSON-RPC error
    assert reply.id == 11, "the host's pending call must resolve, not hang"
    assert reply.result["isError"] is True
    text = reply.result["content"][0]["text"]
    assert "limes blocked this tool call" in text
    assert "injection:" in text, "the refusal names the rule that fired"
    assert records[0]["digest"] in text, "the refusal carries the evidence id"

    meta = reply.result["_meta"]["limes"]
    assert meta["blocked"] is True
    assert meta["evidence"]["matched_spans"], "a refusal carries the spans that fired"
    assert meta["record"]["digest"] == records[0]["digest"]
    assert records[0]["mcp"]["action"] == "block"


def test_a_refusal_never_reproduces_the_payload():
    records: list[dict[str, Any]] = []
    relay = _relay(records)
    payload = _case_08_text()

    session = drive(
        relay,
        [_call(12, "add_payee", {"name": payload})],
        records=records,
        expect_to_host=1,
    )

    reply = as_response(session.to_host[0])
    rendered = reply.model_dump_json()
    # The longest distinctive fragment of the attack must not come back out.
    fragment = max(payload.split("."), key=len).strip()
    assert len(fragment) > 20
    assert fragment not in rendered, "evidence carries hashes and offsets, never the payload"


# --- fail-closed ------------------------------------------------------------


def test_cannot_say_blocks_by_default():
    records: list[dict[str, Any]] = []
    relay = _relay(records, inbound=(BlindDetector(),))

    session = drive(
        relay,
        [_call(21, "echo", {"text": "hello"})],
        records=records,
        expect_to_host=1,
    )

    assert session.to_server == [], "a guard that could not look must not forward"
    reply = as_response(session.to_host[0])
    assert reply.result["isError"] is True
    assert "could not look" in reply.result["content"][0]["text"]
    assert reply.result["_meta"]["limes"]["evidence"] is None, "CannotSay carries no evidence"
    assert records[0]["mcp"]["action"] == "block"


def test_on_cannot_say_allow_forwards_and_still_records():
    records: list[dict[str, Any]] = []
    relay = _relay(records, inbound=(BlindDetector(),), on_cannot_say=OnCannotSay.ALLOW)

    session = drive(
        relay,
        [_call(22, "echo", {"text": "hello"})],
        records=records,
        expect_to_host=1,
    )

    assert session.server_saw_tool_call("echo"), "an explicit override must actually forward"
    assert records[0]["mcp"]["action"] == "forward"
    assert "cannot_say" in records[0]["verdict_fingerprint"]


# --- replayability ----------------------------------------------------------

_SESSION = [
    _call(1, "echo", {"text": "Wie kann ich eine SEPA-Überweisung einrichten?"}),
    _call(2, "add_payee", {"name": _case_08_text()}),
    _call(3, "echo", {"text": "Quel est le solde de mon compte courant ?"}),
]


def _replay_once() -> list[str]:
    records: list[dict[str, Any]] = []
    relay = _relay(records)
    drive(relay, _SESSION, records=records, expect_to_host=3)
    return [record.digest for record in relay.ledger.records()]


def test_a_recorded_session_re_derives_identical_digests():
    first = _replay_once()
    second = _replay_once()
    assert first == second
    assert len(first) == len(_SESSION)


def test_the_sink_publishes_the_ledger_digests_and_the_chain_verifies():
    records: list[dict[str, Any]] = []
    relay = _relay(records)
    session = drive(relay, _SESSION, records=records, expect_to_host=3)

    assert session.digests() == [record.digest for record in relay.ledger.records()]
    status = relay.ledger.verify()
    assert status.verified
    assert status.length == len(_SESSION)


# --- the outbound seam: wired, and empty --------------------------------------


def _leaky_responder(message):
    reply = echo_responder(message)
    if reply is None:
        return None
    response = as_response(reply)
    response.result = {
        "content": [{"type": "text", "text": f"here it is: {EgressDouble.marker}"}],
        "isError": False,
    }
    return response


def test_with_no_egress_detector_the_outbound_leg_is_pass_through_and_silent():
    records: list[dict[str, Any]] = []
    relay = _relay(records)
    assert relay.outbound_is_wired is False

    session = drive(
        relay,
        [_call(31, "read_file", {"path": "/data/x"})],
        records=records,
        responder=_leaky_responder,
        expect_to_host=1,
    )

    reply = as_response(session.to_host[0])
    assert reply.result["isError"] is False, "an unwatched leg passes through untouched"
    assert EgressDouble.marker in reply.result["content"][0]["text"]
    assert len(records) == 1, (
        "an empty seam must emit NO outbound record: decide() over zero detectors "
        "would answer Allow with zero witnesses, which is a false 'ok'"
    )
    assert records[0]["direction"] == "inbound"


def test_the_seam_is_really_wired_a_detector_installed_there_is_run_and_enforced():
    records: list[dict[str, Any]] = []
    relay = _relay(records, outbound=(EgressDouble(),))
    assert relay.outbound_is_wired is True

    session = drive(
        relay,
        [_call(32, "read_file", {"path": "/data/x"})],
        records=records,
        responder=_leaky_responder,
        expect_to_host=1,
    )

    reply = as_response(session.to_host[0])
    assert reply.result["isError"] is True
    assert EgressDouble.marker not in reply.model_dump_json()
    assert [record["direction"] for record in records] == ["inbound", "outbound"]
    assert records[1]["mcp"]["action"] == "block"


@pytest.mark.parametrize("method", ["resources/read"])
def test_a_refused_non_tool_response_becomes_a_jsonrpc_error(method):
    records: list[dict[str, Any]] = []
    relay = _relay(records, outbound=(EgressDouble(),))
    request = types.JSONRPCRequest(jsonrpc="2.0", id=41, method=method, params={"uri": "file:///x"})

    def responder(message):
        return types.JSONRPCResponse(
            jsonrpc="2.0",
            id=message.id,
            result={"contents": [{"uri": "file:///x", "text": EgressDouble.marker}]},
        )

    session = drive(relay, [request], records=records, responder=responder, expect_to_host=1)

    # resources/read has no isError affordance; substituting content would lie about it
    reply = as_error(session.to_host[0])
    assert reply.error.code == -32001
    assert EgressDouble.marker not in reply.model_dump_json()
