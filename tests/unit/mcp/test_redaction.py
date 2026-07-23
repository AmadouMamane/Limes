"""Egress redaction across the relay: a masked result is a *normal* result (ADR 0006).

The relay is driven over in-memory streams with a scripted server on the far
side, so a test can read exactly what the host received — which is the only way
to prove the host got the masked payload and not the server's own bytes.

The outbound detectors here are doubles (``tests/unit/redaction/doubles.py``).
limes ships none; the machinery is what is under test.
"""

from __future__ import annotations

from typing import Any

import mcp.types as types

from limes.detectors.injection import InjectionDetector
from limes.transports.mcp.config import OnCannotSay
from limes.transports.redaction import EgressPolicy, OnEgressFinding
from tests.unit.mcp.harness import AnyMessage, as_error, as_response, drive, make_relay
from tests.unit.redaction.doubles import PiiDouble, SecretDouble, WholeContentDouble

CARD = "4111 1111 1111 1111"
EMAIL = "alice@example.com"
KEY = "sk-live-AB12cd34"

REDACT_PII_BLOCK_SECRETS = EgressPolicy(
    default=OnEgressFinding.BLOCK,
    by_kind={"pii": OnEgressFinding.REDACT, "secret": OnEgressFinding.BLOCK},
)


def _call(request_id: int, name: str = "lookup") -> types.JSONRPCRequest:
    return types.JSONRPCRequest(
        jsonrpc="2.0", id=request_id, method="tools/call", params={"name": name, "arguments": {}}
    )


def _read(request_id: int) -> types.JSONRPCRequest:
    return types.JSONRPCRequest(
        jsonrpc="2.0",
        id=request_id,
        method="resources/read",
        params={"uri": "file:///statement.txt"},
    )


def _server_replies(result: dict[str, Any]):
    def responder(message: AnyMessage) -> AnyMessage | None:
        if not isinstance(message, types.JSONRPCRequest):
            return None
        return types.JSONRPCResponse(jsonrpc="2.0", id=message.id, result=result)

    return responder


def _tool_result(text: str, **extra: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False, **extra}


def _relay(records: list[dict[str, Any]], *detectors, egress: EgressPolicy | None = None):
    # The inbound leg carries the real shipped detector, as the proxy does: the
    # inbound decision on a `tools/call` is a record of its own, and the outbound
    # one is the last. A relay with no inbound detector would record an Allow
    # naming no witness, which is the shape this project refuses.
    injection = InjectionDetector()
    return make_relay(
        inbound=(injection,),
        outbound=detectors,
        policy_hash=injection.policy_hash,
        on_cannot_say=OnCannotSay.DENY,
        records=records,
        egress=egress,
    )


# --- the masked forward -----------------------------------------------------


def test_the_host_receives_a_normal_masked_result_and_the_rest_of_the_payload_intact():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    served = _tool_result(
        f"Carte {CARD}, confirmation à {EMAIL}. Solde 1 240,50 EUR.",
        structuredContent={"balance": 1240.5, "currency": "EUR"},
    )

    session = drive(
        relay, [_call(1)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    result = as_response(session.to_host[0]).result
    assert result["isError"] is False, (
        "a masked result is a normal result: the host's tool call succeeded, and what "
        "it may not see is gone from the text — not turned into an error"
    )
    assert result["content"][0]["text"] == (
        "Carte [REDACTED:pii], confirmation à [REDACTED:pii]. Solde 1 240,50 EUR."
    )
    assert result["structuredContent"] == {"balance": 1240.5, "currency": "EUR"}, (
        "non-string leaves and unmatched fields cross untouched"
    )


def test_what_the_server_sent_never_reaches_the_host():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    served = _tool_result(f"Carte {CARD} pour {EMAIL}.")

    session = drive(
        relay, [_call(2)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    crossed = repr(as_response(session.to_host[0]).result)
    assert CARD not in crossed
    assert EMAIL not in crossed
    assert len(session.to_host) == 1, "exactly one reply reaches the host, and it is the masked one"


def test_the_masked_result_says_so_in_meta_without_reproducing_what_it_masked():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)

    session = drive(
        relay,
        [_call(3)],
        records=records,
        responder=_server_replies(_tool_result(f"Carte {CARD}.")),
        expect_to_host=1,
    )

    meta = as_response(session.to_host[0]).result["_meta"]["limes"]
    assert meta["blocked"] is False
    assert meta["redacted"] is True
    assert meta["redaction"]["kinds"] == ["pii"]
    assert meta["redaction"]["spans"][0]["token"] == "[REDACTED:pii]"
    assert meta["record"]["digest"] == records[-1]["digest"]
    assert CARD not in repr(meta), "the annotation carries coordinates, never content"


def test_an_existing_meta_on_the_result_is_kept_alongside_the_annotation():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    served = _tool_result(f"Carte {CARD}.", _meta={"vendor.example/trace": "abc-123"})

    session = drive(
        relay, [_call(4)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    meta = as_response(session.to_host[0]).result["_meta"]
    assert meta["vendor.example/trace"] == "abc-123", "the wrapped server's own _meta survives"
    assert meta["limes"]["redacted"] is True


def test_the_decision_is_recorded_as_a_redaction_and_the_chain_still_says_deny():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)

    drive(
        relay,
        [_call(5)],
        records=records,
        responder=_server_replies(_tool_result(f"Carte {CARD}.")),
        expect_to_host=1,
    )

    assert [entry["mcp"]["action"] for entry in records] == ["forward", "redact"], (
        "the inbound call was clean and the outbound response was masked"
    )
    entry = records[-1]
    assert entry["mcp"]["action"] == "redact"
    assert entry["mcp"]["redaction"]["kinds"] == ["pii"]
    assert entry["direction"] == "outbound"
    assert '"kind":"deny"' in entry["verdict_fingerprint"], (
        "the response left, masked; the chain must still carry the refusal it came from"
    )
    assert relay.ledger.verify().verified


# --- per kind, and the default ----------------------------------------------


def test_a_blocking_kind_still_comes_back_as_an_error_result():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), SecretDouble(), egress=REDACT_PII_BLOCK_SECRETS)

    session = drive(
        relay,
        [_call(6)],
        records=records,
        responder=_server_replies(_tool_result(f"Clé {KEY} et carte {CARD}.")),
        expect_to_host=1,
    )

    result = as_response(session.to_host[0]).result
    assert result["isError"] is True
    assert KEY not in repr(result)
    assert CARD not in repr(result)
    assert records[-1]["mcp"]["action"] == "block"
    assert records[-1]["mcp"]["redaction"] is None


def test_without_a_declared_policy_an_outbound_finding_blocks():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble())  # no egress policy: the closed default

    session = drive(
        relay,
        [_call(7)],
        records=records,
        responder=_server_replies(_tool_result(f"Carte {CARD}.")),
        expect_to_host=1,
    )

    assert as_response(session.to_host[0]).result["isError"] is True
    assert records[-1]["mcp"]["action"] == "block"


def test_a_clean_response_crosses_unchanged_with_the_seam_wired():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    served = _tool_result("Solde 1 240,50 EUR.")

    session = drive(
        relay, [_call(8)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    assert as_response(session.to_host[0]).result == served
    assert records[-1]["mcp"]["action"] == "forward"
    assert records[-1]["mcp"]["redaction"] is None


# --- a method with no isError affordance ------------------------------------


def test_a_resources_read_result_is_masked_in_place_rather_than_erroring():
    records: list[dict[str, Any]] = []
    relay = _relay(records, PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    served = {"contents": [{"uri": "file:///statement.txt", "text": f"Carte {CARD}."}]}

    session = drive(
        relay, [_read(9)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    result = as_response(session.to_host[0]).result
    assert result["contents"][0]["text"] == "Carte [REDACTED:pii]."
    assert result["contents"][0]["uri"] == "file:///statement.txt"
    assert result["_meta"]["limes"]["redacted"] is True


def test_a_blocked_resources_read_is_still_a_json_rpc_error():
    records: list[dict[str, Any]] = []
    relay = _relay(records, SecretDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    served = {"contents": [{"uri": "file:///statement.txt", "text": f"Clé {KEY}."}]}

    session = drive(
        relay, [_read(10)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    error = as_error(session.to_host[0])
    assert error.error.code == -32001
    assert KEY not in repr(error.error)


def test_a_match_the_masking_cannot_reproduce_faithfully_blocks_instead_of_leaking():
    # This span straddles two separate strings of the payload, so overwriting it
    # leaf by leaf does not reproduce the plan applied to the flat content. The
    # relay re-derives the sanitised payload, sees the disagreement, and refuses:
    # an unverified redaction is not a redaction.
    records: list[dict[str, Any]] = []
    straddler = WholeContentDouble("premier\ndeuxieme", "pii:straddle")
    relay = _relay(records, straddler, egress=REDACT_PII_BLOCK_SECRETS)
    served = {"a": "premier", "b": "deuxieme"}

    session = drive(
        relay, [_read(11)], records=records, responder=_server_replies(served), expect_to_host=1
    )

    error = as_error(session.to_host[0])
    assert error.error.code == -32001
    assert "did not re-derive" in error.error.message
    assert records[-1]["mcp"]["action"] == "block"
