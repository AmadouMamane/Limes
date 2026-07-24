"""Egress redaction against real processes (ADR 0006 definition of done).

A real host session, a real proxy process, a real MCP server process, real stdio.
The claims, each with its control:

* **usable** — a response carrying a card number and an e-mail address comes back
  to the host as a *normal* tool result, masked in place, everything else intact.
  The control is the same call made **directly** against the server, which shows
  the server really does return the unmasked text;
* **per kind** — the same session, same policy: ``pii`` is masked, ``secret``
  blocks. Two dispositions, one policy file;
* **the default** — with no ``on_egress_finding`` declared, the same PII response
  is blocked. Masking is something an operator asks for;
* **the record** — ``--record`` shows the decision as a redaction, names the kinds
  and offsets, carries none of the masked text, and chains.

The proxy here is ``redacting_proxy.py``: :func:`limes.transports.mcp.bridge.serve`
with an outbound double installed, because limes ships no egress detector.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent
SERVER = HERE / "journal_server.py"
PROXY = HERE / "redacting_proxy.py"

CARD = "4111 1111 1111 1111"
EMAIL = "alice@example.com"
KEY = "sk-live-AB12cd34"
ANSWER = f"Carte {CARD} renvoyée, confirmation à {EMAIL}. Solde 1 240,50 EUR."
LEAKY = f"La clé du connecteur est {KEY}, ne la partagez pas."
CARD_ONLY = f"Votre carte se terminant par {CARD} a été débitée."

_RULES = (
    "rules:\n  - label: 'injection:never'\n    origin: limes\n    pattern: 'zzz-never-matches'\n"
)


def _policy(tmp_path: Path, egress: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(f"version: 1\n{egress}{_RULES}", encoding="utf-8")
    return path


def _direct(journal: Path) -> list[str]:
    return [sys.executable, str(SERVER), str(journal)]


def _proxied(journal: Path, *, policy: Path, record: Path | None = None) -> list[str]:
    options = ["--policy", str(policy)]
    if record is not None:
        options += ["--record", str(record)]
    return [sys.executable, str(PROXY), *options, "--", *_direct(journal)]


def _call(command: list[str], text: str) -> dict[str, Any]:
    """Run one real host session with one tool call, and report what came back."""

    async def _run() -> dict[str, Any]:
        parameters = StdioServerParameters(command=command[0], args=command[1:])
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            async with (
                stdio_client(parameters, errlog=quiet) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                result = await session.call_tool("echo", {"text": text})
                # by_alias so the observation is what crossed the wire (`_meta`).
                return dict(result.model_dump(mode="json", by_alias=True))

    return anyio.run(_run)


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _text(result: dict[str, Any]) -> str:
    return str(result["content"][0]["text"])


# --- the control ------------------------------------------------------------


def test_unproxied_the_server_really_returns_the_card_and_the_address(tmp_path):
    # Without this, "the host received no card number" could just mean the server
    # never sends one. It does.
    direct = _call(_direct(tmp_path / "direct.jsonl"), ANSWER)
    assert _text(direct) == ANSWER
    assert CARD in _text(direct)
    assert EMAIL in _text(direct)


# --- usable -----------------------------------------------------------------


def test_proxied_the_host_receives_a_normal_result_masked_in_place(tmp_path):
    policy = _policy(tmp_path, "on_egress_finding:\n  by_kind:\n    pii: redact\n")
    journal = tmp_path / "proxied.jsonl"

    result = _call(_proxied(journal, policy=policy), ANSWER)

    assert result["isError"] is False, "a masked response is a success, not an error"
    assert _text(result) == (
        "Carte [REDACTED:pii] renvoyée, confirmation à [REDACTED:pii]. Solde 1 240,50 EUR."
    )
    assert "1 240,50 EUR" in _text(result), "the useful part of the answer survives"
    crossed = json.dumps(result)
    assert CARD not in crossed, "nothing masked may appear anywhere in what crossed the wire"
    assert EMAIL not in crossed
    assert result["_meta"]["limes"]["redacted"] is True
    assert result["_meta"]["limes"]["redaction"]["kinds"] == ["pii"]

    journalled = _records(journal)
    assert journalled == [{"tool": "echo", "arguments": {"text": ANSWER}}], (
        "the outbound leg masks the response; it does not stop the call"
    )


# --- per kind, and the default ----------------------------------------------


def test_the_same_policy_masks_pii_and_blocks_secrets(tmp_path):
    policy = _policy(
        tmp_path,
        "on_egress_finding:\n  default: block\n  by_kind:\n    pii: redact\n    secret: block\n",
    )

    masked = _call(_proxied(tmp_path / "a.jsonl", policy=policy), ANSWER)
    blocked = _call(_proxied(tmp_path / "b.jsonl", policy=policy), LEAKY)

    assert masked["isError"] is False
    assert "[REDACTED:pii]" in _text(masked)

    assert blocked["isError"] is True, "a secret is worth losing the response over"
    assert KEY not in json.dumps(blocked)
    assert "secret" in _text(blocked)


def test_without_a_declared_policy_the_same_response_is_blocked(tmp_path):
    policy = _policy(tmp_path, "")

    result = _call(_proxied(tmp_path / "c.jsonl", policy=policy), ANSWER)

    assert result["isError"] is True, "masking is asked for; it is never the default"
    assert CARD not in json.dumps(result)


# --- mask style (ADR 0008) --------------------------------------------------


def test_the_last4_style_masks_the_card_in_place_over_stdio(tmp_path):
    policy = _policy(
        tmp_path,
        "on_egress_finding:\n  by_kind:\n    pii: redact\n  mask_style:\n    pii: last4\n",
    )

    result = _call(_proxied(tmp_path / "e.jsonl", policy=policy), CARD_ONLY)

    assert result["isError"] is False
    assert _text(result) == "Votre carte se terminant par ••••1111 a été débitée."
    assert CARD not in json.dumps(result), "the full PAN never leaves, only the last four"
    assert result["_meta"]["limes"]["redaction"]["spans"][0]["style"] == "last4", (
        "the style is recorded in the annotation"
    )


# --- the record -------------------------------------------------------------


def test_the_record_names_what_was_masked_and_still_says_deny(tmp_path):
    policy = _policy(tmp_path, "on_egress_finding:\n  by_kind:\n    pii: redact\n")
    record = tmp_path / "decisions.jsonl"

    _call(_proxied(tmp_path / "d.jsonl", policy=policy, record=record), ANSWER)

    entries = _records(record)
    assert [entry["mcp"]["action"] for entry in entries] == ["forward", "redact"]

    outbound = entries[-1]
    assert outbound["direction"] == "outbound"
    assert '"kind":"deny"' in outbound["verdict_fingerprint"], (
        "the content left the proxy, masked — the chain still records the refusal"
    )
    assert outbound["mcp"]["redaction"]["kinds"] == ["pii"]
    assert outbound["mcp"]["redaction"]["masked"] == 2
    assert [span["token"] for span in outbound["mcp"]["redaction"]["spans"]] == [
        "[REDACTED:pii]",
        "[REDACTED:pii]",
    ]
    logged = json.dumps(entries)
    assert CARD not in logged, "a decision log that quotes what it masked has not masked it"
    assert EMAIL not in logged
    assert outbound["prev_hash"] == entries[0]["digest"], "the decisions chain"
