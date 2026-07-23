"""A real host, a real proxy process, a real server process (v0.2 DoD, ADR 0005).

Three claims, each proven against the wire rather than against a mock:

* **transparency** — the same host script against the server *directly* and
  *through the proxy* observes the same handshake, the same tool list, the same
  benign result, and the same server→host notification;
* **blocking** — an injection from the corpus, placed in a tool argument, comes
  back as ``isError: true`` with the evidence, and the server's own journal shows
  it never arrived. The control: unproxied, that same call *does* arrive;
* **the record** — ``--record`` writes the decisions, and they chain.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from limes.eval.corpus import CASE_08, load_attacks

SERVER = Path(__file__).resolve().parent / "journal_server.py"
BENIGN = "Quel est le solde de mon compte courant ?"


def _injection() -> str:
    attacks = [attack for attack in load_attacks() if attack.case_id == CASE_08]
    assert attacks, "the corpus must still carry case 08"
    return attacks[0].text


def _direct(journal: Path) -> list[str]:
    return [sys.executable, str(SERVER), str(journal)]


def _proxied(journal: Path, *, record: Path | None = None, extra: list[str] | None = None):
    options = ["--record", str(record)] if record is not None else []
    return [
        sys.executable,
        "-m",
        "limes.transports.mcp",
        *options,
        *(extra or []),
        "--",
        *_direct(journal),
    ]


def _session(command: list[str], calls: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """Run one host session and report everything it observed."""

    async def _run() -> dict[str, Any]:
        notifications: list[tuple[str, object]] = []

        async def logging_callback(params: types.LoggingMessageNotificationParams) -> None:
            notifications.append((params.level, params.data))

        parameters = StdioServerParameters(command=command[0], args=command[1:])
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            async with (
                stdio_client(parameters, errlog=quiet) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream, logging_callback=logging_callback) as (
                    session
                ),
            ):
                initialized = await session.initialize()
                tools = await session.list_tools()
                results = [await session.call_tool(name, arguments) for name, arguments in calls]
                # by_alias so the observation is what crossed the wire (`_meta`,
                # not the python field name) — the point is wire fidelity.
                return {
                    "initialize": initialized.model_dump(mode="json", by_alias=True),
                    "tools": tools.model_dump(mode="json", by_alias=True),
                    "results": [
                        result.model_dump(mode="json", by_alias=True) for result in results
                    ],
                    "notifications": notifications,
                }

    return anyio.run(_run)


def _journal(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --- transparency -----------------------------------------------------------


def test_a_proxied_session_is_indistinguishable_from_a_direct_one(tmp_path):
    calls = [("echo", {"text": BENIGN}), ("announce", {})]

    direct = _session(_direct(tmp_path / "direct.jsonl"), calls)
    proxied = _session(_proxied(tmp_path / "proxied.jsonl"), calls)

    assert proxied["initialize"] == direct["initialize"], (
        "the host must see the WRAPPED server's capabilities, name and version — "
        "the proxy answers nothing on its behalf"
    )
    assert proxied["tools"] == direct["tools"]
    assert proxied["results"] == direct["results"]
    assert (
        proxied["notifications"]
        == direct["notifications"]
        == [("info", "the wrapped server speaks")]
    ), "server->host notifications must cross the proxy too"

    assert _journal(tmp_path / "direct.jsonl") == _journal(tmp_path / "proxied.jsonl")


# --- blocking ---------------------------------------------------------------


def test_unproxied_the_injection_reaches_the_server(tmp_path):
    # The control. Without it, "the server never received it" could just mean
    # the call never happened.
    journal = tmp_path / "direct.jsonl"
    observed = _session(_direct(journal), [("echo", {"text": _injection()})])

    assert observed["results"][0]["isError"] is False
    assert [entry["arguments"]["text"] for entry in _journal(journal)] == [_injection()]


def test_proxied_the_injection_is_refused_and_the_server_never_receives_it(tmp_path):
    journal = tmp_path / "proxied.jsonl"
    record = tmp_path / "decisions.jsonl"
    observed = _session(
        _proxied(journal, record=record),
        [("echo", {"text": BENIGN}), ("echo", {"text": _injection()})],
    )

    benign, refused = observed["results"]
    assert benign["isError"] is False

    assert refused["isError"] is True, "a refusal is a tool result, not a transport error"
    text = refused["content"][0]["text"]
    assert "limes blocked this tool call" in text
    assert "injection:" in text, "the refusal names the rule that fired"
    assert refused["_meta"]["limes"]["evidence"]["matched_spans"], "…and carries the spans"

    seen = [entry["arguments"]["text"] for entry in _journal(journal)]
    assert seen == [BENIGN], f"the real server must never have seen the injection, saw: {seen}"


# --- the record -------------------------------------------------------------


def test_the_record_file_carries_the_decisions_and_they_chain(tmp_path):
    record = tmp_path / "decisions.jsonl"
    _session(
        _proxied(tmp_path / "proxied.jsonl", record=record),
        [("echo", {"text": BENIGN}), ("echo", {"text": _injection()})],
    )

    entries = [json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()]
    assert [entry["mcp"]["action"] for entry in entries] == ["forward", "block"]
    assert [entry["seq"] for entry in entries] == [0, 1]
    assert entries[0]["prev_hash"] == "0" * 64, "genesis is 64 zeros"
    assert entries[1]["prev_hash"] == entries[0]["digest"], "each record links to the last"
    assert all(entry["direction"] == "inbound" for entry in entries)
    assert all(entry["actor"] is None for entry in entries), (
        "no --actor was asserted, so the records name nobody"
    )


# --- fail-closed ------------------------------------------------------------


def test_the_on_cannot_say_flag_is_accepted_and_the_session_still_works(tmp_path):
    # What this proves is exactly its name: the flag is plumbed through the CLI
    # into a working session. The *behaviour* of CannotSay — blocked by default,
    # forwarded under `allow` — is proven in tests/unit/mcp/test_relay.py against
    # a simulated blind detector, because no shipped detector can be made blind
    # on demand and pretending otherwise would be the simulation this repo bans.
    observed = _session(
        _proxied(tmp_path / "proxied.jsonl", extra=["--on-cannot-say", "allow"]),
        [("echo", {"text": BENIGN})],
    )
    assert observed["results"][0]["isError"] is False


def test_an_unreadable_policy_stops_the_proxy_instead_of_running_unguarded(tmp_path):
    missing = tmp_path / "nope.yaml"
    result = subprocess.run(
        _proxied(tmp_path / "proxied.jsonl", extra=["--policy", str(missing)]),
        capture_output=True,
        text=True,
        input="",
        check=False,
    )
    assert result.returncode != 0, "a proxy that cannot load its policy must not start"
    assert "refused to start" in result.stderr or str(missing) in result.stderr
    assert _journal(tmp_path / "proxied.jsonl") == [], "…and must not have started the server"
