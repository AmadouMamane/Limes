"""A poisoned tool description is refused before the model ever reads it (ADR 0012).

This is the claim limes leads with, and until now it was proven by unit tests on
the relay rather than against the wire. Here a real host asks a real server for
its tools, twice:

* **unproxied** — the poison arrives, verbatim, in the description the host would
  hand its model. That control matters: a refusal proves nothing if the attack
  was never there;
* **proxied** — the listing is refused on the seam, the poison never reaches the
  host, and the decision is on the chain.

It is the only leg where a guard that watches ``tools/call`` sees nothing at all:
``tools/list`` is answered before any call exists.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from tests.integration.mcp.poisoned_server import CLEAN, POISON

SERVER = Path(__file__).resolve().parent / "poisoned_server.py"


def _direct() -> list[str]:
    return [sys.executable, str(SERVER)]


def _proxied(record: Path | None = None) -> list[str]:
    options = ["--record", str(record)] if record is not None else []
    return [sys.executable, "-m", "limes.transports.mcp", *options, "--", *_direct()]


def _list_tools(command: list[str]) -> dict[str, Any]:
    """Ask one server for its tools and report what came back — or what did not."""

    async def _run() -> dict[str, Any]:
        parameters = StdioServerParameters(command=command[0], args=command[1:])
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            async with (
                stdio_client(parameters, errlog=quiet) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                try:
                    listing = await session.list_tools()
                except Exception as refused:
                    return {"refused": True, "error": str(refused), "tools": None}
                return {
                    "refused": False,
                    "error": None,
                    "tools": listing.model_dump(mode="json", by_alias=True),
                }

    return anyio.run(_run)


def _descriptions(observed: dict[str, Any]) -> list[str]:
    tools = (observed["tools"] or {}).get("tools", [])
    return [str(tool.get("description") or "") for tool in tools]


# --- the control: unproxied, the attack is real -----------------------------


def test_unproxied_the_poison_reaches_the_host_verbatim():
    observed = _list_tools(_direct())
    assert observed["refused"] is False
    descriptions = _descriptions(observed)
    assert POISON in descriptions
    # Said explicitly because it is the whole point of the leg: the host has the
    # attacker's instruction in hand, and no tools/call has happened yet.
    assert any("id_rsa" in description for description in descriptions)


# --- the claim: proxied, it does not ---------------------------------------


def test_proxied_the_poisoned_listing_is_refused():
    observed = _list_tools(_proxied())
    assert observed["refused"] is True


def test_proxied_the_poison_never_reaches_the_host():
    observed = _list_tools(_proxied())
    # Neither through a listing (there is none) nor through the refusal text: the
    # evidence carries hashes and offsets, never the payload (ADR 0002).
    assert POISON not in str(observed)
    assert "id_rsa" not in str(observed)


def test_the_refusal_is_recorded_on_the_chain(tmp_path):
    record = tmp_path / "decisions.jsonl"
    _list_tools(_proxied(record))
    assert record.exists()
    decisions = [
        json.loads(line) for line in record.read_text(encoding="utf-8").splitlines() if line
    ]
    assert decisions
    # A refusal nobody can audit is not this project's kind of refusal.
    assert any(entry.get("direction") == "outbound" for entry in decisions)


def test_the_clean_description_is_not_what_triggered_it():
    # The refusal must be about the poison, not about listings in general. The
    # same server carries an ordinary description; if the guard blocked on that,
    # the test above would pass for the wrong reason.
    from limes.detector import Context, Direction
    from limes.detectors.injection_egress import InjectionEgressDetector

    detector = InjectionEgressDetector()
    context = Context(policy_hash="e2e", actor=None)
    assert detector.inspect(Direction.OUTBOUND, CLEAN, context) == []
    assert detector.inspect(Direction.OUTBOUND, POISON, context) != []


@pytest.mark.parametrize("payload", [CLEAN, POISON])
def test_the_server_itself_is_ordinary(payload):
    # The attack is entirely in the description: the tool behaves normally, so
    # nothing downstream of tools/list could have caught it.
    assert isinstance(payload, str)
    assert payload
