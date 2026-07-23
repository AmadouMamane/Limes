"""Drive a Relay over in-memory streams, with a scripted server on the far side.

The relay is transport-shaped but stream-agnostic: it reads and writes
``SessionMessage``. So a test can hold both ends and observe exactly what crossed
— in particular, what the *real server* did and did not receive, which is the
only way to prove a blocked call never reached it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import anyio
import mcp.types as types
from mcp.shared.message import SessionMessage

from limes.detector import Context, Detector, DetectorBlind, Direction, Finding
from limes.record import DecisionRecord
from limes.spans import redact
from limes.transports.mcp.bridge import Relay

AnyMessage = (
    types.JSONRPCRequest | types.JSONRPCNotification | types.JSONRPCResponse | types.JSONRPCError
)
Responder = Callable[[AnyMessage], AnyMessage | None]

FIXED_CLOCK = "2026-07-23T00:00:00Z"


def fixed_clock() -> str:
    """A clock that never moves, so a replay re-derives the same digests."""
    return FIXED_CLOCK


class BlindDetector:
    """A test double that always refuses to look, producing ``CannotSay``.

    Not a shipped detector: it exists to exercise the fail-closed path, which is
    otherwise unreachable while every real detector can see.
    """

    id = "blind-double"
    version = "0.0.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        raise DetectorBlind("simulated blindness: this double never looks")


class EgressDouble:
    """A test double for the *outbound* leg. limes ships no egress detector.

    It exists only to prove the outbound seam is really wired — that a detector
    installed there is run and enforced — not to stand in for a product feature.
    """

    id = "egress-double"
    version = "0.0.0"
    marker = "SECRET-CANARY"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        if direction is not Direction.OUTBOUND:
            return []
        start = content.find(self.marker)
        if start < 0:
            return []
        return [
            Finding(
                detector_id=self.id,
                label="egress:double",
                spans=(redact(content, start, start + len(self.marker), "egress:double"),),
            )
        ]


@dataclass
class Session:
    """What crossed the relay during one driven session."""

    to_host: list[AnyMessage] = field(default_factory=list)
    to_server: list[AnyMessage] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)

    def digests(self) -> list[str]:
        """The chain digests, in order, as the sink saw them."""
        return [str(entry["digest"]) for entry in self.records]

    def server_saw_tool_call(self, name: str) -> bool:
        """Whether the wrapped server received a ``tools/call`` for ``name``."""
        return any(
            isinstance(message, types.JSONRPCRequest)
            and message.method == "tools/call"
            and (message.params or {}).get("name") == name
            for message in self.to_server
        )


class CollectingSink:
    """A sink that keeps the records instead of writing them."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def emit(self, entry: Mapping[str, object]) -> None:
        self._records.append(dict(entry))

    def close(self) -> None:
        return


def as_response(message: AnyMessage) -> types.JSONRPCResponse:
    """Narrow to a JSON-RPC *result* — and assert it is one, which is the claim."""
    assert isinstance(message, types.JSONRPCResponse), (
        f"expected a JSON-RPC result, got {type(message).__name__}"
    )
    return message


def as_error(message: AnyMessage) -> types.JSONRPCError:
    """Narrow to a JSON-RPC error — and assert it is one."""
    assert isinstance(message, types.JSONRPCError), (
        f"expected a JSON-RPC error, got {type(message).__name__}"
    )
    return message


def echo_responder(message: AnyMessage) -> AnyMessage | None:
    """Reply to any request with a benign ``CallToolResult``-shaped result."""
    if not isinstance(message, types.JSONRPCRequest):
        return None
    return types.JSONRPCResponse(
        jsonrpc="2.0",
        id=message.id,
        result={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )


def make_relay(
    *,
    inbound: Sequence[Detector],
    outbound: Sequence[Detector] = (),
    policy_hash: str,
    on_cannot_say: object,
    records: list[dict[str, Any]],
    actor: str | None = "session-under-test",
) -> Relay:
    """Build a relay wired to a collecting sink and a frozen clock."""
    from limes.transports.mcp.config import OnCannotSay

    return Relay(
        inbound=inbound,
        outbound=outbound,
        policy_hash=policy_hash,
        on_cannot_say=on_cannot_say if isinstance(on_cannot_say, OnCannotSay) else OnCannotSay.DENY,
        actor=actor,
        sink=CollectingSink(records),
        clock=fixed_clock,
    )


def drive(
    relay: Relay,
    messages: Sequence[AnyMessage],
    *,
    records: list[dict[str, Any]],
    responder: Responder = echo_responder,
    expect_to_host: int,
    timeout: float = 5.0,
) -> Session:
    """Push ``messages`` through ``relay`` and collect both sides.

    Args:
        relay: The relay under test.
        messages: Host→server messages, sent in order.
        records: The list the relay's sink appends to.
        responder: What the scripted server replies with, per message.
        expect_to_host: How many messages the host should receive before the
            session is closed — the driver waits for them rather than racing.
        timeout: Seconds to wait for those messages.

    Returns:
        The session: what the host saw, what the server saw, and the records.
    """
    session = Session(records=records)

    async def _run() -> None:
        host_send, host_read = anyio.create_memory_object_stream[SessionMessage | Exception](64)
        host_write, host_out = anyio.create_memory_object_stream[SessionMessage](64)
        server_write, server_in = anyio.create_memory_object_stream[SessionMessage](64)
        server_send, server_read = anyio.create_memory_object_stream[SessionMessage | Exception](64)

        async def scripted_server() -> None:
            async for item in server_in:
                session.to_server.append(item.message.root)
                reply = responder(item.message.root)
                if reply is not None:
                    await server_send.send(SessionMessage(types.JSONRPCMessage(reply)))

        async def host_collector() -> None:
            async for item in host_out:
                session.to_host.append(item.message.root)

        async with anyio.create_task_group() as workers:
            workers.start_soon(scripted_server)
            workers.start_soon(host_collector)

            async def driver() -> None:
                for message in messages:
                    await host_send.send(SessionMessage(types.JSONRPCMessage(message)))
                if expect_to_host:
                    with anyio.fail_after(timeout):
                        while len(session.to_host) < expect_to_host:
                            await anyio.sleep(0.002)
                await host_send.aclose()

            async with anyio.create_task_group() as inner:
                inner.start_soon(driver)
                await relay.run(host_read, host_write, server_read, server_write)

            await host_write.aclose()
            await server_write.aclose()
            await server_send.aclose()

    anyio.run(_run)
    return session


def last_record(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The most recent emitted record."""
    return records[-1]


def chain_of(relay: Relay) -> list[DecisionRecord]:
    """The relay's ledger records."""
    return list(relay.ledger.records())
