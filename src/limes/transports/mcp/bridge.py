"""The bridge — a server to the host, a client to the real server, a relay between.

An MCP stdio server faces the host, an MCP stdio client faces the wrapped server,
and the relay in the middle carries the JSON-RPC both ways (ADR 0005).

**This module is the only one in limes that imports the MCP SDK.** It is reached
through the ``limes[mcp]`` extra; everything else in the package imports without
it.

What the relay does, message by message:

* ``tools/call`` (host → server) — the **inbound** leg. The arguments are
  flattened into text (:mod:`limes.transports.mcp.payload`), the core decides,
  and the ruling is either *forward* or *block*. A blocked call is **never
  forwarded**: the real server does not see it, and the host gets a
  ``CallToolResult`` with ``isError: true`` carrying the reason and the evidence.
* the *result* of a ``tools/call`` / ``resources/read`` (server → host) — the
  **outbound** leg. The seam is wired: it runs the same core pipeline over the
  response and enforces the same way. It is also **empty**, because limes ships
  no egress detector: with no outbound detector the relay passes the response
  through *untouched and unrecorded*. It deliberately does **not** call
  ``decide()`` over an empty detector list, because that returns an ``Allow``
  whose evidence names no witness — a pass that reads like a verdict. An
  unwatched leg is a blind spot, and it is declared in the README, not simulated
  here.
* **everything else** — ``initialize``, ``tools/list``, ``prompts/*``,
  capabilities, notifications, errors, unknown methods — is relayed byte-faithful
  in both directions, ids preserved. The host sees the wrapped server's real
  capabilities, not the proxy's.

The relay owns no protocol state of its own: it does not implement ``initialize``
and it does not answer on the server's behalf. That is what makes "identical to
direct" a testable claim rather than a hope.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any, Final

import anyio
import mcp.types as types
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

from limes.detector import Detector, Direction
from limes.detectors.injection import InjectionDetector
from limes.policy import load_injection_policy
from limes.record import DecisionRecord, Ledger
from limes.transports.in_process import Guard
from limes.transports.mcp.config import OnCannotSay, ProxyConfig
from limes.transports.mcp.decision import Action, Ruling, refusal_meta, refusal_text, rule
from limes.transports.mcp.payload import inspected_content, tool_call_arguments, tool_call_name
from limes.transports.mcp.sink import RecordSink, open_sink, record_entry

__all__ = [
    "BLOCKED_ERROR_CODE",
    "IncomingStream",
    "OutgoingStream",
    "Relay",
    "run",
    "serve",
    "utc_now_iso",
]

#: Messages read from a peer. The SDK pushes parse failures through as ``Exception``.
type IncomingStream = MemoryObjectReceiveStream[SessionMessage | Exception]
#: Messages written to a peer.
type OutgoingStream = MemoryObjectSendStream[SessionMessage]

#: JSON-RPC reserves -32000..-32099 for implementation-defined server errors. A
#: blocked ``tools/call`` never uses it (it gets an ``isError`` result); this is
#: only for a blocked response on a method that has no ``isError`` affordance.
BLOCKED_ERROR_CODE: Final = -32001

#: Requests whose *response* the outbound seam inspects.
_OUTBOUND_METHODS: Final = frozenset({"tools/call", "resources/read"})

_TOOLS_CALL: Final = "tools/call"


class _LinkClosed(Exception):
    """The peer went away mid-relay; the pump unwinds and the session ends."""


def utc_now_iso() -> str:
    """Return the current UTC instant as an ISO-8601 ``Z`` string.

    This is the transport's clock, injected into the core rather than read by it:
    :class:`limes.verdict.Evidence` takes ``observed_at`` as *data*, so a recorded
    session replays to the same digests (ADR 0002).

    Returns:
        e.g. ``"2026-07-23T09:41:07.123456Z"``.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class Relay:
    """The guarded relay between one host and one wrapped server.

    One pair, one process (v0.2 anti-scope). The relay holds a single
    :class:`~limes.record.Ledger`, so inbound and outbound decisions land on one
    chain in the order they were made.
    """

    def __init__(
        self,
        *,
        inbound: Sequence[Detector],
        outbound: Sequence[Detector] = (),
        policy_hash: str,
        on_cannot_say: OnCannotSay,
        actor: str | None,
        sink: RecordSink,
        clock: Callable[[], str] = utc_now_iso,
        ledger: Ledger | None = None,
    ) -> None:
        """Wire the relay.

        Args:
            inbound: Detectors run over ``tools/call`` arguments.
            outbound: Detectors run over guarded responses. **Empty in v0.2** —
                limes ships no egress detector. When empty, the outbound leg is
                a pure pass-through and emits no record.
            policy_hash: SHA-256 of the active policy, recorded into evidence.
            on_cannot_say: Fail-closed policy for a blind detector.
            actor: The identity asserted by the invoking session, or ``None``.
            sink: Where decision records are written.
            clock: Supplies ``observed_at``; injectable so a replay is exact.
            ledger: An existing chain to append to (a fresh one by default).
        """
        self._ledger = ledger if ledger is not None else Ledger()
        self._inbound_guard = Guard(inbound, policy_hash=policy_hash, ledger=self._ledger)
        # Constructed only when there is something to run. A Guard over zero
        # detectors would answer Allow with zero witnesses — the shape of a
        # false "ok" (ADR 0002). `None` is the honest encoding of "no egress
        # detector exists yet".
        self._outbound_guard = (
            Guard(outbound, policy_hash=policy_hash, ledger=self._ledger) if outbound else None
        )
        self._on_cannot_say = on_cannot_say
        self._actor = actor
        self._sink = sink
        self._clock = clock
        self._pending: dict[str | int, str] = {}

    @property
    def ledger(self) -> Ledger:
        """The chain every decision of this session was appended to."""
        return self._ledger

    @property
    def outbound_is_wired(self) -> bool:
        """Whether an egress detector is actually installed on the outbound leg."""
        return self._outbound_guard is not None

    async def run(
        self,
        host_read: IncomingStream,
        host_write: OutgoingStream,
        server_read: IncomingStream,
        server_write: OutgoingStream,
    ) -> None:
        """Pump both directions until either peer closes.

        Args:
            host_read: Messages arriving from the host.
            host_write: Messages to send to the host.
            server_read: Messages arriving from the wrapped server.
            server_write: Messages to send to the wrapped server.
        """
        async with anyio.create_task_group() as task_group:

            async def from_host() -> None:
                try:
                    async for item in host_read:
                        await self._on_host_message(item, host_write, server_write)
                except _LinkClosed:
                    pass
                finally:
                    task_group.cancel_scope.cancel()

            async def from_server() -> None:
                try:
                    async for item in server_read:
                        await self._on_server_message(item, host_write)
                except _LinkClosed:
                    pass
                finally:
                    task_group.cancel_scope.cancel()

            task_group.start_soon(from_host)
            task_group.start_soon(from_server)

    async def _on_host_message(
        self,
        item: SessionMessage | Exception,
        host_write: OutgoingStream,
        server_write: OutgoingStream,
    ) -> None:
        """Inspect a host→server message and forward it, or refuse it."""
        if isinstance(item, Exception):
            _note(f"unparseable message from the host, dropped: {item}")
            return

        message = item.message.root
        if isinstance(message, types.JSONRPCRequest):
            if message.method == _TOOLS_CALL:
                ruling, record = self._inspect_call(message)
                self._emit(
                    record,
                    method=_TOOLS_CALL,
                    tool=tool_call_name(message.params),
                    request_id=message.id,
                    action=ruling.action,
                )
                if ruling.action is Action.BLOCK:
                    await self._send(host_write, _blocked_tool_result(message.id, ruling, record))
                    return
            if message.method in _OUTBOUND_METHODS:
                self._pending[message.id] = message.method

        await self._send(server_write, item)

    async def _on_server_message(
        self, item: SessionMessage | Exception, host_write: OutgoingStream
    ) -> None:
        """Inspect a server→host message and forward it, or refuse it."""
        if isinstance(item, Exception):
            _note(f"unparseable message from the wrapped server, dropped: {item}")
            return

        message = item.message.root
        if isinstance(message, types.JSONRPCError):
            self._pending.pop(message.id, None)
        elif isinstance(message, types.JSONRPCResponse):
            method = self._pending.pop(message.id, None)
            # The outbound seam. Wired, and empty until an egress detector exists.
            if method is not None and self._outbound_guard is not None:
                ruling, record = self._inspect_result(message, self._outbound_guard)
                self._emit(
                    record,
                    method=method,
                    tool=None,
                    request_id=message.id,
                    action=ruling.action,
                )
                if ruling.action is Action.BLOCK:
                    await self._send(
                        host_write, _blocked_response(message.id, method, ruling, record)
                    )
                    return

        await self._send(host_write, item)

    def _inspect_call(self, message: types.JSONRPCRequest) -> tuple[Ruling, DecisionRecord]:
        """Run the inbound pipeline over a ``tools/call``'s arguments."""
        content = inspected_content(tool_call_arguments(message.params))
        verdict = self._inbound_guard.check(
            content,
            actor=self._actor,
            observed_at=self._clock(),
            direction=Direction.INBOUND,
        )
        # `check` is synchronous and appends exactly one record, so the last
        # record is this decision's — no await separates the two.
        return rule(verdict, on_cannot_say=self._on_cannot_say), self._ledger.records()[-1]

    def _inspect_result(
        self, message: types.JSONRPCResponse, guard: Guard
    ) -> tuple[Ruling, DecisionRecord]:
        """Run the outbound pipeline over a guarded response's result."""
        content = inspected_content(message.result)
        verdict = guard.check(
            content,
            actor=self._actor,
            observed_at=self._clock(),
            direction=Direction.OUTBOUND,
        )
        return rule(verdict, on_cannot_say=self._on_cannot_say), self._ledger.records()[-1]

    def _emit(
        self,
        record: DecisionRecord,
        *,
        method: str,
        tool: str | None,
        request_id: str | int | None,
        action: Action,
    ) -> None:
        """Write one decision to the sink."""
        self._sink.emit(
            record_entry(
                record,
                method=method,
                tool=tool,
                request_id=request_id,
                action=action.value,
            )
        )

    @staticmethod
    async def _send(stream: OutgoingStream, message: SessionMessage) -> None:
        """Send ``message``, unwinding the relay if the peer is gone."""
        try:
            await stream.send(message)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError) as exc:
            raise _LinkClosed(str(exc)) from exc


def _note(text: str) -> None:
    """Write one diagnostic line to stderr — never stdout, which is the host's channel."""
    print(f"limes-proxy: {text}", file=sys.stderr, flush=True)


def _wrap(message: types.JSONRPCResponse | types.JSONRPCError) -> SessionMessage:
    """Wrap a synthesised reply for the outbound stream."""
    return SessionMessage(types.JSONRPCMessage(message))


def _blocked_tool_result(
    request_id: str | int, ruling: Ruling, record: DecisionRecord
) -> SessionMessage:
    """Build the ``isError: true`` tool result a blocked ``tools/call`` gets.

    Args:
        request_id: The id of the refused request — preserved, so the host's
            pending call resolves instead of hanging.
        ruling: The blocking ruling.
        record: The chain record indexing the decision.

    Returns:
        A ``JSONRPCResponse`` carrying a ``CallToolResult`` marked ``isError``.
        Never a JSON-RPC error: an agent degrades on a failed tool result, and
        crashes on a transport error.
    """
    result = types.CallToolResult(
        content=[
            types.TextContent(type="text", text=refusal_text(ruling, record, subject="tool call"))
        ],
        isError=True,
        _meta=refusal_meta(ruling, record),
    )
    payload: dict[str, Any] = result.model_dump(by_alias=True, mode="json", exclude_none=True)
    return _wrap(types.JSONRPCResponse(jsonrpc="2.0", id=request_id, result=payload))


def _blocked_response(
    request_id: str | int, method: str, ruling: Ruling, record: DecisionRecord
) -> SessionMessage:
    """Build the reply that replaces a refused *response*.

    A refused ``tools/call`` result becomes an ``isError`` tool result, exactly
    like a refused call. Any other guarded method has no ``isError`` affordance,
    so the only refusal that does not lie about the content is a JSON-RPC error.

    Args:
        request_id: The id of the request whose response was refused.
        method: The method that response answered.
        ruling: The blocking ruling.
        record: The chain record indexing the decision.

    Returns:
        The message to send to the host in place of the server's response.
    """
    if method == _TOOLS_CALL:
        return _blocked_tool_result(request_id, ruling, record)
    return _wrap(
        types.JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=types.ErrorData(
                code=BLOCKED_ERROR_CODE,
                message=refusal_text(ruling, record, subject=f"{method} result"),
                data=refusal_meta(ruling, record),
            ),
        )
    )


async def serve(
    config: ProxyConfig,
    *,
    sink: RecordSink | None = None,
    clock: Callable[[], str] = utc_now_iso,
) -> Ledger:
    """Run the proxy on this process's stdio until the host disconnects.

    Args:
        config: The invocation — the wrapped server's command, the policy, the
            record sink, the fail-closed setting, and the asserted actor.
        sink: Override the sink (tests, embedders). Defaults to the one
            ``config`` asks for: stderr, or ``--record``'s file.
        clock: Override the clock (replay). Defaults to UTC now.

    Returns:
        The session's decision chain.
    """
    policy = load_injection_policy(config.policy_path)
    owned_sink = sink if sink is not None else open_sink(config.record_path)
    relay = Relay(
        inbound=(InjectionDetector(policy),),
        # v0.2 ships no egress detector; the seam stays empty rather than
        # pretending. See this module's docstring.
        outbound=(),
        policy_hash=policy.policy_hash,
        on_cannot_say=config.on_cannot_say,
        actor=config.actor,
        sink=owned_sink,
        clock=clock,
    )
    parameters = StdioServerParameters(
        command=config.server_command[0],
        args=list(config.server_command[1:]),
    )
    try:
        async with (
            stdio_server() as (host_read, host_write),
            stdio_client(parameters) as (server_read, server_write),
        ):
            await relay.run(host_read, host_write, server_read, server_write)
    finally:
        if sink is None:
            owned_sink.close()
    return relay.ledger


def run(config: ProxyConfig) -> None:
    """Run :func:`serve` to completion on a fresh event loop.

    Args:
        config: The invocation to run.
    """
    anyio.run(serve, config)
