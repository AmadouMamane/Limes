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
  response and enforces the same way, with one behaviour of its own — under a
  redacting egress policy a refusal is *masked and forwarded* rather than
  blocked (ADR 0006). The masked result is a **normal** result: the matched
  offsets read ``[REDACTED:<kind>]``, everything else is the server's own bytes,
  and ``_meta`` says what was masked. The masking is verified before it is sent:
  the sanitised payload is re-derived and compared to the plan applied to the
  flat content, and a disagreement blocks. It is also **empty**, because limes ships
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
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, final

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
from limes.transports.mcp.decision import (
    Action,
    Ruling,
    redaction_meta,
    refusal_meta,
    refusal_text,
    rule,
)
from limes.transports.mcp.payload import (
    inspected_content,
    redact_payload,
    tool_call_arguments,
    tool_call_name,
)
from limes.transports.mcp.sink import RecordSink, open_sink, record_entry
from limes.transports.redaction import (
    EgressPolicy,
    RedactEgress,
    Redaction,
    apply_masking,
    conceals_all,
    rule_egress,
)
from limes.verdict import Deny

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


@final
@dataclass(frozen=True, slots=True)
class _Screening:
    """What the outbound seam decided about one response.

    Attributes:
        action: What the relay did — forward, redact, or block.
        record: The chain record the decision produced.
        replacement: The message to send instead of the server's, or ``None`` to
            send the server's own. A masked forward is a *replacement*: it is not
            the bytes the server sent.
        redaction: The masking plan, present exactly when ``action`` is ``REDACT``.
    """

    action: Action
    record: DecisionRecord
    replacement: SessionMessage | None
    redaction: Redaction | None


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
        egress: EgressPolicy | None = None,
    ) -> None:
        """Wire the relay.

        Args:
            inbound: Detectors run over ``tools/call`` arguments.
            outbound: Detectors run over guarded responses. **Empty in the shipped
                proxy** — limes ships no egress detector. When empty, the outbound
                leg is a pure pass-through and emits no record.
            policy_hash: SHA-256 of the active policy, recorded into evidence.
            on_cannot_say: Fail-closed policy for a blind detector.
            actor: The identity asserted by the invoking session, or ``None``.
            sink: Where decision records are written.
            clock: Supplies ``observed_at``; injectable so a replay is exact.
            ledger: An existing chain to append to (a fresh one by default).
            egress: What to do with an outbound finding. ``None`` means block
                everything, which is what an operator who has said nothing gets.
        """
        self._ledger = ledger if ledger is not None else Ledger()
        self._egress = egress if egress is not None else EgressPolicy.blocking()
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
                    redaction=None,
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
                screening = self._screen_result(message, method=method, guard=self._outbound_guard)
                self._emit(
                    screening.record,
                    method=method,
                    tool=None,
                    request_id=message.id,
                    action=screening.action,
                    redaction=screening.redaction,
                )
                if screening.replacement is not None:
                    await self._send(host_write, screening.replacement)
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

    def _screen_result(
        self, message: types.JSONRPCResponse, *, method: str, guard: Guard
    ) -> _Screening:
        """Run the outbound pipeline over a guarded response's result.

        Args:
            message: The server's response.
            method: The method it answers — a refused ``tools/call`` result gets
                an ``isError`` result, anything else a JSON-RPC error.
            guard: The outbound guard (never ``None`` here: the caller checked).

        Returns:
            The action, its chain record, the message that replaces the server's
            (``None`` to forward it as it stands), and the masking plan if one
            was applied.
        """
        content = inspected_content(message.result)
        verdict = guard.check(
            content,
            actor=self._actor,
            observed_at=self._clock(),
            direction=Direction.OUTBOUND,
        )
        record = self._ledger.records()[-1]

        if isinstance(verdict, Deny):
            egress = rule_egress(verdict, policy=self._egress, content_length=len(content))
            if isinstance(egress, RedactEgress):
                masked = _masked_response(message, content, egress, verdict, record)
                if masked is not None:
                    return _Screening(
                        action=Action.REDACT,
                        record=record,
                        replacement=masked,
                        redaction=egress.redaction,
                    )
                # The masking did not come out as planned. Nobody knows what the
                # payload would carry, so nothing leaves: the fallback of a
                # failed redaction is the refusal it was standing in for.
                _note(
                    "the masking could not be applied faithfully to the payload; blocking instead "
                    f"of forwarding (record {record.digest})"
                )
                unfaithful = Ruling(
                    action=Action.BLOCK,
                    verdict=verdict,
                    reason=(
                        f"{egress.reason} — but the masked payload did not re-derive to the "
                        "planned content, so limes blocked it instead"
                    ),
                )
                return _Screening(
                    action=Action.BLOCK,
                    record=record,
                    replacement=_blocked_response(message.id, method, unfaithful, record),
                    redaction=None,
                )
            blocked = Ruling(action=Action.BLOCK, verdict=verdict, reason=egress.reason)
            return _Screening(
                action=Action.BLOCK,
                record=record,
                replacement=_blocked_response(message.id, method, blocked, record),
                redaction=None,
            )

        ruling = rule(verdict, on_cannot_say=self._on_cannot_say)
        if ruling.action is Action.BLOCK:
            return _Screening(
                action=Action.BLOCK,
                record=record,
                replacement=_blocked_response(message.id, method, ruling, record),
                redaction=None,
            )
        return _Screening(action=Action.FORWARD, record=record, replacement=None, redaction=None)

    def _emit(
        self,
        record: DecisionRecord,
        *,
        method: str,
        tool: str | None,
        request_id: str | int | None,
        action: Action,
        redaction: Redaction | None,
    ) -> None:
        """Write one decision to the sink."""
        self._sink.emit(
            record_entry(
                record,
                method=method,
                tool=tool,
                request_id=request_id,
                action=action.value,
                redaction=None if redaction is None else redaction.annotation(),
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


def _masked_response(
    message: types.JSONRPCResponse,
    content: str,
    egress: RedactEgress,
    verdict: Deny,
    record: DecisionRecord,
) -> SessionMessage | None:
    """Build the masked result that replaces a refused response (ADR 0006).

    The result stays a **normal** result — no ``isError``, no JSON-RPC error. The
    host's tool call succeeds; the matched regions read ``[REDACTED:<kind>]`` and
    ``_meta`` carries what was masked, where, and under which chain record.

    The masking is then *checked* rather than trusted: the sanitised payload is
    put back through the very derivation the offsets came from, and compared to
    the plan applied to the flat content. They agree when every masked region sat
    inside a single string; they disagree if a match straddled two strings, or if
    the two walks ever drift apart. A disagreement means the payload is not what
    the plan says it is, and an unverified redaction is not a redaction.

    Args:
        message: The server's response.
        content: The inspected content the offsets index into.
        egress: The redacting ruling — its plan, and the reason to annotate with.
        verdict: The outbound ``Deny`` being masked.
        record: The chain record indexing the decision.

    Returns:
        The replacement message, or ``None`` when the masking could not be
        verified — the caller then blocks.
    """
    redaction = egress.redaction
    if not conceals_all(content, redaction):
        # A styled mask (last4, format_preserving) that left the sensitive value
        # recoverable is no mask at all (ADR 0008). Fall closed to the block it
        # was standing in for, rather than forward it.
        return None
    sanitised = redact_payload(message.result, redaction)
    if not isinstance(sanitised, dict):
        return None
    if inspected_content(sanitised) != apply_masking(content, redaction):
        return None

    result: dict[str, Any] = dict(sanitised)
    existing = result.get("_meta")
    meta: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    meta.update(redaction_meta(verdict, record, redaction, reason=egress.reason))
    result["_meta"] = meta
    return _wrap(types.JSONRPCResponse(jsonrpc="2.0", id=message.id, result=result))


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
    outbound: Sequence[Detector] = (),
) -> Ledger:
    """Run the proxy on this process's stdio until the host disconnects.

    Args:
        config: The invocation — the wrapped server's command, the policy, the
            record sink, the fail-closed setting, and the asserted actor.
        sink: Override the sink (tests, embedders). Defaults to the one
            ``config`` asks for: stderr, or ``--record``'s file.
        clock: Override the clock (replay). Defaults to UTC now.
        outbound: Detectors for the outbound leg. **Empty by default, and the
            console entry point never passes any** — limes ships no egress
            detector. It is a parameter so an embedder with one of their own can
            install it (and so the egress behaviour can be proven end to end
            against a real process, which is how ADR 0006 is evidenced).

    Returns:
        The session's decision chain.
    """
    policy = load_injection_policy(config.policy_path)
    owned_sink = sink if sink is not None else open_sink(config.record_path)
    relay = Relay(
        inbound=(InjectionDetector(policy),),
        outbound=outbound,
        policy_hash=policy.policy_hash,
        on_cannot_say=config.on_cannot_say,
        actor=config.actor,
        sink=owned_sink,
        clock=clock,
        egress=config.egress,
    )
    if config.egress.redacts_anything() and not relay.outbound_is_wired:
        # A setting that governs nothing must say so. limes ships no egress
        # detector, so the outbound leg observes nothing and there is nothing to
        # mask — the operator asked for a behaviour this process cannot exhibit.
        _note(
            "on_egress_finding asks for masking, but no egress detector is installed: the "
            "outbound leg inspects nothing, so nothing will be masked. The setting is live for "
            "embedders who wire their own outbound detectors into Relay."
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
