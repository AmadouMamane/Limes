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
  A ``tools/call`` carrying no ``id`` — a *notification*, which MCP does not
  define for that method — is judged exactly the same way and, when refused,
  dropped, because there is no id to answer (ADR 0024). Before ADR 0024 it
  crossed uninspected and unrecorded.
* the *result* of a ``tools/call`` / ``resources/read`` / ``tools/list`` /
  ``prompts/get`` (server → host) — the **outbound** leg. The seam runs the same
  core pipeline over the response and enforces the same way, with one behaviour
  of its own — under a redacting egress policy a refusal is *masked and
  forwarded* rather than blocked (ADR 0006). The masked result is a **normal**
  result: the matched offsets read ``[REDACTED:<kind>]``, everything else is the
  server's own bytes, and ``_meta`` says what was masked. The masking is
  verified before it is sent: the sanitised payload is re-derived and compared
  to the plan applied to the flat content, and a disagreement blocks.
  ``tools/list`` is guarded because a poisoned tool description reaches the
  model through it (ADR 0012); ``prompts/get`` because a prompt's messages go
  straight into the model's context (ADR 0024). When a deployment wires **no**
  outbound detector the relay passes the response through *untouched and
  unrecorded*: it deliberately does **not** call ``decide()`` over an empty
  detector list, because that returns an ``Allow`` whose evidence names no
  witness — a pass that reads like a verdict. An unwatched leg is a blind spot,
  declared rather than simulated.
* ``sampling/createMessage`` and ``elicitation/create`` (server → host
  **requests**) — the same outbound leg, because their parameters are content
  the host's model or user reads (ADR 0024). A refusal is a JSON-RPC error
  answered to the *server*, which asked; redaction does not apply to a request,
  so any finding blocks.
* **everything else** — ``initialize``, ``prompts/list``, ``resources/list``,
  capabilities, notifications, errors, unknown methods — is relayed
  byte-faithful in both directions, ids preserved, with one reservation: the
  relay owns the ``limes`` key of a result's ``_meta``. A wrapped server that
  sends one has it moved to ``limes-upstream`` before the host sees it, so a
  forged annotation cannot pass for the relay's own (ADR 0024). The host sees
  the wrapped server's real capabilities, not the proxy's.

Every decision is sealed with its **disposition** (ADR 0025): the record says
``forward``, ``redact`` or ``block`` inside the hashed core, so the chain proves
what left and not only what was refused.

The relay owns no protocol state of its own: it does not implement ``initialize``
and it does not answer on the server's behalf. That is what makes "identical to
direct" a testable claim rather than a hope. It remembers which guarded requests
await a response, and refuses — closed, on the chain — rather than forget when
that table fills: a forgotten request's response would cross unscreened.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping, Sequence
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
from limes.detectors import ADMITTED
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
from limes.verdict import CannotSay, Deny

__all__ = [
    "BLOCKED_ERROR_CODE",
    "GUARDED_SERVER_REQUESTS",
    "OUTBOUND_METHODS",
    "PENDING_LIMIT",
    "UPSTREAM_META_KEY",
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
#: only for a blocked response on a method that has no ``isError`` affordance,
#: and for a blocked server→host request, answered to the server that asked.
BLOCKED_ERROR_CODE: Final = -32001

#: Requests whose *response* the outbound seam inspects. ``tools/list`` is here
#: because a poisoned tool description reaches the model through it (ADR 0012);
#: ``prompts/get`` because the messages it returns go straight into the model's
#: context (ADR 0024). The canonical payload walk already reaches every string,
#: so no special-casing is needed beyond guarding the method.
OUTBOUND_METHODS: Final = frozenset({"tools/call", "resources/read", "tools/list", "prompts/get"})

#: Requests the SERVER sends the host whose parameters the host's model or user
#: reads: a sampling request carries the messages the model is asked to
#: complete, an elicitation carries the text shown to the user (ADR 0024).
GUARDED_SERVER_REQUESTS: Final = frozenset({"sampling/createMessage", "elicitation/create"})

#: How many guarded requests may await a response at once. Beyond it the relay
#: refuses the next one — closed, on the chain — rather than forget the oldest,
#: whose response would then cross unscreened. A wrapped server that leaves this
#: many requests unanswered in one session is not answering at all.
PENDING_LIMIT: Final = 4096

#: The ``_meta`` key the relay writes its annotation under, and the key an
#: upstream value found there is moved to (ADR 0024).
LIMES_META_KEY: Final = "limes"
UPSTREAM_META_KEY: Final = "limes-upstream"

_META: Final = "_meta"
_TOOLS_CALL: Final = "tools/call"


def outbound_detectors() -> tuple[Detector, ...]:
    """The admitted detectors that guard the outbound leg (ADR 0018).

    Derived from :data:`limes.detectors.ADMITTED` rather than listed here, so a
    detector admitted tomorrow reaches this transport without anybody
    remembering to come back. A test pins what the derivation currently yields,
    so it cannot quietly select nothing.

    Returns:
        One instance of each admitted egress detector, in admission order.
    """
    return tuple(cls() for cls in ADMITTED if str(cls.id).endswith("-egress"))


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
            outbound: Detectors run over guarded responses and guarded
                server→host requests. The shipped proxies install every admitted
                egress detector here via :func:`outbound_detectors` (ADR 0018);
                an empty sequence is a deliberately unguarded leg — a pure
                pass-through that emits no record, which the transparency tests
                use to prove exact pass-through.
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
                        await self._on_server_message(item, host_write, server_write)
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
                ruling, record = self._inspect_call(message.params)
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
            if message.method in OUTBOUND_METHODS and not self._remember(
                message.id, message.method
            ):
                # The table of unanswered guarded requests is full. Forgetting
                # one would let its response cross unscreened; refusing this
                # one is closed, and it is on the chain like any refusal.
                ruling, record = self._refuse_unscreenable(message.method)
                self._emit(
                    record,
                    method=message.method,
                    tool=tool_call_name(message.params),
                    request_id=message.id,
                    action=ruling.action,
                    redaction=None,
                )
                await self._send(
                    host_write, _blocked_response(message.id, message.method, ruling, record)
                )
                return
        elif isinstance(message, types.JSONRPCNotification) and message.method == _TOOLS_CALL:
            # MCP defines tools/call as a request; a notification-shaped one has
            # no id to answer. It is judged like any call (ADR 0024) — an
            # uninspected path to the server would be a hole with a spelling.
            ruling, record = self._inspect_call(message.params)
            self._emit(
                record,
                method=_TOOLS_CALL,
                tool=tool_call_name(message.params),
                request_id=None,
                action=ruling.action,
                redaction=None,
            )
            if ruling.action is Action.BLOCK:
                _note(
                    f"a tools/call notification (no id) was refused and dropped — "
                    f"{ruling.reason} (record {record.digest})"
                )
                return

        await self._send(server_write, item)

    async def _on_server_message(
        self,
        item: SessionMessage | Exception,
        host_write: OutgoingStream,
        server_write: OutgoingStream,
    ) -> None:
        """Inspect a server→host message and forward it, or refuse it."""
        if isinstance(item, Exception):
            _note(f"unparseable message from the wrapped server, dropped: {item}")
            return

        message = item.message.root
        if isinstance(message, types.JSONRPCError):
            self._pending.pop(message.id, None)
        elif isinstance(message, types.JSONRPCRequest):
            # A request the SERVER makes of the host: its params are what the
            # host's model or user will read, so they cross the outbound seam
            # too (ADR 0024). A refusal is answered to the server, which asked.
            if message.method in GUARDED_SERVER_REQUESTS and self._outbound_guard is not None:
                ruling, record = self._screen_server_request(
                    message.params, guard=self._outbound_guard
                )
                self._emit(
                    record,
                    method=message.method,
                    tool=None,
                    request_id=message.id,
                    action=ruling.action,
                    redaction=None,
                )
                if ruling.action is Action.BLOCK:
                    await self._send(
                        server_write,
                        _blocked_server_request(message.id, message.method, ruling, record),
                    )
                    return
        elif isinstance(message, types.JSONRPCResponse):
            method = self._pending.pop(message.id, None)
            # The outbound seam: wired when an egress detector is installed.
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
            reserved = _reserve_meta(message)
            if reserved is not None:
                await self._send(host_write, reserved)
                return

        await self._send(host_write, item)

    def _remember(self, request_id: str | int, method: str) -> bool:
        """Note that ``request_id``'s response must be screened; ``False`` when full."""
        if len(self._pending) >= PENDING_LIMIT:
            return False
        self._pending[request_id] = method
        return True

    def _refuse_unscreenable(self, method: str) -> tuple[Ruling, DecisionRecord]:
        """Refuse a guarded request whose response the relay could not promise to screen."""
        verdict = CannotSay(
            blind_spot=(
                f"the relay is holding {PENDING_LIMIT} guarded requests the wrapped server has "
                f"not answered, so it cannot promise to screen the response to this {method}"
            )
        )
        ruling = Ruling(
            action=Action.BLOCK,
            verdict=verdict,
            reason=f"the guard could not look: {verdict.blind_spot}",
        )
        record = self._ledger.append(
            Direction.OUTBOUND, verdict, self._actor, disposition=ruling.action.value
        )
        return ruling, record

    def _inspect_call(self, params: Mapping[str, Any] | None) -> tuple[Ruling, DecisionRecord]:
        """Run the inbound pipeline over a ``tools/call``'s arguments and seal the ruling."""
        content = inspected_content(tool_call_arguments(params))
        verdict = self._inbound_guard.verdict(
            content,
            actor=self._actor,
            observed_at=self._clock(),
            direction=Direction.INBOUND,
        )
        ruling = rule(verdict, on_cannot_say=self._on_cannot_say)
        record = self._inbound_guard.record(
            Direction.INBOUND, verdict, self._actor, disposition=ruling.action.value
        )
        return ruling, record

    def _screen_server_request(
        self, params: Mapping[str, Any] | None, *, guard: Guard
    ) -> tuple[Ruling, DecisionRecord]:
        """Run the outbound pipeline over a server→host request's parameters.

        Redaction is a behaviour for *results* (ADR 0006); a request that trips
        a detector is refused whatever the egress policy says about its kind.
        """
        content = inspected_content(params)
        verdict = guard.verdict(
            content,
            actor=self._actor,
            observed_at=self._clock(),
            direction=Direction.OUTBOUND,
        )
        ruling = rule(verdict, on_cannot_say=self._on_cannot_say)
        record = guard.record(
            Direction.OUTBOUND, verdict, self._actor, disposition=ruling.action.value
        )
        return ruling, record

    def _screen_result(
        self, message: types.JSONRPCResponse, *, method: str, guard: Guard
    ) -> _Screening:
        """Run the outbound pipeline over a guarded response's result.

        The disposition is decided *before* the record is sealed, so the chain
        carries what actually happened — including a masking that could not be
        verified and fell back to a block (ADR 0025).

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
        verdict = guard.verdict(
            content,
            actor=self._actor,
            observed_at=self._clock(),
            direction=Direction.OUTBOUND,
        )

        if isinstance(verdict, Deny):
            egress = rule_egress(verdict, policy=self._egress, content_length=len(content))
            if isinstance(egress, RedactEgress):
                sanitised = _sanitised_result(message.result, content, egress.redaction)
                if sanitised is not None:
                    record = guard.record(
                        Direction.OUTBOUND, verdict, self._actor, disposition=Action.REDACT.value
                    )
                    return _Screening(
                        action=Action.REDACT,
                        record=record,
                        replacement=_masked_response(
                            message.id, sanitised, verdict, record, egress
                        ),
                        redaction=egress.redaction,
                    )
                # The masking did not come out as planned. Nobody knows what the
                # payload would carry, so nothing leaves: the fallback of a
                # failed redaction is the refusal it was standing in for.
                ruling = Ruling(
                    action=Action.BLOCK,
                    verdict=verdict,
                    reason=(
                        f"{egress.reason} — but the masked payload did not re-derive to the "
                        "planned content, so limes blocked it instead"
                    ),
                )
                record = guard.record(
                    Direction.OUTBOUND, verdict, self._actor, disposition=ruling.action.value
                )
                _note(
                    "the masking could not be applied faithfully to the payload; blocking instead "
                    f"of forwarding (record {record.digest})"
                )
            else:
                ruling = Ruling(action=Action.BLOCK, verdict=verdict, reason=egress.reason)
                record = guard.record(
                    Direction.OUTBOUND, verdict, self._actor, disposition=ruling.action.value
                )
            return _Screening(
                action=Action.BLOCK,
                record=record,
                replacement=_blocked_response(message.id, method, ruling, record),
                redaction=None,
            )

        ruling = rule(verdict, on_cannot_say=self._on_cannot_say)
        record = guard.record(
            Direction.OUTBOUND, verdict, self._actor, disposition=ruling.action.value
        )
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


def _quarantine_upstream_meta(result: Mapping[str, Any]) -> dict[str, Any]:
    """Copy ``result``, moving an upstream ``_meta.limes`` to ``_meta.limes-upstream``.

    The relay is the only writer of ``_meta.limes`` on the host-facing side
    (ADR 0024). An annotation the wrapped server sent under that key is not
    dropped — the host may want to see what the server claimed — but it may not
    pass for the relay's own.
    """
    copied: dict[str, Any] = dict(result)
    meta = copied.get(_META)
    if isinstance(meta, dict) and LIMES_META_KEY in meta:
        moved: dict[str, Any] = dict(meta)
        moved[UPSTREAM_META_KEY] = moved.pop(LIMES_META_KEY)
        copied[_META] = moved
    return copied


def _reserve_meta(message: types.JSONRPCResponse) -> SessionMessage | None:
    """Return a rebuilt response if the server's result claimed the relay's ``_meta`` key."""
    meta = message.result.get(_META)
    if not isinstance(meta, dict) or LIMES_META_KEY not in meta:
        return None
    _note(
        f"the wrapped server sent a `_meta.{LIMES_META_KEY}` annotation of its own; moved to "
        f"`_meta.{UPSTREAM_META_KEY}` — only the relay writes `_meta.{LIMES_META_KEY}` (ADR 0024)"
    )
    return _wrap(
        types.JSONRPCResponse(
            jsonrpc="2.0", id=message.id, result=_quarantine_upstream_meta(message.result)
        )
    )


def _sanitised_result(
    result: Mapping[str, Any], content: str, redaction: Redaction
) -> dict[str, Any] | None:
    """Apply ``redaction`` to ``result`` and verify it, or return ``None`` (ADR 0006).

    The masking is *checked* rather than trusted: the sanitised payload is put
    back through the very derivation the offsets came from, and compared to the
    plan applied to the flat content. They agree when every masked region sat
    inside a single string; they disagree if a match straddled two strings, or
    if the two walks ever drift apart. A disagreement means the payload is not
    what the plan says it is, and an unverified redaction is not a redaction.
    A styled mask that left the value recoverable fails the same way (ADR 0008).
    """
    if not conceals_all(content, redaction):
        return None
    sanitised = redact_payload(result, redaction)
    if not isinstance(sanitised, dict):
        return None
    if inspected_content(sanitised) != apply_masking(content, redaction):
        return None
    return _quarantine_upstream_meta(sanitised)


def _masked_response(
    request_id: str | int,
    sanitised: Mapping[str, Any],
    verdict: Deny,
    record: DecisionRecord,
    egress: RedactEgress,
) -> SessionMessage:
    """Build the masked result that replaces a refused response (ADR 0006).

    The result stays a **normal** result — no ``isError``, no JSON-RPC error. The
    host's tool call succeeds; the matched regions read ``[REDACTED:<kind>]`` and
    ``_meta`` carries what was masked, where, and under which chain record.

    Args:
        request_id: The id of the request whose response was masked.
        sanitised: The verified, sanitised result (:func:`_sanitised_result`).
        verdict: The outbound ``Deny`` being masked.
        record: The chain record indexing the decision.
        egress: The redacting ruling — its plan, and the reason to annotate with.

    Returns:
        The replacement message.
    """
    result: dict[str, Any] = dict(sanitised)
    existing = result.get(_META)
    meta: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    meta.update(redaction_meta(verdict, record, egress.redaction, reason=egress.reason))
    result[_META] = meta
    return _wrap(types.JSONRPCResponse(jsonrpc="2.0", id=request_id, result=result))


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


def _blocked_server_request(
    request_id: str | int, method: str, ruling: Ruling, record: DecisionRecord
) -> SessionMessage:
    """Build the error answered to a *server* whose request to the host was refused.

    The server asked; the host never sees the request; the server is told why,
    with the evidence, in the only shape a refused request has (ADR 0024).
    """
    return _wrap(
        types.JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=types.ErrorData(
                code=BLOCKED_ERROR_CODE,
                message=refusal_text(ruling, record, subject=f"{method} request"),
                data=refusal_meta(ruling, record),
            ),
        )
    )


async def serve(
    config: ProxyConfig,
    *,
    sink: RecordSink | None = None,
    clock: Callable[[], str] = utc_now_iso,
    outbound: Sequence[Detector] | None = None,
) -> Ledger:
    """Run the proxy on this process's stdio until the host disconnects.

    Args:
        config: The invocation — the wrapped server's command, the policy, the
            record sink, the fail-closed setting, and the asserted actor.
        sink: Override the sink (tests, embedders). Defaults to the one
            ``config`` asks for: stderr, or ``--record``'s file.
        clock: Override the clock (replay). Defaults to UTC now.
        outbound: Detectors for the outbound leg. ``None`` — the default, and
            what the console entry point passes — installs every admitted egress
            detector (ADR 0018: the leg selects its detectors, in every
            transport). Pass an explicit sequence to override, including ``()``
            for a deliberately unguarded outbound leg, which the transparency
            tests use to prove exact pass-through.

            This used to default to ``()``, with a docstring saying limes shipped
            no egress detector. That was true at v0.4 and had been false since
            v0.5, so the proxy — the transport this project leads with — ran with
            its outbound leg empty while the README described what it caught. An
            end-to-end test of a poisoned ``tools/list`` is what found it.

    Returns:
        The session's decision chain.
    """
    if outbound is None:
        outbound = outbound_detectors()
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
        # A setting that governs nothing must say so. Reachable only when the
        # caller passed a deliberately empty outbound leg: it observes nothing
        # and there is nothing to mask — a behaviour this process cannot exhibit.
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
