"""The MCP Streamable HTTP proxy transport (ADR 0007) — the third transport.

Same guard, new wire. The *decision* — inbound ``tools/call`` inspection, the
outbound seam, egress redaction, the hash-chained ledger — is the very
:class:`~limes.transports.mcp.bridge.Relay` the stdio proxy runs. The ``Relay``
reads and writes :class:`~mcp.shared.message.SessionMessage` and is blind to
whether the bytes arrived over a pipe or an HTTP POST, so *nothing* about the
decision is re-implemented here. That is the whole point of a transport-agnostic
core (ADR 0004): the third transport proves it.

Only the plumbing is new, and even that is mostly reused from the SDK:

* the **host-facing** side is the SDK's
  :class:`~mcp.server.streamable_http_manager.StreamableHTTPSessionManager`,
  which owns session routing by ``Mcp-Session-Id``, the SSE stream server→host,
  and session cleanup — behind a small Starlette app;
* the **server-facing** side is the SDK's
  :func:`~mcp.client.streamable_http.streamablehttp_client`, one upstream
  connection per host session.

What limes adds is the seam between them: :class:`_ProxyApp`, which the manager
calls in place of an MCP server. Instead of *answering* MCP it opens the upstream
client and runs a fresh ``Relay`` between the manager's host-facing streams and
the upstream client's streams. One host session, one upstream session, one
decision chain.

Like the stdio bridge, this module imports the MCP SDK and a running ASGI server
(``uvicorn``, which ``mcp`` already depends on); it is reached through the
``limes[http]`` extra.

Anti-scope (v1): the current Streamable HTTP only (no deprecated HTTP+SSE), one
host↔server pair per session, no host authentication beyond what the SDK's
transport enforces, no upstream credentials forwarded (the upstream connection
uses the SDK's default client), and no multiplexing.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, cast, final

import anyio
import uvicorn
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel.server import Server as MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send

from limes.detector import Detector
from limes.detectors.injection import InjectionDetector
from limes.policy import load_injection_policy
from limes.transports.mcp.bridge import IncomingStream, OutgoingStream, Relay, utc_now_iso
from limes.transports.mcp.config import (
    DEFAULT_ON_CANNOT_SAY,
    OnCannotSay,
    read_on_cannot_say,
)
from limes.transports.mcp.sink import RecordSink, open_sink
from limes.transports.redaction import (
    DEFAULT_ON_EGRESS_FINDING,
    EgressPolicy,
    OnEgressFinding,
    read_egress_policy,
)

__all__ = [
    "HttpProxyConfig",
    "build_asgi_app",
    "main_http",
    "parse_http_config",
    "run_http",
    "serve_http",
]

_DEFAULT_HOST: Final = "127.0.0.1"
_DEFAULT_PORT: Final = 8080
_DEFAULT_MOUNT: Final = "/mcp"


@final
@dataclass(frozen=True, slots=True)
class HttpProxyConfig:
    """One guarded host↔upstream pairing, served over Streamable HTTP.

    Attributes:
        upstream_url: The real MCP server's Streamable HTTP endpoint, e.g.
            ``"http://127.0.0.1:9000/mcp"``. The proxy opens one client to it per
            host session.
        host: The interface the proxy listens on (loopback by default — a guard
            you expose to the world is a decision, made explicitly).
        port: The port the proxy listens on.
        mount_path: The path the proxy serves MCP on.
        policy_path: The injection policy to load, or ``None`` for the packaged
            one. May also carry ``on_cannot_say`` / ``on_egress_finding``.
        record_path: Where decision records are appended, or ``None`` for stderr.
        on_cannot_say: Fail-closed policy for ``CannotSay``.
        actor: The identity asserted by the operator running the proxy; ``None``
            is honest for an unattributed deployment.
        egress: What to do with an outbound finding, by kind. Blocking by default.
        json_response: Ask the SDK transport to answer with a single JSON body
            instead of an SSE stream where it can. Off by default.
    """

    upstream_url: str
    host: str = _DEFAULT_HOST
    port: int = _DEFAULT_PORT
    mount_path: str = _DEFAULT_MOUNT
    policy_path: Path | None = None
    record_path: Path | None = None
    on_cannot_say: OnCannotSay = DEFAULT_ON_CANNOT_SAY
    actor: str | None = None
    egress: EgressPolicy = field(default_factory=EgressPolicy.blocking)
    json_response: bool = False

    def __post_init__(self) -> None:
        """Refuse a configuration with no upstream to guard.

        Raises:
            ValueError: If ``upstream_url`` is empty or not http(s).
        """
        if not self.upstream_url:
            raise ValueError(
                "a proxy with no upstream guards nothing; pass the real server's "
                "Streamable HTTP endpoint, e.g. `--upstream http://127.0.0.1:9000/mcp`"
            )
        if not self.upstream_url.startswith(("http://", "https://")):
            raise ValueError(f"--upstream must be an http(s) URL, got {self.upstream_url!r}")


@final
class _ProxyApp:
    """The seam the session manager calls in place of an MCP server.

    It is *not* an MCP server: it owns no protocol state, answers nothing, and
    implements only the two methods the manager touches
    (:meth:`create_initialization_options` and :meth:`run`). :meth:`run` opens the
    upstream client and drives a fresh :class:`Relay` per host session, so the
    decision is the stdio proxy's decision, unchanged.
    """

    def __init__(self, *, upstream_url: str, make_relay: Callable[[], Relay]) -> None:
        """Wire the seam to an upstream URL and a per-session relay factory."""
        self._upstream_url = upstream_url
        self._make_relay = make_relay

    def create_initialization_options(self) -> object:
        """Return the value the manager passes straight back into :meth:`run`.

        A proxy has no initialization options of its own — it forwards the host's
        ``initialize`` to the upstream server and forwards the reply back. The
        manager only needs *a* value to hand to :meth:`run`, which ignores it.
        """
        return None

    async def run(
        self,
        read_stream: IncomingStream,
        write_stream: OutgoingStream,
        initialization_options: object,
        *,
        stateless: bool = False,
    ) -> None:
        """Relay one host session to the upstream server, guarded.

        Args:
            read_stream: Messages arriving from the host (the manager's transport).
            write_stream: Messages to send to the host.
            initialization_options: Ignored — a proxy owns no protocol state.
            stateless: Ignored — the pairing is per session either way.
        """
        del initialization_options, stateless
        relay = self._make_relay()
        async with streamable_http_client(self._upstream_url) as (
            server_read,
            server_write,
            _get_session_id,
        ):
            await relay.run(read_stream, write_stream, server_read, server_write)


def _relay_factory(
    config: HttpProxyConfig,
    *,
    sink: RecordSink,
    clock: Callable[[], str],
    outbound: Sequence[Detector],
) -> Callable[[], Relay]:
    """Build the per-session relay factory (a fresh ledger per host session)."""
    policy = load_injection_policy(config.policy_path)
    detector = InjectionDetector(policy)

    def make_relay() -> Relay:
        return Relay(
            inbound=(detector,),
            outbound=outbound,
            policy_hash=policy.policy_hash,
            on_cannot_say=config.on_cannot_say,
            actor=config.actor,
            sink=sink,
            clock=clock,
            egress=config.egress,
        )

    if config.egress.redacts_anything() and not outbound:
        # A setting that governs nothing must say so (as the stdio proxy does).
        print(
            "limes proxy-http: on_egress_finding asks for masking, but no egress detector is "
            "installed — the outbound leg inspects nothing, so nothing will be masked.",
            file=sys.stderr,
            flush=True,
        )
    return make_relay


def build_asgi_app(
    config: HttpProxyConfig,
    *,
    sink: RecordSink,
    clock: Callable[[], str] = utc_now_iso,
    outbound: Sequence[Detector] = (),
) -> Starlette:
    """Build the Starlette app that serves the guarded proxy over Streamable HTTP.

    Args:
        config: The invocation.
        sink: Where decision records are written.
        clock: Supplies ``observed_at``; injectable for a deterministic replay.
        outbound: Detectors for the outbound leg. Empty in the shipped proxy —
            limes ships no egress detector — a parameter so an embedder or an
            end-to-end proof can install one.

    Returns:
        A Starlette application. Its lifespan runs the SDK session manager; the
        mount routes every MCP request to it.
    """
    make_relay = _relay_factory(config, sink=sink, clock=clock, outbound=outbound)
    app = _ProxyApp(upstream_url=config.upstream_url, make_relay=make_relay)
    manager = StreamableHTTPSessionManager(
        app=cast(MCPServer[Any, Any], app),
        json_response=config.json_response,
        stateless=False,
    )

    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    return Starlette(routes=[Mount(config.mount_path, app=handle)], lifespan=lifespan)


async def serve_http(
    config: HttpProxyConfig,
    *,
    sink: RecordSink | None = None,
    clock: Callable[[], str] = utc_now_iso,
    outbound: Sequence[Detector] = (),
) -> None:
    """Serve the guarded proxy until the process is stopped.

    Args:
        config: The invocation.
        sink: Override the record sink; defaults to the one ``config`` asks for
            (stderr, or ``--record``'s file). Never stdout is required here —
            unlike stdio, HTTP does not use stdout as its channel — but stderr
            stays the default for consistency.
        clock: Override the clock (replay). Defaults to UTC now.
        outbound: Detectors for the outbound leg (empty in the shipped proxy).
    """
    owned_sink = sink if sink is not None else open_sink(config.record_path)
    app = build_asgi_app(config, sink=owned_sink, clock=clock, outbound=outbound)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=config.host,
            port=config.port,
            log_level="warning",
            access_log=False,
        )
    )
    try:
        await server.serve()
    finally:
        if sink is None:
            owned_sink.close()


def run_http(
    config: HttpProxyConfig,
    *,
    sink: RecordSink | None = None,
    clock: Callable[[], str] = utc_now_iso,
    outbound: Sequence[Detector] = (),
) -> None:
    """Run :func:`serve_http` to completion on a fresh event loop."""

    async def _main() -> None:
        await serve_http(config, sink=sink, clock=clock, outbound=outbound)

    anyio.run(_main)


def build_http_parser(prog: str) -> argparse.ArgumentParser:
    """Build the argument parser for ``limes proxy-http``.

    Args:
        prog: The program name to show in usage.

    Returns:
        The parser.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Guard a Streamable HTTP MCP server by proxying it: the host connects to this "
            "proxy, the proxy connects to the real server, and every tool call becomes a "
            "decision that carries its evidence — the same decision the stdio proxy makes."
        ),
    )
    parser.add_argument(
        "--upstream",
        required=True,
        metavar="URL",
        help="the real MCP server's Streamable HTTP endpoint, e.g. http://127.0.0.1:9000/mcp",
    )
    parser.add_argument("--host", default=_DEFAULT_HOST, help="interface to listen on")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, help="port to listen on")
    parser.add_argument("--path", default=_DEFAULT_MOUNT, help="path to serve MCP on")
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        metavar="PATH",
        help="injection policy YAML (default: the packaged one). May also carry the "
        "optional `on_cannot_say` / `on_egress_finding` keys.",
    )
    parser.add_argument(
        "--record",
        type=Path,
        default=None,
        metavar="FILE",
        help="append decision records here as JSONL (default: stderr).",
    )
    parser.add_argument(
        "--on-cannot-say",
        choices=[member.value for member in OnCannotSay],
        default=None,
        help=f"what to do when a detector could not look (default: "
        f"{DEFAULT_ON_CANNOT_SAY.value} — fail closed). Overrides the policy file.",
    )
    parser.add_argument(
        "--on-egress-finding",
        choices=[member.value for member in OnEgressFinding],
        default=None,
        help=f"what to do when a detector fires on a response (default: "
        f"{DEFAULT_ON_EGRESS_FINDING.value}). Overrides the policy file's default. limes "
        "ships no egress detector, so nothing exercises this today.",
    )
    parser.add_argument(
        "--actor",
        default=None,
        metavar="NAME",
        help="the identity this deployment asserts, recorded on every decision. Omitted "
        "means unattributed, which is honest; it is never filled in for you.",
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        help="answer with a single JSON body instead of an SSE stream where possible.",
    )
    return parser


def parse_http_config(argv: Sequence[str], *, prog: str) -> HttpProxyConfig:
    """Parse one invocation into a :class:`HttpProxyConfig`.

    Args:
        argv: The arguments, without the program name.
        prog: The program name to show in usage.

    Returns:
        The configuration.

    Raises:
        SystemExit: With code 2 on a usage error, or an unreadable
            ``on_cannot_say`` / ``on_egress_finding`` in the policy file — never a
            silent fallback to the default (as the stdio proxy refuses too).
    """
    parser = build_http_parser(prog)
    options = parser.parse_args(list(argv))

    on_cannot_say = DEFAULT_ON_CANNOT_SAY
    egress = EgressPolicy.blocking()
    if options.policy is not None:
        try:
            declared = read_on_cannot_say(options.policy)
            declared_egress = read_egress_policy(options.policy)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        else:
            if declared is not None:
                on_cannot_say = declared
            if declared_egress is not None:
                egress = declared_egress
    if options.on_cannot_say is not None:
        on_cannot_say = OnCannotSay(options.on_cannot_say)
    if options.on_egress_finding is not None:
        egress = EgressPolicy(
            default=OnEgressFinding(options.on_egress_finding), by_kind=egress.by_kind
        )

    try:
        return HttpProxyConfig(
            upstream_url=options.upstream,
            host=options.host,
            port=options.port,
            mount_path=options.path,
            policy_path=options.policy,
            record_path=options.record,
            on_cannot_say=on_cannot_say,
            actor=options.actor,
            egress=egress,
            json_response=options.json_response,
        )
    except ValueError as exc:
        parser.error(str(exc))


def main_http(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``limes proxy-http``.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns:
        The process exit code.
    """
    config = parse_http_config(sys.argv[1:] if argv is None else argv, prog="limes proxy-http")
    try:
        run_http(config)
    except (OSError, ValueError) as exc:
        # No degraded mode: a proxy that cannot load its policy or bind its port
        # stops, rather than becoming a pass-through the operator believes guards
        # them.
        print(f"limes proxy-http refused to start: {exc}", file=sys.stderr)
        return 2
    return 0
