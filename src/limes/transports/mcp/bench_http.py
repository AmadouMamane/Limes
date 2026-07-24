"""Measure what the HTTP proxy costs — never assert it (ADR 0003's ethic, ADR 0007).

    uv run python -m limes.transports.mcp.bench_http                 # measure
    uv run python -m limes.transports.mcp.bench_http --serve-echo --port N   # its echo server

It times the same ``tools/call`` twice over Streamable HTTP: once against an echo
server directly, and once against that same server through the limes HTTP proxy.
The difference is the transport's added latency — one guarded tool call, on the
machine that ran it. The report names the machine, the payload size and the
sample count, because a latency number without them is a decoration.

What it does **not** measure: throughput under concurrency, large payloads, or
the cost of a *blocked* call (a refusal never reaches the server, so it is
strictly cheaper than an allowed one).
"""

from __future__ import annotations

import argparse
import contextlib
import platform
import socket
import statistics
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, cast

import anyio
import mcp.types as types
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send

__all__ = ["main"]

_ECHO_TOOL = "echo"
_DEFAULT_CALLS = 200
_DEFAULT_PAYLOAD = 256

# The SDK's low-level registration decorators carry no annotations; name the
# shapes they actually have rather than suppress strict-mode errors (see bench.py).
type _ListTools = Callable[[], Awaitable[list[types.Tool]]]
type _CallTool = Callable[[str, dict[str, Any]], Awaitable[list[types.ContentBlock]]]
type _Register[T] = Callable[[], Callable[[T], T]]


def _serve_echo(port: int) -> None:
    """Run the echo server this benchmark measures, over Streamable HTTP."""
    server: Server[object, object] = Server("limes-bench-http-echo", version="0.2.0")
    register_list_tools = cast(_Register[_ListTools], server.list_tools)
    register_call_tool = cast(_Register[_CallTool], server.call_tool)

    @register_list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=_ECHO_TOOL,
                description="Return the text it was given.",
                inputSchema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            )
        ]

    @register_call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
        return [types.TextContent(type="text", text=str(arguments.get("text", "")))]

    manager = StreamableHTTPSessionManager(app=server, json_response=False, stateless=False)

    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    app = Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} never came up")


async def _timed_calls(url: str, *, calls: int, payload: str) -> list[float]:
    """Time ``calls`` benign tool calls against ``url`` (after one warm-up call)."""
    durations: list[float] = []
    async with (
        streamable_http_client(url) as (read_stream, write_stream, _get_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        await session.call_tool(_ECHO_TOOL, {"text": payload})
        for _ in range(calls):
            started = time.perf_counter()
            await session.call_tool(_ECHO_TOOL, {"text": payload})
            durations.append((time.perf_counter() - started) * 1000.0)
    return durations


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * len(ordered)) - 1))
    return ordered[index]


def _report(label: str, durations: list[float]) -> str:
    return (
        f"  {label:<10} median {statistics.median(durations):6.2f} ms   "
        f"p95 {_percentile(durations, 0.95):6.2f} ms   "
        f"mean {statistics.fmean(durations):6.2f} ms"
    )


def _proxy_command(*, upstream_url: str, port: int) -> list[str]:
    """The command that starts the shipped HTTP proxy in front of the echo server."""
    return [
        sys.executable,
        "-c",
        "from limes.transports.mcp.http import run_http, HttpProxyConfig; "
        f"run_http(HttpProxyConfig(upstream_url={upstream_url!r}, host='127.0.0.1', port={port}))",
    ]


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark, or the echo server it measures.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns:
        The process exit code.
    """
    parser = argparse.ArgumentParser(prog="python -m limes.transports.mcp.bench_http")
    parser.add_argument("--serve-echo", action="store_true", help="run the echo HTTP server")
    parser.add_argument("--port", type=int, default=0, help="port for --serve-echo")
    parser.add_argument("--calls", type=int, default=_DEFAULT_CALLS)
    parser.add_argument("--payload", type=int, default=_DEFAULT_PAYLOAD)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if options.serve_echo:
        _serve_echo(options.port)
        return 0

    up_port = _free_port()
    proxy_port = _free_port()
    upstream_url = f"http://127.0.0.1:{up_port}/mcp"
    proxy_url = f"http://127.0.0.1:{proxy_port}/mcp"

    upstream = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "limes.transports.mcp.bench_http",
            "--serve-echo",
            "--port",
            str(up_port),
        ],
        stderr=subprocess.DEVNULL,
    )
    proxy = subprocess.Popen(
        _proxy_command(upstream_url=upstream_url, port=proxy_port), stderr=subprocess.DEVNULL
    )
    try:
        _wait_port(up_port)
        _wait_port(proxy_port)
        payload = "x" * options.payload
        direct = anyio.run(lambda: _timed_calls(upstream_url, calls=options.calls, payload=payload))
        proxied = anyio.run(lambda: _timed_calls(proxy_url, calls=options.calls, payload=payload))

        print("limes MCP Streamable HTTP proxy — measured overhead of one guarded tools/call")
        print(
            f"  machine: {platform.platform()} · python {platform.python_version()} · "
            f"n={options.calls} calls · payload={options.payload} bytes"
        )
        print(_report("direct", direct))
        print(_report("proxied", proxied))
        added_median = statistics.median(proxied) - statistics.median(direct)
        added_p95 = _percentile(proxied, 0.95) - _percentile(direct, 0.95)
        print(f"  added     median {added_median:+6.2f} ms   p95 {added_p95:+6.2f} ms")
    finally:
        for process in (proxy, upstream):
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
