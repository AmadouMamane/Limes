"""Measure what the proxy costs — never assert it (ADR 0003's ethic, ADR 0005).

    uv run python -m limes.transports.mcp.bench            # measure
    uv run python -m limes.transports.mcp.bench --serve    # the echo server it measures

It times the same ``tools/call`` twice: once against an echo server directly, and
once against that same server through ``limes-proxy``. The difference is the
transport's added latency — one guarded tool call, on the machine that ran it.
The report names the machine, the payload size and the sample count, because a
latency number without them is a decoration.

What it does **not** measure: throughput under concurrency, large payloads, or
the cost of a *blocked* call (a refusal never reaches the server, so it is
strictly cheaper than an allowed one).
"""

from __future__ import annotations

import argparse
import os
import platform
import statistics
import sys
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

__all__ = ["main"]

_ECHO_TOOL = "echo"
_DEFAULT_CALLS = 200
_DEFAULT_PAYLOAD = 256

# The SDK's low-level registration decorators carry no annotations. Rather than
# suppress the resulting strict-mode errors (suppressions in src/ are frozen at
# zero by tests/unit/ratchets/test_exceptions_frozen_at_zero.py), name the shapes
# they actually have. The handlers themselves stay fully typed.
type _ListTools = Callable[[], Awaitable[list[types.Tool]]]
type _CallTool = Callable[[str, dict[str, Any]], Awaitable[list[types.ContentBlock]]]
type _Register[T] = Callable[[], Callable[[T], T]]


def _serve_echo() -> None:
    """Run the echo server this benchmark measures, on stdio."""
    server: Server[object, object] = Server("limes-bench-echo", version="0.2.0")
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

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(NotificationOptions()),
            )

    anyio.run(_run)


def _echo_command() -> list[str]:
    """The command that starts the echo server."""
    return [sys.executable, "-m", "limes.transports.mcp.bench", "--serve"]


def _proxied_command() -> list[str]:
    """The command that starts the echo server behind the proxy, default settings."""
    return [sys.executable, "-m", "limes.transports.mcp", "--", *_echo_command()]


async def _timed_calls(command: list[str], *, calls: int, payload: str) -> list[float]:
    """Time ``calls`` benign tool calls against ``command``.

    Args:
        command: The server (or proxy) to start.
        calls: How many timed calls to make, after a warm-up call.
        payload: The text argument to send.

    Returns:
        One duration in milliseconds per call.
    """
    parameters = StdioServerParameters(command=command[0], args=command[1:])
    durations: list[float] = []
    with open(os.devnull, "w", encoding="utf-8") as quiet:
        async with stdio_client(parameters, errlog=quiet) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                await session.call_tool(_ECHO_TOOL, {"text": payload})
                for _ in range(calls):
                    started = time.perf_counter()
                    await session.call_tool(_ECHO_TOOL, {"text": payload})
                    durations.append((time.perf_counter() - started) * 1000.0)
    return durations


def _percentile(values: list[float], fraction: float) -> float:
    """Return the ``fraction`` percentile of ``values`` (nearest rank)."""
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * len(ordered)) - 1))
    return ordered[index]


def _report(label: str, durations: list[float]) -> str:
    """Render one line of the report."""
    return (
        f"  {label:<10} median {statistics.median(durations):6.2f} ms   "
        f"p95 {_percentile(durations, 0.95):6.2f} ms   "
        f"mean {statistics.fmean(durations):6.2f} ms"
    )


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark, or the echo server it measures.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns:
        The process exit code.
    """
    parser = argparse.ArgumentParser(prog="python -m limes.transports.mcp.bench")
    parser.add_argument("--serve", action="store_true", help="run the echo server on stdio")
    parser.add_argument("--calls", type=int, default=_DEFAULT_CALLS)
    parser.add_argument("--payload", type=int, default=_DEFAULT_PAYLOAD)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if options.serve:
        _serve_echo()
        return 0

    payload = "x" * options.payload
    direct = anyio.run(lambda: _timed_calls(_echo_command(), calls=options.calls, payload=payload))
    proxied = anyio.run(
        lambda: _timed_calls(_proxied_command(), calls=options.calls, payload=payload)
    )

    print("limes MCP proxy — measured overhead of one guarded tools/call")
    print(
        f"  machine: {platform.platform()} · python {platform.python_version()} · "
        f"n={options.calls} calls · payload={options.payload} bytes"
    )
    print(_report("direct", direct))
    print(_report("proxied", proxied))
    added_median = statistics.median(proxied) - statistics.median(direct)
    added_p95 = _percentile(proxied, 0.95) - _percentile(direct, 0.95)
    print(f"  added     median {added_median:+6.2f} ms   p95 {added_p95:+6.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
