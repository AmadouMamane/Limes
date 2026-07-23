"""A real MCP stdio server that writes down every tool call it receives.

    python journal_server.py <journal.jsonl>

It is a genuine server built on the official SDK — not a stub of the proxy's
inner half — because the claim under test is that a real host and a real server
cannot tell the proxy is there. The journal is the witness for the other claim:
a blocked call must be absent from it. The path arrives as an *argument* rather
than an environment variable, because the SDK's stdio client passes only an
allow-listed environment to a child, so an env var would not survive the proxy
spawning this process.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server

INSTRUCTIONS = "A server that echoes text and announces itself."


def main() -> int:
    journal = Path(sys.argv[1])
    server: Server[object, object] = Server(
        "limes-journal-server", version="0.2.0", instructions=INSTRUCTIONS
    )

    def note(entry: dict[str, Any]) -> None:
        with journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="echo",
                description="Return the text it was given.",
                inputSchema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            ),
            types.Tool(
                name="announce",
                description="Send a server->host log notification, then answer.",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
        note({"tool": name, "arguments": arguments})
        if name == "announce":
            await server.request_context.session.send_log_message(
                level="info", data="the wrapped server speaks", logger="journal"
            )
            return [types.TextContent(type="text", text="announced")]
        return [types.TextContent(type="text", text=str(arguments.get("text", "")))]

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(NotificationOptions()),
            )

    anyio.run(_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
