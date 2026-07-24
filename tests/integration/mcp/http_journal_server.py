"""A real MCP Streamable HTTP server that journals every tool call it receives.

    python http_journal_server.py <journal.jsonl> <port>

The HTTP twin of ``journal_server.py``: a genuine server built on the official
SDK — echo and announce tools, a server→host log notification — served over
Streamable HTTP by the SDK's own session manager behind a Starlette app. It is
the upstream the HTTP proxy wraps, so the end-to-end claims (a real host cannot
tell the proxy is there; a blocked call is absent from this journal) are proven
against a real server, not a stub.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send

INSTRUCTIONS = "A server that echoes text and announces itself."


def main() -> int:
    journal = Path(sys.argv[1])
    port = int(sys.argv[2])
    server: Server[object, object] = Server(
        "limes-http-journal-server", version="0.2.0", instructions=INSTRUCTIONS
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

    manager = StreamableHTTPSessionManager(app=server, json_response=False, stateless=False)

    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    app = Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
