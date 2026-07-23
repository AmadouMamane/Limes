"""The MCP stdio proxy transport — the adoption wedge (ADR 0005).

A proxy that slips **between an MCP host and an MCP server**: to the host it
looks like a server, to the server it looks like a client. It relays the whole
JSON-RPC 2.0 conversation faithfully and inspects only the messages that carry
guardable content — refusing a ``tools/call`` whose arguments trip the core's
pipeline, and saying, in the refusal, exactly what fired.

This is a **transport** (ADR 0004). It imports :func:`limes.guard.decide` (through
:class:`limes.transports.in_process.Guard`), the verdict algebra and the ledger,
and it modifies none of them. It ships **no detector**.

The MCP SDK is an optional extra — ``pip install 'limes[mcp]'``. Every module in
this package imports without it **except** :mod:`limes.transports.mcp.bridge`, so
the console entry point can report a missing extra instead of dying on an
``ImportError`` traceback.

Note for readers of the source: this package is named ``mcp`` *inside*
``limes.transports`` while also depending on the top-level ``mcp`` distribution.
Python 3 resolves ``import mcp.types`` inside these modules to the installed SDK,
not to this package, because absolute imports are the default. A test
(``tests/unit/mcp/test_boundary.py``) asserts that is what actually happens
rather than trusting the rule.
"""

from __future__ import annotations

from limes.transports.mcp.config import OnCannotSay, ProxyConfig, read_on_cannot_say
from limes.transports.mcp.decision import Action, Ruling, refusal_meta, refusal_text, rule
from limes.transports.mcp.payload import inspected_content, tool_call_arguments, tool_call_name
from limes.transports.mcp.sink import JsonlSink, NullSink, RecordSink, open_sink, record_entry

__all__ = [
    "Action",
    "JsonlSink",
    "NullSink",
    "OnCannotSay",
    "ProxyConfig",
    "RecordSink",
    "Ruling",
    "inspected_content",
    "open_sink",
    "read_on_cannot_say",
    "record_entry",
    "refusal_meta",
    "refusal_text",
    "rule",
    "tool_call_arguments",
    "tool_call_name",
]
