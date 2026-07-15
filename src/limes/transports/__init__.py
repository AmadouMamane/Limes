"""Transports — adapters that carry the core's decision to a host (ADR 0004).

v0.1 ships one transport: in-process (:class:`limes.transports.in_process.Guard`).
The MCP stdio proxy is v0.2, and it will be a transport because that path
actually speaks MCP — not because of a name.
"""

from __future__ import annotations

from limes.transports.in_process import Blocked, Guard

__all__ = ["Blocked", "Guard"]
