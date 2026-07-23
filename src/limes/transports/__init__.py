"""Transports — adapters that carry the core's decision to a host (ADR 0004).

Two transports, one core. **In-process**
(:class:`limes.transports.in_process.Guard`), shipped in v0.1, and the **MCP
stdio proxy** (:mod:`limes.transports.mcp`, v0.2, ADR 0005) — a transport because
that path actually speaks MCP, not because of a name.

They share one behaviour, in :mod:`limes.transports.redaction` (v0.3, ADR 0006):
what to do with a finding on the way *out*. Block, which is the default, or mask
the matched offsets and forward the rest. It lives here rather than in the core
because it decides about a *message*, not about content — the core's answer to
"is this clean?" is the same either way.

This module deliberately does **not** import the MCP subpackage: the SDK is the
optional ``limes[mcp]`` extra, and ``import limes`` must keep working without it.
"""

from __future__ import annotations

from limes.transports.in_process import Blocked, Guard

__all__ = ["Blocked", "Guard"]
