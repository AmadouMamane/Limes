"""limes — the guard that can prove what it refused.

A transport-agnostic decision core whose verdicts carry evidence (ADR 0002),
detectors as plugins (ADR 0004), and an admission rule that no detector lands
without its eval cases and its null control (ADR 0003).

v0.1 shipped the core, one detector (``injection``, inbound), and the in-process
transport. v0.2 adds a second transport and nothing else: the MCP stdio proxy
(``limes proxy``, extra ``limes[mcp]``, ADR 0005), which reuses this core
unchanged. Still not shipped: an HTTP transport, an egress detector, or any
detector beyond ``injection`` — see the README's "What limes does not do".
"""

from __future__ import annotations

from limes.detector import Context, Detector, DetectorBlind, Direction, Finding
from limes.guard import decide
from limes.record import ChainStatus, DecisionRecord, Ledger
from limes.spans import RedactedSpan, redact
from limes.transports.in_process import Blocked, Guard
from limes.verdict import (
    Allow,
    CannotSay,
    Deny,
    Evidence,
    Verdict,
    Witness,
    fingerprint,
    render,
)

__all__ = [
    "Allow",
    "Blocked",
    "CannotSay",
    "ChainStatus",
    "Context",
    "DecisionRecord",
    "Deny",
    "Detector",
    "DetectorBlind",
    "Direction",
    "Evidence",
    "Finding",
    "Guard",
    "Ledger",
    "RedactedSpan",
    "Verdict",
    "Witness",
    "decide",
    "fingerprint",
    "redact",
    "render",
]
