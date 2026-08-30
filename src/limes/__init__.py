"""limes — the guard that can prove what it refused.

A transport-agnostic decision core whose verdicts carry evidence (ADR 0002),
detectors as plugins (ADR 0004), and an admission rule that no detector lands
without its eval cases and its null control (ADR 0003).

v0.1 shipped the core, one detector (``injection``, inbound), and the in-process
transport. v0.2 adds a second transport and nothing else: the MCP stdio proxy
(``limes proxy``, extra ``limes[mcp]``, ADR 0005), which reuses this core
unchanged. v0.3 adds a *behaviour* to both transports' outbound leg and, again,
nothing to the core: under a redacting egress policy a refused response is masked
at the offsets its evidence already carried, and forwarded
(:mod:`limes.transports.redaction`, ADR 0006). v0.4 adds a third transport — the
MCP Streamable HTTP proxy (``limes proxy-http``, extra ``limes[http]``, ADR 0007)
— which reuses the stdio proxy's decision unchanged, and a command-line surface,
``limes check`` (:mod:`limes.cli`); the core does not move.

Three detectors then land on the outbound leg, each a plugin, each with the two
numbers ADR 0003 demands before admission: ``pii-egress`` (v0.5),
``secrets-egress`` (v0.6) and ``injection-egress`` (v0.8), which reads tool
descriptions and tool results for the instructions an attacker plants there
(ADR 0012). So the v0.3 redaction behaviour has something to mask out of the box.
One core file has moved since v0.1, once and by decision: ADR 0011 made the
evidence digest total, so content this runtime cannot encode yields ``CannotSay``
rather than a crash.

Still not shipped: any detector outside those four. No classifier layer — ADR
0013 frames one as an optional extra, admitted by the same gate and only on its
own two numbers. No PII category beyond the five a checksum or a format can
actually separate from ordinary prose. No generic high-entropy secret scanning.
And note where the four run: ``limes check`` wires inbound ``injection`` only,
while the egress detectors run in the proxy transports. See the README's "What
limes does not do".
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

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

#: The build that is answering, read from the installed distribution's metadata —
#: the same single source `limes --version` reads, so the two cannot disagree and
#: neither can go stale against the wheel a user actually installed (ADR 0014).
try:
    __version__ = version("limes")
except PackageNotFoundError:
    # A source tree on sys.path rather than an installed distribution. Letting
    # this escape would make `import limes` fail because the package could not
    # name itself — a crash where a blind spot is the honest answer (ADR 0011's
    # lesson, one layer out). "0+unknown" is a valid PEP 440 local version that
    # sorts below every release and cannot be misread as one.
    __version__ = "0+unknown"

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
