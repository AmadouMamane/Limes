"""A real ``limes proxy`` process with an outbound double installed.

This fixture is the same :func:`limes.transports.mcp.bridge.serve` — same relay,
same policy parsing, same stdio wiring — with a **deterministic test double**
passed as ``outbound`` in place of the admitted detectors the shipped proxy
installs (ADR 0018). It exists so egress redaction can be proven against a
**real process pair over real stdio** with exactly known findings, rather than
only over in-memory streams.

It is spawned exactly like the proxy is: ``python redacting_proxy.py [options] --
<server command...>``.
"""

from __future__ import annotations

import sys
from functools import partial
from pathlib import Path

import anyio

REPO = Path(__file__).resolve().parents[3]


def main() -> int:
    """Parse the same command line the proxy does, and serve with a double wired."""
    sys.path.insert(0, str(REPO))
    from limes.transports.mcp.bridge import serve
    from limes.transports.mcp.cli import parse_config
    from tests.unit.redaction.doubles import PiiDouble, SecretDouble

    config = parse_config(sys.argv[1:], prog="redacting-proxy")
    anyio.run(partial(serve, config, outbound=(PiiDouble(), SecretDouble())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
