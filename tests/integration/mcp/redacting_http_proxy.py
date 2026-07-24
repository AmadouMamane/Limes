"""The HTTP proxy with an outbound double installed, as a spawnable process.

    python redacting_http_proxy.py --upstream URL --port N [options]

limes ships no egress detector, so the shipped HTTP proxy never masks anything.
This fixture is the same :func:`limes.transports.mcp.http.run_http` — same relay,
same policy parsing, same HTTP wiring — with test doubles passed as ``outbound``,
so egress redaction can be proven over a **real HTTP process pair** rather than
only over in-memory streams. The doubles live in ``tests/`` and are not shippable
(ADR 0003).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def main() -> int:
    sys.path.insert(0, str(REPO))
    from limes.transports.mcp.bridge import utc_now_iso
    from limes.transports.mcp.http import parse_http_config, run_http
    from tests.unit.redaction.doubles import PiiDouble, SecretDouble

    config = parse_http_config(sys.argv[1:], prog="redacting-http-proxy")

    # A fixed clock, only when a test asks for one, so a replayed session
    # re-derives identical chain digests over real HTTP — the same lever the
    # in-memory relay test pulls, exercised here against real processes.
    fixed = os.environ.get("LIMES_FIXED_CLOCK")

    def clock() -> str:
        return fixed if fixed else utc_now_iso()

    run_http(config, outbound=(PiiDouble(), SecretDouble()), clock=clock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
