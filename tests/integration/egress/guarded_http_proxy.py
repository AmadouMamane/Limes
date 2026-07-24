"""The HTTP proxy with the **shipped** ``pii-egress`` detector wired, as a process.

    python guarded_http_proxy.py --upstream URL --port N [options]

The HTTP sibling of ``guarded_proxy.py``, and the reason both exist: the claim is
that the detector is transport-agnostic, and a claim about two transports is
worth exactly one of them until it has been run over both. Same
:func:`limes.transports.mcp.http.run_http`, same relay, same policy.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def main() -> int:
    """Serve the HTTP proxy with the admitted egress detector on the outbound leg."""
    sys.path.insert(0, str(REPO))
    from limes.detectors.pii_egress import PiiEgressDetector
    from limes.transports.mcp.http import parse_http_config, run_http

    config = parse_http_config(sys.argv[1:], prog="guarded-http-proxy")
    run_http(config, outbound=(PiiEgressDetector(),))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
