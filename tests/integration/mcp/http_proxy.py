"""The shipped HTTP proxy, as a spawnable process for the end-to-end tests.

    python http_proxy.py --upstream URL --port N [options]

This is exactly what ``limes proxy-http`` runs — :func:`limes.transports.mcp.http.main_http`
— nothing passed, nothing overridden, so the outbound leg carries whatever the
shipped default installs (every admitted egress detector, ADR 0018). It exists so
the tests can spawn the shipped proxy the same way an operator would, over real
HTTP — which is precisely what caught the leg empty.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def main() -> int:
    sys.path.insert(0, str(REPO))
    from limes.transports.mcp.http import main_http

    return main_http(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
