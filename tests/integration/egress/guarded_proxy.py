"""A real ``limes proxy`` process with the **shipped** ``pii-egress`` detector wired.

The difference from ``tests/integration/mcp/redacting_proxy.py`` is the whole
point of this work: that one installs a *double*, because until now limes shipped
no egress detector and the outbound seam was machinery with nobody to feed it.
This one installs :class:`~limes.detectors.pii_egress.PiiEgressDetector` — the
admitted plugin, the one with a corpus and a matrix — and nothing else changes:
same :func:`limes.transports.mcp.bridge.serve`, same relay, same policy parsing.

It stays a test fixture rather than becoming the default of ``limes-proxy``
because *which* detectors an operator wants on the outbound leg is a deployment
decision, and a proxy that silently masked everybody's tool results would be
making it for them. What the shipped proxy gains is that the choice is now
available at all.

Spawned exactly like the proxy: ``python guarded_proxy.py [options] -- <server…>``.
"""

from __future__ import annotations

import sys
from functools import partial
from pathlib import Path

import anyio

REPO = Path(__file__).resolve().parents[3]


def main() -> int:
    """Parse the same command line the proxy does, and serve with pii-egress wired."""
    sys.path.insert(0, str(REPO))
    from limes.detectors.pii_egress import PiiEgressDetector
    from limes.transports.mcp.bridge import serve
    from limes.transports.mcp.cli import parse_config

    config = parse_config(sys.argv[1:], prog="guarded-proxy")
    anyio.run(partial(serve, config, outbound=(PiiEgressDetector(),)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
