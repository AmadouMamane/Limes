"""``python -m limes.transports.mcp`` — the same thing as ``limes-proxy``.

The console scripts need the package to be installed; this module does not, so
tests and benchmarks can drive the real entry point from a source checkout.
"""

from __future__ import annotations

from limes.transports.mcp.cli import main_proxy

if __name__ == "__main__":
    raise SystemExit(main_proxy())
