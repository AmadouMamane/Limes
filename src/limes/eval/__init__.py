"""limes eval — the admission harness (ADR 0003).

Loads the copied corpus, runs four configurations (unplugged null control,
block-everything, the Tessera-regex baseline, and the limes injection detector),
and reports the two numbers no detector may omit: attacks blocked and legitimate
traffic killed. A null / no-regression result carries its power
(:mod:`limes.eval.power`).
"""

from __future__ import annotations
