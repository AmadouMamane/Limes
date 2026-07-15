"""Comparison baselines — not shipping detectors (ADR 0003).

A baseline exists to make a detector's contribution a *delta*. The Tessera-regex
baseline reproduces Tessera's injection recall (and its blind spot on case 08),
so the injection detector's value is measured against it, not against zero.
"""

from __future__ import annotations

from limes.baselines.tessera_regex import TesseraRegexBaseline

__all__ = ["TesseraRegexBaseline"]
