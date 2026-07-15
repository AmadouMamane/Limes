"""limes detectors — the admitted plugin set (ADR 0003/0004).

``ADMITTED`` is the canonical, code-level set of detectors that have passed the
admission rule (a positive corpus, a benign corpus, a null control, a published
matrix). A test asserts the ``limes.detectors`` entry points name exactly these,
so metadata and code cannot drift.
"""

from __future__ import annotations

from limes.detector import Detector
from limes.detectors.injection import InjectionDetector

ADMITTED: tuple[type[Detector], ...] = (InjectionDetector,)

__all__ = ["ADMITTED", "InjectionDetector"]
