"""limes detectors — the admitted plugin set (ADR 0003/0004).

``ADMITTED`` is the canonical, code-level set of detectors that have passed the
admission rule (a positive corpus, a benign corpus, a null control, a published
matrix). A test asserts the ``limes.detectors`` entry points name exactly these,
so metadata and code cannot drift.

This tuple is the one place in the package that is *meant* to grow: ADR 0004 says
a new capability is a detector, and a registry that could never gain an entry
would make ADR 0003's admission procedure unreachable. What may not happen is a
name appearing here without its two numbers — enforced, not asserted, by
``tests/unit/test_admission_rule.py``, which refuses any member whose measurement
it cannot run.
"""

from __future__ import annotations

from limes.detector import Detector
from limes.detectors.injection import InjectionDetector
from limes.detectors.injection_egress import InjectionEgressDetector
from limes.detectors.pii_egress import PiiEgressDetector
from limes.detectors.secrets_egress import SecretsEgressDetector

ADMITTED: tuple[type[Detector], ...] = (
    InjectionDetector,
    PiiEgressDetector,
    SecretsEgressDetector,
    InjectionEgressDetector,
)

__all__ = [
    "ADMITTED",
    "InjectionDetector",
    "InjectionEgressDetector",
    "PiiEgressDetector",
    "SecretsEgressDetector",
]
