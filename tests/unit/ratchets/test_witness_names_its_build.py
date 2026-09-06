"""A witness names the build that looked (ADR 0025).

Every shipped detector carried ``version = "0.1.0"`` through every change to its
rules and its code, so the ``Witness`` in every piece of evidence named a
detector that no longer existed. The version is now the package's own — the
string ``limes --version`` prints — so an auditor can reinstall exactly what
produced a verdict. Seen red: all four detectors reported "0.1.0".
"""

from __future__ import annotations

import pytest

import limes
from limes.detector import Context, Direction
from limes.detectors import ADMITTED
from limes.detectors.injection import InjectionDetector
from limes.guard import decide
from limes.verdict import Allow

pytestmark = pytest.mark.mutation


def test_every_admitted_detector_names_the_package_version():
    assert limes.__version__ != "0.1.0"
    for detector_cls in ADMITTED:
        assert detector_cls.version == limes.__version__, detector_cls.id


def test_the_witness_in_the_evidence_carries_that_version():
    verdict = decide(
        Direction.INBOUND,
        "Quel est le solde de mon compte ?",
        Context(policy_hash="build", actor=None),
        [InjectionDetector()],
        observed_at="2026-09-06T00:00:00Z",
    )
    assert isinstance(verdict, Allow)
    assert [w.detector_version for w in verdict.evidence.witnesses] == [limes.__version__]
