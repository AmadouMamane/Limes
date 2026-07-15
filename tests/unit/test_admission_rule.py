"""The admission rule enforcer (ADR 0003): no detector without eval + null control.

Also: the entry points and the canonical ``ADMITTED`` tuple name the same
detectors, with no silent fallback that could let a mis-declared plugin pass.
"""

from __future__ import annotations

from limes.detectors import ADMITTED, InjectionDetector
from limes.eval.harness import compute
from limes.registry import discover


def test_entry_points_match_the_admitted_set():
    discovered = discover()
    assert set(discovered.values()) == set(ADMITTED)
    assert discovered.get("injection") is InjectionDetector


def test_the_sole_admitted_detector_is_the_injection_detector():
    # v0.1 admits exactly one detector; adding one without wiring its measurement
    # here (below) is caught by test_every_admitted_detector_is_measured.
    assert (InjectionDetector,) == ADMITTED


def test_every_admitted_detector_is_measured():
    report = compute()
    limes = report.by_name("limes injection")
    # A positive corpus, a benign corpus.
    assert limes.n_attacks > 0
    assert limes.n_benign > 0
    # It beats the unplugged null control (which blocks 0) — measurably.
    unplugged = report.by_name("unplugged (null control)")
    assert unplugged.attacks_blocked == 0
    assert limes.attacks_blocked > unplugged.attacks_blocked
    # Two numbers, not one: the false-positive number exists and is measured.
    assert limes.benign_killed == 0
    # The null control is stated (a NoEffect with power, or an honest CannotSay).
    assert report.null_control.strip()
