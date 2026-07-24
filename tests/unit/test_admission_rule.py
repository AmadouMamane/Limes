"""The admission rule enforcer (ADR 0003): no detector without eval + null control.

Also: the entry points and the canonical ``ADMITTED`` tuple name the same
detectors, with no silent fallback that could let a mis-declared plugin pass.

This file is the reason ``ADMITTED`` is safe to grow. v0.1 asserted that the
tuple held exactly one detector, which said nothing about the *second* one being
measured — it just made adding one fail. What is asserted now is stronger and
does not need editing when a detector lands honestly: **every** member of
``ADMITTED`` must have a positive corpus, a benign corpus, a beaten null control
and a published matrix, and the test goes red for any member whose measurement
it cannot run. A detector added to the tuple without its corpus does not produce
a green suite with a missing case; it produces this file, red, naming the
detector.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from limes.detectors import ADMITTED, InjectionDetector, PiiEgressDetector
from limes.eval.egress_harness import compute as egress_compute
from limes.eval.harness import compute as injection_compute
from limes.registry import discover

MATRICES = Path(__file__).resolve().parents[2] / "eval" / "matrices"


@dataclass(frozen=True)
class Measured:
    """One detector's admission evidence, however it was produced."""

    n_positive: int
    positive_hits: int
    null_hits: int
    n_benign: int
    benign_killed: int
    null_control: str
    matrix: Path


def _measure(detector_cls) -> Measured:
    """Run the admission measurement for ``detector_cls``, or fail saying why.

    A detector whose measurement cannot be reached is not "unmeasured pending
    work": it is inadmissible, and it takes this test down with it.
    """
    detector_id = detector_cls.id
    if detector_id == "injection":
        injection = injection_compute()
        blocked = injection.by_name("limes injection")
        return Measured(
            n_positive=blocked.n_attacks,
            positive_hits=blocked.attacks_blocked,
            null_hits=injection.by_name("unplugged (null control)").attacks_blocked,
            n_benign=blocked.n_benign,
            benign_killed=blocked.benign_killed,
            null_control=injection.null_control,
            matrix=MATRICES / "injection.md",
        )
    egress = egress_compute(detector_id)
    located = egress.subject
    return Measured(
        n_positive=located.n_positive,
        positive_hits=located.located,
        null_hits=egress.by_name("unplugged (null control)").located,
        n_benign=located.n_benign,
        benign_killed=located.benign_killed,
        null_control=egress.null_control,
        matrix=MATRICES / f"{detector_id.replace('-', '_')}.md",
    )


def test_entry_points_match_the_admitted_set():
    discovered = discover()
    assert set(discovered.values()) == set(ADMITTED)
    assert discovered.get("injection") is InjectionDetector
    assert discovered.get("pii-egress") is PiiEgressDetector


def test_the_admitted_set_only_ever_grew():
    # Nothing is removed by adding: v0.1's detector is still admitted, and the
    # tuple has no duplicate that would let one name shadow another.
    assert InjectionDetector in ADMITTED
    assert len(set(ADMITTED)) == len(ADMITTED)


@pytest.mark.parametrize("detector_cls", ADMITTED, ids=lambda cls: str(cls.id))
def test_every_admitted_detector_is_measured(detector_cls):
    measured = _measure(detector_cls)
    # A positive corpus, a benign corpus.
    assert measured.n_positive > 0
    assert measured.n_benign > 0
    # It beats the unplugged null control — measurably, not by assertion.
    assert measured.positive_hits > measured.null_hits
    # Two numbers, not one: the false-positive number exists and is measured.
    assert measured.benign_killed < measured.n_benign
    # The null control is stated (a NoEffect with power, or an honest CannotSay).
    assert measured.null_control.strip()


@pytest.mark.mutation
def test_a_detector_with_no_corpus_cannot_be_measured():
    # The enforcer, seen red on purpose. Admitting a detector is adding a name to
    # ADMITTED; if that could happen without a corpus, this whole file would be a
    # decoration (ADR 0003). It cannot: the measurement is unreachable, loudly.
    class Unmeasured:
        id = "unmeasured-egress"
        version = "0.0.0"

    with pytest.raises((FileNotFoundError, KeyError)):
        _measure(Unmeasured)


@pytest.mark.parametrize("detector_cls", ADMITTED, ids=lambda cls: str(cls.id))
def test_every_admitted_detector_publishes_a_dated_matrix(detector_cls):
    measured = _measure(detector_cls)
    assert measured.matrix.exists(), (
        f"{detector_cls.id} is admitted but publishes no confusion matrix at "
        f"{measured.matrix}; run `make eval`"
    )
    published = measured.matrix.read_text(encoding="utf-8")
    assert detector_cls.id in published
    assert "Generated 20" in published, "a matrix without its date is not dated"
