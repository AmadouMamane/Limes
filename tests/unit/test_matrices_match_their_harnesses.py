"""Every committed matrix is exactly what its harness computes (the honour gap).

``make eval`` regenerates ``eval/matrices/`` live, and nothing ever compared
those files to what the harnesses compute — every published number was on the
honour system, on the one asset that distinguishes this project. That gap let
two errors stand at once: the comparison matrix published "4 templates" over a
family the pinned corpus test said has five (a lowercasing re-derivation fused
the all-capitals template with its mixed-case twin), and the external injection
matrix published an egress-only measurement under a "both legs" label. Neither
run errored; both printed.

Each test recomputes one matrix with its own harness, stamps it with the date
the committed file already carries, and compares byte for byte — so a harness
change that moves a number without ``make eval`` being re-run, or a hand-edited
matrix, goes red here instead of shipping. The comparison matrix alone is
compared with its measured-latency tokens masked: a median measured on this
machine today is a measurement, not a regression, when it moves.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from limes.eval.external_corpus import ExternalCorpusUnavailable

# Seen red before the 2026-08-31 regeneration: the comparison and external
# injection pins failed against the pre-fix committed files, and go red again
# whenever any harness's numbers move without the matrices moving with them.
pytestmark = pytest.mark.mutation

_MATRICES = Path(__file__).resolve().parents[2] / "eval" / "matrices"


def _committed(name: str) -> str:
    path = _MATRICES / name
    if not path.is_file():
        pytest.skip(f"{name} ships in the repository and the sdist, never in the wheel")
    return path.read_text(encoding="utf-8")


def _when(committed: str) -> str:
    # Recompute with the committed file's own date, so equality does not depend
    # on the day this test runs.
    found = re.search(r"Generated (\d{4}-\d{2}-\d{2})", committed)
    assert found is not None, "a matrix states the date it was generated"
    return found.group(1)


def _or_skip[T](compute: Callable[[], T]) -> T:
    try:
        return compute()
    except ExternalCorpusUnavailable as unavailable:
        pytest.skip(str(unavailable))


def test_the_injection_matrix_matches_its_harness():
    from limes.eval import harness

    committed = _committed("injection.md")
    assert harness.render(harness.compute(), when=_when(committed)) + "\n" == committed


@pytest.mark.parametrize("detector", ["pii-egress", "secrets-egress", "injection-egress"])
def test_the_egress_matrices_match_their_harness(detector):
    from limes.eval import egress_harness

    committed = _committed(f"{detector.replace('-', '_')}.md")
    report = egress_harness.compute(detector)
    assert egress_harness.render(report, when=_when(committed)) + "\n" == committed


def test_the_external_injection_matrix_matches_its_harness():
    from limes.eval import external_harness

    committed = _committed("external_injection.md")
    report = _or_skip(lambda: external_harness.compute(("dev", "holdout")))
    assert external_harness.render(report, when=_when(committed)) + "\n" == committed


def test_the_external_pii_matrix_matches_its_harness():
    from limes.eval import external_egress_harness

    committed = _committed("external_pii.md")
    report = _or_skip(lambda: external_egress_harness.compute_pii(("dev", "holdout")))
    assert external_egress_harness.render_pii(report, when=_when(committed)) + "\n" == committed


def test_the_external_secrets_matrix_matches_its_harness():
    from limes.eval import external_egress_harness

    committed = _committed("external_secrets.md")
    report = _or_skip(lambda: external_egress_harness.compute_secrets(("dev", "holdout")))
    assert external_egress_harness.render_secrets(report, when=_when(committed)) + "\n" == committed


def _mask_latency(text: str) -> str:
    return re.sub(r"median \d+(?:\.\d+)? ms/case", "median [measured] ms/case", text)


def test_the_comparison_matrix_matches_up_to_measured_latency():
    from limes.eval import comparison_harness

    committed = _committed("comparison.md")
    report = _or_skip(comparison_harness.compute)
    rendered = comparison_harness.render(report, when=_when(committed)) + "\n"
    assert _mask_latency(rendered) == _mask_latency(committed)


@pytest.mark.parametrize("bench", ["pii", "secrets"])
def test_the_egress_comparison_matrices_match_up_to_measured_latency(bench):
    from limes.eval import egress_comparison_harness

    committed = _committed(f"comparison_{bench}.md")
    report = _or_skip(lambda: egress_comparison_harness.compute(bench))
    rendered = egress_comparison_harness.render(report, when=_when(committed)) + "\n"
    assert _mask_latency(rendered) == _mask_latency(committed)
