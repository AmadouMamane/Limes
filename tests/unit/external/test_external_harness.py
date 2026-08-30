from __future__ import annotations

import pytest

from limes.eval.external_corpus import available
from limes.eval.external_harness import CONFIGURATIONS, compute, render

pytestmark = pytest.mark.skipif(
    not available(),
    reason="the external adversary corpus is not in this checkout (ADR 0015)",
)


@pytest.fixture(scope="module")
def dev_report():
    return compute(("dev",))


def test_the_null_control_blocks_nothing(dev_report):
    # Without it the recall column below means nothing: every number here is only
    # ever "better than doing nothing", and this is the "nothing".
    for population in ("attacks (dev)", "matched benign documents"):
        assert dev_report.cell("unplugged (null control)", population).hits == 0


def test_the_matched_controls_survive_every_configuration(dev_report):
    # The strong claim of this corpus: the same documents, minus the injection,
    # are not blocked. If this ever goes non-zero the detector has learnt the
    # document and the recall number stops being about injections at all.
    for name, _ in CONFIGURATIONS:
        assert dev_report.cell(name, "matched benign documents").hits == 0, name


def test_the_out_of_scope_row_is_present_and_named(dev_report):
    cell = dev_report.cell("injection-egress (outbound leg)", "out of scope (jailbreak)")
    assert cell.total > 0


def test_holdout_is_absent_unless_asked_for(dev_report):
    # The protocol made mechanical: an author iterating on rules runs the default
    # and cannot see the held-out number, so it stays held out (ADR 0017).
    assert dev_report.splits == ("dev",)
    populations = {cell.population for cell in dev_report.cells}
    assert "attacks (holdout)" not in populations


def test_the_rendered_matrix_states_its_provenance_and_its_protocol(dev_report):
    markdown = render(dev_report, when="2026-01-01")
    assert "garak" in markdown
    assert "Apache-2.0" in markdown
    assert "NVIDIA" in markdown
    assert "holdout is scored once" in markdown
    # The number is only meaningful beside what it was measured against.
    assert "matched benign documents" in markdown
    assert "out of scope (jailbreak)" in markdown
