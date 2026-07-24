"""The grader may not be satisfied by tokens its own input handed the detector.

Tessera's injection grader once passed `08|en` green because the model echoed the
attacker's own word "instruction" *while obeying* — a refusal marker that lived
in the attack text (Tessera ADR 0028 §5, ported into limes as ADR 0003). The
egress form of that mistake is easier to make: every positive case *contains* the
value, so "the value is in the content" proves nothing, and "the detector
returned a finding" proves only that it fired somewhere.

So a case counts only when a finding's offsets reproduce the declared value at
its declared position. This file is the proof that the rule has teeth, and the
witness is `block-everything`: a detector that flags every message, scoring
**zero**.
"""

from __future__ import annotations

import pytest

from limes.eval.egress_corpus import load_benign, load_positive
from limes.eval.egress_harness import compute

DETECTORS = ["pii-egress", "secrets-egress"]


@pytest.mark.parametrize("detector", DETECTORS)
def test_block_everything_flags_all_and_locates_none(detector):
    report = compute(detector)
    blocker = report.by_name("block-everything")
    # It "catches" every single case…
    assert blocker.flagged == blocker.n_positive
    # …and is credited with none of them, because its span is the whole message.
    assert blocker.located == 0
    assert blocker.recall == 0.0
    # And it kills every benign input, which is the other half of the pair.
    assert blocker.benign_killed == blocker.n_benign


@pytest.mark.parametrize("detector", DETECTORS)
def test_the_unplugged_control_locates_nothing(detector):
    unplugged = compute(detector).by_name("unplugged (null control)")
    assert unplugged.located == 0
    assert unplugged.flagged == 0
    assert unplugged.benign_killed == 0


@pytest.mark.parametrize("detector", DETECTORS)
def test_the_subject_beats_the_null_control_measurably(detector):
    report = compute(detector)
    assert report.subject.located > report.by_name("unplugged (null control)").located
    assert report.null_control.startswith("ADMITTED")


@pytest.mark.parametrize("detector", DETECTORS)
def test_the_null_control_statement_carries_its_power(detector):
    # "No false positives" over a corpus too small to detect any is a fact about
    # the experiment, not the world (ADR 0003). The sentence names n and the
    # minimum detectable effect, or it says CANNOT SAY.
    statement = compute(detector).null_control
    assert "minimum detectable effect" in statement or statement.startswith("CANNOT SAY")


@pytest.mark.parametrize("detector", DETECTORS)
def test_the_baseline_verdict_is_a_number_or_an_honest_absence(detector):
    # Either there is a ported baseline and the verdict is arithmetic, or there
    # is none and the report SAYS so. What it may never be is a comparison
    # invented to dress up a detector nobody has anything to compare against
    # (ADR 0003) — which is exactly what secrets-egress would have tempted.
    verdict = compute(detector).baseline_verdict
    if verdict.startswith("NO BASELINE"):
        assert "null control is the baseline" in verdict
        return
    assert "located against" in verdict
    assert "benign killed against" in verdict


def test_exactly_one_egress_detector_has_a_ported_baseline():
    # Checked rather than assumed: Tessera's guard policy declares tools,
    # prompt_injection and pii — and no secrets section — so pii-egress has a
    # comparison point and secrets-egress does not.
    assert compute("pii-egress").baseline_verdict.startswith("limes pii-egress")
    assert compute("secrets-egress").baseline_verdict.startswith("NO BASELINE")


@pytest.mark.parametrize("detector", DETECTORS)
def test_every_positive_case_declares_a_value_its_own_content_contains(detector):
    # A case whose `locate` is absent from its `content` could never be located
    # and would be a permanent, unfixable false negative. The loader refuses it;
    # this asserts the shipped corpus is clean.
    for case in load_positive(detector):
        assert case.locate in case.content
        assert case.content.index(case.locate) == case.offset


@pytest.mark.parametrize("detector", DETECTORS)
def test_every_benign_case_names_the_category_it_imitates(detector):
    categories = {case.category for case in load_positive(detector)}
    for case in load_benign(detector):
        assert case.mimics in categories, (
            f"{case.case_id} mimics {case.mimics!r}, which is not a category the positive "
            f"corpus covers; its false positive could not be attributed to any rule"
        )


@pytest.mark.parametrize("detector", DETECTORS)
def test_both_corpora_are_non_trivial(detector):
    positive = load_positive(detector)
    benign = load_benign(detector)
    assert len(positive) >= 15
    # 0.5**n <= 0.05 needs n >= 5 for the sign test to have any power at all.
    assert len(benign) >= 5
    assert len({case.category for case in positive}) >= 5
