"""What the head-to-head comparison must be unable to do (ADR 0020).

A comparison written by one contestant's author is worth exactly what its
witnesses can check. These are the checks: the threshold cannot see the held-out
split, a missing score cannot become a zero, limes is scored on the union of its
legs rather than its better one, and the rendered matrix cannot drop the caveats
that make its numbers readable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from limes.eval.comparison_harness import (
    ATTACK_POPULATIONS,
    ATTACKS_DEV,
    ATTACKS_HOLDOUT,
    BENIGN_DEV,
    BENIGN_HOLDOUT,
    DECLARED_TOOLS,
    DEV_POPULATIONS,
    HIJACK_BLIND,
    JAILBREAK,
    LIMES_ROW,
    POPULATIONS,
    Cell,
    ComparisonCase,
    Competitor,
    case_key,
    comparison_cases,
    compute,
    limes_flags,
    load_competitors,
    render,
    results_dir,
    select_threshold,
    unique_cases,
)
from limes.eval.external_corpus import available, load_external, load_flat

pytestmark = pytest.mark.skipif(
    not available(),
    reason=(
        "the external adversary corpus lives under eval/ and ships in the sdist and a "
        "checkout, never in the wheel (ADR 0015: a blind spot, not an empty result)"
    ),
)


@pytest.fixture(scope="module")
def cases() -> tuple[ComparisonCase, ...]:
    return comparison_cases()


@pytest.fixture(scope="module")
def report():
    return compute()


def _competitor(scores: dict[str, float], **overrides: object) -> Competitor:
    defaults: dict[str, object] = {
        "tool": "fixture",
        "label": "fixture",
        "scope": "a fixture",
        "versions": {"fixture": "0"},
        "model": None,
        "default_threshold": 0.5,
        "default_configuration": "only",
        "configurations": {"only": scores},
        "notes": (),
        "latency_ms": None,
    }
    defaults.update(overrides)
    return Competitor(**defaults)  # type: ignore[arg-type]


# --- the ground -------------------------------------------------------------


def test_every_case_comes_from_the_corpus_nobody_here_wrote(cases):
    # The whole claim of this table. limes's own corpora — and above all
    # injection_benign.json, whose lookalikes were written to trip THESE rules —
    # must not leak in: scoring a competitor on a corpus written against one
    # specific detector would distort the answer in both directions at once.
    garak = {case.text for case in load_external("latent_injection").attacks}
    garak |= {case.text for case in load_external("latent_injection").benign}
    garak |= {case.text for case in load_external("latent_jailbreak").attacks}
    garak |= {case.text for case in load_flat("prompt_hijack").attacks}
    strangers = [case for case in cases if case.text not in garak]
    assert strangers == [], f"{len(strangers)} case(s) in the comparison are not garak's"


def test_every_population_is_populated(cases):
    for population in POPULATIONS:
        assert any(case.population == population for case in cases), population


def test_the_case_key_separates_every_distinct_text(cases):
    # The join between a committed results file and this enumeration is the key.
    # A collision would silently give two texts one verdict, and the matrix would
    # be a statement about a join nobody checked.
    texts = {case.text for case in cases}
    assert len({case_key(text) for text in texts}) == len(texts)


def test_the_benign_split_is_a_function_of_the_text_and_nothing_else(cases):
    # Unsteerable for the same reason the corpus's own split is: an author cannot
    # move an inconvenient control out of the reported half without changing the
    # control, which changes its hash.
    for case in cases:
        if case.population not in (BENIGN_DEV, BENIGN_HOLDOUT):
            continue
        import hashlib

        nibble = hashlib.sha256(case.text.encode("utf-8", "surrogatepass")).hexdigest()[0]
        expected = BENIGN_DEV if int(nibble, 16) < 8 else BENIGN_HOLDOUT
        assert case.population == expected


# --- the frozen threshold ---------------------------------------------------


def test_a_threshold_is_never_chosen_on_a_population_that_is_held_out():
    assert set(DEV_POPULATIONS) & {ATTACKS_HOLDOUT, HIJACK_BLIND, BENIGN_HOLDOUT} == set()
    assert set(DEV_POPULATIONS) <= {ATTACKS_DEV, BENIGN_DEV}


@pytest.mark.mutation
def test_the_tuned_row_cannot_see_the_holdout(cases):
    # The strong form, and the only one worth having: perturb every held-out and
    # blind score to the extreme and the chosen threshold must not move. Let
    # `_tuned` read one population outside DEV_POPULATIONS and this goes red.
    from limes.eval.comparison_harness import _tuned

    honest = {case.key: 0.9 if case.population in ATTACK_POPULATIONS else 0.1 for case in cases}
    poisoned = dict(honest)
    for case in cases:
        if case.population not in DEV_POPULATIONS:
            poisoned[case.key] = 0.5
    assert _tuned(cases, _competitor(honest)) == _tuned(cases, _competitor(poisoned))


def test_the_threshold_rule_prefers_the_more_conservative_of_two_equal_cuts():
    # Youden's J is flat between 0.2 and 0.4 here; the rule says take the higher.
    scored = [(0.9, True), (0.8, True), (0.1, False), (0.05, False)]
    assert select_threshold(scored) == 0.1


def test_a_threshold_needs_both_sides_to_mean_anything():
    # Positives alone would always choose zero and call it perfect recall.
    assert select_threshold([(0.9, True), (0.8, True)]) == 0.5


# --- a blind spot is not a zero ---------------------------------------------


@pytest.mark.mutation
def test_a_tool_that_did_not_score_a_case_is_not_credited_with_missing_it(cases):
    # Rule 7 of the protocol, and ADR 0026 under it. Score half the corpus and
    # every cell must say so rather than report a rate over what it happens to
    # have. Make an absent score default to False and this goes red.
    half = {case.key: 1.0 for index, case in enumerate(unique_cases(cases)) if index % 2 == 0}
    competitor = _competitor(half)
    verdicts = competitor.verdicts(cases, "only", 0.5)
    assert any(value is None for value in verdicts.values())
    cell = Cell("fixture", ATTACKS_DEV, hits=3, covered=3, total=10)
    assert cell.rate is None
    assert "not measured" in cell.render()


def test_a_full_cell_states_its_rate():
    assert Cell("x", ATTACKS_DEV, hits=3, covered=10, total=10).rate == pytest.approx(0.3)
    assert "30.0%" in Cell("x", ATTACKS_DEV, 3, 10, 10).render()


def test_a_declared_tool_with_no_results_is_named_and_not_scored(report):
    measured = {competitor.tool for competitor in report.competitors}
    assert set(report.missing) == set(DECLARED_TOOLS) - measured
    for name in report.missing:
        assert not any(row.label.startswith(name) for row in report.rows)


# --- limes's own row --------------------------------------------------------


def test_the_null_control_blocks_nothing(report):
    for population in POPULATIONS:
        assert report.row("unplugged (null control)").cell(population).hits == 0


@pytest.mark.mutation
def test_limes_is_scored_on_the_union_of_its_legs_not_its_better_one():
    # The proxy runs `injection` inbound and `injection-egress` outbound, so the
    # comparison must ask both. Drop either call in `limes_flags` and this goes
    # red — the inbound-only text below is one the outbound leg never inspects.
    from limes.detector import Context, Direction
    from limes.detectors.injection import InjectionDetector
    from limes.detectors.injection_egress import InjectionEgressDetector
    from limes.guard import decide
    from limes.verdict import Deny

    context = Context(policy_hash="test", actor=None)
    corpus = load_external("latent_injection")
    for case in corpus.attacks:
        inbound = isinstance(
            decide(
                Direction.INBOUND,
                case.text,
                context,
                [InjectionDetector()],
                observed_at="2026-01-01T00:00:00Z",
            ),
            Deny,
        )
        outbound = isinstance(
            decide(
                Direction.OUTBOUND,
                case.text,
                context,
                [InjectionEgressDetector()],
                observed_at="2026-01-01T00:00:00Z",
            ),
            Deny,
        )
        if inbound != outbound:
            assert limes_flags(case.text) is True
            return
    pytest.skip("the two legs agree on every case in this corpus, so the union is untestable here")


def test_limes_kills_none_of_the_matched_controls(report):
    # The corpus's strongest claim: the same documents with the injection removed.
    # If this ever goes non-zero the rules have learnt the document.
    for population in (BENIGN_DEV, BENIGN_HOLDOUT):
        assert report.row(LIMES_ROW).cell(population).hits == 0


def test_limes_claims_nothing_on_the_family_it_says_is_out_of_scope(report):
    assert report.row(LIMES_ROW).cell(JAILBREAK).hits == 0


# --- the committed results --------------------------------------------------


def test_every_committed_results_file_covers_every_case(cases):
    # A partial file would let a row quietly report a rate over the cases it
    # happens to hold. The bench script refuses to write one; this refuses to
    # trust that it did.
    keys = {case.key for case in cases}
    for competitor in load_competitors():
        for name, scores in competitor.configurations.items():
            missing = keys - set(scores)
            assert missing == set(), f"{competitor.tool}/{name} is missing {len(missing)} case(s)"


def test_every_committed_results_file_is_a_tool_the_harness_declares():
    for competitor in load_competitors():
        assert competitor.tool in DECLARED_TOOLS


def test_every_committed_results_file_names_what_produced_it():
    # A number whose versions are not written down cannot be re-derived, and an
    # un-re-derivable number in a comparison is a rumour.
    for path in sorted(results_dir().glob("*.results.json")):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        assert raw["versions"], path
        assert raw["generated_at"], path
        assert raw["scope"], path
        fidelity = raw["fidelity"]
        # A fidelity block that sampled nothing, or whose claim is blank, would read
        # as "checked" while checking nothing — the shape ADR 0026 exists to forbid.
        assert fidelity["claim"].strip(), path
        assert fidelity["sampled"] > 0, path
        assert fidelity["sampled"] == fidelity["agreements"], (
            f"{path.name} recorded a fidelity check that did not fully agree; the adapter "
            "does not reproduce the tool it claims to run"
        )


def test_the_vendor_default_is_the_vendors_and_is_written_down():
    # A comparison in which the author picked the competitor's threshold is a
    # comparison the author won. Each file records the shipped value, and the
    # harness reports that row before any tuned one.
    expected = {
        "llm-guard": 0.92,
        "rebuff": 0.75,
        "deberta-injection-v2": 0.5,
        "deepset-injection": 0.5,
    }
    for competitor in load_competitors():
        if competitor.tool in expected:
            assert competitor.default_threshold == expected[competitor.tool]


# --- the rendered matrix ----------------------------------------------------


def test_the_matrix_names_its_ground_its_grader_and_its_limits(report):
    markdown = render(report, when="2026-01-01")
    assert "garak" in markdown
    assert "no contestant wrote" in markdown.lower()
    # Two numbers, never one: the false-positive columns are never optional.
    for population in POPULATIONS:
        assert population in markdown
    assert "not thereby answered" in markdown
    assert "may have seen these attacks" in markdown


def test_the_matrix_answers_the_persuasion_question_from_its_own_numbers(report):
    markdown = render(report, when="2026-01-01")
    assert "LatentInjectionResumeFull" in markdown
    verdicts = ("Nobody catches it", "Something does catch it", "No competitor was measured")
    assert sum(verdict in markdown for verdict in verdicts) == 1


def test_the_matrix_says_which_row_under_states_its_tool(report):
    markdown = render(report, when="2026-01-01")
    if any(competitor.tool == "rebuff" for competitor in report.competitors):
        assert "under-states rebuff" in markdown
