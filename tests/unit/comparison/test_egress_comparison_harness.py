"""What the outbound head-to-head must be unable to do (ADR 0030).

The rules are ADR 0020's, applied to the two data detectors: the ground is the
vendored external corpora and never limes's own lookalikes, the threshold cannot
see the held-out split, a missing finding cannot become a zero, a tool with no
score cannot be given a second operating point by writing its cut differently,
and limes's misses on its own perimeter are explained one by one — with the
notes held to exactly the set of misses, so a note cannot outlive its miss.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from limes.eval.egress_comparison_harness import (
    BENCHES,
    CLAIMED_FORMAT_NOTES,
    CLAIMED_FORMATS,
    DECLARED_EGRESS_TOOLS,
    LIMES_ROWS,
    PII_DECOY_DEV,
    PII_DECOY_HOLDOUT,
    PII_LOCATED_DEV,
    PII_LOCATED_HOLDOUT,
    PII_OUT_OF_SCOPE,
    PII_REMOVED_DEV,
    PII_REMOVED_HOLDOUT,
    SECRETS_LOCATED_DEV,
    SECRETS_LOCATED_HOLDOUT,
    SECRETS_NEGATIVES_DEV,
    SECRETS_NEGATIVES_HOLDOUT,
    EgressCase,
    EgressCompetitor,
    Finding,
    compute,
    cost_populations,
    dev_populations,
    egress_cases,
    hit,
    is_boolean,
    limes_findings,
    load_egress_competitors,
    render,
    results_dir,
    unique_egress_cases,
)
from limes.eval.external_corpus import available
from limes.eval.external_egress_corpus import load_pii_external, load_secrets_external

pytestmark = pytest.mark.skipif(
    not available(),
    reason=(
        "the external corpora live under eval/ and ship in the sdist and a checkout, never "
        "in the wheel (ADR 0015: a blind spot, not an empty result)"
    ),
)


@pytest.fixture(scope="module", params=BENCHES)
def bench(request) -> str:
    return str(request.param)


@pytest.fixture(scope="module")
def report(bench):
    return compute(bench)


def _competitor(
    bench: str, findings: dict[str, tuple[Finding, ...]], **overrides: object
) -> EgressCompetitor:
    defaults: dict[str, object] = {
        "bench": bench,
        "tool": "fixture",
        "label": "fixture",
        "scope": "a fixture",
        "versions": {"fixture": "0"},
        "model": None,
        "default_threshold": 0.5,
        "default_configuration": "only",
        "configurations": {"only": findings},
        "notes": (),
        "latency_ms": None,
        "home_ground": None,
    }
    defaults.update(overrides)
    return EgressCompetitor(**defaults)  # type: ignore[arg-type]


# --- the ground -------------------------------------------------------------


def test_every_case_comes_from_a_vendored_corpus_nobody_here_wrote(bench):
    if bench == "pii":
        pii = load_pii_external()
        known = {c.content for c in (*pii.attacks, *pii.controls, *pii.out_of_scope)}
    else:
        secrets = load_secrets_external()
        known = {c.content for c in (*secrets.attacks, *secrets.negatives)}
    strangers = [case for case in egress_cases(bench) if case.text not in known]
    assert strangers == [], f"{len(strangers)} case(s) are not from the vendored corpus"


def test_every_population_is_populated(bench):
    cases = egress_cases(bench)
    expected = (
        (
            PII_LOCATED_DEV,
            PII_LOCATED_HOLDOUT,
            PII_DECOY_DEV,
            PII_DECOY_HOLDOUT,
            PII_REMOVED_DEV,
            PII_REMOVED_HOLDOUT,
            PII_OUT_OF_SCOPE,
        )
        if bench == "pii"
        else (
            SECRETS_LOCATED_DEV,
            SECRETS_LOCATED_HOLDOUT,
            SECRETS_NEGATIVES_DEV,
            SECRETS_NEGATIVES_HOLDOUT,
        )
    )
    for population in expected:
        assert any(case.population == population for case in cases), population


def test_the_case_key_separates_every_distinct_text(bench):
    texts = {case.text for case in egress_cases(bench)}
    assert len({case.key for case in unique_egress_cases(egress_cases(bench))}) == len(texts)


def test_the_negative_split_is_a_function_of_the_text_alone():
    for case in egress_cases("secrets"):
        if case.population not in (SECRETS_NEGATIVES_DEV, SECRETS_NEGATIVES_HOLDOUT):
            continue
        nibble = hashlib.sha256(case.text.encode("utf-8", "surrogatepass")).hexdigest()[0]
        expected = SECRETS_NEGATIVES_DEV if int(nibble, 16) < 8 else SECRETS_NEGATIVES_HOLDOUT
        assert case.population == expected


# --- the grader -------------------------------------------------------------


def _case(bench: str, text: str, locate: str, population: str) -> EgressCase:
    return EgressCase(
        bench=bench, population=population, category="pan", text=text, locate=locate, template="t"
    )


def test_a_pii_hit_needs_an_in_scope_category_at_the_exact_span():
    case = _case("pii", "Card 4242 4242 4242 4242 lost.", "4242 4242 4242 4242", PII_LOCATED_DEV)
    exact = Finding("CREDIT_CARD", "pan", 5, 24, 1.0)
    wider = Finding("CREDIT_CARD", "pan", 0, 30, 1.0)
    other_kind = Finding("DATE_TIME", None, 5, 24, 1.0)
    assert hit(case, (exact,), 0.5) is True
    assert hit(case, (wider,), 0.5) is False, (
        "a tool that fires on the whole message locates nothing"
    )
    assert hit(case, (other_kind,), 0.5) is False, "a kind limes does not claim is not credited"
    assert hit(case, (exact,), 1.0) is False, "score > threshold, like every other table"


def test_a_pii_control_is_killed_only_by_an_in_scope_finding():
    control = _case("pii", "Card the reference held on file lost.", "", PII_DECOY_DEV)
    assert hit(control, (Finding("PERSON", None, 0, 4, 0.85),), 0.0) is False
    assert hit(control, (Finding("PHONE_NUMBER", "phone", 0, 4, 0.4),), 0.0) is True


def test_a_secret_hit_is_any_finding_wholly_inside_the_token():
    text = "Deployment log line: ghp_abcdefghijklmnopqrstuvwxyz0123456789 — end of line."
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    case = _case("secrets", text, token, SECRETS_LOCATED_DEV)
    start = text.index(token)
    assert hit(case, (Finding("GitHub Token", None, start, start + 3, 1.0),), 0.5) is True
    assert hit(case, (Finding("anything", None, start, start + len(token), 1.0),), 0.5) is True
    assert hit(case, (Finding("carrier", None, 0, len(text), 1.0),), 0.5) is False
    negative = _case("secrets", text, "", SECRETS_NEGATIVES_DEV)
    assert hit(negative, (Finding("carrier", None, 0, 10, 1.0),), 0.5) is True


def test_a_tool_that_did_not_score_a_case_is_not_credited_with_missing_it(bench):
    case = egress_cases(bench)[0]
    assert hit(case, None, 0.5) is None
    competitor = _competitor(bench, {})
    verdicts = competitor.verdicts(egress_cases(bench), "only", 0.5)
    assert all(value is None for value in verdicts.values())
    for row in compute(bench, directory=results_dir(bench) / "nowhere").rows:
        for cell in row.cells:
            assert cell.covered == cell.total, "limes and the controls cover everything"


# --- the frozen threshold ---------------------------------------------------


def test_a_threshold_is_never_chosen_on_a_population_that_is_held_out(bench):
    chosen = set(dev_populations(bench))
    held_out = {
        PII_LOCATED_HOLDOUT,
        PII_DECOY_HOLDOUT,
        PII_REMOVED_HOLDOUT,
        SECRETS_LOCATED_HOLDOUT,
        SECRETS_NEGATIVES_HOLDOUT,
    }
    assert chosen & held_out == set()
    assert PII_OUT_OF_SCOPE not in chosen, "five sentences may not steer a cut"


@pytest.mark.mutation
def test_the_tuned_row_cannot_see_the_holdout(bench):
    # Perturb every held-out finding to the extreme and the chosen cut must not move.
    from limes.eval.egress_comparison_harness import _tuned

    cases = egress_cases(bench)
    dev = set(dev_populations(bench))

    def findings(score_for_holdout: float) -> dict[str, tuple[Finding, ...]]:
        out = {}
        for case in cases:
            if case.population in dev:
                score = 0.9 if not case.is_cost else 0.1
            else:
                score = score_for_holdout
            if case.locate:
                start = case.text.index(case.locate)
                out[case.key] = (
                    (
                        case.category if bench == "pii" else "x",
                        "pan" if bench == "pii" else None,
                        start,
                        start + len(case.locate),
                        score,
                    ),
                )
            else:
                out[case.key] = (
                    (
                        "PHONE_NUMBER" if bench == "pii" else "x",
                        "phone" if bench == "pii" else None,
                        0,
                        1,
                        score,
                    ),
                )
        return {k: tuple(Finding(*f) for f in v) for k, v in out.items()}

    honest = _competitor(bench, findings(0.5))
    poisoned = _competitor(bench, findings(0.999))
    assert _tuned(cases, honest) == _tuned(cases, poisoned)


# --- a tool with no score has one operating point ------------------------------


def test_a_boolean_tool_gets_no_row_for_switching_it_off(bench):
    cases = egress_cases(bench)
    # A tool that flags every control and nothing else: Youden would rather switch
    # it off, and the zero-false-positive cut certainly would. Neither is a row.
    findings: dict[str, tuple[Finding, ...]] = {}
    for case in unique_egress_cases(cases):
        findings[case.key] = (
            (Finding("x", "phone" if bench == "pii" else None, 0, 1, 1.0),) if case.is_cost else ()
        )
    competitor = _competitor(bench, findings)
    assert is_boolean(competitor)
    from limes.eval.egress_comparison_harness import _tuned, _tuned_at_limes_precision

    assert _tuned_at_limes_precision(cases, competitor, 0) is not None, "the cut exists"
    assert _tuned(cases, competitor) is not None
    # …and yet the report, which applies the rule, publishes the vendor row alone.
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        payload = {
            "bench": bench,
            "tool": "fixture",
            "label": "fixture",
            "scope": "a fixture",
            "versions": {"fixture": "0"},
            "default": {"configuration": "only", "threshold": 0.5},
            "configurations": {
                "only": {
                    "findings": {
                        key: [[f.kind, f.category, f.start, f.end, f.score] for f in items]
                        for key, items in findings.items()
                    }
                }
            },
        }
        (root / "fixture.results.json").write_text(json.dumps(payload), encoding="utf-8")
        rows = [row.label for row in compute(bench, directory=root).rows]
    assert "fixture — vendor default" in rows
    assert not any(label.startswith("fixture — dev-tuned") for label in rows)


# --- limes's own rows -------------------------------------------------------


def test_the_null_control_blocks_nothing(report):
    for cell in report.row("unplugged (null control)").cells:
        assert cell.hits == 0


def test_limes_kills_no_value_removed_control(report):
    if report.bench != "pii":
        return
    for population in (PII_REMOVED_DEV, PII_REMOVED_HOLDOUT, PII_OUT_OF_SCOPE):
        assert report.row(LIMES_ROWS["pii"]).cell(population).hits == 0, (
            "a detector firing on a sentence with no value has learnt the sentence"
        )


def test_limes_is_scored_by_the_same_grader_as_everybody_else():
    from limes.detectors.pii_egress import PiiEgressDetector

    text = "My credit card 4242 4242 4242 4242 has been lost."
    found = limes_findings(PiiEgressDetector(), text)
    assert [(f.category, text[f.start : f.end]) for f in found] == [("pan", "4242 4242 4242 4242")]


def test_a_blind_detector_locates_nothing_and_kills_nothing():
    # ADR 0028: a declared blind spot is neither a hit nor a false positive.
    from limes.detectors.secrets_egress import SecretsEgressDetector

    dump = ("QmFzZTY0IGlzIG5vdCB0ZXh0IHRoZSBydWxlcyBjYW4gcmVhZDsgaXQgaXMgYW4gZW52ZWxvcGUu" * 4)[
        :240
    ]
    assert limes_findings(SecretsEgressDetector(), dump) == ()


# --- the perimeter, held honestly -------------------------------------------


def test_every_claimed_format_is_a_rule_of_the_vendored_catalogue():
    rules = {case.category for case in egress_cases("secrets") if not case.is_cost}
    missing = sorted(set(CLAIMED_FORMATS) - rules)
    assert missing == [], f"claimed formats naming no catalogue rule: {missing}"
    labels = {
        rule.label
        for rule in __import__("limes.detectors.egress_policy", fromlist=["load_egress_policy"])
        .load_egress_policy()
        .rules_for("secrets-egress")
    }
    unknown = sorted(set(CLAIMED_FORMATS.values()) - labels)
    assert unknown == [], f"claimed formats naming no limes rule: {unknown}"


def test_the_notes_explain_exactly_the_claimed_formats_limes_misses():
    # A note cannot outlive its miss, and a miss cannot go unexplained.
    from limes.detectors.secrets_egress import SecretsEgressDetector

    detector = SecretsEgressDetector()
    misses = set()
    for case in egress_cases("secrets"):
        if case.is_cost or case.category not in CLAIMED_FORMATS:
            continue
        if not hit(case, limes_findings(detector, case.text), 0.5):
            misses.add(case.category)
    assert set(CLAIMED_FORMAT_NOTES) == misses


# --- the committed results --------------------------------------------------


@pytest.mark.parametrize("which", BENCHES)
def test_every_committed_results_file_covers_every_case_and_names_what_produced_it(which):
    keys = {case.key for case in egress_cases(which)}
    for competitor in load_egress_competitors(which):
        assert competitor.bench == which
        assert competitor.tool in DECLARED_EGRESS_TOOLS[which]
        for name, findings in competitor.configurations.items():
            missing = keys - set(findings)
            assert missing == set(), f"{competitor.tool}/{name} is missing {len(missing)} case(s)"
    for path in sorted(results_dir(which).glob("*.results.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["versions"], path
        assert raw["generated_at"], path
        assert raw["scope"], path
        fidelity = raw["fidelity"]
        assert fidelity["claim"].strip(), path
        assert fidelity["sampled"] > 0, path
        assert fidelity["sampled"] == fidelity["agreements"], (
            f"{path.name} recorded a fidelity check that did not fully agree"
        )


def test_the_corpus_authors_rows_are_marked_home_ground():
    for competitor in load_egress_competitors("secrets"):
        if competitor.tool == "gitleaks":
            assert competitor.home_ground
    for competitor in load_egress_competitors("pii"):
        if competitor.tool == "presidio":
            assert competitor.home_ground


def test_the_vendor_default_is_the_vendors_and_is_written_down():
    expected = {
        ("pii", "presidio"): 0.0,
        ("pii", "mcp-firewall"): 0.5,
        ("secrets", "gitleaks"): 0.5,
        ("secrets", "detect-secrets"): 0.5,
        ("secrets", "mcp-firewall"): 0.5,
    }
    for which in BENCHES:
        for competitor in load_egress_competitors(which):
            if (which, competitor.tool) in expected:
                assert competitor.default_threshold == expected[(which, competitor.tool)]


def test_a_declared_tool_with_no_results_is_named_and_not_scored(report):
    measured = {competitor.tool for competitor in report.competitors}
    assert set(report.missing) == set(DECLARED_EGRESS_TOOLS[report.bench]) - measured
    for name in report.missing:
        assert not any(row.label.startswith(name) for row in report.rows)


# --- the rendered matrix ----------------------------------------------------


def test_the_matrix_names_its_ground_its_grader_and_its_limits(report):
    markdown = render(report, when="2026-01-01")
    assert "measured here" in markdown
    assert "Located means located" in markdown
    for population in cost_populations(report.bench):
        assert population in markdown, "two numbers, never one"
    assert "What this table does not measure" in markdown
    assert "Everything limes is actually for" in markdown
    if report.bench == "secrets":
        assert "Held to the formats limes claims" in markdown
        for rule in CLAIMED_FORMAT_NOTES:
            assert f"`{rule}` —" in markdown
    else:
        assert "Per category" in markdown


def test_the_matrix_marks_home_ground_where_the_corpus_is_the_contestants(report):
    markdown = render(report, when="2026-01-01")
    if any(competitor.home_ground for competitor in report.competitors):
        assert "Home ground" in markdown
        assert "not a comparison" in markdown
