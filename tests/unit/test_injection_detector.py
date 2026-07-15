"""The injection detector — the measured numbers (ADR 0003).

Freezes the real measurement: limes dominates the Tessera-regex baseline (a
superset of what it catches), closes case 08 in all three languages, and adds no
false positives. The residual misses are frozen as a set that may only shrink.
"""

from __future__ import annotations

from limes.baselines.tessera_regex import TesseraRegexBaseline
from limes.detector import Context, Direction
from limes.detectors.injection import InjectionDetector
from limes.eval.corpus import CASE_08, load_attacks, load_benign
from limes.eval.harness import compute
from limes.guard import decide
from limes.verdict import Allow, Deny
from tests.conftest import FIXED_OBSERVED_AT

# The 8 attack prompts limes does NOT yet block, measured on tree-of-record.
# This set may only SHRINK: a new miss is a regression (test goes red); fixing
# one is progress (the subset check stays green). Case 08 may never enter it.
FROZEN_LIMES_MISSES = frozenset(
    {
        "11_prompt_injection_base64|de",
        "41_prompt_injection_rag_poison|de",
        "41_prompt_injection_rag_poison|en",
        "42_prompt_injection_email_zeroclick|de",
        "42_prompt_injection_email_zeroclick|en",
        "43_prompt_injection_binding_offer|fr",
        "43_prompt_injection_binding_offer|de",
        "43_prompt_injection_binding_offer|en",
    }
)


def _blocked(detector, text: str) -> bool:
    ctx = Context(policy_hash="t", actor=None)
    return isinstance(
        decide(Direction.INBOUND, text, ctx, [detector], observed_at=FIXED_OBSERVED_AT), Deny
    )


def test_case_08_is_denied_in_every_language():
    detector = InjectionDetector()
    langs = [a.language for a in load_attacks() if a.case_id == CASE_08]
    assert sorted(langs) == ["de", "en", "fr"]
    for attack in load_attacks():
        if attack.case_id == CASE_08:
            assert _blocked(detector, attack.text), f"08|{attack.language} slipped the guard"


def test_baseline_is_blind_to_case_08():
    # The gap is real: the ported Tessera patterns miss 08 in all three languages.
    baseline = TesseraRegexBaseline()
    for attack in load_attacks():
        if attack.case_id == CASE_08:
            assert not _blocked(baseline, attack.text), (
                f"baseline unexpectedly caught 08|{attack.language}"
            )


def test_limes_dominates_the_baseline():
    # Every attack the baseline blocks, limes blocks (limes runs all baseline rules + more).
    detector, baseline = InjectionDetector(), TesseraRegexBaseline()
    for attack in load_attacks():
        if _blocked(baseline, attack.text):
            assert _blocked(detector, attack.text), f"regression: limes missed {attack.key}"


def test_benign_inputs_are_allowed():
    detector = InjectionDetector()
    ctx = Context(policy_hash="t", actor=None)
    for text in load_benign():
        verdict = decide(Direction.INBOUND, text, ctx, [detector], observed_at=FIXED_OBSERVED_AT)
        assert isinstance(verdict, Allow), f"benign input killed: {text!r}"


def test_residual_misses_only_shrink():
    detector = InjectionDetector()
    misses = {a.key for a in load_attacks() if not _blocked(detector, a.text)}
    assert misses <= FROZEN_LIMES_MISSES, f"new miss(es): {sorted(misses - FROZEN_LIMES_MISSES)}"
    assert not any(key.startswith(CASE_08) for key in misses), "case 08 must stay closed"


def test_the_two_numbers_are_frozen():
    report = compute()
    limes = report.by_name("limes injection")
    baseline = report.by_name("tessera-regex baseline")
    assert (limes.n_attacks, limes.n_benign) == (33, 8)
    assert baseline.attacks_blocked == 22  # the ported Tessera recall, fixed
    assert limes.attacks_blocked >= 25  # 22 + case 08 in fr/de/en; may only improve
    assert limes.benign_killed == 0
    assert baseline.benign_killed == 0
    assert "NO EFFECT" in report.null_control  # the no-regression claim, with its power


def test_a_deny_redacts_what_it_matched():
    detector = InjectionDetector()
    ctx = Context(policy_hash="t", actor=None)
    attack = next(a for a in load_attacks() if a.case_id == CASE_08 and a.language == "en")
    verdict = decide(Direction.INBOUND, attack.text, ctx, [detector], observed_at=FIXED_OBSERVED_AT)
    assert isinstance(verdict, Deny)
    assert verdict.evidence.matched_spans, "a Deny must carry the spans that fired"
    for span in verdict.evidence.matched_spans:
        assert len(span.matched_sha) == 64  # a sha, not the raw payload
        assert (
            attack.text[span.start : span.end] not in verdict.reason
        )  # payload never in the reason
