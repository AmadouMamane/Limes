"""The inbound leg declares a scan budget too (ADR 0023), and a policy that cannot load says why.

Until ADR 0023 only the egress detectors declared ``max_content_chars``; the
inbound ``injection`` detector read whatever arrived. Seen red: the first test
returned an ``Allow`` over 200 001 characters before the budget existed.
"""

from __future__ import annotations

import pytest

from limes.detector import Context, DetectorBlind, Direction
from limes.detectors.injection import InjectionDetector
from limes.guard import decide
from limes.policy import DEFAULT_MAX_CONTENT_CHARS, load_injection_policy
from limes.verdict import CannotSay

pytestmark = pytest.mark.mutation

_CONTEXT = Context(policy_hash="budget", actor=None)
_OBSERVED_AT = "2026-09-06T00:00:00Z"
_RULES = "rules:\n  - label: 'injection:never'\n    origin: limes\n    pattern: 'zzz'\n"


def _policy(tmp_path, body: str):
    path = tmp_path / "policy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_content_over_the_declared_budget_makes_the_detector_blind():
    detector = InjectionDetector()
    budget = load_injection_policy().max_content_chars
    with pytest.raises(DetectorBlind, match="max_content_chars"):
        detector.inspect(Direction.INBOUND, "a" * (budget + 1), _CONTEXT)


def test_a_blind_inbound_detector_becomes_cannot_say_never_allow():
    budget = load_injection_policy().max_content_chars
    verdict = decide(
        Direction.INBOUND,
        "a" * (budget + 1),
        _CONTEXT,
        [InjectionDetector()],
        observed_at=_OBSERVED_AT,
    )
    assert isinstance(verdict, CannotSay)
    assert "injection" in verdict.blind_spot


def test_content_at_the_budget_is_still_scanned():
    budget = load_injection_policy().max_content_chars
    assert InjectionDetector().inspect(Direction.INBOUND, "a" * budget, _CONTEXT) == []


def test_the_packaged_policy_declares_the_budget_and_it_matches_egress():
    from limes.detectors.egress_policy import load_egress_policy

    policy = load_injection_policy()
    assert policy.max_content_chars == DEFAULT_MAX_CONTENT_CHARS
    egress = load_egress_policy()
    for detector_id in egress.detectors():
        assert egress.budget_for(detector_id) == policy.max_content_chars, (
            "both legs refuse at one size, or the README has to explain two"
        )


def test_a_policy_that_declares_no_budget_gets_the_default(tmp_path):
    # Injection policies written before ADR 0023 are in use; they keep loading.
    policy = load_injection_policy(_policy(tmp_path, f"version: 1\n{_RULES}"))
    assert policy.max_content_chars == DEFAULT_MAX_CONTENT_CHARS


def test_a_declared_budget_is_honoured(tmp_path):
    policy = load_injection_policy(
        _policy(tmp_path, f"version: 1\nmax_content_chars: 10\n{_RULES}")
    )
    assert policy.max_content_chars == 10
    with pytest.raises(DetectorBlind):
        InjectionDetector(policy).inspect(Direction.INBOUND, "x" * 11, _CONTEXT)


@pytest.mark.parametrize("value", ["0", "-1", "true", "'12'"])
def test_a_budget_that_is_not_a_positive_integer_is_refused(tmp_path, value):
    with pytest.raises(ValueError, match="max_content_chars"):
        load_injection_policy(
            _policy(tmp_path, f"version: 1\nmax_content_chars: {value}\n{_RULES}")
        )


def test_a_pattern_that_does_not_compile_is_a_value_error_not_a_traceback(tmp_path):
    # The CLI maps ValueError to exit 2 (a usage error); a bare re.error escaped
    # as a traceback with exit 1 — the code that means DENY.
    body = "version: 1\nrules:\n  - label: 'injection:x'\n    origin: limes\n    pattern: '(['\n"
    with pytest.raises(ValueError, match="does not compile"):
        load_injection_policy(_policy(tmp_path, body))


def test_invalid_yaml_is_a_value_error_not_a_traceback(tmp_path):
    with pytest.raises(ValueError, match="not valid YAML"):
        load_injection_policy(_policy(tmp_path, "version: [1\n"))


def test_the_egress_loader_keeps_the_same_contract(tmp_path):
    from limes.detectors.egress_policy import load_egress_policy

    path = tmp_path / "egress.yaml"
    path.write_text("version: 1\ndetectors: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_egress_policy(path)
    path.write_text(
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 10\n    rules:\n"
        "      - label: pii:x\n        validator: none\n        pattern: '(['\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="does not compile"):
        load_egress_policy(path)
