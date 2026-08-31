"""The egress policy is data, and a policy that cannot check refuses to load."""

from __future__ import annotations

import pytest

from limes.detectors.egress_policy import VALIDATORS, load_egress_policy


def _write(tmp_path, body):
    path = tmp_path / "egress.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_packaged_policy_loads_and_hashes():
    policy = load_egress_policy()
    assert policy.version >= 1
    assert len(policy.policy_hash) == 64
    assert "pii-egress" in policy.detectors()


def test_every_packaged_rule_names_a_validator_that_exists():
    for rule in load_egress_policy().rules:
        assert rule.validator in VALIDATORS
        assert callable(rule.check)


def test_rules_are_owned_by_their_detector():
    policy = load_egress_policy()
    labels = {rule.label for rule in policy.rules_for("pii-egress")}
    assert labels == {"pii:pan", "pii:iban", "pii:email", "pii:phone", "pii:nir"}
    assert policy.rules_for("no-such-detector") == ()


def test_every_label_carries_the_kind_the_transport_policies_by():
    # `pii:pan` -> kind `pii`. An egress policy keys its block/redact decision on
    # that half (ADR 0006), so a label with no kind would be unpolicyable.
    for rule in load_egress_policy().rules_for("pii-egress"):
        assert rule.label.startswith("pii:")


def test_an_unknown_validator_is_a_load_error_not_a_default(tmp_path):
    # The failure this refuses: a policy that loads, matches a shape, and vouches
    # for nothing — a detector reporting "clean" over a check that never ran.
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: definitely_not_a_validator\n"
        "        pattern: '\\d+'\n",
    )
    with pytest.raises(ValueError, match=r"not.*one of"):
        load_egress_policy(path)


def test_a_rule_with_no_validator_at_all_is_refused(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        pattern: '\\d+'\n",
    )
    with pytest.raises(ValueError, match="validator"):
        load_egress_policy(path)


def test_a_duplicate_label_is_refused(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n        pattern: 'a'\n"
        "      - label: pii:pan\n        validator: none\n        pattern: 'b'\n",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_egress_policy(path)


def test_an_empty_detector_block_is_refused(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules: []\n",
    )
    with pytest.raises(ValueError, match="non-empty 'rules'"):
        load_egress_policy(path)


def test_a_non_boolean_retry_trim_is_refused(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n"
        "        retry_trim: maybe\n        pattern: 'a'\n",
    )
    with pytest.raises(ValueError, match="retry_trim"):
        load_egress_policy(path)


def test_a_value_group_the_pattern_does_not_define_is_refused(tmp_path):
    # The failure this refuses: a rule declaring its value lives in a group its
    # own shape never captures — every match would silently span nothing.
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n"
        "        value_group: secret\n        pattern: '\\d+'\n",
    )
    with pytest.raises(ValueError, match="no group of that name"):
        load_egress_policy(path)


def test_value_group_with_retry_trim_is_refused(tmp_path):
    # Trimming re-derives the span from the whole match, narrowing derives it
    # from a group; the combination has no measured meaning and is refused
    # rather than guessed at.
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n        retry_trim: true\n"
        "        value_group: secret\n        pattern: '(?P<secret>\\d+)'\n",
    )
    with pytest.raises(ValueError, match="both value_group and"):
        load_egress_policy(path)


def test_a_non_string_value_group_is_refused(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n"
        "        value_group: 3\n        pattern: '(\\d+)'\n",
    )
    with pytest.raises(ValueError, match="value_group"):
        load_egress_policy(path)


def test_exactly_the_context_anchored_rule_declares_a_value_group():
    # Every rule before ADR 0022 spans its whole match; the AWS-secret rule is
    # the one whose shape includes context. A second value_group rule is not
    # wrong — but it must arrive by the same gate, so this list is explicit.
    grouped = [rule.label for rule in load_egress_policy().rules if rule.value_group is not None]
    assert grouped == ["secret:aws-secret-access-key"]


def test_the_hash_changes_with_the_file(tmp_path):
    first = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n        pattern: 'a'\n",
    )
    before = load_egress_policy(first).policy_hash
    first.write_text(
        "version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: 1000\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n        pattern: 'b'\n",
        encoding="utf-8",
    )
    assert load_egress_policy(first).policy_hash != before


def test_a_detector_with_no_scan_budget_is_refused(tmp_path):
    # A detector with no declared limit either sweeps an unbounded payload, or
    # stops at an undeclared point and cannot say where. Both are refusals to be
    # auditable, and the policy will not load either.
    path = _write(
        tmp_path,
        "version: 1\ndetectors:\n  pii-egress:\n    rules:\n"
        "      - label: pii:pan\n        validator: none\n        pattern: 'a'\n",
    )
    with pytest.raises(ValueError, match="max_content_chars"):
        load_egress_policy(path)


def test_a_zero_or_negative_budget_is_refused(tmp_path):
    for value in ("0", "-1"):
        path = _write(
            tmp_path,
            f"version: 1\ndetectors:\n  pii-egress:\n    max_content_chars: {value}\n"
            "    rules:\n      - label: pii:pan\n        validator: none\n        pattern: 'a'\n",
        )
        with pytest.raises(ValueError, match="max_content_chars"):
            load_egress_policy(path)


def test_the_packaged_policy_declares_a_budget_for_every_detector():
    policy = load_egress_policy()
    for detector in policy.detectors():
        assert policy.budget_for(detector) > 0
