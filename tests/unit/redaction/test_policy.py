"""The egress policy is data, and the default is the closed one.

Every test here is about one question: what does an operator get for what they
wrote? In particular, what do they get for writing *nothing* (block), and for
writing something wrong (an error, never a silent fallback).
"""

from __future__ import annotations

import pytest

from limes.transports.redaction import (
    DEFAULT_ON_EGRESS_FINDING,
    EgressPolicy,
    OnEgressFinding,
    kind_of,
    read_egress_policy,
)


def _policy_file(tmp_path, body: str):
    path = tmp_path / "policy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_kind_is_the_half_of_the_label_before_the_colon():
    assert kind_of("pii:pan") == "pii"
    assert kind_of("injection:embedded-system-directive") == "injection"
    assert kind_of("secret:aws:key") == "secret", "only the first colon splits"
    assert kind_of("unlabelled") == "unlabelled", "a label with no colon is its own kind"


def test_the_default_policy_blocks_every_kind():
    policy = EgressPolicy.blocking()
    assert DEFAULT_ON_EGRESS_FINDING is OnEgressFinding.BLOCK
    for kind in ("pii", "secret", "injection", "a-kind-nobody-thought-about"):
        assert policy.action_for(kind) is OnEgressFinding.BLOCK
    assert not policy.redacts_anything()


def test_a_file_without_the_key_declares_nothing(tmp_path):
    # `None` rather than a blocking policy: the caller must apply the default and
    # be seen to. Returning a policy object here would hide which layer decided.
    path = _policy_file(tmp_path, "version: 1\nrules: []\n")
    assert read_egress_policy(path) is None


def test_the_scalar_form_sets_the_default(tmp_path):
    path = _policy_file(tmp_path, "version: 1\non_egress_finding: redact\nrules: []\n")
    policy = read_egress_policy(path)
    assert policy == EgressPolicy(default=OnEgressFinding.REDACT, by_kind={})
    assert policy is not None
    assert policy.redacts_anything()


def test_the_mapping_form_sets_the_default_and_the_kinds(tmp_path):
    path = _policy_file(
        tmp_path,
        "version: 1\n"
        "on_egress_finding:\n"
        "  default: block\n"
        "  by_kind:\n"
        "    pii: redact\n"
        "    secret: block\n"
        "rules: []\n",
    )
    policy = read_egress_policy(path)
    assert policy is not None
    assert policy.action_for("pii") is OnEgressFinding.REDACT
    assert policy.action_for("secret") is OnEgressFinding.BLOCK
    assert policy.action_for("phi") is OnEgressFinding.BLOCK, "an unnamed kind gets the default"
    assert policy.redacts_anything()


def test_a_mapping_without_a_default_still_defaults_to_block(tmp_path):
    path = _policy_file(
        tmp_path,
        "version: 1\non_egress_finding:\n  by_kind:\n    pii: redact\nrules: []\n",
    )
    policy = read_egress_policy(path)
    assert policy is not None
    assert policy.default is OnEgressFinding.BLOCK
    assert policy.action_for("pii") is OnEgressFinding.REDACT


@pytest.mark.parametrize(
    "body",
    [
        "version: 1\non_egress_finding: mask\nrules: []\n",
        "version: 1\non_egress_finding:\n  default: mask\nrules: []\n",
        "version: 1\non_egress_finding:\n  by_kind:\n    pii: mask\nrules: []\n",
        "version: 1\non_egress_finding:\n  by_kind:\n    pii: true\nrules: []\n",
        "version: 1\non_egress_finding:\n  default: 3\nrules: []\n",
    ],
)
def test_an_undeclarable_disposition_is_refused_never_silently_blocked(tmp_path, body):
    path = _policy_file(tmp_path, body)
    with pytest.raises(ValueError, match="must be one of block, redact"):
        read_egress_policy(path)


def test_a_typo_in_a_key_is_refused_rather_than_ignored(tmp_path):
    # `bykind` would have meant "block everything" while reading like "mask PII".
    # A key nobody reads is a policy nobody can trust (ADR 0026).
    path = _policy_file(
        tmp_path,
        "version: 1\non_egress_finding:\n  bykind:\n    pii: redact\nrules: []\n",
    )
    with pytest.raises(ValueError, match="unrecognised key"):
        read_egress_policy(path)


def test_a_malformed_policy_says_what_is_wrong(tmp_path):
    with pytest.raises(ValueError, match="must be a mapping"):
        read_egress_policy(_policy_file(tmp_path, "- just\n- a list\n"))
    with pytest.raises(ValueError, match="must be a string or a mapping"):
        read_egress_policy(_policy_file(tmp_path, "version: 1\non_egress_finding:\n  - redact\n"))
    with pytest.raises(ValueError, match="must be a string or a mapping"):
        read_egress_policy(_policy_file(tmp_path, "version: 1\non_egress_finding: 3\n"))
    with pytest.raises(ValueError, match="by_kind must be a mapping"):
        read_egress_policy(
            _policy_file(tmp_path, "version: 1\non_egress_finding:\n  by_kind: redact\n")
        )
    with pytest.raises(ValueError, match="non-empty kind names"):
        read_egress_policy(
            _policy_file(tmp_path, "version: 1\non_egress_finding:\n  by_kind:\n    '': redact\n")
        )
