"""The verdict contract (ADR 0002): evidence, no truthiness, no empty verdicts."""

from __future__ import annotations

import dataclasses

import pytest

from limes.verdict import Allow, CannotSay, Deny, Evidence, fingerprint, render


def test_bool_of_a_verdict_raises(sample_evidence):
    for verdict in (
        Allow(evidence=sample_evidence),
        Deny(reason="nope", evidence=sample_evidence),
        CannotSay(blind_spot="unreadable"),
    ):
        with pytest.raises(TypeError, match="not a boolean"):
            bool(verdict)


def test_allow_carries_evidence(sample_evidence):
    allow = Allow(evidence=sample_evidence)
    assert allow.evidence is sample_evidence


def test_deny_rejects_empty_reason(sample_evidence):
    with pytest.raises(ValueError, match="tells the reader nothing"):
        Deny(reason="   ", evidence=sample_evidence)


def test_cannotsay_rejects_empty_blind_spot():
    with pytest.raises(ValueError, match="blind spot about a blind spot"):
        CannotSay(blind_spot="")


def test_no_evidence_field_has_a_default():
    for field in dataclasses.fields(Evidence):
        assert field.default is dataclasses.MISSING
        assert field.default_factory is dataclasses.MISSING


def test_fingerprint_is_deterministic(sample_evidence):
    a = Deny(reason="r", evidence=sample_evidence)
    b = Deny(reason="r", evidence=sample_evidence)
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_distinguishes_kinds(sample_evidence):
    allow = fingerprint(Allow(evidence=sample_evidence))
    deny = fingerprint(Deny(reason="r", evidence=sample_evidence))
    cannot = fingerprint(CannotSay(blind_spot="b"))
    assert allow != deny != cannot != allow


def test_render_prefixes(sample_evidence):
    assert render(Allow(evidence=sample_evidence)).startswith("[ALLOW]")
    assert render(Deny(reason="r", evidence=sample_evidence)).startswith("[DENY]")
    assert render(CannotSay(blind_spot="b")).startswith("[CANNOT SAY]")
