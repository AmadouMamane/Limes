"""The verdict contract (ADR 0002): evidence, no truthiness, no empty verdicts."""

from __future__ import annotations

import dataclasses

import pytest

from limes.verdict import Allow, BlindCause, CannotSay, Deny, Evidence, fingerprint, render

_DECLARED = BlindCause.DECLARED


def test_bool_of_a_verdict_raises(sample_evidence):
    for verdict in (
        Allow(evidence=sample_evidence),
        Deny(reason="nope", evidence=sample_evidence),
        CannotSay(blind_spot="unreadable", cause=_DECLARED),
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
        CannotSay(blind_spot="", cause=_DECLARED)


def test_cannotsay_names_its_cause_and_has_no_default_for_it():
    # ADR 0026: a blind spot's cause is a fact of the verdict, and a cause the
    # type guessed would be a lie that reads complete — so there is no default.
    cause = next(field for field in dataclasses.fields(CannotSay) if field.name == "cause")
    assert cause.default is dataclasses.MISSING
    assert cause.default_factory is dataclasses.MISSING
    with pytest.raises(TypeError, match="BlindCause"):
        CannotSay(blind_spot="x", cause="declared")  # type: ignore[arg-type]


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
    cannot = fingerprint(CannotSay(blind_spot="b", cause=_DECLARED))
    assert allow != deny != cannot != allow


def test_fingerprint_seals_the_cause_of_a_blind_spot():
    # Two blind spots that differ only in cause are different verdicts to the
    # transport (ADR 0026), so they must be different verdicts to the chain.
    declared = fingerprint(CannotSay(blind_spot="b", cause=BlindCause.DECLARED))
    fault = fingerprint(CannotSay(blind_spot="b", cause=BlindCause.FAULT))
    refused = fingerprint(CannotSay(blind_spot="b", cause=BlindCause.REFUSED))
    assert len({declared, fault, refused}) == 3
    assert '"cause":"fault"' in fault


def test_render_prefixes(sample_evidence):
    assert render(Allow(evidence=sample_evidence)).startswith("[ALLOW]")
    assert render(Deny(reason="r", evidence=sample_evidence)).startswith("[DENY]")
    assert render(CannotSay(blind_spot="b", cause=_DECLARED)).startswith("[CANNOT SAY]")
    assert "(fault)" in render(CannotSay(blind_spot="b", cause=BlindCause.FAULT))
