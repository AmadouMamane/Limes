"""The verdict contract (ADR 0002): evidence, no truthiness, no empty verdicts."""

from __future__ import annotations

import dataclasses

import pytest

from limes.verdict import (
    Allow,
    BlindCause,
    BlindKind,
    CannotSay,
    Deny,
    Evidence,
    blind_label,
    fingerprint,
    render,
)

_DECLARED = BlindCause.DECLARED
_BUDGET = frozenset({BlindKind.BUDGET})
_NONE: frozenset[BlindKind] = frozenset()


def test_bool_of_a_verdict_raises(sample_evidence):
    for verdict in (
        Allow(evidence=sample_evidence),
        Deny(reason="nope", evidence=sample_evidence),
        CannotSay(blind_spot="unreadable", cause=_DECLARED, kinds=_BUDGET),
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
        CannotSay(blind_spot="", cause=_DECLARED, kinds=_BUDGET)


def test_cannotsay_names_its_cause_and_has_no_default_for_it():
    # ADR 0026: a blind spot's cause is a fact of the verdict, and a cause the
    # type guessed would be a lie that reads complete — so there is no default.
    cause = next(field for field in dataclasses.fields(CannotSay) if field.name == "cause")
    assert cause.default is dataclasses.MISSING
    assert cause.default_factory is dataclasses.MISSING
    with pytest.raises(TypeError, match="BlindCause"):
        CannotSay(blind_spot="x", cause="declared", kinds=_BUDGET)  # type: ignore[arg-type]


def test_a_declared_blind_spot_names_its_families_and_has_no_default_for_them():
    # ADR 0029: the families are what the transport policy opens one at a time,
    # so they are a fact of the verdict — no default, a closed vocabulary, and a
    # declared limit with none is refused: UNSPECIFIED exists to be said out loud.
    kinds = next(field for field in dataclasses.fields(CannotSay) if field.name == "kinds")
    assert kinds.default is dataclasses.MISSING
    assert kinds.default_factory is dataclasses.MISSING
    with pytest.raises(ValueError, match="names its family"):
        CannotSay(blind_spot="x", cause=_DECLARED, kinds=_NONE)
    with pytest.raises(TypeError, match="BlindKind"):
        CannotSay(blind_spot="x", cause=_DECLARED, kinds=frozenset({"budget"}))  # type: ignore[arg-type]
    assert CannotSay(blind_spot="x", cause=BlindCause.REFUSED, kinds=_NONE).kinds == _NONE


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
    cannot = fingerprint(CannotSay(blind_spot="b", cause=_DECLARED, kinds=_BUDGET))
    assert allow != deny != cannot != allow


def test_fingerprint_seals_the_cause_of_a_blind_spot():
    # Two blind spots that differ only in cause are different verdicts to the
    # transport (ADR 0026), so they must be different verdicts to the chain.
    declared = fingerprint(CannotSay(blind_spot="b", cause=BlindCause.DECLARED, kinds=_BUDGET))
    fault = fingerprint(CannotSay(blind_spot="b", cause=BlindCause.FAULT, kinds=_NONE))
    refused = fingerprint(CannotSay(blind_spot="b", cause=BlindCause.REFUSED, kinds=_NONE))
    assert len({declared, fault, refused}) == 3
    assert '"cause":"fault"' in fault


def test_fingerprint_seals_the_families_of_a_declared_blind_spot():
    # Two declared blind spots that differ only in family are different verdicts
    # to the policy (ADR 0029), so they are different verdicts to the chain.
    budget = fingerprint(CannotSay(blind_spot="b", cause=_DECLARED, kinds=_BUDGET))
    binary = fingerprint(
        CannotSay(blind_spot="b", cause=_DECLARED, kinds=frozenset({BlindKind.BINARY}))
    )
    both = fingerprint(
        CannotSay(
            blind_spot="b", cause=_DECLARED, kinds=frozenset({BlindKind.BINARY, BlindKind.BUDGET})
        )
    )
    assert len({budget, binary, both}) == 3
    assert '"kinds":["binary","budget"]' in both, "sorted, so the same set is the same bytes"


def test_render_prefixes(sample_evidence):
    assert render(Allow(evidence=sample_evidence)).startswith("[ALLOW]")
    assert render(Deny(reason="r", evidence=sample_evidence)).startswith("[DENY]")
    assert render(CannotSay(blind_spot="b", cause=_DECLARED, kinds=_BUDGET)).startswith(
        "[CANNOT SAY]"
    )
    assert "(fault)" in render(CannotSay(blind_spot="b", cause=BlindCause.FAULT, kinds=_NONE))
    assert "(declared: budget)" in render(CannotSay(blind_spot="b", cause=_DECLARED, kinds=_BUDGET))


def test_blind_label_is_the_cause_and_then_the_families():
    assert (
        blind_label(CannotSay(blind_spot="b", cause=BlindCause.REFUSED, kinds=_NONE)) == "refused"
    )
    both = frozenset({BlindKind.SCRIPT, BlindKind.BINARY})
    assert blind_label(CannotSay(blind_spot="b", cause=_DECLARED, kinds=both)) == (
        "declared: binary, script"
    )
