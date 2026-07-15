"""Ratchet 4 — exceptions frozen at zero (ADR 0002).

Two zeros the source may never grow: type/lint suppressions, and defaults on
evidence/identity fields. Mutation-tested: add a ``# type: ignore`` in ``src/``
and the first test goes red; give ``Context.actor`` a default and the second does.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from limes.detector import Context
from limes.verdict import Evidence

_SRC = Path(__file__).resolve().parents[3] / "src" / "limes"


@pytest.mark.mutation
def test_no_suppressions_in_source():
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "type: ignore" in line or "noqa" in line:
                offenders.append(f"{path.relative_to(_SRC)}:{lineno}")
    assert not offenders, f"suppressions are frozen at zero in src/; found: {offenders}"


@pytest.mark.mutation
def test_no_evidence_or_identity_field_has_a_default():
    for field in dataclasses.fields(Evidence):
        assert field.default is dataclasses.MISSING, f"Evidence.{field.name} gained a default"
        assert field.default_factory is dataclasses.MISSING, (
            f"Evidence.{field.name} gained a default factory"
        )
    actor = {f.name: f for f in dataclasses.fields(Context)}["actor"]
    assert actor.default is dataclasses.MISSING, (
        "Context.actor gained a default (a named default is a lie)"
    )
    assert actor.default_factory is dataclasses.MISSING, "Context.actor gained a default factory"
