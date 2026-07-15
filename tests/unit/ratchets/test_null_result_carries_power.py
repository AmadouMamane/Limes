"""Ratchet 3 — a null result carries its power (ADR 0003).

``NoEffect`` cannot be built without a ``Power``, and ``Power`` refuses to exist
for a design that could never reject the null. Mutation-tested: give
``NoEffect.power`` a default and the first test goes red; drop the blind-design
guard in ``Power.__post_init__`` and the second goes red.
"""

from __future__ import annotations

import dataclasses

import pytest

from limes.eval.power import NoEffect, Power, sign_test_power


@pytest.mark.mutation
def test_noeffect_has_no_default_power():
    fields = {f.name: f for f in dataclasses.fields(NoEffect)}
    power = fields["power"]
    assert power.default is dataclasses.MISSING, "NoEffect.power gained a default"
    assert power.default_factory is dataclasses.MISSING, "NoEffect.power gained a default factory"


@pytest.mark.mutation
def test_power_refuses_a_blind_design():
    # A design whose best achievable p exceeds its threshold is a blind spot,
    # not a null result — it must not be constructible.
    with pytest.raises(ValueError, match="BLIND SPOT"):
        Power(
            samples=1,
            threshold=0.05,
            best_achievable_p=0.5,
            minimum_detectable_effect=1.0,
            effect_unit="benign inputs flipped",
        )


@pytest.mark.mutation
def test_underpowered_benign_set_is_cannot_say_not_no_effect():
    # With too few pairs, the honest answer is None (CannotSay), never a NoEffect.
    assert sign_test_power(4) is None
