"""A null result carries its power (ADR 0003): Power and NoEffect guards."""

from __future__ import annotations

import pytest

from limes.eval.power import NoEffect, Power, sign_test_power


def _valid_power() -> Power:
    return Power(
        samples=8,
        threshold=0.05,
        best_achievable_p=0.5**8,
        minimum_detectable_effect=0.625,
        effect_unit="benign inputs flipped",
    )


def test_power_rejects_no_samples():
    with pytest.raises(ValueError, match="no power"):
        Power(
            samples=0,
            threshold=0.05,
            best_achievable_p=0.01,
            minimum_detectable_effect=0.5,
            effect_unit="u",
        )


def test_power_rejects_a_blind_design():
    # best_achievable_p > threshold: the design can never reject the null.
    with pytest.raises(ValueError, match="BLIND SPOT"):
        Power(
            samples=1,
            threshold=0.05,
            best_achievable_p=0.5,
            minimum_detectable_effect=1.0,
            effect_unit="u",
        )


def test_power_rejects_a_bare_unit():
    with pytest.raises(ValueError, match="name the unit"):
        Power(
            samples=8,
            threshold=0.05,
            best_achievable_p=0.01,
            minimum_detectable_effect=0.5,
            effect_unit="  ",
        )


def test_noeffect_needs_a_claim():
    with pytest.raises(ValueError, match="names no absence"):
        NoEffect(claim="", power=_valid_power())


def test_sign_test_power_is_blind_for_small_n():
    # 0.5**4 = 0.0625 > 0.05 — even an all-discordant result can't reach significance.
    assert sign_test_power(1) is None
    assert sign_test_power(4) is None


def test_sign_test_power_for_the_benign_corpus():
    power = sign_test_power(8)
    assert power is not None
    assert power.samples == 8
    assert power.minimum_detectable_effect == 5 / 8
