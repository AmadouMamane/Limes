"""A null result carries its power (ADR 0003).

Ported from Tessera's ``verdict.py``. A :class:`Power` is the licence to report a
null result; it refuses to exist for a design that could not have rejected the
null (``best_achievable_p > threshold`` is a blind spot, not a null result — the
caller should report ``CannotSay``). :class:`NoEffect` cannot be built without it,
so "no effect" always arrives with the ``n`` and the minimum detectable effect
that license it — never as a bare claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

__all__ = ["NoEffect", "Power", "sign_test_power"]


@final
@dataclass(frozen=True, slots=True)
class Power:
    """The statistical licence to report a null result.

    Attributes:
        samples: Number of observations (must be > 0).
        threshold: The significance threshold the design is judged against.
        best_achievable_p: The smallest p-value the design could produce for the
            largest possible effect. If it exceeds ``threshold`` the design is
            blind and cannot construct a ``Power``.
        minimum_detectable_effect: The smallest effect the design could detect.
        effect_unit: The unit of the effect — a bare number is not an effect.
    """

    samples: int
    threshold: float
    best_achievable_p: float
    minimum_detectable_effect: float
    effect_unit: str

    def __post_init__(self) -> None:
        if self.samples <= 0:
            raise ValueError("a test with no observations has no power, and no null result.")
        if not self.effect_unit.strip():
            raise ValueError("a bare number is not an effect size — name the unit.")
        if self.best_achievable_p > self.threshold:
            raise ValueError(
                "this design CANNOT reject the null at its own threshold for any effect — that is "
                "a BLIND SPOT, not a null result. Report CannotSay, not NoEffect."
            )


@final
@dataclass(frozen=True, slots=True)
class NoEffect:
    """An observed absence, plus the :class:`Power` that licenses reporting it."""

    claim: str
    power: Power

    def __post_init__(self) -> None:
        if not self.claim.strip():
            raise ValueError(
                "NoEffect('') names no absence. Say what you looked for and did not find."
            )


def sign_test_power(n_pairs: int, threshold: float = 0.05) -> Power | None:
    """Power of a one-sided exact sign test over ``n_pairs`` paired observations.

    Used for the no-regression null control: is limes's false-positive rate no
    worse than the baseline's, over the benign corpus? With all pairs discordant
    in one direction the p-value is ``0.5 ** n_pairs``; the minimum detectable
    effect is the smallest number of discordant pairs whose one-sided p-value
    clears ``threshold``.

    Args:
        n_pairs: Number of paired observations (benign inputs).
        threshold: Significance threshold.

    Returns:
        A :class:`Power`, or ``None`` if the design is blind (too few pairs to
        ever reach significance) — in which case the caller reports ``CannotSay``.
    """
    if n_pairs <= 0:
        return None
    best_achievable_p = 0.5**n_pairs
    if best_achievable_p > threshold:
        return None
    detectable = 1
    while 0.5**detectable > threshold:
        detectable += 1
    return Power(
        samples=n_pairs,
        threshold=threshold,
        best_achievable_p=best_achievable_p,
        minimum_detectable_effect=detectable / n_pairs,
        effect_unit=f"of {n_pairs} benign inputs flipped (one-sided exact sign test)",
    )
