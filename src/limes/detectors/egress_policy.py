r"""Load the YAML egress detection policy and hash it into evidence (ADR 0004).

The same discipline as :mod:`limes.policy`, extended by exactly one field. An
egress rule is a *shape* plus a *check*:

.. code-block:: yaml

    - label: pii:pan
      validator: luhn
      pattern: "(?<![A-Za-z0-9+])\\d(?:[ -]?\\d){12,18}(?![A-Za-z0-9]|[.,]\\d)"

The shape is data — an auditor reads which runs of text are even considered
without reading Python. The check is arithmetic, and arithmetic does not fit in a
regex: Luhn, MOD 97-10 and the NIR key are what separate a card number from an
order reference. So the rule *names* its validator, from a closed registry
(:data:`VALIDATORS`), and an unknown name is a load error rather than a silent
``allow-everything``. ``validator: none`` is a rule saying explicitly that its
shape is the whole claim.

Two more things a rule declares, because a detector that guesses them is a
detector nobody can audit:

* ``retry_trim`` — whether a candidate that fails its validator may be retried
  after dropping its trailing group. Banking prose runs an IBAN straight into the
  next word (``…0130 00 EUR``), and the greedy shape swallows it; without the
  retry the checksum fails and a real IBAN goes unseen. The retry can only ever
  *shorten* a candidate, and every shortened candidate must pass the same
  validator, so it buys recall without loosening the check.
* ``detector`` — which detector owns the rule. One file, one hash, two detectors;
  the alternative is two files whose drift nobody notices.

Each detector block also declares ``max_content_chars``: the size beyond which it
does not scan. It is data rather than a constant because refusing to sweep an
unbounded payload is an operational trade-off somebody has to be able to read and
change — and because the refusal must be *auditable*. Over budget the detector
raises :class:`~limes.detector.DetectorBlind`, the core answers ``CannotSay``, and
the egress leg blocks. Never a silent "nothing found".
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, final

import yaml

from limes.detectors.checksums import (
    compact,
    iban_mod97_valid,
    jwt_header_valid,
    luhn_valid,
    nir_key_valid,
)

__all__ = [
    "VALIDATORS",
    "EgressPolicy",
    "EgressRule",
    "load_egress_policy",
]

_DEFAULT_POLICY: Final = Path(__file__).resolve().parent / "egress.yaml"

#: The per-detector key declaring the size beyond which it will not scan.
_BUDGET_KEY: Final = "max_content_chars"

_PHONE_MIN_DIGITS: Final = 9
_PHONE_MAX_DIGITS: Final = 15
_NON_DIGIT: Final = re.compile(r"\D")


def _always(candidate: str) -> bool:
    """The explicit ``none`` validator: the shape is the whole claim."""
    del candidate
    return True


def _grouped_luhn(candidate: str) -> bool:
    """Luhn over a human-grouped card number (``4242 4242 4242 4242``)."""
    return luhn_valid(compact(candidate))


def _phone_digit_count(candidate: str) -> bool:
    """A plausible subscriber number: 9 to 15 digits, the E.164 range."""
    digits = _NON_DIGIT.sub("", candidate)
    return _PHONE_MIN_DIGITS <= len(digits) <= _PHONE_MAX_DIGITS


#: The closed registry a rule's ``validator`` field names. Closed on purpose: a
#: policy that could name an unknown validator would load, run, and check
#: nothing — a detector reporting "clean" over a check that never happened.
VALIDATORS: Final[Mapping[str, Callable[[str], bool]]] = {
    "none": _always,
    "luhn": _grouped_luhn,
    "iban_mod97": iban_mod97_valid,
    "nir_key": nir_key_valid,
    "phone_digits": _phone_digit_count,
    "jwt_header": jwt_header_valid,
}


@final
@dataclass(frozen=True, slots=True)
class EgressRule:
    """One shape, and the check that decides whether the shape meant anything.

    Attributes:
        detector: The id of the detector that owns this rule.
        label: Stable ``kind:rule`` id, e.g. ``"pii:pan"``. The half before the
            colon is the egress kind the transport policies by (ADR 0006).
        pattern: The compiled candidate shape.
        validator: The name of the check applied to each candidate.
        retry_trim: Whether a failing candidate is retried without its trailing
            group.
    """

    detector: str
    label: str
    pattern: re.Pattern[str]
    validator: str
    retry_trim: bool

    @property
    def check(self) -> Callable[[str], bool]:
        """The validator function this rule names."""
        return VALIDATORS[self.validator]


@final
@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """A versioned, hashed set of egress rules, owned by detector id.

    Attributes:
        version: The policy schema version.
        policy_hash: SHA-256 of the file, recorded into every verdict's evidence.
        rules: Every rule, in declaration order, each naming its owner.
        budgets: Per detector, the content size beyond which it declares itself
            blind rather than scanning.
    """

    version: int
    policy_hash: str
    rules: tuple[EgressRule, ...]
    budgets: Mapping[str, int]

    def rules_for(self, detector: str) -> tuple[EgressRule, ...]:
        """Return the rules owned by ``detector``, in declaration order."""
        return tuple(rule for rule in self.rules if rule.detector == detector)

    def budget_for(self, detector: str) -> int:
        """Return the scan budget declared for ``detector``, in characters."""
        return self.budgets[detector]

    def detectors(self) -> tuple[str, ...]:
        """Return every detector id this policy declares rules for, sorted."""
        return tuple(sorted({rule.detector for rule in self.rules}))


def _read_rule(raw: object, *, policy_path: Path, detector: str) -> EgressRule:
    """Read and validate one rule mapping, or say precisely what was wrong."""
    if not isinstance(raw, dict):
        raise ValueError(f"policy {policy_path}: each rule of {detector!r} must be a mapping")
    label = raw.get("label")
    pattern = raw.get("pattern")
    validator = raw.get("validator")
    retry_trim = raw.get("retry_trim", False)
    if not isinstance(label, str) or not label:
        raise ValueError(
            f"policy {policy_path}: a rule of {detector!r} is missing a string 'label'"
        )
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"policy {policy_path}: rule {label!r} is missing a string 'pattern'")
    if not isinstance(validator, str) or validator not in VALIDATORS:
        known = ", ".join(sorted(VALIDATORS))
        raise ValueError(
            f"policy {policy_path}: rule {label!r} names validator {validator!r}, which is not "
            f"one of {known}. A rule whose check does not exist would match a shape and vouch "
            f"for nothing; declare 'none' if the shape is the whole claim."
        )
    if not isinstance(retry_trim, bool):
        raise ValueError(
            f"policy {policy_path}: rule {label!r} has a non-boolean 'retry_trim' {retry_trim!r}"
        )
    return EgressRule(
        detector=detector,
        label=label,
        pattern=re.compile(pattern),
        validator=validator,
        retry_trim=retry_trim,
    )


def load_egress_policy(path: Path | None = None) -> EgressPolicy:
    """Load, validate, and hash the egress detection policy.

    Args:
        path: Policy file; defaults to the packaged ``detectors/egress.yaml``.

    Returns:
        The compiled, hashed policy.

    Raises:
        ValueError: If the file is malformed, a rule is missing a field, a label
            is declared twice, or a rule names a validator that does not exist.
    """
    policy_path = path or _DEFAULT_POLICY
    raw = policy_path.read_bytes()
    policy_hash = hashlib.sha256(raw).hexdigest()
    data = yaml.safe_load(raw)

    if not isinstance(data, dict):
        raise ValueError(f"policy {policy_path} must be a mapping, got {type(data).__name__}")
    version = data.get("version")
    if not isinstance(version, int):
        raise ValueError(f"policy {policy_path}: 'version' must be an integer")
    declared = data.get("detectors")
    if not isinstance(declared, dict) or not declared:
        raise ValueError(f"policy {policy_path}: 'detectors' must be a non-empty mapping")

    rules: list[EgressRule] = []
    budgets: dict[str, int] = {}
    seen_labels: set[str] = set()
    for detector, block in declared.items():
        if not isinstance(detector, str) or not detector:
            raise ValueError(f"policy {policy_path}: a detector id must be a non-empty string")
        if not isinstance(block, dict):
            raise ValueError(f"policy {policy_path}: detector {detector!r} must be a mapping")
        budget = block.get(_BUDGET_KEY)
        if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
            raise ValueError(
                f"policy {policy_path}: detector {detector!r} must declare a positive integer "
                f"{_BUDGET_KEY!r}. A detector with no declared limit is one whose refusal to "
                f"scan cannot be audited — and one that never refuses is a denial-of-service "
                f"surface."
            )
        budgets[detector] = budget
        rules_raw = block.get("rules")
        if not isinstance(rules_raw, list) or not rules_raw:
            raise ValueError(
                f"policy {policy_path}: detector {detector!r} must declare a non-empty 'rules' list"
            )
        for item in rules_raw:
            rule = _read_rule(item, policy_path=policy_path, detector=detector)
            if rule.label in seen_labels:
                raise ValueError(f"policy {policy_path}: duplicate rule label {rule.label!r}")
            seen_labels.add(rule.label)
            rules.append(rule)

    return EgressPolicy(
        version=version, policy_hash=policy_hash, rules=tuple(rules), budgets=budgets
    )
