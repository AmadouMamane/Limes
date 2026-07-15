"""Load a YAML injection policy and hash it into evidence (ADR 0004).

The policy is data, not code: an auditor reads the rules without reading Python,
and every rule's SHA-256 (the file's hash) is recorded into each verdict's
evidence. Each rule carries an ``origin`` — ``tessera`` for a pattern ported
verbatim from Tessera's ``guard/policy.yaml``, ``limes`` for one added here — so
the same file can be read as the ported baseline or as the full limes detector,
and the delta between them is data, not a second file.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

__all__ = ["InjectionPolicy", "Rule", "load_injection_policy"]

_DEFAULT_POLICY = Path(__file__).resolve().parent / "detectors" / "policy.yaml"

_VALID_ORIGINS = frozenset({"tessera", "limes"})


@dataclass(frozen=True, slots=True)
class Rule:
    """One named injection pattern.

    Attributes:
        label: Stable rule id, e.g. ``"injection:embedded-system-directive"``.
        origin: ``"tessera"`` (ported) or ``"limes"`` (added here).
        pattern: The compiled regex.
    """

    label: str
    origin: str
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class InjectionPolicy:
    """A versioned, hashed set of injection rules."""

    version: int
    policy_hash: str
    rules: tuple[Rule, ...]

    def rules_from(self, *origins: str) -> tuple[Rule, ...]:
        """Return the rules whose ``origin`` is in ``origins`` (all rules if empty)."""
        if not origins:
            return self.rules
        wanted = set(origins)
        return tuple(rule for rule in self.rules if rule.origin in wanted)


def load_injection_policy(path: Path | None = None) -> InjectionPolicy:
    """Load, validate, and hash the injection policy.

    Args:
        path: Policy file; defaults to the packaged ``detectors/policy.yaml``.

    Returns:
        The compiled, hashed policy.

    Raises:
        ValueError: If the file is malformed or a rule is missing a field.
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
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ValueError(f"policy {policy_path}: 'rules' must be a non-empty list")

    rules: list[Rule] = []
    seen_labels: set[str] = set()
    for item in rules_raw:
        if not isinstance(item, dict):
            raise ValueError(f"policy {policy_path}: each rule must be a mapping")
        label = item.get("label")
        origin = item.get("origin")
        pattern = item.get("pattern")
        if not isinstance(label, str) or not label:
            raise ValueError(f"policy {policy_path}: a rule is missing a string 'label'")
        if label in seen_labels:
            raise ValueError(f"policy {policy_path}: duplicate rule label {label!r}")
        if origin not in _VALID_ORIGINS:
            raise ValueError(
                f"policy {policy_path}: rule {label!r} has an invalid origin {origin!r}"
            )
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"policy {policy_path}: rule {label!r} is missing a string 'pattern'")
        seen_labels.add(label)
        rules.append(Rule(label=label, origin=origin, pattern=re.compile(pattern)))

    return InjectionPolicy(version=version, policy_hash=policy_hash, rules=tuple(rules))
