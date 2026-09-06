"""Load a YAML injection policy and hash it into evidence (ADR 0004).

The policy is data, not code: an auditor reads the rules without reading Python,
and every rule's SHA-256 (the file's hash) is recorded into each verdict's
evidence. Each rule carries an ``origin`` — ``tessera`` for a pattern ported
verbatim from Tessera's ``guard/policy.yaml``, ``limes`` for one added here — so
the same file can be read as the ported baseline or as the full limes detector,
and the delta between them is data, not a second file.

The file may also declare ``max_content_chars`` (ADR 0023): the size beyond
which the inbound detector does not scan and says so (``DetectorBlind`` ->
``CannotSay``), exactly as every egress detector already declares in
``egress.yaml``. It is optional here, unlike there, because injection policies
written before it existed are in use; when absent the packaged default applies
and is recorded — the file's hash covers the declaration or its absence.
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

#: The optional key declaring the inbound scan budget (ADR 0023).
_BUDGET_KEY = "max_content_chars"

#: The budget an injection policy gets when it declares none — the same figure
#: the packaged egress detectors declare, so the two legs refuse at one size.
DEFAULT_MAX_CONTENT_CHARS = 200_000


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
    """A versioned, hashed set of injection rules.

    Attributes:
        version: The policy schema version.
        policy_hash: SHA-256 of the file, recorded into every verdict's evidence.
        rules: Every rule, in declaration order.
        max_content_chars: The size beyond which the inbound detector declares
            itself blind rather than scanning (ADR 0023).
    """

    version: int
    policy_hash: str
    rules: tuple[Rule, ...]
    max_content_chars: int

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
        ValueError: If the file is malformed, is not valid YAML, a rule is
            missing a field, a pattern does not compile, or the scan budget is
            not a positive integer.
    """
    policy_path = path or _DEFAULT_POLICY
    raw = policy_path.read_bytes()
    policy_hash = hashlib.sha256(raw).hexdigest()
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"policy {policy_path} is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"policy {policy_path} must be a mapping, got {type(data).__name__}")
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError(f"policy {policy_path}: 'version' must be an integer")
    budget = data.get(_BUDGET_KEY, DEFAULT_MAX_CONTENT_CHARS)
    if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
        raise ValueError(
            f"policy {policy_path}: {_BUDGET_KEY!r} must be a positive integer. A detector "
            f"with no declared limit is one whose refusal to scan cannot be audited."
        )
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
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"policy {policy_path}: rule {label!r} has a pattern that does not compile: {exc}"
            ) from exc
        rules.append(Rule(label=label, origin=origin, pattern=compiled))

    return InjectionPolicy(
        version=version,
        policy_hash=policy_hash,
        rules=tuple(rules),
        max_content_chars=budget,
    )
