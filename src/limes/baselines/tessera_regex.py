"""The Tessera-regex baseline — the comparison point, not a shipping detector.

It runs only the patterns ported verbatim from Tessera's ``guard/policy.yaml``
(``origin == "tessera"``), so it reproduces Tessera's injection recall — and
misses case 08 exactly as Tessera does. The injection detector's contribution is
the delta against this baseline (ADR 0003).
"""

from __future__ import annotations

from limes.detector import Context, Direction, Finding
from limes.policy import InjectionPolicy, load_injection_policy
from limes.spans import redact

__all__ = ["TesseraRegexBaseline"]


class TesseraRegexBaseline:
    """Injection detection using only the ported Tessera patterns."""

    id = "tessera-regex-baseline"
    version = "tessera-0227d2c5"

    def __init__(self, policy: InjectionPolicy | None = None) -> None:
        """Wire the baseline to ``policy`` (defaults to the packaged policy)."""
        self._policy = policy if policy is not None else load_injection_policy()

    @property
    def policy_hash(self) -> str:
        """SHA-256 of the active policy."""
        return self._policy.policy_hash

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return findings using only ``origin == 'tessera'`` rules."""
        del ctx
        if direction is not Direction.INBOUND:
            return []
        findings: list[Finding] = []
        for rule in self._policy.rules_from("tessera"):
            findings.extend(
                Finding(
                    detector_id=self.id,
                    label=rule.label,
                    spans=(redact(content, match.start(), match.end(), rule.label),),
                )
                for match in rule.pattern.finditer(content)
            )
        return findings
