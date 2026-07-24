"""The ``pii-egress`` detector (ADR 0003/0004) — personal data on the way out.

Five fixed categories, each admitted on its own numbers
(``eval/matrices/pii_egress.md``): **PAN** (Luhn), **IBAN** (MOD 97-10),
**e-mail**, **telephone** (FR / DE / E.164) and **NIR** (the French
social-security number and its control key).

It is the outbound mirror of ``injection``: same Protocol, same evidence, same
admission rule. What is different is where precision comes from. An injection
rule is a pattern and nothing else; a PII rule is a pattern *plus arithmetic*,
because the shapes are shared with things that are not personal data at all — a
sixteen-digit order reference, an IBAN-shaped internal identifier, a date. The
checksums are what make the difference measurable rather than asserted, and the
benign corpus is what proves it: the lookalikes are in the eval, and they must
not fire.

The categories are **fixed**, not configurable. A deployment that could add a
sixth could add one nobody measured, and an unmeasured category is a capability
claimed and never proven (ADR 0003).

What it does **not** do: free-text names, postal addresses, dates of birth — none
has a check that separates it from ordinary prose, so none is claimed. It reads
the outbound leg only; ``injection`` still owns inbound.
"""

from __future__ import annotations

from limes.detector import Context, Direction, Finding
from limes.detectors.egress_policy import EgressPolicy, load_egress_policy
from limes.detectors.egress_scan import refuse_unreadable, scan

__all__ = ["PiiEgressDetector"]


class PiiEgressDetector:
    """Rule-based, checksum-gated outbound personal-data detector."""

    id = "pii-egress"
    version = "0.1.0"

    def __init__(self, policy: EgressPolicy | None = None) -> None:
        """Wire the detector to ``policy`` (defaults to the packaged egress policy)."""
        self._policy = policy if policy is not None else load_egress_policy()
        self._rules = self._policy.rules_for(self.id)
        self._budget = self._policy.budget_for(self.id)

    @property
    def policy_hash(self) -> str:
        """SHA-256 of the active egress policy (recorded into evidence)."""
        return self._policy.policy_hash

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return PII findings for outbound ``content`` (empty on inbound).

        Args:
            direction: The leg being inspected; only ``OUTBOUND`` is scanned.
            content: The content about to leave.
            ctx: Unused — the rules read the content, not the actor.

        Returns:
            One finding per validated match, each spanning exactly the value.

        Raises:
            DetectorBlind: If the content exceeds the declared scan budget, or
                does not encode to UTF-8 — in either case the detector did not
                observe and must not read as clean.
        """
        del ctx  # the egress rules read only the content, not the actor
        if direction is not Direction.OUTBOUND:
            return []
        refuse_unreadable(content, detector_id=self.id, budget=self._budget)
        return scan(content, self._rules, detector_id=self.id)
