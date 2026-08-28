"""The ``injection-egress`` detector (ADR 0012) — instructions arriving on the way out.

The proxy guards two directions asymmetrically: host→server tool calls are
inspected for injection, and server→host traffic is inspected for data *leaving*
(``pii-egress``, ``secrets-egress``). This detector closes the third corner —
instructions *arriving* on the server→host leg — the family two published
attacks live in:

* **tool poisoning** (Invariant Labs): a hostile MCP server hides directives in
  its **tool descriptions**, delivered to the model at ``tools/list``;
* **indirect injection**: a fetched page, email or document in a tool *result*
  that says "ignore previous instructions".

Both are content the agent's model will read, on the egress leg. The detector is
admitted the same way its siblings were (ADR 0003): a synthetic positive corpus,
a benign corpus of lookalikes, a null control and a per-category matrix
(``eval/matrices/injection_egress.md``). Four rule categories — attack-marker
tags, override directives, concealment, and exfiltration — each `validator:
none` out loud, because there is no checksum for a directive: precision comes
from the markers, verbs and named sensitive sources the rules scope to, and from
the benign corpus that proves those shapes do not fire on ordinary description
prose.

**Known, measured limit — mention versus use.** A rule cannot tell an article
*about* prompt injection from an injection: a fetched security page quoting
"ignore previous instructions" is flagged. That benign case ships in the corpus,
and if the rules kill it the matrix publishes it with its cause rather than
narrowing the rule until the attack could hide behind quoting (ADR 0003).
"""

from __future__ import annotations

from limes.detector import Context, Direction, Finding
from limes.detectors.egress_policy import EgressPolicy, load_egress_policy
from limes.detectors.egress_scan import refuse_unreadable, scan

__all__ = ["InjectionEgressDetector"]


class InjectionEgressDetector:
    """Rule-based outbound injection detector: poisoned descriptions and results."""

    id = "injection-egress"
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
        """Return injection findings for outbound ``content`` (empty on inbound).

        Args:
            direction: The leg being inspected; only ``OUTBOUND`` is scanned.
            content: The content about to reach the host — a tool description or
                a tool result.
            ctx: Unused — the rules read the content, not the actor.

        Returns:
            One finding per validated match, each spanning exactly the directive.

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
