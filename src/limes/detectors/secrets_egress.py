"""The ``secrets-egress`` detector (ADR 0003/0004) — credentials on the way out.

Prefixed API keys (AWS, OpenAI, GitHub, Stripe, Google, Slack), **PEM private-key
blocks**, **JWTs** — and the **AWS secret access key by its assignment context**
(ADR 0022). Admitted on its own numbers
(``eval/matrices/secrets_egress.md``), with one difference from ``pii-egress``
that is stated rather than glossed: there is **no comparable baseline**. Tessera's
guard policy declares ``tools``, ``prompt_injection`` and ``pii`` and nothing
else — checked, not assumed — so no ported comparison exists, and the **null
control is the baseline**. The number to read is the delta against the unplugged
guard; no comparison is invented to dress it up (ADR 0003).

**Where the precision comes from, per rule.** A prefixed key needs no checksum:
the vendor's type prefix is the discriminator, and twenty upper-case
alphanumerics on their own are an order code while ``AKIA`` + sixteen is a key.
A JWT is the opposite case — its shape (three dot-separated base64url segments)
is shared with file names, version strings and package coordinates, so the shape
is worth nothing and the whole claim is the validator: the first segment must
decode to a JSON object declaring ``alg``. A PEM block is armour, and the span is
the **whole block**, because a finding that located only the ``BEGIN`` line would
be masked to exactly that and would forward the key material underneath it. The
AWS *secret* access key has neither prefix nor checksum, so its discriminant is
the **name it is assigned to**: gitleaks' assignment grammar around AWS's own
vocabulary, the finding narrowed to the value group, and a charset check
refusing an unbroken hex run — the measured split ADR 0022 records.

**Deferred, deliberately: generic high-entropy scanning.** A UUID, a git digest,
a content hash and a base64 blob are all high-entropy and none is a secret. An
entropy rule with no context is a false-positive generator that teaches its
operator to switch the detector off — so it is not here, and the benign corpus
holds exactly those lookalikes to prove the rules that *are* here do not fire on
them.

**Consequence, stated:** a *bare* unprefixed credential is still not detected —
a database password, a bare bearer token, a forty-character blob on its own.
The AWS secret access key is caught **when its name is in reach** (ADR 0022);
with no keyword, the same measurement prices the bare-body rule at 17/20 hard
lookalikes and 15/339 of gitleaks' negatives killed, and the only discriminant
left is the entropy threshold ADR 0009 forbids. A declared boundary with tests
pinning both sides, not an oversight.
"""

from __future__ import annotations

from limes.detector import Context, Direction, Finding
from limes.detectors.egress_policy import EgressPolicy, load_egress_policy
from limes.detectors.egress_scan import refuse_unreadable, scan

__all__ = ["SecretsEgressDetector"]


class SecretsEgressDetector:
    """Rule-based outbound credential detector: prefixed keys, PEM armour, JWTs."""

    id = "secrets-egress"
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
        """Return credential findings for outbound ``content`` (empty on inbound).

        Args:
            direction: The leg being inspected; only ``OUTBOUND`` is scanned.
            content: The content about to leave.
            ctx: Unused — the rules read the content, not the actor.

        Returns:
            One finding per validated match, each spanning exactly the credential
            (and, for a PEM key, the whole block rather than its armour line).

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
