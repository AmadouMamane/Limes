"""The in-process transport (ADR 0004): a Guard object over the pure core.

``Guard`` wires a set of detectors and a policy hash to a :class:`~limes.record.Ledger`,
exposes ``check()`` returning a :class:`~limes.verdict.Verdict`, and offers a
convenience ``require_allow`` that raises :class:`Blocked` on anything but
``Allow`` — for callers who want a hard gate rather than a match.

Its **outbound** leg has one thing more, and it is a transport behaviour rather
than a verdict (ADR 0006): :meth:`Guard.check_egress` returns an :class:`Egress`,
which is a verdict *plus what to do with the content*. Under a redacting policy a
refused response is not dropped — the matched offsets are overwritten with a
fixed token and the rest is forwarded untouched. The refusal is still a ``Deny``
and still lands on the chain: a masked forward is never recorded as an ``Allow``.

Two seams sit under ``check``, and a transport that takes a disposition of its
own uses them directly (ADR 0025): :meth:`Guard.verdict` decides without
recording, :meth:`Guard.record` seals the decision *with* the disposition the
transport took — ``forward``, ``redact`` or ``block`` — so the chain proves not
only that a response was refused but what then left. ``check`` itself records
``None``: a caller who receives a bare verdict decides what to do with it, and
the ledger does not guess on their behalf.

Two things the guard says rather than lets pass (ADR 0027/0028). A detector
that names its legs is asked only on them, so a guard wired with both an inbound
and an outbound detector lists as witness only the one that read the leg; a leg
no wired detector reads answers ``CannotSay`` rather than an ``Allow`` with no
witness. And a caller may declare ``blind_spots`` of its own — the parts of what
it handed over that it could derive no text from — which the core aggregates
like a detector's declared limit.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import final

from limes.detector import Context, Detector, Direction
from limes.guard import decide
from limes.record import DecisionRecord, Ledger
from limes.transports.redaction import (
    Action,
    EgressPolicy,
    RedactEgress,
    Redaction,
    apply_masking,
    conceals_all,
    rule_egress,
)
from limes.verdict import Allow, CannotSay, Deny, Verdict

__all__ = ["Blocked", "Egress", "Guard"]


class Blocked(Exception):
    """Raised by :meth:`Guard.require_allow` when a verdict is not ``Allow``."""

    def __init__(self, verdict: Deny | CannotSay) -> None:
        self.verdict = verdict
        if isinstance(verdict, Deny):
            super().__init__(f"blocked: {verdict.reason}")
        else:
            super().__init__(f"blocked (cannot say, {verdict.cause.value}): {verdict.blind_spot}")


@final
@dataclass(frozen=True, slots=True)
class Egress:
    """What the outbound leg decided about one piece of content.

    Attributes:
        action: ``FORWARD`` (clean), ``REDACT`` (masked and forwarded) or
            ``BLOCK`` (does not leave).
        content: What to send — the original for ``FORWARD``, the masked text for
            ``REDACT``, and ``None`` for ``BLOCK``, because there is nothing to
            send and a caller must not be able to reach for it by accident.
        verdict: The core's verdict, unchanged. A redacted egress still carries
            its ``Deny``.
        redaction: The masking plan, present exactly when ``action`` is ``REDACT``.
        reason: One human-readable line.
    """

    action: Action
    content: str | None
    verdict: Verdict
    redaction: Redaction | None
    reason: str

    def __post_init__(self) -> None:
        """Refuse a state the transport could misread.

        Raises:
            ValueError: If a block carries content, a forward has none, or the
                masking plan does not agree with the action.
        """
        if (self.action is Action.BLOCK) != (self.content is None):
            raise ValueError(
                "a blocked egress carries no content, and a forwarded one must carry it; got "
                f"action={self.action.value} with content "
                f"{'absent' if self.content is None else 'present'}"
            )
        if (self.action is Action.REDACT) != (self.redaction is not None):
            raise ValueError(
                "a masking plan belongs to a redacted egress and to no other; got "
                f"action={self.action.value} with plan "
                f"{'absent' if self.redaction is None else 'present'}"
            )


class Guard:
    """An in-process guard over a fixed set of detectors and one policy."""

    def __init__(
        self,
        detectors: Sequence[Detector],
        *,
        policy_hash: str,
        ledger: Ledger | None = None,
        egress: EgressPolicy | None = None,
    ) -> None:
        """Wire ``detectors`` under ``policy_hash``, recording into ``ledger``.

        Args:
            detectors: The detectors to run.
            policy_hash: SHA-256 of the active policy, recorded into evidence.
            ledger: An existing chain to append to (a fresh one by default).
            egress: What to do with an outbound finding. ``None`` means
                :meth:`~limes.transports.redaction.EgressPolicy.blocking` — the
                closed default, which is also the default a caller gets by not
                thinking about it (ADR 0006).
        """
        self._detectors = tuple(detectors)
        self._policy_hash = policy_hash
        self._ledger = ledger if ledger is not None else Ledger()
        self._egress = egress if egress is not None else EgressPolicy.blocking()

    @property
    def ledger(self) -> Ledger:
        """The ledger this guard appends decisions to."""
        return self._ledger

    @property
    def egress_policy(self) -> EgressPolicy:
        """The egress policy this guard enforces on the outbound leg."""
        return self._egress

    def verdict(
        self,
        content: str,
        *,
        actor: str | None,
        observed_at: str,
        direction: Direction = Direction.INBOUND,
        locale: str | None = None,
        blind_spots: Sequence[str] = (),
    ) -> Verdict:
        """Inspect ``content`` and return the verdict **without** recording it.

        The seam a transport uses when it takes a disposition of its own: decide
        first, dispose, then :meth:`record` the two together (ADR 0025).

        Args:
            content: The content to inspect.
            actor: The caller's asserted identity (``None`` for anonymous).
            observed_at: ISO-8601 timestamp recorded into evidence.
            direction: The leg to inspect (default inbound).
            locale: Optional locale hint — a word-reading detector whose policy
                declares its languages declares itself blind on one it does not
                read (ADR 0028).
            blind_spots: Limits the caller declares about what it handed over,
                one sentence each — the parts it could derive no text from
                (ADR 0028). A finding still dominates them; otherwise they make
                the verdict ``CannotSay`` with cause ``declared``.

        Returns:
            The verdict, not yet on the chain.
        """
        ctx = Context(policy_hash=self._policy_hash, actor=actor, locale=locale)
        return decide(
            direction,
            content,
            ctx,
            self._detectors,
            observed_at=observed_at,
            blind_spots=blind_spots,
        )

    def record(
        self,
        direction: Direction,
        verdict: Verdict,
        actor: str | None,
        *,
        disposition: str | None,
    ) -> DecisionRecord:
        """Seal ``verdict`` and the transport's ``disposition`` into the chain (ADR 0025).

        Args:
            direction: The leg the decision was made on.
            verdict: The verdict :meth:`verdict` returned.
            actor: The caller's asserted identity.
            disposition: What the transport did with the content —
                ``"forward"``, ``"redact"`` or ``"block"`` — or ``None`` when it
                took no disposition of its own.

        Returns:
            The linked record.
        """
        return self._ledger.append(direction, verdict, actor, disposition=disposition)

    def check(
        self,
        content: str,
        *,
        actor: str | None,
        observed_at: str,
        direction: Direction = Direction.INBOUND,
        locale: str | None = None,
        blind_spots: Sequence[str] = (),
    ) -> Verdict:
        """Inspect ``content`` and record the verdict in the ledger.

        The record's disposition is ``None``: the caller receives a bare verdict
        and decides what to do with it, and the ledger does not guess.

        Args:
            content: The content to inspect.
            actor: The caller's asserted identity (``None`` for anonymous).
            observed_at: ISO-8601 timestamp recorded into evidence.
            direction: The leg to inspect (default inbound).
            locale: Optional locale hint (see :meth:`verdict`).
            blind_spots: Limits the caller declares (see :meth:`verdict`).

        Returns:
            The verdict, which is also appended to :attr:`ledger`.
        """
        verdict = self.verdict(
            content,
            actor=actor,
            observed_at=observed_at,
            direction=direction,
            locale=locale,
            blind_spots=blind_spots,
        )
        self.record(direction, verdict, actor, disposition=None)
        return verdict

    def check_egress(
        self,
        content: str,
        *,
        actor: str | None,
        observed_at: str,
        locale: str | None = None,
        blind_spots: Sequence[str] = (),
    ) -> Egress:
        """Inspect content that is about to leave, and say what may leave (ADR 0006).

        The verdict is taken exactly as :meth:`check` takes it — same core, same
        pipeline, same single record on the chain. The egress policy then decides
        what the transport *does* with a refusal, and that disposition is sealed
        into the record beside the verdict (ADR 0025):

        * every kind that fired is configured ``redact`` → the matched offsets
          are overwritten with fixed tokens and the rest is forwarded;
        * any kind is configured ``block`` (the default) → nothing leaves;
        * ``CannotSay`` → nothing leaves, whatever its cause. A detector that
          could not look cannot have located anything to mask, so there is no
          masked forward to offer; a caller who wants another answer has the
          verdict, and its cause, in hand.

        Args:
            content: The outbound content.
            actor: The caller's asserted identity (``None`` for anonymous).
            observed_at: ISO-8601 timestamp recorded into evidence.
            locale: Optional locale hint (see :meth:`verdict`).
            blind_spots: Limits the caller declares (see :meth:`verdict`).

        Returns:
            The egress decision, whose ``content`` is what may be sent.
        """
        verdict = self.verdict(
            content,
            actor=actor,
            observed_at=observed_at,
            direction=Direction.OUTBOUND,
            locale=locale,
            blind_spots=blind_spots,
        )
        egress = self._dispose(content, verdict)
        self.record(Direction.OUTBOUND, verdict, actor, disposition=egress.action.value)
        return egress

    def _dispose(self, content: str, verdict: Verdict) -> Egress:
        """Turn an outbound verdict into what leaves, under the egress policy."""
        if isinstance(verdict, Allow):
            return Egress(
                action=Action.FORWARD,
                content=content,
                verdict=verdict,
                redaction=None,
                reason="allowed",
            )
        if isinstance(verdict, CannotSay):
            return Egress(
                action=Action.BLOCK,
                content=None,
                verdict=verdict,
                redaction=None,
                reason=f"the guard could not look ({verdict.cause.value}): {verdict.blind_spot}",
            )

        ruling = rule_egress(verdict, policy=self._egress, content_length=len(content))
        if isinstance(ruling, RedactEgress) and conceals_all(content, ruling.redaction):
            return Egress(
                action=Action.REDACT,
                content=apply_masking(content, ruling.redaction),
                verdict=verdict,
                redaction=ruling.redaction,
                reason=ruling.reason,
            )
        # Either the policy blocks this kind, or the mask would have left the
        # sensitive value recoverable (ADR 0008). Both fall closed: an unverified
        # redaction is not a redaction.
        if isinstance(ruling, RedactEgress):
            reason = (
                f"{ruling.reason} — but the mask left the value recoverable, so limes blocked it"
            )
        else:
            reason = ruling.reason
        return Egress(
            action=Action.BLOCK,
            content=None,
            verdict=verdict,
            redaction=None,
            reason=reason,
        )

    @staticmethod
    def require_allow(verdict: Verdict) -> Allow:
        """Return the ``Allow`` or raise :class:`Blocked` — a hard gate helper.

        Args:
            verdict: The verdict to enforce.

        Returns:
            The verdict, narrowed to ``Allow``.

        Raises:
            Blocked: If the verdict is ``Deny`` or ``CannotSay``.
        """
        if isinstance(verdict, Allow):
            return verdict
        raise Blocked(verdict)
