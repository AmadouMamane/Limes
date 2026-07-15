"""The in-process transport (ADR 0004): a Guard object over the pure core.

``Guard`` wires a set of detectors and a policy hash to a :class:`~limes.record.Ledger`,
exposes ``check()`` returning a :class:`~limes.verdict.Verdict`, and offers a
convenience ``require_allow`` that raises :class:`Blocked` on anything but
``Allow`` — for callers who want a hard gate rather than a match.
"""

from __future__ import annotations

from collections.abc import Sequence

from limes.detector import Context, Detector, Direction
from limes.guard import decide
from limes.record import Ledger
from limes.verdict import Allow, CannotSay, Deny, Verdict

__all__ = ["Blocked", "Guard"]


class Blocked(Exception):
    """Raised by :meth:`Guard.require_allow` when a verdict is not ``Allow``."""

    def __init__(self, verdict: Deny | CannotSay) -> None:
        self.verdict = verdict
        if isinstance(verdict, Deny):
            super().__init__(f"blocked: {verdict.reason}")
        else:
            super().__init__(f"blocked (cannot say): {verdict.blind_spot}")


class Guard:
    """An in-process guard over a fixed set of detectors and one policy."""

    def __init__(
        self,
        detectors: Sequence[Detector],
        *,
        policy_hash: str,
        ledger: Ledger | None = None,
    ) -> None:
        """Wire ``detectors`` under ``policy_hash``, recording into ``ledger``."""
        self._detectors = tuple(detectors)
        self._policy_hash = policy_hash
        self._ledger = ledger if ledger is not None else Ledger()

    @property
    def ledger(self) -> Ledger:
        """The ledger this guard appends decisions to."""
        return self._ledger

    def check(
        self,
        content: str,
        *,
        actor: str | None,
        observed_at: str,
        direction: Direction = Direction.INBOUND,
        locale: str | None = None,
    ) -> Verdict:
        """Inspect ``content`` and record the verdict in the ledger.

        Args:
            content: The content to inspect.
            actor: The caller's asserted identity (``None`` for anonymous).
            observed_at: ISO-8601 timestamp recorded into evidence.
            direction: The leg to inspect (default inbound).
            locale: Optional locale hint.

        Returns:
            The verdict, which is also appended to :attr:`ledger`.
        """
        ctx = Context(policy_hash=self._policy_hash, actor=actor, locale=locale)
        verdict = decide(direction, content, ctx, self._detectors, observed_at=observed_at)
        self._ledger.append(direction, verdict, actor)
        return verdict

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
