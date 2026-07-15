"""The opposable decision chain (ADR 0002).

Every decision — Allow, Deny, *and* CannotSay — becomes a hash-linked
:class:`DecisionRecord`. The chain is the registry: each record carries the
digest of its predecessor, so tampering with any record breaks every later link.
The linkage lives on the record, not on the evidence, because ``CannotSay``
carries no evidence yet a blind spot must still be in the ledger.

The scheme mirrors Tessera's ``guard/audit.py``: genesis is 64 zeros; the digest
is SHA-256 over a canonical, sorted-key, whitespace-free JSON core. Because the
verdict fingerprint (see :func:`limes.verdict.fingerprint`) is deterministic and
``observed_at`` is data (never ``now()``), replaying a recorded session
re-derives byte-identical digests.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from limes.detector import Direction
from limes.verdict import Verdict, fingerprint

__all__ = ["GENESIS", "ChainStatus", "DecisionRecord", "Ledger"]

GENESIS = "0" * 64


def _digest(core: dict[str, object]) -> str:
    canonical = json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _core(
    seq: int, direction: str, actor: str | None, vfp: str, prev_hash: str
) -> dict[str, object]:
    return {
        "seq": seq,
        "direction": direction,
        "actor": actor,
        "verdict": vfp,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """One decision, linked into the chain.

    Attributes:
        seq: 0-based position in the chain.
        direction: The leg the decision was made on.
        actor: The asserted caller identity (may be ``None``).
        verdict_fingerprint: Canonical fingerprint of the verdict.
        prev_hash: Digest of the previous record (``GENESIS`` for the first).
        digest: SHA-256 of this record's canonical core.
    """

    seq: int
    direction: str
    actor: str | None
    verdict_fingerprint: str
    prev_hash: str
    digest: str


@dataclass(frozen=True, slots=True)
class ChainStatus:
    """The result of verifying a chain.

    Attributes:
        verified: Whether every link recomputed and matched.
        length: Number of records verified.
        broken_at: 0-based index of the first broken record, or ``None``.
    """

    verified: bool
    length: int
    broken_at: int | None


class Ledger:
    """An append-only, hash-linked ledger of decisions."""

    def __init__(self) -> None:
        self._records: list[DecisionRecord] = []

    @property
    def head(self) -> str:
        """Digest of the last record, or ``GENESIS`` if the ledger is empty."""
        return self._records[-1].digest if self._records else GENESIS

    def append(self, direction: Direction, verdict: Verdict, actor: str | None) -> DecisionRecord:
        """Append a decision and return its linked record."""
        seq = len(self._records)
        vfp = fingerprint(verdict)
        prev = self.head
        digest = _digest(_core(seq, direction.value, actor, vfp, prev))
        record = DecisionRecord(
            seq=seq,
            direction=direction.value,
            actor=actor,
            verdict_fingerprint=vfp,
            prev_hash=prev,
            digest=digest,
        )
        self._records.append(record)
        return record

    def records(self) -> tuple[DecisionRecord, ...]:
        """Return the recorded decisions in order."""
        return tuple(self._records)

    def verify(self) -> ChainStatus:
        """Recompute every link and report whether the chain holds."""
        prev = GENESIS
        for index, record in enumerate(self._records):
            recomputed = _digest(
                _core(record.seq, record.direction, record.actor, record.verdict_fingerprint, prev)
            )
            if record.prev_hash != prev or record.digest != recomputed:
                return ChainStatus(verified=False, length=len(self._records), broken_at=index)
            prev = record.digest
        return ChainStatus(verified=True, length=len(self._records), broken_at=None)
