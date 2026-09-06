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

The core also seals the **disposition** (ADR 0025): what the recording transport
did with the content once the verdict was in — ``forward``, ``redact`` or
``block`` — or ``None`` when that transport takes no disposition of its own
(the in-process ``check``, the CLI). Until ADR 0025 the verdict was sealed and
the disposition travelled in an unhashed annotation, so a chain could prove a
response was refused and not whether it left masked or did not leave at all.
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
    seq: int,
    direction: str,
    actor: str | None,
    disposition: str | None,
    vfp: str,
    prev_hash: str,
) -> dict[str, object]:
    return {
        "seq": seq,
        "direction": direction,
        "actor": actor,
        "disposition": disposition,
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
        disposition: What the recording transport did with the content —
            ``"forward"``, ``"redact"`` or ``"block"`` — or ``None`` when it
            took no disposition of its own (ADR 0025). Sealed into the digest,
            so a record cannot claim the content was blocked when it left.
        verdict_fingerprint: Canonical fingerprint of the verdict.
        prev_hash: Digest of the previous record (``GENESIS`` for the first).
        digest: SHA-256 of this record's canonical core.
    """

    seq: int
    direction: str
    actor: str | None
    disposition: str | None
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

    def append(
        self,
        direction: Direction,
        verdict: Verdict,
        actor: str | None,
        *,
        disposition: str | None = None,
    ) -> DecisionRecord:
        """Append a decision and return its linked record.

        Args:
            direction: The leg the decision was made on.
            verdict: The verdict to seal.
            actor: The asserted caller identity (``None`` for anonymous).
            disposition: What the transport did with the content (ADR 0025),
                or ``None`` when the caller takes no disposition of its own.
        """
        seq = len(self._records)
        vfp = fingerprint(verdict)
        prev = self.head
        digest = _digest(_core(seq, direction.value, actor, disposition, vfp, prev))
        record = DecisionRecord(
            seq=seq,
            direction=direction.value,
            actor=actor,
            disposition=disposition,
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
                _core(
                    record.seq,
                    record.direction,
                    record.actor,
                    record.disposition,
                    record.verdict_fingerprint,
                    prev,
                )
            )
            if record.prev_hash != prev or record.digest != recomputed:
                return ChainStatus(verified=False, length=len(self._records), broken_at=index)
            prev = record.digest
        return ChainStatus(verified=True, length=len(self._records), broken_at=None)
