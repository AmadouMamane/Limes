"""The opposable decision chain (ADR 0002): linkage, verification, tamper-evidence."""

from __future__ import annotations

import dataclasses

from limes.detector import Direction
from limes.record import GENESIS, Ledger
from limes.verdict import Allow, CannotSay, Deny


def _session(evidence):
    return [
        (Direction.INBOUND, Allow(evidence=evidence)),
        (Direction.INBOUND, Deny(reason="injection", evidence=evidence)),
        (Direction.OUTBOUND, CannotSay(blind_spot="detector offline")),
    ]


def test_empty_ledger_head_is_genesis():
    assert Ledger().head == GENESIS


def test_append_links_prev_hash(sample_evidence):
    ledger = Ledger()
    first = ledger.append(Direction.INBOUND, Allow(evidence=sample_evidence), actor="a")
    second = ledger.append(Direction.INBOUND, Deny(reason="x", evidence=sample_evidence), actor="a")
    assert first.prev_hash == GENESIS
    assert second.prev_hash == first.digest
    assert ledger.head == second.digest


def test_cannotsay_is_chained_too(sample_evidence):
    ledger = Ledger()
    for direction, verdict in _session(sample_evidence):
        ledger.append(direction, verdict, actor=None)
    assert len(ledger.records()) == 3
    assert ledger.verify().verified


def test_verify_detects_tampering(sample_evidence):
    ledger = Ledger()
    for direction, verdict in _session(sample_evidence):
        ledger.append(direction, verdict, actor=None)
    records = list(ledger.records())
    # Forge the middle record's verdict without recomputing its stored digest.
    records[1] = dataclasses.replace(records[1], verdict_fingerprint="FORGED")
    ledger._records = records  # the test reaches into the store on purpose
    status = ledger.verify()
    assert not status.verified
    assert status.broken_at == 1
