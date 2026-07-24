"""No record, annotation or journal line ever carries the value it caught.

A guard that logs what it caught leaks what it caught — and an egress guard logs
on the one leg where the payload is, by construction, the sensitive thing. So this
sweeps the **whole** corpus through the real pipeline and the real serialisations
and asserts the values are nowhere in the output.

One deliberate exclusion: 64-hex digests are stripped before searching. A
``matched_sha`` is a one-way digest — it is *how* evidence proves what matched
without keeping it — and a sixteen-digit value has a real chance of appearing
inside some hash by coincidence, which would be a false alarm rather than a leak.
Everything else is searched verbatim.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict

import pytest

from limes.detector import Direction
from limes.detectors.pii_egress import PiiEgressDetector
from limes.eval.egress_corpus import load_positive
from limes.record import Ledger
from limes.transports.in_process import Guard
from limes.transports.mcp.sink import record_entry
from limes.transports.redaction import Action, EgressPolicy, MaskStyle, OnEgressFinding
from limes.verdict import fingerprint

DETECTOR = "pii-egress"
OBSERVED_AT = "2026-07-24T00:00:00Z"

_HEX64 = re.compile(r"\b[0-9a-f]{64}\b")

REDACTING = EgressPolicy(
    default=OnEgressFinding.BLOCK,
    by_kind={"pii": OnEgressFinding.REDACT},
    mask_style={"pii": MaskStyle.LAST4},
)


def _searchable(payload: object) -> str:
    """Serialise, then remove the one-way digests that are not a leak."""
    return _HEX64.sub("<sha>", json.dumps(payload, sort_keys=True, ensure_ascii=False))


@pytest.fixture(name="cases")
def _cases():
    return load_positive(DETECTOR)


def test_no_verdict_fingerprint_carries_a_value(cases):
    detector = PiiEgressDetector()
    for case in cases:
        guard = Guard((detector,), policy_hash="test", ledger=Ledger())
        verdict = guard.check(
            case.content, actor=None, observed_at=OBSERVED_AT, direction=Direction.OUTBOUND
        )
        serialised = _HEX64.sub("<sha>", fingerprint(verdict))
        assert case.locate not in serialised, f"{case.case_id}: value in the verdict fingerprint"
        assert case.content not in serialised, f"{case.case_id}: content in the fingerprint"


def test_no_chain_record_carries_a_value(cases):
    detector = PiiEgressDetector()
    for case in cases:
        ledger = Ledger()
        guard = Guard((detector,), policy_hash="test", ledger=ledger)
        guard.check(case.content, actor=None, observed_at=OBSERVED_AT, direction=Direction.OUTBOUND)
        for record in ledger.records():
            serialised = _searchable(asdict(record))
            assert case.locate not in serialised, f"{case.case_id}: value in a DecisionRecord"
            assert case.content not in serialised


def test_no_redaction_annotation_carries_a_value(cases):
    detector = PiiEgressDetector()
    for case in cases:
        guard = Guard((detector,), policy_hash="test", ledger=Ledger(), egress=REDACTING)
        egress = guard.check_egress(case.content, actor=None, observed_at=OBSERVED_AT)
        if egress.redaction is None:
            continue
        serialised = _searchable(egress.redaction.annotation())
        assert case.locate not in serialised, f"{case.case_id}: value in the redaction annotation"


def test_no_journal_line_carries_a_value(cases):
    # The JSONL a proxy actually writes: the record's own fields plus the mcp
    # annotation, which is where the masking plan travels.
    detector = PiiEgressDetector()
    for case in cases:
        ledger = Ledger()
        guard = Guard((detector,), policy_hash="test", ledger=ledger, egress=REDACTING)
        egress = guard.check_egress(case.content, actor=None, observed_at=OBSERVED_AT)
        entry = record_entry(
            ledger.records()[-1],
            method="tools/call",
            tool="lookup",
            request_id=1,
            action=egress.action.value,
            redaction=None if egress.redaction is None else egress.redaction.annotation(),
        )
        serialised = _searchable(entry)
        assert case.locate not in serialised, f"{case.case_id}: value in the journal line"
        assert case.content not in serialised, f"{case.case_id}: content in the journal line"


def test_the_masked_content_no_longer_carries_the_value(cases):
    # The other half: what actually goes on the wire. `last4` is the most
    # revealing style shipped, so it is the one worth asserting against.
    detector = PiiEgressDetector()
    for case in cases:
        guard = Guard((detector,), policy_hash="test", ledger=Ledger(), egress=REDACTING)
        egress = guard.check_egress(case.content, actor=None, observed_at=OBSERVED_AT)
        assert egress.action is not Action.FORWARD, f"{case.case_id} left unguarded"
        if egress.content is None:
            continue
        assert case.locate not in egress.content, f"{case.case_id}: value survived the mask"
