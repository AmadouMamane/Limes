"""The chain seals the disposition beside the verdict (ADR 0025).

Before ADR 0025 a record proved a response was *refused* and said nothing about
whether it then left masked or did not leave at all: the action lived in the
proxy's unhashed ``mcp`` annotation and nowhere at all for the in-process guard.
Seen red: ``DecisionRecord`` had no ``disposition`` field, and a forged one could
not break a chain.
"""

from __future__ import annotations

import dataclasses

import pytest

from limes.detector import Direction
from limes.record import Ledger
from limes.transports.in_process import Guard
from limes.transports.redaction import Action, EgressPolicy, OnEgressFinding
from limes.verdict import BlindCause, BlindKind, CannotSay
from tests.unit.redaction.doubles import PiiDouble, SecretDouble

pytestmark = pytest.mark.mutation

CLOCK = "2026-09-06T00:00:00Z"
ANSWER = "Votre carte 4111 1111 1111 1111 a été renvoyée à alice@example.com."
LEAKY = "Utilisez la clé sk-live-AB12cd34 pour l'API."
REDACT_PII = EgressPolicy(default=OnEgressFinding.BLOCK, by_kind={"pii": OnEgressFinding.REDACT})


def _guard(egress=None):
    return Guard([PiiDouble(), SecretDouble()], policy_hash="p" * 64, egress=egress)


def test_a_masked_forward_is_sealed_as_redact():
    guard = _guard(REDACT_PII)
    egress = guard.check_egress(ANSWER, actor=None, observed_at=CLOCK)
    assert egress.action is Action.REDACT
    assert guard.ledger.records()[-1].disposition == "redact"


def test_a_blocked_response_is_sealed_as_block():
    guard = _guard(REDACT_PII)
    egress = guard.check_egress(LEAKY, actor=None, observed_at=CLOCK)
    assert egress.action is Action.BLOCK
    assert guard.ledger.records()[-1].disposition == "block"


def test_a_clean_response_is_sealed_as_forward():
    guard = _guard(REDACT_PII)
    guard.check_egress("Bonjour.", actor=None, observed_at=CLOCK)
    assert guard.ledger.records()[-1].disposition == "forward"


def test_a_bare_check_takes_no_disposition_and_says_so():
    guard = _guard()
    guard.check("hello", actor=None, observed_at=CLOCK)
    assert guard.ledger.records()[-1].disposition is None


def test_a_forged_disposition_breaks_the_chain():
    guard = _guard(REDACT_PII)
    guard.check_egress(ANSWER, actor=None, observed_at=CLOCK)
    guard.check_egress("Bonjour.", actor=None, observed_at=CLOCK)
    records = list(guard.ledger.records())
    # Claim the masked forward was a block, without recomputing the digest.
    records[0] = dataclasses.replace(records[0], disposition="block")
    guard.ledger._records = records  # the test reaches into the store on purpose
    status = guard.ledger.verify()
    assert not status.verified
    assert status.broken_at == 0


def test_the_disposition_is_inside_the_digest_not_beside_it():
    blind = CannotSay(
        blind_spot="x", cause=BlindCause.DECLARED, kinds=frozenset({BlindKind.BUDGET})
    )
    a = Ledger().append(Direction.OUTBOUND, blind, None, disposition="block")
    b = Ledger().append(Direction.OUTBOUND, blind, None, disposition=None)
    assert a.digest != b.digest, "two records that differ only in disposition must not collide"
