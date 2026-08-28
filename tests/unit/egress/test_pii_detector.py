"""The pii-egress detector: what it locates, what it refuses, and how it fails.

The corpus-wide numbers live in the admission harness; this file pins the
behaviours that must hold whatever the corpus says — the DoD items a matrix
cannot express.
"""

from __future__ import annotations

import pytest

from limes.detector import Context, DetectorBlind, Direction
from limes.detectors.pii_egress import PiiEgressDetector
from limes.guard import decide
from limes.record import Ledger
from limes.transports.in_process import Guard
from limes.transports.redaction import Action
from limes.verdict import Allow, CannotSay, Deny

CTX = Context(policy_hash="test", actor=None)


@pytest.fixture(name="detector")
def _detector():
    return PiiEgressDetector()


def _located(detector, text):
    return {
        (finding.label, text[span.start : span.end])
        for finding in detector.inspect(Direction.OUTBOUND, text, CTX)
        for span in finding.spans
    }


# --- the DoD pair: a real card is found, its lookalike is not ----------------


def test_a_luhn_valid_test_pan_is_located_exactly(detector):
    text = "Carte 4242 4242 4242 4242 renvoyée."
    assert ("pii:pan", "4242 4242 4242 4242") in _located(detector, text)


def test_a_sixteen_digit_non_luhn_reference_is_not_located(detector):
    # Same shape, same grouping, same sentence. Only the check digit differs,
    # and that is the whole claim of a checksum-gated rule.
    assert _located(detector, "Commande n° 1234 5678 9012 3456 expédiée.") == set()


def test_an_iban_shaped_identifier_failing_mod97_is_not_located_as_an_iban(detector):
    found = _located(detector, "Référence FR76 3000 6000 0112 3456 7890 188 interne.")
    assert not any(label == "pii:iban" for label, _ in found)


# --- the span is the value, not the sentence --------------------------------


def test_the_span_is_exactly_the_value(detector):
    text = "Le virement part vers CH93 0076 2011 6238 5295 7 ce soir."
    spans = [
        (span.start, span.end)
        for finding in detector.inspect(Direction.OUTBOUND, text, CTX)
        if finding.label == "pii:iban"
        for span in finding.spans
    ]
    assert len(spans) == 1
    start, end = spans[0]
    assert text[start:end] == "CH93 0076 2011 6238 5295 7"


def test_retry_trim_recovers_an_iban_that_ran_into_the_next_word(detector):
    # The greedy shape swallows the currency code; only the trimming retry gets
    # the account number back. Without it this is a silent false negative.
    text = "Überweisung an DE89 3704 0044 0532 0130 00 EUR 1240 ausgeführt."
    assert ("pii:iban", "DE89 3704 0044 0532 0130 00") in _located(detector, text)


def test_retry_trim_never_reports_a_candidate_that_failed_the_check(detector):
    # Trimming may only shorten. A run whose every prefix fails MOD 97-10 yields
    # no IBAN finding at all, however many retries it takes to establish that.
    found = _located(detector, "Ticket XX99 0000 1111 2222 3333 44 escalated.")
    assert not any(label == "pii:iban" for label, _ in found)


# --- legs --------------------------------------------------------------------


def test_the_inbound_leg_is_not_this_detector_s(detector):
    # `injection` owns inbound. A PII value a *user* typed is not an egress event,
    # and quietly guarding both legs would make the matrix a claim about neither.
    assert detector.inspect(Direction.INBOUND, "Carte 4242 4242 4242 4242.", CTX) == []


# --- fail-closed -------------------------------------------------------------


def test_content_over_the_declared_budget_makes_the_detector_blind(detector):
    with pytest.raises(DetectorBlind, match="max_content_chars"):
        detector.inspect(Direction.OUTBOUND, "a" * 200_001, CTX)


def test_a_blind_detector_becomes_cannot_say_never_allow(detector):
    verdict = decide(
        Direction.OUTBOUND, "a" * 200_001, CTX, (detector,), observed_at="2026-07-24T00:00:00Z"
    )
    # `Allow` is a disjoint type, and mypy says so — which is the point: the
    # degradation this guards against is unrepresentable, not merely untested.
    assert isinstance(verdict, CannotSay)
    assert Allow not in type(verdict).__mro__
    assert "pii-egress" in verdict.blind_spot


def test_a_blind_egress_leg_blocks_rather_than_forwarding(detector):
    # The whole point of the blind spot: nothing leaves. `CannotSay` on the way
    # out is not "probably fine", it is "I did not look".
    guard = Guard((detector,), policy_hash="test", ledger=Ledger())
    egress = guard.check_egress("a" * 200_001, actor=None, observed_at="2026-07-24T00:00:00Z")
    assert egress.action is Action.BLOCK
    assert egress.content is None
    assert isinstance(egress.verdict, CannotSay)


def test_content_that_does_not_encode_makes_the_detector_blind(detector):
    # The detector's answer is right…
    with pytest.raises(DetectorBlind, match="UTF-8"):
        detector.inspect(Direction.OUTBOUND, "solde \ud800 EUR", CTX)


def test_the_core_renders_the_unencodable_blind_spot_as_cannot_say(detector):
    # …and from v0.5 to v0.6 the core could not carry that answer: it hashed the
    # content *after* running the detectors and raised `UnicodeEncodeError`
    # before it could render `CannotSay`. This test pinned that crash so nobody
    # had to rediscover it. ADR 0011 made the digest total, and the same test
    # now pins the verdict the architecture promised all along.
    verdict = decide(
        Direction.OUTBOUND,
        "solde \ud800 EUR",
        CTX,
        (detector,),
        observed_at="2026-07-24T00:00:00Z",
    )
    assert isinstance(verdict, CannotSay)
    assert "pii-egress" in verdict.blind_spot
    assert "UTF-8" in verdict.blind_spot


def test_the_core_answers_unencodable_content_with_no_detector_at_all(detector):
    # The other half of the old diagnosis, kept: with zero detectors wired the
    # same input took the same crash path down, which is why it was never this
    # detector's bug. Post-ADR 0011 it follows the ordinary zero-detector
    # semantics — an Allow whose evidence names every detector that ran: none.
    # Scannability is the detectors' concern, and both egress detectors refuse
    # it; the core does not invent a witness.
    del detector
    verdict = decide(
        Direction.OUTBOUND, "solde \ud800 EUR", CTX, (), observed_at="2026-07-24T00:00:00Z"
    )
    assert isinstance(verdict, Allow)
    assert verdict.evidence.witnesses == ()


def test_clean_content_still_produces_an_allow_that_names_its_witness(detector):
    verdict = decide(
        Direction.OUTBOUND,
        "Votre demande a été transmise au service concerné.",
        CTX,
        (detector,),
        observed_at="2026-07-24T00:00:00Z",
    )
    assert isinstance(verdict, Allow)
    assert [witness.detector_id for witness in verdict.evidence.witnesses] == ["pii-egress"]


def test_a_finding_becomes_a_deny_carrying_the_offsets(detector):
    text = "Confirmation envoyée à jean.dupont@example.com hier."
    verdict = decide(Direction.OUTBOUND, text, CTX, (detector,), observed_at="2026-07-24T00:00:00Z")
    assert isinstance(verdict, Deny)
    span = verdict.evidence.matched_spans[0]
    assert text[span.start : span.end] == "jean.dupont@example.com"
    assert span.label == "pii:email"


# --- evidence carries no payload --------------------------------------------


def test_the_span_carries_a_hash_and_never_the_value(detector):
    text = "Carte 4242 4242 4242 4242 renvoyée."
    finding = detector.inspect(Direction.OUTBOUND, text, CTX)[0]
    span = finding.spans[0]
    assert "4242" not in span.matched_sha
    assert len(span.matched_sha) == 64
    assert span.label == "pii:pan"


# --- the policy is data ------------------------------------------------------


def test_the_detector_publishes_the_hash_of_the_policy_it_ran(detector):
    assert len(detector.policy_hash) == 64
    assert int(detector.policy_hash, 16) >= 0
