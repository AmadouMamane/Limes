"""The in-process transport's outbound leg (ADR 0006).

The DoD item this file answers is "usable": a response carrying a card number and
an e-mail address comes back **masked and whole** — the caller gets a string it
can still use, with two regions overwritten — while a response carrying a secret
does not come back at all. Same guard, same core, one policy apart.
"""

from __future__ import annotations

from limes.detector import Direction
from limes.record import Ledger
from limes.transports.in_process import Guard
from limes.transports.redaction import Action, EgressPolicy, OnEgressFinding
from limes.verdict import Allow, CannotSay, Deny, fingerprint
from tests.unit.mcp.harness import BlindDetector
from tests.unit.redaction.doubles import PiiDouble, SecretDouble, WholeContentDouble

CLOCK = "2026-07-24T00:00:00Z"
POLICY_HASH = "p" * 64

ANSWER = (
    "Votre carte 4111 1111 1111 1111 a été renvoyée le 12 mars. "
    "Confirmation envoyée à alice@example.com. Solde : 1 240,50 EUR."
)
LEAKY_ANSWER = "Utilisez la clé sk-live-AB12cd34 pour l'API, merci."

REDACT_PII_BLOCK_SECRETS = EgressPolicy(
    default=OnEgressFinding.BLOCK,
    by_kind={"pii": OnEgressFinding.REDACT, "secret": OnEgressFinding.BLOCK},
)


def _guard(*detectors, egress: EgressPolicy | None = None, ledger: Ledger | None = None) -> Guard:
    return Guard(detectors, policy_hash=POLICY_HASH, ledger=ledger, egress=egress)


def _egress(guard: Guard, content: str):
    return guard.check_egress(content, actor="session-under-test", observed_at=CLOCK)


# --- usable -----------------------------------------------------------------


def test_a_pan_and_an_email_are_masked_and_everything_else_survives():
    egress = _egress(_guard(PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS), ANSWER)

    assert egress.action is Action.REDACT
    assert egress.content == (
        "Votre carte [REDACTED:pii] a été renvoyée le 12 mars. "
        "Confirmation envoyée à [REDACTED:pii]. Solde : 1 240,50 EUR."
    )
    assert "4111" not in (egress.content or "")
    assert "alice@example.com" not in (egress.content or "")
    assert "Solde : 1 240,50 EUR." in (egress.content or ""), (
        "a masked response must stay useful; only the located regions move"
    )


def test_a_masked_forward_is_still_a_refusal_on_the_chain():
    guard = _guard(PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    egress = _egress(guard, ANSWER)

    assert isinstance(egress.verdict, Deny)
    record = guard.ledger.records()[-1]
    assert record.direction == Direction.OUTBOUND.value
    assert '"kind":"deny"' in record.verdict_fingerprint, (
        "content left the process; the chain must still say it was refused, not allowed"
    )
    assert guard.ledger.verify().verified, "the chain still verifies"


def test_a_clean_response_is_forwarded_untouched_and_carries_no_plan():
    egress = _egress(_guard(PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS), "Bonjour, tout va bien.")
    assert egress.action is Action.FORWARD
    assert egress.content == "Bonjour, tout va bien."
    assert egress.redaction is None
    assert isinstance(egress.verdict, Allow)


# --- per kind ---------------------------------------------------------------


def test_secrets_block_while_pii_is_masked_under_the_same_policy():
    policy = REDACT_PII_BLOCK_SECRETS
    masked = _egress(_guard(PiiDouble(), SecretDouble(), egress=policy), ANSWER)
    blocked = _egress(_guard(PiiDouble(), SecretDouble(), egress=policy), LEAKY_ANSWER)

    assert masked.action is Action.REDACT
    assert blocked.action is Action.BLOCK
    assert blocked.content is None, (
        "a blocked egress hands the caller nothing to forward by mistake"
    )
    assert "secret" in blocked.reason


def test_a_secret_alongside_maskable_pii_blocks_the_whole_response():
    both = ANSWER + " " + LEAKY_ANSWER
    egress = _egress(_guard(PiiDouble(), SecretDouble(), egress=REDACT_PII_BLOCK_SECRETS), both)

    assert egress.action is Action.BLOCK
    assert egress.content is None, (
        "masking the maskable half would forward the unmaskable one alongside it"
    )


# --- the default ------------------------------------------------------------


def test_a_guard_told_nothing_blocks():
    egress = _egress(_guard(PiiDouble()), ANSWER)
    assert egress.action is Action.BLOCK
    assert egress.content is None
    assert Guard((), policy_hash=POLICY_HASH).egress_policy == EgressPolicy.blocking()


def test_a_blind_detector_blocks_and_offers_no_masked_alternative():
    egress = _egress(_guard(BlindDetector(), egress=REDACT_PII_BLOCK_SECRETS), ANSWER)
    assert egress.action is Action.BLOCK
    assert isinstance(egress.verdict, CannotSay)
    assert egress.redaction is None, (
        "a detector that could not look located nothing, so there is nothing to mask"
    )


def test_offsets_that_do_not_fit_the_content_block_rather_than_mask():
    stretched = WholeContentDouble("carte", "pii:pan", stretch=500)
    egress = _egress(_guard(stretched, egress=REDACT_PII_BLOCK_SECRETS), ANSWER)
    assert egress.action is Action.BLOCK
    assert "outside the" in egress.reason


# --- evidence and replay ----------------------------------------------------


def test_the_evidence_carries_coordinates_and_never_the_masked_text():
    guard = _guard(PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
    egress = _egress(guard, ANSWER)

    published = fingerprint(egress.verdict) + repr(
        egress.redaction and egress.redaction.annotation()
    )
    for secret in ("4111 1111 1111 1111", "alice@example.com", "4111", "alice"):
        assert secret not in published, "a guard that logs what it hid has not hidden it (ADR 0002)"
    assert egress.redaction is not None
    assert [(m.start, m.end) for m in egress.redaction.maskings] == [(12, 31), (82, 99)]


def test_the_same_session_replayed_masks_identically_and_chains_identically():
    def run() -> tuple[str | None, list[str]]:
        guard = _guard(PiiDouble(), egress=REDACT_PII_BLOCK_SECRETS)
        egress = _egress(guard, ANSWER)
        return egress.content, [record.digest for record in guard.ledger.records()]

    first_content, first_digests = run()
    second_content, second_digests = run()

    assert first_content == second_content
    assert first_digests == second_digests, (
        "the clock is data, so a replay of the same decision re-derives the same chain"
    )
