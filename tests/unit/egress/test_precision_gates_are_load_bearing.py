"""The three precision gates ADR 0021 Am. 2 added are load-bearing, not decoration.

Each one was bought with a measured false positive, and each is asserted here the
only way that means anything: the shipped rule refuses the lookalike, and a
**named mutant** of that same rule accepts it. A gate whose removal changes
nothing was never a gate.

The three, and what each cost before it existed:

* ``pem_key_material`` — the PEM rule fired on armour lines with nothing between
  them and on a block whose body is the word ``anything``. Two of gitleaks' own
  hard negatives.
* the **slack grammar** — the rule asked for a vendor prefix plus ten of
  anything, and killed 14 of gitleaks' hard negatives: ``xoxb-12345-abcd234``,
  ``xoxa-access-token-string``, ``xoxp-1234567890``.
* the **phone left boundary** — a telephone number does not continue a run of
  digit groups, and ``0532 0130 00`` inside a broken IBAN passed the rule's own
  E.164 validator.

The fourth thing this file pins is a **refusal**: two false-positive classes were
measured and deliberately left, and the reason is a false negative that would be
worse. A later reader who "fixes" them should have to delete an assertion that
says so.
"""

from __future__ import annotations

import re

import pytest

from limes.detector import Context, Direction
from limes.detectors.egress_policy import VALIDATORS, load_egress_policy
from limes.detectors.pii_egress import PiiEgressDetector
from limes.detectors.secrets_egress import SecretsEgressDetector

#: Every gate here is asserted against a NAMED MUTANT of its own rule — red by
#: construction, per test — which is the mutation marker's exact meaning.
pytestmark = pytest.mark.mutation

_CONTEXT = Context(policy_hash="precision-gates", actor=None)

#: The PEM shapes gitleaks ships as false positives: armour with no key under it.
_ARMOUR_ONLY = "-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----"
_ARMOUR_ROUND_A_WORD = "-----BEGIN PRIVATE KEY-----\nanything\n-----END PRIVATE KEY-----"

#: Slack lookalikes the loose rule killed, modelled on gitleaks' own negatives.
_SLACK_LOOKALIKES = (
    "xoxb-12345-EXAMPLE234",
    "xoxb-xoxb-EXAMPLE-bot-token",
    "xoxa-EXAMPLE-token-string",
)

#: A checksum-invalid IBAN. Its eleven-digit tail passes the phone rule's own
#: E.164 validator, and is not a telephone number.
_BROKEN_IBAN = "Referenz DE00 3704 0044 0532 0130 00 wurde storniert."


def _rule(detector_id: str, label: str):
    policy = load_egress_policy()
    for rule in policy.rules_for(detector_id):
        if rule.label == label:
            return rule
    raise AssertionError(f"{label} is not in the shipped policy")


def _fires(detector, content: str) -> bool:
    return bool(detector.inspect(Direction.OUTBOUND, content, _CONTEXT))


# --------------------------------------------------------------------------
# 1. pem_key_material
# --------------------------------------------------------------------------


@pytest.mark.parametrize("lookalike", [_ARMOUR_ONLY, _ARMOUR_ROUND_A_WORD])
def test_the_shipped_pem_rule_refuses_armour_with_no_key_under_it(lookalike):
    assert not _fires(SecretsEgressDetector(), lookalike)


@pytest.mark.parametrize("lookalike", [_ARMOUR_ONLY, _ARMOUR_ROUND_A_WORD])
def test_and_the_mutant_that_drops_the_material_check_accepts_them(lookalike):
    # THE MUTATION: `validator: pem_key_material` reverted to `validator: none`.
    rule = _rule("secrets-egress", "secret:private-key-pem")
    match = rule.pattern.search(lookalike)
    assert match is not None, "the shape still matches — only the validator refuses"
    assert VALIDATORS["none"](match.group(0)) is True
    assert VALIDATORS["pem_key_material"](match.group(0)) is False


def test_the_pem_gate_still_passes_a_block_that_carries_material():
    # And the mirror, so the gate cannot be satisfied by refusing everything.
    real_shape = "-----BEGIN RSA PRIVATE KEY-----\n" + "RVhBTVBMRSBPTkxZIC0gbm90IGEga2V5" * 2
    assert VALIDATORS["pem_key_material"](real_shape) is True


def test_an_unterminated_block_still_passes_on_its_material():
    # The rule deliberately swallows to the end of the content when the END line
    # is missing: masking too much beats forwarding a truncated key. The gate may
    # not undo that.
    assert (
        VALIDATORS["pem_key_material"](
            "-----BEGIN EC PRIVATE KEY-----\nUExBQ0VIT0xERVIgLSBzeW50aGV0aWM="
        )
        is True
    )


# --------------------------------------------------------------------------
# 2. the slack grammar
# --------------------------------------------------------------------------


@pytest.mark.parametrize("lookalike", _SLACK_LOOKALIKES)
def test_the_shipped_slack_rule_refuses_a_prefix_with_no_token_shape(lookalike):
    assert not _fires(SecretsEgressDetector(), f'The sample config says "{lookalike}".')


@pytest.mark.parametrize("lookalike", _SLACK_LOOKALIKES)
def test_and_the_mutant_that_asks_only_for_the_prefix_accepts_them(lookalike):
    # THE MUTATION: the rule as it shipped until ADR 0021 Am. 2 — a vendor prefix
    # plus ten of anything.
    loose = re.compile(r"(?<![A-Za-z0-9-])xox[baprse]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])")
    assert loose.search(lookalike) is not None


def test_the_slack_grammar_still_accepts_the_shapes_slack_actually_issues():
    # The mirror. These are the vendor's own grammars; losing one is how the
    # first attempt at this rule dropped four real formats.
    rule = _rule("secrets-egress", "secret:slack-token")
    # Assembled, never a contiguous literal (ADR 0010): these shapes are the
    # vendor's own grammar, which is exactly what a host secret scanner matches
    # too — GitHub push protection refused the literal form of this very test.
    for prefix, body in (
        ("xoxb-", "123456789012-210987654321-EXAMPLEONLYnotarealtoken"),
        ("xoxb-", "4938479689-9153451358"),
        ("xoxb-", "29523055-es2h8pR51yCIxSFBi4"),
        ("xoxa-", "7-nJL8ZjTG"),
    ):
        issued = prefix + body
        assert rule.pattern.search(issued) is not None, issued


# --------------------------------------------------------------------------
# 3. the phone left boundary
# --------------------------------------------------------------------------


def test_the_shipped_phone_rule_refuses_a_digit_run_inside_a_broken_iban():
    findings = PiiEgressDetector().inspect(Direction.OUTBOUND, _BROKEN_IBAN, _CONTEXT)
    assert not [f for f in findings if f.label == "pii:phone"]


def test_and_the_mutant_without_the_second_lookbehind_accepts_it():
    # THE MUTATION: `(?<![0-9][ \xa0])` removed from pii:phone.
    rule = _rule("pii-egress", "pii:phone")
    mutant = re.compile(rule.pattern.pattern.replace(r"(?<![0-9][ \xa0])", ""))
    assert mutant.pattern != rule.pattern.pattern, "the mutation did not change the rule"
    matched = [m.group(0) for m in mutant.finditer(_BROKEN_IBAN)]
    assert any(VALIDATORS["phone_digits"](m) for m in matched)


@pytest.mark.parametrize(
    "content",
    [
        "TEL 06 12 34 56 78 — merci de rappeler avant 18h.",
        "CONTACT +33 6 12 34 56 78 for the escalation rota.",
        "MOBIL +49 30 901820 steht im Ticket.",
        "Appelez le 06 12 34 56 78 avant midi.",
    ],
)
def test_the_phone_boundary_still_finds_a_number_after_a_word(content):
    # The blind spot that nearly shipped: tightening the boundary to reject any
    # preceding UPPER-CASE group measured zero cost on every corpus here, because
    # no corpus held an upper-case label before a number. These cases are the
    # corpus learning to see it.
    findings = PiiEgressDetector().inspect(Direction.OUTBOUND, content, _CONTEXT)
    assert [f for f in findings if f.label == "pii:phone"], content


# --------------------------------------------------------------------------
# 4. what was measured and deliberately NOT fixed
# --------------------------------------------------------------------------


def test_a_luhn_valid_run_inside_a_broken_iban_still_fires_and_that_is_deliberate():
    """Suppressing this would buy a false positive with an exploitable evasion.

    `AT00 1904 3002 3457 3201` is a checksum-invalid IBAN whose sixteen-digit body
    passes Luhn by coincidence, so `pii:pan` reports it. The obvious fix — let an
    IBAN-shaped span suppress findings inside it — cannot tell that case from
    `AB12 4242 4242 4242 4242`, which is a real card number behind four characters
    of prefix. There is no content property separating them, so the suppression
    would trade a false positive on a corrupted account number for a **false
    negative on a card number**, which is the worse error for an egress guard.

    Measured and left: 3 of 289 external decoys and 1 of 26 internal lookalikes.
    Change this only with a measurement that closes the evasion too.
    """
    findings = PiiEgressDetector().inspect(
        Direction.OUTBOUND, "Reference AT00 1904 3002 3457 3201 was cancelled.", _CONTEXT
    )
    assert [f for f in findings if f.label == "pii:pan"]
