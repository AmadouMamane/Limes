"""From a ``Deny``'s evidence to a masking plan — and when there is no plan.

The plan is a pure function of the verdict, the policy and the length of the
content. That is what makes a masked forward replayable: the same refusal under
the same policy always masks the same regions with the same tokens.
"""

from __future__ import annotations

from limes.spans import RedactedSpan, redact
from limes.transports.redaction import (
    BlockEgress,
    EgressPolicy,
    OnEgressFinding,
    RedactEgress,
    apply_masking,
    rule_egress,
)
from limes.verdict import Deny, Evidence, Witness

CONTENT = "call 4111 1111 1111 1111 or write to alice@example.com about it"
PAN_AT = (5, 24)
EMAIL_AT = (37, 54)

REDACT_PII = EgressPolicy(default=OnEgressFinding.BLOCK, by_kind={"pii": OnEgressFinding.REDACT})


def _deny(*spans: RedactedSpan, reason: str = "2 rule match(es) on outbound content") -> Deny:
    return Deny(
        reason=reason,
        evidence=Evidence(
            witnesses=(Witness(detector_id="double", detector_version="0.0.0"),),
            policy_hash="p" * 64,
            content_sha="c" * 64,
            matched_spans=spans,
            observed_at="2026-07-24T00:00:00Z",
        ),
    )


def _span(bounds: tuple[int, int], label: str, content: str = CONTENT) -> RedactedSpan:
    return redact(content, bounds[0], bounds[1], label)


def _rule(verdict: Deny, policy: EgressPolicy = REDACT_PII, content: str = CONTENT):
    return rule_egress(verdict, policy=policy, content_length=len(content))


def test_the_configured_kinds_are_masked_and_the_rest_of_the_content_survives():
    ruling = _rule(_deny(_span(PAN_AT, "pii:pan"), _span(EMAIL_AT, "pii:email")))

    assert isinstance(ruling, RedactEgress)
    masked = apply_masking(CONTENT, ruling.redaction)
    assert masked == "call [REDACTED:pii] or write to [REDACTED:pii] about it"
    assert "4111" not in masked
    assert "alice@example.com" not in masked


def test_the_token_is_fixed_and_leaks_neither_length_nor_shape():
    short = _rule(_deny(_span((0, 4), "pii:pan"), _span((5, 24), "pii:pan")), content=CONTENT)
    assert isinstance(short, RedactEgress)
    tokens = {masking.token for masking in short.redaction.maskings}
    assert tokens == {"[REDACTED:pii]"}, (
        "a token that varied with what it replaced would leak what it replaced"
    )


def test_one_blocking_kind_blocks_the_whole_response():
    ruling = _rule(_deny(_span(PAN_AT, "pii:pan"), _span((5, 12), "secret:api-key")))
    assert isinstance(ruling, BlockEgress)
    assert "secret" in ruling.reason
    assert "pii" not in ruling.reason.split("blocks kind:")[-1], (
        "the reason names the kinds that blocked, not the ones that would have been masked"
    )


def test_an_unconfigured_kind_blocks_because_the_default_does():
    ruling = _rule(_deny(_span(PAN_AT, "phi:diagnosis")))
    assert isinstance(ruling, BlockEgress)
    assert "phi" in ruling.reason


def test_the_blocking_default_blocks_a_kind_it_was_never_told_about():
    ruling = _rule(_deny(_span(PAN_AT, "pii:pan")), policy=EgressPolicy.blocking())
    assert isinstance(ruling, BlockEgress)


def test_a_refusal_with_no_span_cannot_be_masked_and_is_blocked():
    ruling = _rule(_deny())
    assert isinstance(ruling, BlockEgress)
    assert "located no span" in ruling.reason


def test_a_span_that_does_not_fit_the_content_is_blocked_not_clamped():
    # Clamping would mask a region nobody located. The honest answer to "these
    # offsets do not describe this content" is that nothing leaves.
    beyond = RedactedSpan(start=5, end=len(CONTENT) + 10, label="pii:pan", matched_sha="0" * 64)
    ruling = _rule(_deny(beyond))
    assert isinstance(ruling, BlockEgress)
    assert "outside the" in ruling.reason


def test_overlapping_spans_are_merged_so_offsets_cannot_shift_under_each_other():
    ruling = _rule(_deny(_span((5, 24), "pii:pan"), _span((10, 30), "pii:email")))
    assert isinstance(ruling, RedactEgress)
    assert [(m.start, m.end) for m in ruling.redaction.maskings] == [(5, 30)]
    assert ruling.redaction.maskings[0].kinds == ("pii",)


def test_a_merged_region_of_two_kinds_names_both():
    policy = EgressPolicy(
        default=OnEgressFinding.BLOCK,
        by_kind={"pii": OnEgressFinding.REDACT, "phi": OnEgressFinding.REDACT},
    )
    ruling = _rule(
        _deny(_span((5, 24), "pii:pan"), _span((10, 30), "phi:diagnosis")), policy=policy
    )
    assert isinstance(ruling, RedactEgress)
    assert ruling.redaction.maskings[0].token == "[REDACTED:phi+pii]"


def test_adjacent_spans_stay_separate_tokens():
    ruling = _rule(_deny(_span((5, 24), "pii:pan"), _span((24, 30), "pii:email")))
    assert isinstance(ruling, RedactEgress)
    assert len(ruling.redaction.maskings) == 2


def test_the_plan_is_a_pure_function_of_verdict_and_policy():
    verdict = _deny(_span(PAN_AT, "pii:pan"), _span(EMAIL_AT, "pii:email"))
    first = _rule(verdict)
    second = _rule(verdict)
    assert isinstance(first, RedactEgress)
    assert isinstance(second, RedactEgress)
    assert first == second, "a replay must re-derive the same plan, byte for byte"
    assert apply_masking(CONTENT, first.redaction) == apply_masking(CONTENT, second.redaction)


def test_the_annotation_publishes_offsets_and_kinds_and_no_masked_text():
    ruling = _rule(_deny(_span(PAN_AT, "pii:pan"), _span(EMAIL_AT, "pii:email")))
    assert isinstance(ruling, RedactEgress)
    annotation = ruling.redaction.annotation()

    assert annotation["masked"] == 2
    assert annotation["kinds"] == ["pii"]
    rendered = repr(annotation)
    for secret in ("4111 1111 1111 1111", "alice@example.com", "4111"):
        assert secret not in rendered, "the annotation may carry coordinates, never content"
