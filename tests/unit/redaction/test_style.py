"""Mask styles (ADR 0008): full | last4 | format_preserving, per kind, verified.

The default is ``full`` and unchanged from v0.3. The two styled masks keep a
little of the shape — the last four characters, or the length and separators —
and every one of them is verified by re-derivation: a mask that would leave the
sensitive value recoverable is not applied, the transport blocks instead.
"""

from __future__ import annotations

import pytest

from limes.spans import redact
from limes.transports.in_process import Guard
from limes.transports.redaction import (
    Action,
    EgressPolicy,
    Masking,
    MaskStyle,
    OnEgressFinding,
    RedactEgress,
    apply_masking,
    conceals_all,
    read_egress_policy,
    rule_egress,
)
from limes.verdict import Deny, Evidence
from tests.unit.redaction.doubles import PiiDouble, SecretDouble

CARD = "4111 1111 1111 1111"
KEY = "sk-live-AB12cd34"
CLOCK = "2026-07-24T00:00:00Z"


# --- rendering, per style ---------------------------------------------------


def test_full_writes_the_kind_token_and_ignores_the_original():
    masking = Masking(start=0, end=len(CARD), kinds=("pii",), style=MaskStyle.FULL)
    assert masking.render(CARD) == "[REDACTED:pii]"
    assert masking.conceals(CARD)


def test_last4_reveals_only_the_last_four_characters():
    masking = Masking(start=0, end=len(CARD), kinds=("pii",), style=MaskStyle.LAST4)
    assert masking.render(CARD) == "••••1111"
    assert masking.conceals(CARD), "the full PAN is unrecoverable from four digits"


def test_last4_reveals_nothing_for_a_value_of_four_or_fewer():
    masking = Masking(start=0, end=3, kinds=("secret",), style=MaskStyle.LAST4)
    assert masking.render("abc") == "••••", "a short value is never shown whole"
    assert masking.conceals("abc")


def test_format_preserving_keeps_the_shape_and_replaces_the_content():
    masking = Masking(start=0, end=len(CARD), kinds=("pii",), style=MaskStyle.FORMAT_PRESERVING)
    assert masking.render(CARD) == "0000 0000 0000 0000"
    assert masking.conceals(CARD)


def test_format_preserving_over_all_placeholders_conceals_nothing():
    # The verification with teeth: a value that is already all zeros renders to
    # itself, so the mask hid nothing, and `conceals` says so.
    masking = Masking(start=0, end=4, kinds=("pii",), style=MaskStyle.FORMAT_PRESERVING)
    assert masking.render("0000") == "0000"
    assert not masking.conceals("0000")


# --- policy parsing ---------------------------------------------------------


def _write_policy(tmp_path, body: str):
    path = tmp_path / "policy.yaml"
    path.write_text(
        f"version: 1\n{body}rules:\n  - label: 'injection:never'\n    origin: limes\n"
        "    pattern: 'zzz'\n",
        encoding="utf-8",
    )
    return path


def test_mask_style_is_read_per_kind(tmp_path):
    policy = _write_policy(
        tmp_path,
        "on_egress_finding:\n  by_kind:\n    pii: redact\n  mask_style:\n    pii: last4\n",
    )
    egress = read_egress_policy(policy)
    assert egress is not None
    assert egress.style_for("pii") is MaskStyle.LAST4
    assert egress.style_for("secret") is MaskStyle.FULL, "an unnamed kind masks full"


def test_an_unknown_mask_style_is_refused(tmp_path):
    policy = _write_policy(
        tmp_path,
        "on_egress_finding:\n  by_kind:\n    pii: redact\n  mask_style:\n    pii: sneaky\n",
    )
    with pytest.raises(ValueError, match="mask_style"):
        read_egress_policy(policy)


def test_a_typo_in_the_egress_block_is_still_refused(tmp_path):
    # mask_style is recognised now; a neighbouring typo must still be caught.
    policy = _write_policy(tmp_path, "on_egress_finding:\n  by_knid:\n    pii: redact\n")
    with pytest.raises(ValueError, match="unrecognised key"):
        read_egress_policy(policy)


# --- plan derivation --------------------------------------------------------


def _deny(content: str, *spans) -> Deny:
    evidence = Evidence(
        witnesses=(),
        policy_hash="p" * 64,
        content_sha="c" * 64,
        matched_spans=tuple(spans),
        observed_at=CLOCK,
    )
    return Deny(reason="1 rule match(es)", evidence=evidence)


def test_rule_egress_assigns_the_configured_style_and_masks_by_it():
    content = "card 4111 1111 1111 1111 end"
    span = redact(content, 5, 24, "pii:pan")
    policy = EgressPolicy(
        default=OnEgressFinding.BLOCK,
        by_kind={"pii": OnEgressFinding.REDACT},
        mask_style={"pii": MaskStyle.LAST4},
    )

    ruling = rule_egress(_deny(content, span), policy=policy, content_length=len(content))

    assert isinstance(ruling, RedactEgress)
    assert ruling.redaction.maskings[0].style is MaskStyle.LAST4
    assert apply_masking(content, ruling.redaction) == "card ••••1111 end"
    assert conceals_all(content, ruling.redaction)


def test_a_merged_multi_kind_region_falls_back_to_full():
    content = "x 4111 1111 1111 1111 y"
    pan = redact(content, 2, 21, "pii:pan")
    secret = redact(content, 10, 21, "secret:overlap")  # overlaps the pan
    policy = EgressPolicy(
        default=OnEgressFinding.BLOCK,
        by_kind={"pii": OnEgressFinding.REDACT, "secret": OnEgressFinding.REDACT},
        mask_style={"pii": MaskStyle.LAST4, "secret": MaskStyle.LAST4},
    )

    ruling = rule_egress(_deny(content, pan, secret), policy=policy, content_length=len(content))

    assert isinstance(ruling, RedactEgress)
    assert len(ruling.redaction.maskings) == 1, "the overlapping spans merged"
    assert ruling.redaction.maskings[0].style is MaskStyle.FULL, (
        "two kinds' styles cannot both be honoured over one region; fall back to full"
    )


# --- in-process, end to end -------------------------------------------------

CARD_ANSWER = "Votre carte 4111 1111 1111 1111 a été débitée."


def _guard(egress: EgressPolicy) -> Guard:
    return Guard([PiiDouble(), SecretDouble()], policy_hash="p" * 64, egress=egress)


def _egress(guard: Guard, content: str):
    return guard.check_egress(content, actor=None, observed_at=CLOCK)


def _redact_pii(style: MaskStyle | None) -> EgressPolicy:
    return EgressPolicy(
        default=OnEgressFinding.BLOCK,
        by_kind={"pii": OnEgressFinding.REDACT},
        mask_style={} if style is None else {"pii": style},
    )


def test_in_process_last4_masks_the_card_and_conceals_it():
    result = _egress(_guard(_redact_pii(MaskStyle.LAST4)), CARD_ANSWER)

    assert result.action is Action.REDACT
    assert "••••1111" in (result.content or "")
    assert CARD not in (result.content or ""), "the full PAN is gone from the forwarded content"
    assert result.redaction is not None
    assert result.redaction.maskings[0].style is MaskStyle.LAST4


def test_in_process_format_preserving_keeps_the_shape():
    result = _egress(_guard(_redact_pii(MaskStyle.FORMAT_PRESERVING)), CARD_ANSWER)

    assert result.action is Action.REDACT
    assert "0000 0000 0000 0000" in (result.content or "")
    assert CARD not in (result.content or "")


def test_in_process_default_style_is_full_and_unchanged():
    result = _egress(_guard(_redact_pii(None)), CARD_ANSWER)

    assert result.action is Action.REDACT
    assert "[REDACTED:pii]" in (result.content or "")


def test_in_process_format_preserving_blocks_when_it_would_conceal_nothing():
    # A response whose PAN is already all zeros: format_preserving renders it to
    # itself, conceals nothing, and the transport falls closed to a block.
    all_zeros = "Votre carte 0000 0000 0000 0000 a été débitée."
    result = _egress(_guard(_redact_pii(MaskStyle.FORMAT_PRESERVING)), all_zeros)

    assert result.action is Action.BLOCK, "an unverified mask is no mask; fall closed"
    assert result.content is None
    assert "recoverable" in result.reason


def test_in_process_per_kind_styles_sit_side_by_side():
    # pii masks last4, secret (also redact) has no style so it masks full.
    content = f"Carte {CARD}, clé {KEY}."
    policy = EgressPolicy(
        default=OnEgressFinding.BLOCK,
        by_kind={"pii": OnEgressFinding.REDACT, "secret": OnEgressFinding.REDACT},
        mask_style={"pii": MaskStyle.LAST4},
    )

    result = _egress(_guard(policy), content)

    assert result.action is Action.REDACT
    assert "••••1111" in (result.content or ""), "pii masked last4"
    assert "[REDACTED:secret]" in (result.content or ""), "secret masked full"
    assert CARD not in (result.content or "")
    assert KEY not in (result.content or "")


def test_the_style_is_recorded_in_the_evidence_but_never_the_masked_text():
    result = _egress(_guard(_redact_pii(MaskStyle.LAST4)), CARD_ANSWER)
    assert result.redaction is not None
    annotation = result.redaction.annotation()

    assert annotation["spans"][0]["style"] == "last4", "the style rides in the record"
    published = repr(annotation)
    assert CARD not in published, "the record names the style, never the bytes it masked"
    assert "1111" not in published, "not even the revealed four digits leak into the record"
