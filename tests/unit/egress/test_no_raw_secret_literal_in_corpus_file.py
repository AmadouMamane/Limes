"""The secrets corpus FILE carries no vendor-key literal a host scanner would flag.

The point of the secrets corpus is to prove the detector fires on real credential
FORMATS. But a file that stores those formats as contiguous literals does two bad
things at once: it trips every host's secret scanner (GitHub push protection
blocked exactly this, on the Stripe vectors), and it commits a credential-shaped
string into a public security repository for ever. So a vendor-prefixed vector is
stored ASSEMBLED (``token_parts`` joined at load, ADR 0010); the detector still
runs on the reconstructed real format.

This witness interrogates the FILE, not the loaded corpus (ADR 0026): it runs
limes' own secrets rules over the raw bytes and refuses any match. PEM blocks and
JWTs are excluded — they appear literally on purpose, being documentation values
(a PEM body that base64-decodes to 'EXAMPLE ONLY', the JWT every tutorial ships)
that no host scanner push-protects. Every OTHER secrets rule is a vendor-key prefix
whose shape a scanner DOES match, so its literal may never appear in the file.

If a contributor pastes a raw ``sk_live_…`` back into a template, or reverts an
assembled case to ``content``/``locate`` with the literal, this goes red — which is
the whole point of a witness that reads the thing itself.
"""

from __future__ import annotations

from limes.detectors.egress_policy import load_egress_policy
from limes.eval.egress_corpus import corpus_path, load_positive

#: Rules whose value is a multi-line / base64 documentation shape no host secret
#: scanner push-protects, and which therefore appear literally in the corpus. Every
#: rule NOT in this set is a vendor-key prefix that must be stored assembled.
_LITERAL_ALLOWED = frozenset({"secret:private-key-pem", "secret:jwt"})

#: The positive categories that are stored assembled (ADR 0010) — the vendor keys.
_ASSEMBLED_CATEGORIES = frozenset(
    {"aws_key", "openai_key", "github_token", "stripe_key", "google_api_key", "slack_token"}
)


def _prefixed_key_rules():
    policy = load_egress_policy()
    return tuple(
        rule for rule in policy.rules_for("secrets-egress") if rule.label not in _LITERAL_ALLOWED
    )


def test_no_prefixed_key_literal_appears_in_the_secrets_corpus_file():
    raw = corpus_path("secrets-egress", "positive").read_text(encoding="utf-8")
    offenders = [
        (rule.label, match.group(0))
        for rule in _prefixed_key_rules()
        for match in rule.pattern.finditer(raw)
    ]
    assert not offenders, (
        "the secrets corpus file carries vendor-key literals a host secret scanner would "
        f"flag: {offenders[:3]}. Store them assembled (content_template + token_parts) so the "
        "file never contains a contiguous credential-shaped string (ADR 0010)."
    )


def test_the_witness_is_not_vacuous_it_sees_the_rules_it_scans_with():
    # A witness that scanned with zero rules would pass over anything. Name the
    # floor: every vendor-key prefix except PEM and JWT is actually being looked for.
    labels = {rule.label for rule in _prefixed_key_rules()}
    assert labels == {
        "secret:aws-access-key-id",
        "secret:openai-key",
        "secret:github-token",
        "secret:stripe-key",
        "secret:google-api-key",
        "secret:slack-token",
    }


def test_every_assembled_case_reconstructs_a_value_the_detector_can_locate():
    # The other half: assembly must not have hollowed the corpus. Each assembled
    # vendor-key case still yields a content that carries its located token at a
    # real offset — the value the file no longer stores literally.
    assembled = [c for c in load_positive("secrets-egress") if c.category in _ASSEMBLED_CATEGORIES]
    assert assembled, "expected assembled vendor-key cases in the secrets corpus"
    for case in assembled:
        assert case.locate in case.content
        assert case.content[case.offset : case.offset + len(case.locate)] == case.locate
