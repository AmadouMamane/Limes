"""The context-anchored AWS secret rule (ADR 0022): what it catches, what it
refuses, and the two refusals that must stay pinned.

The value is forty base64 characters with no vendor prefix, so the body alone is
indistinguishable from a git SHA-1, a content digest or a cache key. The split
verdict ADR 0022 records:

* **keyword + assignment grammar** — lands. The shape is gitleaks' own
  semi-generic machinery with AWS's own vocabulary as keywords; measured at
  12/12 assignment carriers located, 0/20 hard lookalikes, 0/339 gitleaks
  negatives, 0/51 internal benigns.
* **bare body, no keyword** — out of scope by measurement: the same body with
  no keyword kills 17/20 hard lookalikes, 15/339 gitleaks negatives and 3 of
  limes' own benigns, and the only remaining discriminant would be an entropy
  threshold, which ADR 0009 makes unusable (limes' own positives are
  placeholders by law). git-secrets ships that rule anyway — all its context
  groups optional — and prices it at 64/339.

Every mutant below is a rule that was measured and REFUSED; a later change that
makes one of these assertions fail must bring the measurement that licenses it.
"""

from __future__ import annotations

import re

import pytest

from limes.detector import Context, Direction
from limes.detectors.egress_policy import VALIDATORS, load_egress_policy
from limes.detectors.secrets_egress import SecretsEgressDetector

_CONTEXT = Context(policy_hash="aws-secret-context", actor=None)
_LABEL = "secret:aws-secret-access-key"

#: AWS's two published documentation secrets (git-secrets ships the first in its
#: own allowlist). Assembled here as in the corpus (ADR 0010): the file never
#: carries a contiguous credential-shaped literal.
V1 = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
V2 = "je7MtGbClwBF/" + "2Zp9Utk/h3yCo8nvbEXAMPLEKEY"


def _rule():
    for rule in load_egress_policy().rules_for("secrets-egress"):
        if rule.label == _LABEL:
            return rule
    raise AssertionError(f"{_LABEL} is not in the shipped policy")


def _findings(content: str):
    detector = SecretsEgressDetector()
    return [
        (finding.label, content[span.start : span.end], span.start)
        for finding in detector.inspect(Direction.OUTBOUND, content, _CONTEXT)
        for span in finding.spans
        if finding.label == _LABEL
    ]


# --------------------------------------------------------------------------
# 1. the assignment carriers are located, and the span is the VALUE
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "secret"),
    [
        (f"AWS_SECRET_ACCESS_KEY={V1}", V1),
        (f"AWS_SECRET_ACCESS_KEY:{V1}", V1),
        (f'aws_secret_access_key = "{V2}"', V2),
        (f"aws_secret_access_key => '{V2}'", V2),
        (f"SECRET_ACCESS_KEY={V1}", V1),
        (f"set AWS_SECRET_ACCESS_KEY={V1}", V1),
        (f'{{"secretAccessKey":"{V2}"}}', V2),
        (f'"SecretAccessKey": "{V2}"', V2),
        (f"The AWS secret access key: {V1} was pasted into the ticket.", V1),
        (f"secret access key\xa0: {V2}", V2),
        (f"MINIO_SECRET_KEY={V1}", V1),
        (f'secret_key = "{V2}"', V2),
    ],
    ids=[
        "env-bare",
        "yaml-compact",
        "toml-quoted",
        "ruby-hashrocket",
        "bare-secret-access-key",
        "windows-set",
        "json-camel-compact",
        "sts-camel-field",
        "prose-colon",
        "fr-nbsp-colon",
        "minio-env",
        "terraform-bare-secret-key",
    ],
)
def test_an_assigned_aws_secret_is_located_exactly(content, secret):
    at = content.index(secret)
    assert (_LABEL, secret, at) in _findings(content)


def test_the_span_is_the_credential_never_the_carrier_line():
    # `value_group` is what buys this: the keyword and operator are how the
    # value was recognised, not part of it. A span covering the carrier would be
    # masked to the whole line and graded as a miss by the exact-span rule.
    content = f"[default]\naws_secret_access_key = {V1}\nregion = eu-west-1\n"
    assert _findings(content) == [(_LABEL, V1, content.index(V1))]


def test_two_secrets_on_one_line_are_two_findings():
    content = f"aws_secret_access_key = {V1} aws_secret_access_key = {V2}"
    assert [value for (_, value, _) in _findings(content)] == [V1, V2]


# --------------------------------------------------------------------------
# 2. the hard lookalikes stay silent — bodies of the right length, wrong role
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "aws_secret_access_key_hash = 2b7e151628aed2a6abf7158809cf4f3c762e7160",
        "secret_key_rotation_log: 9d5e1f4c8a7b6e5d4c3b2a1908f7e6d5c4b3a2c1 appended.",
        "secret_id = arn:aws:secretsmanager:eu-west-1:210987654321:secret:"
        "prodDatabaseCredentialBundle/version26R7",
        "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}",
        "aws_secret_access_key = <YOUR_SECRET_ACCESS_KEY>",
        "cache_key = c3ludGhldGljIGNhY2hlIGVudHJ5IHZhbHVlIDR6",
        "password_sha1 = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        "Der Token wurde widerrufen, Commit 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b ist deployt.",
        "Le secret a été déplacé ; voir le commit 0f1e2d3c4b5a69788796a5b4c3d2e1f001122334.",
        "Rotated aws_secret_access_key; archive saved as dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy",
        "aws_secret_access_key_sha256 = "
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        f"AWS_SECRET_ACCESS_KEY={V1[:39]}",
        f"AWS_SECRET_ACCESS_KEY={V1}A",
        'secret_keys = ["kid1", "kid2"]',
        "secret_key = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc",
    ],
    ids=[
        "hex-fingerprint-of-the-key",
        "rotation-log-sha",
        "secretsmanager-arn-tail",
        "variable-reference",
        "angle-placeholder",
        "cache-key-base64",
        "password-sha1",
        "de-comma-operator-then-sha",
        "fr-prose-secret-then-sha",
        "post-rotation-prose-b64",
        "sha256-is-64-chars",
        "39-char-body",
        "41-char-body",
        "secret-keys-list",
        "jwt-behind-secret-key",
    ],
)
def test_a_lookalike_of_the_right_length_and_wrong_role_stays_silent(content):
    assert not _findings(content)


# --------------------------------------------------------------------------
# 3. THE MUTATION — not_pure_hex is load-bearing, not decoration
# --------------------------------------------------------------------------

_FINGERPRINT = "aws_secret_access_key_hash = 2b7e151628aed2a6abf7158809cf4f3c762e7160"


def test_the_shape_still_matches_the_fingerprint_only_the_validator_refuses():
    # THE MUTATION: `validator: not_pure_hex` reverted to `validator: none`.
    rule = _rule()
    match = rule.pattern.search(_FINGERPRINT)
    assert match is not None, "the shape no longer matches — the gate test is dead"
    body = match.group(rule.value_group)
    assert VALIDATORS["none"](body) is True
    assert VALIDATORS["not_pure_hex"](body) is False


def test_the_hex_gate_still_passes_a_real_shaped_secret():
    # The mirror, so the gate cannot be satisfied by refusing everything: both
    # published documentation secrets pass, and so does a body that is hex but
    # for one character — the gate refuses only the UNBROKEN hex run.
    assert VALIDATORS["not_pure_hex"](V1) is True
    assert VALIDATORS["not_pure_hex"](V2) is True
    assert VALIDATORS["not_pure_hex"]("2b7e151628aed2a6abf7158809cf4f3c762e716g") is True
    assert VALIDATORS["not_pure_hex"]("2B7E151628AED2A6ABF7158809CF4F3C762E7160") is False


# --------------------------------------------------------------------------
# 4. the REFUSED generic keyword list, pinned with its price
# --------------------------------------------------------------------------

#: The mutant: the same assignment grammar with gitleaks' generic keyword list
#: (access|api|key|token|…) instead of AWS's own vocabulary. Measured price:
#: 11/20 hard lookalikes killed and 3 of gitleaks' own negatives (ADR 0022).
_BROAD_MUTANT = re.compile(
    r"(?i)[\w.-]{0,50}?(?:access|auth|api|credential|creds|key|passwd?|password|secret|token)"
    r"(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}"
    r"(?P<secret>[A-Za-z0-9/+]{40})(?:[\x60'\"\s;]|\\[nr]|$)"
)


@pytest.mark.parametrize(
    "lookalike",
    [
        "cache_key = c3ludGhldGljIGNhY2hlIGVudHJ5IHZhbHVlIDR6",
        "password_sha1 = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        "secret_id = arn:aws:secretsmanager:eu-west-1:210987654321:secret:"
        "prodDatabaseCredentialBundle/version26R7",
        "upload id token: 3M9zX0aL7bQ4cR8dT2eV6fW1gY5hJ9kN3mP7qS1u",
    ],
)
def test_the_generic_keyword_mutant_fires_on_what_the_shipped_rule_refuses(lookalike):
    assert _BROAD_MUTANT.search(lookalike) is not None
    assert not _findings(lookalike)


# --------------------------------------------------------------------------
# 5. the BODYLESS case is out of scope by measurement, and the pin says why
# --------------------------------------------------------------------------


def test_a_bare_forty_char_body_with_no_keyword_is_deliberately_not_detected():
    """The 4b half of ADR 0022's split verdict, pinned.

    A bare-body rule was measured, not assumed away: it kills 17/20 of the hard
    benign corpus (git SHAs, ETags, cache keys), 15/339 of gitleaks' own
    negatives and 3 of limes' internal benigns — and the only content property
    left to separate those would be an entropy threshold, which ADR 0009 makes
    unusable: limes' own positives are placeholder-bodied by law, and
    `AKIAIOSFODNN7EXAMPLE` is a limes positive and a gitleaks negative at once.
    git-secrets ships the bare rule anyway (every context group in its pattern
    is optional) and prices it at 64/339.

    Deleting this test means shipping that rule; bring the measurement.
    """
    content = f"Deployment artefact {V1} uploaded to the registry."
    assert not _findings(content)
    # The keyword is what refuses it — the bare-body mutant does fire here.
    bare = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])")
    assert bare.search(content) is not None


# --------------------------------------------------------------------------
# 6. declared misses — measured, left, and visible
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        f"ENV AWS_SECRET_ACCESS_KEY {V2}",
        f"$ aws configure set aws_secret_access_key {V1}",
        f'os.environ["AWS_SECRET_ACCESS_KEY"] = "{V2}"',
    ],
    ids=["dockerfile-env-space", "aws-configure-set", "python-environ-bracket"],
)
def test_a_carrier_with_no_assignment_operator_in_reach_is_a_declared_miss(content):
    # The vendor grammar requires an operator, and its classes cannot cross a
    # closing bracket. These carriers are real and are MISSED today — declared
    # in the policy comment and in ADR 0022, not discovered by a user. Lifting
    # any of them is welcome; it arrives with a measurement, and deletes its
    # line here.
    assert not _findings(content)
