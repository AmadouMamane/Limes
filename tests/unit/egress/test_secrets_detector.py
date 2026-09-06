"""The secrets-egress detector: prefixes, PEM blocks, JWTs — and what it refuses.

The corpus-wide numbers live in the admission harness. This file pins the
behaviours a matrix cannot express, and the two the whole design turns on: a PEM
finding spans the **block**, not the armour line, and a JWT is decided by its
**header**, not by its shape.
"""

from __future__ import annotations

import pytest

from limes.detector import Context, DetectorBlind, Direction
from limes.detectors.secrets_egress import SecretsEgressDetector
from limes.guard import decide
from limes.record import Ledger
from limes.transports.in_process import Guard
from limes.transports.redaction import Action, EgressPolicy, OnEgressFinding
from limes.verdict import Allow, CannotSay, Deny

CTX = Context(policy_hash="test", actor=None)

PEM_BLOCK = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "RVhBTVBMRSBPTkxZIC0gbm90IGEga2V5IC0gc3ludGhldGlj\n"
    "-----END RSA PRIVATE KEY-----"
)
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)


@pytest.fixture(name="detector")
def _detector():
    return SecretsEgressDetector()


def _located(detector, text):
    return {
        (finding.label, text[span.start : span.end])
        for finding in detector.inspect(Direction.OUTBOUND, text, CTX)
        for span in finding.spans
    }


# --- the DoD pair: a prefixed key is found, its lookalikes are not -----------


def test_a_documented_aws_key_id_is_located_exactly(detector):
    text = "Deployment used AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE today."
    assert ("secret:aws-access-key-id", "AKIAIOSFODNN7EXAMPLE") in _located(detector, text)


def test_the_a3t_prefix_family_is_an_aws_key_id_too(detector):
    # ADR 0030 Am. 1: the head-to-head drew `A3TR…` from gitleaks' catalogue and
    # the rule, which listed only AWS's documented prefixes, missed it. The
    # family is in AWS's own git-secrets pattern; twenty characters, as ever.
    key = "A3TR" + "EXAMPLEONLY22222"  # assembled: no key-shaped literal in the file (ADR 0010)
    assert ("secret:aws-access-key-id", key) in _located(detector, f"Deployment log: {key}.")


def test_a_fine_grained_github_token_is_located_exactly(detector):
    # ADR 0030 Am. 1: `github_pat_` + 82 word characters, the shape GitHub
    # publishes, which the `gh[pousr]_` alternative never covered.
    token = "github_pat_" + "EXAMPLEONLY00000000000" + "_" + "EXAMPLEONLY" * 5 + "0000"
    assert ("secret:github-token", token) in _located(detector, f"Token {token} pasted.")


@pytest.mark.parametrize(
    "text",
    [
        "Request id 123e4567-e89b-12d3-a456-426614174000 traced.",
        "Commit 8cd605c5c0873de5f74f075a2497dbac6b0c24c6 merged.",
        "Payload dGhlIHF1aWNrIGJyb3duIGZveA decoded fine.",
        "The string akiaiosfodnn7example is lowercase prose.",
        "The column MAKIAIOSFODNN7EXAMPLED holds a legacy label.",
        "Accent colour #4A90D9 approved.",
    ],
)
def test_high_entropy_lookalikes_do_not_fire(detector, text):
    # The reason generic entropy scanning is deferred rather than shipped: every
    # one of these is as random-looking as a key and none is a secret.
    assert _located(detector, text) == set()


@pytest.mark.parametrize(
    "text",
    [
        "The form rejected the short key sk-1 as malformed.",
        "Header ghp_tooshort was ignored.",
        "Le préfixe AIzaSy seul ne suffit pas.",
        "The docs show github_pat_REDACTED where the real token goes.",
        "La référence A3TR2026Q3SHIPMENT figure sur le bon de commande.",
    ],
)
def test_a_vendor_prefix_without_a_body_is_not_a_key(detector, text):
    assert _located(detector, text) == set()


# --- PEM: the span is the block, not the armour -----------------------------


def test_a_pem_finding_spans_the_whole_block_not_the_header(detector):
    text = f"Here it is:\n{PEM_BLOCK}\nkeep it safe."
    found = _located(detector, text)
    assert ("secret:private-key-pem", PEM_BLOCK) in found, (
        "a finding that located only the BEGIN line would be masked to exactly that, "
        "and would forward the key material underneath it"
    )


def test_an_unterminated_pem_block_swallows_to_the_end(detector):
    # Masking too much beats forwarding a partial key. A rule that required the
    # END line would silently miss every clipped or streamed result.
    text = "Truncated:\n-----BEGIN EC PRIVATE KEY-----\nUExBQ0VIT0xERVI="
    located = {value for label, value in _located(detector, text) if label.endswith("pem")}
    assert len(located) == 1
    assert located.pop().endswith("UExBQ0VIT0xERVI=")


@pytest.mark.parametrize("armour", ["CERTIFICATE", "PUBLIC KEY"])
def test_public_armour_is_not_a_secret(detector, armour):
    text = f"-----BEGIN {armour}-----\nRVhBTVBMRQ==\n-----END {armour}-----"
    assert _located(detector, text) == set()


# --- JWT: the header decides, not the shape ---------------------------------


def test_a_real_jwt_is_located(detector):
    assert ("secret:jwt", JWT) in _located(detector, f"Authorization: Bearer {JWT}")


@pytest.mark.parametrize(
    "text",
    [
        "Module limes.detectors.egress_policy imported.",
        "Archive backup_2026_07.tar.gz uploaded.",
        "Version 1.2.3 released.",
        "Chunks aGVsbG93b3JsZA.c2Vjb25k.dGhpcmQ were reassembled.",
    ],
)
def test_the_jwt_shape_alone_is_not_a_jwt(detector, text):
    # The shape is worthless here — it is shared with module paths, file names and
    # version strings. The whole claim is that the header decodes to a JSON object
    # declaring `alg`.
    assert _located(detector, text) == set()


# --- deferred, and said so ---------------------------------------------------


def test_a_bare_secret_spelling_is_a_measured_boundary_not_an_oversight(detector):
    # The AWS secret access key is caught by its NAME since ADR 0022 —
    # aws_secret_access_key, SecretAccessKey, secret_key. The single word SECRET
    # is deliberately not in that vocabulary: bare `secret` was measured into the
    # refused generic list (it fires on a Secrets Manager ARN's resource tail,
    # `…:secret:<forty slashed chars>`). This line pins the boundary; moving it
    # means re-running that measurement, not widening a regex.
    assert _located(detector, "SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") == set()


# --- legs, fail-closed, evidence --------------------------------------------


def test_the_inbound_leg_is_not_this_detector_s(detector):
    assert detector.inspect(Direction.INBOUND, "key AKIAIOSFODNN7EXAMPLE", CTX) == []


def test_content_over_the_declared_budget_makes_the_detector_blind(detector):
    with pytest.raises(DetectorBlind, match="max_content_chars"):
        detector.inspect(Direction.OUTBOUND, "a" * 200_001, CTX)


def test_a_blind_detector_becomes_cannot_say_never_allow(detector):
    verdict = decide(
        Direction.OUTBOUND, "a" * 200_001, CTX, (detector,), observed_at="2026-07-24T00:00:00Z"
    )
    assert isinstance(verdict, CannotSay)
    assert Allow not in type(verdict).__mro__
    assert "secrets-egress" in verdict.blind_spot


def test_the_default_egress_policy_blocks_a_secret_rather_than_masking_it(detector):
    # `secret` gets the closed default like every other kind. An operator can
    # declare otherwise per kind; nobody gets it by not thinking about it.
    guard = Guard((detector,), policy_hash="test", ledger=Ledger())
    egress = guard.check_egress(f"The key is {JWT}", actor=None, observed_at="2026-07-24T00:00:00Z")
    assert egress.action is Action.BLOCK
    assert egress.content is None
    assert isinstance(egress.verdict, Deny)


def test_a_secret_can_be_masked_when_an_operator_asks_for_it(detector):
    guard = Guard(
        (detector,),
        policy_hash="test",
        ledger=Ledger(),
        egress=EgressPolicy(
            default=OnEgressFinding.BLOCK, by_kind={"secret": OnEgressFinding.REDACT}
        ),
    )
    egress = guard.check_egress(
        "Deploy key AKIAIOSFODNN7EXAMPLE rotated.",
        actor=None,
        observed_at="2026-07-24T00:00:00Z",
    )
    assert egress.action is Action.REDACT
    assert egress.content == "Deploy key [REDACTED:secret] rotated."


def test_the_span_carries_a_hash_and_never_the_value(detector):
    text = "key AKIAIOSFODNN7EXAMPLE here"
    span = detector.inspect(Direction.OUTBOUND, text, CTX)[0].spans[0]
    assert "AKIA" not in span.matched_sha
    assert len(span.matched_sha) == 64
