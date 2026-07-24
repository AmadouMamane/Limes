"""ADR 0009's enforcer: an egress corpus is synthetic, and says so, in every file.

The rule is worth nothing as prose. What a contributor actually does is copy a
value out of a ticket to reproduce a bug, and that value is a real card number in
a public repository for ever. So the constraint is checked, per file and per
case: the declared provenance, the reserved domains, the published test vectors,
and the absence of anything that reads like a live credential.
"""

from __future__ import annotations

import json
import re

import pytest

from limes.detectors.checksums import compact, luhn_valid
from limes.eval.egress_corpus import SYNTHETIC, corpus_path, load_benign, load_positive

DETECTORS = ["pii-egress", "secrets-egress"]
KINDS = ["positive", "benign"]

#: Card numbers a positive case may carry: the vectors payment processors publish
#: for testing. Any other Luhn-valid PAN in the corpus is refused — it had to come
#: from somewhere, and there is no legitimate somewhere.
PUBLISHED_TEST_PANS = frozenset(
    {
        "4242424242424242",
        "4111111111111111",
        "5555555555554444",
        "5105105105105100",
        "378282246310005",
        "6011111111111117",
        "4000056655665556",
        "3056930009020004",
    }
)

#: RFC 2606 / RFC 6761 reserved names, which can never resolve to a real mailbox.
RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.co.uk", "example.")

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

#: Anything carrying a vendor's credential prefix. Whatever follows it in this
#: repository must be visibly placeholder text — see the test below.
_VENDOR_PREFIXED = re.compile(
    r"(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[0-9A-Z]{16}"
    r"|sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}"
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{24,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|xox[baprse]-[A-Za-z0-9-]{10,}"
)

#: The one credential-shaped string in the corpus that does not say EXAMPLE in
#: its body: AWS publishes it verbatim in its own documentation.
AWS_DOCUMENTATION_KEY = "AKIAIOSFODNN7EXAMPLE"

#: A line that is plausibly PEM key material rather than the prose around it.
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_DIGIT_RUN = re.compile(r"(?:\d[ \xa0-]?){12,18}\d")


def _every_case_content(detector):
    for case in load_positive(detector):
        yield case.case_id, case.content
    for benign in load_benign(detector):
        yield benign.case_id, benign.content


@pytest.mark.parametrize("detector", DETECTORS)
@pytest.mark.parametrize("kind", KINDS)
def test_every_corpus_file_declares_synthetic_provenance(detector, kind):
    raw = json.loads(corpus_path(detector, kind).read_text(encoding="utf-8"))
    assert raw["provenance"] == SYNTHETIC


@pytest.mark.parametrize("detector", DETECTORS)
def test_the_loader_refuses_a_file_that_declares_anything_else(detector, tmp_path):
    # Asked of the LOADER, not re-implemented here: a rule whose only enforcer is
    # a test that restates it is not enforced — the harness would happily read a
    # corpus nobody checked (ADR 0026).
    source = corpus_path(detector, "positive")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["provenance"] = "collected-from-production"
    (tmp_path / source.name).write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="provenance"):
        load_positive(detector, root=tmp_path)


@pytest.mark.parametrize("detector", DETECTORS)
def test_the_loader_accepts_the_same_file_once_provenance_is_restored(detector, tmp_path):
    # The other half of the mutation: without it, a loader that raised on
    # *everything* would pass the test above and protect nothing.
    source = corpus_path(detector, "positive")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["provenance"] = SYNTHETIC
    (tmp_path / source.name).write_text(json.dumps(raw), encoding="utf-8")
    assert len(load_positive(detector, root=tmp_path)) == len(load_positive(detector))


@pytest.mark.parametrize("detector", DETECTORS)
def test_every_luhn_valid_card_number_is_a_published_test_vector(detector):
    for case_id, content in _every_case_content(detector):
        # A placeholder key body is a long run of zeros, and a run of zeros passes
        # Luhn. Those are credential FORMATS, checked by their own rule below;
        # this one is about card numbers, so it does not look inside them.
        credentials = [match.span() for match in _VENDOR_PREFIXED.finditer(content)]
        for match in _DIGIT_RUN.finditer(content):
            start, end = match.span()
            if any(begin <= start and end <= stop for begin, stop in credentials):
                continue
            digits = compact(match.group(0))
            if luhn_valid(digits):
                assert digits in PUBLISHED_TEST_PANS, (
                    f"{case_id} carries the Luhn-valid number {digits!r}, which is not one of "
                    f"the published test vectors. A card number that passes Luhn and is not a "
                    f"documented test value has no legitimate way into this repository "
                    f"(ADR 0009)."
                )


@pytest.mark.parametrize("detector", DETECTORS)
def test_every_email_address_is_on_a_reserved_domain(detector):
    for case_id, content in _every_case_content(detector):
        for match in _EMAIL.finditer(content):
            address = match.group(0).rstrip(".")
            assert address.endswith(RESERVED_DOMAINS), (
                f"{case_id} carries {address!r}, which is not on an RFC 2606 reserved domain "
                f"and could therefore be a real mailbox (ADR 0009)."
            )


@pytest.mark.parametrize("detector", DETECTORS)
def test_every_case_says_why_it_is_in_the_corpus(detector):
    # The field that makes a corpus reviewable. A vector with no stated origin is
    # a vector nobody can confirm is synthetic.
    for case in load_positive(detector):
        assert case.why.strip()
    for benign in load_benign(detector):
        assert benign.why.strip()


@pytest.mark.parametrize("detector", DETECTORS)
def test_case_ids_are_unique_within_a_file(detector):
    for cases in (load_positive(detector), load_benign(detector)):
        ids = [case.case_id for case in cases]
        assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("detector", DETECTORS)
def test_every_credential_shaped_string_is_visibly_a_placeholder(detector):
    # The secrets analogue of the published-test-PAN rule. A contributor
    # reproducing a bug will paste the value that caused it; this is what stops
    # that value being a live key in a public repository for ever (ADR 0009).
    for case_id, content in _every_case_content(detector):
        for match in _VENDOR_PREFIXED.finditer(content):
            found = match.group(0)
            assert "EXAMPLE" in found.upper() or found == AWS_DOCUMENTATION_KEY, (
                f"{case_id} carries the credential-shaped string {found!r}, whose body does "
                f"not say EXAMPLE. Every key in this corpus is a FORMAT with placeholder "
                f"content; a body that looks real has no legitimate way in (ADR 0009)."
            )


@pytest.mark.parametrize("detector", DETECTORS)
def test_no_pem_block_carries_decodable_key_material(detector):
    # A PEM body that is not obviously placeholder text is a key somebody may
    # have pasted. The corpus bodies base64-decode to English sentences.
    import base64
    import binascii

    for case_id, content in _every_case_content(detector):
        if "PRIVATE KEY-----" not in content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if not _BASE64_LINE.fullmatch(stripped):
                continue
            try:
                decoded = base64.b64decode(stripped, validate=True).decode("ascii")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                decoded = ""
            assert "EXAMPLE" in decoded.upper() or "PLACEHOLDER" in decoded.upper(), (
                f"{case_id} carries a PEM body that does not decode to placeholder text: "
                f"{stripped[:24]!r}… (ADR 0009)"
            )
