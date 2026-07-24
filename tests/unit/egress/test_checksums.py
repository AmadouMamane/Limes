"""The arithmetic that separates a datum from its lookalike.

Every vector here is synthetic (ADR 0009): published test card numbers,
documentation IBANs, and NIR keys recomputed over fictional identities.
"""

from __future__ import annotations

import pytest

from limes.detectors.checksums import (
    compact,
    iban_mod97_valid,
    jwt_header_valid,
    luhn_valid,
    nir_key_valid,
)

# Published test card numbers — Luhn-valid by construction, never issued.
VALID_PANS = [
    "4242424242424242",
    "4111111111111111",
    "5555555555554444",
    "378282246310005",
    "6011111111111117",
    "5105105105105100",
]

# The lookalikes the whole checksum exists for.
INVALID_PANS = [
    "1234567890123456",
    "9999888877776666",
    "8001234512345678",
    "4242424242424241",
]

VALID_IBANS = [
    "FR14 2004 1010 0505 0001 3M02 606",
    "DE89 3704 0044 0532 0130 00",
    "GB29 NWBK 6016 1331 9268 19",
    "BE68539007547034",
    "NL91 ABNA 0417 1643 00",
    "AT61 1904 3002 3457 3201",
    "ES91 2100 0418 4502 0005 1332",
    "CH93 0076 2011 6238 5295 7",
    "IT60 X054 2811 1010 0000 0123 456",
]

INVALID_IBANS = [
    "FR76 3000 6000 0112 3456 7890 188",
    "DE00 1234 5678 9012 3456 78",
    "XX99 0000 1111 2222 3333 44",
    "DE89 3704 0044 0532 0130 01",
    "GB29 NWBK 6016 1331 9268 18",
]

VALID_NIRS = [
    "1 85 05 78 006 084 91",
    "2 89 07 92 044 021 71",
    "190013312345625",
    "1 75 12 2A 123 456 53",
    "2 66 12 75 116 042 41",
]

INVALID_NIRS = [
    "1 85 05 78 006 084 99",
    "2 66 12 75 116 042 40",
    "190013312345600",
]


@pytest.mark.parametrize("digits", VALID_PANS)
def test_published_test_cards_pass_luhn(digits):
    assert luhn_valid(digits)


@pytest.mark.parametrize("digits", INVALID_PANS)
def test_card_shaped_references_fail_luhn(digits):
    assert not luhn_valid(digits)


def test_luhn_refuses_what_it_cannot_read():
    # Not "safe by default": a checksum over non-digits vouches for nothing, and
    # the honest answer is that this is not a card number.
    assert not luhn_valid("")
    assert not luhn_valid("4242-4242")
    assert not luhn_valid("abcd")


@pytest.mark.parametrize("iban", VALID_IBANS)
def test_documentation_ibans_pass_mod97(iban):
    assert iban_mod97_valid(iban)


@pytest.mark.parametrize("iban", INVALID_IBANS)
def test_iban_shaped_identifiers_fail_mod97(iban):
    assert not iban_mod97_valid(iban)


def test_iban_is_case_and_separator_insensitive():
    assert iban_mod97_valid("de89 3704 0044 0532 0130 00")
    assert iban_mod97_valid("DE89370400440532013000")
    assert iban_mod97_valid("DE89-3704-0044-0532-0130-00")


def test_iban_refuses_a_shape_it_cannot_rotate():
    assert not iban_mod97_valid("")
    assert not iban_mod97_valid("DE8")
    assert not iban_mod97_valid("1234 5678 9012")  # no country code
    assert not iban_mod97_valid("DEXX 3704 0044")  # no check digits


@pytest.mark.parametrize("nir", VALID_NIRS)
def test_recomputed_nir_keys_check_out(nir):
    assert nir_key_valid(nir)


@pytest.mark.parametrize("nir", INVALID_NIRS)
def test_nir_with_a_wrong_key_is_refused(nir):
    assert not nir_key_valid(nir)


def test_corsica_is_not_a_blind_spot():
    # 2A / 2B are the only non-numeric department codes. A key computed without
    # substituting them refuses every Corsican NIR — a whole département
    # silently unprotected.
    assert nir_key_valid("1 75 12 2A 123 456 53")
    assert not nir_key_valid("1 75 12 2A 123 456 52")


def test_nir_refuses_a_wrong_length():
    assert not nir_key_valid("1 85 05 78 006 084")
    assert not nir_key_valid("1 85 05 78 006 084 911")


def test_jwt_header_must_decode_to_a_signed_object():
    # The classic self-signed test token from the JWT documentation.
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    assert jwt_header_valid(token)


@pytest.mark.parametrize(
    "candidate",
    [
        "a.b.c",
        "lib.tar.gz",
        "1.2.3",
        "eyJhbGciOiJIUzI1NiJ9.only.two_segments.too_many",
        "..",
        "eyJzdWIiOiIxIn0.eyJhIjoxfQ.sig",  # decodes, but the header has no `alg`
    ],
)
def test_dotted_words_are_not_jwts(candidate):
    assert not jwt_header_valid(candidate)


def test_compact_strips_exactly_what_a_human_types():
    assert compact("4242 4242 4242 4242") == "4242424242424242"
    assert compact("4242\xa04242-4242.4242") == "4242424242424242"
    assert compact("de89 3704") == "DE893704"
