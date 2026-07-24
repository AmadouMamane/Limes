"""Checksums — the precision half of an egress detector (ADR 0003/0004).

A shape alone does not identify a card number. Sixteen digits are also an order
reference, a contract number, a padded internal id; a regex that fires on all of
them is not a detector, it is a nuisance that trains its operator to switch it
off. What separates the datum from its lookalike is arithmetic the issuer put
there on purpose:

* :func:`luhn_valid` — ISO/IEC 7812, the card-number check digit. It kills ~90 %
  of coincidental digit runs.
* :func:`iban_mod97_valid` — ISO 13616 / ISO 7064 MOD 97-10. An IBAN-shaped
  internal identifier fails it.
* :func:`nir_key_valid` — the French NIR's two-digit control key,
  ``97 - (body mod 97)``, with the Corsican ``2A``/``2B`` department substitution.

These are pure functions over a digit string, and they are what the egress policy
names in each rule's ``validator`` field: the *shape* is data an auditor reads in
YAML, and the *arithmetic* is code, named from that YAML rather than hidden in
it. A rule declaring ``validator: none`` is saying, explicitly, that its shape is
the whole claim.

They are deliberately not a module of the core: a detector may not touch the core
(ADR 0004), and this is detector machinery.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Final

__all__ = [
    "compact",
    "iban_mod97_valid",
    "jwt_header_valid",
    "luhn_valid",
    "nir_key_valid",
]

#: A doubled digit above nine folds back to a single digit (16 -> 1 + 6 = 7).
_LUHN_FOLD: Final = 9

#: ISO 7064 MOD 97-10 leaves 1 for a well-formed IBAN.
_MOD97_REMAINDER: Final = 1

#: 'A' -> 10 … 'Z' -> 35 in the IBAN alphanumeric expansion.
_LETTER_OFFSET: Final = 55

_IBAN_MIN_LENGTH: Final = 5
_IBAN_MAX_LENGTH: Final = 34
_IBAN_ROTATE: Final = 4

_NIR_LENGTH: Final = 15
_NIR_BODY: Final = 13
#: Corsica has no numeric department code; the NIR key is computed with these.
_CORSICA: Final = {"2A": "19", "2B": "18"}

_JWT_SEGMENTS: Final = 3

#: Grouping characters a human writes into a card number, IBAN or NIR. The
#: no-break space is listed explicitly: it is what a word processor and most
#: banking UIs actually emit, and a checksum that silently failed on it would
#: read as "not sensitive" for exactly the copy-pasted values that matter.
_SEPARATORS: Final = re.compile("[ \\xa0\\u202f.\\u2011-]")


def compact(candidate: str) -> str:
    """Strip the grouping separators a human writes, and upper-case the rest.

    Public because it is part of a detector's declared tolerance: a value written
    with a no-break space is the same value, and a caller composing its own check
    (``luhn_valid(compact(text))``) must strip exactly what these checksums strip.

    Args:
        candidate: The matched text, as it appears in the inspected content.

    Returns:
        The candidate without spaces, no-break spaces, narrow no-break spaces,
        dots or hyphens, upper-cased.
    """
    return _SEPARATORS.sub("", candidate).upper()


def luhn_valid(digits: str) -> bool:
    """Whether ``digits`` satisfies the ISO/IEC 7812 Luhn checksum.

    Args:
        digits: A digit-only string (separators must already be stripped).

    Returns:
        ``True`` when the check digit is consistent. An empty or non-digit
        string is ``False`` — a checksum cannot vouch for something it cannot
        read, and here the honest answer is simply "not a card number".
    """
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > _LUHN_FOLD:
                digit -= _LUHN_FOLD
        total += digit
    return total % 10 == 0


def iban_mod97_valid(candidate: str) -> bool:
    """Whether ``candidate`` satisfies the ISO 13616 MOD 97-10 check.

    The country code and check digits are rotated to the back, letters are
    expanded to two-digit numbers (``A`` = 10), and the result must be ``1``
    modulo 97.

    Args:
        candidate: An IBAN with or without spaces, any case.

    Returns:
        ``True`` when the checksum holds and the shape is plausible.
    """
    normalised = compact(candidate)
    if not (_IBAN_MIN_LENGTH <= len(normalised) <= _IBAN_MAX_LENGTH):
        return False
    if not normalised[:2].isalpha() or not normalised[2:4].isdigit():
        return False
    if not normalised.isalnum():
        return False
    rotated = normalised[_IBAN_ROTATE:] + normalised[:_IBAN_ROTATE]
    expanded = "".join(
        str(ord(char) - _LETTER_OFFSET) if char.isalpha() else char for char in rotated
    )
    if not expanded.isdigit():
        return False
    return int(expanded) % 97 == _MOD97_REMAINDER


def nir_key_valid(candidate: str) -> bool:
    """Whether a French NIR's two-digit control key matches its body.

    The key is ``97 - (body mod 97)`` over the first thirteen characters, with
    the Corsican department codes ``2A`` and ``2B`` replaced by ``19`` and ``18``
    before the arithmetic.

    Args:
        candidate: A NIR with or without spaces.

    Returns:
        ``True`` when the key is the one the body implies.
    """
    normalised = compact(candidate)
    if len(normalised) != _NIR_LENGTH:
        return False
    body, key = normalised[:_NIR_BODY], normalised[_NIR_BODY:]
    if not key.isdigit():
        return False
    for corsican, numeric in _CORSICA.items():
        body = body.replace(corsican, numeric)
    if not body.isdigit():
        return False
    return 97 - (int(body) % 97) == int(key)


def _b64url_decode(segment: str) -> bytes:
    """Decode one base64url segment, padding it as JWT omits the padding."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def jwt_header_valid(candidate: str) -> bool:
    """Whether ``candidate`` is a JWT rather than three dot-separated words.

    The shape — three base64url segments — is shared by file names, version
    strings and package coordinates. What is *not* shared is that the first
    segment decodes to a JSON object declaring an algorithm. That is the check,
    and it is what keeps ``a.b.c`` and ``lib.tar.gz`` out of the findings.

    Args:
        candidate: The dotted candidate.

    Returns:
        ``True`` when the header segment decodes to a JSON object with ``alg``.
    """
    segments = candidate.split(".")
    if len(segments) != _JWT_SEGMENTS or not all(segments[:2]):
        return False
    try:
        header = json.loads(_b64url_decode(segments[0]))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return isinstance(header, dict) and isinstance(header.get("alg"), str)
