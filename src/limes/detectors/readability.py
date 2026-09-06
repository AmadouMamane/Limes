"""What a rule-based detector cannot read, said out loud (ADR 0028).

The rules read text: runs of letters and digits, shaped the way the policy's
patterns expect, in the languages the patterns were written for. Three kinds of
content defeat every rule without matching anything, and until ADR 0028 each of
them passed as "nothing found":

* **Opaque runs.** Base64, hex, a data URL, a serialised blob — long runs of the
  encoding alphabet with no words in them. A tool that returns a file's bytes as
  base64 returns something the host's model may decode and read, and that no
  pattern here can. The screen measures how much of the content is such runs and
  declares the content unreadable when most of it is.
* **Wedged invisibles.** A zero-width space inside ``ig<U+200B>nore`` splits the
  word every override rule looks for, and a zero-width joiner inside a card
  number splits the digits the Luhn rule counts. Format characters between two
  alphanumerics — where at least one side is ASCII, so an emoji sequence or a
  Persian word keeps its joiners — have no legitimate use, and the screen
  declares the content unreadable on the first one. The soft hyphen is the
  exception, deliberately: extracted web text carries hyphenation hints inside
  ordinary words, so it is read as text, and a directive split with one is a
  documented miss rather than a false blind spot on every scraped page.
* **Another script, or a declared language the rules do not cover.** The
  injection rules are written for Latin-script French, German and English. When
  most letters are in another script the rules were not written for it, and
  when the caller *declares* a locale the policy does not list, the detector
  says so instead of answering "clean" about text it cannot read. Shape-bound
  detectors (a card number, a key) are not script-bound and skip this part.
  The script measure rests on one premise — that the rules read Latin script —
  and it **stands down when the policy says otherwise** (ADR 0028 Amendment 1):
  a policy declaring a language outside :data:`LATIN_SCRIPT_LANGUAGES` has rules
  written for another script, and counting its own text as foreign would make
  the guard unusable for exactly the deployment that declared itself honestly.
  The declared-locale check stays: it compares the caller's claim to the
  policy's, and needs no premise about scripts.

Every measure is a single linear pass. The screen runs **after** the rules, so a
finding still dominates: a key inside a base64 dump is a key found, and a
directive in an English sentence under Cyrillic prose is a directive found.
Each blind spot names its family (ADR 0029) — ``opaque``, ``invisible``,
``script``, ``locale`` — so an operator opens the one they accept and no other.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from limes.detector import DetectorBlind
from limes.verdict import BlindKind

__all__ = [
    "LATIN_SCRIPT_LANGUAGES",
    "OPAQUE_MIN_CHARS",
    "OPAQUE_RUN",
    "OPAQUE_SHARE",
    "SCRIPT_MIN_LETTERS",
    "SCRIPT_SHARE",
    "foreign_letters",
    "language_of",
    "opaque_chars",
    "refuse_unreadable_text",
    "unreadable",
    "wedged_invisibles",
]

#: A run of the base64 / base64url / hex alphabet long enough that it is data,
#: not a word: a git SHA-1 is 40 characters, a sha256 is 64, a UUID is 36.
OPAQUE_RUN: Final = re.compile(r"[A-Za-z0-9+/=_-]{100,}")
#: Below this size nothing is declared opaque: a short token inside a sentence
#: is a token, and the sentence around it is what the rules read.
OPAQUE_MIN_CHARS: Final = 200
#: The share of the content that must sit inside opaque runs before the content
#: as a whole is declared unreadable.
OPAQUE_SHARE: Final = 0.5
#: Below this many letters no script is inferred: a short reply is not a corpus.
SCRIPT_MIN_LETTERS: Final = 40
#: The share of letters outside the Latin script that makes the text one the
#: word-reading rules were not written for.
SCRIPT_SHARE: Final = 0.5
#: Languages whose standard orthography is the Latin script — the premise of the
#: script measure. A policy whose every declared language is here has rules
#: written for Latin text, and "mostly another script" means what it says; a
#: policy declaring any language outside this set has rules written for another
#: script, and the measure stands down (ADR 0028 Amendment 1). The set is not a
#: census: a Latin-script language it lacks can only make the measure stand
#: down, never fire, so an omission costs a check and never a false blind spot.
LATIN_SCRIPT_LANGUAGES: Final = frozenset(
    {
        "af", "an", "ast", "az", "br", "bs", "ca", "co", "cs", "cy", "da", "de", "en", "eo",
        "es", "et", "eu", "fi", "fj", "fo", "fr", "fy", "ga", "gd", "gl", "gn", "ha", "haw",
        "hr", "ht", "hu", "id", "ig", "is", "it", "jv", "kw", "la", "lb", "lt", "lv", "mg",
        "mi", "ms", "mt", "nb", "nl", "nn", "no", "oc", "pl", "pt", "qu", "rm", "ro", "rw",
        "sc", "sk", "sl", "sm", "sn", "so", "sq", "st", "su", "sv", "sw", "tk", "tl", "tn",
        "to", "tr", "ts", "uz", "vi", "wa", "wo", "xh", "yo", "zu",
    }
)  # fmt: skip

_SOFT_HYPHEN: Final = "\u00ad"


def opaque_chars(content: str) -> int:
    """Count the characters of ``content`` that sit inside opaque encoded runs.

    A run counts only if it carries both a digit and a letter: a run of letters
    alone is a long word, a DNA fragment or a placeholder, and a run of digits
    alone is a number the shape-bound rules already read.

    Args:
        content: The text to measure.

    Returns:
        How many characters are inside qualifying runs.
    """
    total = 0
    for match in OPAQUE_RUN.finditer(content):
        run = match.group(0)
        if any(ch.isdigit() for ch in run) and any(ch.isalpha() for ch in run):
            total += len(run)
    return total


def wedged_invisibles(content: str) -> int:
    """Count the format characters wedged inside words or numbers.

    A character of Unicode category ``Cf`` whose neighbours are both
    alphanumeric, at least one of them ASCII — the position where a zero-width
    character splits a word or a number the rules would otherwise read. The soft
    hyphen is not counted (see the module docstring).

    Args:
        content: The text to measure.

    Returns:
        How many such characters ``content`` carries.
    """
    count = 0
    last = len(content) - 1
    for index in range(1, last):
        ch = content[index]
        if ch == _SOFT_HYPHEN or unicodedata.category(ch) != "Cf":
            continue
        before, after = content[index - 1], content[index + 1]
        if before.isalnum() and after.isalnum() and (before.isascii() or after.isascii()):
            count += 1
    return count


def _is_latin(letter: str) -> bool:
    code = ord(letter)
    return code < 0x250 or 0x1E00 <= code <= 0x1EFF


def foreign_letters(content: str) -> tuple[int, int]:
    """Count the letters outside the Latin script, and the letters overall.

    Latin here is ASCII, Latin-1, Latin Extended-A/B and Latin Extended
    Additional — every letter French, German, English and their neighbours use.

    Args:
        content: The text to measure.

    Returns:
        ``(foreign, letters)``.
    """
    letters = 0
    foreign = 0
    for ch in content:
        if not ch.isalpha():
            continue
        letters += 1
        if not _is_latin(ch):
            foreign += 1
    return foreign, letters


def language_of(locale: str) -> str:
    """Return the language subtag of a locale (``"fr-FR"`` and ``"fr_FR"`` give ``"fr"``)."""
    return locale.replace("_", "-").split("-", 1)[0].strip().lower()


def _rules_read_latin(locales: frozenset[str] | None) -> bool:
    """Whether the script measure's premise holds for a policy declaring ``locales``.

    ``None`` declares nothing, and the packaged rules are Latin-script: the
    premise holds. A declaration whose every language is Latin-script confirms
    it. Any declared language outside :data:`LATIN_SCRIPT_LANGUAGES` — known to
    use another script, or simply unknown here — denies it, and the measure
    stands down rather than call the operator's own text foreign (ADR 0028
    Amendment 1).
    """
    return locales is None or locales <= LATIN_SCRIPT_LANGUAGES


def unreadable(
    content: str,
    *,
    detector_id: str,
    reads_words: bool,
    locale: str | None = None,
    locales: frozenset[str] | None = None,
) -> tuple[BlindKind, str] | None:
    """Say why ``detector_id``'s rules could not read ``content``, or ``None`` if they could.

    Args:
        content: The content the rules just scanned without a finding.
        detector_id: The detector's id, named in the blind spot.
        reads_words: Whether the detector's rules read words in a language
            (an injection detector) rather than shapes (a card number, a key).
            Only a word-reading detector is script- and language-bound.
        locale: The locale the caller declared for the content, if any.
        locales: The languages the detector's policy declares its rules cover,
            or ``None`` when the policy declares nothing.

    Returns:
        The blind spot's family and the blind spot in words (ADR 0029), or
        ``None`` when nothing here applies.
    """
    size = len(content)
    if size >= OPAQUE_MIN_CHARS:
        opaque = opaque_chars(content)
        if opaque >= OPAQUE_SHARE * size:
            return BlindKind.OPAQUE, (
                f"{detector_id} did not read {opaque} of {size} characters: they are opaque "
                "encoded runs (base64, hex or a serialised blob) its rules cannot read. It is "
                "refusing to answer, not answering that the content is clean"
            )
    wedged = wedged_invisibles(content)
    if wedged:
        return BlindKind.INVISIBLE, (
            f"{detector_id} found {wedged} invisible format character(s) wedged inside words or "
            "numbers; its rules read across none of them, and a word split that way is how a "
            "directive hides from a pattern"
        )
    if not reads_words:
        return None
    if locale is not None and locales is not None and language_of(locale) not in locales:
        covered = ", ".join(sorted(locales))
        return BlindKind.LOCALE, (
            f"{detector_id} reads {covered}; the caller declared this content as {locale!r}, "
            "a language its rules were not written for"
        )
    if not _rules_read_latin(locales):
        # The policy declares a language written in another script, so "mostly
        # another script" would describe the operator's own text. The rules ran;
        # the declaration is taken at its word (ADR 0028 Amendment 1).
        return None
    foreign, letters = foreign_letters(content)
    if letters >= SCRIPT_MIN_LETTERS and foreign >= SCRIPT_SHARE * letters:
        return BlindKind.SCRIPT, (
            f"{detector_id} reads Latin-script text, and {foreign} of the {letters} letters "
            "here are in another script; its rules were not written for it"
        )
    return None


def refuse_unreadable_text(
    content: str,
    *,
    detector_id: str,
    reads_words: bool,
    locale: str | None = None,
    locales: frozenset[str] | None = None,
) -> None:
    """Raise :class:`~limes.detector.DetectorBlind` if the rules could not read ``content``.

    Called after the rules ran and found nothing, so a finding always dominates.

    Args:
        content: The content the rules just scanned without a finding.
        detector_id: The detector's id, named in the blind spot.
        reads_words: Whether the detector reads words (see :func:`unreadable`).
        locale: The locale the caller declared, if any.
        locales: The languages the policy declares, if any.

    Raises:
        DetectorBlind: With the blind spot :func:`unreadable` names, carrying
            its family (ADR 0029).
    """
    found = unreadable(
        content, detector_id=detector_id, reads_words=reads_words, locale=locale, locales=locales
    )
    if found is not None:
        kind, reason = found
        raise DetectorBlind(reason, kind=kind)
