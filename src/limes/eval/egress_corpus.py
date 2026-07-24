"""Load the synthetic egress corpora (ADR 0003/0009).

Two files per detector, and both are required for admission:

* a **positive** corpus — what must be located, each case naming the exact
  substring the detector has to span (``locate``);
* a **benign** corpus — the lookalikes, each naming which category it imitates
  (``mimics``). It is the benign set that measures precision, and it is the half
  a detector author is tempted to skip.

The values are synthetic by construction and may never be real (ADR 0009):
published test card numbers, documentation IBANs, RFC 2606 reserved domains,
reserved fictional phone ranges, recomputed NIR keys over fictional identities,
and — for secrets — documentation or revoked key *formats*. What is being
measured is the detection of a **shape and its checksum**, never of a real datum,
so nothing is lost by the constraint and a whole class of accident is prevented.

A vendor-prefixed secret vector is stored **assembled** (ADR 0010): the case
declares ``content_template`` (with a ``{token}`` placeholder) and ``token_parts``
(fragments joined at load), never a contiguous ``sk_live_…`` literal. The literal
would trip a host secret scanner and commit a credential-shaped string into a
public repository, while proving nothing the reconstructed value does not. The
loader assembles the real token, so the detector still runs on the true format.
The two shapes are mutually exclusive, and the loader refuses a case that mixes
them — a rule enforced only by a test that restates it is not enforced (ADR 0026).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final, final

__all__ = [
    "BenignCase",
    "PositiveCase",
    "categories",
    "corpus_path",
    "load_benign",
    "load_positive",
]

_CORPUS: Final = Path(__file__).resolve().parent.parent / "corpus" / "egress"

#: The only provenance a corpus file may declare (ADR 0009).
SYNTHETIC: Final = "synthetic"


@final
@dataclass(frozen=True, slots=True)
class PositiveCase:
    """One outbound message that carries a value the detector must locate.

    Attributes:
        case_id: Stable id, unique within its file.
        category: The category of the value (``pan``, ``iban``, …).
        language: ``"fr"``, ``"de"`` or ``"en"``.
        content: The outbound content.
        locate: The exact substring a finding must span. Grading on this rather
            than on "did anything fire" is what stops a block-everything
            detector from scoring: its span is the whole message, which is not
            this string (ADR 0003).
        why: Which published test vector this is, and what it exercises.
    """

    case_id: str
    category: str
    language: str
    content: str
    locate: str
    why: str

    @property
    def offset(self) -> int:
        """Where :attr:`locate` starts in :attr:`content`."""
        return self.content.index(self.locate)


@final
@dataclass(frozen=True, slots=True)
class BenignCase:
    """One outbound message that only *looks* like it carries a value.

    Attributes:
        case_id: Stable id, unique within its file.
        mimics: The category this lookalike imitates, so a false positive can be
            attributed to the rule whose precision it cost.
        language: ``"fr"``, ``"de"`` or ``"en"``.
        content: The outbound content. No finding of any kind may fire on it.
        why: Which check this case is meant to fail.
    """

    case_id: str
    mimics: str
    language: str
    content: str
    why: str


def corpus_path(detector: str, kind: str, *, root: Path | None = None) -> Path:
    """Return the path of one corpus file.

    Args:
        detector: The detector id, e.g. ``"pii-egress"``.
        kind: ``"positive"`` or ``"benign"``.
        root: Directory to look in; the packaged corpus by default. Exposed so a
            test can hand the loader a forged file and check that the *loader*
            refuses it — a rule enforced by a test that re-implements the rule is
            not enforced at all (ADR 0026).

    Returns:
        The path, whether or not it exists — the caller reports the absence.
    """
    return (root or _CORPUS) / f"{detector.replace('-egress', '')}_{kind}.json"


def _read(detector: str, kind: str, *, root: Path | None = None) -> list[dict[str, object]]:
    """Read and structurally validate one corpus file.

    Values are returned **as parsed**, not stringified: an assembled positive case
    carries ``token_parts`` as a list, and flattening it to ``str`` would destroy
    exactly the field whose point is to keep a credential-shaped literal out of the
    file (ADR 0010). The keys are normalised to ``str`` (JSON keys always are).
    """
    path = corpus_path(detector, kind, root=root)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"corpus {path} must be a mapping, got {type(raw).__name__}")
    if raw.get("detector") != detector:
        raise ValueError(
            f"corpus {path}: declares detector {raw.get('detector')!r}, not {detector!r}"
        )
    if raw.get("kind") != kind:
        raise ValueError(f"corpus {path}: declares kind {raw.get('kind')!r}, not {kind!r}")
    if raw.get("provenance") != SYNTHETIC:
        raise ValueError(
            f"corpus {path}: provenance is {raw.get('provenance')!r}, and the only value an "
            f"egress corpus may declare is {SYNTHETIC!r} (ADR 0009). A corpus that could say "
            f"otherwise is one a real value can land in."
        )
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"corpus {path}: 'cases' must be a non-empty list")
    out: list[dict[str, object]] = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError(f"corpus {path}: each case must be a mapping")
        out.append({str(key): value for key, value in case.items()})
    return out


def _positive_content(raw: dict[str, object]) -> tuple[str, str]:
    """Return ``(content, locate)`` for one positive case, assembling if declared.

    Two mutually exclusive shapes (ADR 0010):

    * a **literal** case declares ``content`` and ``locate`` verbatim (PANs, IBANs,
      PEM blocks, JWTs — values no host scanner push-protects);
    * an **assembled** case declares ``content_template`` (holding ``{token}``) and
      ``token_parts`` (joined into the token), so the file never carries a
      contiguous vendor-key literal.

    Raises:
        ValueError: If a case mixes the two shapes, if ``token_parts`` is not a
            list of at least two non-empty strings, or if ``content_template`` is
            not a string containing ``{token}``. Enforced here, in the loader, so a
            forged file is refused by the thing that reads it (ADR 0026).
    """
    case_id = raw.get("id")
    assembled = "token_parts" in raw or "content_template" in raw
    if assembled:
        if "content" in raw or "locate" in raw:
            raise ValueError(
                f"corpus case {case_id!r}: an assembled case declares content_template and "
                f"token_parts, never content/locate — the two shapes are mutually exclusive "
                f"(ADR 0010)."
            )
        parts = raw.get("token_parts")
        template = raw.get("content_template")
        if (
            not isinstance(parts, list)
            or len(parts) < 2
            or not all(isinstance(part, str) and part for part in parts)
        ):
            raise ValueError(
                f"corpus case {case_id!r}: 'token_parts' must be a list of at least two "
                f"non-empty strings; a single fragment would be the very literal ADR 0010 keeps "
                f"out of the file."
            )
        if not isinstance(template, str) or "{token}" not in template:
            raise ValueError(
                f"corpus case {case_id!r}: 'content_template' must be a string containing the "
                f"'{{token}}' placeholder."
            )
        token = "".join(parts)
        return template.replace("{token}", token), token
    content = raw.get("content")
    locate = raw.get("locate")
    if not isinstance(content, str) or not isinstance(locate, str):
        raise ValueError(
            f"corpus case {case_id!r}: a literal positive case needs string 'content' and "
            f"'locate' (or declare an assembled case with content_template/token_parts)."
        )
    return content, locate


def load_positive(detector: str, *, root: Path | None = None) -> tuple[PositiveCase, ...]:
    """Load the positive corpus for ``detector``.

    Args:
        detector: The detector id, e.g. ``"pii-egress"``.
        root: Directory to load from; the packaged corpus by default.

    Returns:
        Every positive case, in file order.

    Raises:
        ValueError: If the file is malformed, or a case's ``locate`` is not a
            substring of its ``content`` — a case that names a value its own
            text does not contain could never be located, and would be a
            permanent false negative nobody could fix.
    """
    cases: list[PositiveCase] = []
    for raw in _read(detector, "positive", root=root):
        content, locate = _positive_content(raw)
        case = PositiveCase(
            case_id=str(raw["id"]),
            category=str(raw["category"]),
            language=str(raw["language"]),
            content=content,
            locate=locate,
            why=str(raw["why"]),
        )
        if case.locate not in case.content:
            raise ValueError(
                f"corpus case {case.case_id}: locate {case.locate!r} is not in its own content"
            )
        cases.append(case)
    return tuple(cases)


def load_benign(detector: str, *, root: Path | None = None) -> tuple[BenignCase, ...]:
    """Load the benign corpus for ``detector``.

    Args:
        detector: The detector id, e.g. ``"pii-egress"``.
        root: Directory to load from; the packaged corpus by default.

    Returns:
        Every benign case, in file order.
    """
    return tuple(
        BenignCase(
            case_id=str(raw["id"]),
            mimics=str(raw["mimics"]),
            language=str(raw["language"]),
            content=str(raw["content"]),
            why=str(raw["why"]),
        )
        for raw in _read(detector, "benign", root=root)
    )


def categories(cases: tuple[PositiveCase, ...]) -> tuple[str, ...]:
    """Return every category present in ``cases``, sorted."""
    return tuple(sorted({case.category for case in cases}))
