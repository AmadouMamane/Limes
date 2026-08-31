"""Load the vendored external egress corpora (ADR 0021).

``pii-egress`` scores 32/32 and ``secrets-egress`` 15/15 on corpora their author
wrote. ADR 0017 already showed what that kind of number is worth: ``injection``
went from 76% on the author's cases to 24% on an adversary's. These two loaders
bring the same treatment to the outbound leg.

Two sources, two different strengths, and both are labelled rather than blended.

**presidio-research (MIT)** supplies *document contexts*: 209 customer-support and
banking sentence templates with placeholders where a value goes. The values
substituted into them are limes's own already-cleared synthetic vectors, because
ADR 0009 forbids any other kind — so what this corpus varies is the **document**,
alone. Weaker than garak, where the attack itself is foreign, and said so.

**gitleaks (MIT)** supplies the *credential-format catalogue*: 222 rules, of which
218 materialise into a self-verified instance, plus 339 of gitleaks' own
false-positive vectors as external hard negatives. Here the taxonomy and the
negatives are foreign and the positive bytes are generated locally from the
foreign spec.

**The controls are derived, never written.** For every PII attack there are two
matched controls built from the same sentence: one with the value replaced by a
neutral phrase, and one with it replaced by a **same-shape, checksum-invalid
decoy**. The second is the sharp one — it asks whether the checksum limes says its
precision comes from actually carries that weight in prose limes did not write.
A control derived from the attack's own data cannot drift out of step with it.

**An absent corpus is a blind spot, never an empty result** (ADR 0015). These
files ship in the repository and the sdist, never in the wheel: a guard library
has no business carrying a megabyte of adversary material to every install.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from limes.eval.egress_corpus import load_positive
from limes.eval.external_corpus import ExternalCorpusUnavailable

__all__ = [
    "ExternalEgressCase",
    "PiiExternalCorpus",
    "SecretsExternalCorpus",
    "corpus_root",
    "load_pii_external",
    "load_secrets_external",
]

#: Where the vendored external egress corpora live in a checkout.
_ROOT: Final = Path(__file__).resolve().parents[3] / "eval" / "corpus"

#: The neutral phrase a `removed` control carries where the value stood.
_REMOVED: Final = "the reference held on file"

#: The carrier a vendored secret instance is scored inside. Deliberately plain:
#: what is under test is the credential, not the prose around it.
_SECRET_CARRIER: Final = "Deployment log line: {token} — end of line."


@dataclass(frozen=True, slots=True)
class ExternalEgressCase:
    """One scored case: a document, the span under test, and where it came from.

    Attributes:
        case_id: Stable identity, unique within its corpus.
        template: The upstream template (PII) or rule id (secrets) it came from.
        category: The limes category the value belongs to (``pan``, ``aws_key``…).
        split: ``dev``, ``holdout``, or ``control``/``negative`` for a control.
        content: The full content handed to the detector.
        locate: The exact substring a finding must cover; empty for a control that
            carries no value at all.
        kind: ``attack``, ``control_decoy``, ``control_removed`` or ``negative``.
    """

    case_id: str
    template: str
    category: str
    split: str
    content: str
    locate: str
    kind: str


@dataclass(frozen=True, slots=True)
class PiiExternalCorpus:
    """PII in third-party document contexts, with its matched controls."""

    source: Mapping[str, Any]
    strength: str
    sampling: Mapping[str, Any]
    attacks: tuple[ExternalEgressCase, ...]
    controls: tuple[ExternalEgressCase, ...]
    out_of_scope: tuple[ExternalEgressCase, ...]
    templates: int

    def split(self, name: str) -> tuple[ExternalEgressCase, ...]:
        """The attacks belonging to one split."""
        return tuple(case for case in self.attacks if case.split == name)

    @property
    def categories(self) -> tuple[str, ...]:
        """Every category represented, in a stable order."""
        return tuple(sorted({case.category for case in self.attacks}))


@dataclass(frozen=True, slots=True)
class SecretsExternalCorpus:
    """The credential-format catalogue, its instances and its hard negatives."""

    source: Mapping[str, Any]
    strength: str
    sampling: Mapping[str, Any]
    attacks: tuple[ExternalEgressCase, ...]
    negatives: tuple[ExternalEgressCase, ...]
    blind_spots: tuple[Mapping[str, str], ...]
    catalogue_rules: int

    def split(self, name: str) -> tuple[ExternalEgressCase, ...]:
        """The instances belonging to one split."""
        return tuple(case for case in self.attacks if case.split == name)


def corpus_root() -> Path:
    """Where the vendored external corpora live (``<repo>/eval/corpus``)."""
    return _ROOT


def _read(source: str, name: str) -> dict[str, Any]:
    path = _ROOT / source / name
    if not path.is_file():
        raise ExternalCorpusUnavailable(
            f"{path} is not on disk. The external corpora ship in the repository and the "
            "sdist, never in the wheel; run this from a checkout."
        )
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def _cleared_vectors() -> dict[str, tuple[str, ...]]:
    """The already-admitted synthetic values, by category (ADR 0009).

    Read from the corpus that admitted ``pii-egress`` rather than re-declared
    here, so the external bench and the internal one carry the *same* values and
    differ by the document alone. A second list would drift.
    """
    vectors: dict[str, list[str]] = {}
    for case in load_positive("pii-egress"):
        vectors.setdefault(case.category, []).append(case.locate)
    return {category: tuple(values) for category, values in sorted(vectors.items())}


def _decoy(category: str, value: str) -> str:
    """A same-shape, checksum-invalid twin of ``value``.

    The point of the pair: attack and control differ by exactly the property the
    detector says its precision comes from. A card number whose Luhn digit is
    wrong is still sixteen grouped digits; an IBAN whose check digits are wrong is
    still a country code and thirty characters. If the detector fires on both, the
    checksum it advertises is not what is doing the work.
    """
    if category == "pan":
        # Flip the final digit: the shape survives, the Luhn check does not.
        digits = [c for c in value if c.isdigit()]
        replacement = "0" if digits[-1] != "0" else "1"
        return value[::-1].replace(digits[-1], replacement, 1)[::-1]
    if category == "iban":
        # Flip the two check digits (positions 2-3): MOD 97-10 fails, shape holds.
        head, tail = value[:2], value[4:]
        check = "00" if value[2:4] != "00" else "11"
        return f"{head}{check}{tail}"
    if category == "phone":
        # A telephone number carries no checksum, so the only thing this decoy can
        # test is the gate the rule actually declares: a digit count inside E.164's
        # 9-15. Truncating to eight digits lands below it. Appending digits was
        # tried first and was WRONG — it leaves the whole valid number standing as
        # a prefix, so the rule was right to fire and the column measured the decoy,
        # not the detector.
        digits = [c for c in value if c.isdigit()]
        keep = 8
        out: list[str] = []
        seen = 0
        for character in value:
            if character.isdigit():
                if seen >= keep:
                    continue
                seen += 1
            out.append(character)
        return "".join(out).rstrip(" -.") if len(digits) > keep else value[:-1]
    if category == "email":
        # No dot in the domain at all, so nothing satisfies the rule's trailing
        # `\.[A-Za-z]{2,}` — the shape its docstring says it already rejects.
        # `rsplit(".", 1)` was tried first and was WRONG: on `sub.example.co.uk`
        # it just yields `sub.example.co`, which is a perfectly good address.
        local, _, domain = value.partition("@")
        return f"{local}@{domain.split('.')[0]}"
    if category == "nir":
        return value[:-2] + ("00" if value[-2:] != "00" else "11")
    return value


def load_pii_external() -> PiiExternalCorpus:
    """Materialise the PII corpus: attacks, matched controls, out-of-scope rows.

    Returns:
        The corpus. Every attack carries exactly one detectable value; every
        control is the same sentence with that value replaced.

    Raises:
        ExternalCorpusUnavailable: The vendored file is not on disk.
    """
    document = _read("presidio", "pii_templates.json")
    claimed: dict[str, str] = document["claimed_slots"]
    out_of_scope_slots: dict[str, str] = document["out_of_scope_slots"]
    fillers: dict[str, str] = document["fillers"]
    vectors = _cleared_vectors()

    def fill(template: str, target: str, value: str) -> tuple[str, int]:
        """Substitute every placeholder; return the text and the target's offset."""
        text = template
        for slot, filler in fillers.items():
            text = text.replace("{{" + slot + "}}", filler)
        for slot in {**claimed, **out_of_scope_slots}:
            if slot != target:
                text = text.replace("{{" + slot + "}}", _REMOVED)
        marker = "{{" + target + "}}"
        offset = text.index(marker)
        return text.replace(marker, value, 1), offset

    attacks: list[ExternalEgressCase] = []
    controls: list[ExternalEgressCase] = []
    out_of_scope: list[ExternalEgressCase] = []

    for index, template in enumerate(document["templates"]):
        text: str = template["text"]
        split: str = template["split"]
        stem = f"t{index:03d}"
        for slot in template["claimed_slots"]:
            category = claimed[slot]
            for vector_index, value in enumerate(vectors.get(category, ())):
                content, _ = fill(text, slot, value)
                attacks.append(
                    ExternalEgressCase(
                        case_id=f"{stem}_{category}_{vector_index:02d}",
                        template=text,
                        category=category,
                        split=split,
                        content=content,
                        locate=value,
                        kind="attack",
                    )
                )
                decoy = _decoy(category, value)
                decoy_content, _ = fill(text, slot, decoy)
                controls.append(
                    ExternalEgressCase(
                        case_id=f"{stem}_{category}_{vector_index:02d}_decoy",
                        template=text,
                        category=category,
                        split=split,
                        content=decoy_content,
                        locate="",
                        kind="control_decoy",
                    )
                )
            removed_content, _ = fill(text, slot, _REMOVED)
            controls.append(
                ExternalEgressCase(
                    case_id=f"{stem}_{category}_removed",
                    template=text,
                    category=category,
                    split=split,
                    content=removed_content,
                    locate="",
                    kind="control_removed",
                )
            )
        for slot in template["out_of_scope_slots"]:
            content, _ = fill(text, slot, _REMOVED)
            out_of_scope.append(
                ExternalEgressCase(
                    case_id=f"{stem}_{out_of_scope_slots[slot]}",
                    template=text,
                    category=out_of_scope_slots[slot],
                    split=split,
                    content=content,
                    locate="",
                    kind="attack",
                )
            )

    return PiiExternalCorpus(
        source=document["source"],
        strength=document["strength"],
        sampling=document["sampling"],
        attacks=tuple(attacks),
        controls=tuple(controls),
        out_of_scope=tuple(out_of_scope),
        templates=len(document["templates"]),
    )


def load_secrets_external() -> SecretsExternalCorpus:
    """Materialise the secrets corpus: one instance per catalogue format.

    Returns:
        The corpus, with the vendored blind spots carried rather than dropped —
        a format nobody could materialise is not a format the detector missed.

    Raises:
        ExternalCorpusUnavailable: The vendored file is not on disk.
    """
    document = _read("gitleaks", "secret_formats.json")

    attacks: list[ExternalEgressCase] = []
    for entry in document["formats"]:
        token = "".join(entry["token_parts"])
        attacks.append(
            ExternalEgressCase(
                case_id=entry["rule"],
                template=entry["rule"],
                category=entry["rule"],
                split=entry["split"],
                content=_SECRET_CARRIER.format(token=token),
                locate=token,
                kind="attack",
            )
        )

    negatives: list[ExternalEgressCase] = []
    for index, entry in enumerate(document["hard_negatives"]):
        text = "".join(entry["text_parts"])
        negatives.append(
            ExternalEgressCase(
                case_id=f"fp{index:03d}_{entry['origin_file']}",
                template=entry["origin_file"],
                category=entry["origin_file"],
                split="negative",
                content=text,
                locate="",
                kind="negative",
            )
        )

    blind: Sequence[Mapping[str, str]] = document["blind_spots"]
    return SecretsExternalCorpus(
        source=document["source"],
        strength=document["strength"],
        sampling=document["sampling"],
        attacks=tuple(attacks),
        negatives=tuple(negatives),
        blind_spots=tuple(blind),
        catalogue_rules=int(document["_counts"]["catalogue_rules"]),
    )
