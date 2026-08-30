"""Load the vendored external adversary corpus (ADR 0017).

Every other corpus in this repository was written by limes's author. This one was
not: it is copied from NVIDIA's garak, by value and with provenance
(``eval/corpus/garak/``, produced by ``scripts/vendor_garak_corpus.py``). limes
does not depend on garak at runtime or in its gate — the dependency runs one way
and only at vendoring time, exactly as it does for the Tessera corpus (ADR 0004).

Two things this module is careful about.

**It is not in the wheel.** The corpus is a megabyte of adversary documents; a
guard library has no business carrying it to every install. So it lives under
``eval/``, which ships in the sdist and in a checkout but not in the built
package. From an installed limes it is simply absent, and the loader says so with
:class:`ExternalCorpusUnavailable` rather than returning an empty corpus — an
empty corpus would score a perfect zero-false-positives and a perfect
zero-recall, and both would be statements about a file nobody read (ADR 0015).

**The benign set is derived, not written.** For every attack the corpus holds
``top_instruction + document(injection)``, and the matched benign is the *same*
``top_instruction + document`` with the injection removed. So the two differ by
exactly the attack, and a detector that fires on both has learnt the document
rather than the injection. That control cannot drift out of step with the attacks
because it is not a second file.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "MARKER",
    "ExternalCase",
    "ExternalCorpus",
    "ExternalCorpusUnavailable",
    "available",
    "corpus_dir",
    "load_external",
    "load_flat",
]

#: The literal garak substitutes an injection into. Kept verbatim from the source.
MARKER = "<|garak_injection|>"

#: The split names the vendored file carries, in report order.
SPLITS = ("dev", "holdout")


class ExternalCorpusUnavailable(LookupError):
    """The vendored corpus is not on disk — a blind spot, never an empty result."""


@dataclass(frozen=True, slots=True)
class ExternalCase:
    """One prompt from the external corpus.

    Attributes:
        probe: The garak probe class the case came from.
        split: ``"dev"``, ``"holdout"``, or ``"benign"`` for a matched control.
        text: The materialised prompt, exactly as garak would have sent it.
    """

    probe: str
    split: str
    text: str


@dataclass(frozen=True, slots=True)
class ExternalCorpus:
    """A vendored corpus: its provenance, its attacks by split, its matched controls."""

    name: str
    kind: str
    source: Mapping[str, Any]
    sampling: Mapping[str, Any]
    attacks: tuple[ExternalCase, ...]
    benign: tuple[ExternalCase, ...]

    def split(self, name: str) -> tuple[ExternalCase, ...]:
        """The attacks belonging to one split."""
        return tuple(case for case in self.attacks if case.split == name)

    @property
    def probes(self) -> tuple[str, ...]:
        """Every probe represented, in a stable order."""
        return tuple(sorted({case.probe for case in self.attacks}))


def corpus_dir() -> Path:
    """Where the vendored corpus lives in a checkout (``<repo>/eval/corpus/garak``)."""
    return Path(__file__).resolve().parents[3] / "eval" / "corpus" / "garak"


def available() -> bool:
    """Whether the vendored corpus can be read from here."""
    return (corpus_dir() / "latent_injection.json").is_file()


def load_flat(name: str) -> ExternalCorpus:
    """Load a corpus whose probes hand back finished prompts, with no injection factor.

    PromptInject's hijacks *are* the prompt: there is no surrounding document, so
    there is nothing to factor out and no matched control to derive. Every case is
    labelled ``blind`` — the family is held out whole and scored once, which the
    latent corpus's ``holdout`` can no longer claim (ADR 0017, Amendment 1).

    Args:
        name: The file stem under ``eval/corpus/garak/``.

    Returns:
        The corpus, with an empty ``benign`` tuple: this family carries no control
        of its own, and inventing one here would be a control nobody measured.

    Raises:
        ExternalCorpusUnavailable: The file is not on disk.
    """
    path = corpus_dir() / f"{name}.json"
    if not path.is_file():
        raise ExternalCorpusUnavailable(f"{path} is not on disk.")
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    attacks = tuple(
        ExternalCase(probe=probe, split="blind", text=text)
        for probe, spec in sorted(raw["probes"].items())
        for text in spec["prompts"]
    )
    return ExternalCorpus(
        name=name,
        kind=raw["kind"],
        source=raw["source"],
        sampling=raw["sampling"],
        attacks=attacks,
        benign=(),
    )


def load_external(name: str) -> ExternalCorpus:
    """Load one vendored corpus by file stem (``latent_injection``/``latent_jailbreak``).

    Args:
        name: The file stem under ``eval/corpus/garak/``.

    Returns:
        The corpus, with attacks split as vendored and the matched benign controls
        derived from the same documents.

    Raises:
        ExternalCorpusUnavailable: The file is not on disk — from an installed
            wheel, for instance, which deliberately does not carry it.
    """
    path = corpus_dir() / f"{name}.json"
    if not path.is_file():
        raise ExternalCorpusUnavailable(
            f"{path} is not on disk. The external corpus ships in the repository and the "
            "sdist, never in the wheel; run this from a checkout."
        )
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))

    attacks: list[ExternalCase] = []
    benign: list[ExternalCase] = []
    for probe, spec in sorted(raw["probes"].items()):
        tops: list[str] = spec["top_instructions"]
        contexts: list[str] = spec["contexts"]
        injections: list[str] = spec["injections"]
        for split in SPLITS:
            for top_index, context_index, injection_index in spec["cases"][split]:
                text = tops[top_index] + contexts[context_index].replace(
                    MARKER, injections[injection_index]
                )
                attacks.append(ExternalCase(probe=probe, split=split, text=text))
        # The control: the same documents, the injection removed. Derived here so
        # it cannot fall out of step with the attacks it is matched against.
        for top in tops:
            for context in contexts:
                benign.append(
                    ExternalCase(
                        probe=probe, split="benign", text=top + context.replace(MARKER, "")
                    )
                )

    seen: set[str] = set()
    unique_benign: list[ExternalCase] = []
    for case in benign:
        if case.text not in seen:
            seen.add(case.text)
            unique_benign.append(case)

    return ExternalCorpus(
        name=name,
        kind=raw["kind"],
        source=raw["source"],
        sampling=raw["sampling"],
        attacks=tuple(attacks),
        benign=tuple(unique_benign),
    )
