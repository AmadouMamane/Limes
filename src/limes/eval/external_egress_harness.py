"""Score the egress detectors against adversaries limes did not write (ADR 0021).

``eval/matrices/pii_egress.md`` says 32/32 and ``secrets_egress.md`` says 15/15.
Both are true, and both are answers to "does the detector do what its author
intended" over cases its author chose. ADR 0017 already measured what the other
question costs: ``injection`` scored 76% on the author's corpus and **24%** on
garak's. This harness asks the outbound leg the same question, from two outside
sources, and publishes whatever comes back.

**Recall and false positives, always together.** Every table here carries both
sides, because a recall number alone is satisfied by blocking everything and a
false-positive number alone is satisfied by blocking nothing. Four configurations
per detector make the number a delta rather than a score: the unplugged null
control, block-everything, the ported baseline where one exists, and limes.

**Two graders, and the difference is declared.** For PII the value is substituted
into the sentence by this repository, so its offsets are known exactly and the
strict rule applies: a hit is a finding whose span *reproduces the value*, which
is what keeps block-everything at zero. For secrets the vendored instance often
carries gitleaks' own context keywords (``apikey = <secret>``), so an exact-span
rule would score a correct finding as a miss; a hit there is a finding falling
**wholly inside** the vendored token — still zero for block-everything, which
spans the carrier too.

**A format nobody could materialise is not a format the detector missed.** The
four gitleaks rules the vendoring script could not instantiate are carried into
this report as named blind spots and excluded from the denominator (ADR 0015).

Run ``python -m limes.eval.external_egress_harness pii`` (or ``secrets``) to print
the matrix, ``--write`` to write it to ``eval/matrices/external_<name>.md``.
Default is ``--split dev``; the held-out number exists only when somebody
deliberately passes ``--split all``.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Final, final

from limes.detector import Context, Detector, Direction
from limes.detectors.pii_egress import PiiEgressDetector
from limes.detectors.secrets_egress import SecretsEgressDetector
from limes.eval.egress_harness import BASELINES, _BlockEverything
from limes.eval.external_corpus import ExternalCorpusUnavailable
from limes.eval.external_egress_corpus import (
    ExternalEgressCase,
    load_pii_external,
    load_secrets_external,
)
from limes.eval.power import sign_test_power
from limes.spans import RedactedSpan

__all__ = ["Cell", "Row", "compute_pii", "compute_secrets", "render_pii", "render_secrets"]

_OBSERVED_AT: Final = "2026-08-31T00:00:00Z"
_MATRICES: Final = Path(__file__).resolve().parents[3] / "eval" / "matrices"
_UNPLUGGED: Final = "unplugged (null control)"
_BLOCK_EVERYTHING: Final = "block-everything"
_CONTEXT: Final = Context(policy_hash="external-egress-eval", actor=None)


@final
@dataclass(frozen=True, slots=True)
class Cell:
    """One (configuration, population) count."""

    population: str
    hits: int
    total: int
    is_cost: bool

    @property
    def rate(self) -> float:
        """Fraction of the population this configuration fired on."""
        return self.hits / self.total if self.total else 0.0

    def render(self) -> str:
        """The cell as it appears in a matrix."""
        return "—" if not self.total else f"{self.hits}/{self.total} ({self.rate:.1%})"


@final
@dataclass(frozen=True, slots=True)
class Row:
    """One configuration, scored over every population."""

    name: str
    cells: tuple[Cell, ...]

    def cell(self, population: str) -> Cell:
        """Look one cell up by population name."""
        for candidate in self.cells:
            if candidate.population == population:
                return candidate
        raise KeyError(population)


def _spans(detectors: Sequence[Detector], content: str) -> tuple[RedactedSpan, ...]:
    findings = [
        finding
        for detector in detectors
        for finding in detector.inspect(Direction.OUTBOUND, content, _CONTEXT)
    ]
    return tuple(span for finding in findings for span in finding.spans)


def _locates_exactly(case: ExternalEgressCase, spans: Sequence[RedactedSpan]) -> bool:
    """The strict grader: a span reproduces the value at its own offsets."""
    return any(case.content[span.start : span.end] == case.locate for span in spans)


def _locates_inside(case: ExternalEgressCase, spans: Sequence[RedactedSpan]) -> bool:
    """The containment grader: a non-empty span falls wholly inside the token."""
    start = case.content.index(case.locate)
    end = start + len(case.locate)
    return any(span.end > span.start and start <= span.start and span.end <= end for span in spans)


def _configurations(detector_id: str) -> tuple[tuple[str, list[Detector]], ...]:
    limes: Detector = (
        PiiEgressDetector() if detector_id == "pii-egress" else SecretsEgressDetector()
    )
    configurations: list[tuple[str, list[Detector]]] = [
        (_UNPLUGGED, []),
        (_BLOCK_EVERYTHING, [_BlockEverything()]),
    ]
    baseline = BASELINES.get(detector_id)
    if baseline is not None:
        name, factory = baseline
        configurations.append((name, [factory()]))
    configurations.append((f"limes {detector_id}", [limes]))
    return tuple(configurations)


@final
@dataclass(frozen=True, slots=True)
class PiiReport:
    """Everything the PII bench measured, ready to render."""

    corpus_strength: str
    source_url: str
    source_license: str
    source_commit: str
    templates: int
    splits: tuple[str, ...]
    rows: tuple[Row, ...]
    populations: tuple[str, ...]
    by_category: tuple[tuple[str, int, int, int], ...]
    by_template_worst: tuple[tuple[str, int, int], ...]
    decoys_killed: tuple[str, ...]


def compute_pii(splits: Sequence[str]) -> PiiReport:
    """Score every configuration over the presidio-derived PII corpus.

    Args:
        splits: ``("dev",)`` while iterating, ``("dev", "holdout")`` for the record.

    Returns:
        The report.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk.
    """
    corpus = load_pii_external()
    decoys = tuple(c for c in corpus.controls if c.kind == "control_decoy")
    removed = tuple(c for c in corpus.controls if c.kind == "control_removed")

    populations: list[str] = [f"values located ({split})" for split in splits]
    populations += [
        "matched control: checksum-invalid decoy",
        "matched control: value removed",
        "out-of-scope slots (declared)",
    ]

    rows: list[Row] = []
    for name, detectors in _configurations("pii-egress"):
        cells: list[Cell] = []
        for split in splits:
            cases = corpus.split(split)
            hits = sum(1 for c in cases if _locates_exactly(c, _spans(detectors, c.content)))
            cells.append(Cell(f"values located ({split})", hits, len(cases), False))
        for population, group in (
            ("matched control: checksum-invalid decoy", decoys),
            ("matched control: value removed", removed),
            ("out-of-scope slots (declared)", corpus.out_of_scope),
        ):
            killed = sum(1 for c in group if _spans(detectors, c.content))
            cells.append(Cell(population, killed, len(group), True))
        rows.append(Row(name=name, cells=tuple(cells)))

    limes = [PiiEgressDetector()]
    scored = tuple(c for split in splits for c in corpus.split(split))
    by_category: list[tuple[str, int, int, int]] = []
    for category in corpus.categories:
        category_cases = [c for c in scored if c.category == category]
        hits = sum(1 for c in category_cases if _locates_exactly(c, _spans(limes, c.content)))
        category_decoys = [c for c in decoys if c.category == category and c.split in set(splits)]
        killed = sum(1 for c in category_decoys if _spans(limes, c.content))
        by_category.append((category, hits, len(category_cases), killed))

    worst: list[tuple[str, int, int]] = []
    for template in sorted({c.template for c in scored}):
        template_cases = [c for c in scored if c.template == template]
        hits = sum(1 for c in template_cases if _locates_exactly(c, _spans(limes, c.content)))
        if hits < len(template_cases):
            worst.append((template, hits, len(template_cases)))

    killed_decoys = tuple(
        c.case_id for c in decoys if c.split in set(splits) and _spans(limes, c.content)
    )
    return PiiReport(
        corpus_strength=corpus.strength,
        source_url=str(corpus.source["url"]),
        source_license=str(corpus.source["license"]),
        source_commit=str(corpus.source["commit"])[:12],
        templates=corpus.templates,
        splits=tuple(splits),
        rows=tuple(rows),
        populations=tuple(populations),
        by_category=tuple(by_category),
        by_template_worst=tuple(worst),
        decoys_killed=killed_decoys,
    )


@final
@dataclass(frozen=True, slots=True)
class SecretsReport:
    """Everything the secrets bench measured, ready to render."""

    corpus_strength: str
    source_url: str
    source_license: str
    source_commit: str
    catalogue_rules: int
    materialised: int
    splits: tuple[str, ...]
    rows: tuple[Row, ...]
    populations: tuple[str, ...]
    caught: tuple[str, ...]
    blind_spots: tuple[tuple[str, str], ...]
    negatives_killed: tuple[str, ...]


def compute_secrets(splits: Sequence[str]) -> SecretsReport:
    """Score every configuration over the gitleaks-derived secrets corpus.

    Args:
        splits: ``("dev",)`` while iterating, ``("dev", "holdout")`` for the record.

    Returns:
        The report.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk.
    """
    corpus = load_secrets_external()
    populations: list[str] = [f"formats located ({split})" for split in splits]
    populations.append("gitleaks' own hard negatives")

    rows: list[Row] = []
    for name, detectors in _configurations("secrets-egress"):
        cells: list[Cell] = []
        for split in splits:
            cases = corpus.split(split)
            hits = sum(1 for c in cases if _locates_inside(c, _spans(detectors, c.content)))
            cells.append(Cell(f"formats located ({split})", hits, len(cases), False))
        killed = sum(1 for c in corpus.negatives if _spans(detectors, c.content))
        cells.append(Cell("gitleaks' own hard negatives", killed, len(corpus.negatives), True))
        rows.append(Row(name=name, cells=tuple(cells)))

    limes = [SecretsEgressDetector()]
    scored = tuple(c for split in splits for c in corpus.split(split))
    caught = tuple(
        sorted(c.category for c in scored if _locates_inside(c, _spans(limes, c.content)))
    )
    killed_negatives = tuple(c.case_id for c in corpus.negatives if _spans(limes, c.content))
    return SecretsReport(
        corpus_strength=corpus.strength,
        source_url=str(corpus.source["url"]),
        source_license=str(corpus.source["license"]),
        source_commit=str(corpus.source["commit"])[:12],
        catalogue_rules=corpus.catalogue_rules,
        materialised=len(corpus.attacks),
        splits=tuple(splits),
        rows=tuple(rows),
        populations=tuple(populations),
        caught=caught,
        blind_spots=tuple((str(b["rule"]), str(b["reason"])) for b in corpus.blind_spots),
        negatives_killed=killed_negatives,
    )


def _matrix(rows: Sequence[Row], populations: Sequence[str]) -> list[str]:
    lines = [
        "| configuration | " + " | ".join(populations) + " |",
        "|---" * (len(populations) + 1) + "|",
    ]
    for row in rows:
        name = f"**{row.name}**" if row.name.startswith("limes") else row.name
        cells = [name]
        for population in populations:
            try:
                cells.append(row.cell(population).render())
            except KeyError:
                cells.append("—")
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def render_pii(report: PiiReport, when: str) -> str:
    """Render the PII bench as a Markdown matrix."""
    lines = [
        "# limes `pii-egress` — against document contexts it did not write",
        "",
        f"Generated {when} from **presidio-research** ({report.source_license}, "
        f"commit `{report.source_commit}`, <{report.source_url}>) — "
        f"{report.templates} sentence templates vendored by value into "
        "`eval/corpus/presidio/` (ADR 0021). limes does not depend on "
        "presidio-research; the corpus is a copy, reproducible with "
        "`scripts/vendor_presidio_corpus.py`.",
        "",
        f"**Strength of this number.** {report.corpus_strength}",
        "",
        "**Read both sides of every row.** A recall column alone is satisfied by "
        "blocking everything; a false-positive column alone is satisfied by blocking "
        "nothing. `block-everything` is on the table for exactly that reason.",
        "",
    ]
    lines += _matrix(report.rows, report.populations)
    lines += [
        "",
        "- **values located** — the exact synthetic vector, at its own offsets, inside a "
        "third-party sentence. The *documents* are presidio-research's; the *values* are "
        "limes's own already-admitted ones, because ADR 0009 forbids any other kind.",
        "- **checksum-invalid decoy** — the same sentence, the value replaced by a "
        "same-shape twin whose Luhn / MOD 97-10 / E.164 check fails. limes says its "
        "precision comes from the checksum; this column is where that claim is paid for.",
        "- **value removed** — the same sentence with the value replaced by a neutral "
        "phrase. A detector firing here has learnt the sentence, not the value.",
        "- **out-of-scope slots** — templates carrying `{{ssn}}`, `{{us_driver_license}}` "
        "or `{{ip_address}}`, which limes has never claimed. Measured so the perimeter "
        "is a number rather than a sentence.",
        "",
        "## Per category",
        "",
        "| category | located | decoys killed |",
        "|---|---|---|",
    ]
    for category, hits, total, killed in report.by_category:
        rate = f"{hits / total:.1%}" if total else "—"
        lines.append(f"| **{category}** | {hits}/{total} ({rate}) | {killed} |")

    lines += ["", "## Where the misses are", ""]
    if not report.by_template_worst:
        lines.append(
            "- No template loses a value. Over "
            f"{report.templates} third-party sentence contexts, the detector's recall does "
            "not depend on the prose around the value — which is the claim this corpus "
            "exists to test, and the one it supports."
        )
    else:
        for template, hits, total in report.by_template_worst[:12]:
            lines.append(f"- `{template[:90]}` — {hits}/{total}")
    if report.decoys_killed:
        lines += [
            "",
            f"**Decoys killed:** {len(report.decoys_killed)}. Named, not rounded away: "
            + ", ".join(f"`{name}`" for name in report.decoys_killed[:12]),
        ]

    power = sign_test_power(sum(cell.total for cell in report.rows[0].cells if cell.is_cost))
    lines += ["", "## The two numbers", ""]
    limes_row = report.rows[-1]
    for split in report.splits:
        cell = limes_row.cell(f"values located ({split})")
        lines.append(f"- **Values located ({split}):** {cell.render()}.")
    for population in report.populations:
        cell = limes_row.cell(population)
        if cell.is_cost:
            lines.append(f"- **{population}:** {cell.render()} killed.")
    if power is not None:
        lines.append(
            f"- **Power of the false-positive claim:** n={power.samples}, "
            f"alpha={power.threshold}, minimum detectable effect "
            f"~= {power.minimum_detectable_effect:.3f} ({power.effect_unit})."
        )
    lines += [
        "",
        "## The protocol",
        "",
        "Split by **template**, never by materialised case: one template becomes as many "
        "cases as its category has vectors, so splitting the cases would put the same "
        "template on both sides and a rule written on `dev` would score on `holdout` by "
        "identity rather than by generalisation. A test asserts no template appears on "
        "both sides.",
        "",
        "Splits scored here: " + ", ".join(f"`{s}`" for s in report.splits) + ".",
        "",
    ]
    return "\n".join(lines)


def render_secrets(report: SecretsReport, when: str) -> str:
    """Render the secrets bench as a Markdown matrix."""
    lines = [
        "# limes `secrets-egress` — against the industry's credential catalogue",
        "",
        f"Generated {when} from **gitleaks** ({report.source_license}, commit "
        f"`{report.source_commit}`, <{report.source_url}>) — "
        f"{report.catalogue_rules} catalogue rules, of which **{report.materialised}** "
        "materialise into a self-verified instance, vendored by value into "
        "`eval/corpus/gitleaks/` (ADR 0021). limes does not depend on gitleaks; the "
        "corpus is a copy, reproducible with `scripts/vendor_gitleaks_corpus.py`.",
        "",
        f"**Strength of this number.** {report.corpus_strength}",
        "",
        "**What this table is asking.** Not *do my eight rules find my eight formats* — "
        "the internal matrix answers that, 15/15. This asks how much of what the "
        "industry calls a credential limes sees at all.",
        "",
    ]
    lines += _matrix(report.rows, report.populations)
    lines += [
        "",
        "- **formats located** — a finding falling wholly inside the vendored instance. "
        "gitleaks' patterns often carry their own context keywords, so the instance may "
        "read `apikey = <secret>` rather than the bare credential and an exact-span rule "
        "would score a correct finding as a miss. `block-everything` still scores zero: "
        "it spans the carrier line too.",
        "- **hard negatives** — gitleaks' *own* false-positive vectors: placeholder runs, "
        "wrong-length keys, a Finnish sentence, a DNA fragment. Precision measured on "
        "ground limes did not choose.",
        "",
        "## What limes catches, and what it does not",
        "",
    ]
    if report.caught:
        lines.append(
            f"**Located ({len(report.caught)} of {report.materialised}):** "
            + ", ".join(f"`{name}`" for name in report.caught)
        )
    else:
        lines.append("**Located: none.**")
    lines += [
        "",
        f"The remaining {report.materialised - len(report.caught)} are formats limes "
        "ships no rule for. That is not a bug being reported here — the README has always "
        "said the perimeter is eight vendor prefixes plus PEM and JWT, and that generic "
        "high-entropy scanning is a declared non-capability. What this table adds is the "
        "**size** of that perimeter, measured against somebody else's census instead of "
        "asserted in prose.",
        "",
        "## Blind spots — formats nobody could materialise",
        "",
        "A rule this harness could not instantiate is **not** a rule the detector missed, "
        "and is excluded from the denominator above (ADR 0015).",
        "",
        "| gitleaks rule | why |",
        "|---|---|",
    ]
    for rule, reason in report.blind_spots:
        lines.append(f"| `{rule}` | {reason} |")

    power = sign_test_power(next(cell.total for cell in report.rows[0].cells if cell.is_cost))
    lines += ["", "## The two numbers", ""]
    limes_row = report.rows[-1]
    for split in report.splits:
        cell = limes_row.cell(f"formats located ({split})")
        lines.append(f"- **Formats located ({split}):** {cell.render()}.")
    negatives = limes_row.cell("gitleaks' own hard negatives")
    lines.append(f"- **gitleaks' own hard negatives killed:** {negatives.render()}.")
    if report.negatives_killed:
        lines.append("  Named: " + ", ".join(f"`{name}`" for name in report.negatives_killed[:12]))
    if power is not None:
        lines.append(
            f"- **Power of the false-positive claim:** n={power.samples}, "
            f"alpha={power.threshold}, minimum detectable effect "
            f"~= {power.minimum_detectable_effect:.3f} ({power.effect_unit})."
        )
    lines += [
        "",
        "## The protocol",
        "",
        "Split by **rule id**, which is this corpus's template: a rule id names a format, "
        "and a format is what a detector meets. A test asserts no rule id appears on both "
        "sides.",
        "",
        "Splits scored here: " + ", ".join(f"`{s}`" for s in report.splits) + ".",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """CLI entry point for ``python -m limes.eval.external_egress_harness``."""
    parser = argparse.ArgumentParser(description="limes egress vs external adversaries")
    parser.add_argument("bench", choices=("pii", "secrets"), help="which bench to score")
    parser.add_argument(
        "--split",
        choices=("dev", "all"),
        default="dev",
        help="dev (default, safe to iterate against) or all (dev + holdout, for the record)",
    )
    parser.add_argument("--write", action="store_true", help="write the matrix to disk")
    arguments = parser.parse_args()

    splits = ("dev", "holdout") if arguments.split == "all" else ("dev",)
    try:
        if arguments.bench == "pii":
            markdown = render_pii(compute_pii(splits), when=date.today().isoformat())
        else:
            markdown = render_secrets(compute_secrets(splits), when=date.today().isoformat())
    except ExternalCorpusUnavailable as unavailable:
        # A blind spot, reported as one (ADR 0015): not an empty table.
        raise SystemExit(f"cannot say: {unavailable}") from unavailable

    print(markdown)
    if arguments.write:
        out = _MATRICES / f"external_{arguments.bench}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown + "\n", encoding="utf-8")
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
