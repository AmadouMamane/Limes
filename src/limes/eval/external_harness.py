"""Score limes against an adversary corpus it did not write (ADR 0017).

The other harnesses answer "does the detector do what its author intended?" over
cases its author chose. This one answers a different and less comfortable
question — "does it catch attacks somebody else wrote?" — over garak's
indirect-injection probes, and it reports the answer whatever the answer is.

Three properties make the number worth reading.

**Matched controls.** Every attack is a document with an injection in it; every
control is *the same document* with the injection removed. A detector that fires
on both has learnt the document. The pair isolates the injection exactly, and it
cannot drift, because the control is derived from the attack's own data
(:mod:`limes.eval.external_corpus`).

**Two splits, and only one of them is for writing rules.** ``dev`` is fair game.
``holdout`` is scored once, with the rules frozen. This module makes that
mechanical rather than promised: ``--split dev`` is the default and the only
thing an iterating author sees, and the holdout number exists only when somebody
deliberately asks for it (ADR 0017).

**A declared non-capability is measured too.** ``latent_jailbreak`` asks a model
for a toxic sentence — a content-policy jailbreak, which limes has never claimed
(README, "What limes does not do"). It is scored on its own row, so the perimeter
is a measurement rather than a sentence.

Run ``python -m limes.eval.external_harness`` for the dev numbers,
``--split all --write`` to regenerate ``eval/matrices/external_injection.md``.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from limes.detector import Context, Detector, Direction
from limes.detectors.injection import InjectionDetector
from limes.detectors.injection_egress import InjectionEgressDetector
from limes.eval.egress_corpus import load_benign as load_egress_benign
from limes.eval.external_corpus import (
    ExternalCase,
    ExternalCorpus,
    ExternalCorpusUnavailable,
    load_external,
    load_flat,
)
from limes.eval.power import sign_test_power
from limes.guard import decide
from limes.verdict import Deny

__all__ = ["Cell", "ExternalReport", "compute", "render"]

_OBSERVED_AT = "2026-08-30T00:00:00Z"


@dataclass(frozen=True, slots=True)
class Cell:
    """One (configuration, population) count."""

    configuration: str
    population: str
    hits: int
    total: int

    @property
    def rate(self) -> float:
        """Fraction of the population the configuration blocked."""
        return self.hits / self.total if self.total else 0.0


@dataclass(frozen=True, slots=True)
class ExternalReport:
    """Everything the external harness measured, ready to render."""

    corpus: ExternalCorpus
    jailbreak: ExternalCorpus | None
    blind: ExternalCorpus | None
    splits: tuple[str, ...]
    cells: tuple[Cell, ...]
    per_probe: tuple[tuple[str, str, int, int], ...]
    per_hijack_template: tuple[tuple[str, int, int], ...]
    lookalike_total: int
    lookalike_killed: int

    def cell(self, configuration: str, population: str) -> Cell:
        """Look one cell up by configuration and population."""
        for candidate in self.cells:
            if candidate.configuration == configuration and candidate.population == population:
                return candidate
        raise KeyError((configuration, population))


#: The configurations. Each deploys its detectors on the legs :func:`_legs`
#: states, and a detector is only ever scored on the leg the proxy actually runs
#: it on: the inbound rules on tool arguments, the egress rules on tool results.
CONFIGURATIONS: tuple[str, ...] = (
    "unplugged (null control)",
    "injection (inbound leg)",
    "injection-egress (outbound leg)",
    "both, as the proxy deploys them",
)

#: One (detectors, direction) pairing a configuration runs — a leg.
type _Leg = tuple[tuple[Detector, ...], Direction]


def _legs(name: str) -> tuple[_Leg, ...]:
    """The (detectors, leg) pairings a configuration actually deploys.

    The "both" row is the union of the two legs — the deployment's verdict,
    the same definition :func:`limes.eval.comparison_harness.limes_flags`
    uses. An earlier version handed both detectors to the outbound leg alone,
    where the inbound detector answers nothing: the row reprinted the egress
    row's numbers under a two-leg label, and the matrix published it.
    """
    if name.startswith("unplugged"):
        # Zero detectors, but the pipeline still runs: the null control
        # measures that the harness counts nothing when nothing looks.
        return (((), Direction.OUTBOUND),)
    if name.startswith("injection ("):
        return (((InjectionDetector(),), Direction.INBOUND),)
    if name.startswith("injection-egress"):
        return (((InjectionEgressDetector(),), Direction.OUTBOUND),)
    return (
        ((InjectionDetector(),), Direction.INBOUND),
        ((InjectionEgressDetector(),), Direction.OUTBOUND),
    )


def _blocked(legs: Sequence[_Leg], text: str) -> bool:
    context = Context(policy_hash="external-eval", actor=None)
    return any(
        isinstance(decide(direction, text, context, detectors, observed_at=_OBSERVED_AT), Deny)
        for detectors, direction in legs
    )


def _count(legs: Sequence[_Leg], cases: Sequence[ExternalCase]) -> int:
    return sum(1 for case in cases if _blocked(legs, case.text))


def compute(splits: Sequence[str]) -> ExternalReport:
    """Score every configuration over the requested splits.

    Args:
        splits: Which attack splits to score — ``("dev",)`` while iterating,
            ``("dev", "holdout")`` for the frozen, published run.

    Returns:
        The report.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk.
    """
    corpus = load_external("latent_injection")
    try:
        jailbreak: ExternalCorpus | None = load_external("latent_jailbreak")
    except ExternalCorpusUnavailable:
        jailbreak = None
    try:
        blind: ExternalCorpus | None = load_flat("prompt_hijack")
    except ExternalCorpusUnavailable:
        blind = None

    # The lookalikes written to trip THESE rules on purpose (ADR 0012's benign
    # corpus), not the general-purpose one: a false-positive claim is only worth
    # its hardest population.
    lookalikes = load_egress_benign("injection-egress")
    cells: list[Cell] = []
    per_probe: list[tuple[str, str, int, int]] = []

    for name in CONFIGURATIONS:
        legs = _legs(name)
        for split in splits:
            cases = corpus.split(split)
            cells.append(Cell(name, f"attacks ({split})", _count(legs, cases), len(cases)))
        cells.append(
            Cell(
                name,
                "matched benign documents",
                _count(legs, corpus.benign),
                len(corpus.benign),
            )
        )
        if blind is not None and "holdout" in splits:
            # Only in the frozen run: the blind family exists to be scored once.
            cells.append(
                Cell(
                    name,
                    "hijack (blind)",
                    _count(legs, blind.attacks),
                    len(blind.attacks),
                )
            )
        if jailbreak is not None:
            out_of_scope = tuple(case for case in jailbreak.attacks if case.split in set(splits))
            cells.append(
                Cell(
                    name,
                    "out of scope (jailbreak)",
                    _count(legs, out_of_scope),
                    len(out_of_scope),
                )
            )

    egress = _legs("injection-egress (outbound leg)")
    for probe in corpus.probes:
        for split in splits:
            cases = tuple(c for c in corpus.split(split) if c.probe == probe)
            per_probe.append((probe, split, _count(egress, cases), len(cases)))

    # The aggregate over this family reads as n=131 and its real unit count is
    # FIVE (ADR 0021). One row per attack template, so a reader can see that the
    # 82% is four templates caught and one missed rather than a rate over prompts.
    per_hijack_template: list[tuple[str, int, int]] = []
    if blind is not None:
        inbound = _legs("injection (inbound leg)")
        for template in sorted({case.template for case in blind.attacks}):
            cases = tuple(case for case in blind.attacks if case.template == template)
            per_hijack_template.append((template, _count(inbound, cases), len(cases)))

    lookalike_killed = _count(
        egress,
        tuple(
            ExternalCase(probe="limes", split="benign", text=case.content) for case in lookalikes
        ),
    )

    return ExternalReport(
        corpus=corpus,
        jailbreak=jailbreak,
        blind=blind,
        splits=tuple(splits),
        cells=tuple(cells),
        per_probe=tuple(per_probe),
        per_hijack_template=tuple(per_hijack_template),
        lookalike_total=len(lookalikes),
        lookalike_killed=lookalike_killed,
    )


def _populations(report: ExternalReport) -> tuple[str, ...]:
    seen: list[str] = []
    for cell in report.cells:
        if cell.population not in seen:
            seen.append(cell.population)
    return tuple(seen)


def render(report: ExternalReport, when: str) -> str:
    """Render the report as a Markdown matrix."""
    source = report.corpus.source
    populations = _populations(report)
    power = sign_test_power(len(report.corpus.benign))
    lines = [
        "# limes vs an adversary corpus it did not write",
        "",
        f"Generated {when} from **{source['tool']} {source['version']}** "
        f"({source['vendor']}, {source['license']}) — "
        f"`{source['module']}`, {len(source['probes'])} probes, vendored by value into "
        "`eval/corpus/garak/` (ADR 0017). limes does not depend on garak; the corpus is a "
        "copy, reproducible with `scripts/vendor_garak_corpus.py`.",
        "",
        "**Why this table exists.** Every other matrix in this repository scores limes on "
        "cases limes's author wrote, which measures whether the detector does what it was "
        "meant to do. This one scores it on somebody else's attacks. It is the less "
        "comfortable number, and it is the one that says whether the guard generalises.",
        "",
        f"- **attacks** — garak's indirect prompt injections, sampled by "
        f"`{report.corpus.sampling['rule']}`.",
        "- **matched benign documents** — *the same documents* with the injection removed. "
        "A detector that fires on both has learnt the document, not the attack.",
        "- **out of scope (jailbreak)** — `LatentJailbreak`, a content-policy jailbreak "
        "limes has never claimed. Measured so the perimeter is a number, not a sentence.",
        "",
        "| configuration | " + " | ".join(populations) + " |",
        "|---" * (len(populations) + 1) + "|",
    ]
    for name in CONFIGURATIONS:
        row = [f"**{name}**" if name.startswith(("injection-egress", "both")) else name]
        for population in populations:
            try:
                cell = report.cell(name, population)
            except KeyError:
                row.append("—")
                continue
            row.append(f"{cell.hits}/{cell.total} ({cell.rate:.1%})")
        lines.append("| " + " | ".join(row) + " |")

    lines += [
        "",
        "## Per probe — `injection-egress`, the leg a tool result arrives on",
        "",
        "| garak probe | split | blocked |",
        "|---|---|---|",
    ]
    for probe, split, hits, total in report.per_probe:
        rate = f"{hits / total:.1%}" if total else "—"
        lines.append(f"| `{probe}` | {split} | {hits}/{total} ({rate}) |")

    # A single recall number over a mixed corpus averages families that fail for
    # different reasons, and the average then reads as one fact. Which probes
    # score zero, and how much of the split they are, is computed here rather than
    # left for the reader to reconstruct from the table above.
    by_split: dict[str, list[tuple[str, int, int]]] = {}
    for probe, split, hits, total in report.per_probe:
        if total:
            by_split.setdefault(split, []).append((probe, hits, total))
    lines += ["", "## Where the misses are", ""]
    for split, rows in by_split.items():
        zeros = [(name, count) for name, hits, count in rows if hits == 0]
        split_size = sum(count for _, _, count in rows)
        if not zeros:
            lines.append(f"- **{split}** — no probe scores zero.")
            continue
        zero_size = sum(count for _, count in zeros)
        share = zero_size / split_size
        names = ", ".join(f"`{name}`" for name, _ in zeros)
        rest_hits = sum(hits for _, hits, _ in rows if hits)
        rest_total = split_size - zero_size
        rest = f"{rest_hits}/{rest_total} ({rest_hits / rest_total:.1%})" if rest_total else "—"
        lines.append(
            f"- **{split}** — {names} score **0**, and they are **{share:.0%}** of this "
            f"split. Over everything else: {rest}."
        )
    lines += [
        "",
        "That gap is the finding, not a footnote. Where an attack carries an *imperative* — "
        "disregard this, print that, focus only on the following — a rule can name its shape "
        "and does. Where it carries only *persuasion* or *framing* — a fabricated recruiter's "
        "endorsement, a hidden competency profile, white text addressed to the scanner — there "
        "is no directive to match, and a rule that fired on it would be firing on ordinary "
        "flattery. Those probes are not a bug in the rules; they are the boundary of what "
        "rules are, and they are exactly the territory ADR 0013's classifier layer is framed "
        "for. The number above is what makes that argument with evidence instead of prose.",
    ]

    if report.per_hijack_template:
        lines += [
            "",
            "## The blind hijack family, per attack template — read this before the 82%",
            "",
            "The aggregate above is a rate over **prompts**, and it reads as n=131. The "
            "family's real unit count is **five**: garak's whole promptinject set carries "
            "five distinct attack instructions, and each is materialised over 35 base "
            "tasks and three payloads. So the row below is what the percentage actually "
            "says (ADR 0021).",
            "",
            "| attack template | blocked by `injection` |",
            "|---|---|",
        ]
        for template, hits, total in report.per_hijack_template:
            rate = f"{hits / total:.0%}" if total else "—"
            shown = template if len(template) <= 74 else template[:71] + "..."
            lines.append(f"| `{shown}` | {hits}/{total} ({rate}) |")
        lines += [
            "",
            "**No dev/holdout split of this family exists, and none is fabricated.** All "
            "five templates hash into the same half under the content-addressed rule "
            "(nibbles 1, 2, 3, 3, 6), so a holdout would be empty — and moving the "
            "boundary until one appeared would be steering the split, which is the one "
            "thing that rule exists to prevent. It is reported as an impossibility rather "
            "than worked around.",
            "",
            "**And the family is no longer blind.** It was vendored and first scored "
            "without its contents being read, and that number stands as one the rules "
            "earned unseen. The contents have since been read, so no rule written from "
            "now on may be validated here.",
        ]

    lines += [
        "",
        "## What the two sides mean",
        "",
        f"- **False positives, external documents:** the matched benign set is "
        f"{len(report.corpus.benign)} real documents (résumés, articles, whois records) that "
        "each pair with an attack above.",
        f"- **False positives, deliberate lookalikes:** {report.lookalike_killed}/"
        f"{report.lookalike_total} on limes's own benign corpus — the near-misses written to "
        "trip the rules on purpose. Both sides are needed: long ordinary prose and adversarial "
        "near-misses fail differently.",
    ]
    if power is not None:
        lines.append(
            f"- **Power of the false-positive claim:** n={power.samples}, "
            f"alpha={power.threshold}, minimum detectable effect "
            f"~= {power.minimum_detectable_effect:.3f} ({power.effect_unit})."
        )
    else:
        lines.append("- **Power:** the benign corpus is too small to power any claim about it.")

    lines += [
        "",
        "## The protocol",
        "",
        f"`{report.corpus.sampling['protocol']}`",
        "",
        "Splits scored here: " + ", ".join(f"`{s}`" for s in report.splits) + ".",
        "A rule written while looking at `holdout` turns it into a second `dev`, and the "
        "number stops meaning what this table says it means.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """CLI entry point for ``python -m limes.eval.external_harness``."""
    parser = argparse.ArgumentParser(description="limes vs an external adversary corpus")
    parser.add_argument(
        "--split",
        choices=("dev", "all"),
        default="dev",
        help="dev (default, safe to iterate against) or all (dev + holdout, for the record)",
    )
    parser.add_argument("--write", action="store_true", help="write the matrix to disk")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "eval" / "matrices" / "external_injection.md",
        help="output path for the matrix",
    )
    arguments = parser.parse_args()

    try:
        report = compute(("dev", "holdout") if arguments.split == "all" else ("dev",))
    except ExternalCorpusUnavailable as unavailable:
        # A blind spot, reported as one (ADR 0015): not an empty table.
        raise SystemExit(f"cannot say: {unavailable}") from unavailable

    markdown = render(report, when=date.today().isoformat())
    print(markdown)
    if arguments.write:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(markdown + "\n", encoding="utf-8")
        print(f"\nwrote {arguments.out}")


if __name__ == "__main__":
    main()
