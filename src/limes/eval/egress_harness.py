"""The egress detector admission harness — the two numbers, per category (ADR 0003).

The same discipline as :mod:`limes.eval.harness`, with one change that is the
whole point of this file.

**The grader reads the offsets, not the text.** An injection is graded by "was it
blocked"; a leak cannot be, because *everything* is blocked by a detector that
fires on everything. So a positive case here declares the exact substring that
must be spanned (``locate``), and a case counts as **located** only when a
finding's ``[start, end)`` reproduces that substring at that offset. The
consequence is mechanical and it is the point: ``block-everything`` — which
spans the whole message — scores **0 located** while killing every benign input.
It is flagged everywhere and right nowhere. No token the case handed the
detector can be mistaken for evidence that the detector found something, which
is the egress form of the corrected-grader rule limes inherits (ADR 0003;
Tessera ADR 0028 §5).

**Four configurations**, so the detector's worth is a delta and never a bare
score: the unplugged null control (locates 0), block-everything (kills all),
the ported baseline where one exists, and the limes detector.

**A per-category matrix**, because a single F1 over five categories hides which
one is broken. Recall is reported per category; precision is reported over the
benign corpus, attributed to the category each lookalike imitates.

Run ``python -m limes.eval.egress_harness pii-egress`` to print the matrix,
``--write`` to also write it to ``eval/matrices/<detector>.md``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Final, final

from limes.detector import Context, Detector, Direction, Finding
from limes.detectors import ADMITTED
from limes.eval.egress_corpus import BenignCase, PositiveCase, load_benign, load_positive
from limes.eval.power import NoEffect, sign_test_power
from limes.guard import decide
from limes.spans import RedactedSpan, redact
from limes.verdict import Deny

__all__ = [
    "BASELINES",
    "CategoryScore",
    "ConfigResult",
    "Report",
    "compute",
    "render",
]

# The harness is deterministic; evidence timestamps are fixed data, not now().
_OBSERVED_AT = "2026-07-24T00:00:00Z"

_MATRICES = Path(__file__).resolve().parents[3] / "eval" / "matrices"

_UNPLUGGED = "unplugged (null control)"
_BLOCK_EVERYTHING = "block-everything"


class _BlockEverything:
    """The guard's null control: flag every non-empty output (trivially safe, useless).

    It spans the whole message, so under the located-span grader it scores zero
    true positives while killing every benign input. That is not a quirk of the
    scoring — it is the scoring working.
    """

    id = "block-everything"
    version = "0.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        """Return one finding spanning the entire content."""
        del ctx
        if direction is not Direction.OUTBOUND or not content:
            return []
        return [
            Finding(
                detector_id=self.id,
                label="block-all",
                spans=(redact(content, 0, len(content), "block-all"),),
            )
        ]


@final
@dataclass(frozen=True, slots=True)
class CategoryScore:
    """What one configuration did on one category.

    Attributes:
        category: The category name, e.g. ``"pan"``.
        n_positive: How many positive cases carry this category.
        located: How many were spanned exactly.
        flagged: How many produced any finding at all — the gap against
            ``located`` is where a detector fired on the wrong bytes.
        n_benign: How many benign lookalikes imitate this category.
        benign_killed: How many of them wrongly produced a finding.
    """

    category: str
    n_positive: int
    located: int
    flagged: int
    n_benign: int
    benign_killed: int

    @property
    def recall(self) -> float:
        """Fraction of this category's values located exactly."""
        return self.located / self.n_positive if self.n_positive else 0.0


@final
@dataclass(frozen=True, slots=True)
class ConfigResult:
    """The confusion counts for one configuration over the whole corpus."""

    name: str
    n_positive: int
    located: int
    flagged: int
    n_benign: int
    benign_killed: int
    by_category: tuple[CategoryScore, ...]
    missed: tuple[str, ...]
    killed_benign: tuple[str, ...]

    @property
    def recall(self) -> float:
        """Fraction of positive cases located exactly."""
        return self.located / self.n_positive if self.n_positive else 0.0

    @property
    def fp_rate(self) -> float:
        """Fraction of benign inputs wrongly flagged."""
        return self.benign_killed / self.n_benign if self.n_benign else 0.0

    @property
    def precision(self) -> float:
        """Precision over the flagged set, counting benign hits as false positives."""
        tp, fp = self.located, self.benign_killed
        return tp / (tp + fp) if (tp + fp) else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@final
@dataclass(frozen=True, slots=True)
class Report:
    """The full harness result for one detector."""

    detector: str
    configs: tuple[ConfigResult, ...]
    null_control: str
    baseline_verdict: str

    def by_name(self, name: str) -> ConfigResult:
        """Return the configuration result named ``name``."""
        for config in self.configs:
            if config.name == name:
                return config
        raise KeyError(name)

    @property
    def subject(self) -> ConfigResult:
        """The configuration under test — the limes detector."""
        return self.by_name(f"limes {self.detector}")


def _spans(detectors: Sequence[Detector], content: str) -> tuple[RedactedSpan, ...]:
    """Run the real pipeline and return whatever spans the verdict carries."""
    ctx = Context(policy_hash="eval", actor=None)
    verdict = decide(Direction.OUTBOUND, content, ctx, detectors, observed_at=_OBSERVED_AT)
    return verdict.evidence.matched_spans if isinstance(verdict, Deny) else ()


def _locates(case: PositiveCase, spans: Sequence[RedactedSpan]) -> bool:
    """Whether some span reproduces the case's declared value, exactly.

    The label is deliberately *not* compared: what an egress guard owes is that
    the value was found and can be masked. Which category name it filed the value
    under is a reporting question, and holding the ported baseline to limes's own
    category names would flatter limes rather than measure it.
    """
    offset = case.offset
    return any(
        span.start == offset and case.content[span.start : span.end] == case.locate
        for span in spans
    )


def _run(
    name: str,
    detectors: Sequence[Detector],
    positive: Sequence[PositiveCase],
    benign: Sequence[BenignCase],
) -> ConfigResult:
    """Score one configuration over the corpus."""
    located_ids: set[str] = set()
    flagged_ids: set[str] = set()
    for case in positive:
        spans = _spans(detectors, case.content)
        if spans:
            flagged_ids.add(case.case_id)
        if _locates(case, spans):
            located_ids.add(case.case_id)

    killed = tuple(case.case_id for case in benign if _spans(detectors, case.content))
    killed_set = set(killed)

    by_category: list[CategoryScore] = []
    for category in sorted({case.category for case in positive}):
        cases = [case for case in positive if case.category == category]
        lookalikes = [case for case in benign if case.mimics == category]
        by_category.append(
            CategoryScore(
                category=category,
                n_positive=len(cases),
                located=sum(1 for case in cases if case.case_id in located_ids),
                flagged=sum(1 for case in cases if case.case_id in flagged_ids),
                n_benign=len(lookalikes),
                benign_killed=sum(1 for case in lookalikes if case.case_id in killed_set),
            )
        )

    return ConfigResult(
        name=name,
        n_positive=len(positive),
        located=len(located_ids),
        flagged=len(flagged_ids),
        n_benign=len(benign),
        benign_killed=len(killed),
        by_category=tuple(by_category),
        missed=tuple(case.case_id for case in positive if case.case_id not in located_ids),
        killed_benign=killed,
    )


def _null_control(subject: ConfigResult, unplugged: ConfigResult) -> str:
    """State the delta against doing nothing, with the power that licenses it."""
    if subject.located <= unplugged.located:
        return (
            f"REFUSED — {subject.name} locates {subject.located}/{subject.n_positive}, no better "
            f"than the unplugged guard's {unplugged.located}. A detector that does not "
            f"measurably beat doing nothing does not enter (ADR 0003)."
        )
    power = sign_test_power(subject.n_benign)
    if power is None:
        return (
            f"CANNOT SAY — n={subject.n_benign} benign inputs is too small to power any "
            f"claim about false positives (a witness that cannot see may never report 'ok')."
        )
    effect = NoEffect(
        claim=(
            f"{subject.name} locates {subject.located}/{subject.n_positive} against the unplugged "
            f"control's {unplugged.located}/{subject.n_positive}, and kills "
            f"{subject.benign_killed}/{subject.n_benign} benign inputs"
        ),
        power=power,
    )
    return (
        f"ADMITTED — {effect.claim}. Power on the benign claim: n={power.samples}, "
        f"alpha={power.threshold}, minimum detectable effect ~= "
        f"{power.minimum_detectable_effect:.3f} ({power.effect_unit}). A smaller "
        f"false-positive rate than that would be invisible here — grow the benign corpus."
    )


def _baseline_verdict(subject: ConfigResult, baseline: ConfigResult | None) -> str:
    """State how the subject compares to the ported baseline, or that there is none."""
    if baseline is None:
        return (
            "NO BASELINE — nothing comparable ships elsewhere for this detector, so the "
            "**null control is the baseline**. The number to read is the delta against the "
            "unplugged guard, and no comparison is invented to dress it up (ADR 0003)."
        )
    verdict = "beats" if subject.located > baseline.located else "does not beat"
    regressions = sorted(set(subject.killed_benign) - set(baseline.killed_benign))
    tail = (
        f" It REGRESSES on {len(regressions)} benign input(s) the baseline allows: "
        f"{', '.join(regressions)}."
        if regressions
        else " It adds no false positive the baseline does not already make."
    )
    return (
        f"{subject.name} {verdict} {baseline.name}: {subject.located}/{subject.n_positive} "
        f"located against {baseline.located}/{baseline.n_positive}, "
        f"{subject.benign_killed}/{subject.n_benign} benign killed against "
        f"{baseline.benign_killed}/{baseline.n_benign}.{tail}"
    )


def _pii_baseline() -> Detector:
    """The ported Tessera output guard, built lazily so the map stays cheap."""
    from limes.baselines.tessera_pii import TesseraPiiBaseline

    return TesseraPiiBaseline()


#: Which ported baseline, if any, each detector is measured against. A detector
#: absent from this map has none — and says so, rather than inventing one.
BASELINES: Final[Mapping[str, tuple[str, Callable[[], Detector]]]] = {
    "pii-egress": ("tessera-pii baseline (apply_output_guard)", _pii_baseline),
}


def _detector_for(detector_id: str) -> Detector:
    """Build the limes detector named by ``detector_id``.

    Args:
        detector_id: The detector to build.

    Returns:
        The detector instance.

    Raises:
        KeyError: If no egress detector goes by that name — which is what makes
            adding a name to ``ADMITTED`` without a corpus fail loudly rather
            than measure nothing (ADR 0003).
    """
    for admitted in ADMITTED:
        if admitted.id == detector_id:
            return admitted()
    raise KeyError(f"no egress detector named {detector_id!r}")


def compute(detector_id: str) -> Report:
    """Run every configuration over ``detector_id``'s corpus and return the report.

    Args:
        detector_id: The detector to admit, e.g. ``"pii-egress"``.

    Returns:
        The report: four configurations (three when there is no ported
        baseline), the null-control statement, and the baseline verdict.
    """
    positive = load_positive(detector_id)
    benign = load_benign(detector_id)

    configs = [
        _run(_UNPLUGGED, (), positive, benign),
        _run(_BLOCK_EVERYTHING, (_BlockEverything(),), positive, benign),
    ]
    baseline_entry = BASELINES.get(detector_id)
    baseline_result: ConfigResult | None = None
    if baseline_entry is not None:
        baseline_name, factory = baseline_entry
        baseline_result = _run(baseline_name, (factory(),), positive, benign)
        configs.append(baseline_result)
    subject = _run(f"limes {detector_id}", (_detector_for(detector_id),), positive, benign)
    configs.append(subject)

    return Report(
        detector=detector_id,
        configs=tuple(configs),
        null_control=_null_control(subject, configs[0]),
        baseline_verdict=_baseline_verdict(subject, baseline_result),
    )


def _why(detector_id: str, case_ids: Sequence[str]) -> list[str]:
    """Render the documented cause of each miss — never a bare count (ADR 0003)."""
    reasons = {case.case_id: case.why for case in load_positive(detector_id)}
    return [f"- `{case_id}` — {reasons.get(case_id, 'no recorded reason')}" for case_id in case_ids]


def _why_benign(detector_id: str, case_ids: Sequence[str]) -> list[str]:
    """Render what each false positive was, and what it cost.

    A false positive reported as an id is a number; reported with the case's own
    ``why`` it is a defect somebody can act on — which is the difference ADR 0003
    is about.
    """
    cases = {case.case_id: case for case in load_benign(detector_id)}
    detector = _detector_for(detector_id)
    lines: list[str] = []
    for case_id in case_ids:
        case = cases.get(case_id)
        if case is None:
            lines.append(f"- `{case_id}` — no recorded reason")
            continue
        fired = ", ".join(
            f"`{span.label}` on `{case.content[span.start : span.end]}`"
            for span in _spans((detector,), case.content)
        )
        lines.append(f"- `{case_id}` (mimics **{case.mimics}**) — {case.why}")
        lines.append(f"  - Content: `{case.content}`")
        lines.append(f"  - What actually fired: {fired or 'nothing (the case no longer fails)'}")
    return lines


def render(report: Report, when: str) -> str:
    """Render the report as a dated Markdown confusion matrix."""
    subject = report.subject
    lines = [
        f"# limes `{report.detector}` — confusion matrix",
        "",
        f"Generated {when} over the synthetic egress corpus "
        f"({subject.n_positive} positive cases across "
        f"{len(subject.by_category)} categories, fr/de/en; "
        f"{subject.n_benign} benign lookalikes). Every value is synthetic by construction "
        "and may never be a real one (ADR 0009).",
        "",
        "**How a hit is counted.** A positive case declares the exact substring that must be "
        "spanned. A finding counts only when its `[start, end)` reproduces that substring at "
        "that offset — so a detector that fires on the whole message is *flagged* everywhere "
        "and *located* nowhere. Read the `located` column, not the `flagged` one.",
        "",
        "| configuration | located | flagged | benign killed | recall | precision | F1 |",
        "|---|---|---|---|---|---|---|",
    ]
    for config in report.configs:
        emphasis = "**" if config is subject else ""
        lines.append(
            f"| {emphasis}{config.name}{emphasis} "
            f"| {emphasis}{config.located}/{config.n_positive}{emphasis} "
            f"| {config.flagged}/{config.n_positive} "
            f"| {emphasis}{config.benign_killed}/{config.n_benign}{emphasis} "
            f"| {config.recall:.2f} | {config.precision:.2f} | {config.f1:.2f} |"
        )

    lines += [
        "",
        "## Per category",
        "",
        "| category | " + " | ".join(config.name for config in report.configs) + " | lookalikes |",
        "|---" * (len(report.configs) + 2) + "|",
    ]
    for index, score in enumerate(subject.by_category):
        cells = []
        for config in report.configs:
            other = config.by_category[index]
            cells.append(f"{other.located}/{other.n_positive}")
        lines.append(
            f"| **{score.category}** | "
            + " | ".join(cells)
            + f" | {score.benign_killed}/{score.n_benign} killed |"
        )

    lines += [
        "",
        "## The two numbers",
        "",
        f"- **Values located:** {subject.located}/{subject.n_positive} "
        f"(the unplugged guard locates 0/{subject.n_positive}).",
        f"- **Legitimate output killed:** {subject.benign_killed}/{subject.n_benign} "
        f"(block-everything kills {subject.n_benign}/{subject.n_benign} while locating "
        f"{report.by_name(_BLOCK_EVERYTHING).located}/{subject.n_positive}).",
        "",
        "## Null control",
        "",
        report.null_control,
        "",
        "## Baseline",
        "",
        report.baseline_verdict,
        "",
        "## What still fails, and why",
        "",
    ]
    lines += _why(report.detector, subject.missed) or [
        "Nothing in this corpus. That is a statement about this corpus, not about the world: "
        "the corpus grows adversarially (ADR 0003)."
    ]
    if subject.killed_benign:
        lines += [
            "",
            "## False positives — what fired, and what it cost",
            "",
            *_why_benign(report.detector, subject.killed_benign),
        ]
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """CLI entry point for ``python -m limes.eval.egress_harness``."""
    parser = argparse.ArgumentParser(description="limes egress detector admission harness")
    parser.add_argument("detector", help="detector id, e.g. pii-egress")
    parser.add_argument("--write", action="store_true", help="write the confusion matrix to disk")
    parser.add_argument("--out", type=Path, default=None, help="output path for the matrix")
    args = parser.parse_args()
    report = compute(args.detector)
    markdown = render(report, when=date.today().isoformat())
    print(markdown)
    if args.write:
        out = args.out or _MATRICES / f"{args.detector.replace('-', '_')}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown + "\n", encoding="utf-8")
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
