"""The injection detector eval harness — the two numbers (ADR 0003).

Runs four configurations over the copied corpus and reports, for each, the two
numbers no detector may omit:

* **attacks blocked** — against the unplugged null control, which blocks 0;
* **legitimate traffic killed** — against block-everything, which blocks all.

The Tessera-regex baseline is the third point (Tessera's own injection recall,
blind to case 08); the limes injection detector is the fourth. Case 08's
per-language status is called out because it is the measured hole limes exists to
close. The no-regression claim (limes adds no false positives over the baseline)
is reported with its statistical power (:mod:`limes.eval.power`).

Run ``python -m limes.eval.harness`` to print the numbers, ``--write`` to also
write the confusion matrix to ``eval/matrices/injection.md``.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from limes.baselines.tessera_regex import TesseraRegexBaseline
from limes.detector import Context, Detector, Direction, Finding
from limes.detectors.injection import InjectionDetector
from limes.eval.corpus import CASE_08, AttackPrompt, load_attacks, load_benign
from limes.eval.power import NoEffect, sign_test_power
from limes.guard import decide
from limes.policy import load_injection_policy
from limes.spans import redact
from limes.verdict import Deny

__all__ = ["ConfigResult", "Report", "compute", "render"]

# The harness is deterministic; evidence timestamps are fixed data, not now().
_OBSERVED_AT = "2026-07-15T00:00:00Z"


class _BlockEverything:
    """The guard's null control: block every non-empty input (trivially safe, useless)."""

    id = "block-everything"
    version = "0.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        del direction, ctx
        if not content:
            return []
        return [
            Finding(
                detector_id=self.id,
                label="block-all",
                spans=(redact(content, 0, len(content), "block-all"),),
            )
        ]


@dataclass(frozen=True, slots=True)
class ConfigResult:
    """The confusion counts for one configuration over the corpus."""

    name: str
    n_attacks: int
    attacks_blocked: int
    n_benign: int
    benign_killed: int
    case08: tuple[tuple[str, bool], ...]
    killed_benign: tuple[str, ...]

    @property
    def recall(self) -> float:
        """Fraction of attacks blocked."""
        return self.attacks_blocked / self.n_attacks if self.n_attacks else 0.0

    @property
    def fp_rate(self) -> float:
        """Fraction of benign inputs killed (false-positive rate)."""
        return self.benign_killed / self.n_benign if self.n_benign else 0.0

    @property
    def precision(self) -> float:
        """Precision over the blocked set."""
        tp, fp = self.attacks_blocked, self.benign_killed
        return tp / (tp + fp) if (tp + fp) else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass(frozen=True, slots=True)
class Report:
    """The full harness result: the four configurations and the null-control claim."""

    configs: tuple[ConfigResult, ...]
    null_control: str

    def by_name(self, name: str) -> ConfigResult:
        """Return the configuration result named ``name``."""
        for config in self.configs:
            if config.name == name:
                return config
        raise KeyError(name)


def _blocked(detectors: Sequence[Detector], text: str) -> bool:
    ctx = Context(policy_hash="eval", actor=None)
    verdict = decide(Direction.INBOUND, text, ctx, detectors, observed_at=_OBSERVED_AT)
    return isinstance(verdict, Deny)


def _run(
    name: str,
    detectors: Sequence[Detector],
    attacks: Sequence[AttackPrompt],
    benign: Sequence[str],
) -> ConfigResult:
    attacks_blocked = sum(1 for attack in attacks if _blocked(detectors, attack.text))
    killed_benign = tuple(text for text in benign if _blocked(detectors, text))
    case08 = tuple(
        sorted(
            (attack.language, _blocked(detectors, attack.text))
            for attack in attacks
            if attack.case_id == CASE_08
        )
    )
    return ConfigResult(
        name=name,
        n_attacks=len(attacks),
        attacks_blocked=attacks_blocked,
        n_benign=len(benign),
        benign_killed=len(killed_benign),
        case08=case08,
        killed_benign=killed_benign,
    )


def _null_control(limes: ConfigResult, baseline: ConfigResult) -> str:
    regressions = set(limes.killed_benign) - set(baseline.killed_benign)
    if regressions:
        return (
            f"REGRESSION — limes kills {len(regressions)} benign input(s) the Tessera baseline "
            f"allows. Not a null result; fix the detector."
        )
    power = sign_test_power(limes.n_benign)
    if power is None:
        return (
            f"CANNOT SAY — n={limes.n_benign} benign inputs is too small to power any "
            f"no-regression claim (a witness that cannot see may never report 'ok')."
        )
    effect = NoEffect(
        claim=(
            f"limes introduces no false positives over the Tessera-regex baseline "
            f"(both {limes.benign_killed}/{limes.n_benign} benign killed)"
        ),
        power=power,
    )
    return (
        f"NO EFFECT — {effect.claim}. Power: n={power.samples}, alpha={power.threshold}, "
        f"minimum detectable effect ~= {power.minimum_detectable_effect:.3f} "
        f"({power.effect_unit}). A smaller regression would be invisible here — "
        f"grow the benign corpus to tighten it."
    )


def compute() -> Report:
    """Run the four configurations over the corpus and return the report."""
    attacks = load_attacks()
    benign = load_benign()
    policy = load_injection_policy()
    configs = (
        _run("unplugged (null control)", (), attacks, benign),
        _run("block-everything", (_BlockEverything(),), attacks, benign),
        _run("tessera-regex baseline", (TesseraRegexBaseline(policy),), attacks, benign),
        _run("limes injection", (InjectionDetector(policy),), attacks, benign),
    )
    null_control = _null_control(configs[3], configs[2])
    return Report(configs=configs, null_control=null_control)


def _case08_cell(case08: tuple[tuple[str, bool], ...]) -> str:
    return ", ".join(f"{lang}={'blocked' if hit else 'MISS'}" for lang, hit in case08) or "—"


def render(report: Report, when: str) -> str:
    """Render the report as a Markdown confusion matrix."""
    limes = report.by_name("limes injection")
    lines = [
        "# limes injection detector — confusion matrix",
        "",
        f"Generated {when} from the copied corpus "
        f"({limes.n_attacks} attack prompts across 11 cases, fr/de/en; "
        f"{limes.n_benign} benign inputs). Calibrated against Tessera's corrected-grader "
        "baseline (ADR 0003; Tessera ADR 0028 §5, criteria sha `11-69bcc3f57015`).",
        "",
        "| configuration | attacks blocked | benign killed | recall | precision | F1 |",
        "|---|---|---|---|---|---|",
    ]
    for config in report.configs:
        emphasis = "**" if config.name == "limes injection" else ""
        lines.append(
            f"| {emphasis}{config.name}{emphasis} "
            f"| {emphasis}{config.attacks_blocked}/{config.n_attacks}{emphasis} "
            f"| {emphasis}{config.benign_killed}/{config.n_benign}{emphasis} "
            f"| {config.recall:.2f} | {config.precision:.2f} | {config.f1:.2f} |"
        )
    lines += [
        "",
        "## Case 08 (the measured hole) — per language, per configuration",
        "",
        "| configuration | case 08 |",
        "|---|---|",
    ]
    for config in report.configs:
        lines.append(f"| {config.name} | {_case08_cell(config.case08)} |")
    lines += [
        "",
        "## The two numbers (limes injection)",
        "",
        f"- **Attacks blocked:** {limes.attacks_blocked}/{limes.n_attacks} "
        f"(the unplugged guard blocks 0/{limes.n_attacks}).",
        f"- **Legitimate traffic killed:** {limes.benign_killed}/{limes.n_benign} "
        f"(block-everything kills {limes.n_benign}/{limes.n_benign}).",
        "",
        "## Null control — the no-regression claim, with its power",
        "",
        report.null_control,
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """CLI entry point for ``python -m limes.eval.harness``."""
    parser = argparse.ArgumentParser(description="limes injection detector eval harness")
    parser.add_argument("--write", action="store_true", help="write the confusion matrix to disk")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "eval" / "matrices" / "injection.md",
        help="output path for the confusion matrix",
    )
    args = parser.parse_args()
    report = compute()
    markdown = render(report, when=date.today().isoformat())
    print(markdown)
    if args.write:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(markdown + "\n", encoding="utf-8")
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
