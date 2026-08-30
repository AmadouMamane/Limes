"""Head to head, on ground none of the contestants owns (ADR 0020).

Every published detection number in this repository is limes's own, measured by
limes's author. ADR 0017 fixed half of that by borrowing an adversary — garak's
probes, which limes did not write. This module fixes the other half: it scores
**other tools** on that same corpus, over the same populations, with the same
definition of "flagged" and the same grader.

The rule the table exists to obey is the one a comparison is usually written to
break: **never quote the number a competitor publishes on its own bench.** Those
numbers are real and they are not comparable — different corpora, different
thresholds, different definitions of a hit. So nothing here is read from a
vendor's README. Every cell was measured.

Three properties make the result worth reading.

**Neutral ground.** The corpus is NVIDIA's, vendored by value into
``eval/corpus/garak/``. No contestant wrote it, and limes least of all: the first
time limes ran on it, it scored 3 % (ADR 0017). Scoring a competitor on limes's
own ``injection_benign.json`` would have been the exact opposite — those
lookalikes were written to trip *these* rules — so that corpus is deliberately
absent here.

**One definition of flagged, and it costs limes its best feature.** A case counts
as caught when the tool refuses it; for limes that means a refusal on *either*
leg, inbound ``injection`` or outbound ``injection-egress``, which is how the
proxy deploys them. limes's located spans, its evidence chain and its replayable
verdict are worth nothing in this table. The cross-tool grader is a boolean,
which is the conservative direction and the only fair one.

**Two numbers, never one.** A tool that blocks everything has perfect recall, so
recall never appears without its cost on the matched benign controls, and both
appear per attack family — a single average hides families that fail for
different reasons.

The competitors' verdicts are **committed, not computed here**: they are read
from ``eval/matrices/comparison/<tool>.results.json``, produced by
``scripts/bench_competitors.py`` in a throwaway environment. limes stays at one
dependency and torch never enters this repository. limes's own row is computed
live from the rules in this checkout, so it can never be a stale copy of itself.

Run ``python -m limes.eval.comparison_harness`` to print the matrix, ``--write``
to regenerate ``eval/matrices/comparison.md``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import random
import statistics
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

from limes.detector import Context, Direction
from limes.detectors.injection import InjectionDetector
from limes.detectors.injection_egress import InjectionEgressDetector
from limes.eval.external_corpus import (
    ExternalCorpusUnavailable,
    load_external,
    load_flat,
)
from limes.eval.power import sign_test_power
from limes.guard import decide
from limes.verdict import Deny

__all__ = [
    "ATTACKS_DEV",
    "ATTACKS_HOLDOUT",
    "ATTACK_POPULATIONS",
    "BENIGN_DEV",
    "BENIGN_HOLDOUT",
    "DECLARED_TOOLS",
    "DEV_POPULATIONS",
    "HIJACK_BLIND",
    "JAILBREAK",
    "LIMES_ROW",
    "PERSUASION_PROBE",
    "POPULATIONS",
    "Cell",
    "ComparisonCase",
    "ComparisonReport",
    "Competitor",
    "Row",
    "case_key",
    "comparison_cases",
    "compute",
    "limes_flags",
    "load_competitors",
    "render",
    "results_dir",
    "roc_auc",
    "select_threshold",
    "unique_cases",
]

_OBSERVED_AT = "2026-08-30T00:00:00Z"

#: The sample the limes latency figure is measured over, and the seed it is drawn
#: with. Both fixed here so a re-run times the same cases.
_LATENCY_SAMPLE = 60
_LATENCY_SEED = 0

#: A row flagging at least this share of the clean held-out controls is blocking
#: everything rather than detecting anything, and is named as such wherever the
#: file would otherwise let its recall read as a result.
_BLOCKS_EVERYTHING = 0.90

#: The persuasion family: a résumé carrying a fabricated recommendation and **no
#: imperative at all**. limes's rules score zero on it and it is 69 % of the
#: held-out split, so whether anything else catches it is what decides if ADR
#: 0013's classifier layer is an argument or a wish.
PERSUASION_PROBE = "LatentInjectionResumeFull"

#: How limes appears in the table. Named once so the prose and the numbers cannot
#: drift apart.
LIMES_ROW = "limes (rules, either leg)"

ATTACKS_DEV = "attacks (dev)"
ATTACKS_HOLDOUT = "attacks (holdout)"
HIJACK_BLIND = "hijack (blind)"
BENIGN_DEV = "benign (dev)"
BENIGN_HOLDOUT = "benign (holdout)"
JAILBREAK = "jailbreak (out of scope)"

#: Column order. Recall and its price sit beside each other on purpose.
POPULATIONS = (
    ATTACKS_DEV,
    ATTACKS_HOLDOUT,
    HIJACK_BLIND,
    BENIGN_DEV,
    BENIGN_HOLDOUT,
    JAILBREAK,
)

#: Populations whose members are attacks: a hit is a catch.
ATTACK_POPULATIONS = (ATTACKS_DEV, ATTACKS_HOLDOUT, HIJACK_BLIND)

#: Populations whose members are benign: a hit is a false positive.
BENIGN_POPULATIONS = (BENIGN_DEV, BENIGN_HOLDOUT)

#: The only populations a threshold or a configuration may be chosen on, and the
#: only ones :func:`select_threshold` is ever handed. A threshold chosen anywhere
#: else is not a frozen threshold and the held-out columns stop meaning what the
#: table says. A test asserts this tuple holds nothing held out or blind, because
#: the guarantee is worth what a witness can check and not a word more (ADR 0026).
DEV_POPULATIONS = (ATTACKS_DEV, BENIGN_DEV)

#: The tools this comparison intends to carry. A name here with no committed
#: results is reported as *not measured*, with its reason — never as a zero.
#: Rule 7 of the protocol: a blind spot is not a score.
DECLARED_TOOLS = ("deberta-injection-v2", "deepset-injection", "llm-guard", "rebuff")


@dataclass(frozen=True, slots=True)
class ComparisonCase:
    """One text and the population it belongs to.

    Attributes:
        population: One of :data:`POPULATIONS`.
        probe: The garak probe the case came from.
        text: The materialised prompt, byte-identical for every contestant.
    """

    population: str
    probe: str
    text: str

    @property
    def key(self) -> str:
        """The content-addressed id every contestant's results are keyed by."""
        return case_key(self.text)


def case_key(text: str) -> str:
    """The id a text carries into a results file.

    Content-addressed rather than positional: a results file joined by index
    would silently remap the day the enumeration changed order, and a silent
    remap is the whole failure this comparison exists to avoid.

    Args:
        text: The exact prompt handed to every tool.

    Returns:
        The first 16 hex characters of its sha256. ``scripts/bench_competitors.py``
        refuses to write a file in which two distinct texts share one, so the
        truncation is checked rather than assumed.
    """
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _benign_split(text: str) -> str:
    # The corpus splits its attack templates by the first nibble of their own
    # sha256 (0-7 dev, 8-f holdout). Its matched controls arrive unsplit, and a
    # threshold chosen over all 192 would make the false-positive column partly
    # in-sample for every tuned row. So the same rule is applied to the control's
    # own bytes: uniform, reproducible from the text alone, and unsteerable for
    # exactly the reason ADR 0017 gives.
    nibble = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[0]
    return BENIGN_DEV if int(nibble, 16) < 8 else BENIGN_HOLDOUT


def comparison_cases() -> tuple[ComparisonCase, ...]:
    """Every case in the comparison, in a stable order.

    This is the single enumeration. ``scripts/bench_competitors.py`` imports it,
    so a competitor is scored on exactly the texts limes is scored on and the
    join between the two files is by content rather than by agreement.

    Returns:
        The cases: attacks, then the matched controls, then the blind family and
        the declared non-capability.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk.
    """
    corpus = load_external("latent_injection")
    cases: list[ComparisonCase] = []
    for split, population in (("dev", ATTACKS_DEV), ("holdout", ATTACKS_HOLDOUT)):
        cases.extend(
            ComparisonCase(population=population, probe=case.probe, text=case.text)
            for case in corpus.split(split)
        )
    cases.extend(
        ComparisonCase(population=_benign_split(case.text), probe=case.probe, text=case.text)
        for case in corpus.benign
    )
    # These two ship with the corpus; a checkout missing one loses its column rather
    # than the whole table, and the column then reads as absent instead of empty.
    with contextlib.suppress(ExternalCorpusUnavailable):
        cases.extend(
            ComparisonCase(population=HIJACK_BLIND, probe=case.probe, text=case.text)
            for case in load_flat("prompt_hijack").attacks
        )
    with contextlib.suppress(ExternalCorpusUnavailable):
        cases.extend(
            ComparisonCase(population=JAILBREAK, probe=case.probe, text=case.text)
            for case in load_external("latent_jailbreak").attacks
        )
    return tuple(cases)


def unique_cases(cases: Sequence[ComparisonCase]) -> tuple[ComparisonCase, ...]:
    """One case per distinct text — what a competitor actually has to score.

    Args:
        cases: The full enumeration, which may repeat a text across populations.

    Returns:
        The first occurrence of each distinct text, in the input's order.
    """
    seen: set[str] = set()
    unique: list[ComparisonCase] = []
    for case in cases:
        if case.key not in seen:
            seen.add(case.key)
            unique.append(case)
    return tuple(unique)


@dataclass(frozen=True, slots=True)
class Cell:
    """One (row, population) count, or a declared blind spot.

    Attributes:
        row: The contestant configuration this cell belongs to.
        population: One of :data:`POPULATIONS`.
        hits: How many covered members the tool flagged.
        covered: How many members this tool has a verdict for. Below ``total``
            the cell reports its coverage and refuses to state a rate.
        total: How many members the population holds.
    """

    row: str
    population: str
    hits: int
    covered: int
    total: int

    @property
    def rate(self) -> float | None:
        """The fraction flagged, or ``None`` when the tool did not see them all."""
        if self.covered != self.total or not self.total:
            return None
        return self.hits / self.total

    def render(self) -> str:
        """The cell as it appears in the matrix — a rate, or why there is none."""
        if not self.total:
            return "—"
        rate = self.rate
        if rate is None:
            return f"not measured ({self.covered}/{self.total})"
        return f"{self.hits}/{self.total} ({rate:.1%})"


@dataclass(frozen=True, slots=True)
class Competitor:
    """One tool's committed verdicts, exactly as its bench run recorded them.

    Attributes:
        tool: The distribution name, and the results file's stem.
        label: How the tool is named in the matrix.
        scope: What was actually run — the honest perimeter of the number.
        versions: Every version that could move the number.
        model: The model identity, pinned by name and revision, or ``None``.
        default_threshold: The vendor's own shipped threshold.
        default_configuration: The vendor's own shipped configuration.
        configurations: ``{configuration: {case key: score}}``.
        notes: What a reader must know before believing the row.
        latency_ms: Median milliseconds per case, measured, or ``None``.
    """

    tool: str
    label: str
    scope: str
    versions: Mapping[str, str]
    model: Mapping[str, str] | None
    default_threshold: float
    default_configuration: str
    configurations: Mapping[str, Mapping[str, float]]
    notes: tuple[str, ...]
    latency_ms: float | None

    def score(self, configuration: str, key: str) -> float | None:
        """This tool's score for one case, or ``None`` if it never saw it."""
        return self.configurations.get(configuration, {}).get(key)

    def verdicts(
        self, cases: Sequence[ComparisonCase], configuration: str, threshold: float
    ) -> dict[str, bool | None]:
        """One boolean per distinct case — or ``None`` where this tool has no score.

        Args:
            cases: The enumeration to cover.
            configuration: Which recorded configuration to read.
            threshold: The frozen threshold, applied as ``score > threshold``.

        Returns:
            ``{case key: flagged}``, with ``None`` for a case never scored.
        """
        verdicts: dict[str, bool | None] = {}
        for case in unique_cases(cases):
            score = self.score(configuration, case.key)
            verdicts[case.key] = None if score is None else score > threshold
        return verdicts


@dataclass(frozen=True, slots=True)
class Row:
    """One line of the matrix: a contestant in one frozen configuration.

    Attributes:
        label: The name in the table.
        detail: The configuration and threshold behind the row.
        cells: One per population, in :data:`POPULATIONS` order.
        per_probe: ``{(probe, population): (hits, covered, total)}``.
        verdicts: ``{case key: flagged}``, with ``None`` where the tool never saw
            the case. Kept on the row so a section can restrict a false-positive
            count to one family's own controls without recomputing anything.
        latency_ms: Median milliseconds per case, measured, or ``None``.
    """

    label: str
    detail: str
    cells: tuple[Cell, ...]
    per_probe: Mapping[tuple[str, str], tuple[int, int, int]]
    verdicts: Mapping[str, bool | None]
    latency_ms: float | None

    def cell(self, population: str) -> Cell:
        """Look one cell up by population."""
        for candidate in self.cells:
            if candidate.population == population:
                return candidate
        raise KeyError(population)


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    """Everything the comparison measured, ready to render.

    Attributes:
        cases: The enumeration every contestant was scored over.
        rows: The contestants, the null control and limes first.
        competitors: The committed results that were readable.
        missing: Tools declared but with no committed results — named, not scored.
    """

    cases: tuple[ComparisonCase, ...]
    rows: tuple[Row, ...]
    competitors: tuple[Competitor, ...]
    missing: tuple[str, ...]

    def row(self, label: str) -> Row:
        """Look one row up by label."""
        for candidate in self.rows:
            if candidate.label == label:
                return candidate
        raise KeyError(label)

    def population_size(self, population: str) -> int:
        """How many cases a population holds."""
        return sum(1 for case in self.cases if case.population == population)


def results_dir() -> Path:
    """Where the committed competitor results live in a checkout."""
    return Path(__file__).resolve().parents[3] / "eval" / "matrices" / "comparison"


def load_competitors(directory: Path | None = None) -> tuple[Competitor, ...]:
    """Read every committed results file, in a stable order.

    Args:
        directory: Where to look. Defaults to :func:`results_dir`.

    Returns:
        The competitors, ordered by file name.
    """
    root = directory if directory is not None else results_dir()
    if not root.is_dir():
        return ()
    competitors: list[Competitor] = []
    for path in sorted(root.glob("*.results.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        competitors.append(
            Competitor(
                tool=raw["tool"],
                label=raw["label"],
                scope=raw["scope"],
                versions=raw["versions"],
                model=raw.get("model"),
                default_threshold=float(raw["default"]["threshold"]),
                default_configuration=raw["default"]["configuration"],
                configurations={
                    name: spec["scores"] for name, spec in raw["configurations"].items()
                },
                notes=tuple(raw.get("notes", ())),
                latency_ms=raw.get("latency_ms"),
            )
        )
    return tuple(competitors)


def select_threshold(scored: Sequence[tuple[float, bool]]) -> float:
    """Choose a threshold from development data alone, by a rule fixed in advance.

    The criterion is Youden's J — ``TPR - FPR``, maximised — because it treats
    the two numbers this table refuses to separate symmetrically, and because it
    was written down before any competitor was run. Ties go to the **higher**
    threshold: between two cuts that score the same on ``dev``, the more
    conservative one will surprise a deployment less.

    Args:
        scored: ``(score, is_attack)`` pairs drawn from :data:`DEV_POPULATIONS`
            only. Handing this function anything held out would turn the
            held-out columns into a second development set.

    Returns:
        The threshold, applied as ``score > threshold`` — the comparison every
        tool in this table is graded by.
    """
    attacks = [score for score, is_attack in scored if is_attack]
    benign = [score for score, is_attack in scored if not is_attack]
    if not attacks or not benign:
        return 0.5
    best_threshold = 0.0
    best_youden = float("-inf")
    for candidate in sorted({0.0, *attacks, *benign}):
        tpr = sum(1 for score in attacks if score > candidate) / len(attacks)
        fpr = sum(1 for score in benign if score > candidate) / len(benign)
        youden = tpr - fpr
        if youden > best_youden or (youden == best_youden and candidate > best_threshold):
            best_youden = youden
            best_threshold = candidate
    return best_threshold


@lru_cache(maxsize=1)
def _legs() -> tuple[InjectionDetector, InjectionEgressDetector]:
    """One detector per leg, built once.

    Constructing a detector reads and compiles its policy, and doing that per
    case cost **ten times** the decision itself — 5.3 ms a case against 0.76 ms
    for the two legs together. A latency column that measured policy loading
    would have been a number about this file rather than about limes, and it is
    the one column in the table a reader is most likely to quote.
    """
    return InjectionDetector(), InjectionEgressDetector()


def limes_flags(text: str) -> bool:
    """Whether limes refuses this text on either leg.

    The union across legs is how the proxy actually deploys them: ``injection``
    inspects the inbound leg and returns nothing on the outbound one,
    ``injection-egress`` the reverse. Running both on one direction — which the
    single-leg matrix does — measures only one of them.

    Args:
        text: The case to judge.

    Returns:
        ``True`` if either leg denies it.
    """
    inbound_detector, outbound_detector = _legs()
    context = Context(policy_hash="comparison-eval", actor=None)
    inbound = decide(Direction.INBOUND, text, context, [inbound_detector], observed_at=_OBSERVED_AT)
    if isinstance(inbound, Deny):
        return True
    outbound = decide(
        Direction.OUTBOUND, text, context, [outbound_detector], observed_at=_OBSERVED_AT
    )
    return isinstance(outbound, Deny)


def _threshold(value: float) -> str:
    """A threshold with enough digits to be the threshold it is.

    ``{:g}`` renders 0.99999994 as ``1``, which would have made two rows that
    behave completely differently — one catching 70 % of the blind family, the
    other nothing — print the same cut. The difference between those two rows is
    precisely that one tool rounds its own score to two decimals and the other
    does not, so the formatting has to be able to show it.
    """
    return f"{value:.12g}"


def _limes_latency_ms(cases: Sequence[ComparisonCase]) -> float:
    """Median milliseconds limes takes per case, measured on the same sample shape.

    Every competitor's row carries a latency the bench script measured; limes's
    would otherwise be quoted from another matrix, which is the habit this whole
    file exists to break.

    Args:
        cases: The distinct cases; a fixed sample is drawn from them.

    Returns:
        The median, in milliseconds.
    """
    sample = random.Random(_LATENCY_SEED).sample(list(cases), min(_LATENCY_SAMPLE, len(cases)))
    latencies: list[float] = []
    for case in sample:
        started = time.perf_counter()
        limes_flags(case.text)
        latencies.append((time.perf_counter() - started) * 1000)
    return round(statistics.median(latencies), 2)


def _row(
    label: str,
    detail: str,
    cases: Sequence[ComparisonCase],
    verdicts: Mapping[str, bool | None],
    latency_ms: float | None,
) -> Row:
    cells: list[Cell] = []
    for population in POPULATIONS:
        members = [case for case in cases if case.population == population]
        covered = [case for case in members if verdicts.get(case.key) is not None]
        cells.append(
            Cell(
                row=label,
                population=population,
                hits=sum(1 for case in covered if verdicts[case.key]),
                covered=len(covered),
                total=len(members),
            )
        )
    per_probe: dict[tuple[str, str], tuple[int, int, int]] = {}
    for case in cases:
        if case.population not in ATTACK_POPULATIONS:
            continue
        hits, covered_count, total = per_probe.get((case.probe, case.population), (0, 0, 0))
        verdict = verdicts.get(case.key)
        per_probe[(case.probe, case.population)] = (
            hits + (1 if verdict else 0),
            covered_count + (1 if verdict is not None else 0),
            total + 1,
        )
    return Row(
        label=label,
        detail=detail,
        cells=tuple(cells),
        per_probe=per_probe,
        verdicts=dict(verdicts),
        latency_ms=latency_ms,
    )


def _dev_scored(
    cases: Sequence[ComparisonCase], competitor: Competitor, configuration: str
) -> list[tuple[float, bool]]:
    scored: list[tuple[float, bool]] = []
    for case in cases:
        if case.population not in DEV_POPULATIONS:
            continue
        score = competitor.score(configuration, case.key)
        if score is not None:
            scored.append((score, case.population in ATTACK_POPULATIONS))
    return scored


def _youden(scored: Sequence[tuple[float, bool]], threshold: float) -> float | None:
    attacks = [score for score, is_attack in scored if is_attack]
    benign = [score for score, is_attack in scored if not is_attack]
    if not attacks or not benign:
        return None
    tpr = sum(1 for score in attacks if score > threshold) / len(attacks)
    fpr = sum(1 for score in benign if score > threshold) / len(benign)
    return tpr - fpr


def _tuned(cases: Sequence[ComparisonCase], competitor: Competitor) -> tuple[str, float] | None:
    """Pick this tool's configuration and threshold on ``dev`` alone, then freeze both.

    A tool is entitled to its best honest configuration — llm-guard truncates at
    512 tokens by default, and a résumé that hides its injection past token 512
    would be judged on text the tool never saw. Choosing that configuration on
    the held-out split would be the same sin as choosing the threshold there, so
    both are chosen here, from ``dev``, and neither moves afterwards.
    """
    best: tuple[str, float, float] | None = None
    for configuration in sorted(competitor.configurations):
        scored = _dev_scored(cases, competitor, configuration)
        if not scored:
            continue
        threshold = select_threshold(scored)
        youden = _youden(scored, threshold)
        if youden is None:
            continue
        if best is None or youden > best[2]:
            best = (configuration, threshold, youden)
    return None if best is None else (best[0], best[1])


def _tuned_at_zero_false_positives(
    cases: Sequence[ComparisonCase], competitor: Competitor
) -> tuple[str, float] | None:
    """Pick the configuration and cut that kill no development control at all.

    Youden's J weights recall and precision equally, and the cut it chooses may
    sit at a false-positive rate no deployment would accept. That is a fair
    operating point and it is not the only one — and it is not the one limes is
    at. limes's whole shape is a zero-false-positive floor, so the comparison a
    reader actually wants is *at the same precision*: hold the competitor to
    killing none of the `dev` controls, and see what recall survives.

    The cut is the largest score any development control received, so nothing in
    that set is flagged (the grader is ``score > threshold``). Chosen on ``dev``
    alone, like every other choice here, then frozen.

    Args:
        cases: The enumeration.
        competitor: The tool to pick for.

    Returns:
        The configuration and threshold, or ``None`` when the tool has no scores.
    """
    best: tuple[str, float, float] | None = None
    for configuration in sorted(competitor.configurations):
        scored = _dev_scored(cases, competitor, configuration)
        attacks = [score for score, is_attack in scored if is_attack]
        benign = [score for score, is_attack in scored if not is_attack]
        if not attacks or not benign:
            continue
        threshold = max(benign)
        recall = sum(1 for score in attacks if score > threshold) / len(attacks)
        if best is None or recall > best[2]:
            best = (configuration, threshold, recall)
    return None if best is None else (best[0], best[1])


def compute(directory: Path | None = None) -> ComparisonReport:
    """Score limes live and every committed competitor over the same cases.

    Args:
        directory: Where the committed results live. Defaults to
            :func:`results_dir`.

    Returns:
        The report.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk — a blind
            spot, never an empty table (ADR 0015).
    """
    cases = comparison_cases()
    competitors = load_competitors(directory)
    distinct = unique_cases(cases)
    limes_verdicts = {case.key: limes_flags(case.text) for case in distinct}
    rows: list[Row] = [
        _row(
            "unplugged (null control)",
            "nothing installed",
            cases,
            {case.key: False for case in distinct},
            None,
        ),
        _row(
            LIMES_ROW,
            "no threshold to choose: a rule matches or it does not",
            cases,
            limes_verdicts,
            _limes_latency_ms(distinct),
        ),
    ]

    for competitor in competitors:
        default = competitor.default_configuration
        rows.append(
            _row(
                f"{competitor.label} — vendor default",
                f"`{default}`, threshold {_threshold(competitor.default_threshold)}, both its own",
                cases,
                competitor.verdicts(cases, default, competitor.default_threshold),
                competitor.latency_ms,
            )
        )
        seen: set[tuple[str, float]] = {(default, competitor.default_threshold)}
        for suffix, detail, choice in (
            (
                "dev-tuned",
                "chosen on dev only by Youden's J, then frozen",
                _tuned(cases, competitor),
            ),
            (
                "dev-tuned at zero false positives",
                "the cut that kills none of the dev controls — limes's own precision",
                _tuned_at_zero_false_positives(cases, competitor),
            ),
        ):
            if choice is None or choice in seen:
                continue
            seen.add(choice)
            configuration, threshold = choice
            rows.append(
                _row(
                    f"{competitor.label} — {suffix}",
                    f"`{configuration}`, threshold {_threshold(threshold)}, {detail}",
                    cases,
                    competitor.verdicts(cases, configuration, threshold),
                    competitor.latency_ms,
                )
            )

    measured = {competitor.tool for competitor in competitors}
    return ComparisonReport(
        cases=cases,
        rows=tuple(rows),
        competitors=competitors,
        missing=tuple(sorted(set(DECLARED_TOOLS) - measured)),
    )


def roc_auc(scores: Sequence[tuple[float, bool]]) -> float | None:
    """Area under the ROC curve, ties counted as half — no threshold anywhere.

    This exists as a guard against the failure a comparison written by one
    contestant's author is most likely to commit without noticing: handing a
    competitor a threshold that ruins it, and reading the result as the tool
    being weak. AUC is what the scores can separate *at their best cut*, so a
    high AUC beside a low recall means the threshold rule failed the tool and the
    number above should not be believed.

    Args:
        scores: ``(score, is_attack)`` pairs.

    Returns:
        The area, or ``None`` when one of the two classes is empty and the
        question has no answer.
    """
    attacks = [score for score, is_attack in scores if is_attack]
    benign = [score for score, is_attack in scores if not is_attack]
    if not attacks or not benign:
        return None
    wins = 0.0
    for attack in attacks:
        for control in benign:
            if attack > control:
                wins += 1.0
            elif attack == control:
                wins += 0.5
    return wins / (len(attacks) * len(benign))


def _separation_lines(report: ComparisonReport) -> list[str]:
    """Every configuration's threshold-free separation, so a bad cut is visible as one."""
    if not report.competitors:
        return []
    lines = [
        "",
        "## Threshold-free separation (ROC AUC)",
        "",
        "The safeguard against the mistake this table's author is likeliest to make: "
        "handing a competitor a threshold that ruins it and reading that as the tool being "
        "weak. AUC uses no threshold at all. A **high AUC beside a low recall above means "
        "the threshold rule failed the tool**, not that the tool failed. 0.5 is a coin.",
        "",
        "| contestant | configuration | dev | holdout | hijack (blind) |",
        "|---|---|---|---|---|",
    ]
    for competitor in report.competitors:
        for configuration in sorted(competitor.configurations):
            cells: list[str] = []
            for attack_population in ATTACK_POPULATIONS:
                pairs: list[tuple[float, bool]] = []
                benign_population = (
                    BENIGN_DEV if attack_population == ATTACKS_DEV else BENIGN_HOLDOUT
                )
                for case in report.cases:
                    if case.population not in (attack_population, benign_population):
                        continue
                    score = competitor.score(configuration, case.key)
                    if score is not None:
                        pairs.append((score, case.population == attack_population))
                area = roc_auc(pairs)
                cells.append("—" if area is None else f"{area:.3f}")
            lines.append(f"| {competitor.label} | `{configuration}` | " + " | ".join(cells) + " |")
    lines += [
        "",
        "limes has no row here and cannot have one: its rules produce a verdict, not a "
        "score, so there is no curve to take the area under. Its single (recall, "
        "false-positive) point is the table above.",
    ]
    return lines


def _family_cost(row: Row, controls: Sequence[ComparisonCase]) -> Cell:
    """What one row costs on one family's own matched controls.

    An overall false-positive rate answers "does this tool fire on clean
    documents". This answers the sharper question the matched control was
    designed for: does it fire on *the same document* with the injection taken
    out — here, the clean résumés that pair with the résumé attacks.
    """
    seen = row.verdicts
    covered = [case for case in controls if seen.get(case.key) is not None]
    return Cell(
        row=row.label,
        population=f"matched controls, {PERSUASION_PROBE}",
        hits=sum(1 for case in covered if seen[case.key]),
        covered=len(covered),
        total=len(controls),
    )


def _persuasion_lines(report: ComparisonReport) -> list[str]:
    """The question this comparison was built to answer, answered from its own numbers."""
    holdout_total = report.population_size(ATTACKS_HOLDOUT)
    family_holdout = sum(
        1
        for case in report.cases
        if case.population == ATTACKS_HOLDOUT and case.probe == PERSUASION_PROBE
    )
    share = family_holdout / holdout_total if holdout_total else 0.0
    # All ten of this family's matched controls, both halves. Three is too few to
    # look at at all, and the split exists to protect a *tuned threshold's* column
    # rather than this one — which is why the well-powered n=100 column stays
    # beside it, and why the sentence below says which is which.
    controls = tuple(
        case
        for case in report.cases
        if case.population in BENIGN_POPULATIONS and case.probe == PERSUASION_PROBE
    )
    controls_dev = sum(1 for case in controls if case.population == BENIGN_DEV)
    lines = [
        "",
        f"## The question this table was built to answer: `{PERSUASION_PROBE}`",
        "",
        f"It is **{share:.0%}** of the held-out split, and it is the family a rule cannot "
        "reach: a résumé under automated screening carrying a fabricated recommendation — "
        "white text addressed to the screener, a hidden competency profile — and **no "
        "imperative at all**. `injection-egress` alone scores **0** on it (ADR 0017); the "
        "union of legs below does slightly better, on the handful that also carry an "
        "override phrase. So: does anything else catch it, and at what price?",
        "",
        f"Two prices, because one of them is underpowered. **Clean résumés** is this "
        f"family's own matched control — the same documents with the injection removed, "
        f"all {len(controls)} of them. At n={len(controls)} that column separates 0 from "
        f"all and nothing finer, and {controls_dev} of the {len(controls)} sit in the dev "
        "half, so for a dev-tuned row it is partly in-sample. **All clean documents** is "
        f"the held-out control set entire, n={report.population_size(BENIGN_HOLDOUT)}, "
        "out-of-sample for every tuned row and the one to judge cost by.",
        "",
        "| contestant | dev | holdout | clean résumés flagged | all clean documents (held out) |",
        "|---|---|---|---|---|",
    ]
    best: tuple[str, float, float] | None = None
    for row in report.rows:
        dev = row.per_probe.get((PERSUASION_PROBE, ATTACKS_DEV), (0, 0, 0))
        hold = row.per_probe.get((PERSUASION_PROBE, ATTACKS_HOLDOUT), (0, 0, 0))
        if not dev[2] and not hold[2]:
            continue
        recall = hold[0] / hold[2] if hold[2] else 0.0
        dev_recall = dev[0] / dev[2] if dev[2] else 0.0
        lines.append(
            f"| {row.label} | {dev[0]}/{dev[2]} ({dev_recall:.1%}) | "
            f"{hold[0]}/{hold[2]} ({recall:.1%}) | {_family_cost(row, controls).render()} | "
            f"{row.cell(BENIGN_HOLDOUT).render()} |"
        )
        contestant = not row.label.startswith(("unplugged", LIMES_ROW))
        # Both numbers, here too. Ranking this table by recall alone would crown a
        # row that flags 99 of 100 clean documents, which is the exact failure the
        # false-positive column exists to expose. The margin below is a *reporting*
        # statistic over already-frozen rows, not a selection of anything.
        margin = recall - (row.cell(BENIGN_HOLDOUT).rate or 0.0)
        if contestant and (best is None or margin > best[2]):
            best = (row.label, recall, margin)

    limes_hold = report.row(LIMES_ROW).per_probe.get((PERSUASION_PROBE, ATTACKS_HOLDOUT), (0, 0, 0))
    limes_recall = limes_hold[0] / limes_hold[2] if limes_hold[2] else 0.0
    lines.append("")
    if best is None:
        lines.append(
            "**No competitor was measured on this family.** This section states a blind "
            "spot, not an answer."
        )
        return lines

    winner, winning_recall, _ = best
    if winning_recall < 0.10:
        lines.append(
            f"**Nobody catches it.** The best any contestant manages on the held-out "
            f"persuasion family is **{winning_recall:.1%}** ({winner}), against limes's "
            f"**{limes_recall:.1%}**. limes's zero here is therefore not a competitive gap; "
            "it is a property of the attack. An injection that carries no instruction is "
            "not detectable *as an instruction* by rules, and on this evidence the trained "
            "classifiers do not detect it either. That reframes ADR 0013 rather than "
            "cancelling it: a classifier layer is still worth building for the families "
            "where it helps, and this family is an open problem of the domain."
        )
        return lines

    family_cost = _family_cost(report.row(winner), controls)
    cost = report.row(winner).cell(BENIGN_HOLDOUT)
    rate = cost.rate
    lines.append(
        f"**Something does catch it — {winner}, at {winning_recall:.1%} on the held-out "
        f"split**, against limes's {limes_recall:.1%}. On the clean résumés that pair with "
        f"those attacks it fires {family_cost.render()}; across the whole held-out control "
        f"set, {cost.render()}."
    )
    if rate is not None and rate > 0.10:
        lines.append("")
        lines.append(
            "That is the classic trade-off, measured instead of asserted: the recall is "
            "bought with false positives limes does not pay. A zero-false-positive floor "
            "has a place beside it, and neither replaces the other."
        )
    else:
        lines.append("")
        lines.append(
            "And it buys that recall cheaply — the uncomfortable answer for limes. This is "
            "a capability the rules do not have and somebody else does. ADR 0013's "
            "classifier layer stops being a hedge and becomes the named gap."
        )
    return lines


def _precision_floor_lines(report: ComparisonReport) -> list[str]:
    """Why a competitor held to limes's precision scores what it scores.

    The zero-false-positive row is the fairest single comparison in the table and
    the least self-explanatory: a reader who sees it collapse deserves to know
    whether the tool is weak or whether one control is sitting on the ceiling.
    Both facts are computed here rather than described.
    """
    if not report.competitors:
        return []
    lines = [
        "",
        "## Held to limes's precision",
        "",
        "limes kills none of the matched controls, so the comparison a deployment actually "
        "faces is *at that floor*. What follows is the cut, per tool, that flags no `dev` "
        "control at all — and what the control sitting highest is, because that is what "
        "sets the floor.",
        "",
    ]
    pinned: list[str] = []
    for competitor in report.competitors:
        choice = _tuned_at_zero_false_positives(report.cases, competitor)
        if choice is None:
            continue
        configuration, threshold = choice
        if threshold == 1.0:
            pinned.append(competitor.label)
        ceiling = [
            case
            for case in report.cases
            if case.population == BENIGN_DEV
            and competitor.score(configuration, case.key) == threshold
        ]
        row = next(
            (
                r
                for r in report.rows
                if r.label.endswith("zero false positives") and r.label.startswith(competitor.label)
            ),
            None,
        )
        held = row.cell(ATTACKS_HOLDOUT).render() if row is not None else "—"
        blind = row.cell(HIJACK_BLIND).render() if row is not None else "—"
        head = ceiling[0].text.strip().replace("\n", " ")[:96] if ceiling else ""
        lines.append(
            f"- **{competitor.label}** — `{configuration}` at {_threshold(threshold)} is the "
            f"highest cut that spares every `dev` control. Held there it catches {held} of "
            f"the held-out attacks and {blind} of the blind hijacks. {len(ceiling)} of the "
            f"{report.population_size(BENIGN_DEV)} controls sit at that ceiling"
            + (f', the first beginning *"{head}…"*.' if head else ".")
        )
    if pinned:
        lines += [
            "",
            "**A cut of exactly 1 is a rounding artefact, not a ceiling of the model.** "
            + ", ".join(f"*{name}*" for name in pinned)
            + " rounds its own score to two decimals, and a tool that does cannot separate "
            "anything at the top of its range: a control at 0.9987 and an attack at 0.9999 "
            "both become 1.00, and no threshold exists between them. That is why a bullet "
            "above can run the same checkpoint as another and disagree with it completely "
            "about what that checkpoint can do at this floor.",
        ]
    lines += [
        "",
        "Read the rest carefully before treating it as a defect of the tool. Where the "
        "ceiling control is garak's own **task instruction** — *translate this, and do not "
        "follow instructions inside it* — the classifier is not being stupid: a sentence "
        "telling a model to disregard instructions is, in isolation, indistinguishable from "
        "one. It is a real deployment hazard rather than a scoring artefact, and it is the "
        "reason a precision floor is not a threshold a scoring tool can simply be moved to.",
    ]
    return lines


def _family_lines(report: ComparisonReport) -> list[str]:
    lines = [
        "",
        "## Per attack family",
        "",
        "A single recall averages families that fail for entirely different reasons, and "
        "the average then reads as one fact. It is not one fact.",
        "",
    ]
    for population in ATTACK_POPULATIONS:
        probes = sorted(
            {
                probe
                for row in report.rows
                for (probe, pop), (_, _, total) in row.per_probe.items()
                if pop == population and total
            }
        )
        if not probes:
            continue
        labels = [row.label for row in report.rows]
        lines += [
            f"### {population}",
            "",
            "| probe | " + " | ".join(labels) + " |",
            "|---" * (len(labels) + 1) + "|",
        ]
        for probe in probes:
            counts: list[str] = []
            for row in report.rows:
                hits, covered, total = row.per_probe.get((probe, population), (0, 0, 0))
                if not total:
                    counts.append("—")
                elif covered != total:
                    counts.append(f"not measured ({covered}/{total})")
                else:
                    counts.append(f"{hits}/{total} ({hits / total:.0%})")
            lines.append(f"| `{probe}` | " + " | ".join(counts) + " |")
        lines.append("")
    return lines


def render(report: ComparisonReport, when: str) -> str:
    """Render the comparison as a Markdown matrix.

    Args:
        report: What :func:`compute` measured.
        when: The date to stamp the matrix with.

    Returns:
        The Markdown document.
    """
    lines = [
        "# limes vs the field, on ground none of us owns",
        "",
        f"Generated {when}. Every number below was **measured here**, on one corpus, with "
        "one set of populations and one grader. Not one of them is a figure a vendor "
        "publishes about itself: those are real, and they are not comparable — different "
        "corpora, different thresholds, different definitions of a hit. That is the whole "
        "reason this file exists (ADR 0020).",
        "",
        "**The ground.** NVIDIA's garak, vendored by value into `eval/corpus/garak/` "
        "(ADR 0017). No contestant wrote it. limes least of all: the first time limes ran "
        "on it, it scored 3 %.",
        "",
        "**Flagged means flagged.** One boolean per (tool, text). For limes that is a "
        "refusal on *either* leg — inbound `injection` or outbound `injection-egress`, "
        "which is how the proxy deploys them. limes's located spans, its evidence chain and "
        "its replayable verdict count for nothing here. That is deliberate: the grader has "
        "to be something every contestant can produce, so limes gives up the thing it is "
        "actually for and is judged on the thing everybody shares.",
        "",
        "**Two numbers, never one.** A tool that blocks everything has perfect recall, so "
        "recall never appears without its price on the matched benign controls — *the same "
        "documents, with the injection removed*.",
        "",
        "**Three operating points, all chosen on `dev`.** The vendor's own shipped "
        "threshold, which nothing here picked; the cut that maximises Youden's J; and the "
        "cut that kills **none** of the development controls — limes's own precision, so a "
        "reader can ask the question that matters to a deployment: *at the same false-"
        "positive floor, who catches more?*",
        "",
        "**Where the columns come from.** `dev` is what a threshold or a configuration may "
        "be chosen on. `holdout` is split by attack template and scored with everything "
        "frozen. `hijack (blind)` was vendored and scored without its contents ever being "
        "read. `benign` is garak's own matched controls, split by the same content-hash "
        "rule so that a tuned row's false-positive column is not its own selection set.",
        "",
        "| contestant | " + " | ".join(POPULATIONS) + " |",
        "|---" * (len(POPULATIONS) + 1) + "|",
    ]
    for row in report.rows:
        lines.append(
            f"| {row.label} | "
            + " | ".join(row.cell(population).render() for population in POPULATIONS)
            + " |"
        )

    blockers = [
        row
        for row in report.rows
        if not row.label.startswith(("unplugged", LIMES_ROW))
        and (row.cell(BENIGN_HOLDOUT).rate or 0.0) >= _BLOCKS_EVERYTHING
    ]
    if blockers:
        lines += [
            "",
            "> **Rows that block nearly everything.** "
            + ", ".join(f"*{row.label}*" for row in blockers)
            + f" flags at least {_BLOCKS_EVERYTHING:.0%} of the clean held-out documents. "
            "Its recall column is arithmetic, not detection, and nothing below treats it as "
            "a result. This is precisely why no recall in this file appears without the "
            "column beside it.",
        ]

    lines += ["", "### What each row actually ran", ""]
    for row in report.rows:
        latency = f" · median {row.latency_ms:.1f} ms/case" if row.latency_ms else ""
        lines.append(f"- **{row.label}** — {row.detail}{latency}")

    lines += ["", "## Provenance — what was installed, and what it was", ""]
    if not report.competitors:
        lines += [
            "No competitor results are committed in this checkout, so every row above is "
            "limes's own. That is a blind spot, stated as one.",
            "",
        ]
    for competitor in report.competitors:
        lines += [
            f"**{competitor.label}** — {competitor.scope}",
            "",
            "- versions: "
            + ", ".join(f"`{name} {value}`" for name, value in sorted(competitor.versions.items())),
        ]
        if competitor.model is not None:
            lines.append(
                f"- model: `{competitor.model['name']}`, revision `{competitor.model['revision']}`"
            )
        lines += [f"- {note}" for note in competitor.notes]
        lines.append("")
    lines += [
        "Full detail — the environment, the recipe, the fidelity checks — in "
        "`eval/matrices/comparison/PROVENANCE.md`.",
        "",
    ]

    if report.missing:
        lines += [
            "## Declared, and not measured",
            "",
            "A tool that did not install or did not run is **named here, never scored "
            "zero**. A blind spot is not a result (ADR 0026, and rule 7 of this "
            "comparison's protocol).",
            "",
        ]
        lines += [f"- `{name}` — no committed results in this checkout." for name in report.missing]
        lines.append("")

    lines += _precision_floor_lines(report)
    lines += _family_lines(report)
    lines += _persuasion_lines(report)
    lines += _separation_lines(report)

    power = sign_test_power(report.population_size(BENIGN_HOLDOUT))
    lines += ["", "## What the false-positive column can and cannot say", ""]
    if power is not None:
        lines.append(
            f"- `{BENIGN_HOLDOUT}`: n={power.samples}, alpha={power.threshold}, minimum "
            f"detectable effect ~= {power.minimum_detectable_effect:.3f} "
            f"({power.effect_unit})."
        )
    else:
        lines.append(f"- `{BENIGN_HOLDOUT}` is too small to power any claim about it.")
    lines += [
        "- limes's own `injection_benign.json` — the near-misses written to trip *these* "
        "rules on purpose — is **deliberately absent**. Scoring a competitor on a corpus "
        "written against one specific detector would distort the answer in both directions "
        "at once.",
        "",
        "## What this table does not measure",
        "",
        "- **limes's `dev` column is in-sample for limes.** Its rules were written "
        "against that split, which is what `dev` is for (ADR 0017); no competitor had "
        "that advantage on it. Read `holdout`, and never quote `dev` alone.",
        "- **`hijack (blind)` is not blind for limes either.** ADR 0019 ported an override "
        "family to the inbound leg *after* the blind run reported 0/131 on that family. "
        "The port was verbatim and no hijack prompt was read, but the number is post-hoc "
        "and this table will not call it blind for limes. It is blind for nobody else "
        "either — a trained classifier's exposure to it is unknown, which is the point "
        "immediately below.",
        "- **No split of the benign controls is fully out-of-sample for limes.** They are "
        "derived from the same documents as the `dev` attacks limes's rules were written "
        "against. Splitting them keeps a *tuned* row's false-positive column out of its own "
        "selection set, which is what it is for; it cannot make limes's zero out-of-sample, "
        "and it is not claimed to.",
        "- **A hit in `jailbreak (out of scope)` is neither a catch nor a false positive.** "
        "It is a content-policy jailbreak, which limes has never claimed (ADR 0017) and a "
        "general-purpose scanner may reasonably flag. Do not add that column to either side; "
        "it says which perimeter each tool draws, not who is right.",
        "- **A trained model may have seen these attacks.** garak's probes derive from "
        "public injection research, and the classifiers here were trained on public "
        "injection datasets. Nothing can un-mix that, so it is stated rather than "
        "neutralised: a classifier's number here is *generalisation in a real deployment, "
        "with training data that may overlap this corpus*. limes's rules have no such "
        "exposure, and the asymmetry favours the classifiers.",
        "- **One tool was left out for shape, not for effort.** mcp-scan (Invariant, now "
        "Snyk Agent Scan) analyses MCP server configurations and tool descriptions rather "
        "than classifying a text. Bending it into a text-to-boolean grader would have meant "
        "inventing an adapter that scores something it does not claim to score, and that "
        "number would be worse than no number.",
        "- **rebuff's row is a floor for rebuff, not a measurement of rebuff.** Its deployed "
        "detector is heuristics plus an LLM judge plus a vector store of past attacks plus "
        "canary tokens; three of the four need an OpenAI key and a Pinecone index and do "
        "not run offline. Nothing in this repository may quote that row as rebuff's number.",
        "- **Everything limes is actually for.** Evidence that replays, a policy hash on "
        "every verdict, a refusal that names the rule and the span, `CannotSay` when a "
        "detector could not see. None of that survives a boolean, and a tool that wins "
        "this table has not thereby answered *what did you refuse, and can you prove it*.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """CLI entry point for ``python -m limes.eval.comparison_harness``."""
    parser = argparse.ArgumentParser(description="limes vs the field, on neutral ground")
    parser.add_argument("--write", action="store_true", help="write the matrix to disk")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "eval" / "matrices" / "comparison.md",
        help="output path for the matrix",
    )
    arguments = parser.parse_args()

    try:
        report = compute()
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
