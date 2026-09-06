"""Head to head on the outbound leg: PII and secrets, against the tools that claim them (ADR 0030).

ADR 0020 measured limes's injection detectors against the field on garak's
corpus. The two data detectors — ``pii-egress`` and ``secrets-egress`` — had
external corpora (ADR 0021) but no competitor: their matrices compared limes to
a null control, a block-everything control and, for PII, the guard limes grew
out of. This module puts the tools that actually claim those detections on the
same ground, under the same grader, and publishes whatever comes back.

The rules are ADR 0020's, and three things are specific to this leg.

**The ground is partly the contestant's own, and the table says so.** The
secrets corpus is gitleaks' catalogue, materialised from gitleaks' own regexes;
gitleaks scoring on it is a ceiling and a sanity check, not a comparison, and
its row carries that label. The PII sentences are presidio-research's, so
Presidio meets prose its own project wrote — though the *values* inside them are
limes's synthetic vectors, which nobody's recogniser was tuned on.

**Two views of the secrets question, because the census and the perimeter are
different questions.** Against the whole catalogue, limes has always said it
reads eight vendor prefixes plus PEM, JWT and the keyword-anchored AWS secret;
the census column measures how much of the industry's list that is. *Held to the
formats limes claims* is the fairer question — on the formats limes says it
reads, who reads them? — and it is asked per format, with limes's own misses
named and explained rather than averaged away.

**Located, not flagged.** As in every egress matrix: a PII hit is a finding of
an in-scope category whose span reproduces the value exactly; a secret hit is a
finding wholly inside the vendored token. A tool that fires on the whole message
locates nothing. The categories compared are the ones **both** sides claim — a
card number, an IBAN, an e-mail, a phone — so a competitor's detections of names,
dates and places in the same sentences are neither credited nor charged.

The competitors' findings are committed, never computed here
(``eval/matrices/comparison/<bench>/<tool>.results.json``, written by
``scripts/bench_competitors.py --bench pii|secrets`` in a throwaway environment).
limes's own rows are computed live from this checkout.

Run ``python -m limes.eval.egress_comparison_harness pii`` (or ``secrets``) to
print the matrix, ``--write`` to regenerate ``eval/matrices/comparison_<bench>.md``.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Final

from limes.detector import Context, Detector, DetectorBlind, Direction
from limes.detectors.pii_egress import PiiEgressDetector
from limes.detectors.secrets_egress import SecretsEgressDetector
from limes.eval.comparison_harness import Cell, case_key, format_threshold, select_threshold
from limes.eval.egress_harness import BASELINES
from limes.eval.external_corpus import ExternalCorpusUnavailable
from limes.eval.external_egress_corpus import (
    ExternalEgressCase,
    load_pii_external,
    load_secrets_external,
)
from limes.eval.power import sign_test_power

__all__ = [
    "BENCHES",
    "CLAIMED_FORMATS",
    "CLAIMED_FORMAT_NOTES",
    "DECLARED_EGRESS_TOOLS",
    "LIMES_ROWS",
    "PII_POPULATIONS",
    "SECRETS_POPULATIONS",
    "EgressCase",
    "EgressCompetitor",
    "EgressReport",
    "EgressRow",
    "Finding",
    "compute",
    "cost_populations",
    "dev_populations",
    "egress_cases",
    "is_boolean",
    "limes_findings",
    "load_egress_competitors",
    "render",
    "results_dir",
    "unique_egress_cases",
]

_OBSERVED_AT: Final = "2026-09-07T00:00:00Z"
_CONTEXT: Final = Context(policy_hash="egress-comparison-eval", actor=None)
_LATENCY_SAMPLE: Final = 60
_LATENCY_SEED: Final = 0
#: A row killing at least this share of the held-out controls is blocking rather
#: than detecting, and is named as such.
_BLOCKS_EVERYTHING: Final = 0.90

BENCHES: Final = ("pii", "secrets")

#: The tools each bench intends to carry. A name here with no committed results
#: is reported as *not measured*, never as a zero (ADR 0020, rule 8).
DECLARED_EGRESS_TOOLS: Final[Mapping[str, tuple[str, ...]]] = {
    "pii": ("presidio", "mcp-firewall"),
    "secrets": ("gitleaks", "detect-secrets", "mcp-firewall"),
}

#: How limes appears in each table.
LIMES_ROWS: Final[Mapping[str, str]] = {
    "pii": "limes pii-egress",
    "secrets": "limes secrets-egress",
}

PII_LOCATED_DEV: Final = "values located (dev)"
PII_LOCATED_HOLDOUT: Final = "values located (holdout)"
PII_DECOY_DEV: Final = "checksum-invalid decoys killed (dev)"
PII_DECOY_HOLDOUT: Final = "checksum-invalid decoys killed (holdout)"
PII_REMOVED_DEV: Final = "value-removed controls killed (dev)"
PII_REMOVED_HOLDOUT: Final = "value-removed controls killed (holdout)"
PII_OUT_OF_SCOPE: Final = "out-of-scope slots killed"

PII_POPULATIONS: Final = (
    PII_LOCATED_DEV,
    PII_LOCATED_HOLDOUT,
    PII_DECOY_DEV,
    PII_DECOY_HOLDOUT,
    PII_REMOVED_DEV,
    PII_REMOVED_HOLDOUT,
    PII_OUT_OF_SCOPE,
)

SECRETS_LOCATED_DEV: Final = "formats located (dev)"
SECRETS_LOCATED_HOLDOUT: Final = "formats located (holdout)"
SECRETS_NEGATIVES_DEV: Final = "gitleaks' hard negatives killed (dev)"
SECRETS_NEGATIVES_HOLDOUT: Final = "gitleaks' hard negatives killed (holdout)"

SECRETS_POPULATIONS: Final = (
    SECRETS_LOCATED_DEV,
    SECRETS_LOCATED_HOLDOUT,
    SECRETS_NEGATIVES_DEV,
    SECRETS_NEGATIVES_HOLDOUT,
)

#: The gitleaks rules whose format limes *claims* to read, mapped to the limes
#: rule that claims it. This is the perimeter the README has always stated —
#: eight vendor prefixes plus PEM and JWT — written as the catalogue names it,
#: so the fair question (on the formats limes says it reads, who reads them?)
#: is asked over a list a reader can check against both sides.
CLAIMED_FORMATS: Final[Mapping[str, str]] = {
    "aws-access-token": "secret:aws-access-key-id",
    "openai-api-key": "secret:openai-key",
    "github-pat": "secret:github-token",
    "github-oauth": "secret:github-token",
    "github-app-token": "secret:github-token",
    "github-refresh-token": "secret:github-token",
    "github-fine-grained-pat": "secret:github-token",
    "stripe-access-token": "secret:stripe-key",
    "gcp-api-key": "secret:google-api-key",
    "slack-app-token": "secret:slack-token",
    "slack-bot-token": "secret:slack-token",
    "slack-config-access-token": "secret:slack-token",
    "slack-config-refresh-token": "secret:slack-token",
    "slack-legacy-bot-token": "secret:slack-token",
    "slack-legacy-token": "secret:slack-token",
    "slack-legacy-workspace-token": "secret:slack-token",
    "slack-user-token": "secret:slack-token",
    "private-key": "secret:private-key-pem",
    "jwt": "secret:jwt",
}

#: Why limes misses a claimed format on the vendored instance — one sentence per
#: miss, about the instance and the rule, never a rounding. A test holds this
#: mapping to exactly the set of claimed formats limes does not locate, so a
#: note cannot outlive its miss and a miss cannot go unexplained.
CLAIMED_FORMAT_NOTES: Final[Mapping[str, str]] = {
    "stripe-access-token": (
        "the generated body is 10 characters; gitleaks' regex admits 10 to 99, limes's "
        "requires at least 24, the shortest body Stripe documents. Whether a 10-character "
        "`sk_test_` is a credential or a shape is exactly where the two rules disagree."
    ),
    "private-key": (
        "the generated armour is `-----BEGINPPRIVATE KEY BLOCK-----` — no space after "
        "`BEGIN`, a `BLOCK` suffix — a shape gitleaks' regex admits and no real PEM carries. "
        "limes reads PEM armour as written; it also does not cover PGP's `PRIVATE KEY BLOCK` "
        "armour, which is a real format and a real gap."
    ),
    "jwt": (
        "the generated first segment does not decode to a JSON header. limes's JWT rule is "
        "*only* its validator — the three-segment shape is shared with file names and "
        "version strings, so limes refuses the shape alone by design — and a shape-only "
        "instance is invisible to it. Counted as a miss; explained as a choice."
    ),
}


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a tool found in one case, as its bench run recorded it.

    Attributes:
        kind: The tool's own label for the finding (an entity type, a rule id).
        category: The limes category this maps to (``pan``, ``iban``, ``email``,
            ``phone``), or ``None`` for a kind limes does not claim.
        start: Offset in the case text.
        end: End offset, exclusive.
        score: The tool's confidence, or ``1.0`` for a tool that has none.
    """

    kind: str
    category: str | None
    start: int
    end: int
    score: float


@dataclass(frozen=True, slots=True)
class EgressCase:
    """One text of one bench, and what a hit on it means.

    Attributes:
        bench: ``pii`` or ``secrets``.
        population: One of the bench's populations.
        category: The limes category (PII) or the gitleaks rule id / negative
            origin (secrets).
        text: The exact content handed to every tool.
        locate: The value a finding must reproduce; empty for a control.
        template: The upstream template or rule id the case came from.
    """

    bench: str
    population: str
    category: str
    text: str
    locate: str
    template: str

    @property
    def key(self) -> str:
        """The content-addressed id every tool's findings are keyed by."""
        return case_key(self.text)

    @property
    def is_cost(self) -> bool:
        """Whether a hit on this case is a false positive."""
        return self.population in cost_populations(self.bench)


def cost_populations(bench: str) -> tuple[str, ...]:
    """The populations of ``bench`` whose members are controls: a hit is a cost."""
    if bench == "pii":
        return (
            PII_DECOY_DEV,
            PII_DECOY_HOLDOUT,
            PII_REMOVED_DEV,
            PII_REMOVED_HOLDOUT,
            PII_OUT_OF_SCOPE,
        )
    return (SECRETS_NEGATIVES_DEV, SECRETS_NEGATIVES_HOLDOUT)


def dev_populations(bench: str) -> tuple[str, ...]:
    """The only populations a threshold may be chosen on (ADR 0020, rule 7).

    The out-of-scope slots are excluded even though they are ``dev``-and-``holdout``
    mixed: at five members they would let one sentence steer a cut.
    """
    if bench == "pii":
        return (PII_LOCATED_DEV, PII_DECOY_DEV, PII_REMOVED_DEV)
    return (SECRETS_LOCATED_DEV, SECRETS_NEGATIVES_DEV)


def populations(bench: str) -> tuple[str, ...]:
    """Column order for ``bench``."""
    return PII_POSITIONS if bench == "pii" else SECRETS_POPULATIONS


PII_POSITIONS: Final = PII_POPULATIONS


def _negative_split(text: str) -> str:
    # gitleaks' negatives arrive unsplit; the same content-hash rule the corpora
    # use keeps a tuned row's false-positive column out of its own selection set.
    import hashlib

    nibble = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[0]
    return SECRETS_NEGATIVES_DEV if int(nibble, 16) < 8 else SECRETS_NEGATIVES_HOLDOUT


def egress_cases(bench: str) -> tuple[EgressCase, ...]:
    """Every case of ``bench``, in a stable order — the single enumeration.

    ``scripts/bench_competitors.py`` imports this, so a competitor is scored on
    exactly the texts limes is scored on and the join is by content.

    Args:
        bench: ``pii`` or ``secrets``.

    Returns:
        The cases.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk.
        ValueError: ``bench`` is not one of :data:`BENCHES`.
    """
    if bench == "pii":
        return _pii_cases()
    if bench == "secrets":
        return _secrets_cases()
    raise ValueError(f"unknown bench {bench!r}; expected one of {BENCHES}")


def _pii_cases() -> tuple[EgressCase, ...]:
    corpus = load_pii_external()
    cases: list[EgressCase] = []

    def make(case: ExternalEgressCase, population: str) -> EgressCase:
        return EgressCase(
            bench="pii",
            population=population,
            category=case.category,
            text=case.content,
            locate=case.locate,
            template=case.template,
        )

    for split, population in (("dev", PII_LOCATED_DEV), ("holdout", PII_LOCATED_HOLDOUT)):
        cases.extend(make(case, population) for case in corpus.split(split))
    for case in corpus.controls:
        if case.kind == "control_decoy":
            population = PII_DECOY_DEV if case.split == "dev" else PII_DECOY_HOLDOUT
        else:
            population = PII_REMOVED_DEV if case.split == "dev" else PII_REMOVED_HOLDOUT
        cases.append(make(case, population))
    cases.extend(make(case, PII_OUT_OF_SCOPE) for case in corpus.out_of_scope)
    return tuple(cases)


def _secrets_cases() -> tuple[EgressCase, ...]:
    corpus = load_secrets_external()
    cases: list[EgressCase] = []
    for split, population in (("dev", SECRETS_LOCATED_DEV), ("holdout", SECRETS_LOCATED_HOLDOUT)):
        cases.extend(
            EgressCase(
                bench="secrets",
                population=population,
                category=case.category,
                text=case.content,
                locate=case.locate,
                template=case.template,
            )
            for case in corpus.split(split)
        )
    cases.extend(
        EgressCase(
            bench="secrets",
            population=_negative_split(case.content),
            category=case.category,
            text=case.content,
            locate="",
            template=case.template,
        )
        for case in corpus.negatives
    )
    return tuple(cases)


def unique_egress_cases(cases: Sequence[EgressCase]) -> tuple[EgressCase, ...]:
    """One case per distinct text — what a competitor actually has to score."""
    seen: set[str] = set()
    unique: list[EgressCase] = []
    for case in cases:
        if case.key not in seen:
            seen.add(case.key)
            unique.append(case)
    return tuple(unique)


# --- the grader -------------------------------------------------------------


def _in_scope(finding: Finding, threshold: float) -> bool:
    return finding.category is not None and finding.score > threshold


def _locates_exactly(case: EgressCase, findings: Sequence[Finding], threshold: float) -> bool:
    """PII: an in-scope finding whose span reproduces the value."""
    return any(
        _in_scope(f, threshold) and case.text[f.start : f.end] == case.locate for f in findings
    )


def _locates_inside(case: EgressCase, findings: Sequence[Finding], threshold: float) -> bool:
    """Secrets: any finding falling wholly inside the vendored token."""
    start = case.text.index(case.locate)
    end = start + len(case.locate)
    return any(
        f.score > threshold and f.end > f.start and start <= f.start and f.end <= end
        for f in findings
    )


def _kills(case: EgressCase, findings: Sequence[Finding], threshold: float) -> bool:
    """A control is killed by any counted finding — in-scope for PII, any for secrets."""
    if case.bench == "pii":
        return any(_in_scope(f, threshold) for f in findings)
    return any(f.score > threshold for f in findings)


def hit(case: EgressCase, findings: Sequence[Finding] | None, threshold: float) -> bool | None:
    """Whether ``findings`` count as a hit on ``case`` — or ``None`` when the tool never saw it."""
    if findings is None:
        return None
    if case.is_cost:
        return _kills(case, findings, threshold)
    if case.bench == "pii":
        return _locates_exactly(case, findings, threshold)
    return _locates_inside(case, findings, threshold)


# --- limes, live ------------------------------------------------------------


def _limes_detector(bench: str) -> Detector:
    return PiiEgressDetector() if bench == "pii" else SecretsEgressDetector()


def limes_findings(detector: Detector, text: str) -> tuple[Finding, ...]:
    """What one limes-shaped detector finds in ``text``, in this table's shape.

    A declared blind spot (ADR 0028) is rendered as no findings, exactly as the
    external egress harness renders it: neither a hit nor a kill.

    Args:
        detector: A detector with limes's ``inspect`` contract.
        text: The case.

    Returns:
        One finding per span, its category read from the label's kind prefix.
    """
    try:
        found = detector.inspect(Direction.OUTBOUND, text, _CONTEXT)
    except DetectorBlind:
        return ()
    findings: list[Finding] = []
    for finding in found:
        _, _, rule = finding.label.partition(":")
        for span in finding.spans:
            findings.append(
                Finding(
                    kind=finding.label,
                    category=rule if finding.label.startswith("pii:") else None,
                    start=span.start,
                    end=span.end,
                    score=1.0,
                )
            )
    return tuple(findings)


def _live_findings(
    detector: Detector, cases: Sequence[EgressCase]
) -> dict[str, tuple[Finding, ...]]:
    return {case.key: limes_findings(detector, case.text) for case in cases}


def _live_latency_ms(detector: Detector, cases: Sequence[EgressCase]) -> float:
    sample = random.Random(_LATENCY_SEED).sample(list(cases), min(_LATENCY_SAMPLE, len(cases)))
    latencies: list[float] = []
    for case in sample:
        started = time.perf_counter()
        limes_findings(detector, case.text)
        latencies.append((time.perf_counter() - started) * 1000)
    return round(statistics.median(latencies), 2)


# --- the committed competitors ----------------------------------------------


@dataclass(frozen=True, slots=True)
class EgressCompetitor:
    """One tool's committed findings, exactly as its bench run recorded them.

    Attributes:
        bench: Which bench the file belongs to.
        tool: The results file's stem.
        label: How the tool is named in the matrix.
        scope: What was actually run.
        versions: Every version that could move the number.
        model: The model identity, or ``None``.
        default_threshold: The vendor's own threshold (``0.5`` for a boolean tool).
        default_configuration: The vendor's own configuration.
        configurations: ``{configuration: {case key: findings}}``.
        notes: What a reader must know before believing the row.
        latency_ms: Median milliseconds per case, measured, or ``None``.
        home_ground: The corpus is this tool's own material, and its row is a
            ceiling rather than a comparison.
    """

    bench: str
    tool: str
    label: str
    scope: str
    versions: Mapping[str, str]
    model: Mapping[str, str] | None
    default_threshold: float
    default_configuration: str
    configurations: Mapping[str, Mapping[str, tuple[Finding, ...]]]
    notes: tuple[str, ...]
    latency_ms: float | None
    home_ground: str | None

    def findings(self, configuration: str, key: str) -> tuple[Finding, ...] | None:
        """This tool's findings for one case, or ``None`` if it never saw it."""
        return self.configurations.get(configuration, {}).get(key)

    def score(self, configuration: str, case: EgressCase) -> float | None:
        """The strongest counted finding on ``case``, for threshold selection."""
        findings = self.findings(configuration, case.key)
        if findings is None:
            return None
        counted = [f for f in findings if hit(case, (f,), float("-inf"))]
        return max((f.score for f in counted), default=0.0)

    def verdicts(
        self, cases: Sequence[EgressCase], configuration: str, threshold: float
    ) -> dict[str, bool | None]:
        """One boolean per case key — or ``None`` where this tool has no findings."""
        return {
            case.key: hit(case, self.findings(configuration, case.key), threshold) for case in cases
        }


def results_dir(bench: str) -> Path:
    """Where the committed results of ``bench`` live in a checkout."""
    return Path(__file__).resolve().parents[3] / "eval" / "matrices" / "comparison" / bench


def load_egress_competitors(
    bench: str, directory: Path | None = None
) -> tuple[EgressCompetitor, ...]:
    """Read every committed results file of ``bench``, in a stable order."""
    root = directory if directory is not None else results_dir(bench)
    if not root.is_dir():
        return ()
    competitors: list[EgressCompetitor] = []
    for path in sorted(root.glob("*.results.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        configurations = {
            name: {
                key: tuple(
                    Finding(
                        kind=str(item[0]),
                        category=None if item[1] is None else str(item[1]),
                        start=int(item[2]),
                        end=int(item[3]),
                        score=float(item[4]),
                    )
                    for item in items
                )
                for key, items in spec["findings"].items()
            }
            for name, spec in raw["configurations"].items()
        }
        competitors.append(
            EgressCompetitor(
                bench=raw["bench"],
                tool=raw["tool"],
                label=raw["label"],
                scope=raw["scope"],
                versions=raw["versions"],
                model=raw.get("model"),
                default_threshold=float(raw["default"]["threshold"]),
                default_configuration=raw["default"]["configuration"],
                configurations=configurations,
                notes=tuple(raw.get("notes", ())),
                latency_ms=raw.get("latency_ms"),
                home_ground=raw.get("home_ground"),
            )
        )
    return tuple(competitors)


# --- rows and the report ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class EgressRow:
    """One line of the matrix: a contestant in one frozen configuration.

    Attributes:
        label: The name in the table.
        detail: The configuration and threshold behind the row.
        cells: One per population.
        verdicts: ``{case key: hit}``, ``None`` where the tool never saw the case.
        latency_ms: Median milliseconds per case, or ``None``.
        home_ground: Set when the corpus is this contestant's own material.
    """

    label: str
    detail: str
    cells: tuple[Cell, ...]
    verdicts: Mapping[str, bool | None]
    latency_ms: float | None
    home_ground: str | None = None

    def cell(self, population: str) -> Cell:
        """Look one cell up by population."""
        for candidate in self.cells:
            if candidate.population == population:
                return candidate
        raise KeyError(population)


@dataclass(frozen=True, slots=True)
class EgressReport:
    """Everything one bench measured, ready to render."""

    bench: str
    cases: tuple[EgressCase, ...]
    rows: tuple[EgressRow, ...]
    competitors: tuple[EgressCompetitor, ...]
    missing: tuple[str, ...]

    def row(self, label: str) -> EgressRow:
        """Look one row up by label."""
        for candidate in self.rows:
            if candidate.label == label:
                return candidate
        raise KeyError(label)

    def population_size(self, population: str) -> int:
        """How many cases a population holds."""
        return sum(1 for case in self.cases if case.population == population)


def _row(
    label: str,
    detail: str,
    cases: Sequence[EgressCase],
    verdicts: Mapping[str, bool | None],
    latency_ms: float | None,
    home_ground: str | None = None,
) -> EgressRow:
    cells: list[Cell] = []
    for population in populations(cases[0].bench):
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
    return EgressRow(
        label=label,
        detail=detail,
        cells=tuple(cells),
        verdicts=dict(verdicts),
        latency_ms=latency_ms,
        home_ground=home_ground,
    )


def is_boolean(competitor: EgressCompetitor) -> bool:
    """Whether the tool has no score — every recorded finding is 0 or 1.

    Such a tool has one operating point per configuration: a rule matches or it
    does not. A "tuned" cut can only pick another of its configurations or
    switch it off, and switching it off is not an operating point.
    """
    return all(
        finding.score in (0.0, 1.0)
        for findings in competitor.configurations.values()
        for items in findings.values()
        for finding in items
    )


def _dev_scored(
    cases: Sequence[EgressCase], competitor: EgressCompetitor, configuration: str
) -> list[tuple[float, bool]]:
    scored: list[tuple[float, bool]] = []
    allowed = set(dev_populations(cases[0].bench))
    for case in cases:
        if case.population not in allowed:
            continue
        score = competitor.score(configuration, case)
        if score is not None:
            scored.append((score, not case.is_cost))
    return scored


def _youden(scored: Sequence[tuple[float, bool]], threshold: float) -> float | None:
    attacks = [score for score, is_attack in scored if is_attack]
    benign = [score for score, is_attack in scored if not is_attack]
    if not attacks or not benign:
        return None
    tpr = sum(1 for score in attacks if score > threshold) / len(attacks)
    fpr = sum(1 for score in benign if score > threshold) / len(benign)
    return tpr - fpr


def _tuned(cases: Sequence[EgressCase], competitor: EgressCompetitor) -> tuple[str, float] | None:
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


def _tuned_at_limes_precision(
    cases: Sequence[EgressCase], competitor: EgressCompetitor, limes_kills: int
) -> tuple[str, float] | None:
    """Pick the configuration and cut that kill no more ``dev`` controls than limes does.

    ADR 0020's third operating point was "zero false positives", because limes
    killed none of garak's controls. On these corpora limes is not at zero — the
    Luhn coincidence inside an IBAN-shaped decoy costs it a handful — so the
    honest floor is limes's *actual* count on the ``dev`` controls: the lowest cut
    at which the competitor kills no more of them than limes does, chosen on
    ``dev`` alone, then frozen. With ``limes_kills == 0`` this is exactly the
    zero-false-positive cut.

    Args:
        cases: The enumeration.
        competitor: The tool to pick for.
        limes_kills: How many ``dev`` controls limes killed.

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
        threshold = min(
            candidate
            for candidate in sorted({0.0, *attacks, *benign})
            if sum(1 for score in benign if score > candidate) <= limes_kills
        )
        recall = sum(1 for score in attacks if score > threshold) / len(attacks)
        if best is None or recall > best[2]:
            best = (configuration, threshold, recall)
    return None if best is None else (best[0], best[1])


def _limes_dev_kills(bench: str, rows: Sequence[EgressRow]) -> int:
    """How many ``dev`` controls limes's own row killed — the precision the floor is held to."""
    limes_row = next(row for row in rows if row.label == LIMES_ROWS[bench])
    return sum(
        limes_row.cell(population).hits
        for population in dev_populations(bench)
        if population in cost_populations(bench)
    )


def compute(bench: str, directory: Path | None = None) -> EgressReport:
    """Score limes live and every committed competitor of ``bench`` over the same cases.

    Args:
        bench: ``pii`` or ``secrets``.
        directory: Where the committed results live. Defaults to :func:`results_dir`.

    Returns:
        The report.

    Raises:
        ExternalCorpusUnavailable: The vendored corpus is not on disk — a blind
            spot, never an empty table (ADR 0015).
    """
    cases = egress_cases(bench)
    distinct = unique_egress_cases(cases)
    competitors = load_egress_competitors(bench, directory)
    threshold_none = 0.5

    rows: list[EgressRow] = [
        _row(
            "unplugged (null control)",
            "nothing installed",
            cases,
            {case.key: False for case in distinct},
            None,
        )
    ]
    limes = _limes_detector(bench)
    live = _live_findings(limes, distinct)
    rows.append(
        _row(
            LIMES_ROWS[bench],
            "no threshold to choose: a rule matches and its check passes, or it does not",
            cases,
            {case.key: hit(case, live[case.key], threshold_none) for case in distinct},
            _live_latency_ms(limes, distinct),
        )
    )
    baseline = BASELINES.get(f"{bench}-egress")
    if baseline is not None:
        name, factory = baseline
        ported = factory()
        found = _live_findings(ported, distinct)
        rows.append(
            _row(
                name,
                "the output guard limes grew out of, transcribed verbatim and run live",
                cases,
                {case.key: hit(case, found[case.key], threshold_none) for case in distinct},
                _live_latency_ms(ported, distinct),
            )
        )

    for competitor in competitors:
        default = competitor.default_configuration
        default_verdicts = competitor.verdicts(cases, default, competitor.default_threshold)
        rows.append(
            _row(
                f"{competitor.label} — vendor default",
                f"`{default}`, threshold {format_threshold(competitor.default_threshold)}, "
                "both its own",
                cases,
                default_verdicts,
                competitor.latency_ms,
                competitor.home_ground,
            )
        )
        seen: list[Mapping[str, bool | None]] = [default_verdicts]
        boolean = is_boolean(competitor)
        limes_kills = _limes_dev_kills(bench, rows)
        for suffix, detail, choice in (
            (
                "dev-tuned",
                "chosen on dev only by Youden's J, then frozen",
                _tuned(cases, competitor),
            ),
            (
                "dev-tuned at limes's precision",
                f"the cut that kills no more of the dev controls than limes does ({limes_kills})",
                None if boolean else _tuned_at_limes_precision(cases, competitor, limes_kills),
            ),
        ):
            if choice is None:
                continue
            configuration, threshold = choice
            verdicts = competitor.verdicts(cases, configuration, threshold)
            # A cut that changes no verdict is not a second row, whatever number
            # it is written as; and for a tool with no score, a cut that flags
            # nothing is the tool switched off, not an operating point.
            if any(verdicts == earlier for earlier in seen):
                continue
            if boolean and not any(verdicts.values()):
                continue
            seen.append(verdicts)
            rows.append(
                _row(
                    f"{competitor.label} — {suffix}",
                    f"`{configuration}`, threshold {format_threshold(threshold)}, {detail}",
                    cases,
                    verdicts,
                    competitor.latency_ms,
                    competitor.home_ground,
                )
            )

    measured = {competitor.tool for competitor in competitors}
    return EgressReport(
        bench=bench,
        cases=cases,
        rows=tuple(rows),
        competitors=competitors,
        missing=tuple(sorted(set(DECLARED_EGRESS_TOOLS[bench]) - measured)),
    )


# --- rendering --------------------------------------------------------------


def _matrix_lines(report: EgressReport) -> list[str]:
    columns = populations(report.bench)
    lines = [
        "| contestant | " + " | ".join(columns) + " |",
        "|---" * (len(columns) + 1) + "|",
    ]
    for row in report.rows:
        name = f"**{row.label}**" if row.label.startswith("limes") else row.label
        if row.home_ground:
            name += " ⚑"
        lines.append(
            f"| {name} | "
            + " | ".join(row.cell(population).render() for population in columns)
            + " |"
        )
    return lines


def _category_lines(report: EgressReport) -> list[str]:
    """PII only: located and decoys killed per category, per row."""
    categories = sorted({case.category for case in report.cases if not case.is_cost})
    located_populations = (PII_LOCATED_DEV, PII_LOCATED_HOLDOUT)
    decoy_populations = (PII_DECOY_DEV, PII_DECOY_HOLDOUT)
    lines = [
        "",
        "## Per category — located over both splits, and decoys killed",
        "",
        "| contestant | "
        + " | ".join(f"{c} located" for c in categories)
        + " | "
        + " | ".join(f"{c} decoys killed" for c in categories)
        + " |",
        "|---" * (2 * len(categories) + 1) + "|",
    ]
    for row in report.rows:
        cells: list[str] = []
        for group in (located_populations, decoy_populations):
            for category in categories:
                members = [
                    case
                    for case in report.cases
                    if case.population in group and case.category == category
                ]
                covered = [case for case in members if row.verdicts.get(case.key) is not None]
                if not members:
                    cells.append("—")
                elif len(covered) != len(members):
                    cells.append(f"not measured ({len(covered)}/{len(members)})")
                else:
                    hits = sum(1 for case in covered if row.verdicts[case.key])
                    cells.append(f"{hits}/{len(members)}")
        lines.append(f"| {row.label} | " + " | ".join(cells) + " |")
    return lines


def _claimed_lines(report: EgressReport) -> list[str]:
    """Secrets only: held to the formats limes claims, format by format."""
    by_id = {
        case.category: case
        for case in report.cases
        if not case.is_cost and case.category in CLAIMED_FORMATS
    }
    claimed = [rule for rule in CLAIMED_FORMATS if rule in by_id]
    census = report.population_size(SECRETS_LOCATED_DEV) + report.population_size(
        SECRETS_LOCATED_HOLDOUT
    )
    lines = [
        "",
        "## Held to the formats limes claims",
        "",
        f"The census above asks how much of gitleaks' {census}-format catalogue each tool "
        "sees. This asks the fairer question — **on the formats limes says it reads, who "
        f"reads them?** — over the {len(claimed)} catalogue rules that name "
        "a format limes claims (eight vendor prefixes, PEM, JWT; the AWS *secret* access key "
        "has no gitleaks rule to be measured on). A ✓ is a finding wholly inside the vendored "
        "instance; every miss of limes's is explained below, and a test holds those notes to "
        "exactly the set of misses.",
        "",
        "| gitleaks rule | limes rule | " + " | ".join(row.label for row in report.rows[1:]) + " |",
        "|---|---" + "|---" * len(report.rows[1:]) + "|",
    ]
    for rule in claimed:
        case = by_id[rule]
        marks: list[str] = []
        for row in report.rows[1:]:
            verdict = row.verdicts.get(case.key)
            marks.append("not measured" if verdict is None else ("✓" if verdict else "—"))
        lines.append(f"| `{rule}` | `{CLAIMED_FORMATS[rule]}` | " + " | ".join(marks) + " |")
    lines.append("")
    for row in report.rows[1:]:
        located = sum(1 for rule in claimed if row.verdicts.get(by_id[rule].key))
        seen = sum(1 for rule in claimed if row.verdicts.get(by_id[rule].key) is not None)
        if seen != len(claimed):
            lines.append(f"- **{row.label}** — not measured ({seen}/{len(claimed)} seen)")
        else:
            lines.append(f"- **{row.label}** — {located}/{len(claimed)} claimed formats located")
    limes_row = report.row(LIMES_ROWS[report.bench])
    misses = [rule for rule in claimed if not limes_row.verdicts.get(by_id[rule].key)]
    if misses:
        lines += ["", "**limes's misses on its own perimeter, one by one:**", ""]
        unexplained = "no note recorded — the test holding the notes to the misses is red"
        lines += [f"- `{rule}` — {CLAIMED_FORMAT_NOTES.get(rule, unexplained)}" for rule in misses]
    else:
        lines += ["", "limes locates every claimed format on this corpus."]
    return lines


def _home_ground_lines(report: EgressReport) -> list[str]:
    flagged = [row for row in report.rows if row.home_ground]
    if not flagged:
        return []
    notes = dict.fromkeys(row.home_ground for row in flagged if row.home_ground)
    lines = [
        "",
        "> **⚑ Home ground.** "
        + " ".join(notes)
        + " A row so marked is a ceiling and a sanity check on the corpus, not a comparison, "
        "and no sentence in this repository may quote it as one.",
    ]
    located = [p for p in populations(report.bench) if p not in cost_populations(report.bench)]
    for row in flagged:
        if not row.label.endswith("vendor default"):
            continue
        hits = sum(row.cell(p).hits for p in located)
        total = sum(row.cell(p).total for p in located)
        if hits < total:
            lines.append(
                f"> The ceiling is not 100 %: *{row.label}* locates {hits}/{total} of the "
                "instances generated from its own rules. A rule is more than its regex — an "
                "entropy floor, required keywords, an allowlist — and the generator satisfied "
                "the regex alone, so some instances fall under their own rule's floor. That is "
                "a limit of the corpus, carried by the census column for every contestant alike."
            )
    return lines


def _precision_floor_lines(report: EgressReport) -> list[str]:
    """Why a scored competitor held to limes's precision scores what it scores."""
    scored = [c for c in report.competitors if not is_boolean(c)]
    if not scored:
        return []
    limes_kills = _limes_dev_kills(report.bench, report.rows)
    lines = [
        "",
        "## Held to limes's precision",
        "",
        f"limes kills {limes_kills} of the `dev` controls here, so for a tool that scores its "
        "findings the fair operating point is the lowest cut at which it kills no more than "
        "that — chosen on `dev`, then frozen. What sits just above that cut decides what "
        "survives it.",
        "",
    ]
    for competitor in scored:
        choice = _tuned_at_limes_precision(report.cases, competitor, limes_kills)
        if choice is None:
            continue
        configuration, threshold = choice
        ceiling = [
            case
            for case in report.cases
            if case.population in dev_populations(report.bench)
            and case.is_cost
            and competitor.score(configuration, case) == threshold
        ]
        kinds = sorted(
            {
                finding.kind
                for case in ceiling
                for finding in competitor.findings(configuration, case.key) or ()
                if finding.category is not None and finding.score == threshold
            }
        )
        row = next(
            (
                r
                for r in report.rows
                if r.label.startswith(competitor.label) and r.label.endswith("limes's precision")
            ),
            None,
        )
        if row is None:
            survives = "its vendor default already sits at or under that count"
        else:
            survives = "it locates " + " and ".join(
                row.cell(p).render()
                for p in populations(report.bench)
                if p not in cost_populations(report.bench)
            )
        lines.append(
            f"- **{competitor.label}** — `{configuration}` at {format_threshold(threshold)} is "
            f"the lowest cut that kills no more than {limes_kills} `dev` control(s); held "
            f"there, {survives}. {len(ceiling)} dev control(s) sit exactly at that cut"
            + (f", flagged as {', '.join(f'`{k}`' for k in kinds)}." if kinds else ".")
        )
    lines += [
        "",
        "A control scored at the top of a tool's range means no threshold separates it from a "
        "true value. Where the same checksum-invalid decoy costs limes and the competitor "
        "alike — a run of digits inside an IBAN-shaped span that happens to pass Luhn — the "
        "floor is set by the coincidence, not by either tool.",
    ]
    return lines


def render(report: EgressReport, when: str) -> str:
    """Render one bench's comparison as a Markdown matrix.

    Args:
        report: What :func:`compute` measured.
        when: The date to stamp the matrix with.

    Returns:
        The Markdown document.
    """
    pii = report.bench == "pii"
    lines = [
        (
            "# limes `pii-egress` vs the field — personal data, on presidio-research's sentences"
            if pii
            else "# limes `secrets-egress` vs the field — credentials, on gitleaks' catalogue"
        ),
        "",
        f"Generated {when}. Every number below was **measured here**, on one corpus, with "
        "one grader. Nothing is quoted from a vendor (ADR 0020, extended to the outbound "
        "leg by ADR 0030).",
        "",
    ]
    if pii:
        lines += [
            "**The ground.** presidio-research's 42 sentence templates (MIT, vendored by value "
            "into `eval/corpus/presidio/`, ADR 0021), carrying limes's own already-cleared "
            "synthetic values — ADR 0009 forbids a real card number in this repository at any "
            "price. The *sentences* are Presidio's project's; the *values* are nobody's "
            "training data. Every matched control is the same sentence with the value "
            "replaced: by a same-shape twin whose checksum fails (*decoy*), or by a neutral "
            "phrase (*removed*).",
            "",
            "**Located means located.** A hit is a finding of an in-scope category — card "
            "number, IBAN, e-mail, phone, the four categories **both** limes and the "
            "competitor claim — whose span reproduces the value exactly. A tool that fires on "
            "the whole message locates nothing. A control is killed by any in-scope finding. "
            "Findings of other kinds (a name, a date, a place — which these sentences contain "
            "and Presidio legitimately detects) are neither credited nor charged: they are a "
            "perimeter difference, not a score.",
        ]
    else:
        lines += [
            "**The ground.** gitleaks' catalogue of 222 credential formats (MIT, vendored by "
            "value into `eval/corpus/gitleaks/`, ADR 0021), 218 of them materialised into an "
            "instance generated from the rule's own regex and self-verified against it, plus "
            "339 of gitleaks' own false-positive vectors as hard negatives. The formats and "
            "the negatives are third-party; the bytes of each positive are this repository's.",
            "",
            "**Located means located.** A hit is a finding falling wholly inside the vendored "
            "token, whatever the tool calls it; a negative is killed by any finding at all. A "
            "tool that fires on the whole line locates nothing.",
        ]
    lines += [
        "",
        "**Two numbers, never one.** Recall never appears without its price on the matched "
        "controls, split by the same content-hash rule the corpora use so that a tuned row's "
        "false-positive column is not its own selection set.",
        "",
        "**Operating points, chosen on `dev`.** The vendor's own default; the cut that "
        "maximises Youden's J; the cut that kills no more of the `dev` controls than limes "
        "does — limes's own precision, which on these corpora is not zero and is not "
        "rounded to it. A tool with no score has one operating point per configuration: a tuned "
        "row appears only when `dev` prefers another of its shipped configurations, and a cut "
        "that flags nothing is the tool switched off, not a row.",
        "",
    ]
    lines += _matrix_lines(report)
    lines += _home_ground_lines(report)

    blockers = [
        row
        for row in report.rows
        if not row.label.startswith(("unplugged", "limes"))
        and any(
            (row.cell(population).rate or 0.0) >= _BLOCKS_EVERYTHING
            for population in cost_populations(report.bench)
            if population != PII_OUT_OF_SCOPE
        )
    ]
    if blockers:
        lines += [
            "",
            "> **Rows that block nearly everything.** "
            + ", ".join(f"*{row.label}*" for row in blockers)
            + f" kills at least {_BLOCKS_EVERYTHING:.0%} of a control population. Its recall "
            "column is arithmetic, not detection.",
        ]

    lines += ["", "### What each row actually ran", ""]
    for row in report.rows:
        latency = f" · median {row.latency_ms:.2f} ms/case" if row.latency_ms else ""
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
    ]

    if report.missing:
        lines += [
            "",
            "## Declared, and not measured",
            "",
            "A tool that did not install or did not run is **named here, never scored zero** "
            "(ADR 0020, rule 8).",
            "",
        ]
        lines += [f"- `{name}` — no committed results in this checkout." for name in report.missing]

    lines += _precision_floor_lines(report)
    lines += _category_lines(report) if pii else _claimed_lines(report)

    holdout_cost = PII_DECOY_HOLDOUT if pii else SECRETS_NEGATIVES_HOLDOUT
    power = sign_test_power(report.population_size(holdout_cost))
    lines += ["", "## What the false-positive columns can and cannot say", ""]
    if power is not None:
        lines.append(
            f"- `{holdout_cost}`: n={power.samples}, alpha={power.threshold}, minimum "
            f"detectable effect ~= {power.minimum_detectable_effect:.3f} ({power.effect_unit})."
        )
    else:
        lines.append(f"- `{holdout_cost}` is too small to power any claim about it.")
    if pii:
        lines.append(
            f"- `{PII_OUT_OF_SCOPE}` has {report.population_size(PII_OUT_OF_SCOPE)} members and "
            "separates nothing finer than 0 from all; it is here so the perimeter is a number."
        )
    lines += [
        "- limes's own egress corpora — the lookalikes written to trip *these* rules — are "
        "**deliberately absent**, for the reason ADR 0020 gives.",
        "",
        "## What this table does not measure",
        "",
    ]
    if pii:
        lines += [
            "- **The values are limes's own.** Every card number, IBAN, e-mail and phone here "
            "is a synthetic vector limes admitted; a competitor meets values it never saw, "
            "and so does limes — but limes's author chose them. The strength label of the "
            "corpus (ADR 0021) travels with the number: *external contexts, author-cleared "
            "values*, strictly weaker than an attack nobody here wrote.",
            "- **English only, and no NIR.** presidio-research's templates are English; the "
            "French social-security number limes claims has no slot here and no external "
            "number at all.",
            "- **Presidio's other fifteen entity types.** Names, dates, places, US "
            "identifiers, crypto addresses: real detections limes does not claim, and this "
            "table counts none of them for or against anybody.",
            "- **Presidio on presidio-research's sentences is home ground for the prose**, "
            "and marked so above. The values are not its.",
        ]
    else:
        lines += [
            "- **gitleaks on gitleaks' catalogue is home ground**, marked so above: every "
            "positive was generated from its own regex and verified against it, and every "
            "negative is a vector its allowlists were written to pass. Its row says the corpus "
            "is what it claims to be; it says nothing about gitleaks against an attacker.",
            "- **A shape-only instance favours a shape-only rule.** Two of limes's claimed "
            "formats (PEM, JWT) are read by *content* — key material under the armour, a JSON "
            "header that decodes — and the generator produces shape-valid, content-random "
            "instances. Those misses are named in the perimeter section, not averaged.",
            "- **detect-secrets is a source-code scanner.** Its entropy plugins read quoted "
            "strings, which prose rarely has; its `file` mode is how it ships and its "
            "`adhoc` mode is its `--string` path. Both are recorded; `dev` chose between them.",
            "- **mcp-firewall is at 0.1.0.** Seventeen regexes with no validator, run as "
            "shipped; a young project's floor, not its ceiling.",
            "- **The AWS secret access key has no row.** gitleaks covers that format only "
            "through an entropy gate limes measured itself out of (ADR 0021 Am. 2, ADR 0022), "
            "so the catalogue has no instance to score anybody on.",
        ]
    lines += [
        "- **Everything limes is actually for.** A refusal that names the rule and the span, "
        "a policy hash on every verdict, evidence that replays, `CannotSay` when a detector "
        "could not read. None of that survives a located-span boolean.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """CLI entry point for ``python -m limes.eval.egress_comparison_harness``."""
    parser = argparse.ArgumentParser(description="limes's egress detectors vs the field")
    parser.add_argument("bench", choices=BENCHES, help="which bench to render")
    parser.add_argument("--write", action="store_true", help="write the matrix to disk")
    arguments = parser.parse_args()
    try:
        report = compute(arguments.bench)
    except ExternalCorpusUnavailable as unavailable:
        raise SystemExit(f"cannot say: {unavailable}") from unavailable
    markdown = render(report, when=date.today().isoformat())
    print(markdown)
    if arguments.write:
        out = (
            Path(__file__).resolve().parents[3]
            / "eval"
            / "matrices"
            / f"comparison_{arguments.bench}.md"
        )
        out.write_text(markdown + "\n", encoding="utf-8")
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
