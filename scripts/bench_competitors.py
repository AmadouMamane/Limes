#!/usr/bin/env python3
r"""Score a competitor on the corpus limes is scored on, and commit only the result (ADR 0020).

limes's README compares itself to other tools in prose. Prose is not a number, and
the numbers those tools publish are measured on their own benches — different
corpora, different thresholds, different definitions of a hit. Quoting one of them
beside a limes figure would produce a comparison that reads like a measurement and
is not one.

So this script measures them, here, on garak's corpus (ADR 0017) — ground **no
contestant wrote**, limes least of all.

**It vendors the result, not the dependency.** llm-guard pulls torch,
transformers, presidio and spacy; a guard library has no business carrying that,
and ADR 0004's frontier says it never will. This script runs in a throwaway
environment, writes one JSON file of verdicts per tool into
``eval/matrices/comparison/``, and those files are what the repository keeps.
``limes.eval.comparison_harness`` renders the matrix from them plus limes computed
live, with no dependency at all. Exactly the shape ``vendor_garak_corpus.py`` uses
for garak.

Reproduce
---------
One environment per tool, none of them the repository's::

    # llm-guard, and the two bare classifiers (they share torch + transformers)
    uv venv mlenv --python 3.12
    uv pip install --python mlenv/bin/python llm-guard==0.3.16 sentencepiece protobuf
    uv pip install --python mlenv/bin/python --no-deps -e .
    mlenv/bin/python scripts/bench_competitors.py --tool llm-guard
    mlenv/bin/python scripts/bench_competitors.py --tool deberta-injection-v2
    mlenv/bin/python scripts/bench_competitors.py --tool deepset-injection

    # rebuff, whose dependency set conflicts with nothing but is its own product
    uv venv rebuffenv --python 3.12
    uv pip install --python rebuffenv/bin/python rebuff==0.1.1
    uv pip install --python rebuffenv/bin/python --no-deps -e .
    rebuffenv/bin/python scripts/bench_competitors.py --tool rebuff

    # mcp-firewall (AGPL-3.0), a rule-based MCP gateway: its injection detector
    # joins the injection table, its PII and secret scanners the two egress
    # tables (ADR 0030)
    uv venv fwenv --python 3.12
    uv pip install --python fwenv/bin/python mcp-firewall==0.1.0
    uv pip install --python fwenv/bin/python --no-deps -e .
    fwenv/bin/python scripts/bench_competitors.py --tool mcp-firewall
    fwenv/bin/python scripts/bench_competitors.py --bench pii --tool mcp-firewall
    fwenv/bin/python scripts/bench_competitors.py --bench secrets --tool mcp-firewall

    # Presidio (its analyzer, with spaCy's large English model) and detect-secrets
    # share an environment; gitleaks is a binary on PATH, run with the catalogue
    # configuration at the vendored commit, whose sha256 the corpus records
    uv venv piienv --python 3.12
    uv pip install --python piienv/bin/python presidio-analyzer==2.2.364 detect-secrets==1.5.0
    uv pip install --python piienv/bin/python \
        https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
    uv pip install --python piienv/bin/python --no-deps -e .
    piienv/bin/python scripts/bench_competitors.py --bench pii --tool presidio
    piienv/bin/python scripts/bench_competitors.py --bench secrets --tool detect-secrets
    piienv/bin/python scripts/bench_competitors.py --bench secrets --tool gitleaks

``-e .`` installs limes itself, for one reason only: the case enumeration
(:func:`limes.eval.comparison_harness.comparison_cases`) must be *the same
function* on both sides, or the two files are about different texts and the join
between them is a coincidence.

Every honest configuration, then one frozen choice
--------------------------------------------------
A competitor is entitled to its best honest setting, so this script records
**every** configuration it can reasonably run rather than one. llm-guard's own
default truncates at 512 tokens, and garak's résumés hide their injection well
past that — judged on ``full`` alone the tool would be scored on text it never
saw, which is sandbagging, not measurement. So ``sentence`` and ``chunks`` are
recorded too, and the harness picks the winner **on the dev split alone** and
freezes it before the held-out columns are computed.

The score, not the boolean
--------------------------
Each configuration stores a *score* per case rather than a verdict, so the
harness can apply a threshold chosen on ``dev`` without anybody re-running a
model. For llm-guard that score is the maximum injection score over the inputs
its own ``MatchType`` produced — which reaching past a private attribute is the
only way to obtain, because its public ``scan()`` returns a risk score that
rounds to one decimal and clamps. ``scan()`` refuses a prompt exactly when that
maximum exceeds the threshold, so the two are equivalent by construction; the run
**checks** it on a sample anyway and records the agreement count, because a
witness that only asserts is not a witness (ADR 0026).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

from limes.eval.comparison_harness import ComparisonCase, comparison_cases, unique_cases
from limes.eval.egress_comparison_harness import (
    EgressCase,
    egress_cases,
    unique_egress_cases,
)

#: How many cases each fidelity and latency probe draws. Fixed here, before any
#: number is known: a sample size chosen after a result is a preference.
PROBE_SAMPLE = 60

#: The seed those probes draw with, so a re-run samples the same cases.
PROBE_SEED = 0


@dataclass(slots=True)
class Bench:
    """Everything one tool's run produced, ready to serialise.

    Attributes:
        tool: The results file's stem, and the name the harness declares.
        label: How the tool is named in the matrix.
        scope: What was actually run — the honest perimeter of the number.
        versions: Every version that could move the number.
        default_configuration: The vendor's own shipped configuration.
        default_threshold: The vendor's own shipped threshold.
        configurations: ``{name: {"description": str, "scores": {key: float}}}``.
        model: The model identity, pinned by name and revision, or ``None``.
        notes: What a reader must know before believing the row.
        fidelity: What was checked about this adapter, and how it came out.
        latency_ms: Median milliseconds per case, measured as a deployer runs it.
    """

    tool: str
    label: str
    scope: str
    versions: dict[str, str]
    default_configuration: str
    default_threshold: float
    configurations: dict[str, dict[str, Any]] = field(default_factory=dict)
    model: dict[str, str] | None = None
    notes: list[str] = field(default_factory=list)
    fidelity: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None


def _probe_sample(cases: Sequence[ComparisonCase]) -> list[ComparisonCase]:
    sampler = random.Random(PROBE_SEED)
    return sampler.sample(list(cases), min(PROBE_SAMPLE, len(cases)))


def _device() -> str:
    import torch

    if torch.backends.mps.is_available():
        return "mps"
    return "cuda" if torch.cuda.is_available() else "cpu"


# --- llm-guard --------------------------------------------------------------


def bench_llm_guard(cases: Sequence[ComparisonCase]) -> Bench:
    """Run Protect AI's llm-guard PromptInjection scanner, in every match type it offers.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench, with one configuration per ``MatchType``.
    """
    import torch
    from llm_guard.input_scanners.prompt_injection import V2_MODEL, MatchType, PromptInjection

    device = _device()
    bench = Bench(
        tool="llm-guard",
        label="llm-guard (Protect AI)",
        scope=("the `PromptInjection` input scanner, with its own default model, run as shipped"),
        versions={
            "llm-guard": distribution_version("llm-guard"),
            "torch": torch.__version__,
            "transformers": distribution_version("transformers"),
            "python": platform.python_version(),
        },
        model={"name": V2_MODEL.path, "revision": V2_MODEL.revision},
        default_configuration="full",
        default_threshold=0.92,
        notes=[
            "`full` is llm-guard's own default and truncates at 512 tokens; garak's résumés "
            "and reports run well past that, so `sentence` and `chunks` are recorded too and "
            "the harness picks between them on the dev split alone.",
            "the threshold 0.92 and the match type `full` are the library's shipped defaults, "
            "not values chosen here.",
        ],
    )

    # MatchType.SENTENCE and .CHUNKS split before classifying; .FULL is the default
    # and truncates. TRUNCATE_* are recorded too: they are what the library offers a
    # user who knows their inputs are long, and leaving them out would be choosing
    # the competitor's configuration for it.
    match_types = {
        "full": MatchType.FULL,
        "sentence": MatchType.SENTENCE,
        "chunks": MatchType.CHUNKS,
        "truncate-head-tail": MatchType.TRUNCATE_TOKEN_HEAD_TAIL,
    }
    scanners = {
        name: PromptInjection(threshold=bench.default_threshold, match_type=match_type)
        for name, match_type in match_types.items()
    }

    for name, scanner in scanners.items():
        scores: dict[str, float] = {}
        started = time.perf_counter()
        for index, case in enumerate(cases, start=1):
            scores[case.key] = _llm_guard_score(scanner, case.text)
            if index % 200 == 0:
                elapsed = time.perf_counter() - started
                print(f"  {name}: {index}/{len(cases)} ({elapsed:.0f}s)", file=sys.stderr)
        bench.configurations[name] = {
            "description": f"llm-guard MatchType.{match_types[name].name}",
            "scores": scores,
        }

    # The equivalence this adapter rests on, measured rather than asserted:
    # scan() refuses exactly when the maximum injection score exceeds the
    # threshold, so a recorded maximum reproduces every verdict scan() would give.
    default = scanners["full"]
    agreements = 0
    sample = _probe_sample(cases)
    for case in sample:
        _, is_valid, _ = default.scan(case.text)
        derived = bench.configurations["full"]["scores"][case.key] > bench.default_threshold
        agreements += int(is_valid != derived)
    bench.fidelity = {
        "claim": "scan() refuses iff the recorded maximum score exceeds the threshold",
        "sampled": len(sample),
        "agreements": agreements,
    }

    latencies: list[float] = []
    for case in sample:
        started = time.perf_counter()
        default.scan(case.text)
        latencies.append((time.perf_counter() - started) * 1000)
    bench.latency_ms = round(statistics.median(latencies), 2)
    bench.versions["device"] = device
    return bench


def _llm_guard_score(scanner: Any, text: str) -> float:  # noqa: ANN401
    if not text.strip():
        return 0.0
    highest = 0.0
    for result in scanner._pipeline(scanner._match_type.get_inputs(text)):
        score = round(result["score"] if result["label"] == "INJECTION" else 1 - result["score"], 2)
        highest = max(highest, score)
    return highest


# --- the bare classifiers ---------------------------------------------------


def _hf_bench(
    tool: str,
    label: str,
    scope: str,
    model_name: str,
    revision: str,
    licence: str,
    notes: list[str],
    cases: Sequence[ComparisonCase],
) -> Bench:
    import torch
    from llm_guard.util import split_text_by_sentences
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

    device = _device()
    tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, revision=revision)
    model = model.eval().to(device)

    injection = [
        index for index, name in model.config.id2label.items() if "INJECT" in str(name).upper()
    ]
    if len(injection) != 1:
        # Guessing which logit means "attack" would make every number below a
        # statement about a guess (ADR 0026): refuse instead.
        raise SystemExit(
            f"cannot say: {model_name} labels its classes {model.config.id2label!r}, and "
            "exactly one of them must name injection for this bench to read its output."
        )
    injection_index = injection[0]
    limit = int(getattr(tokenizer, "model_max_length", 512) or 512)
    limit = min(limit, 512)

    def _classify(pieces: Sequence[list[int]]) -> float:
        best = 0.0
        for start in range(0, len(pieces), 16):
            batch = pieces[start : start + 16]
            encoded = tokenizer.pad(
                {
                    "input_ids": [
                        tokenizer.build_inputs_with_special_tokens(piece) for piece in batch
                    ]
                },
                return_tensors="pt",
            ).to(device)
            with torch.no_grad():
                logits = model(**encoded).logits
            best = max(best, float(torch.softmax(logits, dim=-1)[:, injection_index].max()))
        return best

    def score(text: str, strategy: str) -> float:
        room = limit - 2
        if strategy == "sentence":
            pieces = [
                tokenizer(sentence, add_special_tokens=False)["input_ids"][:room]
                for sentence in split_text_by_sentences(text)
            ]
        else:
            ids: list[int] = tokenizer(text, add_special_tokens=False)["input_ids"]
            step = room if strategy == "head-512" else room - 128
            starts = [0] if strategy == "head-512" else list(range(0, max(len(ids), 1), step))
            pieces = [ids[start : start + room] for start in starts]
        return _classify([piece for piece in pieces if piece] or [[]])

    bench = Bench(
        tool=tool,
        label=label,
        scope=scope,
        versions={
            "torch": torch.__version__,
            "transformers": distribution_version("transformers"),
            "python": platform.python_version(),
            "device": device,
        },
        model={"name": model_name, "revision": revision, "license": licence},
        default_configuration="head-512",
        default_threshold=0.5,
        notes=notes,
    )
    # Three input strategies, because a classifier judged on the wrong one is judged
    # on somebody's input handling rather than on its classification. `head-512` is
    # what a naive `truncation=True` gives and misses anything hidden past token 512.
    # `sentence` is the same split llm-guard's SENTENCE match type performs — a
    # wrapper this bench supplies on purpose, so that the bare rows measure the model
    # and not the absence of a product around it.
    plans = {
        "head-512": "the first 512 tokens only — what a naive `truncation=True` gives",
        "window-512": "sliding 512-token windows, 128 tokens of overlap, scored by their maximum",
        "sentence": "sentence by sentence, scored by the maximum — the split llm-guard performs",
    }
    for name, description in plans.items():
        scores: dict[str, float] = {}
        started = time.perf_counter()
        for index, case in enumerate(cases, start=1):
            scores[case.key] = score(case.text, name)
            if index % 200 == 0:
                elapsed = time.perf_counter() - started
                print(f"  {name}: {index}/{len(cases)} ({elapsed:.0f}s)", file=sys.stderr)
        bench.configurations[name] = {"description": description, "scores": scores}

    # This adapter tokenises, pads and softmaxes by hand, so "the score is the
    # model's" is a claim about code nobody has checked. It is checked here
    # against the library's own text-classification pipeline — the path an
    # ordinary user takes — on the single-chunk configuration, where the two must
    # agree exactly. An adapter that quietly disagrees with the tool it claims to
    # run would make every number in the matrix a statement about this file.
    reference = pipeline(
        "text-classification",
        model=model,
        tokenizer=tokenizer,
        device=device,
        top_k=None,
        truncation=True,
        max_length=limit,
    )
    injection_label = str(model.config.id2label[injection_index])
    sample = _probe_sample(cases)
    agreements = 0
    latencies: list[float] = []
    for case in sample:
        started = time.perf_counter()
        mine = score(case.text, "head-512")
        latencies.append((time.perf_counter() - started) * 1000)
        theirs = next(
            entry["score"] for entry in reference(case.text)[0] if entry["label"] == injection_label
        )
        agreements += int(abs(mine - theirs) < 1e-4)
    bench.latency_ms = round(statistics.median(latencies), 2)
    bench.fidelity = {
        "claim": (
            "on the single-chunk configuration this adapter's score equals, to 1e-4, what "
            "transformers' own text-classification pipeline reports for the injection label"
        ),
        "sampled": len(sample),
        "agreements": agreements,
    }
    return bench


def bench_deberta_injection_v2(cases: Sequence[ComparisonCase]) -> Bench:
    """Run llm-guard's model with no product around it — rules versus a classifier.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench.
    """
    return _hf_bench(
        tool="deberta-injection-v2",
        label="DeBERTa injection v2 (bare classifier)",
        scope=(
            "Protect AI's classifier alone, no library around it — the ML floor, and the "
            "isolate that says how much of llm-guard's number is its wrapper"
        ),
        model_name="protectai/deberta-v3-base-prompt-injection-v2",
        revision="89b085cd330414d3e7d9dd787870f315957e1e9f",
        licence="Apache-2.0",
        notes=[
            "the same checkpoint llm-guard pins, at the same revision, so the difference "
            "between this row and llm-guard's is the wrapper and nothing else.",
            "trained on public prompt-injection datasets, which may overlap garak's sources; "
            "that asymmetry favours this row and cannot be undone, only stated.",
        ],
        cases=cases,
    )


def bench_deepset_injection(cases: Sequence[ComparisonCase]) -> Bench:
    """Run a second, independently trained classifier, so the ML answer is not one model's quirk.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench.
    """
    return _hf_bench(
        tool="deepset-injection",
        label="deepset injection (bare classifier)",
        scope="a second classifier, trained by somebody else, as an independent ML floor",
        model_name="deepset/deberta-v3-base-injection",
        revision="80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1",
        licence="MIT",
        notes=[
            "a different author and a different training set from the Protect AI model, so "
            "the two together say whether an ML answer is a property of classifiers or of "
            "one checkpoint.",
            "trained on public prompt-injection datasets, which may overlap garak's sources.",
        ],
        cases=cases,
    )


# --- rebuff -----------------------------------------------------------------


def bench_rebuff(cases: Sequence[ComparisonCase]) -> Bench:
    """Run rebuff's offline half, and say plainly that it is a floor for rebuff, not rebuff.

    rebuff's deployed product is four layers: heuristics, an LLM judge, a vector
    store of past attacks, and canary tokens. Three of them need an OpenAI key and
    a Pinecone index. Offline, only the heuristics run, so this row **under-states
    rebuff** and the matrix says so where a reader will see it.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench.
    """
    from rebuff.detect_pi_heuristics import (
        detect_prompt_injection_using_heuristic_on_input as verbatim,
    )

    bench = Bench(
        tool="rebuff",
        label="rebuff (Protect AI) — heuristics only",
        scope=("`detect_prompt_injection_using_heuristic_on_input`, one of rebuff's four layers"),
        versions={
            "rebuff": distribution_version("rebuff"),
            "python": platform.python_version(),
        },
        default_configuration="heuristic",
        default_threshold=0.75,
        notes=[
            "**this row under-states rebuff, deliberately.** Its deployed detector is "
            "heuristics + an LLM judge + a vector store of past attacks + canary tokens; "
            "the last three need an OpenAI key and a Pinecone index and do not run offline. "
            "Read this as rebuff's floor, never as rebuff.",
            "0.75 is `RebuffSdk.detect_injection`'s own `max_heuristic_score` default, and "
            "the SDK flags when the score is strictly greater than it.",
        ],
    )

    scores: dict[str, float] = {}
    started = time.perf_counter()
    for index, case in enumerate(cases, start=1):
        scores[case.key] = _rebuff_score(case.text)
        if index % 100 == 0:
            elapsed = time.perf_counter() - started
            print(f"  heuristic: {index}/{len(cases)} ({elapsed:.0f}s)", file=sys.stderr)
    bench.configurations["heuristic"] = {
        "description": "rebuff's keyword-similarity heuristic, its own scoring",
        "scores": scores,
    }

    # The pruning below is provably lossless, and proof is not measurement, so the
    # two implementations are run against each other on a sample and the count is
    # recorded. Verbatim rebuff takes ~90 s on a 1.6 kB document, so the sample is
    # drawn from the short population; a full-corpus verbatim run is ~37 hours.
    sampler = random.Random(PROBE_SEED)
    short = [case for case in cases if len(case.text) <= 400]
    sample = sampler.sample(short, min(PROBE_SAMPLE, len(short)))
    agreements = 0
    latencies: list[float] = []
    for case in sample:
        started = time.perf_counter()
        reference = verbatim(case.text)
        latencies.append((time.perf_counter() - started) * 1000)
        agreements += int(_rebuff_score(case.text) == reference)
    bench.fidelity = {
        "claim": (
            "the pruned scorer returns the identical float to rebuff's own function: a "
            "candidate is skipped only when its base score cannot exceed the running maximum"
        ),
        "sampled": len(sample),
        "agreements": agreements,
        "sample_scope": "cases of at most 400 characters — verbatim rebuff is O(keywords x words)",
    }

    bench.latency_ms = round(statistics.median(latencies), 2)
    bench.notes.append(
        f"latency is rebuff's own function, unmodified, on the same short sample: "
        f"{bench.latency_ms:.0f} ms median on texts of at most 400 characters. On a 1.6 kB "
        "document it takes about 90 seconds, which is why the corpus was scored with a "
        "pruned scorer proven and measured to return the identical float."
    )
    return bench


_KEYWORDS_BY_LENGTH: dict[int, list[str]] | None = None


def _rebuff_score(text: str) -> float:
    """Rebuff's heuristic, pruned of the work that provably cannot change its answer.

    rebuff scores 8 800 generated keyword phrases against every same-length window
    of the input, and calls ``SequenceMatcher`` on each pair: about 3 million
    similarity computations for a 2 kB document, roughly 90 seconds. Scoring 1 486
    documents that way is 37 hours, so two candidates are skipped:

    * ``matched_words_count == 0`` gives ``base = 0`` and therefore
      ``adjusted = -similarity/10 <= 0``, which can never exceed a maximum that
      starts at 0;
    * ``base <= highest`` gives ``adjusted = base - similarity/10 <= highest``.

    Neither can be the maximum, so the returned float is identical — and the run
    checks that against rebuff's own function rather than trusting this paragraph.

    Args:
        text: The case to score.

    Returns:
        rebuff's heuristic score.
    """
    from difflib import SequenceMatcher

    from rebuff.detect_pi_heuristics import (
        generate_injection_keywords,
        get_input_substrings,
        normalize_string,
    )

    global _KEYWORDS_BY_LENGTH
    if _KEYWORDS_BY_LENGTH is None:
        grouped: dict[int, list[str]] = {}
        for keyword in generate_injection_keywords():
            normalised = normalize_string(keyword)
            grouped.setdefault(len(normalised.split(" ")), []).append(normalised)
        _KEYWORDS_BY_LENGTH = grouped

    max_matched_words = 5
    highest = 0.0
    normalised_input = normalize_string(text)
    for length, keywords in _KEYWORDS_BY_LENGTH.items():
        substrings = get_input_substrings(normalised_input, length)
        words_of = [substring.split() for substring in substrings]
        for keyword in keywords:
            parts = keyword.split(" ")
            for substring, words in zip(substrings, words_of, strict=True):
                matched = sum(1 for part, word in zip(parts, words, strict=False) if part == word)
                if not matched:
                    continue
                base = 0.5 + 0.5 * min(matched / max_matched_words, 1)
                if base <= highest:
                    continue
                similarity = SequenceMatcher(None, substring, keyword).ratio()
                adjusted = base - similarity * (1 / (max_matched_words * 2))
                if adjusted > highest:
                    highest = adjusted
    return highest


# --- mcp-firewall (ADR 0030) -------------------------------------------------


def _firewall_versions() -> dict[str, str]:
    return {
        "mcp-firewall": distribution_version("mcp-firewall"),
        "python": platform.python_version(),
    }


def bench_mcp_firewall(cases: Sequence[ComparisonCase]) -> Bench:
    """Run mcp-firewall's pattern-based injection detector, at each of its three sensitivities.

    The detector reads a tool call's arguments, so each case is handed to it as
    the one string argument of a tool call — which is how a deployment meets it.
    A rule matches or it does not: the recorded score is ``1.0`` for a refusal
    and ``0.0`` otherwise, and the tool has no threshold of its own to choose.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench, one configuration per sensitivity; ``medium`` is the default.
    """
    from mcp_firewall.models import GatewayConfig, ToolCallRequest
    from mcp_firewall.pipeline.inbound.injection import SENSITIVITY_MAP, InjectionDetector

    detector = InjectionDetector()
    config = GatewayConfig()
    default_sensitivity = config.injection.sensitivity

    def refuses(text: str, sensitivity: str) -> bool:
        config.injection.sensitivity = sensitivity
        request = ToolCallRequest(tool_name="tool", arguments={"text": text})
        return detector.evaluate(request, config) is not None

    bench = Bench(
        tool="mcp-firewall",
        label="mcp-firewall (pattern injection detector)",
        scope=(
            "the `InjectionDetector` inbound stage — a fixed list of regular expressions "
            "over the flattened tool-call arguments — at each sensitivity it ships"
        ),
        versions=_firewall_versions(),
        default_configuration=default_sensitivity,
        default_threshold=0.5,
        notes=[
            f"`{default_sensitivity}` is the sensitivity mcp-firewall's `GatewayConfig` "
            "ships with; `low` and `high` are its other two settings, recorded so the dev "
            "split can pick between them.",
            "the detector has no score: a pattern matches or it does not, so its recorded "
            "score is 1 or 0 and the operating points collapse to one per sensitivity.",
            "each case is handed over as the single string argument of a tool call, which is "
            "what the detector reads in deployment; it flattens the argument name into the "
            "searched text, so the word `text` precedes every case.",
        ],
    )
    for sensitivity, patterns in SENSITIVITY_MAP.items():
        scores: dict[str, float] = {}
        for case in cases:
            scores[case.key] = 1.0 if refuses(case.text, sensitivity) else 0.0
        bench.configurations[sensitivity] = {
            "description": f"sensitivity `{sensitivity}` — {len(patterns)} pattern(s)",
            "scores": scores,
        }

    sample = _probe_sample(cases)
    fresh = InjectionDetector()
    fresh_config = GatewayConfig()
    agreements = 0
    latencies: list[float] = []
    for case in sample:
        request = ToolCallRequest(tool_name="tool", arguments={"text": case.text})
        started = time.perf_counter()
        decision = fresh.evaluate(request, fresh_config)
        latencies.append((time.perf_counter() - started) * 1000)
        recorded = bench.configurations[default_sensitivity]["scores"][case.key] > 0.5
        agreements += int((decision is not None) == recorded)
    bench.fidelity = {
        "claim": (
            "a fresh detector under a fresh default config refuses exactly the sampled "
            "cases the recorded default configuration scored 1.0 — the adapter adds nothing "
            "between the tool and the number"
        ),
        "sampled": len(sample),
        "agreements": agreements,
    }
    bench.latency_ms = round(statistics.median(latencies), 2)
    return bench


ADAPTERS: dict[str, Callable[[Sequence[ComparisonCase]], Bench]] = {
    "llm-guard": bench_llm_guard,
    "rebuff": bench_rebuff,
    "deberta-injection-v2": bench_deberta_injection_v2,
    "deepset-injection": bench_deepset_injection,
    "mcp-firewall": bench_mcp_firewall,
}


# --- the egress benches: PII and secrets (ADR 0030) -----------------------------

#: One recorded finding: the tool's own kind, the limes category it maps to (or
#: None), the span in the case text, and the tool's score (1.0 when it has none).
type RecordedFinding = list[Any]

#: Presidio's entity types for the four categories both sides claim. Its other
#: fifteen types are recorded with a null category: neither credited nor charged.
_PRESIDIO_CATEGORIES = {
    "CREDIT_CARD": "pan",
    "IBAN_CODE": "iban",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
}

#: mcp-firewall's PII pattern names for the same four categories.
_FIREWALL_PII_CATEGORIES = {
    "Credit Card": "pan",
    "IBAN": "iban",
    "Email Address": "email",
    "Phone (International)": "phone",
}


@dataclass(slots=True)
class EgressBench:
    """Everything one tool's egress run produced, ready to serialise.

    Attributes:
        bench: ``pii`` or ``secrets``.
        tool: The results file's stem, and the name the harness declares.
        label: How the tool is named in the matrix.
        scope: What was actually run.
        versions: Every version that could move the number.
        default_configuration: The vendor's own configuration.
        default_threshold: The vendor's own threshold (``0.5`` for a boolean tool).
        configurations: ``{name: {"description": str, "findings": {key: [finding, ...]}}}``.
        model: The model identity, or ``None``.
        notes: What a reader must know before believing the row.
        fidelity: What was checked about this adapter, and how it came out.
        latency_ms: Median milliseconds per case, measured as a deployer runs it.
        home_ground: Why this corpus is the tool's own material, or ``None``.
    """

    bench: str
    tool: str
    label: str
    scope: str
    versions: dict[str, str]
    default_configuration: str
    default_threshold: float
    configurations: dict[str, dict[str, Any]] = field(default_factory=dict)
    model: dict[str, str] | None = None
    notes: list[str] = field(default_factory=list)
    fidelity: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    home_ground: str | None = None


def _egress_sample(cases: Sequence[EgressCase]) -> list[EgressCase]:
    sampler = random.Random(PROBE_SEED)
    return sampler.sample(list(cases), min(PROBE_SAMPLE, len(cases)))


def _regex_findings(
    text: str, patterns: Sequence[tuple[str, str]], categories: dict[str, str]
) -> list[RecordedFinding]:
    found: list[RecordedFinding] = []
    for name, pattern in patterns:
        for match in re.finditer(pattern, text):
            found.append([name, categories.get(name), match.start(), match.end(), 1.0])
    return found


def bench_presidio(cases: Sequence[EgressCase]) -> EgressBench:
    """Run Microsoft Presidio's analyzer, every recogniser it ships, on the PII sentences.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench, with the analyzer's default threshold (0) as the vendor row.
    """
    import spacy
    from presidio_analyzer import AnalyzerEngine

    engine = AnalyzerEngine()
    model_name = "en_core_web_lg"
    model_version = spacy.load(model_name).meta["version"]
    findings: dict[str, list[RecordedFinding]] = {}
    started = time.perf_counter()
    for index, case in enumerate(cases, start=1):
        results = engine.analyze(text=case.text, language="en")
        findings[case.key] = [
            [
                result.entity_type,
                _PRESIDIO_CATEGORIES.get(result.entity_type),
                result.start,
                result.end,
                float(result.score),
            ]
            for result in results
        ]
        if index % 200 == 0:
            print(
                f"  analyzer: {index}/{len(cases)} ({time.perf_counter() - started:.0f}s)",
                file=sys.stderr,
            )

    bench = EgressBench(
        bench="pii",
        tool="presidio",
        label="Presidio analyzer (Microsoft)",
        scope=(
            "`AnalyzerEngine.analyze(language='en')` with every recogniser the library "
            "ships and spaCy's large English model — the whole analyzer, as installed"
        ),
        versions={
            "presidio-analyzer": distribution_version("presidio-analyzer"),
            "spacy": distribution_version("spacy"),
            "python": platform.python_version(),
        },
        model={"name": model_name, "revision": model_version},
        default_configuration="analyzer",
        default_threshold=float(engine.default_score_threshold),
        notes=[
            "four of its entity types are read as the four categories both sides claim — "
            "`CREDIT_CARD`, `IBAN_CODE`, `EMAIL_ADDRESS`, `PHONE_NUMBER`; its other fifteen "
            "(names, dates, places, US identifiers…) are recorded and count for nothing "
            "either way.",
            f"the vendor threshold {engine.default_score_threshold:g} is the analyzer's own "
            "`default_score_threshold`; each recogniser scores its own findings (a checksum-"
            "valid card or IBAN at 1.0, a phone number at 0.4), and the dev split chooses the "
            "cut for the tuned rows.",
            "**home ground for the prose**: the sentence templates are presidio-research's, "
            "the Presidio project's own evaluation material. The values inside them are "
            "limes's synthetic vectors.",
        ],
        home_ground=(
            "The PII sentences are presidio-research's — the Presidio project's own "
            "evaluation templates — so Presidio meets prose its project wrote; the values "
            "inside them are limes's."
        ),
    )
    bench.configurations["analyzer"] = {
        "description": "every shipped recogniser, English, spaCy en_core_web_lg",
        "findings": findings,
    }

    # Presidio applies its threshold itself; the harness applies the recorded scores
    # with `score > threshold`. The two must name the same findings at a cut the
    # vendor did not choose, and the comparison Presidio uses is recorded rather
    # than assumed.
    probe = 0.5
    sample = _egress_sample(cases)
    agreements = 0
    latencies: list[float] = []
    for case in sample:
        started = time.perf_counter()
        results = engine.analyze(text=case.text, language="en", score_threshold=probe)
        latencies.append((time.perf_counter() - started) * 1000)
        theirs = {(r.entity_type, r.start, r.end) for r in results}
        mine = {
            (kind, start, end)
            for kind, _, start, end, score in findings[case.key]
            if score >= probe
        }
        agreements += int(theirs == mine)
    bench.fidelity = {
        "claim": (
            f"at score_threshold={probe}, analyze()'s own filtering names exactly the recorded "
            "findings with score >= threshold (Presidio keeps a score equal to the cut; the "
            "harness's `score > threshold` is therefore stricter by at most the cut itself)"
        ),
        "sampled": len(sample),
        "agreements": agreements,
    }
    bench.latency_ms = round(statistics.median(latencies), 2)
    return bench


def bench_firewall_pii(cases: Sequence[EgressCase]) -> EgressBench:
    """Run mcp-firewall's PII detector — seven regular expressions — over the PII sentences.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench.
    """
    from mcp_firewall.models import GatewayConfig, ToolCallResponse
    from mcp_firewall.pipeline.outbound.pii import PII_PATTERNS, PIIDetector

    config = GatewayConfig()
    shipped_enabled = config.pii.enabled
    config.pii.enabled = True
    detector = PIIDetector()
    findings = {
        case.key: _regex_findings(case.text, PII_PATTERNS, _FIREWALL_PII_CATEGORIES)
        for case in cases
    }
    bench = EgressBench(
        bench="pii",
        tool="mcp-firewall",
        label="mcp-firewall (PII detector)",
        scope="the `PIIDetector` outbound stage — seven regular expressions, no checksum",
        versions=_firewall_versions(),
        default_configuration="patterns",
        default_threshold=0.5,
        notes=[
            "four of its seven pattern names are read as the four categories both sides "
            "claim — `Credit Card`, `IBAN`, `Email Address`, `Phone (International)`; its "
            "`SSN (US)`, `AHV (Swiss SSN)` and `IPv4 Address` count for nothing either way.",
            (
                "PII detection ships **disabled** in mcp-firewall's default configuration "
                "(`pii.enabled = False`); it was switched on for this bench, as an operator "
                "who wants the feature would."
                if not shipped_enabled
                else "PII detection ships enabled in mcp-firewall's default configuration."
            ),
            "the detector reports the pattern names that fired and not their offsets, so the "
            "spans are taken from its own patterns run over the same text; the fidelity check "
            "holds the two to the same set of names.",
        ],
    )
    bench.configurations["patterns"] = {
        "description": "PII_PATTERNS, as shipped, over the text of a tool response",
        "findings": findings,
    }
    sample = _egress_sample(cases)
    agreements = 0
    latencies: list[float] = []
    for case in sample:
        response = ToolCallResponse(request_id="r", content=[{"type": "text", "text": case.text}])
        started = time.perf_counter()
        _, decision = detector.scan(response, config)
        latencies.append((time.perf_counter() - started) * 1000)
        theirs = set(decision.details.get("pii_types", ())) if decision is not None else set()
        mine = {kind for kind, *_ in findings[case.key]}
        agreements += int(theirs == mine)
    bench.fidelity = {
        "claim": (
            "the pattern names the adapter's spans carry are exactly the `pii_types` the "
            "tool's own scan() reports on the same text"
        ),
        "sampled": len(sample),
        "agreements": agreements,
    }
    bench.latency_ms = round(statistics.median(latencies), 2)
    return bench


def bench_firewall_secrets(cases: Sequence[EgressCase]) -> EgressBench:
    """Run mcp-firewall's secret scanner — seventeen regular expressions — over the catalogue.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench.
    """
    from mcp_firewall.models import GatewayConfig, ToolCallResponse
    from mcp_firewall.pipeline.outbound.secrets import SECRET_PATTERNS, SecretScanner

    config = GatewayConfig()
    scanner = SecretScanner()
    patterns = [(name, pattern) for name, pattern, _ in SECRET_PATTERNS]
    findings = {case.key: _regex_findings(case.text, patterns, {}) for case in cases}
    bench = EgressBench(
        bench="secrets",
        tool="mcp-firewall",
        label="mcp-firewall (secret scanner)",
        scope="the `SecretScanner` outbound stage — seventeen regular expressions, no validator",
        versions=_firewall_versions(),
        default_configuration="patterns",
        default_threshold=0.5,
        notes=[
            "secret scanning ships enabled, action `redact`; the scan's decision carries "
            "the names of the patterns that fired, which the fidelity check compares against "
            "the adapter's spans.",
            "the scanner reports pattern names and not offsets, so the spans are taken from "
            "its own patterns run over the same text.",
        ],
    )
    bench.configurations["patterns"] = {
        "description": "SECRET_PATTERNS, as shipped, over the text of a tool response",
        "findings": findings,
    }
    sample = _egress_sample(cases)
    agreements = 0
    latencies: list[float] = []
    for case in sample:
        response = ToolCallResponse(request_id="r", content=[{"type": "text", "text": case.text}])
        started = time.perf_counter()
        _, decision = scanner.scan(response, config)
        latencies.append((time.perf_counter() - started) * 1000)
        theirs = (
            {entry["name"] for entry in decision.details.get("findings", ())}
            if decision is not None
            else set()
        )
        mine = {kind for kind, *_ in findings[case.key]}
        agreements += int(theirs == mine)
    bench.fidelity = {
        "claim": (
            "the pattern names the adapter's spans carry are exactly the findings the tool's "
            "own scan() reports on the same text"
        ),
        "sampled": len(sample),
        "agreements": agreements,
    }
    bench.latency_ms = round(statistics.median(latencies), 2)
    return bench


def _span_of(text: str, secret: str) -> tuple[int, int] | None:
    start = text.find(secret)
    return None if start < 0 or not secret else (start, start + len(secret))


def bench_detect_secrets(cases: Sequence[EgressCase]) -> EgressBench:
    """Run Yelp's detect-secrets in both of its shipped modes over the catalogue.

    ``file`` is how the tool ships — a file scanned by every default plugin, whose
    entropy plugins read quoted strings. ``adhoc`` is its ``--string`` path, which
    searches every whitespace-separated token eagerly. Both are honest
    configurations of the same tool; the dev split chooses between them.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench, ``file`` as the vendor default.
    """
    from detect_secrets.core import scan
    from detect_secrets.settings import default_settings

    file_findings: dict[str, list[RecordedFinding]] = {}
    adhoc_findings: dict[str, list[RecordedFinding]] = {}
    latencies: list[float] = []
    sample_keys = {case.key for case in _egress_sample(cases)}
    with tempfile.TemporaryDirectory() as directory:
        for case in cases:
            path = Path(directory) / f"{case.key}.txt"
            path.write_text(case.text, encoding="utf-8")
            with default_settings():
                started = time.perf_counter()
                secrets = list(scan.scan_file(str(path)))
                if case.key in sample_keys:
                    latencies.append((time.perf_counter() - started) * 1000)
            found: list[RecordedFinding] = []
            for secret in secrets:
                span = _span_of(case.text, secret.secret_value or "")
                if span is not None:
                    found.append([secret.type, None, span[0], span[1], 1.0])
            file_findings[case.key] = found
            with default_settings():
                adhoc = list(scan.scan_line(case.text))
            found = []
            for secret in adhoc:
                span = _span_of(case.text, secret.secret_value or "")
                if span is not None:
                    found.append([secret.type, None, span[0], span[1], 1.0])
            adhoc_findings[case.key] = found

        # The adapter calls the library; the CLI is what a deployer runs. On a
        # sample, the CLI's own baseline output must name the same plugin types.
        agreements = 0
        sampled = 0
        for case in cases:
            if case.key not in sample_keys:
                continue
            sampled += 1
            path = Path(directory) / f"{case.key}.txt"
            completed = subprocess.run(
                [sys.executable, "-m", "detect_secrets", "scan", "--no-verify", str(path)],
                capture_output=True,
                text=True,
                check=False,
                cwd=directory,
            )
            baseline = json.loads(completed.stdout) if completed.stdout.strip() else {}
            theirs = {
                entry["type"]
                for entries in baseline.get("results", {}).values()
                for entry in entries
            }
            mine = {kind for kind, *_ in file_findings[case.key]}
            agreements += int(theirs == mine)

    bench = EgressBench(
        bench="secrets",
        tool="detect-secrets",
        label="detect-secrets (Yelp)",
        scope=(
            "every default plugin, over a file per case (`file`) and over the bare string (`adhoc`)"
        ),
        versions={
            "detect-secrets": distribution_version("detect-secrets"),
            "python": platform.python_version(),
        },
        default_configuration="file",
        default_threshold=0.5,
        notes=[
            "`file` is the tool as shipped: a file scanned by its default plugins, whose "
            "high-entropy plugins read quoted strings and leave prose alone. `adhoc` is its "
            "`--string` path, which searches every token eagerly and flags ordinary words as "
            "high-entropy; both are recorded and the dev split chose between them.",
            "a plugin reports the secret value it matched, and the span is that value's "
            "position in the text; the GitHub plugin reports only the token's prefix, which "
            "still sits inside the token and is credited as located.",
            "the command line verifies some findings against the vendor's API by default — a "
            "Slack token is checked with Slack — and drops a token the vendor rejects; the "
            "fidelity check runs it with `--no-verify`, so the number is offline and does not "
            "depend on a third party's answer about a synthetic token. The library path the "
            "adapter calls does not verify.",
            "a source-code scanner, not a text guard: nothing here is a criticism of the tool "
            "on the ground it was built for.",
        ],
    )
    bench.configurations["file"] = {
        "description": "scan_file over one file per case, default plugins",
        "findings": file_findings,
    }
    bench.configurations["adhoc"] = {
        "description": "scan_line over the bare text — the `--string` path, eager search",
        "findings": adhoc_findings,
    }
    bench.fidelity = {
        "claim": (
            "on the sample, `detect-secrets scan --no-verify <file>` from the command line "
            "names exactly the plugin types the adapter's `file` findings carry"
        ),
        "sampled": sampled,
        "agreements": agreements,
    }
    bench.latency_ms = round(statistics.median(latencies), 2) if latencies else None
    return bench


def bench_gitleaks(cases: Sequence[EgressCase]) -> EgressBench:
    """Run the gitleaks binary over the catalogue it was generated from, and say so.

    The configuration is the catalogue at the vendored commit — fetched, checked
    against the sha256 the corpus records, and passed with ``--config`` — so the
    rules the tool runs are byte-for-byte the rules the instances were made from.
    A binary of any newer version then scores the corpus's rules, not its own.

    Args:
        cases: One entry per distinct text.

    Returns:
        The bench, marked home ground.

    Raises:
        SystemExit: No ``gitleaks`` on PATH, or the fetched configuration does not
            hash to what the corpus records — a number over drifted rules would be
            about the drift.
    """
    from limes.eval.external_egress_corpus import load_secrets_external

    binary = shutil.which("gitleaks")
    if binary is None:
        raise SystemExit("cannot say: no `gitleaks` binary on PATH")
    version = subprocess.run([binary, "version"], capture_output=True, text=True, check=True)
    source = load_secrets_external().source
    commit = str(source["commit"])
    expected_sha = str(source["config_sha256"])
    url = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{commit}/{source['config_path']}"
    with urllib.request.urlopen(url, timeout=60) as response:
        config_bytes = response.read()
    actual_sha = hashlib.sha256(config_bytes).hexdigest()
    if actual_sha != expected_sha:
        raise SystemExit(
            f"cannot say: the catalogue configuration at {commit[:12]} hashes to {actual_sha}, "
            f"and the corpus records {expected_sha}"
        )

    findings: dict[str, list[RecordedFinding]] = {case.key: [] for case in cases}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config_path = root / "gitleaks.toml"
        config_path.write_bytes(config_bytes)
        target = root / "cases"
        target.mkdir()
        for case in cases:
            (target / f"{case.key}.txt").write_text(case.text, encoding="utf-8")
        report = root / "report.json"
        subprocess.run(
            [
                binary,
                "dir",
                str(target),
                "--config",
                str(config_path),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        entries = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else []
        by_key = {case.key: case for case in cases}
        for entry in entries or []:
            key = Path(entry["File"]).stem
            case = by_key.get(key)
            if case is None:
                continue
            secret = str(entry.get("Secret") or entry.get("Match") or "")
            span = _span_of(case.text, secret)
            if span is not None:
                findings[key].append([entry["RuleID"], None, span[0], span[1], 1.0])

        # Two invocation paths, one answer: the per-payload path a deployer would
        # use (`gitleaks stdin`) must name the same rules as the directory scan.
        sample = _egress_sample(cases)
        agreements = 0
        latencies: list[float] = []
        for case in sample:
            started = time.perf_counter()
            completed = subprocess.run(
                [
                    binary,
                    "stdin",
                    "--config",
                    str(config_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(root / "stdin.json"),
                    "--exit-code",
                    "0",
                    "--no-banner",
                ],
                input=case.text,
                capture_output=True,
                text=True,
                check=False,
            )
            latencies.append((time.perf_counter() - started) * 1000)
            stdin_report = root / "stdin.json"
            theirs_entries = (
                json.loads(stdin_report.read_text(encoding="utf-8"))
                if stdin_report.is_file()
                else []
            )
            theirs = {str(e["RuleID"]) for e in theirs_entries or []}
            mine = {kind for kind, *_ in findings[case.key]}
            agreements += int(theirs == mine and completed.returncode == 0)

    bench = EgressBench(
        bench="secrets",
        tool="gitleaks",
        label="gitleaks",
        scope=(
            "the `gitleaks` binary over one file per case, with the catalogue configuration "
            f"at the vendored commit `{commit[:12]}` passed as `--config`"
        ),
        versions={
            "gitleaks": version.stdout.strip(),
            "config": f"{commit[:12]} (sha256 {expected_sha[:12]}…)",
        },
        default_configuration="dir",
        default_threshold=0.5,
        notes=[
            "**home ground**: every positive here was generated from a gitleaks regex and "
            "verified against it, and every negative is a vector gitleaks' own allowlists were "
            "written to pass. This row is a ceiling and a check on the corpus, not a "
            "comparison.",
            "the configuration is the catalogue at the commit the corpus was vendored from, "
            "checked against the sha256 the corpus records, so the binary scores the corpus's "
            "own rules and not a newer catalogue's.",
            "a rule matches or it does not: the recorded score is 1, and there is no "
            "threshold to choose.",
            "latency is one `gitleaks stdin` process per payload, the path a deployer would "
            "run on each tool result, process start included.",
        ],
        home_ground=(
            "The secrets corpus is gitleaks' own catalogue: every positive was generated from a "
            "gitleaks regex and every negative is a vector its allowlists were written to pass."
        ),
    )
    bench.configurations["dir"] = {
        "description": "`gitleaks dir` over one file per case, pinned catalogue configuration",
        "findings": findings,
    }
    bench.fidelity = {
        "claim": (
            "on the sample, a per-payload `gitleaks stdin` run names exactly the rules the "
            "directory scan recorded for that case"
        ),
        "sampled": len(sample),
        "agreements": agreements,
    }
    bench.latency_ms = round(statistics.median(latencies), 2) if latencies else None
    return bench


EGRESS_ADAPTERS: dict[str, dict[str, Callable[[Sequence[EgressCase]], EgressBench]]] = {
    "pii": {"presidio": bench_presidio, "mcp-firewall": bench_firewall_pii},
    "secrets": {
        "gitleaks": bench_gitleaks,
        "detect-secrets": bench_detect_secrets,
        "mcp-firewall": bench_firewall_secrets,
    },
}


def write_egress(bench: EgressBench, cases: Sequence[EgressCase], out: Path) -> Path:
    """Write one tool's egress results, refusing anything a reader could not check.

    Args:
        bench: What the run produced.
        cases: The distinct cases it was asked to score.
        out: The directory to write into (``.../comparison/<bench>``).

    Returns:
        The path written.

    Raises:
        SystemExit: Two distinct texts share a key, or a configuration covers
            fewer cases than it was handed.
    """
    keys = {case.key for case in cases}
    if len(keys) != len(cases):
        raise SystemExit("cannot say: two distinct texts share a 16-hex case key.")
    for name, configuration in bench.configurations.items():
        missing = keys - set(configuration["findings"])
        if missing:
            raise SystemExit(
                f"cannot say: configuration {name!r} covers {len(configuration['findings'])} of "
                f"{len(keys)} cases; a partial run must not be written as a whole one."
            )
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{bench.tool}.results.json"
    payload = {
        "bench": bench.bench,
        "tool": bench.tool,
        "label": bench.label,
        "scope": bench.scope,
        "generated_at": date.today().isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "versions": bench.versions,
        "model": bench.model,
        "default": {
            "configuration": bench.default_configuration,
            "threshold": bench.default_threshold,
        },
        "corpus": {
            "source": (
                "eval/corpus/presidio (ADR 0021)"
                if bench.bench == "pii"
                else "eval/corpus/gitleaks (ADR 0021)"
            ),
            "cases": len(cases),
            "key": "first 16 hex characters of sha256(text)",
        },
        "home_ground": bench.home_ground,
        "fidelity": bench.fidelity,
        "latency_ms": bench.latency_ms,
        "notes": bench.notes,
        "configurations": bench.configurations,
    }
    path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write(bench: Bench, cases: Sequence[ComparisonCase], out: Path) -> Path:
    """Write one tool's results, refusing anything a reader could not check.

    Args:
        bench: What the run produced.
        cases: The distinct cases it was asked to score.
        out: The directory to write into.

    Returns:
        The path written.

    Raises:
        SystemExit: Two distinct texts share a truncated key, or a configuration
            covers fewer cases than it was handed. Either would make the matrix a
            statement about a join nobody verified.
    """
    keys = {case.key for case in cases}
    if len(keys) != len(cases):
        raise SystemExit(
            "cannot say: two distinct texts share a 16-hex case key, so the results file "
            "could not be joined to the corpus unambiguously."
        )
    for name, configuration in bench.configurations.items():
        missing = keys - set(configuration["scores"])
        if missing:
            raise SystemExit(
                f"cannot say: configuration {name!r} scored {len(configuration['scores'])} of "
                f"{len(keys)} cases; a partial run must not be written as a whole one."
            )
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{bench.tool}.results.json"
    payload = {
        "tool": bench.tool,
        "label": bench.label,
        "scope": bench.scope,
        "generated_at": date.today().isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "versions": bench.versions,
        "model": bench.model,
        "default": {
            "configuration": bench.default_configuration,
            "threshold": bench.default_threshold,
        },
        "corpus": {
            "source": "eval/corpus/garak (ADR 0017)",
            "cases": len(cases),
            "key": "first 16 hex characters of sha256(text)",
        },
        "fidelity": bench.fidelity,
        "latency_ms": bench.latency_ms,
        "notes": bench.notes,
        "configurations": bench.configurations,
    }
    path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="bench one competitor on the corpus limes is scored on (ADR 0020, ADR 0030)"
    )
    parser.add_argument(
        "--bench",
        choices=("injection", *sorted(EGRESS_ADAPTERS)),
        default="injection",
        help="which table to bench for (default: injection, on garak's corpus)",
    )
    tools = sorted(set(ADAPTERS) | {t for adapters in EGRESS_ADAPTERS.values() for t in adapters})
    parser.add_argument("--tool", required=True, choices=tools, help="which tool to run")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "eval" / "matrices" / "comparison",
        help="directory for the results files (an egress bench writes into a subdirectory)",
    )
    arguments = parser.parse_args()

    started = time.perf_counter()
    if arguments.bench == "injection":
        if arguments.tool not in ADAPTERS:
            parser.error(f"{arguments.tool} has no injection adapter")
        cases = unique_cases(comparison_cases())
        print(f"{arguments.tool}: {len(cases)} distinct cases", file=sys.stderr)
        bench = ADAPTERS[arguments.tool](cases)
        path = write(bench, cases, arguments.out)
        configurations = len(bench.configurations)
    else:
        adapters = EGRESS_ADAPTERS[arguments.bench]
        if arguments.tool not in adapters:
            parser.error(f"{arguments.tool} has no {arguments.bench} adapter")
        egress = unique_egress_cases(egress_cases(arguments.bench))
        print(
            f"{arguments.tool} ({arguments.bench}): {len(egress)} distinct cases", file=sys.stderr
        )
        egress_bench = adapters[arguments.tool](egress)
        path = write_egress(egress_bench, egress, arguments.out / arguments.bench)
        configurations = len(egress_bench.configurations)
    print(
        f"wrote {path} in {time.perf_counter() - started:.0f}s ({configurations} configuration(s))",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
