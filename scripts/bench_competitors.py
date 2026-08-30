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
import json
import platform
import random
import statistics
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

from limes.eval.comparison_harness import ComparisonCase, comparison_cases, unique_cases

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


ADAPTERS: dict[str, Callable[[Sequence[ComparisonCase]], Bench]] = {
    "llm-guard": bench_llm_guard,
    "rebuff": bench_rebuff,
    "deberta-injection-v2": bench_deberta_injection_v2,
    "deepset-injection": bench_deepset_injection,
}


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
        description="bench one competitor on garak's corpus (ADR 0020)"
    )
    parser.add_argument("--tool", required=True, choices=sorted(ADAPTERS), help="which tool to run")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "eval" / "matrices" / "comparison",
        help="directory for the results file",
    )
    arguments = parser.parse_args()

    cases = unique_cases(comparison_cases())
    print(f"{arguments.tool}: {len(cases)} distinct cases", file=sys.stderr)
    started = time.perf_counter()
    bench = ADAPTERS[arguments.tool](cases)
    path = write(bench, cases, arguments.out)
    print(
        f"wrote {path} in {time.perf_counter() - started:.0f}s "
        f"({len(bench.configurations)} configuration(s))",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
