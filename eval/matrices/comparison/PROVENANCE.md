# Comparison provenance — what was run, and what it was

`eval/matrices/comparison.md` states that limes catches more or less than other
tools. That is a claim about software this repository does not ship, so it is
worth exactly what a reader can re-derive. This file is the re-derivation
(ADR 0020).

**Nothing here is a number a vendor published about itself.** Every figure was
produced by running the tool, here, on the corpus in `eval/corpus/garak/` —
ground no contestant wrote, limes least of all (ADR 0017).

## The recipe

One environment per tool, none of them the repository's. limes stays at one
runtime dependency; torch never enters this project, and the frontier ratchet
(`tests/unit/test_frontier.py`) still asserts it.

```bash
# llm-guard and the two bare classifiers share torch + transformers
uv venv mlenv --python 3.12
uv pip install --python mlenv/bin/python llm-guard==0.3.16 sentencepiece protobuf
uv pip install --python mlenv/bin/python --no-deps -e .
mlenv/bin/python scripts/bench_competitors.py --tool llm-guard
mlenv/bin/python scripts/bench_competitors.py --tool deberta-injection-v2
mlenv/bin/python scripts/bench_competitors.py --tool deepset-injection

# rebuff, whose product is its own
uv venv rebuffenv --python 3.12
uv pip install --python rebuffenv/bin/python rebuff==0.1.1
uv pip install --python rebuffenv/bin/python --no-deps -e .
rebuffenv/bin/python scripts/bench_competitors.py --tool rebuff
```

`--no-deps -e .` installs limes for exactly one reason: the case enumeration
(`limes.eval.comparison_harness.comparison_cases`) has to be *the same function*
on both sides. Otherwise the two files describe different texts and the join
between them is a coincidence rather than a fact. The join itself is
content-addressed — each case is keyed by the first 16 hex characters of its own
sha256 — and the bench script refuses to write a file in which two distinct texts
share a key, or one that covers fewer cases than it was handed.

## The contestants

| tool | version | licence | what ran |
|---|---|---|---|
| **limes** | this checkout, computed live | Apache-2.0 | `injection` (inbound) and `injection-egress` (outbound), a catch on either |
| **llm-guard** (Protect AI) | 0.3.16 | MIT | `PromptInjection` input scanner, in all four of its match types |
| **rebuff** (Protect AI) | 0.1.1 | Apache-2.0 | `detect_prompt_injection_using_heuristic_on_input` — **one of its four layers** |
| **DeBERTa injection v2** (bare) | — | Apache-2.0 | llm-guard's own checkpoint, no product around it |
| **deepset injection** (bare) | — | MIT | a second classifier, trained by somebody else |

### Models, pinned by name *and* revision

An unpinned model is an unpinned policy (ADR 0013's rule, applied here).

| model | revision | used by |
|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | `89b085cd330414d3e7d9dd787870f315957e1e9f` | llm-guard, and the bare row |
| `deepset/deberta-v3-base-injection` | `80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1` | the second bare row |

The first revision is the one **llm-guard itself pins**, not the model's current
`main` — so the bare row and the llm-guard row differ by the wrapper and by
nothing else.

### Runtime

| | |
|---|---|
| Python | 3.12.4 |
| torch | 2.13.0 |
| transformers | 4.51.3 |
| device | `mps` (Apple Silicon) |
| dates | in each `*.results.json` under `generated_at` |

## What each results file holds

A *score* per case rather than a verdict, so the harness can apply a threshold
without anybody re-running a model, and so a reader can check the threshold
choice instead of taking it. Plus, in the header: every version, the model
identity, the vendor's own shipped configuration and threshold, the measured
median latency, the fidelity check, and the notes the matrix reprints.

## The two adapters that are not simply "call the tool"

Both exist because the obvious call was impossible or infeasible, and both are
**measured against the tool's own function** rather than argued for. The
agreement counts live in each results file under `fidelity`, and a test refuses
any file whose check did not fully agree.

**llm-guard — the score behind the verdict.** `PromptInjection.scan()` returns a
*risk* score that rounds to one decimal and clamps to ±1, so the underlying
injection score cannot be recovered from it. The adapter therefore takes the
maximum injection score over the inputs the scanner's own `MatchType` produced.
`scan()` refuses a prompt exactly when that maximum exceeds the threshold, so the
two are equivalent by construction — and the run samples 60 cases, calls the
public `scan()` on each, and records that the derived verdict agreed every time.

**rebuff — the same float, without the 37 hours.** rebuff's heuristic scores
8 800 generated keyword phrases against every same-length word window of the
input, calling `difflib.SequenceMatcher` on each pair: about three million
similarity computations for a 2 kB document, and **91 seconds** measured on a
1.6 kB one. Scoring 1 486 documents that way is roughly 37 hours. Two candidates
are skipped, and neither can change the answer:

- `matched_words_count == 0` gives `base = 0`, hence `adjusted = -similarity/10 ≤ 0`,
  which can never exceed a maximum that starts at 0;
- `base ≤ highest` gives `adjusted = base - similarity/10 ≤ highest`.

The maximum is therefore identical, and the run checks it: 60 sampled cases,
scored by both implementations, compared as **exact floats**. A separate probe
during development compared ten cases from 169 to 12 430 characters — every one
bit-identical, at 30× to 166× the speed.

The **latency** reported for rebuff is its own unmodified function, never the
pruned one.

## What this cannot control for, and does not pretend to

**The classifiers may have been trained on these attacks.** garak's probes derive
from public prompt-injection research; `protectai/…-prompt-injection-v2` and
`deepset/…-injection` were trained on public prompt-injection datasets. There is
no way to un-mix that from the outside, and no attempt is made. Read their
numbers as *generalisation in a real deployment, with training data that may
overlap this corpus*. limes's rules have no such exposure. The asymmetry favours
the classifiers, and stating it is the only honest handling available.

**limes's `dev` column is in-sample for limes**, because `dev` is the split rules
may be written against (ADR 0017). **`hijack (blind)` is not blind for limes**
either: ADR 0019 ported an override family to the inbound leg after that family
reported 0/131. And **no split of the matched benign controls is fully
out-of-sample for limes**, because they are derived from the same documents as
the `dev` attacks. The held-out attack column is the one to read.

**rebuff is under-represented on purpose.** Its deployed detector is heuristics
plus an LLM judge plus a vector store of past attacks plus canary tokens. Three
of those need an OpenAI key and a Pinecone index and do not run offline. Its row
is a *floor for rebuff*, never a measurement of rebuff, and nothing in this
repository may quote it as one.

**mcp-scan / Snyk Agent Scan is absent for shape, not for effort.** It analyses
MCP server configurations and tool descriptions rather than classifying a text.
Bending it into a text → boolean grader would have meant inventing an adapter
that scores something it does not claim to score, and that number would be worse
than no number.

## The fidelity checks, as they came out

Each adapter's claim was checked against the tool's own code path on 60 sampled
cases, and every one agreed on all 60:

| tool | what was checked | result |
|---|---|---|
| llm-guard | the public `scan()` verdict equals *recorded maximum > threshold* | 60/60 |
| DeBERTa v2 bare | the score equals `transformers`' own pipeline, to 1e-4 | 60/60 |
| deepset bare | the score equals `transformers`' own pipeline, to 1e-4 | 60/60 |
| rebuff | the pruned scorer returns the **identical float** to rebuff's function | 60/60 |

A test in `tests/unit/comparison/` refuses any committed results file whose check
sampled nothing, carries no claim, or did not fully agree.

## The latencies, measured the way a deployment would meet them

| tool | median per case | how |
|---|---|---|
| limes | **0.6 ms** | both legs, detectors built once, over garak's ~1.4 kB documents |
| llm-guard | 58.0 ms | its own `scan()`, its own default match type, on `mps` |
| DeBERTa v2 bare | 59.9 ms | single-chunk scoring, on `mps` |
| deepset bare | 58.2 ms | single-chunk scoring, on `mps` |
| rebuff | **5 127 ms** | its own unmodified function, on texts of ≤ 400 characters |

limes's figure is the one number here that had to be fixed before it could be
published. The first measurement said 5.3 ms — nine times too high — because the
harness constructed a fresh detector per case and was timing policy loading. A
latency column that measures the harness is a number about the harness, and it is
the column a reader is most likely to quote.

## What would change these numbers

A new version of any tool; a different model revision; a different device
(`mps` versus `cpu` can move a float in the last places, though not a verdict at
these margins); a different threshold rule; a wider corpus. All of which is why
each is written down here rather than summarised.
