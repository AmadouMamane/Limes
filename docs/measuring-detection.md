# Measuring detection — how to trust the numbers

Every detector limes ships is admitted by measurement, not by assertion (ADR
0003). The README shows the *results* — the two-number tables. This page explains
the *method* behind them: what the numbers mean, why there are always two, how
the grader avoids fooling itself, and how you reproduce and read a matrix.

The point of all of it: a guard you cannot measure against *doing nothing* is a
decoration. limes refuses to make a claim it has not measured.

---

## 1. Two numbers, never one

A single number is always gameable:

- Report only **attacks blocked**, and a guard that blocks *everything* scores a
  perfect 33/33 — while destroying every legitimate request.
- Report only **legitimate traffic preserved**, and a guard that is *unplugged*
  scores a perfect 8/8 — while blocking zero attacks.

Neither is a guard. Only the **pair** is a measurement:

> how many attacks blocked **and** how much legitimate traffic killed.

Every table in the README carries both, plus the two degenerate baselines
(`unplugged`, `block-everything`) so you can see that the detector beats *both*.

---

## 2. The null control — the row that makes the rest meaningful

`unplugged (null control)` is the same harness run with the detector removed. It
is the answer to "what would these numbers be if the detector did nothing?" A
detector is admitted only when it **measurably beats** its null control:

```
limes pii-egress locates 32/32   against the null control's 0/32
```

The admission enforcer (`tests/unit/test_admission_rule.py`) checks this for
**every** member of `ADMITTED`: a positive corpus, a benign corpus, a beaten null
control, and a published matrix. A detector added to the code without its corpus
does not produce a green suite with a missing case — it turns that test **red**,
naming the detector. The measurement is enforced, not promised.

---

## 3. `located`, not `flagged` — the grader that cannot fool itself

For the egress detectors, a positive case declares the **exact substring** that
must be found. A finding counts only when its `[start, end)` reproduces that
substring at that offset. Two columns come out of this:

| column | means |
|---|---|
| `flagged` | the detector fired *somewhere* on the message |
| `located` | it fired on **exactly** the value the case declared |

This distinction is the whole grader. `block-everything` is `flagged` on every
case and `located` on **none** — it fires on the entire message, which is not the
card number. So nothing a case handed the detector can be mistaken for evidence
that the detector *found* something. **Read the `located` column.**

(Why it matters beyond scoring: the transport masks by those offsets. A detector
that reported a span it did not actually validate would hand the masker the wrong
bytes *and* score a true positive for it.)

---

## 4. The corpus is synthetic — by construction, not by promise

Every value in an egress corpus is synthetic (ADR 0009): a published test card
(Stripe's `4242…`), a documentation IBAN, an `example.com` address, a
revoked-format key. This keeps a *real* secret out of the repository. It is
enforced by the **loader**, not by a test that restates the rule: `load_positive`
refuses any file whose `provenance` is not `synthetic`.

One category needs more care. A `secrets-egress` positive is, by construction, a
string shaped exactly like a real credential — which a host secret scanner (and
GitHub push protection) cannot tell from a real one. So vendor-key vectors are
stored **assembled** (ADR 0010): the file holds `content_template` + `token_parts`
joined at load time, never the contiguous literal. The loader reconstructs the
real format, the detector stays measured, and no credential-shaped literal sits in
the repo.

---

## 5. A null result carries its power

"No false positives" over a corpus too small to detect any is a fact about the
experiment, not the world. So when the benign corpus is small, the report does not
claim a clean sheet silently — it states the **minimum detectable effect**:

```
n=8 benign inputs, alpha=0.05 → a one-sided exact sign test can only detect a
regression of ≥5 of 8. A smaller one is invisible here.
```

The honest verdict in that case is `NoEffect` **carrying that power**, not a bare
"no regression". Growing the benign corpus tightens it. This is the same
discipline applied to the injection detector's "no regression over the baseline".

---

## 6. Reproduce and read a matrix

Every matrix is generated, dated, and committed under `eval/matrices/`. Regenerate
them all:

```sh
make eval          # runs each admitted detector's harness, writes the dated matrix
```

A matrix has the configuration table (null control, block-everything, any ported
baseline, and limes), the per-category breakdown, the two numbers stated in prose,
the null-control statement with its power, the baseline verdict (or an explicit
"no baseline — the null control is the baseline"), and — crucially — **the false
positives, each with its cause, never rounded away** (ADR 0003). When a lookalike
is killed, the matrix says which one and why, regenerated from the detector rather
than quoted, so it stays true when the rules change.

---

## 7. What a "baseline" is here

Where a comparable shipping guard exists, limes ports it **verbatim** and runs it
over the same corpus with the same grader — for example Tessera's output guard for
`pii-egress` (`src/limes/baselines/`). The gap is then a measured fact, not a
claim. Where nothing comparable ships (e.g. `secrets-egress`), the report says so
outright — **the null control is the baseline** — rather than inventing a
comparison to win against. A test asserts that exactly the detectors that *should*
have a ported baseline do, so neither an invented comparison nor a silently
dropped one passes.

---

## See also

- [`docs/decisions/0003-no-detector-without-eval-and-null-control.md`](decisions/0003-no-detector-without-eval-and-null-control.md)
- [`docs/decisions/0009-egress-corpus-synthetic-only.md`](decisions/0009-egress-corpus-synthetic-only.md)
- [`docs/decisions/0010-vendor-key-vectors-are-stored-assembled.md`](decisions/0010-vendor-key-vectors-are-stored-assembled.md)
- [Writing a detector](writing-a-detector.md) — the admission bar you must clear.
