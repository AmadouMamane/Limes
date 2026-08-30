# Corpus provenance — an adversary limes did not write

Every other corpus in this repository was written by limes's author. That is
enough to measure *"does the detector do what I meant it to do"* and it is not
enough to measure *"does it catch attacks"* — the two questions have different
answers, and only the second one is a security claim (ADR 0017).

These files are **copied**, by value, from a corpus somebody else wrote and
maintains adversarially.

## Source

| | |
|---|---|
| tool | **garak** — LLM vulnerability scanner |
| vendor | NVIDIA |
| version | **0.16.0** (published 2026-08-04) |
| licence | **Apache-2.0** (`License-Expression` in garak's own distribution metadata) |
| repository | <https://github.com/NVIDIA/garak> |
| module | `garak.probes.latentinjection` |
| artifact | `garak-0.16.0-py3-none-any.whl` |
| sha256 | `871100d78e2bc5a7ee6de58ff8301bdd3de3a41236032690d1a6da21a05e9f06` |
| copied | 2026-08-30 |

**limes does not depend on garak** — not at runtime, not in the gate, not in any
extra. The dependency runs one way and only at vendoring time, exactly as it does
for the Tessera injection corpus (ADR 0004). Regenerate with
`scripts/vendor_garak_corpus.py`, which documents the minimal environment.

Apache-2.0 permits this copy; the attribution above is the condition, and garak's
own licence text travels with its distribution rather than being restated here.

## What was taken

`latent_injection.json` — the **in-scope** family: an instruction buried inside a
document the model is asked to process. A report to summarise, a résumé to
screen, a whois record to assess, a fact snippet, a translation task. This is
precisely what limes's outbound leg claims to inspect (ADR 0012), so it is a fair
test of a stated capability.

| garak probe | the document it hides in |
|---|---|
| `LatentInjectionReportFull` | a news/report article to summarise |
| `LatentInjectionResumeFull` | a résumé under automated screening |
| `LatentInjectionFactSnippetEiffelFull` | encyclopaedic fact snippets |
| `LatentInjectionFactSnippetLegalFull` | legal fact snippets |
| `LatentWhois`, `LatentWhoisSnippetFull` | whois records under malice assessment |
| `LatentInjectionTranslationEnFrFull`, `…EnZhFull` | text handed over for translation |

`latent_jailbreak.json` — the **out-of-scope** one, `LatentJailbreak`, which asks
the model for a toxic sentence. That is a content-policy jailbreak, not an
instruction override, and limes has never claimed it (README, *What limes does
not do*). It is vendored anyway and scored on its own row: a declared
non-capability deserves a number too, or the perimeter is only a sentence.

## The sampling rule, and why there is one

garak's full product over these probes is **7 816 prompts and ~15 MB**. A corpus
nobody can keep in a repository is a corpus nobody re-runs, so this vendoring
keeps a fraction — chosen by the first nibble of each prompt's own **sha256**:

```
'0' -> dev      '1' -> holdout      anything else -> not vendored
```

Three properties, each load-bearing:

- **uniform** — a hash prefix is as good as a coin, over the prompt's own bytes;
- **unsteerable** — the author cannot choose which prompts land in which split
  without changing the prompts, which would change the corpus;
- **reproducible** — anybody can recompute the split from the prompt alone, with
  no seed, no state and no ordering.

## The protocol — read this before writing a rule

**`dev` is what a rule may be written against. `holdout` is scored once, with the
rules frozen.**

The moment a rule is written while looking at `holdout`, `holdout` becomes a
second `dev`, and the published number stops meaning what the matrix says it
means. Nothing enforces this but the person doing it, so the harness helps:
`python -m limes.eval.external_harness` shows **dev only** by default, and the
holdout number exists only when somebody deliberately passes `--split all`.

## The matched control — the benign set nobody wrote either

There is no separate benign file, on purpose. For every attack
`top_instruction + document(injection)`, the control is *the same*
`top_instruction + document` with the injection removed. The two differ by
exactly the attack, so:

- a detector that fires on **both** has learnt the document, not the injection;
- the control cannot drift out of step with the attacks, because it is derived
  from their own data rather than maintained beside them.

74 documents and 192 (instruction × document) controls come out of it — against
the 8 general benign inputs limes had before, which could not power a
false-positive claim below "5 of 8 flipped".

## One thing the copy had to pin

garak's three `FactSnippet` probes assemble each context by drawing paragraphs
with `random.sample`, placing the injection at a `random.randint` position, and
reading the results back out of a `set`. So a naive copy moved on two independent
axes: the draw, and set iteration order under a per-process `PYTHONHASHSEED`.
Both are pinned in the vendoring script (`SEED = 0`, and the writer sorts the
contexts), and the result was checked the only way worth checking — **three runs,
two of them under different hash seeds, byte-identical**. Neither pin changes
what garak generates; they choose one of its outcomes and record which.

## What this corpus is not

It is **not** a benchmark limes may tune against, and it is not a claim that
garak's probes are the whole of indirect injection. It is one adversary, from one
tool, at one version, on one family of attacks. What it buys is the only thing an
author cannot buy from their own corpus: a number they did not choose.
