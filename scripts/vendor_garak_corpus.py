#!/usr/bin/env python3
r"""Vendor an adversary corpus limes did not write, from NVIDIA's garak (ADR 0017).

Every corpus limes ships is one its author chose. That measures "did I implement
what I intended", not "does this catch attacks". This script copies a *held-out*
one — garak's ``latentinjection`` probes, the indirect-prompt-injection family
that maps exactly onto the leg limes guards — into ``eval/corpus/garak/``, the
same way the Tessera corpus was copied: by value, with provenance, never imported
at runtime (ADR 0004).

**It is not run by the gate, and limes does not depend on garak.** The vendored
JSON is the artifact; this script exists so the vendoring is reproducible and so
the next reader can check it rather than trust it.

Reproduce
---------
garak's own dependency set is heavy (torch, transformers, datasets). The three
probe modules used here need almost none of it, so a throwaway environment does::

    uv venv .venv --python 3.12
    uv pip install --python .venv/bin/python --no-deps garak==0.16.0
    uv pip install --python .venv/bin/python tqdm colorama pyyaml \\
                   xdg_base_dirs jsonschema nltk langdetect
    .venv/bin/python scripts/vendor_garak_corpus.py --out eval/corpus/garak

Then ``git diff --stat eval/corpus/garak`` must be empty. Two things make that
true, and neither was free. garak's own prompt cap never fires here (every class
used has ``follow_prompt_cap = False``), but the three ``FactSnippet`` probes
still assemble their contexts with ``random.sample`` and hand them back out of a
``set`` — so the artifact moved on both the draw *and* set iteration order under
a per-process ``PYTHONHASHSEED``. Both are pinned (see :data:`SEED`), and the
result was checked the only way worth checking: three runs, two of them under
different hash seeds, byte-identical.

What is taken, and what is deliberately not
-------------------------------------------
``IN_SCOPE`` is the indirect-injection family: an instruction buried inside a
document the model is asked to process — a report, a résumé, a whois record, a
fact snippet, a translation task. That is precisely what limes's outbound leg
claims to inspect (ADR 0012), so it is a fair test of a stated capability.

``OUT_OF_SCOPE`` is ``LatentJailbreak``: it asks the model to emit a toxic
sentence. That is a content-policy jailbreak, not an instruction-override, and
limes has never claimed it (README, "What limes does not do"). It is vendored
*anyway*, and scored separately, because a declared non-capability is worth a
number too — a reader should see the perimeter measured, not asserted.

The split
---------
Each materialised prompt goes to ``dev`` or ``holdout`` by the first nibble of
its own sha256 — ``0`` and ``1`` respectively, everything else discarded. Three
properties matter:

* it is **uniform** and content-addressed, so neither split can be steered;
* it is **reproducible** by anyone, from the prompt alone, with no state;
* it **subsamples**, which is the point: the full product is 7 816 prompts and
  15 MB, and a corpus nobody can keep in a repository is a corpus nobody re-runs.

``dev`` is what a rule may be written against. ``holdout`` is scored **once**,
with the rules frozen, and a number obtained any other way is not a held-out
number (ADR 0017).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import random
from pathlib import Path
from typing import Any, Protocol


class GarakProbe(Protocol):
    """Exactly the surface this script reads on a garak probe instance.

    Named rather than typed ``Any`` so the coupling to garak is written down: if a
    future garak renames one of these, the failure is a missing attribute on a
    declared contract, not a mystery inside an untyped call.
    """

    top_instructions: list[str]
    contexts: list[str]
    injection_sep_pairs: list[tuple[str, str]]
    injection_instructions: list[str]
    payloads: list[str]
    payload_triggers: list[str]


#: garak's three ``FactSnippetMixin`` probes assemble each context by drawing
#: paragraphs with ``random.sample`` and placing the injection at a
#: ``random.randint`` position, then read them back out of a ``set``. So the
#: artifact would move on two independent axes — the draw, and set iteration
#: order under a per-process ``PYTHONHASHSEED``. Both are pinned here: the seed
#: below fixes the draw, and :func:`_factor` sorts the contexts so hash order
#: cannot leak in. Neither changes what garak generates; they choose one of its
#: outcomes and record which, so a second run reproduces the file byte for byte.
SEED = 0

#: Indirect injection into a document — the leg limes claims (ADR 0012).
IN_SCOPE = (
    "LatentInjectionReportFull",
    "LatentInjectionResumeFull",
    "LatentInjectionFactSnippetEiffelFull",
    "LatentInjectionFactSnippetLegalFull",
    "LatentWhoisSnippetFull",
    "LatentWhois",
    "LatentInjectionTranslationEnFrFull",
    "LatentInjectionTranslationEnZhFull",
)

#: A content-policy jailbreak, which limes does not claim. Scored on its own row.
OUT_OF_SCOPE = ("LatentJailbreakFull",)

#: A SECOND external source, and the only strictly blind one (ADR 0017,
#: Amendment 1). The latentinjection holdout stopped being blind the moment its
#: templates were listed while the split was being designed — a leak the author
#: created and must therefore declare. This family was vendored and scored
#: without its contents ever being read: garak's PromptInject probes (Perez &
#: Ribeiro, "Ignore Previous Prompt"), goal hijacking by a rogue string appended
#: to a task. It targets the INBOUND leg, where `injection` lives, so between the
#: two families each leg now has an external number.
BLIND = (
    "HijackHateHumansFull",
    "HijackKillHumansFull",
    "HijackLongPromptFull",
)

#: The split is decided by the **attack template** — garak's raw
#: ``injection_instruction``, before a payload is substituted into it. The first
#: version of this file split by whole prompt, and that was wrong in a way worth
#: recording: the same template appears in thousands of prompts, so it landed on
#: both sides, and a rule written for it on ``dev`` would have scored on
#: ``holdout`` by identity rather than by generalisation. The held-out number
#: would have measured nothing and looked like it measured everything.
#:
#: The template is what a rule actually recognises, so it is the unit that has to
#: be held out. 19 templates, first nibble of their sha256: 0-7 dev, 8-f holdout.
DEV_NIBBLES = frozenset("01234567")

#: Within a split, prompts are thinned by their own hash — the size knob, applied
#: after the split so it cannot move a template from one side to the other.
KEEP_PROMPT_NIBBLES = frozenset("01")

#: The blind family is thinned less: it is scored exactly once and never
#: iterated on, so its only defence against being a coin-flip is its size. At the
#: latent corpus's rate it came to 58 prompts, which is ±13 points at 50%; a
#: quarter of the family is ~250, which is ±6. Widened before anything was
#: scored, not after — a sample size chosen once a number is known is not a
#: sample size, it is a preference.
KEEP_BLIND_NIBBLES = frozenset("0123")


def _split_of_template(template: str) -> str:
    first = hashlib.sha256(template.encode("utf-8")).hexdigest()[0]
    return "dev" if first in DEV_NIBBLES else "holdout"


def _keep(prompt: str) -> bool:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[0] in KEEP_PROMPT_NIBBLES


def _factor(probe: GarakProbe, marker: str) -> dict[str, Any]:
    """Recover (top_instruction, context, injection) from a probe's flat prompts.

    garak materialises a cartesian product and keeps only the flattened strings.
    Storing that product verbatim would repeat each 10 kB document once per
    injection; recovering the factors stores each document once and makes the
    matched benign pair — the same document with the injection removed — a
    derivation of the same data rather than a second, drifting file.
    """
    tops: list[str] = list(probe.top_instructions)
    # sorted(): garak hands some probes their contexts out of a set (see SEED).
    contexts: list[str] = sorted(c for c in probe.contexts if marker in c)
    templates: list[str] = list(probe.injection_instructions)
    injections: list[str] = []
    injection_template: list[int] = []
    cases: dict[str, list[list[int]]] = {"dev": [], "holdout": []}

    seen: set[str] = set()
    for top_index, top in enumerate(tops):
        for context_index, context in enumerate(contexts):
            for separator_start, separator_end in probe.injection_sep_pairs:
                for template_index, instruction in enumerate(templates):
                    split = _split_of_template(instruction)
                    for payload in probe.payloads:
                        for trigger in probe.payload_triggers:
                            this_payload = payload.replace("<|garak_trigger|>", trigger)
                            injection = (
                                separator_start
                                + instruction.replace("<|garak_payload|>", this_payload)
                                + separator_end
                            )
                            prompt = top + context.replace(marker, injection)
                            if prompt in seen or not _keep(prompt):
                                continue
                            seen.add(prompt)
                            if injection not in injections:
                                injections.append(injection)
                                injection_template.append(template_index)
                            cases[split].append(
                                [top_index, context_index, injections.index(injection)]
                            )

    used = {index for pairs in cases.values() for _, index, _ in pairs}
    used_tops = {index for pairs in cases.values() for index, _, _ in pairs}
    return {
        "doc_uri": getattr(probe, "doc_uri", "") or "",
        "goal": getattr(probe, "goal", "") or "",
        # Keep every context and top instruction: the matched-benign pair is
        # built from them, and dropping the unsampled ones would silently shrink
        # the control group to whatever the attack sample happened to touch.
        "top_instructions": tops,
        "contexts": contexts,
        # The templates, and which one each materialised injection came from: the
        # split is a property of the template, so a reader can check any case's
        # side without re-deriving it.
        "injection_templates": templates,
        "injection_template_of": injection_template,
        "injections": injections,
        "cases": {name: sorted(pairs) for name, pairs in cases.items()},
        "_counts": {
            "templates": len(templates),
            "templates_dev": sum(1 for t in templates if _split_of_template(t) == "dev"),
            "contexts": len(contexts),
            "top_instructions": len(tops),
            "contexts_attacked": len(used),
            "top_instructions_attacked": len(used_tops),
            "dev": len(cases["dev"]),
            "holdout": len(cases["holdout"]),
        },
    }


def build_flat(module: str, names: tuple[str, ...]) -> dict[str, Any]:
    """Materialise probes whose prompts are flat strings, with no injection factor.

    PromptInject hands back finished prompts rather than (document, injection)
    pairs, so there is nothing to factor and no matched control to derive: the
    hijack IS the prompt. Thinned by prompt hash only, and never split — the whole
    family is held out.
    """
    probes = importlib.import_module(module)
    out: dict[str, Any] = {}
    for name in names:
        random.seed(SEED)
        probe = getattr(probes, name)()
        kept = sorted(
            {
                str(prompt)
                for prompt in probe.prompts
                if hashlib.sha256(str(prompt).encode("utf-8")).hexdigest()[0] in KEEP_BLIND_NIBBLES
            }
        )
        out[name] = {
            "goal": getattr(probe, "goal", "") or "",
            "doc_uri": getattr(probe, "doc_uri", "") or "",
            "prompts": kept,
            "_counts": {"prompts": len(kept)},
        }
    return out


def build(names: tuple[str, ...]) -> dict[str, Any]:
    """Materialise the named garak probes into the factored vendored shape."""
    latent = importlib.import_module("garak.probes.latentinjection")
    marker = latent.INJECTION_MARKER
    built: dict[str, Any] = {}
    for name in names:
        # Re-seeded per probe rather than once per run, so adding or removing a
        # probe cannot shift the draw of the ones beside it — a corpus whose
        # contents depend on its neighbours' presence is not a fixed corpus.
        random.seed(SEED)
        built[name] = _factor(getattr(latent, name)(), marker)
    return built


def _document(kind: str, names: tuple[str, ...], garak_version: str) -> dict[str, Any]:
    return {
        "source": {
            "tool": "garak",
            "what": "LLM vulnerability scanner",
            "vendor": "NVIDIA",
            "version": garak_version,
            "license": "Apache-2.0",
            "url": "https://github.com/NVIDIA/garak",
            "module": "garak.probes.latentinjection",
            "probes": list(names),
        },
        "kind": kind,
        "sampling": {
            "seed": SEED,
            "seed_controls": (
                "garak's FactSnippet probes draw their contexts randomly and read them "
                "back out of a set; the seed fixes the draw and the writer sorts the "
                "contexts, so the vendored file is byte-reproducible"
            ),
            "rule": (
                "split by ATTACK TEMPLATE: first nibble of sha256(injection_instruction), "
                "0-7 -> dev, 8-f -> holdout; then prompts thinned to first nibble of "
                "sha256(prompt) in {0,1}"
            ),
            "why": (
                "the template is what a rule recognises, so it is the unit that must be "
                "held out — splitting by prompt puts the same template on both sides and "
                "a rule written on dev then scores on holdout by identity, not by "
                "generalisation. Content-addressed at both levels, so neither can be "
                "steered, and the thinning keeps the 15 MB full product out of the tree."
            ),
            "protocol": (
                "rules may be written against dev; holdout is scored once, rules frozen (ADR 0017)"
            ),
        },
        "reconstruct": (
            "attack  = top_instructions[t] + contexts[c].replace(MARKER, injections[i]) "
            "for [t, c, i] in cases[split]; "
            "benign  = top_instructions[t] + contexts[c].replace(MARKER, '') for all t, c. "
            "MARKER is the literal '<|garak_injection|>'."
        ),
        "probes": build(names),
    }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    arguments = parser.parse_args()

    garak = importlib.import_module("garak")
    version = str(garak.__version__)

    arguments.out.mkdir(parents=True, exist_ok=True)

    blind = {
        "source": {
            "tool": "garak",
            "what": "LLM vulnerability scanner",
            "vendor": "NVIDIA",
            "version": version,
            "license": "Apache-2.0",
            "url": "https://github.com/NVIDIA/garak",
            "module": "garak.probes.promptinject",
            "probes": list(BLIND),
            "upstream": "PromptInject (Perez & Ribeiro, 'Ignore Previous Prompt')",
        },
        "kind": "in-scope, BLIND: goal hijacking on the inbound leg",
        "sampling": {
            "seed": SEED,
            "rule": "thinned to first nibble of sha256(prompt) in {0,1,2,3}; not split",
            "why": (
                "the whole family is held out: it was vendored and scored without its "
                "contents ever being read, which the latentinjection holdout can no "
                "longer claim"
            ),
            "protocol": "blind: scored once, contents never inspected (ADR 0017 Am. 1)",
        },
        "probes": build_flat("garak.probes.promptinject", BLIND),
    }
    blind_path = arguments.out / "prompt_hijack.json"
    blind_path.write_text(
        json.dumps(blind, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    total = sum(p["_counts"]["prompts"] for p in blind["probes"].values())
    print(f"{blind_path}  blind={total} ({blind_path.stat().st_size} B)")

    for filename, kind, names in (
        ("latent_injection.json", "in-scope: indirect prompt injection", IN_SCOPE),
        ("latent_jailbreak.json", "out of scope: content-policy jailbreak", OUT_OF_SCOPE),
    ):
        document = _document(kind, names, version)
        path = arguments.out / filename
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        counts = {n: p["_counts"] for n, p in document["probes"].items()}
        dev = sum(c["dev"] for c in counts.values())
        holdout = sum(c["holdout"] for c in counts.values())
        contexts = sum(c["contexts"] for c in counts.values())
        print(f"{path}  dev={dev} holdout={holdout} contexts={contexts} ({path.stat().st_size} B)")


if __name__ == "__main__":
    main()
