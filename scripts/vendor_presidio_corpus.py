#!/usr/bin/env python3
r"""Vendor third-party PII document contexts, from presidio-research (ADR 0021).

``pii-egress`` was admitted on 32 cases its author wrote, and scores 32/32 on
them. That measures "does the detector do what I meant it to do" over sentences
chosen by the person who wrote the rules. It cannot measure "does it find PII in
documents somebody else wrote", and only the second is a claim about the world —
the same gap ADR 0017 opened for ``injection``, where the author's corpus said
76% and an outside adversary said 24%.

This script copies **209 sentence templates** from presidio-research's data
generator: customer-support and banking prose, with ``{{credit_card_number}}``,
``{{iban}}``, ``{{email}}``, ``{{phone_number}}`` placeholders where a value goes.
The prose is the part limes's author did not write, and it is the part under test.

**The values stay limes's own, and that is not a shortcut.** ADR 0009 forbids a
real PII value in this repository, and a *generated* one would add a second
moving part to the experiment. So the vectors substituted into these templates are
exactly the ones already cleared in ``src/limes/corpus/egress/pii_positive.json``
— the same strings, in prose nobody here chose. The variable under test is
therefore the **document**, alone. That makes the number weaker than garak's (where
the attack itself is foreign) and it is labelled so wherever it is published:
*external contexts, author-cleared synthetic values*.

**limes does not depend on presidio-research.** The dependency runs one way and
only at vendoring time (ADR 0004), like garak and like the Tessera corpus. The
artifact is the JSON; this script exists so the copy is reproducible and can be
checked rather than trusted — it pins the upstream commit and refuses to write
anything if the file's sha256 has moved.

Reproduce
---------
::

    python scripts/vendor_presidio_corpus.py --out eval/corpus/presidio

Then ``git diff --stat eval/corpus/presidio`` must be empty. The only network
call is a fetch of one file at a pinned commit; there is no presidio import and
no environment to build.

The split
---------
By **TEMPLATE**, never by materialised case. A template appears in as many cases
as there are vectors for its category, so splitting the cases would put the same
template on both sides — and a rule written on ``dev`` would then score on
``holdout`` by identity rather than by generalisation. That is not a hypothetical:
it is what happened to the hijack family (ADR 0021 §The repair), where thinning by
prompt hash let every template survive into every bucket and "held out" meant
nothing. A test asserts no template appears on both sides.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

#: presidio-research, pinned. The repository moved from ``microsoft/`` to
#: ``data-privacy-stack/`` after the templates were written; both names are
#: recorded because provenance that silently follows a rename is provenance a
#: reader cannot check.
UPSTREAM = {
    "tool": "presidio-research",
    "what": "PII detection evaluation and data-generation toolkit",
    "vendor": "data-privacy-stack (formerly Microsoft)",
    "license": "MIT",
    "url": "https://github.com/data-privacy-stack/presidio-research",
    "former_url": "https://github.com/microsoft/presidio-research",
    "path": "presidio_evaluator/data_generator/raw_data/templates.txt",
    "commit": "70ff860bed296cc1ce9383d76ec9dcbd44a3e9c6",
    "sha256": "f8b04ff8c5c24d17fcac2e666767f6ba80841b69ee2ea3c1cfe089a676a766ef",
    "copied": "2026-08-31",
}

RAW = "https://raw.githubusercontent.com/data-privacy-stack/presidio-research/{commit}/{path}"

#: presidio placeholder -> the limes category it feeds. Only these four are
#: claimed by ``pii-egress`` and present in the upstream templates. ``nir`` is
#: claimed and has no placeholder here: a declared blind spot, reported as one.
CLAIMED: dict[str, str] = {
    "credit_card_number": "pan",
    "iban": "iban",
    "email": "email",
    "phone_number": "phone",
}

#: Placeholders limes explicitly does NOT claim (README, "what limes does not
#: do"). Vendored and scored on their own row, so the perimeter is a number
#: rather than a sentence — the treatment ADR 0017 gave LatentJailbreak.
OUT_OF_SCOPE: dict[str, str] = {
    "ssn": "us_ssn",
    "us_driver_license": "us_driver_license",
    "ip_address": "ip_address",
}

#: Every other placeholder gets a fixed, non-PII filler so the sentence reads as
#: prose and carries exactly ONE detectable value: the one under test. A filler
#: that itself tripped a rule would put a second variable in a matched pair.
FILLERS: dict[str, str] = {
    "person": "Alex Martin",
    "name": "Alex Martin",
    "name_female": "Claire Martin",
    "name_male": "Alex Martin",
    "first_name": "Alex",
    "first_name_female": "Claire",
    "first_name_male": "Alex",
    "first_name_nonbinary": "Robin",
    "last_name": "Martin",
    "last_name_female": "Martin",
    "last_name_male": "Martin",
    "prefix": "Dr",
    "prefix_female": "Ms",
    "prefix_male": "Mr",
    "organization": "Northwind Trading",
    "job": "operations analyst",
    "address": "the registered address on file",
    "secondary_address": "Suite C",
    "street_name": "Maple Street",
    "building_number": "Twelve",
    "city": "Springfield",
    "country": "Freedonia",
    "nationality": "Freedonian",
    "nation_woman": "Freedonian",
    "nation_plural": "Freedonians",
    "state_abbr": "CA",
    "postcode": "AB1 2CD",
    "zipcode": "AB1 2CD",
    "age": "thirty-seven",
    "year": "two thousand nineteen",
    "day_of_week": "Tuesday",
    "date_time": "Tuesday morning",
    "date_of_birth": "the date of birth on file",
    "url": "https://example.com/help",
}

PLACEHOLDER = re.compile(r"\{\{([a-zA-Z_]+)\}\}")


def _fetch(commit: str, path: str) -> str:
    url = RAW.format(commit=commit, path=path)
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def split_of_template(template: str) -> str:
    """``dev`` or ``holdout``, from the template's own sha256. Unsteerable."""
    return (
        "dev"
        if hashlib.sha256(template.encode("utf-8")).hexdigest()[0] in "01234567"
        else "holdout"
    )


def build(text: str) -> dict[str, Any]:
    """Factor the upstream file into templates, their slots, and their split."""
    templates: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    for line in text.splitlines():
        # Upstream stores every template on ONE physical line and writes its
        # internal line breaks as the two characters `\` and `n` (89 of them).
        # Copying those verbatim would put a literal backslash-n where a newline
        # belongs, and that is not a cosmetic difference: it glues a stray `n`
        # onto the front of the next token, so an e-mail rule spans one character
        # too many and a telephone rule's `(?<![A-Za-z0-9+])` lookbehind never
        # fires at all. The first run of this bench scored 89.8% and every one of
        # its 17 misses was this, not the detector — a corpus that copies an
        # escape sequence verbatim measures its own encoding (ADR 0026).
        template = line.strip().replace("\\n", "\n")
        if not template:
            continue
        slots = PLACEHOLDER.findall(template)
        claimed = sorted({s for s in slots if s in CLAIMED})
        out_of_scope = sorted({s for s in slots if s in OUT_OF_SCOPE})
        if not claimed and not out_of_scope:
            skipped["no claimed or declared slot"] = (
                skipped.get("no claimed or declared slot", 0) + 1
            )
            continue
        unknown = sorted(
            {s for s in slots if s not in CLAIMED and s not in OUT_OF_SCOPE and s not in FILLERS}
        )
        if unknown:
            # Never silently drop: a template this script cannot materialise is
            # counted and named, so the corpus size is auditable (ADR 0015).
            for name in unknown:
                skipped[f"no filler for {{{{{name}}}}}"] = (
                    skipped.get(f"no filler for {{{{{name}}}}}", 0) + 1
                )
            continue
        templates.append(
            {
                "text": template,
                "claimed_slots": claimed,
                "out_of_scope_slots": out_of_scope,
                "split": split_of_template(template),
            }
        )
    templates.sort(key=lambda t: hashlib.sha256(t["text"].encode("utf-8")).hexdigest())
    return {"templates": templates, "skipped": dict(sorted(skipped.items()))}


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    arguments = parser.parse_args()

    raw = _fetch(UPSTREAM["commit"], UPSTREAM["path"])
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if digest != UPSTREAM["sha256"]:
        # A moved upstream is a blind spot, never a silent re-vendor (ADR 0015).
        raise SystemExit(
            f"cannot say: {UPSTREAM['path']} at {UPSTREAM['commit'][:12]} hashes {digest}, "
            f"pinned {UPSTREAM['sha256']}. Verify the source before re-pinning."
        )

    built = build(raw)
    document = {
        "source": UPSTREAM,
        "kind": "in-scope: PII inside third-party document contexts",
        "strength": (
            "external contexts, author-cleared synthetic values — the DOCUMENTS are "
            "third-party, the VALUES are limes's own already-admitted vectors "
            "(ADR 0009 forbids any other kind). Strictly weaker than garak, where "
            "the attack itself is foreign. Labelled wherever published."
        ),
        "sampling": {
            "rule": (
                "every upstream template carrying a claimed or declared-out-of-scope "
                "placeholder is kept; split by TEMPLATE: first nibble of "
                "sha256(template), 0-7 -> dev, 8-f -> holdout"
            ),
            "why": (
                "the template is what a rule meets, and one template materialises into "
                "as many cases as its category has vectors — so splitting the CASES "
                "would put the same template on both sides and a rule written on dev "
                "would score on holdout by identity, not by generalisation"
            ),
            "protocol": "rules may be written against dev; holdout is scored once, rules frozen",
        },
        "claimed_slots": CLAIMED,
        "out_of_scope_slots": OUT_OF_SCOPE,
        "fillers": FILLERS,
        "reconstruct": (
            "attack  = template with the target slot replaced by a cleared synthetic "
            "vector and every other slot by its filler; "
            "control_decoy = the SAME sentence with that vector replaced by a "
            "same-shape checksum-INVALID decoy; "
            "control_removed = the SAME sentence with that vector replaced by a "
            "neutral phrase. Attack and control differ by exactly the token."
        ),
        "templates": built["templates"],
        "_counts": {
            "templates": len(built["templates"]),
            "dev": sum(1 for t in built["templates"] if t["split"] == "dev"),
            "holdout": sum(1 for t in built["templates"] if t["split"] == "holdout"),
            "skipped": built["skipped"],
        },
    }

    arguments.out.mkdir(parents=True, exist_ok=True)
    path = arguments.out / "pii_templates.json"
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    counts = document["_counts"]
    print(
        f"{path}  templates={counts['templates']} dev={counts['dev']} holdout={counts['holdout']}"
    )
    for reason, n in counts["skipped"].items():
        print(f"  skipped {n:3d}: {reason}")


if __name__ == "__main__":
    main()
