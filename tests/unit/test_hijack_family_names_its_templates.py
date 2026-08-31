"""The hijack family names the unit its percentage is a rate over (ADR 0021 Am. 1).

`prompt_hijack` published **107/131, 82%** and the artifact recorded prompts and
nothing else, so the number read as a rate over 131 independent cases. It is not:
garak's whole promptinject set carries **five** distinct attack instructions, and
the same measurement read per template says four caught outright and one missed
outright. "82%" was never a gradient.

These tests hold the repair in place. Each fails on a real regression rather than
on a rephrasing:

* a prompt with no recorded template would put the aggregate back;
* a fabricated dev/holdout split would claim a holdout this family cannot have —
  all five templates hash into the same half, so the honest artifact declares the
  impossibility instead of moving the boundary until a holdout appears;
* a change in the vendored prompt SET would silently invalidate the published
  82%, which was earned before the contents were read and may not be disturbed.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from limes.eval.external_corpus import corpus_dir, load_flat

_available = pytest.mark.skipif(
    not (corpus_dir() / "prompt_hijack.json").is_file(),
    reason="the external corpus ships in the repository and the sdist, never in the wheel",
)

#: What the family was, at the commit this record was written. Pinned so an
#: upstream change forces a human to re-read rather than sliding through.
_EXPECTED_PROMPTS = 131
_EXPECTED_TEMPLATES = 5


@_available
def test_every_hijack_prompt_names_the_template_it_came_from():
    corpus = load_flat("prompt_hijack")
    unnamed = [case for case in corpus.attacks if not case.template]
    assert unnamed == [], f"{len(unnamed)} prompt(s) carry no attack template"


@_available
def test_the_family_has_five_templates_not_a_hundred_and_thirty_one():
    corpus = load_flat("prompt_hijack")
    assert len(corpus.attacks) == _EXPECTED_PROMPTS
    templates = {case.template for case in corpus.attacks}
    assert len(templates) == _EXPECTED_TEMPLATES, (
        "the family's unit count moved; the published percentage is a rate over "
        "templates, so this changes what that number means"
    )


@_available
def test_no_holdout_is_fabricated_for_a_family_that_cannot_have_one():
    # The impossibility is the finding, and it is checkable: every template's
    # first sha256 nibble falls in the dev half, so a content-addressed split
    # leaves the holdout empty. If upstream ever adds a template that lands on
    # the other side, this goes red and a split becomes possible — which is
    # exactly when somebody should be made to look.
    corpus = load_flat("prompt_hijack")
    sides = {
        hashlib.sha256(template.encode("utf-8")).hexdigest()[0] not in "01234567"
        for template in {case.template for case in corpus.attacks}
    }
    assert sides == {False}, "a holdout is now possible for this family — split it"
    assert {case.split for case in corpus.attacks} == {"blind"}


@_available
def test_the_corpus_no_longer_claims_to_be_blind_and_says_why():
    raw = json.loads((corpus_dir() / "prompt_hijack.json").read_text(encoding="utf-8"))
    assert "BLIND" not in raw["kind"], "the contents have been read; the label may not say blind"
    assert "seen" in raw["strength"].lower()
    # The metadata must carry the reason no split exists, not merely omit one.
    assert "five" in raw["sampling"]["why"].lower()
