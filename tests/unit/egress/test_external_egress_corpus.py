"""The external egress corpora keep the four promises their provenance makes.

Each of these was a real failure before it was a test.

* **No template on both sides.** The hijack family was thinned by prompt hash, so
  every attack template survived into every bucket and its "held out" number could
  not have told memorisation from generalisation (ADR 0021). Both corpora here
  split by the unit a rule actually meets — a sentence template, a format id — and
  this file asserts the two sides are disjoint rather than trusting the script.
* **No contiguous credential literal in the file** (ADR 0010). The first version
  of the gitleaks vendoring stored its hard negatives verbatim and put 44
  credential-shaped strings into the repository.
* **An absent corpus declares a blind spot** (ADR 0015), never an empty result —
  an empty corpus scores a perfect zero false positives and a perfect zero recall,
  and both are statements about a file nobody read.
* **A matched control differs from its attack by exactly the token.** Otherwise
  the pair measures the sentence, not the value.
"""

from __future__ import annotations

import json

import pytest

from limes.detectors.egress_policy import load_egress_policy
from limes.eval.external_corpus import ExternalCorpusUnavailable
from limes.eval.external_egress_corpus import (
    corpus_root,
    load_pii_external,
    load_secrets_external,
)

#: The two shapes that appear literally on purpose (ADR 0010): a PEM block whose
#: body decodes to a documentation string, and the JWT every tutorial ships.
_LITERAL_ALLOWED = frozenset({"secret:private-key-pem", "secret:jwt"})

_available = pytest.mark.skipif(
    not (corpus_root() / "presidio" / "pii_templates.json").is_file(),
    reason="the external egress corpora ship in the repository and the sdist, never the wheel",
)


@_available
def test_no_pii_template_appears_in_both_splits():
    corpus = load_pii_external()
    dev = {case.template for case in corpus.split("dev")}
    holdout = {case.template for case in corpus.split("holdout")}
    both = dev & holdout
    assert both == set(), f"{len(both)} template(s) on both sides of the split"
    assert dev, "a split with an empty side cannot hold anything out"
    assert holdout, "a split with an empty side cannot hold anything out"


@_available
def test_no_secret_format_appears_in_both_splits():
    corpus = load_secrets_external()
    dev = {case.template for case in corpus.split("dev")}
    holdout = {case.template for case in corpus.split("holdout")}
    both = dev & holdout
    assert both == set(), f"{len(both)} rule id(s) on both sides of the split"
    assert dev, "a split with an empty side cannot hold anything out"
    assert holdout, "a split with an empty side cannot hold anything out"


@_available
def test_every_pii_attack_carries_its_value_exactly_once():
    # The grader reads offsets. A value that appears twice, or not at all, would
    # make "located" mean something other than what the matrix says it means.
    for case in load_pii_external().attacks:
        assert case.content.count(case.locate) == 1, case.case_id


@_available
def test_a_matched_control_differs_from_its_attack_by_exactly_the_token():
    corpus = load_pii_external()
    attacks = {case.case_id: case for case in corpus.attacks}
    checked = 0
    for control in corpus.controls:
        if control.kind != "control_decoy":
            continue
        attack = attacks[control.case_id.removesuffix("_decoy")]
        # Everything outside the value is identical: same template, same fillers.
        head = attack.content.index(attack.locate)
        assert control.content[:head] == attack.content[:head], control.case_id
        tail = len(attack.content) - head - len(attack.locate)
        assert control.content[len(control.content) - tail :] == attack.content[-tail:] or not tail
        checked += 1
    assert checked > 0, "no decoy control was checked — the pairing is not being verified"


@_available
def test_the_secrets_corpus_file_carries_no_contiguous_credential_literal():
    # The witness interrogates the FILE, not the loaded corpus (ADR 0026): the
    # joined token IS a credential shape, and must be, while the stored bytes
    # must not be.
    raw = (corpus_root() / "gitleaks" / "secret_formats.json").read_text(encoding="utf-8")
    rules = [
        rule
        for rule in load_egress_policy().rules_for("secrets-egress")
        if rule.label not in _LITERAL_ALLOWED
    ]
    offenders = [
        (rule.label, match.group(0)) for rule in rules for match in rule.pattern.finditer(raw)
    ]
    assert offenders == [], f"{len(offenders)} contiguous credential literal(s) in the file"


@_available
def test_the_joined_tokens_are_still_credential_shaped():
    # The mirror of the test above, and the reason it is not vacuous: if the
    # fragments joined to nothing detectable, the file would trivially pass the
    # no-literal check while measuring nothing.
    corpus = load_secrets_external()
    assert all(case.locate for case in corpus.attacks)
    assert all(case.locate in case.content for case in corpus.attacks)


@_available
def test_the_vendored_blind_spots_are_named_and_excluded():
    corpus = load_secrets_external()
    assert corpus.blind_spots, "a corpus that lost formats silently would report a better number"
    for spot in corpus.blind_spots:
        assert spot["reason"].strip(), f"{spot['rule']} is a blind spot with no stated reason"
    ids = {case.template for case in corpus.attacks}
    assert not ids & {spot["rule"] for spot in corpus.blind_spots}
    assert len(corpus.attacks) + len(corpus.blind_spots) == corpus.catalogue_rules


def test_an_absent_corpus_is_a_blind_spot_not_an_empty_result(tmp_path, monkeypatch):
    monkeypatch.setattr("limes.eval.external_egress_corpus._ROOT", tmp_path)
    with pytest.raises(ExternalCorpusUnavailable):
        load_pii_external()
    with pytest.raises(ExternalCorpusUnavailable):
        load_secrets_external()


@_available
def test_the_provenance_records_a_licence_a_commit_and_a_digest():
    # A copy whose licence, commit or digest is missing is a copy nobody can
    # check — and this repository's whole argument is checkable reuse.
    for source, name, digests in (
        ("presidio", "pii_templates.json", ("sha256",)),
        ("gitleaks", "secret_formats.json", ("config_sha256", "tarball_sha256")),
    ):
        document = json.loads((corpus_root() / source / name).read_text(encoding="utf-8"))
        upstream = document["source"]
        assert upstream["license"] == "MIT"
        assert len(upstream["commit"]) == 40
        for key in digests:
            assert len(upstream[key]) == 64
        assert document["strength"].strip()
        assert (corpus_root() / source / "PROVENANCE.md").is_file()
