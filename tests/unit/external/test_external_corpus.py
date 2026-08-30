from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from limes.eval.external_corpus import (
    MARKER,
    ExternalCorpusUnavailable,
    available,
    corpus_dir,
    load_external,
)

pytestmark = pytest.mark.skipif(
    not available(),
    reason=(
        "the external adversary corpus lives under eval/ and ships in the sdist and a "
        "checkout, never in the wheel — from an installed limes there is nothing to read "
        "(ADR 0015: a blind spot, not an empty result)"
    ),
)

NAMES = ("latent_injection", "latent_jailbreak")


@pytest.mark.parametrize("name", NAMES)
def test_the_corpus_loads_and_names_where_it_came_from(name):
    corpus = load_external(name)
    assert corpus.source["tool"] == "garak"
    assert corpus.source["license"] == "Apache-2.0"
    # A vendored corpus with no version is a corpus nobody can re-derive.
    assert corpus.source["version"]
    assert corpus.source["url"].startswith("https://")
    assert corpus.attacks
    assert corpus.benign


@pytest.mark.parametrize("name", NAMES)
def test_every_attack_lands_in_the_split_its_own_hash_names(name):
    # The split rule is the corpus's only defence against being steered: if it
    # were anything but a function of the prompt's bytes, an author could move a
    # hard case out of holdout by editing a list.
    for case in load_external(name).attacks:
        nibble = hashlib.sha256(case.text.encode("utf-8")).hexdigest()[0]
        expected = {"0": "dev", "1": "holdout"}[nibble]
        assert case.split == expected, f"{case.probe}: {case.split} but hash says {expected}"


@pytest.mark.parametrize("name", NAMES)
def test_dev_and_holdout_are_disjoint_and_both_populated(name):
    corpus = load_external(name)
    dev = {case.text for case in corpus.split("dev")}
    holdout = {case.text for case in corpus.split("holdout")}
    assert dev
    assert holdout
    assert dev.isdisjoint(holdout)


@pytest.mark.parametrize("name", NAMES)
def test_the_benign_control_is_the_same_document_without_the_injection(name):
    # The whole design: attack and control differ by exactly the injection. If a
    # control were an unrelated document, a detector could score a clean
    # false-positive sheet by having learnt "attacks are long" — and nobody
    # reading the matrix would see it.
    corpus = load_external(name)
    raw = json.loads((corpus_dir() / f"{name}.json").read_text(encoding="utf-8"))
    controls = {case.text for case in corpus.benign}
    for probe, spec in raw["probes"].items():
        for top in spec["top_instructions"]:
            for context in spec["contexts"]:
                assert top + context.replace(MARKER, "") in controls, probe


@pytest.mark.parametrize("name", NAMES)
def test_no_control_still_carries_an_injection(name):
    corpus = load_external(name)
    raw = json.loads((corpus_dir() / f"{name}.json").read_text(encoding="utf-8"))
    injections = {i for spec in raw["probes"].values() for i in spec["injections"]}
    for case in corpus.benign:
        assert MARKER not in case.text
        # A control that still held its injection would count as a false positive
        # every time the detector worked.
        assert not any(injection and injection in case.text for injection in injections)


@pytest.mark.parametrize("name", NAMES)
def test_every_attack_actually_contains_its_injection(name):
    corpus = load_external(name)
    raw = json.loads((corpus_dir() / f"{name}.json").read_text(encoding="utf-8"))
    for case in corpus.attacks:
        injections = raw["probes"][case.probe]["injections"]
        assert any(injection in case.text for injection in injections), case.probe
        assert MARKER not in case.text


def test_an_absent_corpus_is_a_blind_spot_not_an_empty_corpus(monkeypatch, tmp_path):
    # The failure mode this guards: an empty corpus scores 0 false positives and
    # 0 recall, and both read as measurements of a file nobody opened (ADR 0015).
    monkeypatch.setattr("limes.eval.external_corpus.corpus_dir", lambda: Path(tmp_path))
    with pytest.raises(ExternalCorpusUnavailable) as raised:
        load_external("latent_injection")
    assert "not on disk" in str(raised.value)


def test_the_vendored_files_declare_the_protocol_they_are_used_under():
    corpus = load_external("latent_injection")
    protocol = str(corpus.sampling["protocol"])
    assert "holdout is scored once" in protocol
    assert "dev" in protocol


def test_the_jailbreak_corpus_is_labelled_out_of_scope():
    # It is vendored to be measured, not to be claimed. A reader who finds it in
    # the tree must be able to tell which of the two it is without the matrix.
    assert "out of scope" in load_external("latent_jailbreak").kind
    assert "in-scope" in load_external("latent_injection").kind
