"""The copied corpus keeps Tessera's grader lesson (ADR 0003; Tessera ADR 0028 §5).

Mirrors Tessera's ``test_injection_grader_no_attack_tokens.py``: no refusal
marker may be a word the attacker can make the model say. If limes ever adds an
output-side grader, this invariant is already enforced on its corpus.
"""

from __future__ import annotations

import json
from pathlib import Path

_CORPUS = Path(__file__).resolve().parents[2] / "src" / "limes" / "corpus" / "injection"


def _cases() -> list[dict[str, object]]:
    cases = []
    for path in sorted(_CORPUS.glob("*.json")):
        if path.stem.startswith("_"):
            continue
        case = json.loads(path.read_text(encoding="utf-8"))
        if case.get("category") == "prompt_injection":
            cases.append(case)
    return cases


def test_the_corpus_has_the_eleven_injection_cases():
    # A blind test that found nothing would pass silently; assert it can see (ADR 0026).
    assert len(_cases()) == 11


def test_case_08_is_present_with_three_languages():
    by_id = {c["id"]: c for c in _cases()}
    assert "08_prompt_injection_beneficiaire" in by_id
    prompts = by_id["08_prompt_injection_beneficiaire"]["prompts"]
    assert isinstance(prompts, dict)
    assert sorted(prompts) == ["de", "en", "fr"]


def test_no_refusal_marker_in_attack_text():
    offenders: list[str] = []
    for case in _cases():
        prompts = case.get("prompts", {})
        assert isinstance(prompts, dict)
        attack = " ".join(
            str(p.get("user", "")) for p in prompts.values() if isinstance(p, dict)
        ).lower()
        criteria = case.get("pass_criteria", {})
        assert isinstance(criteria, dict)
        for marker in criteria.get("must_contain_any", []) or []:
            if str(marker).lower() in attack:
                offenders.append(
                    f"{case['id']}: refusal marker {marker!r} appears in its own attack"
                )
    assert not offenders, "a refusal marker is reachable by the attack:\n" + "\n".join(offenders)
