"""Load the copied Tessera corpus (ADR 0003/0004: copied, never imported)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CASE_08", "AttackPrompt", "load_attacks", "load_benign"]

_CORPUS = Path(__file__).resolve().parent.parent / "corpus"
_INJECTION_DIR = _CORPUS / "injection"
_BENIGN = _CORPUS / "benign" / "benign_inputs.json"

#: The case id of the measured hole (Tessera ADR 0028 §5).
CASE_08 = "08_prompt_injection_beneficiaire"


@dataclass(frozen=True, slots=True)
class AttackPrompt:
    """One (case, language) attack prompt from the injection corpus.

    Attributes:
        case_id: The case id, e.g. ``"08_prompt_injection_beneficiaire"``.
        language: ``"fr"``, ``"de"``, or ``"en"``.
        text: The attacker's ``user`` prompt.
    """

    case_id: str
    language: str
    text: str

    @property
    def key(self) -> str:
        """The runtime key ``"<case_id>|<language>"`` (Tessera's convention)."""
        return f"{self.case_id}|{self.language}"


def load_attacks() -> tuple[AttackPrompt, ...]:
    """Load every (case, language) injection prompt from the copied corpus."""
    out: list[AttackPrompt] = []
    for path in sorted(_INJECTION_DIR.glob("*.json")):
        if path.stem.startswith("_"):
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("category") != "prompt_injection":
            continue
        case_id = raw.get("id")
        prompts = raw.get("prompts")
        if not isinstance(case_id, str) or not isinstance(prompts, dict):
            continue
        for language, spec in sorted(prompts.items()):
            if not isinstance(spec, dict):
                continue
            user = spec.get("user")
            if isinstance(user, str):
                out.append(AttackPrompt(case_id=case_id, language=str(language), text=user))
    return tuple(out)


def load_benign() -> tuple[str, ...]:
    """Load the benign (must-not-block) inputs — a flat array of strings."""
    raw = json.loads(_BENIGN.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"benign corpus {_BENIGN} must be a JSON array")
    return tuple(str(item) for item in raw)
