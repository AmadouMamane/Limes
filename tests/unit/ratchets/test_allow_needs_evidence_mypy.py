"""Ratchet 2 — Allow is unconstructible without evidence, proven at the type level.

This is the type-level ratchet: mypy must REJECT ``Allow()``. Mutation-tested by
giving ``Allow.evidence`` a default — then ``Allow()`` type-checks (mypy exit 0),
which is exactly the red this test watches for.

**Presence before verdict** (ADR 0015). ``python -m mypy`` exits non-zero when
mypy is *not installed*, so ``returncode != 0`` — the assertion that means "mypy
rejected ``Allow()``" — is satisfied by mypy's own absence. A guard whose primary
assertion is satisfied by its own blindness is a coin that lands heads either
way. So this file resolves whether mypy exists *before* it interprets any exit
code, and declares a blind spot when it does not: never green over a hole, and
never red about code it was never able to check.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_SNIPPET = "from limes.verdict import Allow\nAllow()  # missing required 'evidence'\n"


def _mypy_is_installed() -> bool:
    # Asked of the thing itself. Not inferred from an exit code, which is the
    # very conflation this ratchet exists downstream of.
    return importlib.util.find_spec("mypy") is not None


@pytest.mark.mutation
def test_mypy_rejects_allow_without_evidence():
    if not _mypy_is_installed():
        pytest.skip(
            "mypy is not installed here, so this ratchet cannot look. It must not fall "
            "back to reading the exit code: `python -m mypy` also exits non-zero when "
            "the module is missing, so 'mypy rejected Allow()' would be satisfied by "
            "mypy's own absence (ADR 0015). Install the dev dependency group: `uv sync`."
        )
    with tempfile.TemporaryDirectory() as tmp:
        snippet = Path(tmp) / "snippet.py"
        snippet.write_text(_SNIPPET, encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--no-incremental",
                "--no-error-summary",
                str(snippet),
            ],
            cwd=tmp,
            capture_output=True,
            text=True,
            check=False,
        )
    combined = (proc.stdout + proc.stderr).lower()
    assert proc.returncode != 0, (
        "mypy ACCEPTED Allow() with no evidence — the type-level ratchet is broken "
        f"(evidence gained a default?).\n{proc.stdout}\n{proc.stderr}"
    )
    assert "evidence" in combined or "missing" in combined, (
        f"mypy failed for the wrong reason:\n{proc.stdout}\n{proc.stderr}"
    )
