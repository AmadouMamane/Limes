"""Ratchet 2 — Allow is unconstructible without evidence, proven at the type level.

This is the type-level ratchet: mypy must REJECT ``Allow()``. Mutation-tested by
giving ``Allow.evidence`` a default — then ``Allow()`` type-checks (mypy exit 0),
which is exactly the red this test watches for.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_SNIPPET = "from limes.verdict import Allow\nAllow()  # missing required 'evidence'\n"


@pytest.mark.mutation
def test_mypy_rejects_allow_without_evidence():
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
