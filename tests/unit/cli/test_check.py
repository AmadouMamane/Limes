"""The `limes check` CLI: the exit code is the verdict, and the evidence prints.

Every case drives the real pipeline (the shipped `injection` detector over the
real corpus), so the CLI is proven on the same decision core the library and the
proxy use — not a stub.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from limes.cli import CheckExit, main, run_check
from limes.eval.corpus import CASE_08, load_attacks

FIXED_CLOCK = "2026-07-24T00:00:00Z"


def _fixed_clock() -> str:
    return FIXED_CLOCK


def _injection_text() -> str:
    attacks = [attack for attack in load_attacks() if attack.case_id == CASE_08]
    assert attacks, "the corpus must still carry case 08"
    return attacks[0].text


BENIGN = "Quel est le solde de mon compte courant ?"


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# --- the exit code is the verdict -------------------------------------------


def test_a_benign_file_is_allowed_and_exits_zero(tmp_path, capsys):
    path = _write(tmp_path, "benign.txt", BENIGN)

    code = run_check([str(path)], clock=_fixed_clock)

    assert code == CheckExit.ALLOW
    out = capsys.readouterr().out
    assert out.startswith("[ALLOW]")
    assert "0 findings" in out


def test_an_injection_file_is_denied_and_exits_nonzero(tmp_path, capsys):
    payload = _injection_text()
    path = _write(tmp_path, "attack.txt", payload)

    code = run_check([str(path)], clock=_fixed_clock)

    assert code == CheckExit.DENY
    out = capsys.readouterr().out
    assert out.startswith("[DENY]")
    assert "injection:" in out, "the refusal names the rule that fired"
    assert "matched:" in out, "evidence carries the offsets that fired"
    assert "sha256" in out, "…and a hash of the match, never the payload"
    # The longest distinctive fragment of the attack must never be echoed back.
    fragment = max(payload.split("."), key=len).strip()
    assert len(fragment) > 20
    assert fragment not in out, "the CLI prints evidence, never the payload"


# --- --json emits the canonical serialization, no new format -----------------


def test_json_prints_the_serialized_verdict_and_record(tmp_path, capsys):
    path = _write(tmp_path, "attack.txt", _injection_text())

    code = run_check(["--json", str(path)], clock=_fixed_clock)

    assert code == CheckExit.DENY
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "deny"
    assert payload["evidence"]["policy_hash"]
    assert payload["evidence"]["content_sha"]
    assert payload["evidence"]["spans"], "a deny serialises the spans that fired"
    span = payload["evidence"]["spans"][0]
    assert {"start", "end", "label", "sha"} <= set(span)
    assert payload["record"]["digest"], "the record linkage rides along for correlation"
    assert payload["record"]["direction"] == "inbound"


def test_json_never_reproduces_the_payload(tmp_path, capsys):
    payload = _injection_text()
    path = _write(tmp_path, "attack.txt", payload)

    run_check(["--json", str(path)], clock=_fixed_clock)

    rendered = capsys.readouterr().out
    fragment = max(payload.split("."), key=len).strip()
    assert fragment not in rendered, "evidence carries hashes and offsets, never the payload"


def test_a_benign_json_verdict_is_allow_with_empty_spans(tmp_path, capsys):
    path = _write(tmp_path, "benign.txt", BENIGN)

    code = run_check(["--json", str(path)], clock=_fixed_clock)

    assert code == CheckExit.ALLOW
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "allow"
    assert payload["evidence"]["spans"] == []


# --- direction is honoured ---------------------------------------------------


def test_direction_outbound_routes_to_the_outbound_leg(tmp_path, capsys):
    # The flag routes the pipeline, and the proof is that the two legs refuse for
    # DIFFERENT REASONS: the inbound rule set names the override, the outbound one
    # names what an egress detector found. Until ADR 0018 this test asserted the
    # outbound leg ALLOWED — it was pinning a hole, because the CLI ran the inbound
    # detector against a tool result and reported a clean sheet over content
    # nothing capable of judging it had read.
    path = _write(tmp_path, "attack.txt", _injection_text())

    inbound = run_check([str(path)], clock=_fixed_clock)
    inbound_out = capsys.readouterr().out
    outbound = run_check(["--direction", "outbound", str(path)], clock=_fixed_clock)
    outbound_out = capsys.readouterr().out

    assert inbound == CheckExit.DENY
    assert outbound == CheckExit.DENY
    assert "on inbound content" in inbound_out
    assert "on outbound content" in outbound_out
    assert inbound_out != outbound_out


# --- stdin, replay, and error paths -----------------------------------------


def test_stdin_is_read_when_no_file_is_given(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(_injection_text()))

    code = run_check([], clock=_fixed_clock)

    assert code == CheckExit.DENY
    assert capsys.readouterr().out.startswith("[DENY]")


def test_the_same_content_replayed_re_derives_the_same_digest(tmp_path, capsys):
    path = _write(tmp_path, "attack.txt", _injection_text())

    run_check(["--json", str(path)], clock=_fixed_clock)
    first = json.loads(capsys.readouterr().out)["record"]["digest"]
    run_check(["--json", str(path)], clock=_fixed_clock)
    second = json.loads(capsys.readouterr().out)["record"]["digest"]

    assert first == second, "a fixed clock and pure core re-derive an identical digest"


def test_a_missing_file_is_a_usage_error_not_a_verdict(tmp_path):
    missing = tmp_path / "nope.txt"

    with pytest.raises(SystemExit) as excinfo:
        run_check([str(missing)], clock=_fixed_clock)

    assert excinfo.value.code == 2, "a mis-invocation exits 2, distinct from a verdict"


def test_an_unreadable_policy_is_a_usage_error(tmp_path):
    path = _write(tmp_path, "benign.txt", BENIGN)
    missing_policy = tmp_path / "no-policy.yaml"

    with pytest.raises(SystemExit) as excinfo:
        run_check(["--policy", str(missing_policy), str(path)], clock=_fixed_clock)

    assert excinfo.value.code == 2


# --- the top-level dispatcher ------------------------------------------------


def test_main_dispatches_check(tmp_path, capsys):
    path = _write(tmp_path, "attack.txt", _injection_text())

    code = main(["check", str(path)])

    assert code == CheckExit.DENY
    assert capsys.readouterr().out.startswith("[DENY]")


def test_main_with_no_command_prints_usage_and_exits_two(capsys):
    code = main([])

    assert code == 2
    assert "limes <command>" in capsys.readouterr().err


def test_main_help_lists_both_commands(capsys):
    code = main(["--help"])

    assert code == 0
    out = capsys.readouterr().out
    assert "check" in out
    assert "proxy" in out


# --- end to end: the installed console script --------------------------------


def test_the_installed_limes_script_runs_check(tmp_path):
    executable = shutil.which("limes") or str(Path(sys.executable).parent / "limes")
    assert Path(executable).exists(), "console script `limes` was not installed"
    attack = _write(tmp_path, "attack.txt", _injection_text())
    benign = _write(tmp_path, "benign.txt", BENIGN)

    denied = subprocess.run([executable, "check", str(attack)], capture_output=True, text=True)
    allowed = subprocess.run([executable, "check", str(benign)], capture_output=True, text=True)

    assert denied.returncode == 1, denied.stderr
    assert denied.stdout.startswith("[DENY]")
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.startswith("[ALLOW]")
