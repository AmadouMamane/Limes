"""The command line — and in particular what `--` means.

Everything after the first bare `--` is the wrapped server's command, launched
verbatim. That is the whole drop-in claim: a host wraps the command it already
runs, flags and all, and nothing else changes.
"""

from __future__ import annotations

import pytest

from limes.transports.mcp.cli import main, parse_config, split_argv
from limes.transports.mcp.config import OnCannotSay
from limes.transports.redaction import EgressPolicy, OnEgressFinding

_POLICY_WITH_ALLOW = """\
version: 1
on_cannot_say: allow
rules:
  - label: 'injection:x'
    origin: limes
    pattern: 'zzz-never-matches'
"""


def test_everything_after_the_first_double_dash_is_the_server_command():
    own, server = split_argv(["--record", "r.jsonl", "--", "srv", "--flag", "--", "-x"])
    assert own == ["--record", "r.jsonl"]
    assert server == ["srv", "--flag", "--", "-x"], (
        "the server's own separators and flags must be passed through untouched"
    )


def test_without_a_double_dash_there_is_no_server_command():
    assert split_argv(["--record", "r.jsonl"]) == (["--record", "r.jsonl"], [])


def test_the_defaults_are_the_packaged_policy_stderr_and_fail_closed():
    config = parse_config(["--", "mcp-server-filesystem", "/data"], prog="limes-proxy")
    assert config.server_command == ("mcp-server-filesystem", "/data")
    assert config.policy_path is None
    assert config.record_path is None, "no --record means stderr, never stdout"
    assert config.on_cannot_say is OnCannotSay.DENY
    assert config.actor is None, "an unasserted identity stays None; it is never filled in"
    assert config.egress == EgressPolicy.blocking(), (
        "an outbound finding blocks unless an operator asked for masking"
    )


def test_no_server_command_is_a_usage_error():
    with pytest.raises(SystemExit) as exit_info:
        parse_config(["--record", "r.jsonl"], prog="limes-proxy")
    assert exit_info.value.code == 2

    with pytest.raises(SystemExit) as exit_info:
        parse_config(["--"], prog="limes-proxy")
    assert exit_info.value.code == 2


def test_the_policy_file_may_declare_on_cannot_say(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(_POLICY_WITH_ALLOW, encoding="utf-8")
    config = parse_config(["--policy", str(policy), "--", "srv"], prog="limes-proxy")
    assert config.on_cannot_say is OnCannotSay.ALLOW


def test_the_flag_overrides_the_policy_file(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(_POLICY_WITH_ALLOW, encoding="utf-8")
    config = parse_config(
        ["--policy", str(policy), "--on-cannot-say", "deny", "--", "srv"], prog="limes-proxy"
    )
    assert config.on_cannot_say is OnCannotSay.DENY


def test_an_unreadable_on_cannot_say_is_a_usage_error_not_a_silent_default(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\non_cannot_say: maybe\nrules: []\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exit_info:
        parse_config(["--policy", str(policy), "--", "srv"], prog="limes-proxy")
    assert exit_info.value.code == 2


def test_an_asserted_actor_is_carried_onto_every_decision():
    config = parse_config(["--actor", "ci-runner", "--", "srv"], prog="limes-proxy")
    assert config.actor == "ci-runner"


def test_limes_without_the_proxy_subcommand_prints_usage_and_exits_2(capsys):
    assert main([]) == 2
    assert main(["nonsense"]) == 2
    assert "limes proxy [options] -- <server command...>" in capsys.readouterr().err


_POLICY_WITH_EGRESS = """\
version: 1
on_egress_finding:
  default: block
  by_kind:
    pii: redact
    secret: block
rules:
  - label: 'injection:x'
    origin: limes
    pattern: 'zzz-never-matches'
"""


def test_the_policy_file_may_declare_the_egress_dispositions(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(_POLICY_WITH_EGRESS, encoding="utf-8")
    config = parse_config(["--policy", str(policy), "--", "srv"], prog="limes-proxy")

    assert config.egress.default is OnEgressFinding.BLOCK
    assert config.egress.action_for("pii") is OnEgressFinding.REDACT
    assert config.egress.action_for("secret") is OnEgressFinding.BLOCK


def test_the_egress_flag_moves_the_default_and_leaves_the_kinds_alone(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(_POLICY_WITH_EGRESS, encoding="utf-8")
    config = parse_config(
        ["--policy", str(policy), "--on-egress-finding", "redact", "--", "srv"], prog="limes-proxy"
    )

    assert config.egress.default is OnEgressFinding.REDACT
    assert config.egress.action_for("secret") is OnEgressFinding.BLOCK, (
        "a flag that quietly unblocked the kinds the file blocks would be a trap"
    )


def test_the_egress_flag_alone_needs_no_policy_file():
    config = parse_config(["--on-egress-finding", "redact", "--", "srv"], prog="limes-proxy")
    assert config.egress == EgressPolicy(default=OnEgressFinding.REDACT, by_kind={})


def test_an_unreadable_egress_policy_is_a_usage_error_not_a_silent_default(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\non_egress_finding: mask\nrules: []\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exit_info:
        parse_config(["--policy", str(policy), "--", "srv"], prog="limes-proxy")
    assert exit_info.value.code == 2
