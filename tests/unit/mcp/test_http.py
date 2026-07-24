"""The HTTP transport is plumbing over the shared decision (ADR 0007 frontier).

The load-bearing claim of the third transport is that it *reuses* the stdio
proxy's decision — the same :class:`~limes.transports.mcp.bridge.Relay` — and adds
only HTTP wiring. These are the ratchets for that claim: the HTTP module runs the
very same relay object, and it defines no decision of its own. Copy a decision
function into the HTTP module, or point it at a private relay, and one of these
goes red.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from limes.transports.mcp import bridge, http
from limes.transports.mcp.http import HttpProxyConfig, parse_http_config

_NEVER = "rules:\n  - label: 'injection:never'\n    origin: limes\n    pattern: 'zzz'\n"


# --- the frontier: shared decision, new plumbing ----------------------------


def test_the_http_proxy_runs_the_same_relay_as_the_stdio_proxy():
    # vars(http)[...] inspects the module namespace directly: the HTTP module
    # imports these without re-exporting them, and the point of this test is
    # precisely that the names it uses are the *bridge's* objects, not copies.
    assert vars(http)["Relay"] is bridge.Relay, "the HTTP transport reuses the Relay, not a copy"
    assert vars(http)["utc_now_iso"] is bridge.utc_now_iso, "…and the same clock seam"


def test_the_http_module_defines_no_decision_logic_of_its_own():
    source = Path(http.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "def rule(",
        "def rule_egress(",
        "def _screen_result(",
        "def _inspect_call(",
        "def _masked_response(",
    ):
        assert forbidden not in source, (
            f"decision logic {forbidden!r} lives in bridge/redaction; the HTTP module is plumbing"
        )


# --- configuration ----------------------------------------------------------


def test_config_refuses_a_missing_upstream():
    with pytest.raises(ValueError, match="no upstream"):
        HttpProxyConfig(upstream_url="")


def test_config_refuses_a_non_http_upstream():
    with pytest.raises(ValueError, match="http"):
        HttpProxyConfig(upstream_url="ftp://host/mcp")


def test_config_defaults_are_loopback_and_blocking():
    config = HttpProxyConfig(upstream_url="http://127.0.0.1:9000/mcp")
    assert config.host == "127.0.0.1"
    assert not config.egress.redacts_anything(), "the closed disposition is the default"


# --- parsing ----------------------------------------------------------------


def test_parse_reads_the_upstream_port_and_egress_policy(tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text(
        f"version: 1\non_egress_finding:\n  by_kind:\n    pii: redact\n{_NEVER}", encoding="utf-8"
    )

    config = parse_http_config(
        ["--upstream", "http://127.0.0.1:9000/mcp", "--port", "9100", "--policy", str(policy)],
        prog="test",
    )

    assert config.upstream_url == "http://127.0.0.1:9000/mcp"
    assert config.port == 9100
    assert config.egress.redacts_anything(), "the policy file's egress rules are read"


def test_parse_requires_an_upstream():
    with pytest.raises(SystemExit) as excinfo:
        parse_http_config(["--port", "9100"], prog="test")
    assert excinfo.value.code == 2


def test_parse_rejects_an_unreadable_policy(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        parse_http_config(
            ["--upstream", "http://127.0.0.1:9000/mcp", "--policy", str(tmp_path / "nope.yaml")],
            prog="test",
        )
    assert excinfo.value.code == 2


def test_parse_rejects_a_non_http_upstream_as_a_usage_error():
    with pytest.raises(SystemExit) as excinfo:
        parse_http_config(["--upstream", "ftp://host/mcp"], prog="test")
    assert excinfo.value.code == 2
