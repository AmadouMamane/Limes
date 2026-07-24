"""The Streamable HTTP proxy against real processes (ADR 0007 definition of done).

A real host session over HTTP, a real limes HTTP proxy process, a real MCP HTTP
server process. The claims are the stdio proxy's claims, re-proven on the new
wire — because the decision is the *same* relay and only the transport changed:

* **transparency** — host↔proxy↔server is indistinguishable from host↔server:
  the same handshake, the same tool list, the same benign result, the same
  server→host notification;
* **blocking** — an injection in a tool argument comes back ``isError`` with its
  evidence, and the server's journal shows it never arrived (with the unproxied
  control that shows it otherwise would);
* **redaction over HTTP** — a response carrying a card and an e-mail comes back
  masked in place, a normal result, with the control that shows the server really
  sends them unmasked; a secret blocks; masking is asked for, never the default;
* **replayable evidence** — a session replayed under a fixed clock re-derives
  byte-identical chain digests, over real HTTP.

The proxies spawned here are ``http_proxy.py`` (shipped, no egress detector) and
``redacting_http_proxy.py`` (the same, with an outbound double, because limes
ships none).
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from limes.eval.corpus import CASE_08, load_attacks

HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "http_journal_server.py"
PROXY = HERE / "http_proxy.py"
REDACTING_PROXY = HERE / "redacting_http_proxy.py"

BENIGN = "Quel est le solde de mon compte courant ?"
CARD = "4111 1111 1111 1111"
EMAIL = "alice@example.com"
KEY = "sk-live-AB12cd34"
ANSWER = f"Carte {CARD} renvoyée, confirmation à {EMAIL}. Solde 1 240,50 EUR."
LEAKY = f"La clé du connecteur est {KEY}, ne la partagez pas."
CARD_ONLY = f"Votre carte se terminant par {CARD} a été débitée."

_NEVER = (
    "rules:\n  - label: 'injection:never'\n    origin: limes\n    pattern: 'zzz-never-matches'\n"
)


def _injection() -> str:
    attacks = [attack for attack in load_attacks() if attack.case_id == CASE_08]
    assert attacks, "the corpus must still carry case 08"
    return attacks[0].text


def _policy(tmp_path: Path, egress: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(f"version: 1\n{egress}{_NEVER}", encoding="utf-8")
    return path


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} never came up")


def _spawn(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True,
        env={**os.environ, **(env or {})},
    )


def _stop(proc: subprocess.Popen[str]) -> str:
    proc.terminate()
    try:
        _, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    return err or ""


@contextlib.contextmanager
def _pair(
    tmp_path: Path,
    *,
    redacting: bool = False,
    policy: Path | None = None,
    record: Path | None = None,
    env: dict[str, str] | None = None,
) -> Iterator[dict[str, Any]]:
    """Start a real upstream server and a real limes HTTP proxy in front of it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    up_port = _free_port()
    proxy_port = _free_port()
    journal = tmp_path / "journal.jsonl"

    upstream = _spawn([sys.executable, str(UPSTREAM), str(journal), str(up_port)])
    proxy_cmd = [
        sys.executable,
        str(REDACTING_PROXY if redacting else PROXY),
        "--upstream",
        f"http://127.0.0.1:{up_port}/mcp",
        "--port",
        str(proxy_port),
    ]
    if policy is not None:
        proxy_cmd += ["--policy", str(policy)]
    if record is not None:
        proxy_cmd += ["--record", str(record)]
    proxy = _spawn(proxy_cmd, env=env)

    try:
        _wait_port(up_port)
        _wait_port(proxy_port)
        yield {
            "proxy_url": f"http://127.0.0.1:{proxy_port}/mcp",
            "upstream_url": f"http://127.0.0.1:{up_port}/mcp",
            "journal": journal,
        }
    finally:
        proxy_err = _stop(proxy)
        upstream_err = _stop(upstream)
        # Surface a crashed child's diagnostics if the test is going to fail.
        if "Traceback" in proxy_err:
            print(f"--- proxy stderr ---\n{proxy_err}", file=sys.stderr)
        if "Traceback" in upstream_err:
            print(f"--- upstream stderr ---\n{upstream_err}", file=sys.stderr)


def _session(
    url: str, calls: list[tuple[str, dict[str, Any]]], *, retries: int = 4
) -> dict[str, Any]:
    """Run one real host session over HTTP and report everything it observed."""

    async def _run() -> dict[str, Any]:
        notifications: list[tuple[str, object]] = []

        async def logging_callback(params: types.LoggingMessageNotificationParams) -> None:
            notifications.append((params.level, params.data))

        async with (
            streamable_http_client(url) as (read_stream, write_stream, _get_id),
            ClientSession(read_stream, write_stream, logging_callback=logging_callback) as session,
        ):
            initialized = await session.initialize()
            tools = await session.list_tools()
            results = [await session.call_tool(name, arguments) for name, arguments in calls]
            return {
                "initialize": initialized.model_dump(mode="json", by_alias=True),
                "tools": tools.model_dump(mode="json", by_alias=True),
                "results": [result.model_dump(mode="json", by_alias=True) for result in results],
                "notifications": notifications,
            }

    last: Exception | None = None
    for attempt in range(retries):
        try:
            return anyio.run(_run)
        except Exception as exc:  # startup race against uvicorn binding; retried below
            last = exc
            time.sleep(0.4 * (attempt + 1))
    raise RuntimeError(f"session against {url} never succeeded: {last}")


def _journal(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _text(result: dict[str, Any]) -> str:
    return str(result["content"][0]["text"])


# --- transparency -----------------------------------------------------------


def test_a_proxied_http_session_is_indistinguishable_from_a_direct_one(tmp_path):
    calls = [("echo", {"text": BENIGN}), ("announce", {})]

    with _pair(tmp_path / "direct") as direct_pair:
        direct = _session(direct_pair["upstream_url"], calls)
        direct_journal = _journal(direct_pair["journal"])
    with _pair(tmp_path / "proxied") as proxied_pair:
        proxied = _session(proxied_pair["proxy_url"], calls)
        proxied_journal = _journal(proxied_pair["journal"])

    assert proxied["initialize"] == direct["initialize"], (
        "the host must see the WRAPPED server's capabilities, name and version"
    )
    assert proxied["tools"] == direct["tools"]
    assert proxied["results"] == direct["results"]
    assert (
        proxied["notifications"]
        == direct["notifications"]
        == [("info", "the wrapped server speaks")]
    ), "server->host notifications must cross the HTTP proxy too"
    assert direct_journal == proxied_journal


# --- blocking, with its control ---------------------------------------------


def test_unproxied_the_injection_reaches_the_http_server(tmp_path):
    with _pair(tmp_path) as pair:
        observed = _session(pair["upstream_url"], [("echo", {"text": _injection()})])
        seen = [entry["arguments"]["text"] for entry in _journal(pair["journal"])]

    assert observed["results"][0]["isError"] is False
    assert seen == [_injection()], "the control: unproxied, the injection does arrive"


def test_proxied_the_injection_is_refused_and_the_http_server_never_receives_it(tmp_path):
    with _pair(tmp_path) as pair:
        observed = _session(
            pair["proxy_url"],
            [("echo", {"text": BENIGN}), ("echo", {"text": _injection()})],
        )
        seen = [entry["arguments"]["text"] for entry in _journal(pair["journal"])]

    benign, refused = observed["results"]
    assert benign["isError"] is False
    assert refused["isError"] is True, "a refusal is a tool result, not a transport error"
    text = refused["content"][0]["text"]
    assert "limes blocked this tool call" in text
    assert "injection:" in text, "the refusal names the rule that fired"
    assert refused["_meta"]["limes"]["evidence"]["matched_spans"], "…and carries the spans"
    assert seen == [BENIGN], f"the real server must never have seen the injection, saw: {seen}"


def test_the_http_record_file_carries_the_decisions_and_they_chain(tmp_path):
    record = tmp_path / "decisions.jsonl"
    with _pair(tmp_path, record=record) as pair:
        _session(
            pair["proxy_url"],
            [("echo", {"text": BENIGN}), ("echo", {"text": _injection()})],
        )

    entries = _records(record)
    assert [entry["mcp"]["action"] for entry in entries] == ["forward", "block"]
    assert entries[0]["prev_hash"] == "0" * 64, "genesis is 64 zeros"
    assert entries[1]["prev_hash"] == entries[0]["digest"], "each record links to the last"
    logged = json.dumps(entries)
    assert _injection() not in logged, "a decision log that quotes the attack has not redacted it"


# --- redaction over HTTP, with its control ----------------------------------


def test_unproxied_the_http_server_really_returns_the_card_and_the_address(tmp_path):
    with _pair(tmp_path) as pair:
        direct = _session(pair["upstream_url"], [("echo", {"text": ANSWER})])
    assert _text(direct["results"][0]) == ANSWER
    assert CARD in _text(direct["results"][0])


def test_proxied_over_http_the_host_receives_a_normal_result_masked_in_place(tmp_path):
    policy = _policy(tmp_path, "on_egress_finding:\n  by_kind:\n    pii: redact\n")
    with _pair(tmp_path, redacting=True, policy=policy) as pair:
        result = _session(pair["proxy_url"], [("echo", {"text": ANSWER})])["results"][0]

    assert result["isError"] is False, "a masked response is a success, not an error"
    assert _text(result) == (
        "Carte [REDACTED:pii] renvoyée, confirmation à [REDACTED:pii]. Solde 1 240,50 EUR."
    )
    crossed = json.dumps(result)
    assert CARD not in crossed, "nothing masked may appear anywhere in what crossed the wire"
    assert EMAIL not in crossed
    assert result["_meta"]["limes"]["redacted"] is True
    assert result["_meta"]["limes"]["redaction"]["kinds"] == ["pii"]


def test_over_http_the_same_policy_masks_pii_and_blocks_secrets(tmp_path):
    policy = _policy(
        tmp_path,
        "on_egress_finding:\n  default: block\n  by_kind:\n    pii: redact\n    secret: block\n",
    )
    with _pair(tmp_path, redacting=True, policy=policy) as pair:
        masked = _session(pair["proxy_url"], [("echo", {"text": ANSWER})])["results"][0]
        blocked = _session(pair["proxy_url"], [("echo", {"text": LEAKY})])["results"][0]

    assert masked["isError"] is False
    assert "[REDACTED:pii]" in _text(masked)
    assert blocked["isError"] is True, "a secret is worth losing the response over"
    assert KEY not in json.dumps(blocked)


def test_over_http_without_a_declared_policy_the_same_response_is_blocked(tmp_path):
    policy = _policy(tmp_path, "")
    with _pair(tmp_path, redacting=True, policy=policy) as pair:
        result = _session(pair["proxy_url"], [("echo", {"text": ANSWER})])["results"][0]

    assert result["isError"] is True, "masking is asked for; it is never the default"
    assert CARD not in json.dumps(result)


def test_over_http_the_last4_style_masks_the_card_in_place(tmp_path):
    policy = _policy(
        tmp_path,
        "on_egress_finding:\n  by_kind:\n    pii: redact\n  mask_style:\n    pii: last4\n",
    )
    with _pair(tmp_path, redacting=True, policy=policy) as pair:
        result = _session(pair["proxy_url"], [("echo", {"text": CARD_ONLY})])["results"][0]

    assert result["isError"] is False
    assert _text(result) == "Votre carte se terminant par ••••1111 a été débitée."
    assert CARD not in json.dumps(result), "the full PAN never leaves, only the last four"
    assert result["_meta"]["limes"]["redaction"]["spans"][0]["style"] == "last4"


# --- replayable evidence over HTTP ------------------------------------------


def test_a_replayed_http_session_re_derives_identical_digests(tmp_path):
    policy = _policy(tmp_path, "on_egress_finding:\n  by_kind:\n    pii: redact\n")
    env = {"LIMES_FIXED_CLOCK": "2026-07-24T00:00:00Z"}

    def digests(where: Path) -> list[str]:
        record = where / "decisions.jsonl"
        with _pair(where, redacting=True, policy=policy, record=record, env=env) as pair:
            _session(pair["proxy_url"], [("echo", {"text": ANSWER})])
        return [entry["digest"] for entry in _records(record)]

    first = digests(tmp_path / "run-a")
    second = digests(tmp_path / "run-b")

    assert first == second, "a fixed clock and a pure core re-derive identical digests over HTTP"
    assert len(first) == 2, "one inbound forward, one outbound redact"
