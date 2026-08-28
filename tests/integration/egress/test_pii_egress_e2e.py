"""The outbound seam, filled by a real detector, over both transports.

Until v0.4 this seam was machinery with nobody to feed it: the transport knew how
to mask offsets, and no shipped detector produced any. The proofs used doubles
that were explicitly not shippable (ADR 0003), which meant the end-to-end claim
was really "the masker works", never "limes catches a leak".

This file makes the claim the whole one. A **published test card number** in a
real MCP server's tool result is detected by the **admitted** ``pii-egress``
detector, and masked before it reaches the host — over stdio and over HTTP —
with, for each, the unproxied **control run** that shows the server does return it
in the clear. Without the control, "the host received no card number" could just
mean the server never sent one.

What is asserted beyond "it was masked": the evidence names ``pii-egress`` as the
witness. A masked forward whose record could not say *who* found the value would
be the same unwitnessed pass the empty seam used to be.
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
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

HERE = Path(__file__).resolve().parent
MCP_FIXTURES = HERE.parent / "mcp"
STDIO_SERVER = MCP_FIXTURES / "journal_server.py"
HTTP_SERVER = MCP_FIXTURES / "http_journal_server.py"
STDIO_PROXY = HERE / "guarded_proxy.py"
HTTP_PROXY = HERE / "guarded_http_proxy.py"

#: Stripe's published test card. Luhn-valid, never issued (ADR 0009).
CARD = "4242 4242 4242 4242"
#: A 16-digit order reference that FAILS Luhn — the lookalike, in the same reply.
ORDER = "1234 5678 9012 3456"
EMAIL = "jean.dupont@example.com"

ANSWER = f"Carte {CARD} débitée, confirmation à {EMAIL}. Commande n° {ORDER}, solde 1 240,50 EUR."

_NEVER = (
    "rules:\n  - label: 'injection:never'\n    origin: limes\n    pattern: 'zzz-never-matches'\n"
)

REDACT = "on_egress_finding:\n  by_kind:\n    pii: redact\n"


def _policy(tmp_path: Path, egress: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(f"version: 1\n{egress}{_NEVER}", encoding="utf-8")
    return path


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --- stdio -------------------------------------------------------------------


def _stdio_direct(journal: Path) -> list[str]:
    return [sys.executable, str(STDIO_SERVER), str(journal)]


def _stdio_proxied(journal: Path, *, policy: Path, record: Path | None = None) -> list[str]:
    options = ["--policy", str(policy)]
    if record is not None:
        options += ["--record", str(record)]
    return [sys.executable, str(STDIO_PROXY), *options, "--", *_stdio_direct(journal)]


def _stdio_call(command: list[str], text: str) -> dict[str, Any]:
    async def _run() -> dict[str, Any]:
        parameters = StdioServerParameters(command=command[0], args=command[1:])
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            async with (
                stdio_client(parameters, errlog=quiet) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                result = await session.call_tool("echo", {"text": text})
                return dict(result.model_dump(mode="json", by_alias=True))

    return anyio.run(_run)


def _text(result: dict[str, Any]) -> str:
    return str(result["content"][0]["text"])


def test_control_over_stdio_the_server_really_returns_the_card(tmp_path):
    direct = _stdio_call(_stdio_direct(tmp_path / "direct.jsonl"), ANSWER)
    assert _text(direct) == ANSWER
    assert CARD in _text(direct), "the control: unguarded, the card leaves the server"
    assert EMAIL in _text(direct)


def test_over_stdio_the_shipped_detector_finds_the_card_and_the_proxy_masks_it(tmp_path):
    record = tmp_path / "decisions.jsonl"
    result = _stdio_call(
        _stdio_proxied(tmp_path / "j.jsonl", policy=_policy(tmp_path, REDACT), record=record),
        ANSWER,
    )

    assert result["isError"] is False, "a masked response is a success, not an error"
    assert CARD not in json.dumps(result), "the card does not reach the host"
    assert EMAIL not in json.dumps(result)
    assert "1 240,50 EUR" in _text(result), "the useful part of the answer survives"
    assert ORDER in _text(result), (
        "the order reference fails Luhn and is NOT personal data — masking it would be the "
        "false positive the checksum exists to prevent, and it would be invisible here if "
        "the test only checked that the card was gone"
    )

    # tools/list is now screened too (ADR 0012), so the redact is not simply the
    # last record — find it by what it is, not by position.
    outbound = next(e for e in _records(record) if e["mcp"]["action"] == "redact")
    assert outbound["direction"] == "outbound"
    assert '"kind":"deny"' in outbound["verdict_fingerprint"], (
        "content left the proxy, masked — the chain still records the refusal"
    )
    assert "pii-egress" in outbound["verdict_fingerprint"], (
        "the seam is no longer empty: the evidence names the detector that found the value"
    )
    assert CARD not in json.dumps(_records(record))


def test_over_stdio_the_default_policy_blocks_the_card_outright(tmp_path):
    result = _stdio_call(_stdio_proxied(tmp_path / "k.jsonl", policy=_policy(tmp_path, "")), ANSWER)
    assert result["isError"] is True, "masking is asked for; blocking is what you get by default"
    assert CARD not in json.dumps(result)


# --- HTTP --------------------------------------------------------------------


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


def _spawn(cmd: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, env=dict(os.environ)
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
def _http_pair(
    tmp_path: Path, *, policy: Path, record: Path | None = None
) -> Iterator[dict[str, Any]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    up_port, proxy_port = _free_port(), _free_port()
    journal = tmp_path / "journal.jsonl"
    upstream = _spawn([sys.executable, str(HTTP_SERVER), str(journal), str(up_port)])
    proxy_cmd = [
        sys.executable,
        str(HTTP_PROXY),
        "--upstream",
        f"http://127.0.0.1:{up_port}/mcp",
        "--port",
        str(proxy_port),
        "--policy",
        str(policy),
    ]
    if record is not None:
        proxy_cmd += ["--record", str(record)]
    proxy = _spawn(proxy_cmd)
    try:
        _wait_port(up_port)
        _wait_port(proxy_port)
        yield {
            "proxy_url": f"http://127.0.0.1:{proxy_port}/mcp",
            "upstream_url": f"http://127.0.0.1:{up_port}/mcp",
        }
    finally:
        proxy_err = _stop(proxy)
        upstream_err = _stop(upstream)
        for label, err in (("proxy", proxy_err), ("upstream", upstream_err)):
            if "Traceback" in err:
                print(f"--- {label} stderr ---\n{err}", file=sys.stderr)


def _http_call(url: str, text: str, *, retries: int = 4) -> dict[str, Any]:
    async def _run() -> dict[str, Any]:
        async with (
            streamable_http_client(url) as (read_stream, write_stream, _get_id),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            result = await session.call_tool("echo", {"text": text})
            return dict(result.model_dump(mode="json", by_alias=True))

    last: Exception | None = None
    for attempt in range(retries):
        try:
            return anyio.run(_run)
        except Exception as exc:  # startup race against uvicorn binding; retried below
            last = exc
            time.sleep(0.4 * (attempt + 1))
    raise AssertionError(f"HTTP session never succeeded: {last}")


@pytest.mark.parametrize("policy_body", [REDACT])
def test_over_http_the_control_and_the_guarded_run_disagree_exactly_once(tmp_path, policy_body):
    # Both halves in one test on purpose: the control and the guarded run go to
    # the SAME upstream process in the SAME session, so "the card was masked"
    # cannot be explained by a server that behaved differently.
    record = tmp_path / "http-decisions.jsonl"
    with _http_pair(tmp_path, policy=_policy(tmp_path, policy_body), record=record) as pair:
        direct = _http_call(pair["upstream_url"], ANSWER)
        proxied = _http_call(pair["proxy_url"], ANSWER)

    assert CARD in _text(direct), "the control: unguarded over HTTP, the card leaves the server"
    assert EMAIL in _text(direct)

    assert proxied["isError"] is False
    assert CARD not in json.dumps(proxied), "guarded over HTTP, it does not reach the host"
    assert EMAIL not in json.dumps(proxied)
    assert ORDER in _text(proxied), "the Luhn-invalid order reference is left alone"
    assert "1 240,50 EUR" in _text(proxied)

    outbound = [entry for entry in _records(record) if entry["direction"] == "outbound"]
    assert outbound, "the guarded call produced an outbound decision"
    # tools/list is screened too now (ADR 0012); the card's redact is the one to find.
    redact = next(entry for entry in outbound if entry["mcp"]["action"] == "redact")
    assert "pii-egress" in redact["verdict_fingerprint"]
    assert CARD not in json.dumps(outbound)


def test_over_http_the_default_policy_blocks_the_card_outright(tmp_path):
    with _http_pair(tmp_path, policy=_policy(tmp_path, "")) as pair:
        result = _http_call(pair["proxy_url"], ANSWER)
    assert result["isError"] is True
    assert CARD not in json.dumps(result)


# --- secrets: masked kind and blocked kind, one policy ------------------------

#: A published AWS documentation key id — it authenticates nothing (ADR 0009).
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
LEAKY = f"Le connecteur utilise AWS_ACCESS_KEY_ID={AWS_KEY}, ne le partagez pas."


def test_over_stdio_a_secret_blocks_while_pii_in_the_same_session_is_masked(tmp_path):
    # Two dispositions from one policy file, proven in one session against real
    # processes: a customer's card is worth masking to keep the answer, a
    # credential is worth losing the answer over.
    policy = _policy(
        tmp_path,
        "on_egress_finding:\n  default: block\n  by_kind:\n    pii: redact\n    secret: block\n",
    )
    masked = _stdio_call(_stdio_proxied(tmp_path / "m.jsonl", policy=policy), ANSWER)
    blocked = _stdio_call(_stdio_proxied(tmp_path / "b.jsonl", policy=policy), LEAKY)

    assert masked["isError"] is False
    assert "[REDACTED:pii]" in _text(masked)

    assert blocked["isError"] is True, "a credential is worth losing the response over"
    assert AWS_KEY not in json.dumps(blocked)
    assert "secret" in _text(blocked)


def test_over_http_a_secret_blocks_with_its_unproxied_control(tmp_path):
    policy = _policy(
        tmp_path, "on_egress_finding:\n  default: block\n  by_kind:\n    secret: block\n"
    )
    with _http_pair(tmp_path, policy=policy) as pair:
        direct = _http_call(pair["upstream_url"], LEAKY)
        proxied = _http_call(pair["proxy_url"], LEAKY)

    assert AWS_KEY in _text(direct), "the control: unguarded, the credential leaves the server"
    assert proxied["isError"] is True
    assert AWS_KEY not in json.dumps(proxied)


# --- the same decision, both transports --------------------------------------


def test_both_transports_mask_the_same_bytes(tmp_path):
    # The transport-agnostic claim, asked rather than assumed: the masked text
    # the host receives is identical over stdio and over HTTP, because the
    # decision is the same core and only the wire changed (ADR 0004/0007).
    policy = _policy(tmp_path, REDACT)
    over_stdio = _stdio_call(_stdio_proxied(tmp_path / "s.jsonl", policy=policy), ANSWER)
    with _http_pair(tmp_path / "http", policy=policy) as pair:
        over_http = _http_call(pair["proxy_url"], ANSWER)
    assert _text(over_stdio) == _text(over_http)
    assert _text(over_stdio) != ANSWER, "…and neither of them is the unguarded answer"
