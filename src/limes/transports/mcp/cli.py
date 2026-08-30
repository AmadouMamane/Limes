"""The console entry points: ``limes proxy`` and ``limes-proxy`` (ADR 0005).

    limes proxy [--policy P] [--record FILE] [--on-cannot-say deny|allow]
                [--on-egress-finding block|redact] [--actor NAME]
                -- <server command...>

**Everything after the first bare ``--`` is the real server's command, launched
verbatim** — including its own flags, which is why the split is done on ``argv``
before argparse ever sees it rather than with ``nargs=REMAINDER``. That is the
whole adoption wedge: an MCP host wraps the command it already runs, and neither
the host nor the server changes.

Both scripts are installed by the base package, so a user without the ``mcp``
extra gets a one-line install hint and exit code 2 — not an ``ImportError``
traceback from a console script that should not have existed.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from limes.transports.mcp.config import (
    DEFAULT_ON_CANNOT_SAY,
    OnCannotSay,
    ProxyConfig,
    read_on_cannot_say,
)
from limes.transports.redaction import (
    DEFAULT_ON_EGRESS_FINDING,
    EgressPolicy,
    OnEgressFinding,
    read_egress_policy,
)

__all__ = ["build_parser", "main", "main_proxy", "parse_config", "split_argv"]

_EPILOG = """\
example (claude_desktop_config.json):
  "command": "uvx",
  "args": ["limes-proxy", "--policy", "~/.limes/policy.yaml",
           "--", "mcp-server-filesystem", "/data"]
"""


def split_argv(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split ``argv`` at the first bare ``--``.

    Args:
        argv: The arguments, without the program name.

    Returns:
        ``(proxy_arguments, server_command)``. The server command is empty when
        there is no ``--``; everything after the first one is passed through
        untouched, separators included.
    """
    for index, token in enumerate(argv):
        if token == "--":
            return list(argv[:index]), list(argv[index + 1 :])
    return list(argv), []


def build_parser(prog: str) -> argparse.ArgumentParser:
    """Build the argument parser for the proxy's own options.

    Args:
        prog: The program name to show in usage.

    Returns:
        The parser. It knows nothing about the wrapped server's command, which
        is split off before parsing.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Guard an MCP server by proxying it: to the host a server, to the server a "
            "client. Every tool call becomes a decision that carries its evidence."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=f"{prog} [options] -- <server command...>",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        metavar="PATH",
        help="injection policy YAML (default: the one packaged with limes). May also "
        "carry the optional `on_cannot_say: deny|allow` key.",
    )
    parser.add_argument(
        "--record",
        type=Path,
        default=None,
        metavar="FILE",
        help="append decision records here as JSONL (default: stderr — stdout is the "
        "host's JSON-RPC channel and must stay clean).",
    )
    parser.add_argument(
        "--on-cannot-say",
        choices=[member.value for member in OnCannotSay],
        default=None,
        help=f"what to do when a detector could not look (default: "
        f"{DEFAULT_ON_CANNOT_SAY.value} — fail closed). Overrides the policy file.",
    )
    parser.add_argument(
        "--on-egress-finding",
        choices=[member.value for member in OnEgressFinding],
        default=None,
        help=f"what to do when a detector fires on a *response* (default: "
        f"{DEFAULT_ON_EGRESS_FINDING.value}). `redact` masks the matched regions with "
        "[REDACTED:<kind>] and forwards the rest. Overrides the policy file's default; "
        "per-kind rules stay as `on_egress_finding.by_kind` declares them. The "
        "outbound leg runs every admitted egress detector (ADR 0018).",
    )
    parser.add_argument(
        "--actor",
        default=None,
        metavar="NAME",
        help="the identity this session asserts, recorded on every decision. Omitted "
        "means unattributed, which is honest; it is never filled in for you.",
    )
    parser.add_argument("--version", action="version", version=f"limes {_installed_version()}")
    return parser


def _installed_version() -> str:
    """Return the installed limes version, or a placeholder outside a install."""
    try:
        return version("limes")
    except PackageNotFoundError:  # pragma: no cover - only outside an install
        return "(not installed)"


def parse_config(argv: Sequence[str], *, prog: str) -> ProxyConfig:
    """Parse one invocation into a :class:`~limes.transports.mcp.config.ProxyConfig`.

    Args:
        argv: The arguments, without the program name.
        prog: The program name to show in usage.

    Returns:
        The configuration.

    Raises:
        SystemExit: With code 2 on a usage error — no ``--``, no server command,
            or an unreadable ``on_cannot_say`` / ``on_egress_finding`` in the
            policy file. An unreadable setting is a usage error and never a
            silent fallback to the default: an operator who mistyped ``redact``
            must be told, not quietly given ``block``.
    """
    own, server_command = split_argv(argv)
    parser = build_parser(prog)
    options = parser.parse_args(own)

    if not server_command:
        parser.error(
            "no server command: everything after `--` is the real MCP server to guard, "
            "e.g. `-- mcp-server-filesystem /data`"
        )

    on_cannot_say = DEFAULT_ON_CANNOT_SAY
    egress = EgressPolicy.blocking()
    if options.policy is not None:
        try:
            declared = read_on_cannot_say(options.policy)
            declared_egress = read_egress_policy(options.policy)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        else:
            if declared is not None:
                on_cannot_say = declared
            if declared_egress is not None:
                egress = declared_egress
    if options.on_cannot_say is not None:
        on_cannot_say = OnCannotSay(options.on_cannot_say)
    if options.on_egress_finding is not None:
        egress = EgressPolicy(
            default=OnEgressFinding(options.on_egress_finding),
            by_kind=egress.by_kind,
            mask_style=egress.mask_style,
        )

    return ProxyConfig(
        server_command=tuple(server_command),
        policy_path=options.policy,
        record_path=options.record,
        on_cannot_say=on_cannot_say,
        actor=options.actor,
        egress=egress,
    )


def _run(config: ProxyConfig) -> int:
    """Run the bridge, reporting a missing extra rather than raising."""
    try:
        from limes.transports.mcp import bridge
    except ImportError as exc:
        print(
            "limes proxy needs the MCP SDK, which is an optional extra:\n"
            "    pip install 'limes[mcp]'      (or:  uv add 'limes[mcp]')\n"
            f"the import failed with: {exc}",
            file=sys.stderr,
        )
        return 2
    try:
        bridge.run(config)
    except (OSError, ValueError) as exc:
        # Any failure of the guard kills the session. There is deliberately no
        # degraded mode: a proxy that cannot load its policy, or that loses a
        # file mid-session, must stop rather than turn into a pass-through the
        # operator believes is guarding them.
        print(f"limes proxy refused to start: {exc}", file=sys.stderr)
        return 2
    return 0


def main_proxy(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``limes-proxy``.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns:
        The process exit code.
    """
    return _run(parse_config(sys.argv[1:] if argv is None else argv, prog="limes-proxy"))


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``limes``, whose only subcommand is ``proxy``.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns:
        The process exit code.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "proxy":
        return _run(parse_config(arguments[1:], prog="limes proxy"))
    print(
        "usage: limes proxy [options] -- <server command...>\n"
        "\n"
        "limes ships one command: `proxy`, the MCP stdio guard.\n"
        "Run `limes proxy --help` for its options.",
        file=sys.stderr,
    )
    return 2
