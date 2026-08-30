"""The ``limes check`` command — the third way to use limes.

After the in-process library (:class:`limes.transports.in_process.Guard`) and the
MCP stdio proxy (``limes proxy``), ``limes check`` runs the *same* pipeline from
the command line, over a file or stdin, with no transport and no server::

    limes check [--policy P] [--direction inbound|outbound] [--json] [FILE | -]

It prints the verdict and its evidence, and **its exit code is the verdict** — 0
for ``Allow``, non-zero for ``Deny`` or ``CannotSay`` — so a CI step can gate on
it ("scan this prompt", "scan this tool output") without parsing anything. It
reuses :func:`limes.guard.decide` unchanged through ``Guard.check``; this module
adds a usage surface, not a decision (ADR 0004). There is no new evidence format:
``--json`` emits the canonical :func:`limes.verdict.fingerprint` of the verdict
plus the chain record it produced — the same serialisation the ledger and the
proxy already publish.

**The direction selects the leg's detectors, exactly as a proxy deploys them**
(ADR 0018). ``--direction inbound`` runs ``injection``; ``--direction outbound``
runs the three egress detectors — ``pii-egress``, ``secrets-egress`` and
``injection-egress`` — because those are what actually guard a tool result. Until
v0.10 this command wired ``injection`` on *both* legs, so ``--direction outbound``
ran the one detector that never inspects that leg and reported a clean Allow over
content nobody had examined.

What it reports is a **verdict**, not a transformation: redaction is a transport
behaviour (ADR 0006), so a masked-and-forwarded response is something a proxy
does and a scanner does not.

``limes`` also dispatches ``limes proxy`` to the MCP transport, importing it only
on that path, so ``limes check`` stays free of the optional ``mcp`` extra.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import IntEnum
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from limes.detector import Detector, Direction
from limes.detectors.injection import InjectionDetector
from limes.detectors.injection_egress import InjectionEgressDetector
from limes.detectors.pii_egress import PiiEgressDetector
from limes.detectors.secrets_egress import SecretsEgressDetector
from limes.policy import load_injection_policy
from limes.record import DecisionRecord
from limes.transports.in_process import Guard
from limes.verdict import Allow, CannotSay, Deny, Verdict, fingerprint, render

__all__ = ["CheckExit", "build_check_parser", "main", "run_check"]


class CheckExit(IntEnum):
    """The process exit code, which *is* the verdict (that is the whole point).

    ``2`` is deliberately skipped: argparse exits ``2`` on a usage error, so a CI
    step can tell "the content was refused" (``1``/``3``) from "the command was
    mis-invoked" (``2``).
    """

    ALLOW = 0
    DENY = 1
    CANNOT_SAY = 3


_TOP_LEVEL_USAGE = (
    "usage: limes <command> [options]\n"
    "\n"
    "commands:\n"
    "  check       run the pipeline over a file or stdin; the exit code is the verdict\n"
    "  proxy       guard an MCP server over stdio (needs the `mcp` extra)\n"
    "  proxy-http  guard a Streamable HTTP MCP server (needs the `http` extra)\n"
    "\n"
    "run `limes check --help`, `limes proxy --help` or `limes proxy-http --help`."
)


def _installed_version() -> str:
    """Return the installed limes version, or a placeholder outside an install."""
    try:
        return version("limes")
    except PackageNotFoundError:  # pragma: no cover - only outside an install
        return "(not installed)"


def _utc_now() -> str:
    """Wall-clock timestamp for evidence — supplied here, never inside the core."""
    return datetime.now(UTC).isoformat()


def build_check_parser(prog: str = "limes check") -> argparse.ArgumentParser:
    """Build the parser for ``limes check``.

    Args:
        prog: The program name to show in usage.

    Returns:
        The argument parser.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Run the limes pipeline over one piece of content and report the verdict. "
            "The exit code IS the verdict: 0 allow, 1 deny, 3 cannot-say — so a CI step "
            "can gate on it."
        ),
    )
    parser.add_argument(
        "content",
        nargs="?",
        default="-",
        metavar="FILE",
        help="file to inspect, or - for stdin (the default).",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        metavar="PATH",
        help="injection policy YAML for the inbound leg (default: the packaged "
        "one). The egress rules are data too, in the packaged egress.yaml.",
    )
    parser.add_argument(
        "--direction",
        choices=[member.value for member in Direction],
        default=Direction.INBOUND.value,
        help="which leg to inspect (default: inbound). The leg selects its "
        "detectors, as a proxy deploys them: inbound runs `injection`; outbound "
        "runs `pii-egress`, `secrets-egress` and `injection-egress`.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the verdict and evidence as one JSON object instead of text.",
    )
    parser.add_argument("--version", action="version", version=f"limes {_installed_version()}")
    return parser


def _detectors_for(direction: Direction, policy: Path | None) -> tuple[list[Detector], str]:
    """The detectors that actually guard this leg, and one hash for the set (ADR 0018).

    The hash is returned with the detectors rather than derived from them later:
    ``policy_hash`` is a property of the concrete detectors, not of the
    :class:`~limes.detector.Detector` protocol, and the protocol is core (ADR
    0004) — so the CLI computes it where the concrete types are still in view
    instead of widening the protocol to suit a usage surface.

    Args:
        direction: The leg to inspect.
        policy: An override injection policy, for the inbound leg only.

    Returns:
        The detector set in a stable order, and the digest binding evidence to
        the rules that produced it.
    """
    if direction is Direction.INBOUND:
        injection = InjectionDetector(load_injection_policy(policy) if policy is not None else None)
        return [injection], injection.policy_hash
    egress = (PiiEgressDetector(), SecretsEgressDetector(), InjectionEgressDetector())
    # With more than one detector on the leg, no single detector's hash describes
    # the set, so the set's own digest is recorded.
    joined = "\n".join(f"{d.id}:{d.policy_hash}" for d in egress)
    return list(egress), sha256(joined.encode("utf-8")).hexdigest()


def _read_content(source: str) -> str:
    """Read the content to inspect from a file, or from stdin when ``source`` is ``-``."""
    if source == "-":
        return sys.stdin.read()
    return Path(source).read_text(encoding="utf-8")


def _exit_for(verdict: Verdict) -> CheckExit:
    """Map a verdict to its exit code (never ``bool(verdict)`` — that raises)."""
    if isinstance(verdict, Allow):
        return CheckExit.ALLOW
    if isinstance(verdict, Deny):
        return CheckExit.DENY
    return CheckExit.CANNOT_SAY


def _as_json(verdict: Verdict, record: DecisionRecord) -> str:
    """Serialise the verdict and its chain record as one JSON object.

    Reuses :func:`limes.verdict.fingerprint` verbatim — the canonical evidence
    serialisation the ledger hashes — and adds the record linkage an auditor
    correlates the exit code with. No new evidence format is introduced.
    """
    core: dict[str, object] = json.loads(fingerprint(verdict))
    payload: dict[str, object] = {
        **core,
        "record": {
            "seq": record.seq,
            "direction": record.direction,
            "actor": record.actor,
            "prev_hash": record.prev_hash,
            "digest": record.digest,
        },
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2)


def _as_text(verdict: Verdict, record: DecisionRecord) -> str:
    """Render the verdict and its evidence for a human reader."""
    lines = [render(verdict), f"decision: seq {record.seq}, record {record.digest}"]
    if isinstance(verdict, CannotSay):
        lines.append("evidence: none — a detector could not look; limes fails closed.")
        return "\n".join(lines)
    evidence = verdict.evidence
    lines.append(f"policy: sha256 {evidence.policy_hash}")
    lines.append(f"inspected content: sha256 {evidence.content_sha}")
    if evidence.matched_spans:
        lines.extend(
            f"matched: {span.label} at [{span.start},{span.end}) sha256 {span.matched_sha}"
            for span in evidence.matched_spans
        )
        lines.append("(evidence carries hashes and offsets, never the payload)")
    return "\n".join(lines)


def run_check(
    argv: Sequence[str], *, prog: str = "limes check", clock: Callable[[], str] = _utc_now
) -> int:
    """Parse ``argv``, run one check, print the result, and return the exit code.

    Args:
        argv: The ``check`` sub-arguments, without the program name.
        prog: The program name to show in usage.
        clock: Supplies the ``observed_at`` timestamp recorded into evidence;
            injectable so a test re-derives a deterministic chain digest.

    Returns:
        The exit code, which is the verdict: 0 allow, 1 deny, 3 cannot-say.
    """
    parser = build_check_parser(prog)
    options = parser.parse_args(list(argv))
    direction = Direction(options.direction)
    try:
        content = _read_content(options.content)
        detectors, policy_hash = _detectors_for(direction, options.policy)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))  # argparse exits 2 — a usage error, not a verdict

    guard = Guard(detectors, policy_hash=policy_hash)
    verdict = guard.check(content, actor=None, observed_at=clock(), direction=direction)
    record = guard.ledger.records()[-1]
    print(_as_json(verdict, record) if options.json else _as_text(verdict, record))
    return int(_exit_for(verdict))


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch ``limes <command>`` — ``check`` here, ``proxy`` to the MCP transport.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns:
        The process exit code.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        if arguments[0] == "check":
            return run_check(arguments[1:])
        if arguments[0] == "proxy":
            from limes.transports.mcp import cli as proxy_cli

            return proxy_cli.main(arguments)
        if arguments[0] == "proxy-http":
            try:
                from limes.transports.mcp import http as http_transport
            except ImportError as exc:
                print(
                    "limes proxy-http needs the MCP + HTTP extra:\n"
                    "    pip install 'limes[http]'      (or:  uv add 'limes[http]')\n"
                    f"the import failed with: {exc}",
                    file=sys.stderr,
                )
                return 2
            return http_transport.main_http(arguments[1:])
        if arguments[0] in ("-h", "--help"):
            print(_TOP_LEVEL_USAGE)
            return 0
        if arguments[0] in ("-V", "--version"):
            print(f"limes {_installed_version()}")
            return 0
    print(_TOP_LEVEL_USAGE, file=sys.stderr)
    return 2
