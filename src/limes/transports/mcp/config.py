"""What a ``limes proxy`` invocation is, as data (ADR 0005).

Two things are worth naming here rather than leaving to the CLI.

**``on_cannot_say`` defaults to ``deny``.** A detector that could not look
returns ``CannotSay``; the transport treats it as a refusal unless an operator
has *explicitly* said otherwise, in the policy file or on the command line. A
witness that cannot see may never report "ok" (ADR 0002).

**``actor`` has no default.** It is asserted by the invoking session and it is
``None`` when nobody was asserted — never a string that names somebody who did
not sign for the call (ADR 0002, Tessera ADR 0024).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, final

import yaml

__all__ = [
    "DEFAULT_ON_CANNOT_SAY",
    "ON_CANNOT_SAY_KEY",
    "OnCannotSay",
    "ProxyConfig",
    "read_on_cannot_say",
]

#: The optional policy-file key that overrides the fail-closed default.
ON_CANNOT_SAY_KEY: Final = "on_cannot_say"


class OnCannotSay(StrEnum):
    """What the proxy does when the pipeline returns ``CannotSay``."""

    DENY = "deny"
    ALLOW = "allow"


#: Fail closed. Overridable, never implicit.
DEFAULT_ON_CANNOT_SAY: Final = OnCannotSay.DENY


@final
@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """One host↔server pair, guarded.

    Attributes:
        server_command: The real server's command, verbatim — everything after
            ``--`` on the command line. Never empty.
        policy_path: The injection policy to load, or ``None`` for the packaged
            one. The same file may carry the optional ``on_cannot_say`` key.
        record_path: Where decision records are appended, or ``None`` for stderr
            (stdout is the host's JSON-RPC channel — see :mod:`limes.transports.mcp.sink`).
        on_cannot_say: Fail-closed policy for ``CannotSay``.
        actor: The identity asserted by the invoking session; ``None`` is honest
            for an unattributed session.
    """

    server_command: tuple[str, ...]
    policy_path: Path | None
    record_path: Path | None
    on_cannot_say: OnCannotSay
    actor: str | None

    def __post_init__(self) -> None:
        """Refuse a configuration with no server to wrap.

        Raises:
            ValueError: If ``server_command`` is empty.
        """
        if not self.server_command:
            raise ValueError(
                "a proxy with no server command guards nothing; pass the real server "
                "after `--`, e.g. `limes proxy -- mcp-server-filesystem /data`"
            )


def read_on_cannot_say(policy_path: Path) -> OnCannotSay | None:
    """Read the optional ``on_cannot_say`` key from a policy file.

    The core's :func:`limes.policy.load_injection_policy` ignores this key — it is
    the *transport's* policy, not a detector rule, so the transport reads it
    itself and the core is untouched.

    Args:
        policy_path: The policy YAML to read.

    Returns:
        The declared value, or ``None`` when the key is absent.

    Raises:
        ValueError: If the file is not a mapping, or the key names something
            other than ``deny`` / ``allow``.
    """
    data = yaml.safe_load(policy_path.read_bytes())
    if not isinstance(data, dict):
        raise ValueError(f"policy {policy_path} must be a mapping, got {type(data).__name__}")
    if ON_CANNOT_SAY_KEY not in data:
        return None
    raw = data[ON_CANNOT_SAY_KEY]
    try:
        return OnCannotSay(raw)
    except ValueError:
        allowed = ", ".join(sorted(member.value for member in OnCannotSay))
        raise ValueError(
            f"policy {policy_path}: {ON_CANNOT_SAY_KEY} must be one of {allowed}, got {raw!r}"
        ) from None
