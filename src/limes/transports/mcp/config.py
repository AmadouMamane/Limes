"""What a ``limes proxy`` invocation is, as data (ADR 0005).

Three things are worth naming here rather than leaving to the CLI.

**``on_cannot_say`` defaults to ``deny``, for every family of blind spot.** A
detector that could not look returns ``CannotSay``; the transport treats it as a
refusal unless an operator has *explicitly* said otherwise, in the policy file or
on the command line. A witness that cannot see may never report "ok" (ADR 0002).
And since ADR 0029 the setting is a policy, not a switch: a declared limit names
its family (an image, an encoded payload, another script, a budget…), and the
operator opens the families they accept and no other — an agent that navigates
by screenshot accepts ``binary``; nothing else moves::

    on_cannot_say: deny            # the default, for every family
    on_cannot_say: allow           # every DECLARED family; never a fault or a refusal
    on_cannot_say:
      default: deny
      by_kind:
        binary: allow              # tool results carrying images or blobs cross
        opaque: allow              # …and base64 file contents

**``actor`` has no default.** It is asserted by the invoking session and it is
``None`` when nobody was asserted — never a string that names somebody who did
not sign for the call (ADR 0002, Tessera ADR 0024).

**``egress`` defaults to blocking.** An outbound finding stops the response
unless an operator has declared that its kind may be masked and forwarded
instead (:mod:`limes.transports.redaction`, ADR 0006). Same reasoning as
``on_cannot_say``: the closed disposition is the one you get by not thinking
about it.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, final

import yaml

from limes.transports.redaction import EgressPolicy
from limes.verdict import BlindCause, BlindKind, CannotSay

__all__ = [
    "DEFAULT_ON_CANNOT_SAY",
    "ON_CANNOT_SAY_KEY",
    "CannotSayPolicy",
    "OnCannotSay",
    "ProxyConfig",
    "read_on_cannot_say",
]

#: The optional policy-file key that overrides the fail-closed default.
ON_CANNOT_SAY_KEY: Final = "on_cannot_say"
_DEFAULT_KEY: Final = "default"
_BY_KIND_KEY: Final = "by_kind"


class OnCannotSay(StrEnum):
    """What the proxy does with a *declared* blind spot of one family."""

    DENY = "deny"
    ALLOW = "allow"


#: Fail closed. Overridable, never implicit.
DEFAULT_ON_CANNOT_SAY: Final = OnCannotSay.DENY


@final
@dataclass(frozen=True, slots=True)
class CannotSayPolicy:
    """What the proxy does when the pipeline returns ``CannotSay``, by family (ADR 0029).

    The policy speaks only about *declared* limits (``BlindCause.DECLARED``). A
    fault and a refusal block under every policy: an operator who accepts the
    guard's declared limits has not accepted a crashed guard (ADR 0026).

    Attributes:
        default: The disposition for a family not named in ``by_kind``.
        by_kind: Per-family overrides, e.g. ``{BlindKind.BINARY: ALLOW}``.
    """

    default: OnCannotSay
    by_kind: Mapping[BlindKind, OnCannotSay]

    @classmethod
    def denying(cls) -> CannotSayPolicy:
        """Return the fail-closed policy: every family blocks, no exception."""
        return cls(default=DEFAULT_ON_CANNOT_SAY, by_kind={})

    @classmethod
    def allowing(cls) -> CannotSayPolicy:
        """Return the legacy ``on_cannot_say: allow``: every declared family forwards."""
        return cls(default=OnCannotSay.ALLOW, by_kind={})

    def disposition_for(self, kind: BlindKind) -> OnCannotSay:
        """Return the disposition configured for one family."""
        return self.by_kind.get(kind, self.default)

    def opens(self, verdict: CannotSay) -> bool:
        """Whether this policy forwards ``verdict``.

        Only a declared blind spot can be opened, and only when **every** family
        it carries is allowed: a result that is both an image and mostly base64
        crosses under a policy that opened ``binary`` and ``opaque``, not under
        one that opened ``binary`` alone. A declared verdict carries at least one
        family by construction (:class:`~limes.verdict.CannotSay`), so nothing
        here is vacuously true.

        Args:
            verdict: The blind spot to rule on.

        Returns:
            ``True`` to forward, ``False`` to block.
        """
        if verdict.cause is not BlindCause.DECLARED or not verdict.kinds:
            return False
        return all(self.disposition_for(kind) is OnCannotSay.ALLOW for kind in verdict.kinds)

    def closed_kinds(self, verdict: CannotSay) -> tuple[BlindKind, ...]:
        """The families of ``verdict`` this policy does not open, sorted."""
        return tuple(
            sorted(kind for kind in verdict.kinds if self.disposition_for(kind) is OnCannotSay.DENY)
        )


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
        on_cannot_say: Fail-closed policy for ``CannotSay``, by family of
            declared limit (ADR 0029).
        actor: The identity asserted by the invoking session; ``None`` is honest
            for an unattributed session.
        egress: What to do with an outbound finding, by kind. Blocking unless the
            policy file says otherwise.
    """

    server_command: tuple[str, ...]
    policy_path: Path | None
    record_path: Path | None
    on_cannot_say: CannotSayPolicy
    actor: str | None
    egress: EgressPolicy

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


def _one_disposition(raw: object, *, policy_path: Path, where: str) -> OnCannotSay:
    """Read one declared disposition, or say precisely what was wrong with it."""
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return OnCannotSay(raw)
    allowed = ", ".join(sorted(member.value for member in OnCannotSay))
    raise ValueError(f"policy {policy_path}: {where} must be one of {allowed}, got {raw!r}")


def _one_kind(raw: object, *, policy_path: Path) -> BlindKind:
    """Read one family name, or refuse a name no blind spot will ever carry."""
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return BlindKind(raw)
    known = ", ".join(sorted(member.value for member in BlindKind))
    raise ValueError(
        f"policy {policy_path}: {ON_CANNOT_SAY_KEY}.{_BY_KIND_KEY} names the family {raw!r}, "
        f"which is not one of {known}. A family no blind spot carries is a setting that "
        f"governs nothing, so it is refused rather than ignored."
    )


def read_on_cannot_say(policy_path: Path) -> CannotSayPolicy | None:
    """Read the optional ``on_cannot_say`` key from a policy file.

    Two shapes are accepted, the scalar being shorthand for the mapping::

        on_cannot_say: allow

        on_cannot_say:
          default: deny
          by_kind:
            binary: allow
            opaque: allow

    The core's :func:`limes.policy.load_injection_policy` ignores this key — it is
    the *transport's* policy, not a detector rule, so the transport reads it
    itself and the core is untouched.

    Args:
        policy_path: The policy YAML to read.

    Returns:
        The declared policy, or ``None`` when the key is absent — the caller then
        applies the fail-closed default, :meth:`CannotSayPolicy.denying`.

    Raises:
        ValueError: If the file is not a mapping, the value is neither a string
            nor a mapping, a disposition is not ``deny`` / ``allow``, a family
            is not one :class:`~limes.verdict.BlindKind` names, or an
            unrecognised key appears. Each is refused rather than ignored: a
            policy whose typo silently means "block everything" — or worse,
            silently opens nothing where the operator believed it opened one
            family — is a policy nobody can trust.
    """
    try:
        data = yaml.safe_load(policy_path.read_bytes())
    except yaml.YAMLError as exc:
        raise ValueError(f"policy {policy_path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"policy {policy_path} must be a mapping, got {type(data).__name__}")
    if ON_CANNOT_SAY_KEY not in data:
        return None

    raw = data[ON_CANNOT_SAY_KEY]
    if isinstance(raw, str):
        return CannotSayPolicy(
            default=_one_disposition(raw, policy_path=policy_path, where=ON_CANNOT_SAY_KEY),
            by_kind={},
        )
    if not isinstance(raw, dict):
        raise ValueError(
            f"policy {policy_path}: {ON_CANNOT_SAY_KEY} must be a string or a mapping, "
            f"got {type(raw).__name__}"
        )

    unknown = sorted(str(key) for key in raw if key not in {_DEFAULT_KEY, _BY_KIND_KEY})
    if unknown:
        raise ValueError(
            f"policy {policy_path}: {ON_CANNOT_SAY_KEY} has unrecognised key(s) "
            f"{', '.join(unknown)}; expected {_DEFAULT_KEY} and/or {_BY_KIND_KEY}"
        )

    default = DEFAULT_ON_CANNOT_SAY
    if _DEFAULT_KEY in raw:
        default = _one_disposition(
            raw[_DEFAULT_KEY],
            policy_path=policy_path,
            where=f"{ON_CANNOT_SAY_KEY}.{_DEFAULT_KEY}",
        )

    by_kind: dict[BlindKind, OnCannotSay] = {}
    declared = raw.get(_BY_KIND_KEY, {})
    if not isinstance(declared, dict):
        raise ValueError(
            f"policy {policy_path}: {ON_CANNOT_SAY_KEY}.{_BY_KIND_KEY} must be a mapping, "
            f"got {type(declared).__name__}"
        )
    for name, disposition in declared.items():
        kind = _one_kind(name, policy_path=policy_path)
        by_kind[kind] = _one_disposition(
            disposition,
            policy_path=policy_path,
            where=f"{ON_CANNOT_SAY_KEY}.{_BY_KIND_KEY}.{kind.value}",
        )
    return CannotSayPolicy(default=default, by_kind=by_kind)
