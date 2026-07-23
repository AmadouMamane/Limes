"""Egress redaction — a transport behaviour, not a verdict (ADR 0006).

The core answers one question: *is this content clean?* It answers with a
:class:`~limes.verdict.Verdict`, and a ``Deny`` on the outbound leg says a
response may not leave as it stands. What to *do* about that is the transport's
business, and this module is where it is decided.

Two dispositions, and the default is the closed one:

* ``block`` — the response does not leave. This is what every kind gets unless an
  operator has said otherwise, because a guard whose default is "let it through,
  masked" is a guard that fails open on the kinds nobody thought about.
* ``redact`` — the transport overwrites each matched region with a fixed token
  and forwards the rest **unchanged**. A secret is worth blocking over; a
  customer's e-mail address in an otherwise useful tool result usually is not.

The masking is possible only because evidence already carries what it takes: a
``Deny``'s :class:`~limes.spans.RedactedSpan` names ``start`` and ``end`` in the
inspected content. The transport still holds that content — it has not forwarded
it yet — so it can overwrite exactly the named offsets. **No new detector, no new
verdict, no new field in the core**: the offsets were always there.

What this deliberately is not (ADR 0006 anti-scope): reversible tokenisation,
format-preserving masking, and partial reveals like ``••••4242``. The token is
fixed and carries no bits of what it replaced. A mask you can undo is an
encoding, not a redaction, and a mask that preserves the shape leaks the shape.

The kind of a finding is the half of its label before the first colon —
``pii:pan`` is kind ``pii``, ``secret:aws-key`` is kind ``secret``. That is the
labelling convention every shipped rule already follows; a label with no colon is
its own kind, and an unknown kind gets the default, which is ``block``.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, final

import yaml

from limes.spans import RedactedSpan
from limes.verdict import Deny

__all__ = [
    "DEFAULT_ON_EGRESS_FINDING",
    "ON_EGRESS_FINDING_KEY",
    "Action",
    "BlockEgress",
    "EgressPolicy",
    "EgressRuling",
    "Masking",
    "OnEgressFinding",
    "RedactEgress",
    "Redaction",
    "apply_masking",
    "kind_of",
    "read_egress_policy",
    "rule_egress",
]

#: The optional policy-file key that turns a blocking egress into a masking one.
ON_EGRESS_FINDING_KEY: Final = "on_egress_finding"

_DEFAULT_KEY: Final = "default"
_BY_KIND_KEY: Final = "by_kind"


class OnEgressFinding(StrEnum):
    """What a transport does with an outbound ``Deny`` of a given kind."""

    BLOCK = "block"
    REDACT = "redact"


#: Fail closed. Overridable per policy and per kind, never implicit.
DEFAULT_ON_EGRESS_FINDING: Final = OnEgressFinding.BLOCK


class Action(StrEnum):
    """What a transport did with the message it just inspected."""

    FORWARD = "forward"
    REDACT = "redact"
    BLOCK = "block"


def kind_of(label: str) -> str:
    """Return the kind half of a ``kind:rule`` label.

    Args:
        label: A rule label, e.g. ``"pii:pan"``.

    Returns:
        The text before the first colon, or the whole label when it has none.
        An unknown kind is not an error: it simply gets the policy default,
        which is ``block``.
    """
    return label.split(":", 1)[0]


@final
@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """What to do with an outbound finding, by kind.

    Attributes:
        default: The disposition for a kind that is not named in ``by_kind``.
        by_kind: Per-kind overrides, e.g. ``{"pii": REDACT, "secret": BLOCK}``.
    """

    default: OnEgressFinding
    by_kind: Mapping[str, OnEgressFinding]

    @classmethod
    def blocking(cls) -> EgressPolicy:
        """Return the fail-closed policy: every kind blocks, no exception."""
        return cls(default=DEFAULT_ON_EGRESS_FINDING, by_kind={})

    def action_for(self, kind: str) -> OnEgressFinding:
        """Return the disposition configured for ``kind``.

        Args:
            kind: The finding kind, as returned by :func:`kind_of`.

        Returns:
            The per-kind override if one is declared, else the default.
        """
        return self.by_kind.get(kind, self.default)

    def redacts_anything(self) -> bool:
        """Whether this policy can mask at all (used to warn about a dead setting)."""
        return self.default is OnEgressFinding.REDACT or any(
            action is OnEgressFinding.REDACT for action in self.by_kind.values()
        )


@final
@dataclass(frozen=True, slots=True)
class Masking:
    """One region of the inspected content the transport will overwrite.

    Attributes:
        start: Start offset in the inspected content (same coordinates as
            :class:`~limes.spans.RedactedSpan`).
        end: End offset, exclusive.
        kinds: The kinds that fired over this region — more than one only when
            spans of different kinds overlapped and were merged.
    """

    start: int
    end: int
    kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        """Refuse a masking that could not be applied.

        Raises:
            ValueError: If the region is empty or negative, or names no kind.
        """
        if self.start < 0 or self.end <= self.start:
            raise ValueError(
                f"a masking must cover at least one character, got [{self.start},{self.end})"
            )
        if not self.kinds:
            raise ValueError(
                "a masking must name the kind(s) it masks; the token is built from them"
            )

    @property
    def token(self) -> str:
        """The fixed replacement, e.g. ``"[REDACTED:pii]"``.

        It carries the kind and nothing else: no length, no shape, no fragment of
        what it replaced. Two different PANs mask to the same eleven characters.
        """
        return f"[REDACTED:{'+'.join(self.kinds)}]"


@final
@dataclass(frozen=True, slots=True)
class Redaction:
    """The masking plan for one outbound message: what will be overwritten, and with what."""

    maskings: tuple[Masking, ...]

    def __post_init__(self) -> None:
        """Refuse a plan that cannot be applied right-to-left.

        Raises:
            ValueError: If the plan is empty, unsorted, or self-overlapping —
                any of which would shift offsets under its own feet.
        """
        if not self.maskings:
            raise ValueError("an empty redaction masks nothing; block instead of forwarding whole")
        for earlier, later in zip(self.maskings, self.maskings[1:], strict=False):
            if later.start < earlier.end:
                raise ValueError(
                    f"maskings must be sorted and disjoint, got [{earlier.start},{earlier.end}) "
                    f"then [{later.start},{later.end})"
                )

    @property
    def kinds(self) -> tuple[str, ...]:
        """Every kind this plan masks, sorted and deduplicated."""
        return tuple(sorted({kind for masking in self.maskings for kind in masking.kinds}))

    def annotation(self) -> dict[str, object]:
        """Render the plan as data for a record or a message annotation.

        Returns:
            The count, the kinds, and the offsets — the same coordinates the
            evidence already publishes. **Never the masked text**: a redaction
            log that quotes what it hid is not a redaction.
        """
        return {
            "masked": len(self.maskings),
            "kinds": list(self.kinds),
            "spans": [
                {
                    "start": masking.start,
                    "end": masking.end,
                    "kinds": list(masking.kinds),
                    "token": masking.token,
                }
                for masking in self.maskings
            ],
        }


@final
@dataclass(frozen=True, slots=True)
class BlockEgress:
    """The ruling: this response does not leave. ``reason`` says why, for the host."""

    reason: str


@final
@dataclass(frozen=True, slots=True)
class RedactEgress:
    """The ruling: this response leaves, masked according to ``redaction``."""

    redaction: Redaction
    reason: str


#: A ``Deny`` on the outbound leg becomes exactly one of these. They are separate
#: types rather than one type with a nullable plan, so a caller that reads the
#: plan has already proven there is one — the same reason ``Verdict`` is a union.
EgressRuling = BlockEgress | RedactEgress


def _merge(spans: tuple[RedactedSpan, ...]) -> tuple[Masking, ...]:
    """Turn matched spans into a sorted, disjoint masking plan."""
    merged: list[tuple[int, int, set[str]]] = []
    for span in sorted(spans, key=lambda span: (span.start, span.end)):
        kind = kind_of(span.label)
        if merged and span.start < merged[-1][1]:
            start, end, kinds = merged[-1]
            merged[-1] = (start, max(end, span.end), kinds | {kind})
            continue
        merged.append((span.start, span.end, {kind}))
    return tuple(
        Masking(start=start, end=end, kinds=tuple(sorted(kinds))) for start, end, kinds in merged
    )


def rule_egress(verdict: Deny, *, policy: EgressPolicy, content_length: int) -> EgressRuling:
    """Decide what a transport does with an outbound refusal.

    Args:
        verdict: The outbound ``Deny``. Its evidence carries the offsets.
        policy: The per-kind egress policy.
        content_length: Length of the inspected content the offsets index into.
            Passed in so a span that does not fit is caught here, where the
            answer is still "block", rather than while rewriting live content.

    Returns:
        :class:`RedactEgress` when every kind that fired is configured to be
        masked *and* every span is usable; :class:`BlockEgress` otherwise —
        including for a refusal that named no span at all, which cannot be
        masked and therefore must not be forwarded.
    """
    spans = verdict.evidence.matched_spans
    if not spans:
        return BlockEgress(
            reason=(
                f"{verdict.reason} (blocked: the refusal located no span, so nothing "
                "could be masked)"
            )
        )

    unusable = [
        span
        for span in spans
        if span.start < 0 or span.end <= span.start or span.end > content_length
    ]
    if unusable:
        return BlockEgress(
            reason=(
                f"{verdict.reason} (blocked: {len(unusable)} finding(s) named a span outside the "
                f"{content_length}-character inspected content)"
            )
        )

    blocking = sorted(
        {
            kind_of(span.label)
            for span in spans
            if policy.action_for(kind_of(span.label)) is OnEgressFinding.BLOCK
        }
    )
    if blocking:
        return BlockEgress(
            reason=f"{verdict.reason} (egress policy blocks kind: {', '.join(blocking)})"
        )

    redaction = Redaction(maskings=_merge(spans))
    return RedactEgress(
        redaction=redaction,
        reason=(
            f"{verdict.reason} (egress policy masks kind: {', '.join(redaction.kinds)}; "
            f"{len(redaction.maskings)} region(s) replaced)"
        ),
    )


def apply_masking(content: str, redaction: Redaction) -> str:
    """Overwrite each planned region of ``content`` with its token.

    Applied right to left, so an earlier replacement cannot shift a later
    offset. The plan's own invariant (sorted, disjoint) is what makes that safe.

    Args:
        content: The inspected content the offsets index into.
        redaction: The plan.

    Returns:
        The masked content. Everything outside the planned regions is byte-identical.
    """
    masked = content
    for masking in reversed(redaction.maskings):
        masked = masked[: masking.start] + masking.token + masked[masking.end :]
    return masked


def _one_action(raw: object, *, policy_path: Path, where: str) -> OnEgressFinding:
    """Read one declared disposition, or say precisely what was wrong with it."""
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return OnEgressFinding(raw)
    allowed = ", ".join(sorted(member.value for member in OnEgressFinding))
    raise ValueError(f"policy {policy_path}: {where} must be one of {allowed}, got {raw!r}")


def read_egress_policy(policy_path: Path) -> EgressPolicy | None:
    """Read the optional ``on_egress_finding`` key from a policy file.

    Two shapes are accepted, the scalar being shorthand for the mapping::

        on_egress_finding: redact

        on_egress_finding:
          default: block
          by_kind:
            pii: redact
            secret: block

    The core's :func:`limes.policy.load_injection_policy` ignores this key: it is
    the *transport's* policy, not a detector rule (ADR 0004/0006).

    Args:
        policy_path: The policy YAML to read.

    Returns:
        The declared policy, or ``None`` when the key is absent — the caller then
        applies the fail-closed default, :meth:`EgressPolicy.blocking`.

    Raises:
        ValueError: If the file is not a mapping, the value is neither a string
            nor a mapping, a disposition is not ``block``/``redact``, a kind is
            not a non-empty string, or an unrecognised key appears. An
            unrecognised key is refused rather than ignored: a policy whose typo
            silently means "block everything" is a policy nobody can trust.
    """
    data = yaml.safe_load(policy_path.read_bytes())
    if not isinstance(data, dict):
        raise ValueError(f"policy {policy_path} must be a mapping, got {type(data).__name__}")
    if ON_EGRESS_FINDING_KEY not in data:
        return None

    raw = data[ON_EGRESS_FINDING_KEY]
    if isinstance(raw, str):
        return EgressPolicy(
            default=_one_action(raw, policy_path=policy_path, where=ON_EGRESS_FINDING_KEY),
            by_kind={},
        )
    if not isinstance(raw, dict):
        raise ValueError(
            f"policy {policy_path}: {ON_EGRESS_FINDING_KEY} must be a string or a mapping, "
            f"got {type(raw).__name__}"
        )

    unknown = sorted(str(key) for key in raw if key not in {_DEFAULT_KEY, _BY_KIND_KEY})
    if unknown:
        raise ValueError(
            f"policy {policy_path}: {ON_EGRESS_FINDING_KEY} has unrecognised key(s) "
            f"{', '.join(unknown)}; expected {_DEFAULT_KEY} and/or {_BY_KIND_KEY}"
        )

    default = DEFAULT_ON_EGRESS_FINDING
    if _DEFAULT_KEY in raw:
        default = _one_action(
            raw[_DEFAULT_KEY],
            policy_path=policy_path,
            where=f"{ON_EGRESS_FINDING_KEY}.{_DEFAULT_KEY}",
        )

    by_kind: dict[str, OnEgressFinding] = {}
    declared = raw.get(_BY_KIND_KEY, {})
    if not isinstance(declared, dict):
        raise ValueError(
            f"policy {policy_path}: {ON_EGRESS_FINDING_KEY}.{_BY_KIND_KEY} must be a mapping, "
            f"got {type(declared).__name__}"
        )
    for kind, action in declared.items():
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError(
                f"policy {policy_path}: {ON_EGRESS_FINDING_KEY}.{_BY_KIND_KEY} keys must be "
                f"non-empty kind names, got {kind!r}"
            )
        by_kind[kind] = _one_action(
            action,
            policy_path=policy_path,
            where=f"{ON_EGRESS_FINDING_KEY}.{_BY_KIND_KEY}.{kind}",
        )

    return EgressPolicy(default=default, by_kind=by_kind)
