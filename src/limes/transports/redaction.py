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

The masked region is rendered by a *style*, chosen per kind (ADR 0008). The
default is ``full`` — a fixed ``[REDACTED:<kind>]`` token that carries no bits of
what it replaced. Two more, opt-in per kind, keep a little of the shape when the
deployment has decided that little is safe:

* ``last4`` — reveal the last four characters and mask the rest (``••••4242``),
  the PCI-DSS convention for a card number; a value of four characters or fewer
  reveals *nothing*, so a short secret can never be shown whole;
* ``format_preserving`` — keep the length and the separators, replace every digit
  with ``0`` and every letter with ``x`` (``0000 0000 0000 0000``), for a UI that
  validates a shape.

Every style is **deterministic and verified**: after masking, the transport
confirms by re-derivation that the sensitive original is unrecoverable from its
rendering (:func:`conceals_all`), and *blocks* rather than forward a mask that
kept too much. What this still is not (ADR 0008 anti-scope): reversible
tokenisation and format-preserving *encryption*. Both need a keystore or a
cipher; a mask you can undo is an encoding, not a redaction.

The kind of a finding is the half of its label before the first colon —
``pii:pan`` is kind ``pii``, ``secret:aws-key`` is kind ``secret``. That is the
labelling convention every shipped rule already follows; a label with no colon is
its own kind, and an unknown kind gets the default, which is ``block``.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, final

import yaml

from limes.spans import RedactedSpan
from limes.verdict import Deny

__all__ = [
    "DEFAULT_MASK_STYLE",
    "DEFAULT_ON_EGRESS_FINDING",
    "MASK_STYLE_KEY",
    "ON_EGRESS_FINDING_KEY",
    "Action",
    "BlockEgress",
    "EgressPolicy",
    "EgressRuling",
    "MaskStyle",
    "Masking",
    "OnEgressFinding",
    "RedactEgress",
    "Redaction",
    "apply_masking",
    "conceals_all",
    "kind_of",
    "read_egress_policy",
    "rule_egress",
]

#: The optional policy-file key that turns a blocking egress into a masking one.
ON_EGRESS_FINDING_KEY: Final = "on_egress_finding"

#: The optional policy-file key that chooses a mask style per kind.
MASK_STYLE_KEY: Final = "mask_style"

_DEFAULT_KEY: Final = "default"
_BY_KIND_KEY: Final = "by_kind"

_BULLET: Final = "•"
_LAST4_REVEAL: Final = 4


class OnEgressFinding(StrEnum):
    """What a transport does with an outbound ``Deny`` of a given kind."""

    BLOCK = "block"
    REDACT = "redact"


#: Fail closed. Overridable per policy and per kind, never implicit.
DEFAULT_ON_EGRESS_FINDING: Final = OnEgressFinding.BLOCK


class MaskStyle(StrEnum):
    """How a masked region is rendered (ADR 0008). ``full`` is the default."""

    FULL = "full"
    LAST4 = "last4"
    FORMAT_PRESERVING = "format_preserving"


#: The unchanged v0.3 behaviour: a fixed, shape-free ``[REDACTED:<kind>]`` token.
DEFAULT_MASK_STYLE: Final = MaskStyle.FULL


def _render_last4(original: str) -> str:
    """Mask all but the last four characters (four or fewer reveals nothing)."""
    revealed = original[-_LAST4_REVEAL:] if len(original) > _LAST4_REVEAL else ""
    return _BULLET * _LAST4_REVEAL + revealed


def _render_format_preserving(original: str) -> str:
    """Keep length and separators; replace each digit with ``0``, each letter with ``x``."""
    rendered: list[str] = []
    for char in original:
        if char.isdigit():
            rendered.append("0")
        elif char.isalpha():
            rendered.append("x")
        else:
            rendered.append(char)
    return "".join(rendered)


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
        mask_style: Per-kind render styles for a masked kind, e.g.
            ``{"pii": MaskStyle.LAST4}``. A kind with no entry masks ``full``.
    """

    default: OnEgressFinding
    by_kind: Mapping[str, OnEgressFinding]
    mask_style: Mapping[str, MaskStyle] = field(default_factory=dict)

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

    def style_for(self, kind: str) -> MaskStyle:
        """Return the mask style configured for ``kind`` (``full`` if none)."""
        return self.mask_style.get(kind, DEFAULT_MASK_STYLE)

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
        style: How the region is rendered (ADR 0008). ``full`` by default, and
            always ``full`` for a merged multi-kind region, whose per-kind styles
            would otherwise conflict.
    """

    start: int
    end: int
    kinds: tuple[str, ...]
    style: MaskStyle = DEFAULT_MASK_STYLE

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
        """The kind marker, e.g. ``"[REDACTED:pii]"``.

        It carries the kind and nothing else: no length, no shape, no fragment of
        what it replaced. It is what ``full`` writes into the content, and — for
        every style — what the record names the region by, so an audit log never
        quotes the masked bytes even when the style revealed the last four.
        """
        return f"[REDACTED:{'+'.join(self.kinds)}]"

    def render(self, original: str) -> str:
        """Render the replacement for ``original`` under this masking's style.

        Args:
            original: The exact substring being masked — ``content[start:end]``.
                The styled renderings are functions of it (the last four
                characters, or its shape); ``full`` ignores it.

        Returns:
            The text that replaces ``original`` in the forwarded content.
        """
        if self.style is MaskStyle.LAST4:
            return _render_last4(original)
        if self.style is MaskStyle.FORMAT_PRESERVING:
            return _render_format_preserving(original)
        return self.token

    def conceals(self, original: str) -> bool:
        """Whether ``original`` is unrecoverable from its rendering (ADR 0008).

        The verification the styled masks require: revealing the last four
        characters is safe only while the whole value stays gone. A rendering that
        still contains the original — ``format_preserving`` over a value that was
        already all placeholders, say — has masked nothing, and the caller blocks.
        """
        return bool(original) and original not in self.render(original)


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
                    "style": masking.style.value,
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


def _merge(
    spans: tuple[RedactedSpan, ...], *, style_for: Callable[[str], MaskStyle]
) -> tuple[Masking, ...]:
    """Turn matched spans into a sorted, disjoint masking plan.

    A single-kind region takes that kind's configured style; a region where
    different kinds overlapped and were merged falls back to ``full``, because two
    kinds' styles cannot both be honoured over the same bytes.
    """
    merged: list[tuple[int, int, set[str]]] = []
    for span in sorted(spans, key=lambda span: (span.start, span.end)):
        kind = kind_of(span.label)
        if merged and span.start < merged[-1][1]:
            start, end, kinds = merged[-1]
            merged[-1] = (start, max(end, span.end), kinds | {kind})
            continue
        merged.append((span.start, span.end, {kind}))
    plan: list[Masking] = []
    for start, end, kinds in merged:
        style = style_for(next(iter(kinds))) if len(kinds) == 1 else DEFAULT_MASK_STYLE
        plan.append(Masking(start=start, end=end, kinds=tuple(sorted(kinds)), style=style))
    return tuple(plan)


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

    redaction = Redaction(maskings=_merge(spans, style_for=policy.style_for))
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
        replacement = masking.render(content[masking.start : masking.end])
        masked = masked[: masking.start] + replacement + masked[masking.end :]
    return masked


def conceals_all(content: str, redaction: Redaction) -> bool:
    """Whether every masked region's sensitive original is gone from its rendering.

    The re-derivation the styled masks require (ADR 0008): applied over the content
    the offsets index into, every masking must leave its original unrecoverable. A
    ``full`` mask always does; ``last4`` does by construction (a value of four
    characters or fewer reveals nothing); ``format_preserving`` does unless the
    value was already all placeholders. When one does not, the caller blocks rather
    than forward a redaction that redacts nothing.

    Args:
        content: The inspected content the offsets index into.
        redaction: The masking plan.

    Returns:
        ``True`` when every region conceals its original.
    """
    return all(
        masking.conceals(content[masking.start : masking.end]) for masking in redaction.maskings
    )


def _one_action(raw: object, *, policy_path: Path, where: str) -> OnEgressFinding:
    """Read one declared disposition, or say precisely what was wrong with it."""
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return OnEgressFinding(raw)
    allowed = ", ".join(sorted(member.value for member in OnEgressFinding))
    raise ValueError(f"policy {policy_path}: {where} must be one of {allowed}, got {raw!r}")


def _one_style(raw: object, *, policy_path: Path, where: str) -> MaskStyle:
    """Read one declared mask style, or say precisely what was wrong with it."""
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return MaskStyle(raw)
    allowed = ", ".join(sorted(member.value for member in MaskStyle))
    raise ValueError(f"policy {policy_path}: {where} must be one of {allowed}, got {raw!r}")


def _read_mask_style(raw: dict[object, object], *, policy_path: Path) -> dict[str, MaskStyle]:
    """Read the optional ``mask_style`` sub-mapping (kind -> style)."""
    declared = raw.get(MASK_STYLE_KEY, {})
    if not isinstance(declared, dict):
        raise ValueError(
            f"policy {policy_path}: {ON_EGRESS_FINDING_KEY}.{MASK_STYLE_KEY} must be a mapping, "
            f"got {type(declared).__name__}"
        )
    styles: dict[str, MaskStyle] = {}
    for kind, style in declared.items():
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError(
                f"policy {policy_path}: {ON_EGRESS_FINDING_KEY}.{MASK_STYLE_KEY} keys must be "
                f"non-empty kind names, got {kind!r}"
            )
        styles[kind] = _one_style(
            style,
            policy_path=policy_path,
            where=f"{ON_EGRESS_FINDING_KEY}.{MASK_STYLE_KEY}.{kind}",
        )
    return styles


def read_egress_policy(policy_path: Path) -> EgressPolicy | None:
    """Read the optional ``on_egress_finding`` key from a policy file.

    Two shapes are accepted, the scalar being shorthand for the mapping::

        on_egress_finding: redact

        on_egress_finding:
          default: block
          by_kind:
            pii: redact
            secret: block
          mask_style:            # optional, per kind; default is `full`
            pii: last4

    The core's :func:`limes.policy.load_injection_policy` ignores this key: it is
    the *transport's* policy, not a detector rule (ADR 0004/0006/0008).

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

    unknown = sorted(
        str(key) for key in raw if key not in {_DEFAULT_KEY, _BY_KIND_KEY, MASK_STYLE_KEY}
    )
    if unknown:
        raise ValueError(
            f"policy {policy_path}: {ON_EGRESS_FINDING_KEY} has unrecognised key(s) "
            f"{', '.join(unknown)}; expected {_DEFAULT_KEY}, {_BY_KIND_KEY} and/or {MASK_STYLE_KEY}"
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

    mask_style = _read_mask_style(raw, policy_path=policy_path)
    return EgressPolicy(default=default, by_kind=by_kind, mask_style=mask_style)
