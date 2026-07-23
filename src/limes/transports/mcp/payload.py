"""How an MCP message becomes the ``str`` the core inspects (ADR 0005).

:func:`limes.guard.decide` inspects text. An MCP ``tools/call`` carries arbitrary
JSON. The derivation between the two is **not** an implementation detail: an
``Evidence.content_sha`` is the hash of *this* text, and a replay only re-derives
the same digests if the derivation is total and deterministic. So it is one
named function, documented here rather than inlined in the bridge:

* a **string leaf** is taken as-is;
* a **mapping** is walked in *sorted key order* — wire order is not stable across
  hosts, and evidence offsets must be;
* a **sequence** is walked in order;
* every other leaf (number, boolean, null) is dropped: it carries no text a
  content detector could read.

The pieces are joined with a newline.

What this deliberately does **not** inspect, and what the README states under
"what the proxy does not do (v0.2)": object *keys*, and non-string scalars. A
directive smuggled into a key would not be seen. That is a declared blind spot,
not a silent one.

The derivation also has to run **backwards** (ADR 0006). Evidence locates a
finding by its offsets in the derived text, and egress redaction overwrites those
offsets — in the *payload*, which is the thing that will actually be forwarded.
:func:`leaves` publishes where each string landed in the derived text, and
:func:`redact_payload` rebuilds the payload with those regions masked, walking in
exactly the same canonical order so the two views cannot drift. Object key order
is restored on the way out: the walk is sorted, the rebuilt payload is not
reordered.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import final

from limes.transports.redaction import Redaction

__all__ = [
    "Leaf",
    "inspected_content",
    "leaves",
    "redact_payload",
    "tool_call_arguments",
    "tool_call_name",
]


def _walk(node: object, out: list[str]) -> None:
    """Append every string leaf of ``node`` to ``out`` in canonical order."""
    if isinstance(node, str):
        out.append(node)
        return
    if isinstance(node, Mapping):
        for key in sorted(node, key=str):
            _walk(node[key], out)
        return
    if isinstance(node, Sequence) and not isinstance(node, str | bytes | bytearray):
        for item in node:
            _walk(item, out)


def inspected_content(payload: object) -> str:
    """Derive the text the core inspects from an arbitrary JSON-shaped payload.

    Args:
        payload: The ``arguments`` of a ``tools/call``, or the ``result`` of a
            response — any JSON-shaped value, including ``None``.

    Returns:
        The string leaves joined by newlines, in the canonical order described in
        this module's docstring. Empty when the payload carries no text.
    """
    parts: list[str] = []
    _walk(payload, parts)
    return "\n".join(parts)


@final
@dataclass(frozen=True, slots=True)
class Leaf:
    """One string of a payload, and where it landed in the derived text.

    Attributes:
        start: Offset of this string in :func:`inspected_content`'s output.
        text: The string itself, as it appears in the payload.
    """

    start: int
    text: str


def leaves(payload: object) -> tuple[Leaf, ...]:
    """Return every string leaf of ``payload`` with its offset in the derived text.

    Args:
        payload: Any JSON-shaped value.

    Returns:
        The leaves in canonical order. Joining their texts with newlines
        reproduces :func:`inspected_content` exactly — both read the same walk —
        and the offsets are the coordinates evidence spans are expressed in.
    """
    parts: list[str] = []
    _walk(payload, parts)
    found: list[Leaf] = []
    position = 0
    for part in parts:
        found.append(Leaf(start=position, text=part))
        position += len(part) + 1  # +1 for the newline the join inserts after it
    return tuple(found)


def _mask_leaf(text: str, start: int, redaction: Redaction) -> str:
    """Overwrite the parts of one leaf that fall inside a planned region."""
    end = start + len(text)
    overlapping = [
        masking for masking in redaction.maskings if masking.start < end and masking.end > start
    ]
    masked = text
    for masking in reversed(overlapping):
        local_start = max(masking.start, start) - start
        local_end = min(masking.end, end) - start
        masked = masked[:local_start] + masking.token + masked[local_end:]
    return masked


@dataclass(slots=True)
class _Cursor:
    """Where the walk currently is in the derived text."""

    position: int = 0


def _rebuild(node: object, cursor: _Cursor, redaction: Redaction) -> object:
    """Copy ``node``, masking the string leaves that fall inside a planned region."""
    if isinstance(node, str):
        start = cursor.position
        cursor.position = start + len(node) + 1
        return _mask_leaf(node, start, redaction)
    if isinstance(node, Mapping):
        masked = {key: _rebuild(node[key], cursor, redaction) for key in sorted(node, key=str)}
        # Walked sorted (offsets must be stable), rebuilt in the order the wire
        # used: the host receives its own object, minus the masked regions.
        return {key: masked[key] for key in node}
    if isinstance(node, Sequence) and not isinstance(node, str | bytes | bytearray):
        return [_rebuild(item, cursor, redaction) for item in node]
    return node


def redact_payload(payload: object, redaction: Redaction) -> object:
    """Return a copy of ``payload`` whose planned regions are replaced by tokens.

    Args:
        payload: The payload to sanitise — typically a response's ``result``.
        redaction: The masking plan, in :func:`inspected_content` coordinates.

    Returns:
        A new payload: same shape, same key order, same non-string leaves, with
        each planned region overwritten by its fixed token. Nothing else moves.
        The caller is expected to *verify* the result rather than trust it — see
        :mod:`limes.transports.mcp.bridge`, which re-derives the sanitised text
        and compares it to the plan applied to the flat content, and blocks if
        the two disagree.
    """
    return _rebuild(payload, _Cursor(), redaction)


def tool_call_name(params: Mapping[str, object] | None) -> str | None:
    """Return the tool name of a ``tools/call`` request.

    Args:
        params: The request's ``params`` object, or ``None``.

    Returns:
        The tool name, or ``None`` when absent or not a string. The name is
        recorded as an annotation on the decision record; it is not inspected.
    """
    if params is None:
        return None
    name = params.get("name")
    return name if isinstance(name, str) else None


def tool_call_arguments(params: Mapping[str, object] | None) -> object:
    """Return the ``arguments`` of a ``tools/call`` request.

    Args:
        params: The request's ``params`` object, or ``None``.

    Returns:
        The arguments value as received, or ``None`` when absent. A call with no
        arguments still gets a verdict — over empty content, which is honest:
        the detectors ran and found nothing.
    """
    if params is None:
        return None
    return params.get("arguments")
