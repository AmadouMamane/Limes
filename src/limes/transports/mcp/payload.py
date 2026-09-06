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

**What the walk cannot read, it names (ADR 0028).** An MCP content block whose
``type`` is ``image`` or ``audio`` carries its bytes base64-encoded under
``data``; a binary resource — embedded in a result, or returned by
``resources/read`` — carries them under ``blob``. Those strings are not text:
no rule reads a picture, and a picture is exactly where a directive can hide
from a text guard while the host's model reads it off the pixels. Until ADR 0028
the walk swept the base64 as if it were prose, found nothing in it, and let the
result pass as inspected. Now :func:`derive` leaves those strings out of the
text and returns, beside it, one plain sentence per block it could not read —
the transport hands them to the core as declared blind spots, and the verdict
says so. The block's other fields (its media type, its URI, a name) are text
and are read as before.

What this deliberately does **not** inspect, and what the README states under
"what the proxy does not do (v0.2)": object *keys*, and non-string scalars. A
directive smuggled into a key would not be seen. That is a declared blind spot,
not a silent one.

The derivation also has to run **backwards** (ADR 0006). Evidence locates a
finding by its offsets in the derived text, and egress redaction overwrites those
offsets — in the *payload*, which is the thing that will actually be forwarded.
:func:`leaves` publishes where each string landed in the derived text, and
:func:`redact_payload` rebuilds the payload with those regions masked, walking in
exactly the same canonical order so the two views cannot drift — a binary block
is left out on both sides, and copied through untouched. Object key order is
restored on the way out: the walk is sorted, the rebuilt payload is not
reordered.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, final

from limes.transports.redaction import Redaction

__all__ = [
    "Derived",
    "Leaf",
    "derive",
    "inspected_content",
    "leaves",
    "redact_payload",
    "tool_call_arguments",
    "tool_call_name",
]

#: MCP content-block types whose ``data`` field is base64, not text.
_BINARY_BLOCK_TYPES: Final = frozenset({"image", "audio"})
#: The field a binary resource's base64 lives under (embedded, or ``resources/read``).
_BLOB: Final = "blob"
#: The field a binary content block's base64 lives under.
_DATA: Final = "data"


@final
@dataclass(frozen=True, slots=True)
class Derived:
    """What the walk made of a payload (ADR 0028).

    Attributes:
        text: The string leaves the rules can read, joined by newlines in the
            canonical order — the content the core inspects.
        unreadable: One sentence per binary block the walk left out of ``text``,
            in walk order. Empty when the payload carried only text.
    """

    text: str
    unreadable: tuple[str, ...]


def _binary_keys(node: Mapping[Any, object]) -> frozenset[str]:
    """The keys of ``node`` whose string values are encoded bytes, not text."""
    keys: set[str] = set()
    if isinstance(node.get(_BLOB), str):
        keys.add(_BLOB)
    if node.get("type") in _BINARY_BLOCK_TYPES and isinstance(node.get(_DATA), str):
        keys.add(_DATA)
    return frozenset(keys)


def _describe(node: Mapping[Any, object], key: str) -> str:
    """One plain sentence naming a binary block the guard cannot read."""
    encoded = node[key]
    size = len(encoded) if isinstance(encoded, str) else 0
    media = node.get("mimeType")
    media_type = media if isinstance(media, str) and media else "unknown media type"
    if key == _BLOB:
        uri = node.get("uri")
        where = f" at {uri}" if isinstance(uri, str) and uri else ""
        kind = f"a binary resource{where}"
    else:
        kind = f"an {node['type']} block"
    return (
        f"{kind} ({media_type}, {size} characters of base64) was not inspected: the guard "
        "reads text, and this is not text"
    )


def _walk(node: object, out: list[str], unreadable: list[str]) -> None:
    """Append every readable string leaf of ``node`` to ``out`` in canonical order."""
    if isinstance(node, str):
        out.append(node)
        return
    if isinstance(node, Mapping):
        binary = _binary_keys(node)
        for key in sorted(node, key=str):
            if key in binary:
                unreadable.append(_describe(node, key))
                continue
            _walk(node[key], out, unreadable)
        return
    if isinstance(node, Sequence) and not isinstance(node, str | bytes | bytearray):
        for item in node:
            _walk(item, out, unreadable)


def derive(payload: object) -> Derived:
    """Derive the text the core inspects, and name what could not be derived.

    Args:
        payload: The ``arguments`` of a ``tools/call``, the ``params`` of a
            request, or the ``result`` of a response — any JSON-shaped value,
            including ``None``.

    Returns:
        The readable string leaves joined by newlines, in the canonical order
        described in this module's docstring, and one sentence per binary block
        left out of them (ADR 0028).
    """
    parts: list[str] = []
    unreadable: list[str] = []
    _walk(payload, parts, unreadable)
    return Derived(text="\n".join(parts), unreadable=tuple(unreadable))


def inspected_content(payload: object) -> str:
    """Derive the text the core inspects from an arbitrary JSON-shaped payload.

    The text half of :func:`derive`, kept under the name the evidence offsets
    are expressed in.

    Args:
        payload: Any JSON-shaped value, including ``None``.

    Returns:
        The readable string leaves joined by newlines. Empty when the payload
        carries no text.
    """
    return derive(payload).text


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
    """Return every readable string leaf of ``payload`` with its offset in the derived text.

    Args:
        payload: Any JSON-shaped value.

    Returns:
        The leaves in canonical order. Joining their texts with newlines
        reproduces :func:`inspected_content` exactly — both read the same walk —
        and the offsets are the coordinates evidence spans are expressed in.
    """
    parts: list[str] = []
    unreadable: list[str] = []
    _walk(payload, parts, unreadable)
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
        # The same rendering the flat `apply_masking` uses, over the same original
        # bytes: a masking that sits inside this leaf sees its full original here,
        # and one that straddles two leaves renders a partial — which the bridge's
        # re-derivation check then catches, and blocks.
        replacement = masking.render(masked[local_start:local_end])
        masked = masked[:local_start] + replacement + masked[local_end:]
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
        binary = _binary_keys(node)
        masked = {
            # A binary block was never in the derived text, so it holds no
            # offset to mask and moves the cursor by nothing: copied through.
            key: node[key] if key in binary else _rebuild(node[key], cursor, redaction)
            for key in sorted(node, key=str)
        }
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
