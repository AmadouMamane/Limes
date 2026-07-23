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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

__all__ = ["inspected_content", "tool_call_arguments", "tool_call_name"]


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
