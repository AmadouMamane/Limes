"""Where the proxy's decision records go (ADR 0005).

**stderr by default — never stdout.** In a stdio transport, stdout *is* the
JSON-RPC channel to the host: one JSONL record written there desynchronises the
very session it was meant to document. The v0.2 design note proposed "stdout
JSONL by default"; that would corrupt the protocol it observes, so the default is
stderr and the deviation is recorded in ADR 0005. ``--record FILE`` appends to a
file instead.

The emitted fields are **exactly** those of :class:`limes.record.DecisionRecord`
— the same record the in-process transport produces — plus one ``mcp``
annotation naming the message the decision was about. The annotation sits outside
the hashed core, so it cannot change a digest; a test asserts both halves of that
(the field names match ``DecisionRecord``, and the digest is the ledger's).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Protocol, TextIO, final, runtime_checkable

from limes.record import DecisionRecord

__all__ = ["JsonlSink", "NullSink", "RecordSink", "open_sink", "record_entry"]


@runtime_checkable
class RecordSink(Protocol):
    """Somewhere a decision record can be written."""

    def emit(self, entry: Mapping[str, object]) -> None:
        """Write one record."""
        ...

    def close(self) -> None:
        """Release whatever this sink owns."""
        ...


@final
class JsonlSink:
    """One canonical JSON object per line, flushed on every record."""

    def __init__(self, stream: TextIO, *, owns_stream: bool = False) -> None:
        """Write records to ``stream``, closing it on :meth:`close` if owned."""
        self._stream = stream
        self._owns_stream = owns_stream

    def emit(self, entry: Mapping[str, object]) -> None:
        """Write ``entry`` as one canonical JSON line and flush it.

        Args:
            entry: The record to write.
        """
        line = json.dumps(dict(entry), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self._stream.write(line + "\n")
        self._stream.flush()

    def close(self) -> None:
        """Close the underlying stream, if this sink opened it."""
        if self._owns_stream:
            self._stream.close()


@final
class NullSink:
    """A sink that drops records — for tests and embedders that keep the ledger."""

    def emit(self, entry: Mapping[str, object]) -> None:
        """Drop ``entry``."""

    def close(self) -> None:
        """Nothing to release."""


def open_sink(record_path: Path | None) -> RecordSink:
    """Open the sink a :class:`~limes.transports.mcp.config.ProxyConfig` asks for.

    Args:
        record_path: A file to append records to, or ``None`` for stderr.

    Returns:
        The sink. Never stdout: that is the host's JSON-RPC channel.
    """
    if record_path is None:
        return JsonlSink(sys.stderr)
    return JsonlSink(record_path.open("a", encoding="utf-8"), owns_stream=True)


def record_entry(
    record: DecisionRecord,
    *,
    method: str,
    tool: str | None,
    request_id: str | int | None,
    action: str,
    redaction: Mapping[str, object] | None,
) -> dict[str, object]:
    """Build the JSONL entry for one decision.

    Args:
        record: The chain record, emitted field for field.
        method: The MCP method the decision was about, e.g. ``"tools/call"``.
        tool: The tool name, when the message named one.
        request_id: The JSON-RPC id the decision belongs to.
        action: ``"forward"``, ``"redact"`` or ``"block"``.
        redaction: What was masked — kinds, offsets and tokens, never the masked
            text (ADR 0006). ``None`` when nothing was. It is required rather
            than defaulted: a forward that silently omitted it would read, in the
            journal, exactly like a forward that masked nothing.

    Returns:
        The record's own fields plus an ``mcp`` annotation. The annotation is
        *not* part of the hashed core and cannot alter a digest.
    """
    entry: dict[str, object] = dict(asdict(record))
    entry["mcp"] = {
        "method": method,
        "tool": tool,
        "request_id": request_id,
        "action": action,
        "redaction": None if redaction is None else dict(redaction),
    }
    return entry
