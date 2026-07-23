"""The JSONL record is the in-process record, plus an annotation that cannot lie.

Two claims worth a witness: the emitted fields are *exactly* the fields of
``DecisionRecord`` (so the format cannot drift from the in-process transport),
and the ``mcp`` annotation sits outside the hashed core (so it cannot change a
digest).
"""

from __future__ import annotations

import dataclasses
import io
import json

from limes.detector import Direction
from limes.record import DecisionRecord, Ledger
from limes.transports.mcp.sink import JsonlSink, NullSink, open_sink, record_entry
from limes.verdict import Allow, Evidence, Witness


def _record() -> DecisionRecord:
    evidence = Evidence(
        witnesses=(Witness(detector_id="injection", detector_version="0.1.0"),),
        policy_hash="p" * 64,
        content_sha="c" * 64,
        matched_spans=(),
        observed_at="2026-07-23T00:00:00Z",
    )
    return Ledger().append(Direction.INBOUND, Allow(evidence=evidence), "session-under-test")


def test_the_entry_carries_exactly_the_in_process_record_fields_plus_the_annotation():
    record = _record()
    entry = record_entry(
        record, method="tools/call", tool="echo", request_id=1, action="forward", redaction=None
    )

    expected = {field.name for field in dataclasses.fields(DecisionRecord)} | {"mcp"}
    assert set(entry) == expected, (
        "the MCP transport must publish the same record shape as the in-process one"
    )
    for field in dataclasses.fields(DecisionRecord):
        assert entry[field.name] == getattr(record, field.name)


def test_the_annotation_cannot_change_a_digest():
    record = _record()
    entry = record_entry(
        record, method="tools/call", tool="echo", request_id=1, action="forward", redaction=None
    )
    assert entry["digest"] == record.digest
    assert entry["mcp"] == {
        "method": "tools/call",
        "tool": "echo",
        "request_id": 1,
        "action": "forward",
        "redaction": None,
    }


def test_one_canonical_line_per_record_flushed():
    stream = io.StringIO()
    sink = JsonlSink(stream)
    sink.emit(
        record_entry(
            _record(),
            method="tools/call",
            tool=None,
            request_id="x",
            action="block",
            redaction=None,
        )
    )
    sink.emit(
        record_entry(
            _record(),
            method="tools/call",
            tool=None,
            request_id="y",
            action="block",
            redaction=None,
        )
    )

    lines = stream.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["mcp"]["request_id"] == "x"
    assert lines[0] == json.dumps(
        json.loads(lines[0]), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )


def test_the_default_sink_is_stderr_because_stdout_is_the_hosts_channel():
    import sys

    sink = open_sink(None)
    assert isinstance(sink, JsonlSink)
    assert sink._stream is sys.stderr


def test_a_record_file_is_appended_to(tmp_path):
    target = tmp_path / "decisions.jsonl"
    for request_id in (1, 2):
        sink = open_sink(target)
        sink.emit(
            record_entry(
                _record(),
                method="tools/call",
                tool="echo",
                request_id=request_id,
                action="forward",
                redaction=None,
            )
        )
        sink.close()
    assert len(target.read_text(encoding="utf-8").splitlines()) == 2


def test_the_null_sink_drops_and_closes_quietly():
    sink = NullSink()
    sink.emit({"anything": True})
    sink.close()
