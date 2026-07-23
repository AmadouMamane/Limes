"""The derivation from JSON to inspected text is total and deterministic.

It has to be: ``Evidence.content_sha`` is the hash of *this* text, so a replay
only re-derives the same digests if the same payload always yields the same
bytes, whatever order the host wrote its object in.
"""

from __future__ import annotations

from limes.transports.mcp.payload import inspected_content, tool_call_arguments, tool_call_name


def test_string_leaves_are_taken_in_canonical_key_order():
    one = {"b": "second", "a": "first"}
    other = {"a": "first", "b": "second"}
    assert inspected_content(one) == "first\nsecond"
    assert inspected_content(one) == inspected_content(other), (
        "wire order is not stable across hosts; the derivation must be"
    )


def test_nested_structures_are_walked():
    payload = {"outer": {"z": ["deep", {"y": "deeper"}], "a": "shallow"}}
    assert inspected_content(payload) == "shallow\ndeep\ndeeper"


def test_non_string_leaves_carry_no_text_and_are_dropped():
    assert inspected_content({"n": 42, "f": 1.5, "b": True, "z": None}) == ""
    assert inspected_content({"n": 42, "s": "kept"}) == "kept"


def test_an_absent_or_empty_payload_yields_empty_content():
    assert inspected_content(None) == ""
    assert inspected_content({}) == ""
    assert inspected_content([]) == ""


def test_a_bare_string_payload_is_itself():
    assert inspected_content("just text") == "just text"


def test_the_tool_name_is_read_defensively():
    assert tool_call_name({"name": "echo"}) == "echo"
    assert tool_call_name({"name": 7}) is None
    assert tool_call_name({}) is None
    assert tool_call_name(None) is None


def test_the_arguments_are_read_as_received():
    assert tool_call_arguments({"arguments": {"a": 1}}) == {"a": 1}
    assert tool_call_arguments({}) is None
    assert tool_call_arguments(None) is None
