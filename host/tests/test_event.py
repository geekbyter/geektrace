import json
from pathlib import Path

import pytest

from geektrace.event import (
    new_event,
    validate_event,
    validate_jsonl_files,
)


def make_event(**overrides):
    fields = {
        "session": "test-session",
        "seq": 1,
        "layer": "crypto",
        "kind": "crypto.evp_update",
        "backend": "demo",
        "args": {"alg": "AES-256-GCM"},
    }
    fields.update(overrides)
    return new_event(**fields)


def test_new_event_has_stable_shape():
    event = make_event()
    assert event["schema"] == "geektrace.event.v1"
    assert event["policy"]["redacted"] is False
    assert event["policy"]["omitted_bytes"] == 0
    assert event["stack"] == []
    assert event["correlation"] == {}
    assert validate_event(event) == []


def test_invalid_layer_and_kind():
    event = make_event(layer="nope")
    assert any("layer" in error for error in validate_event(event))
    event = make_event(kind="Crypto Bad")
    assert any("kind" in error for error in validate_event(event))


def test_invalid_seq_and_timestamp():
    event = make_event(seq=0)
    assert any("seq" in error for error in validate_event(event))
    event = make_event(ts="not-a-time")
    assert any("ts" in error for error in validate_event(event))
    event = make_event(ts="2026-10-26T15:30:00")
    assert any("timezone" in error for error in validate_event(event))


def test_policy_and_evidence_validation():
    event = make_event(policy={"omitted_bytes": -1})
    assert any("omitted_bytes" in error for error in validate_event(event))
    event = make_event(evidence_ids=[0, "x"])
    assert any("evidence_ids" in error for error in validate_event(event))


def test_validate_jsonl_files(tmp_path):
    good = make_event(seq=1)
    bad = make_event(seq=2)
    bad["backend"] = "unknown"
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps(good) + "\n" + json.dumps(bad) + "\n" + "{broken\n",
        encoding="utf-8",
    )
    result = validate_jsonl_files([path])
    assert result.lines == 3
    assert result.events == 1
    assert len(result.errors) == 2
    assert not result.ok


def test_validate_jsonl_detects_duplicate_and_order(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(make_event(seq=1)),
                json.dumps(make_event(seq=1)),
                json.dumps(make_event(seq=0)),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = validate_jsonl_files([path])
    assert 1 in result.seq_duplicates
    assert result.seq_out_of_order


def test_capture_status_and_payload_bytes_validation():
    event = make_event(policy={"capture_status": "captured", "payload_bytes": 12})
    assert validate_event(event) == []
    event = make_event(policy={"capture_status": "bogus"})
    assert any("capture_status" in error for error in validate_event(event))
    event = make_event(policy={"payload_bytes": -1})
    assert any("payload_bytes" in error for error in validate_event(event))


def test_validation_result_fails_on_duplicate_seq(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(json.dumps(make_event(seq=1)) for _ in range(2)) + "\n",
        encoding="utf-8",
    )
    result = validate_jsonl_files([path])
    assert result.seq_duplicates
    assert not result.ok


def test_location_and_stack_validation():
    event = make_event(
        location={"module": "libcrypto.so", "file_offset": "0x1"},
        stack=[{"module": "libcrypto.so", "file_offset": "0x2"}],
    )
    assert validate_event(event) == []
    event["location"] = {"module": 5}
    assert any("location.module" in error for error in validate_event(event))
    event = make_event()
    event["stack"] = ["bad"]
    assert any("stack[0]" in error for error in validate_event(event))
