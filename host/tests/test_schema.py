import json
from pathlib import Path

from geektrace.schema import EVENT_SCHEMA, schema_json


def test_schema_has_required_fields():
    required = set(EVENT_SCHEMA["required"])
    assert {
        "schema",
        "seq",
        "session",
        "ts",
        "mono_ns",
        "layer",
        "kind",
        "backend",
        "confidence",
        "args",
        "policy",
    } <= required


def test_committed_schema_file_is_current():
    root = Path(__file__).resolve().parents[2]
    committed = root / "schema" / "geektrace-event.v1.schema.json"
    assert committed.exists()
    assert json.loads(committed.read_text(encoding="utf-8")) == json.loads(
        schema_json()
    )
