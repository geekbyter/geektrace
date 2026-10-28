import json
from pathlib import Path

from .constants import BACKENDS, CONFIDENCES, LAYERS, SCHEMA_ID


CODE_LOCATION = {
    "type": "object",
    "properties": {
        "module": {"type": ["string", "null"]},
        "build_id": {"type": ["string", "null"]},
        "file_offset": {"type": ["string", "null"]},
        "symbol": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}

STACK_FRAME = {
    "type": "object",
    "properties": {
        "module": {"type": ["string", "null"]},
        "file_offset": {"type": ["string", "null"]},
        "symbol": {"type": ["string", "null"]},
        "pc": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}

POLICY = {
    "type": "object",
    "properties": {
        "redacted": {"type": "boolean"},
        "sensitive": {"type": "boolean"},
        "truncated": {"type": "boolean"},
        "sampled": {"type": "boolean"},
        "omitted_bytes": {"type": "integer", "minimum": 0},
        "payload_bytes": {
            "type": "integer",
            "minimum": 0,
            "description": "Bytes actually copied out of the target.",
        },
        "capture_status": {
            "type": "string",
            "enum": [
                "captured",
                "truncated",
                "read_failed",
                "metadata_only",
                "empty",
                "not_applicable",
                "unknown",
            ],
            "description": (
                "Distinguishes 'nothing captured' from 'not captured at all' and "
                "from 'read failed'."
            ),
        },
        "reason": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}

EVENT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://geektrace.local/schema/event.v1.json",
    "title": "geektrace event",
    "description": (
        "One JSONL line emitted by geektrace. Fields are stable across backends. "
        "Unknown extra fields are allowed for forward compatibility."
    ),
    "type": "object",
    "required": [
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
    ],
    "properties": {
        "schema": {"const": SCHEMA_ID},
        "seq": {"type": "integer", "minimum": 1, "description": "Monotonic within a session."},
        "session": {"type": "string", "minLength": 1},
        "ts": {
            "type": "string",
            "format": "date-time",
            "description": "RFC3339 UTC timestamp for pcap/logcat alignment.",
        },
        "mono_ns": {
            "type": "integer",
            "minimum": 0,
            "description": "CLOCK_MONOTONIC nanoseconds; use for ordering.",
        },
        "layer": {"type": "string", "enum": list(LAYERS)},
        "kind": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9_.-]*$",
            "description": "Dotted event name, e.g. crypto.evp_update.",
        },
        "backend": {"type": "string", "enum": list(BACKENDS)},
        "confidence": {"type": "string", "enum": list(CONFIDENCES)},
        "pid": {"type": ["integer", "null"], "minimum": 1},
        "tid": {"type": ["integer", "null"], "minimum": 1},
        "uid": {"type": ["integer", "null"], "minimum": 0},
        "comm": {"type": ["string", "null"]},
        "thread": {"type": ["string", "null"]},
        "location": {"anyOf": [CODE_LOCATION, {"type": "null"}]},
        "args": {"type": "object", "description": "Layer-specific payload."},
        "correlation": {"type": "object"},
        "stack": {"type": "array", "items": STACK_FRAME},
        "policy": POLICY,
        "evidence_ids": {"type": "array", "items": {"type": "integer", "minimum": 1}},
    },
    "additionalProperties": True,
}


def schema_json() -> str:
    return json.dumps(EVENT_SCHEMA, ensure_ascii=False, indent=2) + "\n"


def write_schema(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(schema_json(), encoding="utf-8")
