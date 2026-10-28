import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .constants import BACKENDS, CONFIDENCES, LAYERS, SCHEMA_ID
from .io_utils import open_event_text

KIND_RE = re.compile(r"^[a-z][a-z0-9_.-]*$")


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def default_policy(**overrides: Any) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "redacted": False,
        "sensitive": False,
        "truncated": False,
        "sampled": False,
        "omitted_bytes": 0,
    }
    policy.update(overrides)
    return policy


def new_event(
    *,
    session: str,
    seq: int,
    layer: str,
    kind: str,
    backend: str,
    confidence: str = "exact",
    ts: str | None = None,
    mono_ns: int = 0,
    pid: int | None = None,
    tid: int | None = None,
    uid: int | None = None,
    comm: str | None = None,
    thread: str | None = None,
    location: dict[str, Any] | None = None,
    args: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
    stack: list[dict[str, Any]] | None = None,
    policy: dict[str, Any] | None = None,
    evidence_ids: list[int] | None = None,
) -> dict[str, Any]:
    normalized_location = None
    if location is not None:
        normalized_location = {
            "module": location.get("module"),
            "build_id": location.get("build_id"),
            "file_offset": location.get("file_offset"),
            "symbol": location.get("symbol"),
        }
        for key, value in location.items():
            normalized_location.setdefault(key, value)

    return {
        "schema": SCHEMA_ID,
        "seq": seq,
        "session": session,
        "ts": ts or utc_now(),
        "mono_ns": mono_ns,
        "layer": layer,
        "kind": kind,
        "backend": backend,
        "confidence": confidence,
        "pid": pid,
        "tid": tid,
        "uid": uid,
        "comm": comm,
        "thread": thread,
        "location": normalized_location,
        "args": args or {},
        "correlation": correlation or {},
        "stack": stack or [],
        "policy": policy or default_policy(),
        "evidence_ids": evidence_ids or [],
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _check_code_location(location: Any, errors: list[str], prefix: str) -> None:
    if location is None:
        return
    if not isinstance(location, dict):
        errors.append(f"{prefix} must be an object or null")
        return
    for key in ("module", "build_id", "file_offset", "symbol"):
        value = location.get(key)
        if value is not None and not isinstance(value, str):
            errors.append(f"{prefix}.{key} must be a string or null")


CAPTURE_STATUSES = (
    "captured",
    "truncated",
    "read_failed",
    "metadata_only",
    "empty",
    "not_applicable",
    "unknown",
)


def _check_policy(policy: Any, errors: list[str]) -> None:
    if not isinstance(policy, dict):
        errors.append("policy must be an object")
        return
    for key in ("redacted", "sensitive", "truncated", "sampled"):
        value = policy.get(key)
        if value is not None and not isinstance(value, bool):
            errors.append(f"policy.{key} must be a boolean")
    omitted = policy.get("omitted_bytes")
    if omitted is not None and (not _is_int(omitted) or omitted < 0):
        errors.append("policy.omitted_bytes must be a non-negative integer")
    payload_bytes = policy.get("payload_bytes")
    if payload_bytes is not None and (
        not _is_int(payload_bytes) or payload_bytes < 0
    ):
        errors.append("policy.payload_bytes must be a non-negative integer")
    status = policy.get("capture_status")
    if status is not None and (
        not isinstance(status, str) or status not in CAPTURE_STATUSES
    ):
        errors.append(
            "policy.capture_status must be one of " + ", ".join(CAPTURE_STATUSES)
        )
    reason = policy.get("reason")
    if reason is not None and not isinstance(reason, str):
        errors.append("policy.reason must be a string or null")


def validate_event(event: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(event, dict):
        return ["event must be a JSON object"]

    for key in (
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
    ):
        if key not in event:
            errors.append(f"missing required field: {key}")
    if errors:
        return errors

    if event.get("schema") != SCHEMA_ID:
        errors.append(f"schema must be {SCHEMA_ID}")
    if not _is_int(event.get("seq")) or event["seq"] < 1:
        errors.append("seq must be an integer >= 1")
    if not isinstance(event.get("session"), str) or not event["session"]:
        errors.append("session must be a non-empty string")
    if not _valid_timestamp(event.get("ts")):
        errors.append("ts must be an RFC3339 timestamp with timezone")
    if not _is_int(event.get("mono_ns")) or event["mono_ns"] < 0:
        errors.append("mono_ns must be a non-negative integer")
    if event.get("layer") not in LAYERS:
        errors.append(f"layer must be one of {', '.join(LAYERS)}")
    if not isinstance(event.get("kind"), str) or not KIND_RE.match(event["kind"]):
        errors.append("kind must match ^[a-z][a-z0-9_.-]*$")
    if event.get("backend") not in BACKENDS:
        errors.append(f"backend must be one of {', '.join(BACKENDS)}")
    if event.get("confidence") not in CONFIDENCES:
        errors.append(f"confidence must be one of {', '.join(CONFIDENCES)}")

    for key in ("pid", "tid"):
        value = event.get(key)
        if value is not None and (not _is_int(value) or value < 1):
            errors.append(f"{key} must be a positive integer or null")
    uid = event.get("uid")
    if uid is not None and (not _is_int(uid) or uid < 0):
        errors.append("uid must be a non-negative integer or null")
    for key in ("comm", "thread"):
        value = event.get(key)
        if value is not None and not isinstance(value, str):
            errors.append(f"{key} must be a string or null")

    _check_code_location(event.get("location"), errors, "location")
    if not isinstance(event.get("args"), dict):
        errors.append("args must be an object")
    if not isinstance(event.get("correlation", {}), dict):
        errors.append("correlation must be an object")
    if not isinstance(event.get("stack", []), list):
        errors.append("stack must be an array")
    else:
        for index, frame in enumerate(event.get("stack", [])):
            if not isinstance(frame, dict):
                errors.append(f"stack[{index}] must be an object")
    _check_policy(event.get("policy"), errors)

    evidence_ids = event.get("evidence_ids", [])
    if not isinstance(evidence_ids, list) or any(
        not _is_int(item) or item < 1 for item in evidence_ids
    ):
        errors.append("evidence_ids must be an array of positive integers")

    return errors


def assert_valid(event: Any) -> None:
    errors = validate_event(event)
    if errors:
        raise ValueError("; ".join(errors))


@dataclass
class ValidationResult:
    files: int = 0
    lines: int = 0
    events: int = 0
    errors: list[str] = field(default_factory=list)
    seq_duplicates: list[int] = field(default_factory=list)
    seq_out_of_order: list[str] = field(default_factory=list)
    sessions: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        # Duplicate or out-of-order sequence numbers mean the capture is not
        # a faithful event stream, so they must fail the validation too.
        return (
            not self.errors
            and not self.seq_duplicates
            and not self.seq_out_of_order
        )


def validate_jsonl_files(paths: Iterable[Path]) -> ValidationResult:
    result = ValidationResult()
    seen: set[int] = set()
    last_seq = 0
    for path in paths:
        result.files += 1
        with open_event_text(path) as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                result.lines += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    result.errors.append(f"{path}:{line_no}: invalid JSON: {exc.msg}")
                    continue
                errors = validate_event(event)
                for error in errors:
                    result.errors.append(f"{path}:{line_no}: {error}")
                if errors:
                    continue
                result.events += 1
                result.sessions.add(event["session"])
                seq = event["seq"]
                if seq in seen:
                    result.seq_duplicates.append(seq)
                if seq <= last_seq:
                    result.seq_out_of_order.append(
                        f"{path}:{line_no}: seq {seq} after {last_seq}"
                    )
                seen.add(seq)
                last_seq = max(last_seq, seq)
    return result
