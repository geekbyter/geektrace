import json
from pathlib import Path
from typing import Any

from . import __version__
from .constants import LOG_PREFIX, MANIFEST_SCHEMA_ID, TOOL_NAME
from .event import utc_now, validate_event, validate_jsonl_files
from .report import generate_summary
from .runstore import (
    iter_event_files,
    iter_event_lines,
    load_manifest,
    save_manifest,
)
from .schema import write_schema

TARGET_STATUS_FIELDS = {
    "Name": ("name", str),
    "Pid": ("pid", int),
    "TracerPid": ("tracer_pid", int),
    "Threads": ("threads", int),
}

ARTIFACTS = (
    ("broker_log", "broker.log"),
    ("adb_log", "adb.log"),
    ("start_log", "start.log"),
    ("target_status", "target-status.txt"),
)


def _first_event_ts(run_dir: Path) -> str | None:
    for _, _, line in iter_event_lines(run_dir):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or validate_event(event):
            continue
        ts = event.get("ts")
        return ts if isinstance(ts, str) else None
    return None


def _parse_target_status(run_dir: Path) -> dict[str, Any] | None:
    path = run_dir / "target-status.txt"
    if not path.exists():
        return None
    target: dict[str, Any] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        field = TARGET_STATUS_FIELDS.get(key.strip())
        if not field:
            continue
        name, converter = field
        raw = value.strip()
        if converter is int:
            try:
                target[name] = int(raw)
            except ValueError:
                continue
        else:
            if raw:
                target[name] = raw
    return target or None


def _artifact_map(run_dir: Path) -> dict[str, str]:
    artifacts = {
        "events": "events.jsonl",
        "event_index": "events/index.json",
        "summary_md": "summary.md",
        "summary_json": "summary.json",
        "readme": "README.log.md",
        "schema": "schema/event.v1.json",
        "human_log": "logs/geektrace.log",
    }
    for key, name in ARTIFACTS:
        if (run_dir / name).exists():
            artifacts[key] = name
    return artifacts


def _device_metadata(
    existing: dict[str, Any],
    *,
    serial: str | None,
    model: str | None,
    android: str | None,
    kernel: str | None,
    abi: str | None,
) -> dict[str, Any]:
    device = dict(existing or {})
    for key, value in (
        ("serial", serial),
        ("model", model),
        ("android", android),
        ("kernel", kernel),
        ("abi", abi),
    ):
        if value:
            device[key] = value
        else:
            device.setdefault(key, None)
    return device


def import_capture(
    run_dir: Path,
    *,
    app: str,
    profile: str = "ai",
    session: str | None = None,
    serial: str | None = None,
    model: str | None = None,
    android: str | None = None,
    kernel: str | None = None,
    abi: str | None = None,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        raise FileNotFoundError(f"capture directory not found: {run_dir}")
    files = iter_event_files(run_dir)
    if not files:
        raise FileNotFoundError(
            f"no events.jsonl or events/part-*.jsonl under {run_dir}"
        )

    first_ts = _first_event_ts(run_dir)
    result = validate_jsonl_files(files)
    if result.events == 0:
        detail = f"; first error: {result.errors[0]}" if result.errors else ""
        raise ValueError(f"no valid events in {run_dir}{detail}")
    if len(result.sessions) > 1:
        raise ValueError(
            "capture mixes sessions: " + ", ".join(sorted(result.sessions))
        )
    capture_session = next(iter(result.sessions))
    if session and session != capture_session:
        raise ValueError(
            f"session mismatch: capture uses {capture_session}, --session is {session}"
        )

    existing: dict[str, Any] = {}
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        existing = load_manifest(run_dir)
        prior_session = existing.get("session")
        if prior_session and prior_session != capture_session:
            raise ValueError(
                f"manifest session {prior_session} does not match capture {capture_session}"
            )
        if existing.get("app") and existing["app"] != app:
            raise ValueError(
                f"manifest app {existing['app']} does not match --app {app}"
            )
    chosen_session = capture_session

    now = utc_now()
    total_bytes = sum(path.stat().st_size for path in files)
    target = _parse_target_status(run_dir)
    validation = {
        "files": result.files,
        "lines": result.lines,
        "valid_events": result.events,
        "errors": len(result.errors),
        "error_samples": result.errors[:10],
        "seq_duplicates": len(result.seq_duplicates),
        "seq_out_of_order": len(result.seq_out_of_order),
    }

    manifest = existing
    options = dict(manifest.get("options") or {})
    options["capture_import"] = {
        "source": "device-broker",
        "imported_at": now,
        "tool_version": __version__,
    }
    manifest.update(
        {
            "schema": MANIFEST_SCHEMA_ID,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "session": chosen_session,
            "created_at": manifest.get("created_at") or first_ts or now,
            "ended_at": now,
            "status": "completed",
            "app": app,
            "profile": profile,
            "mode": manifest.get("mode") or "cold-start",
            "backend": "ebpf",
            "transport": "adb",
            "device": _device_metadata(
                manifest.get("device") or {},
                serial=serial,
                model=model,
                android=android,
                kernel=kernel,
                abi=abi,
            ),
            "demo": False,
            "environment_modified": False,
            "options": options,
            "counts": {
                "events": result.events,
                "lines": result.lines,
                "bytes": total_bytes,
            },
            "validation": validation,
            "artifacts": _artifact_map(run_dir),
        }
    )
    if target:
        manifest["target"] = target
    else:
        manifest.pop("target", None)

    save_manifest(run_dir, manifest)
    write_schema(run_dir / "schema" / "event.v1.json")

    log_dir = run_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    with (log_dir / "geektrace.log").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            f"{now} {LOG_PREFIX} import: session={chosen_session} "
            f"events={result.events} errors={len(result.errors)} app={app}\n"
        )

    paths = generate_summary(run_dir)
    return {
        "run_dir": run_dir,
        "session": chosen_session,
        "manifest": manifest,
        "validation": validation,
        "paths": paths,
    }
