import gzip
import hashlib
import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import __version__
from .constants import LOG_PREFIX, MANIFEST_SCHEMA_ID, TOOL_NAME
from .event import assert_valid, new_event, utc_now
from .io_utils import open_event_text
from .schema import write_schema

DEFAULT_MAX_PART_BYTES = 256 * 1024 * 1024


class RunBudgetExceeded(RuntimeError):
    def __init__(self, budget: str, limit: int) -> None:
        super().__init__(f"run budget exceeded: {budget}={limit}")
        self.budget = budget
        self.limit = limit


def new_session_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    return f"{moment.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temp, path)


def load_manifest(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found in {run_dir}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def save_manifest(run_dir: Path, manifest: dict[str, Any]) -> None:
    _write_json_atomic(run_dir / "manifest.json", manifest)


def iter_event_files(run_dir: Path) -> list[Path]:
    files: list[Path] = []
    primary = run_dir / "events.jsonl"
    if primary.exists():
        files.append(primary)
    parts = run_dir / "events"
    if parts.is_dir():
        candidates: list[Path] = []
        for path in sorted(parts.glob("part-*.jsonl*")):
            if not path.name.endswith((".jsonl", ".jsonl.gz")):
                continue
            if path.name.endswith(".gz") and path.with_suffix("").exists():
                continue
            candidates.append(path)
        files.extend(sorted(candidates, key=lambda item: item.name))
    return files


def iter_event_lines(run_dir: Path) -> Iterator[tuple[Path, int, str]]:
    for path in iter_event_files(run_dir):
        with open_event_text(path) as handle:
            for line_no, line in enumerate(handle, 1):
                if line.strip():
                    yield path, line_no, line


class RunWriter:
    def __init__(
        self,
        runs_root: Path,
        *,
        app: str,
        profile: str,
        backend: str = "ebpf",
        transport: str = "adb",
        mode: str = "cold-start",
        serial: str | None = None,
        demo: bool = False,
        options: dict[str, Any] | None = None,
        session_id: str | None = None,
        max_part_bytes: int = DEFAULT_MAX_PART_BYTES,
        max_events: int = 0,
        max_total_bytes: int = 0,
    ) -> None:
        self.session = session_id or new_session_id()
        self.run_dir = runs_root / self.session
        if self.run_dir.exists():
            raise FileExistsError(f"run directory already exists: {self.run_dir}")
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "logs").mkdir()
        self.app = app
        self.profile = profile
        self.backend = backend
        self.demo = demo
        self.max_part_bytes = max(1024, int(max_part_bytes))
        self.max_events = max(0, int(max_events))
        self.max_total_bytes = max(0, int(max_total_bytes))
        self.budget_exceeded: str | None = None
        self._event_file = None
        self._current_bytes = 0
        self._total_bytes = 0
        self._part_index = 1
        self._event_count = 0
        self._next_seq = 1
        self._closed = False
        self._open_events()

        self.manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA_ID,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "session": self.session,
            "created_at": utc_now(),
            "ended_at": None,
            "status": "planned" if options and options.get("dry_run") else "running",
            "app": app,
            "profile": profile,
            "mode": mode,
            "backend": backend,
            "transport": transport,
            "device": {"serial": serial, "model": None, "android": None, "kernel": None},
            "demo": demo,
            "environment_modified": False,
            "options": options or {},
            "budget": {
                "max_part_bytes": self.max_part_bytes,
                "max_events": self.max_events,
                "max_total_bytes": self.max_total_bytes,
            },
            "counts": {"events": 0, "bytes": 0},
            "artifacts": {
                "events": "events.jsonl",
                "event_index": "events/index.json",
                "summary_md": "summary.md",
                "summary_json": "summary.json",
                "readme": "README.log.md",
                "schema": "schema/event.v1.json",
                "human_log": "logs/geektrace.log",
            },
        }
        _write_json_atomic(self.run_dir / "manifest.json", self.manifest)
        write_schema(self.run_dir / "schema" / "event.v1.json")
        self.log(
            f"session {self.session} created app={app} profile={profile} "
            f"backend={backend} demo={str(demo).lower()}"
        )

    def _open_events(self) -> None:
        if self._part_index == 1:
            path = self.run_dir / "events.jsonl"
        else:
            path = self.run_dir / "events" / f"part-{self._part_index:05d}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        self._event_file = path.open("a", encoding="utf-8", newline="\n")
        self._current_bytes = path.stat().st_size if path.exists() else 0

    def _rotate_if_needed(self, line: str) -> None:
        encoded = len(line.encode("utf-8"))
        if self._current_bytes > 0 and self._current_bytes + encoded > self.max_part_bytes:
            assert self._event_file is not None
            self._event_file.flush()
            self._event_file.close()
            self._part_index += 1
            self._open_events()

    def emit(self, layer: str, kind: str, **fields: Any) -> dict[str, Any]:
        event = new_event(
            session=self.session,
            seq=self._next_seq,
            layer=layer,
            kind=kind,
            backend=fields.pop("backend", self.backend),
            **fields,
        )
        return self.write(event)

    def write(self, event: dict[str, Any]) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("run writer is closed")
        assert_valid(event)
        if event.get("session") != self.session:
            raise ValueError("event session does not match run session")
        seq = event["seq"]
        if seq < self._next_seq:
            raise ValueError(f"seq {seq} is not greater than {self._next_seq - 1}")
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        encoded = len(line.encode("utf-8"))
        if self.max_events and self._event_count >= self.max_events:
            self.budget_exceeded = "max_events"
            raise RunBudgetExceeded("max_events", self.max_events)
        if self.max_total_bytes and self._total_bytes + encoded > self.max_total_bytes:
            self.budget_exceeded = "max_total_bytes"
            raise RunBudgetExceeded("max_total_bytes", self.max_total_bytes)
        self._next_seq = seq + 1
        self._rotate_if_needed(line)
        assert self._event_file is not None
        self._event_file.write(line)
        self._event_file.flush()
        self._current_bytes += encoded
        self._total_bytes += encoded
        self._event_count += 1
        self.manifest["counts"]["events"] = self._event_count
        self.manifest["counts"]["bytes"] = self._total_bytes
        return event

    def update_manifest(self, **fields: Any) -> None:
        self.manifest.update(fields)
        _write_json_atomic(self.run_dir / "manifest.json", self.manifest)

    def set_device(self, device: dict[str, Any]) -> None:
        self.manifest["device"] = device
        _write_json_atomic(self.run_dir / "manifest.json", self.manifest)

    def log(self, message: str) -> None:
        timestamp = utc_now()
        line = f"{timestamp} {LOG_PREFIX} {message}\n"
        with (self.run_dir / "logs" / "geektrace.log").open(
            "a", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(line)

    def close(self, status: str = "completed") -> None:
        if self._closed:
            return
        if self._event_file is not None:
            self._event_file.flush()
            self._event_file.close()
        self._closed = True
        self.manifest["status"] = status
        self.manifest["ended_at"] = utc_now()
        self.manifest["counts"]["events"] = self._event_count
        self.manifest["counts"]["bytes"] = self._total_bytes
        if self.budget_exceeded:
            self.manifest["budget_exceeded"] = self.budget_exceeded
        _write_json_atomic(self.run_dir / "manifest.json", self.manifest)
        self.log(f"session {self.session} closed status={status} events={self._event_count}")

    def __enter__(self) -> "RunWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        status = "failed" if exc_type else "completed"
        self.close(status=status)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_gzip_content(path: Path) -> str:
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compact_event_parts(run_dir: Path) -> list[Path]:
    events_dir = run_dir / "events"
    if not events_dir.is_dir():
        return []
    compacted: list[Path] = []
    for source in sorted(events_dir.glob("part-*.jsonl")):
        target = source.with_name(source.name + ".gz")
        if target.exists():
            raise FileExistsError(f"compressed part already exists: {target}")
        temp = target.with_name(target.name + ".tmp")
        if temp.exists():
            temp.unlink()
        with source.open("rb") as src, gzip.open(temp, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        if _sha256_file(source) != _sha256_gzip_content(temp):
            temp.unlink(missing_ok=True)
            raise OSError(f"compression verification failed for {source}")
        os.replace(temp, target)
        source.unlink()
        compacted.append(target)
    return compacted
