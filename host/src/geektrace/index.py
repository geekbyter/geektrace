import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .constants import EVENT_INDEX_SCHEMA_ID
from .event import utc_now
from .io_utils import open_event_text
from .runstore import iter_event_files, load_manifest


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temp, path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_event_index(run_dir: Path) -> Path:
    manifest = load_manifest(run_dir)
    parts: list[dict[str, Any]] = []
    layers: dict[str, int] = {}
    kinds: dict[str, int] = {}
    confidence: dict[str, int] = {}
    total_events = 0
    total_bytes = 0

    for path in iter_event_files(run_dir):
        part_events = 0
        part_lines = 0
        parse_errors = 0
        first_seq = None
        last_seq = None
        first_ts = None
        last_ts = None
        with open_event_text(path) as handle:
            for line in handle:
                if not line.strip():
                    continue
                part_lines += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                if not isinstance(event, dict):
                    parse_errors += 1
                    continue
                part_events += 1
                seq = event.get("seq")
                if isinstance(seq, int) and not isinstance(seq, bool):
                    first_seq = seq if first_seq is None else min(first_seq, seq)
                    last_seq = seq if last_seq is None else max(last_seq, seq)
                ts = event.get("ts")
                if isinstance(ts, str):
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
                layer = event.get("layer")
                if isinstance(layer, str):
                    layers[layer] = layers.get(layer, 0) + 1
                kind = event.get("kind")
                if isinstance(kind, str):
                    kinds[kind] = kinds.get(kind, 0) + 1
                confidence_value = event.get("confidence")
                if isinstance(confidence_value, str):
                    confidence[confidence_value] = confidence.get(confidence_value, 0) + 1

        size = path.stat().st_size
        total_events += part_events
        total_bytes += size
        parts.append(
            {
                "file": path.relative_to(run_dir).as_posix(),
                "events": part_events,
                "lines": part_lines,
                "parse_errors": parse_errors,
                "bytes_on_disk": size,
                "compressed": path.suffix == ".gz",
                "first_seq": first_seq,
                "last_seq": last_seq,
                "first_ts": first_ts,
                "last_ts": last_ts,
                "sha256": _sha256_file(path),
            }
        )

    index = {
        "schema": EVENT_INDEX_SCHEMA_ID,
        "session": manifest.get("session"),
        "generated_at": utc_now(),
        "total_events": total_events,
        "total_bytes_on_disk": total_bytes,
        "parts": parts,
        "layers": dict(sorted(layers.items())),
        "kinds": dict(sorted(kinds.items())),
        "confidence": dict(sorted(confidence.items())),
    }
    path = run_dir / "events" / "index.json"
    _write_json_atomic(path, index)
    return path
