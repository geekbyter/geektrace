import gzip
import json

import pytest

from geektrace.demo import create_demo_run
from geektrace.event import validate_jsonl_files
from geektrace.index import build_event_index
from geektrace.report import load_run
from geektrace.runstore import (
    RunBudgetExceeded,
    RunWriter,
    compact_event_parts,
    iter_event_files,
    iter_event_lines,
    load_manifest,
)


def test_demo_summary_builds_event_index(tmp_path):
    run_dir, paths = create_demo_run(tmp_path, session_id="index-demo")
    index_path = run_dir / "events" / "index.json"
    assert index_path.exists()
    assert paths["index"] == index_path

    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["schema"] == "geektrace.event-index.v1"
    assert index["total_events"] == 36
    assert sum(part["events"] for part in index["parts"]) == 36
    assert index["layers"]["crypto"] > 0
    assert index["parts"][0]["sha256"]


def test_compact_preserves_events_and_reads_gzip(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.geektrace.bench",
        profile="ai",
        backend="demo",
        session_id="compact-run",
        max_part_bytes=1024,
    )
    for index in range(8):
        writer.emit(
            "file",
            "file.write",
            args={"path": f"/data/user/0/com.geektrace.bench/{index}", "blob": "x" * 400},
        )
    writer.close()

    run_dir = tmp_path / "compact-run"
    before = [json.loads(line) for _, _, line in iter_event_lines(run_dir)]
    parts = sorted((run_dir / "events").glob("part-*.jsonl"))
    assert parts

    compacted = compact_event_parts(run_dir)
    assert len(compacted) == len(parts)
    assert all(path.suffix == ".gz" for path in compacted)
    assert not any(path.exists() for path in parts)
    with gzip.open(compacted[0], "rt", encoding="utf-8") as handle:
        assert any(handle)

    after = [json.loads(line) for _, _, line in iter_event_lines(run_dir)]
    assert [event["seq"] for event in after] == [event["seq"] for event in before]
    result = validate_jsonl_files(iter_event_files(run_dir))
    assert result.ok
    assert result.events == 8

    index = json.loads(build_event_index(run_dir).read_text(encoding="utf-8"))
    assert index["total_events"] == 8
    assert any(part["compressed"] for part in index["parts"])


def test_run_budget_stops_writes(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.geektrace.bench",
        profile="ai",
        backend="demo",
        session_id="budget-run",
        max_events=2,
    )
    writer.emit("process", "process.fork")
    writer.emit("process", "process.fork")
    with pytest.raises(RunBudgetExceeded) as excinfo:
        writer.emit("process", "process.fork")
    assert excinfo.value.budget == "max_events"
    writer.close(status="budget_exceeded")

    manifest = load_manifest(tmp_path / "budget-run")
    assert manifest["status"] == "budget_exceeded"
    assert manifest["counts"]["events"] == 2
    assert manifest["budget_exceeded"] == "max_events"
    assert len(load_run(tmp_path / "budget-run").events) == 2


def test_run_budget_bytes_writes_nothing_when_too_small(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.geektrace.bench",
        profile="ai",
        backend="demo",
        session_id="byte-run",
        max_total_bytes=1,
    )
    with pytest.raises(RunBudgetExceeded) as excinfo:
        writer.emit("process", "process.fork")
    assert excinfo.value.budget == "max_total_bytes"
    writer.close(status="budget_exceeded")
    manifest = load_manifest(tmp_path / "byte-run")
    assert manifest["counts"]["events"] == 0
    assert manifest["counts"]["bytes"] == 0
