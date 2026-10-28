import json

import pytest

from geektrace.event import new_event
from geektrace.report import load_run
from geektrace.runstore import RunWriter, iter_event_files, load_manifest


def test_run_writer_creates_manifest_and_reads_events(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.example.bench",
        profile="ai",
        backend="demo",
        demo=True,
        session_id="test-run",
        max_part_bytes=10_000,
    )
    writer.emit("process", "process.fork", pid=42, args={"ppid": 1})
    writer.emit("crypto", "crypto.evp_update", args={"alg": "AES-256-GCM"})
    writer.close()

    assert (tmp_path / "test-run" / "manifest.json").exists()
    assert (tmp_path / "test-run" / "events.jsonl").exists()
    assert (tmp_path / "test-run" / "schema" / "event.v1.json").exists()
    manifest = load_manifest(tmp_path / "test-run")
    assert manifest["status"] == "completed"
    assert manifest["counts"]["events"] == 2
    data = load_run(tmp_path / "test-run")
    assert len(data.events) == 2
    assert data.events[0]["seq"] == 1
    assert data.events[1]["seq"] == 2


def test_run_writer_rotates_parts(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.example.bench",
        profile="ai",
        backend="demo",
        session_id="rotate-run",
        max_part_bytes=1024,
    )
    for index in range(6):
        writer.emit("file", "file.write", args={"path": f"/x/{index}", "blob": "x" * 400})
    writer.close()

    files = iter_event_files(tmp_path / "rotate-run")
    assert len(files) > 1
    events = []
    for path in files:
        events.extend(
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        )
    assert [event["seq"] for event in events] == list(range(1, 7))


def test_run_writer_rejects_out_of_order_seq(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.example.bench",
        profile="ai",
        session_id="seq-run",
    )
    writer.emit("process", "process.fork")
    event = new_event(
        session="seq-run",
        seq=1,
        layer="process",
        kind="process.fork",
        backend="ebpf",
    )
    with pytest.raises(ValueError):
        writer.write(event)
    writer.close()


def test_run_writer_rejects_session_mismatch(tmp_path):
    writer = RunWriter(
        tmp_path,
        app="com.example.bench",
        profile="ai",
        session_id="session-run",
    )
    event = new_event(
        session="other",
        seq=1,
        layer="process",
        kind="process.fork",
        backend="ebpf",
    )
    with pytest.raises(ValueError):
        writer.write(event)
    writer.close()
