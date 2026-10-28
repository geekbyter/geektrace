import json
from pathlib import Path

from geektrace.cli import main


def _event(seq, layer, kind, pid, tid, comm, args, policy=None):
    return {
        "schema": "geektrace.event.v1",
        "seq": seq,
        "session": "20261026-120000-poc",
        "ts": f"2026-10-26T12:00:{seq:02d}.000Z",
        "mono_ns": seq * 1_000_000,
        "layer": layer,
        "kind": kind,
        "backend": "ebpf",
        "confidence": "exact",
        "pid": pid,
        "tid": tid,
        "uid": 10234,
        "comm": comm,
        "args": args,
        "policy": policy or {"redacted": False, "truncated": False},
    }


def _capture(tmp_path: Path) -> Path:
    run_dir = tmp_path / "poc-capture"
    run_dir.mkdir()
    events = [
        _event(
            1,
            "process",
            "process.fork",
            1234,
            1234,
            "zygote64",
            {
                "ppid": 1234,
                "parent_pid": 1234,
                "child_pid": 4321,
                "parent_comm": "zygote64",
                "child_comm": "com.geektrace.bench",
            },
        ),
        _event(
            2,
            "net",
            "net.tls_write",
            4321,
            4400,
            "bench-workload",
            {"dir": "out", "len": 96, "input_len": 96, "head_hex": "474554202f"},
        ),
        _event(
            3,
            "tool",
            "tool.gap",
            4321,
            4321,
            "geektraced",
            {"reason": "probe_attach_partial", "message": "SSL_read: not found"},
            {"redacted": False, "truncated": False},
        ),
    ]
    (run_dir / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )
    (run_dir / "target-status.txt").write_text(
        "Name:\tcom.geektrace.bench\nPid:\t4321\nTracerPid:\t0\nThreads:\t18\n",
        encoding="utf-8",
    )
    (run_dir / "broker.log").write_text("session ready\n", encoding="utf-8")
    return run_dir


def _import_args(run_dir: Path) -> list[str]:
    return [
        "import",
        str(run_dir),
        "--app",
        "com.geektrace.bench",
        "--serial",
        "emulator-5554",
        "--device-model",
        "Pixel 8",
        "--android",
        "14",
        "--kernel",
        "5.15.94-android14",
        "--abi",
        "arm64-v8a",
    ]


def test_import_capture_writes_manifest_and_summary(tmp_path, capsys):
    run_dir = _capture(tmp_path)
    assert main(_import_args(run_dir)) == 0
    output = capsys.readouterr().out
    assert f"run_dir={run_dir.resolve()}" in output

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["session"] == "20261026-120000-poc"
    assert manifest["status"] == "completed"
    assert manifest["app"] == "com.geektrace.bench"
    assert manifest["backend"] == "ebpf"
    assert manifest["counts"]["events"] == 3
    assert manifest["validation"]["errors"] == 0
    assert manifest["device"]["model"] == "Pixel 8"
    assert manifest["device"]["abi"] == "arm64-v8a"
    assert manifest["target"] == {
        "name": "com.geektrace.bench",
        "pid": 4321,
        "tracer_pid": 0,
        "threads": 18,
    }
    assert manifest["artifacts"]["broker_log"] == "broker.log"
    assert manifest["artifacts"]["target_status"] == "target-status.txt"

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["session"] == "20261026-120000-poc"
    assert summary["counts"]["events"] == 3
    assert summary["network"]["tls"]["count"] == 1
    assert summary["gaps"]["count"] == 1
    assert summary["target"]["tracer_pid"] == 0

    text = (run_dir / "summary.md").read_text(encoding="utf-8")
    assert "TracerPid: `0` (sampled; no debugger at that instant)" in text
    assert "fork pid=4321 ppid=1234 comm=com.geektrace.bench" in text
    assert "观察到 1 条网络/TLS 事件" in text
    assert "Network/TLS events observed: 1" in text
    assert (run_dir / "events" / "index.json").exists()
    assert (run_dir / "schema" / "event.v1.json").exists()
    assert (run_dir / "README.log.md").exists()
    assert "geekbyter===> import:" in (
        run_dir / "logs" / "geektrace.log"
    ).read_text(encoding="utf-8")


def test_import_is_idempotent_and_keeps_metadata(tmp_path, capsys):
    run_dir = _capture(tmp_path)
    assert main(_import_args(run_dir)) == 0
    capsys.readouterr()
    assert main(["import", str(run_dir), "--app", "com.geektrace.bench"]) == 0
    capsys.readouterr()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["device"]["serial"] == "emulator-5554"
    assert manifest["device"]["model"] == "Pixel 8"
    assert manifest["counts"]["events"] == 3


def test_import_skips_invalid_lines_but_reports_them(tmp_path, capsys):
    run_dir = _capture(tmp_path)
    event = _event(
        2,
        "file",
        "file.open",
        4321,
        4321,
        "geektrace.bench",
        {"dfd": -100, "flags": "0x0", "path": "/data/user/0/com.geektrace.bench/a"},
    )
    (run_dir / "events.jsonl").write_text(
        "{broken\n" + json.dumps(event) + "\n", encoding="utf-8"
    )
    assert main(["import", str(run_dir), "--app", "com.geektrace.bench"]) == 0
    stderr = capsys.readouterr().err
    assert "errors=1" in stderr
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["events"] == 1
    assert manifest["validation"]["errors"] == 1
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert len(summary["integrity"]["parse_errors"]) == 1


def test_import_rejects_missing_events(tmp_path, capsys):
    run_dir = tmp_path / "empty"
    run_dir.mkdir()
    assert main(["import", str(run_dir), "--app", "com.geektrace.bench"]) == 5
    assert "no events.jsonl" in capsys.readouterr().err


def test_import_rejects_no_valid_events(tmp_path, capsys):
    run_dir = tmp_path / "invalid"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text("{broken\n", encoding="utf-8")
    assert main(["import", str(run_dir), "--app", "com.geektrace.bench"]) == 5
    assert "no valid events" in capsys.readouterr().err


def test_import_rejects_app_mismatch(tmp_path, capsys):
    run_dir = _capture(tmp_path)
    assert main(["import", str(run_dir), "--app", "com.geektrace.bench"]) == 0
    capsys.readouterr()
    assert main(["import", str(run_dir), "--app", "com.other.app"]) == 5
    assert "does not match" in capsys.readouterr().err


def test_import_rejects_mixed_sessions(tmp_path, capsys):
    run_dir = _capture(tmp_path)
    extra = _event(
        4,
        "file",
        "file.open",
        4321,
        4321,
        "geektrace.bench",
        {"dfd": -100, "flags": "0x0", "path": "/data/user/0/com.geektrace.bench/a"},
    )
    extra["session"] = "20261026-130000-poc"
    with (run_dir / "events.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(extra) + "\n")
    assert main(["import", str(run_dir), "--app", "com.geektrace.bench"]) == 5
    assert "mixes sessions" in capsys.readouterr().err
