import base64
import json
from pathlib import Path

from geektrace.demo import create_demo_run
from geektrace.report import build_summary, generate_summary, load_run


def test_demo_run_produces_full_summary(tmp_path):
    run_dir, paths = create_demo_run(tmp_path, session_id="demo-report")
    assert Path(paths["summary_md"]).exists()
    assert Path(paths["summary_json"]).exists()
    assert Path(paths["readme"]).exists()

    data = load_run(run_dir)
    assert len(data.events) == 36
    summary = build_summary(data)
    assert summary["demo"] is True
    assert summary["counts"]["events"] == 36
    assert "AES-256-GCM" in summary["crypto"]["algorithms"]
    assert "ECDSA-with-SHA256" in summary["crypto"]["algorithms"]
    assert "api.example.com" in summary["network"]["hosts"]
    assert len(summary["detections"]) == 4
    assert summary["gaps"]["count"] == 1
    assert summary["drops"]["count"] == 1
    assert summary["integrity"]["parse_errors"] == []
    assert summary["integrity"]["validation_errors"] == []

    text = Path(paths["summary_md"]).read_text(encoding="utf-8")
    assert "DEMO DATA" in text
    assert "Crypto Ledger" in text
    assert "Detection Findings" in text
    assert "MainActivity.onCreate is AOT-compiled" in text


def test_summary_does_not_duplicate_raw_secrets(tmp_path):
    run_dir, paths = create_demo_run(tmp_path, session_id="demo-secrets")
    text = Path(paths["summary_json"]).read_text(encoding="utf-8")
    raw_key = base64.b64encode(bytes(range(32))).decode("ascii")
    assert raw_key not in text
    assert "<see events.jsonl>" in text

    events_text = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "key_b64" in events_text
    assert raw_key in events_text


def test_footprint_flags_shared_library_breakpoints(tmp_path):
    run_dir = tmp_path / "footprint"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "session": "footprint",
                "app": "com.example.app",
                "profile": "ai",
                "mode": "cold-start",
                "backend": "ebpf",
                "status": "completed",
            }
        ),
        encoding="utf-8",
    )
    capability = {
        "schema": "geektrace.event.v1",
        "seq": 1,
        "session": "footprint",
        "ts": "2026-10-27T00:00:00.000Z",
        "mono_ns": 1,
        "layer": "tool",
        "kind": "tool.capability",
        "backend": "ebpf",
        "confidence": "exact",
        "args": {
            "transport": "ringbuf",
            "user_read": "binary+str",
            "uprobe_mode": "on-sight",
            "payload_limit": 255,
            "stack": False,
            "stack_supported": True,
            "paired_uprobes": True,
            "probes_attached": 24,
            "probes_total": 15,
            "libraries": "/apex/com.android.conscrypt/lib64/libssl.so,"
            "/system/lib64/libcrypto.so",
            "library_copies": 2,
            "lib_copy_limit": 2,
            "shared_copies": 2,
        },
        "policy": {"redacted": False, "truncated": False},
    }
    (run_dir / "events.jsonl").write_text(
        json.dumps(capability) + "\n", encoding="utf-8"
    )
    paths = generate_summary(run_dir)
    summary = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    footprint = summary["footprint"]
    assert footprint["library_copies"] == 2
    assert footprint["shared_copies"] == 2
    assert footprint["lib_copy_limit"] == 2
    shared = next(
        item for item in footprint["surfaces"] if item["surface"] == "共享库代码页断点"
    )
    assert shared["visible"] is True
    text = Path(paths["summary_md"]).read_text(encoding="utf-8")
    assert "Footprint" in text
    assert "共享库代码页断点" in text


def test_report_records_parse_errors(tmp_path):
    run_dir, _ = create_demo_run(tmp_path, session_id="demo-broken")
    with (run_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    paths = generate_summary(run_dir)
    summary = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    assert len(summary["integrity"]["parse_errors"]) == 1
    text = Path(paths["summary_md"]).read_text(encoding="utf-8")
    assert "Parse errors: 1" in text
