import json
from pathlib import Path

import geektrace.cli as cli_module
import geektrace.doctor as doctor_module
import geektrace.preflight as preflight_module
from geektrace.cli import main
from geektrace.runner import CaptureResult


def test_cli_demo_schema_and_report(tmp_path, capsys):
    assert main(["demo", "--runs-root", str(tmp_path), "--session-id", "cli-demo"]) == 0
    run_dir = tmp_path / "cli-demo"
    assert (run_dir / "summary.md").exists()
    assert (run_dir / "events.jsonl").exists()

    capsys.readouterr()
    assert main(["schema", "--validate", str(run_dir)]) == 0
    output = capsys.readouterr().out
    assert "events=36" in output

    assert main(["report", str(run_dir), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["demo"] is True
    assert payload["counts"]["events"] == 36


def test_cli_compact_rebuilds_index(tmp_path, capsys):
    assert main(["demo", "--runs-root", str(tmp_path), "--session-id", "cli-compact"]) == 0
    capsys.readouterr()
    run_dir = tmp_path / "cli-compact"
    assert main(["compact", str(run_dir)]) == 0
    assert "parts=0" in capsys.readouterr().err
    index = json.loads((run_dir / "events" / "index.json").read_text(encoding="utf-8"))
    assert index["total_events"] == 36


def test_cli_schema_validation_failure(tmp_path, capsys):
    path = tmp_path / "bad.jsonl"
    path.write_text("{broken\n", encoding="utf-8")
    assert main(["schema", "--validate", str(path)]) != 0
    assert "schema error" in capsys.readouterr().out


def test_cli_run_dry_run_creates_plan(tmp_path, capsys):
    assert (
        main(
            [
                "run",
                "--app",
                "com.example.bench",
                "--dry-run",
                "--runs-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    run_dir_line = next(
        line for line in output.splitlines() if line.startswith("run_dir=")
    )
    run_dir = Path(run_dir_line.split("=", 1)[1])
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "planned"
    assert manifest["app"] == "com.example.bench"
    assert (run_dir / "summary.md").exists()


def test_cli_run_wires_device_capture(tmp_path, monkeypatch, capsys):
    captured = {}

    def fake_doctor(**kwargs):
        return {
            "ready": True,
            "status": "ready",
            "host": {"adb": "adb"},
            "warnings": [],
            "device": {
                "serial": "emulator-5554",
                "model": "Pixel-Test",
                "android": "14",
                "kernel": "6.1.0-test",
                "abi": "arm64-v8a",
            },
        }

    def fake_capture(options, device, **kwargs):
        captured["options"] = options
        captured["device"] = device
        run_dir = options.runs_root / options.session
        run_dir.mkdir(parents=True)
        (run_dir / "summary.md").write_text("# summary\n", encoding="utf-8")
        return CaptureResult(
            run_dir=run_dir,
            session=options.session,
            events=0,
            paths={
                "summary_md": run_dir / "summary.md",
                "summary_json": run_dir / "summary.json",
                "index": run_dir / "events" / "index.json",
                "readme": run_dir / "README.log.md",
            },
        )

    monkeypatch.setattr(cli_module, "doctor_report", fake_doctor)
    monkeypatch.setattr(cli_module, "execute_capture", fake_capture)

    assert (
        main(
            [
                "run",
                "--app",
                "com.example.bench",
                "--duration",
                "2m",
                "--runs-root",
                str(tmp_path),
                "--session",
                "cli-run",
                "--activity",
                "com.example.bench/.MainActivity",
            ]
        )
        == 0
    )
    options = captured["options"]
    assert options.serial == "emulator-5554"
    assert options.duration_seconds == 120
    assert options.activity == "com.example.bench/.MainActivity"
    assert captured["device"]["abi"] == "arm64-v8a"
    output = capsys.readouterr().out
    assert "run_dir=" in output
    assert "summary_md=" in output


def test_cli_run_rejects_unimplemented_backend_and_profile(tmp_path, capsys):
    assert main(["run", "--app", "com.example.bench", "--backend", "qbdi"]) == 2
    assert "only implements --backend ebpf" in capsys.readouterr().err
    assert main(["run", "--app", "com.example.bench", "--profile", "coverage"]) == 2
    assert "not implemented by the device broker" in capsys.readouterr().err
    assert main(["run", "--app", "com.example.bench", "--mode", "attach"]) == 2
    assert "only implements --mode cold-start" in capsys.readouterr().err


def test_cli_run_rejects_unsafe_options(tmp_path, capsys):
    assert (
        main(
            [
                "run",
                "--app",
                "com.example.bench",
                "--dry-run",
                "--runs-root",
                str(tmp_path),
                "--remote-dir",
                "/sdcard/geektrace",
            ]
        )
        == 2
    )
    assert "--remote-dir must be under /data/local/tmp" in capsys.readouterr().err
    assert (
        main(
            [
                "run",
                "--app",
                "com.example.bench",
                "--dry-run",
                "--runs-root",
                str(tmp_path),
                "--session",
                "bad session",
            ]
        )
        == 2
    )
    assert "--session must match" in capsys.readouterr().err


def test_cli_run_maps_profile_to_device_options(tmp_path, monkeypatch, capsys):
    captured = {}

    def fake_doctor(**kwargs):
        return {
            "ready": True,
            "status": "ready",
            "host": {"adb": "adb"},
            "warnings": [],
            "device": {
                "serial": "emulator-5554",
                "model": "Pixel-Test",
                "android": "14",
                "kernel": "6.1.0-test",
                "abi": "arm64-v8a",
            },
        }

    def fake_capture(options, device, **kwargs):
        captured["options"] = options
        run_dir = options.runs_root / options.session
        run_dir.mkdir(parents=True)
        (run_dir / "summary.md").write_text("# summary\n", encoding="utf-8")
        return CaptureResult(
            run_dir=run_dir,
            session=options.session,
            events=0,
            paths={
                "summary_md": run_dir / "summary.md",
                "summary_json": run_dir / "summary.json",
                "index": run_dir / "events" / "index.json",
                "readme": run_dir / "README.log.md",
            },
        )

    monkeypatch.setattr(cli_module, "doctor_report", fake_doctor)
    monkeypatch.setattr(cli_module, "execute_capture", fake_capture)

    assert (
        main(
            [
                "run",
                "--app",
                "com.example.bench",
                "--profile",
                "stealth",
                "--runs-root",
                str(tmp_path),
                "--session",
                "cli-stealth",
            ]
        )
        == 0
    )
    options = captured["options"]
    assert options.payload_limit == 64
    assert options.stack is False
    assert options.eager_uprobes is False


def test_cli_graph_and_preflight_commands(tmp_path, monkeypatch, capsys):
    assert main(["demo", "--runs-root", str(tmp_path), "--session-id", "cli-graph"]) == 0
    run_dir = tmp_path / "cli-graph"
    capsys.readouterr()

    assert main(["graph", str(run_dir), "--format", "json"]) == 0
    graph = json.loads(capsys.readouterr().out)
    assert graph["schema"] == "geektrace.graph.v1"

    monkeypatch.setattr(
        preflight_module,
        "device_readiness",
        lambda serial: {"capabilities": {}, "unsupported": [], "warnings": []},
    )
    assert main(["preflight", "--app", "com.example.app", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "geektrace.preflight.v1"
    assert report["app"] == "com.example.app"


def test_cli_doctor_without_adb(monkeypatch, capsys):
    monkeypatch.setattr(doctor_module, "find_adb", lambda: None)
    assert main(["doctor", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "no_device"
    assert report["host"]["adb"] is None


def test_cli_doctor_require_device_fails_without_device(monkeypatch, capsys):
    monkeypatch.setattr(doctor_module, "find_adb", lambda: None)
    assert main(["doctor", "--json", "--require-device"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
