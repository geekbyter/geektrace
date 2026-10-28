import json
from pathlib import Path

import pytest

from geektrace.doctor import CommandResult
from geektrace.event import new_event
from geektrace.runner import (
    CaptureOptions,
    DeviceAssets,
    DeviceRunError,
    execute_capture,
    parse_duration,
)

DEVICE = {
    "serial": "emulator-5554",
    "model": "Pixel-Test",
    "android": "14",
    "kernel": "6.1.0-test",
    "abi": "arm64-v8a",
}


def _events_text(session: str, count: int = 2) -> str:
    lines = []
    for seq in range(1, count + 1):
        event = new_event(
            session=session,
            seq=seq,
            layer="file",
            kind="file.open",
            backend="ebpf",
            pid=4321,
            tid=4321,
            uid=10234,
            comm="geektrace.bench",
            args={
                "dfd": -100,
                "flags": "0x0",
                "path": "/data/user/0/com.geektrace.bench/files/bench.log",
            },
        )
        lines.append(json.dumps(event))
    return "\n".join(lines) + "\n"


class FakeAdbClient:
    def __init__(
        self,
        events_text: str,
        *,
        alive_checks: int = 2,
        launch_ok: bool = True,
        interrupt_on_sleep: bool = False,
    ) -> None:
        self.events_text = events_text
        self.alive_checks = alive_checks
        self.launch_ok = launch_ok
        self.interrupt_on_sleep = interrupt_on_sleep
        self.alive = True
        self.calls: list[tuple] = []
        self.pulls = 0
        self.sleeps = 0

    def command(self, *args: str, timeout: float = 30.0) -> CommandResult:
        self.calls.append(("command",) + args)
        if args[0] == "push":
            return CommandResult(list(args), 0, "", "")
        if args[0] == "pull":
            remote = args[1]
            local = Path(args[2])
            if remote.endswith("events.jsonl"):
                local.write_text(self.events_text, encoding="utf-8")
            elif remote.endswith("broker.log"):
                local.write_text("broker started\n", encoding="utf-8")
            elif remote.endswith("broker.pid"):
                local.write_text("4242\n", encoding="utf-8")
            else:
                return CommandResult(list(args), 1, "", "missing")
            self.pulls += 1
            return CommandResult(list(args), 0, "1 file pulled", "")
        return CommandResult(list(args), 0, "", "")

    def shell(
        self, command: str, *, root: bool = False, timeout: float = 30.0
    ) -> CommandResult:
        self.calls.append(("shell", command, root))
        if command.startswith("pm path"):
            return CommandResult([], 0, "package:/data/app/base.apk", "")
        if command.startswith("cmd package list"):
            return CommandResult(
                [], 0, "package:com.geektrace.bench uid:10234", ""
            )
        if command.startswith("nohup sh"):
            return CommandResult([], 0, "4242", "")
        if command.startswith("kill -0"):
            if self.alive and self.alive_checks > 0:
                self.alive_checks -= 1
                return CommandResult([], 0, "", "")
            self.alive = False
            return CommandResult([], 1, "", "")
        if command.startswith("kill -TERM") or command.startswith("kill -KILL"):
            self.alive = False
            self.alive_checks = 0
            return CommandResult([], 0, "", "")
        if command.startswith("monkey") or command.startswith("am start"):
            code = 0 if self.launch_ok else 1
            return CommandResult([], code, "Events injected: 1", "")
        if command.startswith("pidof"):
            return CommandResult([], 0, "4321", "")
        if command.startswith("grep -E"):
            return CommandResult(
                [],
                0,
                "Name:\tcom.geektrace.bench\nPid:\t4321\n"
                "TracerPid:\t0\nThreads:\t24\n",
                "",
            )
        return CommandResult([], 0, "", "")

    def require(self, result: CommandResult, action: str) -> CommandResult:
        if not result.ok:
            raise DeviceRunError(
                f"{action} failed: {result.error or result.stderr or result.stdout}"
            )
        return result


def _sleep_clock(sleeps: list[float], client: FakeAdbClient, *, interrupt: bool):
    now = [0.0]

    def sleep(seconds: float) -> None:
        client.sleeps += 1
        if interrupt and client.sleeps == 1:
            raise KeyboardInterrupt
        sleeps.append(seconds)
        now[0] += seconds

    return sleep, (lambda: now[0])


def _assets(tmp_path: Path) -> DeviceAssets:
    root = tmp_path / "assets"
    root.mkdir()
    broker = root / "geektraced"
    broker.write_bytes(b"broker")
    return DeviceAssets(broker=broker, root=root)


def _options(tmp_path: Path, **overrides) -> CaptureOptions:
    values = {
        "adb": "adb",
        "serial": "emulator-5554",
        "app": "com.geektrace.bench",
        "duration_seconds": 30,
        "duration_label": "30s",
        "runs_root": tmp_path / "runs",
        "session": "runner-session",
    }
    values.update(overrides)
    return CaptureOptions(**values)


def test_parse_duration_units():
    assert parse_duration("30s") == 30
    assert parse_duration("2m") == 120
    assert parse_duration("1h") == 3600
    for bad in ("0s", "5x", "3601s", ""):
        with pytest.raises(ValueError):
            parse_duration(bad)


def test_execute_capture_success(tmp_path):
    assets = _assets(tmp_path)
    client = FakeAdbClient(_events_text("runner-session"))
    sleeps: list[float] = []
    sleep_fn, clock_fn = _sleep_clock(sleeps, client, interrupt=False)

    result = execute_capture(
        _options(tmp_path),
        DEVICE,
        client=client,
        assets=assets,
        sleep_fn=sleep_fn,
        clock_fn=clock_fn,
    )

    assert result.session == "runner-session"
    assert result.events == 2
    run_dir = tmp_path / "runs" / "runner-session"
    assert result.run_dir == run_dir
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["session"] == "runner-session"
    assert manifest["app"] == "com.geektrace.bench"
    assert manifest["target"]["tracer_pid"] == 0
    assert manifest["target"]["pid"] == 4321
    assert manifest["validation"]["valid_events"] == 2
    assert (run_dir / "events.jsonl").exists()
    assert (run_dir / "broker.log").exists()
    assert (run_dir / "target-status.txt").exists()
    assert (run_dir / "summary.md").exists()
    assert (run_dir / "summary.json").exists()

    start_script = (run_dir / "device-start.sh").read_text(encoding="utf-8")
    assert "--session runner-session" in start_script
    assert "--uid 10234" in start_script
    assert "--duration 30" in start_script
    assert "--bpffile" not in start_script

    assert client.pulls == 3
    commands = [call[1] for call in client.calls if call[0] == "shell"]
    assert any("am force-stop com.geektrace.bench" in cmd for cmd in commands)
    assert any("monkey -p com.geektrace.bench" in cmd for cmd in commands)
    assert any(
        cmd.startswith("rm -rf /data/local/tmp/geektrace-poc") for cmd in commands
    )


def test_execute_capture_broker_startup_failure(tmp_path):
    assets = _assets(tmp_path)
    client = FakeAdbClient(_events_text("runner-failed"), alive_checks=0)
    sleeps: list[float] = []
    sleep_fn, clock_fn = _sleep_clock(sleeps, client, interrupt=False)

    with pytest.raises(DeviceRunError, match="broker exited during startup"):
        execute_capture(
            _options(tmp_path, session="runner-failed"),
            DEVICE,
            client=client,
            assets=assets,
            sleep_fn=sleep_fn,
            clock_fn=clock_fn,
        )

    run_dir = tmp_path / "runs" / "runner-failed"
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert "broker exited during startup" in manifest["error"]
    assert (run_dir / "summary.md").exists()


def test_execute_capture_launch_failure(tmp_path):
    assets = _assets(tmp_path)
    client = FakeAdbClient(_events_text("runner-launch"), launch_ok=False)
    sleeps: list[float] = []
    sleep_fn, clock_fn = _sleep_clock(sleeps, client, interrupt=False)

    with pytest.raises(DeviceRunError, match="failed to launch app"):
        execute_capture(
            _options(tmp_path, session="runner-launch"),
            DEVICE,
            client=client,
            assets=assets,
            sleep_fn=sleep_fn,
            clock_fn=clock_fn,
        )

    run_dir = tmp_path / "runs" / "runner-launch"
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert (run_dir / "start.log").exists()
    commands = [call[1] for call in client.calls if call[0] == "shell"]
    assert any(cmd.startswith("kill -TERM 4242") for cmd in commands)
    assert any(
        cmd.startswith("rm -rf /data/local/tmp/geektrace-poc") for cmd in commands
    )


def test_execute_capture_interrupt_marks_aborted(tmp_path):
    assets = _assets(tmp_path)
    client = FakeAdbClient(_events_text("runner-abort"))
    sleeps: list[float] = []
    sleep_fn, clock_fn = _sleep_clock(sleeps, client, interrupt=True)

    with pytest.raises(KeyboardInterrupt):
        execute_capture(
            _options(tmp_path, session="runner-abort"),
            DEVICE,
            client=client,
            assets=assets,
            sleep_fn=sleep_fn,
            clock_fn=clock_fn,
        )

    run_dir = tmp_path / "runs" / "runner-abort"
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "aborted"
    assert manifest["error"] == "interrupted by user"
    commands = [call[1] for call in client.calls if call[0] == "shell"]
    assert any(cmd.startswith("kill -TERM 4242") for cmd in commands)
    assert any(
        cmd.startswith("rm -rf /data/local/tmp/geektrace-poc") for cmd in commands
    )


def test_execute_capture_rejects_unsafe_remote_dir(tmp_path):
    assets = _assets(tmp_path)
    client = FakeAdbClient(_events_text("runner-session"))
    with pytest.raises(ValueError, match="/data/local/tmp"):
        execute_capture(
            _options(tmp_path, remote_dir="/sdcard/geektrace"),
            DEVICE,
            client=client,
            assets=assets,
            sleep_fn=lambda _: None,
        )
    with pytest.raises(ValueError, match="must not contain"):
        execute_capture(
            _options(tmp_path, remote_dir="/data/local/tmp/../data/data"),
            DEVICE,
            client=client,
            assets=assets,
            sleep_fn=lambda _: None,
        )
