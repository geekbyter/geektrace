import os
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .constants import LOG_PREFIX, MANIFEST_SCHEMA_ID, TOOL_NAME
from .doctor import CommandResult, run_command
from .event import utc_now
from .importer import import_capture
from .output import log
from .report import generate_summary
from .runstore import load_manifest, new_session_id, save_manifest
from .schema import write_schema

DEFAULT_REMOTE_DIR = "/data/local/tmp/geektrace-poc"
MAX_DURATION_SECONDS = 3600
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
ACTIVITY_RE = re.compile(r"^[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+$")
DURATION_RE = re.compile(r"^(\d+)([smh]?)$")
SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")
REMOTE_ROOT = "/data/local/tmp/"


def _valid_device_path(value: str | None) -> bool:
    if not value:
        return True
    return value.startswith("/") and not any(ord(ch) < 0x20 for ch in value)


class DeviceRunError(RuntimeError):
    pass


def parse_duration(value: str) -> int:
    match = DURATION_RE.match(str(value).strip().lower())
    if not match:
        raise ValueError(f"invalid duration {value!r}; use e.g. 30s, 2m, 1h")
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    seconds = amount * {"s": 1, "m": 60, "h": 3600}[unit]
    if seconds < 1 or seconds > MAX_DURATION_SECONDS:
        raise ValueError(
            f"duration must be between 1s and {MAX_DURATION_SECONDS}s"
        )
    return seconds


def abi_tag(abi: str | None) -> str | None:
    return {"arm64-v8a": "arm64", "x86_64": "x86_64"}.get(abi or "")


@dataclass(frozen=True)
class DeviceAssets:
    broker: Path
    root: Path


def _asset_pair(base: Path, tag: str) -> DeviceAssets | None:
    for name in ("geektraced", f"geektraced_{tag}"):
        candidate = base / name
        if candidate.is_file() and candidate.stat().st_size > 0:
            return DeviceAssets(broker=candidate, root=base)
    return None


def find_device_assets(tag: str) -> DeviceAssets:
    candidates: list[Path] = []
    env = os.environ.get("GEETRACE_DEVICE_DIR")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(
        Path(__file__).resolve().parent / "assets" / "device" / tag
    )
    candidates.append(Path(__file__).resolve().parents[3] / "device" / "build")
    for base in candidates:
        found = _asset_pair(base, tag)
        if found:
            return found
    searched = ", ".join(str(path) for path in candidates)
    raise DeviceRunError(
        f"device binaries for {tag} not found (searched: {searched}); "
        "run `bash device/build.sh` or set GEETRACE_DEVICE_DIR"
    )


@dataclass
class CaptureOptions:
    adb: str
    serial: str
    app: str
    duration_seconds: int
    duration_label: str
    runs_root: Path
    profile: str = "ai"
    mode: str = "cold-start"
    activity: str | None = None
    libssl: str | None = None
    libcrypto: str | None = None
    tracefs: str | None = None
    session: str | None = None
    remote_dir: str = DEFAULT_REMOTE_DIR
    payload_limit: int = 255
    stack: bool = False
    eager_uprobes: bool = False
    uid: int | None = None
    prearm: str = "on-sight"
    lib_copies: int = 2


@dataclass
class CaptureResult:
    run_dir: Path
    session: str
    events: int
    paths: dict[str, Path] = field(default_factory=dict)


class AdbClient:
    def __init__(self, adb: str, serial: str) -> None:
        self.adb = adb
        self.serial = serial

    def command(self, *args: str, timeout: float = 30.0) -> CommandResult:
        return run_command([self.adb, "-s", self.serial, *args], timeout=timeout)

    def shell(
        self, command: str, *, root: bool = False, timeout: float = 30.0
    ) -> CommandResult:
        if root:
            command = "su -c " + shlex.quote(command)
        return self.command("shell", command, timeout=timeout)

    def require(self, result: CommandResult, action: str) -> CommandResult:
        if result.ok:
            return result
        detail = result.error or result.stderr.strip() or result.stdout.strip()
        raise DeviceRunError(f"{action} failed: {detail or 'unknown adb error'}")


def _remote(options: CaptureOptions, name: str) -> str:
    return f"{options.remote_dir}/{name}"


def _append_log(run_dir: Path, message: str) -> None:
    path = run_dir / "logs" / "geektrace.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{utc_now()} {LOG_PREFIX} {message}\n")


def _base_artifacts() -> dict[str, str]:
    return {
        "events": "events.jsonl",
        "event_index": "events/index.json",
        "summary_md": "summary.md",
        "summary_json": "summary.json",
        "readme": "README.log.md",
        "schema": "schema/event.v1.json",
        "human_log": "logs/geektrace.log",
    }


def _create_run(
    options: CaptureOptions, device: dict[str, Any]
) -> tuple[str, Path, dict[str, Any]]:
    session = options.session or new_session_id()
    run_dir = options.runs_root / session
    if run_dir.exists():
        raise DeviceRunError(f"run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    (run_dir / "logs").mkdir()
    now = utc_now()
    manifest = {
        "schema": MANIFEST_SCHEMA_ID,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "session": session,
        "created_at": now,
        "ended_at": None,
        "status": "running",
        "app": options.app,
        "profile": options.profile,
        "mode": options.mode,
        "backend": "ebpf",
        "transport": "adb",
        "device": device,
        "demo": False,
        "environment_modified": False,
        "options": {
            "duration": options.duration_label,
            "duration_seconds": options.duration_seconds,
            "activity": options.activity,
            "libssl": options.libssl,
            "libcrypto": options.libcrypto,
            "tracefs": options.tracefs,
            "remote_dir": options.remote_dir,
            "payload_limit": options.payload_limit,
            "stack": options.stack,
            "eager_uprobes": options.eager_uprobes,
        },
        "counts": {"events": 0, "bytes": 0},
        "artifacts": _base_artifacts(),
    }
    save_manifest(run_dir, manifest)
    write_schema(run_dir / "schema" / "event.v1.json")
    _append_log(
        run_dir,
        f"run: capture started app={options.app} serial={options.serial} "
        f"duration={options.duration_label} session={session}",
    )
    return session, run_dir, manifest


def _write_start_script(
    options: CaptureOptions, run_dir: Path, uid: int | None
) -> Path:
    argv = [
        f"{options.remote_dir}/geektraced",
        "--package",
        options.app,
        "--duration",
        str(options.duration_seconds),
        "--session",
        options.session or "",
        "--out",
        f"{options.remote_dir}/events.jsonl",
        "--zygote-forks",
        "--pre-arm",
        options.prearm or "on-sight",
        "--lib-copies",
        str(options.lib_copies),
    ]
    if uid is not None:
        argv.extend(["--uid", str(uid)])
    if options.libssl:
        argv.extend(["--libssl", options.libssl])
    if options.libcrypto:
        argv.extend(["--libcrypto", options.libcrypto])
    if options.tracefs:
        argv.extend(["--tracefs", options.tracefs])
    if options.payload_limit != 255:
        argv.extend(["--payload-limit", str(options.payload_limit)])
    if options.stack:
        argv.append("--stack")
    if options.eager_uprobes:
        argv.append("--eager-uprobes")
    command = "exec " + " ".join(shlex.quote(arg) for arg in argv)
    content = "\n".join(
        [
            "#!/system/bin/sh",
            "umask 022",
            f"DIR={shlex.quote(options.remote_dir)}",
            'echo $$ > "$DIR/broker.pid"',
            command + f" 2> {shlex.quote(_remote(options, 'broker.log'))}",
            "",
        ]
    )
    path = run_dir / "device-start.sh"
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def _resolve_uid(client: AdbClient, package: str) -> int | None:
    result = client.shell("cmd package list packages -U", timeout=30.0)
    if result.ok:
        for line in result.stdout.splitlines():
            match = re.match(
                r"^package:(\S+)\s+uid:(\d+)\s*$", line.strip()
            )
            if match and match.group(1) == package:
                return int(match.group(2))
    dumpsys = client.shell(f"dumpsys package {shlex.quote(package)}", timeout=30.0)
    if dumpsys.ok:
        match = re.search(r"\buserId=(\d+)\b", dumpsys.stdout)
        if match:
            return int(match.group(1))
    return None


def _pid_alive(client: AdbClient, pid: int) -> bool:
    result = client.shell(f"kill -0 {pid}", root=True, timeout=8.0)
    if result.error or result.code is None:
        raise DeviceRunError(
            f"lost adb connection while waiting for broker: {result.error}"
        )
    return result.code == 0


def _stop_broker(
    client: AdbClient, pid: int | None, sleep_fn: Callable[[float], None]
) -> None:
    if not pid:
        return
    try:
        client.shell(f"kill -TERM {pid}", root=True, timeout=8.0)
        for _ in range(10):
            if not _pid_alive(client, pid):
                return
            sleep_fn(0.5)
        client.shell(f"kill -KILL {pid}", root=True, timeout=8.0)
    except (DeviceRunError, OSError, KeyboardInterrupt):
        return


def _pull_text(
    client: AdbClient, remote: str, local: Path, *, root: bool = False
) -> bool:
    if local.exists():
        local.unlink()
    result = client.command("pull", remote, str(local), timeout=120.0)
    if result.ok and local.exists():
        return True
    cat = client.shell(f"cat {shlex.quote(remote)}", root=root, timeout=120.0)
    if cat.ok and cat.stdout:
        local.write_text(cat.stdout, encoding="utf-8", newline="\n")
        return True
    return False


def _pull_artifacts(
    client: AdbClient, options: CaptureOptions, run_dir: Path
) -> dict[str, bool]:
    client.shell(
        f"chmod 644 {shlex.quote(_remote(options, 'events.jsonl'))} "
        f"{shlex.quote(_remote(options, 'broker.log'))} "
        f"{shlex.quote(_remote(options, 'broker.pid'))} 2>/dev/null",
        root=True,
        timeout=10.0,
    )
    pulled: dict[str, bool] = {}
    for name in ("events.jsonl", "broker.log", "broker.pid"):
        pulled[name] = _pull_text(
            client,
            _remote(options, name),
            run_dir / name,
            root=True,
        )
    return pulled


def _cleanup_remote(client: AdbClient, options: CaptureOptions) -> None:
    client.shell(
        f"rm -rf {shlex.quote(options.remote_dir)}",
        root=True,
        timeout=10.0,
    )


def _fail_manifest(
    run_dir: Path, status: str, error: str | None
) -> None:
    try:
        manifest = load_manifest(run_dir)
    except (OSError, ValueError):
        return
    manifest["status"] = status
    manifest["ended_at"] = utc_now()
    if error:
        manifest["error"] = error[:2000]
    events = run_dir / "events.jsonl"
    if events.exists():
        size = events.stat().st_size
        count = 0
        try:
            with events.open("r", encoding="utf-8", errors="replace") as handle:
                count = sum(1 for line in handle if line.strip())
        except OSError:
            pass
        manifest["counts"] = {"events": count, "bytes": size}
    try:
        save_manifest(run_dir, manifest)
    except OSError:
        return
    try:
        generate_summary(run_dir)
    except (OSError, ValueError):
        pass
    _append_log(
        run_dir,
        f"run: capture {status}" + (f" error={error}" if error else ""),
    )


def execute_capture(
    options: CaptureOptions,
    device: dict[str, Any],
    *,
    client: AdbClient | None = None,
    assets: DeviceAssets | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    clock_fn: Callable[[], float] = time.monotonic,
    step: Callable[[str], None] | None = None,
) -> CaptureResult:
    if not PACKAGE_RE.match(options.app):
        raise ValueError(f"invalid package name: {options.app!r}")
    if options.activity and not ACTIVITY_RE.match(options.activity):
        raise ValueError(
            f"invalid activity {options.activity!r}; use package/.Activity"
        )
    if options.session and not SESSION_RE.match(options.session):
        raise ValueError("--session must match [A-Za-z0-9._-]{1,63}")
    options.remote_dir = options.remote_dir.rstrip("/")
    if not options.remote_dir.startswith(REMOTE_ROOT):
        raise ValueError("--remote-dir must be under /data/local/tmp")
    if any(part in (".", "..") for part in options.remote_dir.split("/")):
        raise ValueError("--remote-dir must not contain '.' or '..' segments")
    if not all(
        _valid_device_path(value)
        for value in (options.libssl, options.libcrypto, options.tracefs)
    ):
        raise ValueError("libssl/libcrypto/tracefs must be absolute device paths")
    if options.mode != "cold-start":
        raise DeviceRunError(
            f"mode {options.mode!r} is not implemented in v0.1.0; use cold-start"
        )
    if options.duration_seconds < 5:
        raise ValueError("device capture needs --duration of at least 5s")
    tag = abi_tag(device.get("abi"))
    if not tag:
        raise DeviceRunError(
            f"unsupported device ABI {device.get('abi')!r} "
            "(need arm64-v8a or x86_64)"
        )
    assets = assets or find_device_assets(tag)
    client = client or AdbClient(options.adb, options.serial)
    report_step = step or (lambda message: log(f"run: {message}"))

    package_check = client.shell(f"pm path {shlex.quote(options.app)}", timeout=30.0)
    if not package_check.ok or "package:" not in package_check.stdout:
        raise DeviceRunError(
            f"{options.app} is not installed; install the APK before running"
        )
    uid = options.uid if options.uid is not None else _resolve_uid(client, options.app)
    report_step(f"force-stop {options.app}")
    client.require(
        client.shell(
            f"am force-stop {shlex.quote(options.app)}", timeout=30.0
        ),
        "force-stop app",
    )

    session, run_dir, _ = _create_run(options, device)
    options.session = session
    broker_pid: int | None = None
    remote_ready = False
    status = "failed"
    error: str | None = None

    try:
        report_step(f"session {session}; output {run_dir}")
        report_step("prepare remote directory and push broker")
        client.require(
            client.shell(
                f"rm -rf {shlex.quote(options.remote_dir)} && "
                f"mkdir -p {shlex.quote(options.remote_dir)}",
                root=True,
                timeout=20.0,
            ),
            "prepare remote directory",
        )
        remote_ready = True
        # adb push runs as the shell user, but the remote directory belongs to
        # root. Stage the files in a shell-writable directory and move them
        # into place with root.
        staging = f"/data/local/tmp/geektrace-upload-{session}"
        client.require(
            client.shell(
                f"rm -rf {shlex.quote(staging)} && mkdir -p {shlex.quote(staging)}",
                timeout=20.0,
            ),
            "prepare upload directory",
        )
        client.require(
            client.command(
                "push", str(assets.broker), f"{staging}/geektraced",
                timeout=120.0,
            ),
            "push broker",
        )
        script = _write_start_script(options, run_dir, uid)
        client.require(
            client.command("push", str(script), f"{staging}/start.sh"),
            "push start script",
        )
        client.require(
            client.shell(
                f"mv {shlex.quote(staging + '/geektraced')} "
                f"{shlex.quote(_remote(options, 'geektraced'))} && "
                f"mv {shlex.quote(staging + '/start.sh')} "
                f"{shlex.quote(_remote(options, 'start.sh'))} && "
                f"rm -rf {shlex.quote(staging)}",
                root=True,
                timeout=30.0,
            ),
            "install remote binaries",
        )
        client.require(
            client.shell(
                f"chmod 755 {shlex.quote(_remote(options, 'geektraced'))} "
                f"{shlex.quote(_remote(options, 'start.sh'))}",
                root=True,
                timeout=10.0,
            ),
            "chmod remote binaries",
        )

        report_step("start broker")
        start_command = (
            f"nohup sh {shlex.quote(_remote(options, 'start.sh'))} "
            ">/dev/null 2>&1 & echo $!"
        )
        started = client.shell(start_command, root=True, timeout=30.0)
        if started.ok:
            numbers = re.findall(r"\b(\d+)\b", started.stdout)
            if numbers:
                broker_pid = int(numbers[-1])
        if broker_pid is None:
            sleep_fn(1.0)
            pid_text = client.shell(
                f"cat {shlex.quote(_remote(options, 'broker.pid'))}",
                root=True,
                timeout=8.0,
            )
            if pid_text.ok and pid_text.stdout.strip().isdigit():
                broker_pid = int(pid_text.stdout.strip())
        if broker_pid is None:
            raise DeviceRunError("broker did not report a pid")
        sleep_fn(1.0)
        if not _pid_alive(client, broker_pid):
            _pull_text(
                client,
                _remote(options, "broker.log"),
                run_dir / "broker.log",
                root=True,
            )
            raise DeviceRunError("broker exited during startup; see broker.log")

        report_step(f"launch {options.app}")
        if options.activity:
            launch = client.shell(
                f"am start -W -n {shlex.quote(options.activity)}", timeout=60.0
            )
        else:
            launch = client.shell(
                f"monkey -p {shlex.quote(options.app)} "
                "-c android.intent.category.LAUNCHER 1",
                timeout=60.0,
            )
        (run_dir / "start.log").write_text(
            (launch.stdout or "") + (launch.stderr or ""),
            encoding="utf-8",
            newline="\n",
        )
        if not launch.ok:
            raise DeviceRunError(
                "failed to launch app; see start.log (use --activity if the app "
                "has no launcher activity)"
            )

        sleep_fn(min(3.0, max(1.0, options.duration_seconds / 5)))
        target_pid_text = client.shell(
            f"pidof {shlex.quote(options.app)}", timeout=15.0
        )
        target_pid = None
        if target_pid_text.ok:
            match = re.search(r"\b(\d+)\b", target_pid_text.stdout)
            if match:
                target_pid = int(match.group(1))
        if target_pid:
            status_result = client.shell(
                f'grep -E "^(Name|Pid|TracerPid|Threads):" '
                f"/proc/{target_pid}/status",
                root=True,
                timeout=10.0,
            )
            if status_result.ok and status_result.stdout.strip():
                (run_dir / "target-status.txt").write_text(
                    status_result.stdout, encoding="utf-8", newline="\n"
                )
            report_step(f"target pid {target_pid}; target status sampled")

        report_step(f"wait up to {options.duration_seconds}s for broker")
        deadline = clock_fn() + options.duration_seconds + 45
        while clock_fn() < deadline:
            if not _pid_alive(client, broker_pid):
                break
            sleep_fn(1.0)
        else:
            report_step("broker exceeded duration; sending SIGTERM")
        if _pid_alive(client, broker_pid):
            _stop_broker(client, broker_pid, sleep_fn)
        broker_pid = None

        report_step("pull events and broker log")
        pulled = _pull_artifacts(client, options, run_dir)
        if not pulled.get("events.jsonl"):
            raise DeviceRunError("could not pull events.jsonl from device")
        if not (run_dir / "events.jsonl").exists():
            raise DeviceRunError("events.jsonl is missing after pull")

        report_step("validate events and build summary")
        imported = import_capture(
            run_dir,
            app=options.app,
            profile=options.profile,
            serial=options.serial,
            model=device.get("model"),
            android=device.get("android"),
            kernel=device.get("kernel"),
            abi=device.get("abi"),
        )
        status = "completed"
        result = CaptureResult(
            run_dir=run_dir,
            session=session,
            events=int(imported["validation"]["valid_events"]),
            paths=imported["paths"],
        )
        report_step(
            f"completed: {result.events} events; summary={result.paths['summary_md']}"
        )
        return result
    except KeyboardInterrupt:
        status = "aborted"
        error = "interrupted by user"
        raise
    except DeviceRunError as exc:
        error = str(exc)
        raise
    except Exception as exc:
        error = str(exc)
        raise DeviceRunError(f"capture failed: {exc}") from exc
    finally:
        if broker_pid is not None:
            _stop_broker(client, broker_pid, sleep_fn)
        if remote_ready:
            if status != "completed":
                try:
                    _pull_artifacts(client, options, run_dir)
                except (DeviceRunError, OSError):
                    pass
            try:
                _cleanup_remote(client, options)
            except (DeviceRunError, OSError):
                pass
        if status != "completed":
            _fail_manifest(run_dir, status, error)
