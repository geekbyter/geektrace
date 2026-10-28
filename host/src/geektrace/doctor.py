import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .event import utc_now

SERIAL_RE = re.compile(r"^[A-Za-z0-9._:+-]{1,128}$")
PROP_RE = re.compile(r"^\[([^\]]+)\]: \[(.*)\]$")
SUPPORTED_SDK_MIN = 31
SUPPORTED_SDK_MAX = 36


@dataclass
class CommandResult:
    args: list[str]
    code: int | None
    stdout: str
    stderr: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.code == 0


def run_command(args: list[str], timeout: float = 8.0) -> CommandResult:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(args, None, "", "", "executable not found")
    except subprocess.TimeoutExpired:
        return CommandResult(args, None, "", "", f"timeout after {timeout:.0f}s")
    except OSError as exc:
        return CommandResult(args, None, "", "", str(exc))
    return CommandResult(
        args, completed.returncode, completed.stdout or "", completed.stderr or ""
    )


def find_adb() -> str | None:
    candidate = shutil.which("adb")
    if candidate:
        return candidate
    roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
    ]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        roots.append(str(Path(local_app_data) / "Android" / "Sdk"))
    for root in roots:
        if not root:
            continue
        binary = Path(root) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
        if binary.exists():
            return str(binary)
    return None


def parse_devices(output: str) -> list[dict[str, Any]]:
    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        record: dict[str, Any] = {"serial": parts[0], "state": parts[1]}
        for token in parts[2:]:
            if ":" in token:
                key, value = token.split(":", 1)
                record[key] = value
        devices.append(record)
    return devices


def parse_props(output: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in output.splitlines():
        match = PROP_RE.match(line.strip())
        if match:
            props[match.group(1)] = match.group(2)
    return props


def _shell(adb: str, serial: str, *command: str, timeout: float = 8.0) -> CommandResult:
    return run_command([adb, "-s", serial, "shell", *command], timeout=timeout)


def _exists(adb: str, serial: str, path: str) -> bool:
    result = _shell(adb, serial, "test", "-e", path, timeout=5.0)
    return result.code == 0


def _value(result: CommandResult) -> str:
    return result.stdout.strip() if result.ok else ""


def inspect_device(
    adb: str, serial: str, *, check_root: bool = True
) -> dict[str, Any]:
    if not SERIAL_RE.match(serial):
        raise ValueError(f"invalid adb serial: {serial!r}")

    props_result = _shell(adb, serial, "getprop", timeout=12.0)
    props = parse_props(props_result.stdout) if props_result.ok else {}
    kernel = _value(_shell(adb, serial, "uname", "-r"))
    page_size_text = _value(_shell(adb, serial, "getconf", "PAGE_SIZE"))
    selinux = _value(_shell(adb, serial, "getenforce"))

    root_output = ""
    root = False
    if check_root:
        root_result = _shell(adb, serial, "su", "-c", "id", timeout=6.0)
        root_output = (root_result.stdout + root_result.stderr).strip()
        root = root_result.ok and "uid=0" in root_output

    tracefs_paths = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
    tracefs = next((path for path in tracefs_paths if _exists(adb, serial, path)), None)
    uprobe = bool(
        tracefs and _exists(adb, serial, f"{tracefs}/uprobe_events")
    )
    kprobe = bool(
        tracefs and _exists(adb, serial, f"{tracefs}/kprobe_events")
    )
    btf = _exists(adb, serial, "/sys/kernel/btf/vmlinux")
    config_gz = _exists(adb, serial, "/proc/config.gz")

    page_size = None
    if page_size_text.isdigit():
        page_size = int(page_size_text)

    sdk_text = props.get("ro.build.version.sdk", "")
    sdk = int(sdk_text) if sdk_text.isdigit() else None
    android = props.get("ro.build.version.release")
    finger = props.get("ro.build.fingerprint")
    abi = props.get("ro.product.cpu.abi")
    model = props.get("ro.product.model")
    manufacturer = props.get("ro.product.manufacturer")
    wireless_prop = props.get("service.adb.tcp.port") or props.get("persist.adb.tcp.port")
    wireless_adb = bool(wireless_prop and wireless_prop not in ("-1", "0"))

    checks: dict[str, Any] = {
        "root": root if check_root else None,
        "selinux": selinux or None,
        "tracefs": tracefs,
        "uprobe_events": uprobe,
        "kprobe_events": kprobe,
        "btf": btf,
        "proc_config_gz": config_gz,
        "page_size": page_size,
        "wireless_adb": wireless_adb,
    }
    warnings = []
    if check_root and not root:
        warnings.append("root check failed; geektrace requires root and su access")
    if check_root and root:
        pass
    if not tracefs:
        warnings.append("tracefs not found; eBPF uprobe/kprobe collection is unavailable")
    elif not uprobe:
        warnings.append("uprobe_events missing; native crypto/TLS observation is unavailable")
    if not btf:
        warnings.append(
            "BTF missing; the precompiled raw-bpf broker does not require it, "
            "but future CO-RE features will be unavailable"
        )
    if page_size == 16384:
        warnings.append("16KB page device; verify broker, trampoline and ELF alignment")
    if sdk is not None and not (SUPPORTED_SDK_MIN <= sdk <= SUPPORTED_SDK_MAX):
        warnings.append(
            f"Android SDK {sdk} outside supported range {SUPPORTED_SDK_MIN}-{SUPPORTED_SDK_MAX}"
        )
    if root and uprobe and tracefs:
        status = "ready"
    elif root and tracefs:
        status = "degraded"
    elif root:
        status = "degraded"
    else:
        status = "degraded"

    return {
        "serial": serial,
        "model": model,
        "manufacturer": manufacturer,
        "android": android,
        "sdk": sdk,
        "kernel": kernel or None,
        "abi": abi,
        "fingerprint": finger,
        "root_output": root_output[:200] if root_output else None,
        "checks": checks,
        "warnings": warnings,
        "status": status,
    }


def doctor_report(
    *,
    serial: str | None = None,
    check_root: bool = True,
) -> dict[str, Any]:
    adb = find_adb()
    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "host": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "adb": adb,
            "adb_version": None,
            "sdk_roots": {
                "ANDROID_HOME": os.environ.get("ANDROID_HOME"),
                "ANDROID_SDK_ROOT": os.environ.get("ANDROID_SDK_ROOT"),
            },
        },
        "devices": [],
        "device": None,
        "warnings": [],
        "ready": False,
        "status": "no_device",
    }
    if not adb:
        report["warnings"].append(
            "adb not found; set ANDROID_HOME or add platform-tools to PATH"
        )
        return report

    version = run_command([adb, "version"], timeout=8.0)
    if version.ok:
        report["host"]["adb_version"] = version.stdout.splitlines()[0].strip() if version.stdout else None
    else:
        report["warnings"].append(f"adb version check failed: {version.error or version.stderr.strip()}")

    devices_result = run_command([adb, "devices", "-l"], timeout=12.0)
    if not devices_result.ok:
        report["warnings"].append(
            f"adb devices failed: {devices_result.error or devices_result.stderr.strip()}"
        )
        report["status"] = "adb_error"
        return report
    report["devices"] = parse_devices(devices_result.stdout)

    available = [item for item in report["devices"] if item.get("state") == "device"]
    selected = None
    if serial:
        selected = next(
            (item for item in report["devices"] if item["serial"] == serial), None
        )
        if selected is None:
            report["warnings"].append(f"serial {serial} not found in adb devices")
            report["status"] = "device_not_found"
            return report
        if selected.get("state") != "device":
            report["warnings"].append(
                f"serial {serial} is in state {selected.get('state')!r}, not 'device'"
            )
            report["status"] = "device_unauthorized"
            return report
    elif available:
        selected = available[0]
        if len(available) > 1:
            report["warnings"].append(
                f"{len(available)} devices online; selected {selected['serial']}; use --serial to override"
            )
    else:
        report["warnings"].append(
            "no online device; connect a rooted Android device and enable USB debugging"
        )
        report["status"] = "no_device"
        return report

    try:
        device = inspect_device(adb, selected["serial"], check_root=check_root)
    except ValueError as exc:
        report["warnings"].append(str(exc))
        report["status"] = "invalid_serial"
        return report

    report["device"] = device
    report["warnings"].extend(device["warnings"])
    report["status"] = device["status"]
    report["ready"] = device["status"] == "ready"
    return report


def doctor_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


def human_lines(report: dict[str, Any]) -> list[str]:
    lines = [
        f"doctor: host python={report['host']['python']} adb={report['host']['adb'] or 'missing'}",
        f"doctor: devices={len(report['devices'])} status={report['status']} ready={report['ready']}",
    ]
    device = report.get("device")
    if device:
        checks = device.get("checks") or {}
        lines.append(
            "device: serial={} model={} android={} sdk={} kernel={} abi={}".format(
                device.get("serial"),
                device.get("model"),
                device.get("android"),
                device.get("sdk"),
                device.get("kernel"),
                device.get("abi"),
            )
        )
        lines.append(
            "checks: root={} tracefs={} uprobe={} kprobe={} btf={} page_size={} selinux={}".format(
                checks.get("root"),
                checks.get("tracefs"),
                checks.get("uprobe_events"),
                checks.get("kprobe_events"),
                checks.get("btf"),
                checks.get("page_size"),
                checks.get("selinux"),
            )
        )
    for warning in report.get("warnings") or []:
        lines.append(f"warning: {warning}")
    return lines


def write_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doctor_json(report), encoding="utf-8")
