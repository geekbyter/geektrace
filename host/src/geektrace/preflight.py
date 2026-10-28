"""Preflight for an authorized app.

Two halves:

* static - read the APK and report what the app ships (dex files, native
  libraries, ABIs) plus which detection, crypto and network markers are
  present in its bytes. A static hit is a *candidate*: it says the app can
  perform the check, not that the check runs on this device.
* dynamic readiness - ask the device what it can actually deliver, so the
  plan states "supported" or "unsupported" before a capture starts.

The module never proposes a bypass, never touches the target, and never
claims an app is clean: an unreported check is "not observed", not "absent".
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any, Iterable

from .constants import TOOL_NAME
from .doctor import doctor_report

SCHEMA_ID = "geektrace.preflight.v1"

# Only ASCII markers are used: a static hit is a hint that needs a runtime
# check, so a fuzzy match would only add noise.
DETECTION_MARKERS: dict[str, tuple[str, ...]] = {
    "root": (
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "magisk",
        "busybox",
        "Superuser",
        "com.topjohnwu.magisk",
        "com.kernelsu",
    ),
    "hook_framework": (
        "xposed",
        "lsposed",
        "substrate",
        "frida",
        "/data/adb",
        "edxp",
        "de.robv.android.xposed",
    ),
    "debugger": (
        "isDebuggerConnected",
        "TracerPid",
        "android.os.Debug",
        "JDWP",
        "/proc/self/status",
        "ptrace",
        "waitForDebugger",
    ),
    "emulator": (
        "goldfish",
        "generic_x86",
        "sdk_gphone",
        "qemu",
        "vbox86",
    ),
    "adb_developer": (
        "ro.debuggable",
        "ro.secure",
        "ro.build.tags",
        "development_settings_enabled",
        "5555",
        "persist.sys.usb.config",
    ),
    "integrity": (
        "/proc/self/maps",
        "/proc/self/mem",
        "/proc/self/attr",
        "classes.dex",
        "META-INF",
        "getPackageInfo",
    ),
    "webview_bridge": (
        "addJavascriptInterface",
        "evaluateJavascript",
        "loadUrl",
        "WebView",
    ),
    "attestation_pinning": (
        "CertificatePinner",
        "X509TrustManager",
        "HostnameVerifier",
        "SafetyNet",
        "PlayIntegrity",
        "attest",
    ),
}

CRYPTO_MARKERS: tuple[str, ...] = (
    "AES/CBC",
    "AES/GCM",
    "AES/ECB",
    "RSA/ECB",
    "SHA-256",
    "SHA256",
    "MD5",
    "HMAC",
    "PBKDF2",
    "SecretKeySpec",
    "IvParameterSpec",
    "MessageDigest",
    "Cipher",
    "EVP_EncryptUpdate",
    "EVP_DecryptUpdate",
    "EVP_DigestSign",
    "SSL_write",
    "SSL_read",
)

NETWORK_MARKERS: tuple[str, ...] = (
    "https://",
    "http://",
    "api.",
    "User-Agent",
    "Content-Type",
    "application/x-www-form-urlencoded",
    "application/json",
    "okhttp",
    "retrofit",
    "Cronet",
    "grpc",
    "protobuf",
)

AXML_STRING_POOL = 0x0001
UTF8_FLAG = 0x100


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def axml_strings(data: bytes) -> list[str]:
    """Extract the string pool of a binary AndroidManifest.xml.

    Only the string pool is parsed; that is enough to list permissions and
    component names without a full AXML implementation.
    """
    if len(data) < 8:
        return []
    offset = 0
    # The document header (RES_XML_TYPE) spans the whole file; the string
    # pool is the first chunk inside it.
    if struct.unpack_from("<H", data, 0)[0] == 0x0003:
        offset = 8
    while offset + 8 <= len(data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size < 8 or offset + chunk_size > len(data):
            break
        if chunk_type == AXML_STRING_POOL:
            return _read_string_pool(data, offset, header_size, chunk_size)
        offset += chunk_size
    return []


def _read_string_pool(
    data: bytes, offset: int, header_size: int, chunk_size: int
) -> list[str]:
    count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    utf8 = bool(flags & UTF8_FLAG)
    offsets = struct.unpack_from(f"<{count}I", data, offset + header_size)
    base = offset + strings_start
    strings: list[str] = []
    for item in offsets:
        position = base + item
        if position >= offset + chunk_size or position >= len(data):
            strings.append("")
            continue
        try:
            if utf8:
                # utf16 length, byte length, bytes, NUL
                _, byte_length = struct.unpack_from("<BB", data, position)
                position += 2
                raw = data[position : position + byte_length]
                strings.append(raw.decode("utf-8", errors="replace"))
            else:
                (length,) = struct.unpack_from("<H", data, position)
                position += 2
                raw = data[position : position + length * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except struct.error:
            strings.append("")
    return strings


def _scan_markers(data: bytes, markers: Iterable[str]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for marker in markers:
        count = data.count(marker.encode("utf-8", errors="ignore"))
        if count:
            hits[marker] = count
    return hits


def _all_markers() -> tuple[str, ...]:
    markers: list[str] = []
    for values in DETECTION_MARKERS.values():
        markers.extend(values)
    return tuple(markers)


def inspect_apk(path: Path) -> dict[str, Any]:
    """Inventory an APK without executing anything."""
    result: dict[str, Any] = {
        "path": str(path),
        "sha256": None,
        "size": 0,
        "entries": 0,
        "dex_files": [],
        "native_libs": [],
        "abis": [],
        "asset_entries": 0,
        "manifest_strings": [],
        "detection_markers": {},
        "crypto_markers": {},
        "network_markers": {},
        "errors": [],
    }
    if not path.is_file():
        result["errors"].append("apk not found")
        return result
    result["size"] = path.stat().st_size
    result["sha256"] = _sha256(path.read_bytes())
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            result["entries"] = len(names)
            payload = bytearray()
            for name in names:
                lowered = name.lower()
                if lowered.startswith("classes") and lowered.endswith(".dex"):
                    result["dex_files"].append(name)
                    try:
                        payload += archive.read(name)
                    except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
                        result["errors"].append(f"{name}: {exc}")
                elif lowered.startswith("lib/") and lowered.endswith(".so"):
                    parts = name.split("/")
                    abi = parts[1] if len(parts) > 2 else "unknown"
                    if abi not in result["abis"]:
                        result["abis"].append(abi)
                    try:
                        blob = archive.read(name)
                    except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
                        result["errors"].append(f"{name}: {exc}")
                        continue
                    result["native_libs"].append(
                        {
                            "path": name,
                            "abi": abi,
                            "size": len(blob),
                            "sha256": _sha256(blob),
                            "elf": blob[:4] == b"\x7fELF",
                        }
                    )
                    payload += blob
                elif lowered.startswith("assets/"):
                    result["asset_entries"] += 1
                elif lowered == "androidmanifest.xml":
                    try:
                        result["manifest_strings"] = axml_strings(
                            archive.read(name)
                        )
                    except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
                        result["errors"].append(f"{name}: {exc}")
            data = bytes(payload)
            result["detection_markers"] = _scan_markers(data, _all_markers())
            result["crypto_markers"] = _scan_markers(data, CRYPTO_MARKERS)
            result["network_markers"] = _scan_markers(data, NETWORK_MARKERS)
    except zipfile.BadZipFile as exc:
        result["errors"].append(f"not a valid apk/zip: {exc}")
    return result


def detection_candidates(apk: dict[str, Any]) -> list[dict[str, Any]]:
    """Group the static marker hits into detection categories."""
    manifest = " ".join(apk.get("manifest_strings") or [])
    payload_markers = apk.get("detection_markers") or {}
    candidates: list[dict[str, Any]] = []
    for category, markers in DETECTION_MARKERS.items():
        hits = []
        for marker in markers:
            count = payload_markers.get(marker, 0)
            in_manifest = bool(marker) and marker in manifest
            if count or in_manifest:
                hits.append(
                    {
                        "marker": marker,
                        "count": count,
                        "in_manifest": in_manifest,
                    }
                )
        if hits:
            candidates.append(
                {
                    "category": category,
                    "status": "static_candidate",
                    "confidence": "inferred",
                    "observer": "static",
                    "hits": hits,
                }
            )
    return candidates


def device_readiness(serial: str | None) -> dict[str, Any]:
    """Ask the device what it supports, without starting a capture."""
    report = doctor_report(serial=serial, check_root=True)
    device = report.get("device") or {}
    checks = device.get("checks") or {}
    capabilities = {
        "root": bool(checks.get("root")),
        "tracefs": bool(checks.get("tracefs")),
        "uprobe_events": bool(checks.get("uprobe_events")),
        "kprobe_events": bool(checks.get("kprobe_events")),
        "btf": bool(checks.get("btf")),
        "page_size": checks.get("page_size"),
    }
    unsupported = [
        name
        for name in ("root", "tracefs", "uprobe_events")
        if not capabilities.get(name)
    ]
    return {
        "serial": device.get("serial"),
        "model": device.get("model"),
        "android": device.get("android"),
        "kernel": device.get("kernel"),
        "abi": device.get("abi"),
        "capabilities": capabilities,
        "unsupported": unsupported,
        "status": report.get("status"),
        "ready": bool(report.get("ready")),
        "warnings": report.get("warnings") or [],
    }


def build_probe_plan(profile: str = "ai") -> dict[str, Any]:
    """Describe the observation plan and what it costs the target."""
    payload_limit = {"ai": 255, "stealth": 64, "safe": 0}.get(profile, 255)
    stack = False
    probes = [
        {
            "id": "syscall.openat",
            "backend": "ebpf",
            "purpose": "文件读取路径与检测行为证据",
            "target_impact": "目标 UID 过滤，不修改返回值，不写目标内存",
            "stack": stack,
        },
        {
            "id": "syscall.connect",
            "backend": "ebpf",
            "purpose": "连接目标地址与端口",
            "target_impact": "仅记录入口参数，无返回时延",
            "stack": stack,
        },
        {
            "id": "lib.crypto",
            "backend": "ebpf-uprobe",
            "purpose": "EVP 调用方向、长度与输入输出头",
            "target_impact": (
                f"懒挂载：仅当目标映射该库时附加，payload 上限 {payload_limit}B"
            ),
            "stack": stack,
        },
        {
            "id": "lib.tls",
            "backend": "ebpf-uprobe",
            "purpose": "SSL 明文头，用于对齐请求内容",
            "target_impact": (
                f"懒挂载：仅当目标映射该库时附加，payload 上限 {payload_limit}B"
            ),
            "stack": stack,
        },
    ]
    notes = [
        "uprobe 会在被观测函数的入口放置断点，因此只在目标确实使用该库时才挂载。",
        "payload_limit=0 表示完全不读取目标内存，只保留元数据，扰动最小。",
        "开启 stack 会在每次 Focus 事件上取用户态栈，开销明显更高，按需开启。",
    ]
    if profile == "safe":
        notes.append("safe profile 不落明文与密钥，只保留结构、长度和调用位置。")
    return {
        "profile": profile,
        "payload_limit": payload_limit,
        "stack": stack,
        "probes": probes,
        "notes": notes,
    }


def build_preflight(
    apk_path: Path | None,
    *,
    app: str | None = None,
    serial: str | None = None,
    profile: str = "ai",
    device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .event import utc_now

    apk = inspect_apk(apk_path) if apk_path else {}
    readiness = device if device is not None else device_readiness(serial)
    plan = build_probe_plan(profile)
    limits = [
        "静态命中只说明 App 具备该检查能力，不能证明本次运行触发过。",
        "未触发的场景记为 not_exercised，不记为环境干净。",
        "Java AOT/JIT 方法与纯 Java 分支不在当前观测范围内。",
        "自研或白盒加密无法由 EVP 事件还原，需要静态分析配合。",
    ]
    return {
        "schema": SCHEMA_ID,
        "tool": {"name": TOOL_NAME},
        "generated_at": utc_now(),
        "app": app,
        "apk": apk,
        "static_detections": detection_candidates(apk) if apk else [],
        "device": readiness,
        "plan": plan,
        "limits": limits,
        "status": "planned",
    }


def render_markdown(report: dict[str, Any]) -> str:
    apk = report.get("apk") or {}
    device = report.get("device") or {}
    plan = report.get("plan") or {}
    lines = ["# geektrace preflight", ""]
    lines.append(f"- App: `{report.get('app') or 'unknown'}`")
    lines.append(f"- Generated: {report.get('generated_at')}")
    lines.append("")

    lines.append("## 1. APK inventory")
    lines.append("")
    if apk:
        lines.append(f"- Path: `{apk.get('path')}`")
        lines.append(f"- SHA256: `{apk.get('sha256') or 'n/a'}`")
        lines.append(f"- Size: {apk.get('size')} bytes, entries: {apk.get('entries')}")
        lines.append(f"- dex: {', '.join(apk.get('dex_files') or []) or 'none'}")
        lines.append(f"- ABIs: {', '.join(apk.get('abis') or []) or 'none'}")
        lines.append(f"- native libs: {len(apk.get('native_libs') or [])}")
        lines.append(f"- assets entries: {apk.get('asset_entries')}")
        if apk.get("errors"):
            lines.append(f"- errors: {'; '.join(apk['errors'])}")
    else:
        lines.append("_no APK supplied: static inventory skipped_")
    lines.append("")

    lines.append("## 2. Static detection candidates")
    lines.append("")
    candidates = report.get("static_detections") or []
    if candidates:
        lines.append("| category | status | markers |")
        lines.append("|---|---|---|")
        for item in candidates:
            markers = ", ".join(
                f"{hit['marker']}({hit['count']})" for hit in item.get("hits") or []
            )
            lines.append(
                f"| {item.get('category')} | {item.get('status')} | {markers} |"
            )
    else:
        lines.append("_no static candidate found_")
    lines.append("")
    lines.append(
        "> 静态命中是候选，不是结论；运行时是否触发要靠 `detect.finding` 回查。"
    )
    lines.append("")

    lines.append("## 3. Device readiness")
    lines.append("")
    if device:
        capabilities = device.get("capabilities") or {}
        lines.append(
            f"- Device: `{device.get('model')}` / `{device.get('android')}` / "
            f"kernel `{device.get('kernel')}`"
        )
        lines.append(
            "- capabilities: "
            + ", ".join(f"{key}={value}" for key, value in capabilities.items())
        )
        if device.get("unsupported"):
            lines.append(
                "- unsupported: " + ", ".join(device["unsupported"])
            )
        else:
            lines.append("- unsupported: none")
        for warning in device.get("warnings") or []:
            lines.append(f"- warning: {warning}")
    else:
        lines.append("_no device inspected_")
    lines.append("")

    lines.append("## 4. Observation plan")
    lines.append("")
    lines.append(
        f"- profile: `{plan.get('profile')}` | payload limit: "
        f"{plan.get('payload_limit')}B | stack: {plan.get('stack')}"
    )
    lines.append("")
    lines.append("| probe | backend | purpose | target impact |")
    lines.append("|---|---|---|---|")
    for probe in plan.get("probes") or []:
        lines.append(
            f"| `{probe.get('id')}` | {probe.get('backend')} | {probe.get('purpose')} | "
            f"{probe.get('target_impact')} |"
        )
    lines.append("")
    for note in plan.get("notes") or []:
        lines.append(f"- {note}")
    lines.append("")

    lines.append("## 5. Limits")
    lines.append("")
    for limit in report.get("limits") or []:
        lines.append(f"- {limit}")
    lines.append("")
    return "\n".join(lines)
