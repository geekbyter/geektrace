import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import LOG_PREFIX, SUMMARY_SCHEMA_ID
from .crypto_ops import build_crypto_operations, summarize_operations
from .event import validate_event, utc_now
from .index import build_event_index
from .runstore import iter_event_lines, load_manifest

FOCUS_LAYERS = {
    "session",
    "process",
    "loader",
    "art",
    "jni",
    "crypto",
    "net",
    "file",
    "detect",
    "tool",
}

KEY_KINDS = {
    "session.start",
    "session.stop",
    "process.fork",
    "process.rename",
    "loader.apk_open",
    "loader.dex_magic",
    "loader.dlopen",
    "loader.system_load_library",
    "jni.register",
    "art.method_enter",
    "crypto.op",
    "crypto.evp_init",
    "crypto.evp_update",
    "crypto.evp_final",
    "crypto.digest",
    "crypto.sign",
    "crypto.sign_update",
    "crypto.verify_update",
    "net.connect",
    "net.tls_handshake",
    "net.tls_write",
    "net.tls_read",
    "net.http_request",
    "net.http_response",
    "file.write",
    "file.read",
    "detect.finding",
    "tool.gap",
    "tool.drop",
}

MAX_LEDGER_ENTRIES = 500
MAX_TIMELINE_ENTRIES = 300
MAX_MARKDOWN_TIMELINE = 80


@dataclass
class RunData:
    run_dir: Path
    manifest: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)
    events_by_time: list[dict[str, Any]] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    seq_duplicates: list[int] = field(default_factory=list)
    seq_out_of_order: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)


def load_run(run_dir: Path) -> RunData:
    manifest = load_manifest(run_dir)
    data = RunData(run_dir=run_dir, manifest=manifest)
    seen: set[int] = set()
    last_seq = 0
    for path, line_no, line in iter_event_lines(run_dir):
        data.files.append(path)
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            data.parse_errors.append(f"{path.name}:{line_no}: {exc.msg}")
            continue
        errors = validate_event(event)
        if errors:
            for error in errors:
                data.validation_errors.append(f"{path.name}:{line_no}: {error}")
            continue
        seq = event["seq"]
        if seq in seen:
            data.seq_duplicates.append(seq)
        if seq <= last_seq:
            data.seq_out_of_order.append(f"seq {seq} after {last_seq}")
        seen.add(seq)
        last_seq = max(last_seq, seq)
        data.events.append(event)
    data.events.sort(key=lambda item: item["seq"])
    # seq is the broker consumption order; across CPUs the kernel timestamp is
    # the only reliable order, so the timeline uses mono_ns.
    data.events_by_time = sorted(
        data.events, key=lambda item: (item.get("mono_ns") or 0, item["seq"])
    )
    return data


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _arg(event: dict[str, Any], key: str, default: Any = None) -> Any:
    args = event.get("args")
    if isinstance(args, dict):
        return args.get(key, default)
    return default


def _first_arg(event: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for key in keys:
        value = _arg(event, key)
        if value is not None:
            return value
    return default


def _location_text(event: dict[str, Any]) -> str:
    location = event.get("location") or {}
    if not isinstance(location, dict):
        return ""
    module = location.get("module") or ""
    offset = location.get("file_offset") or ""
    symbol = location.get("symbol") or ""
    base = f"{module}+{offset}" if module and offset else module or offset or ""
    if symbol:
        return f"{base}({symbol})" if base else symbol
    return base


def _connection_id(event: dict[str, Any]) -> str | None:
    correlation = event.get("correlation") or {}
    return correlation.get("connection_id") if isinstance(correlation, dict) else None


def _call_id(event: dict[str, Any]) -> str | None:
    correlation = event.get("correlation") or {}
    return correlation.get("call_id") if isinstance(correlation, dict) else None


def summarize_event(event: dict[str, Any]) -> str:
    kind = event["kind"]
    if kind == "session.start":
        return f"start app={_arg(event, 'app', '')} profile={_arg(event, 'profile', '')}"
    if kind == "session.stop":
        return f"stop status={_arg(event, 'status', '')}"
    if kind == "process.fork":
        child = _arg(event, "child_pid", event.get("pid"))
        parent = _arg(event, "ppid", event.get("pid"))
        comm = _arg(event, "child_comm", event.get("comm"))
        return f"fork pid={child} ppid={parent} comm={comm}"
    if kind == "process.rename":
        return f"rename pid={event.get('pid')} -> {_arg(event, 'name', event.get('comm'))}"
    if kind.startswith("loader."):
        path = _first_arg(event, ("path", "name", "library", "apk"), "")
        return f"{kind} {path}"
    if kind.startswith("art."):
        return f"{_arg(event, 'method', '')}{_arg(event, 'signature', '')}".strip()
    if kind.startswith("jni."):
        return f"{_arg(event, 'name', '')} {_arg(event, 'signature', '')}".strip()
    if kind.startswith("crypto."):
        alg = _arg(event, "alg", "")
        direction = _arg(event, "dir", "")
        length = _first_arg(event, ("input_len", "data_len", "output_len"), "")
        return " ".join(str(part) for part in (alg, direction, length) if part != "")
    if kind.startswith("net."):
        http = _arg(event, "http") or {}
        if not isinstance(http, dict):
            http = {}
        method = http.get("method") or _arg(event, "method")
        path = http.get("path") or _arg(event, "path")
        url = http.get("url") or _arg(event, "url")
        status = http.get("status") or _arg(event, "status")
        if method or path:
            return f"{method or ''} {url or path or ''}".strip()
        if status is not None:
            return f"HTTP {status}"
        if kind.startswith("net.tls_"):
            direction = _arg(event, "dir", kind.removeprefix("net.tls_"))
            length = _first_arg(event, ("len", "plaintext_len", "input_len"), "")
            sni = _arg(event, "sni", "")
            return " ".join(
                str(part) for part in (direction, sni, length) if part != ""
            )
        host = _first_arg(event, ("sni", "host", "address", "url"), "")
        port = _arg(event, "port", "")
        return f"{host}:{port}" if host and port else str(host or "")
    if kind.startswith("file."):
        return str(_first_arg(event, ("path", "file", "target"), ""))
    if kind == "detect.finding":
        return f"{_arg(event, 'category', '')} verdict={_arg(event, 'verdict', 'observed')}"
    if kind == "tool.gap":
        return str(_arg(event, "message", _arg(event, "reason", "")))
    if kind == "tool.drop":
        return f"dropped={_arg(event, 'count', '')} reason={_arg(event, 'reason', '')}"
    return ""


def _sanitize_args(value: Any, key: str = "") -> Any:
    if key.endswith("_b64") or key in ("key", "iv", "plaintext", "password", "token"):
        return "<see events.jsonl>"
    if isinstance(value, dict):
        return {item_key: _sanitize_args(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize_args(item) for item in value]
    return value


def _event_entry(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "seq": event["seq"],
        "ts": event["ts"],
        "layer": event["layer"],
        "kind": event["kind"],
        "confidence": event["confidence"],
        "pid": event.get("pid"),
        "comm": event.get("comm"),
        "thread": event.get("thread"),
        "location": _location_text(event),
        "summary": summarize_event(event),
        "args": _sanitize_args(event.get("args") or {}),
        "correlation": event.get("correlation") or {},
        "evidence_ids": event.get("evidence_ids") or [],
        "policy": event.get("policy") or {},
    }


def _cap(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "count": len(entries),
        "truncated": len(entries) > MAX_LEDGER_ENTRIES,
        "entries": entries[:MAX_LEDGER_ENTRIES],
    }


def _crypto_ledger(events: list[dict[str, Any]]) -> dict[str, Any]:
    # Entry and return events describe one crypto call, so the ledger reports
    # calls, not raw events. A call without its return half stays partial.
    operations = build_crypto_operations(events)
    algorithms: set[str] = set()
    for event in events:
        if event.get("layer") != "crypto":
            continue
        alg = _arg(event, "alg")
        if alg:
            algorithms.add(str(alg))
    entries = []
    for operation in operations:
        location = operation.get("location") or {}
        entries.append(
            {
                "op_id": operation["op_id"],
                "call_id": operation.get("call_id"),
                "seq": (operation.get("seqs") or [None])[0],
                "seqs": operation.get("seqs") or [],
                "ts": operation.get("ts"),
                "kind": "crypto.operation",
                "alg": None,
                "fn": operation.get("fn"),
                "dir": operation.get("dir"),
                "key_sha256": None,
                "iv_sha256": None,
                "input_len": operation.get("input_len"),
                "output_len": operation.get("output_len"),
                "ret": operation.get("ret"),
                "input_head_hex": operation.get("input_head_hex"),
                "output_head_hex": operation.get("output_head_hex"),
                "complete": operation.get("complete"),
                "confidence": operation.get("confidence"),
                "matched_by": operation.get("matched_by"),
                "location": location.get("text"),
                "stack_frames": operation.get("stack_frames"),
                "capture_status": operation.get("capture_status"),
            }
        )
    return {
        "operations": _cap(entries),
        "summary": summarize_operations(operations),
        "algorithms": sorted(algorithms),
        "key_sha256": [],
    }


def _capture_integrity(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    missing = 0
    for event in events:
        policy = event.get("policy") or {}
        status = policy.get("capture_status")
        if not status:
            missing += 1
            continue
        counts[status] = counts.get(status, 0) + 1
    return {"counts": counts, "without_status": missing}


def _capabilities(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries = []
    for event in events:
        if event.get("kind") != "tool.capability":
            continue
        args = event.get("args") or {}
        entries.append(
            {
                "seq": event.get("seq"),
                "ts": event.get("ts"),
                "transport": args.get("transport"),
                "user_read": args.get("user_read"),
                "uprobe_mode": args.get("uprobe_mode"),
                "payload_limit": args.get("payload_limit"),
                "stack": args.get("stack"),
                "stack_supported": args.get("stack_supported"),
                "paired_uprobes": args.get("paired_uprobes"),
                "probes_attached": args.get("probes_attached"),
                "probes_total": args.get("probes_total"),
                "libssl": args.get("libssl"),
                "libcrypto": args.get("libcrypto"),
                "libraries": args.get("libraries"),
                "library_copies": args.get("library_copies"),
                "lib_copy_limit": args.get("lib_copy_limit"),
                "shared_copies": args.get("shared_copies"),
            }
        )
    return entries


def _footprint(events: list[dict[str, Any]]) -> dict[str, Any]:
    """What the target (or another process on the device) can observe about us.

    This is a static checklist derived from the events, not a claim that the
    trace is invisible. It exists so a review can see the footprint instead of
    trusting a "stealth" label.
    """
    capability = _capabilities(events)
    last = capability[-1] if capability else {}
    copies = int(last.get("library_copies") or 0)
    shared = int(last.get("shared_copies") or 0)
    probes = int(last.get("probes_attached") or 0)
    payload_limit = last.get("payload_limit")
    uprobe_mode = last.get("uprobe_mode")

    surfaces = [
        {
            "surface": "root / KernelSU",
            "visible": True,
            "note": "设备已 root；任何检查 root 的 App 都能看到（本工具不隐藏）",
        },
        {
            "surface": "broker 进程与二进制",
            "visible": True,
            "note": "geektraced 在 /proc 中可见，默认位于 /data/local/tmp/geektrace",
        },
        {
            "surface": "tracefs 探针定义",
            "visible": True,
            "note": "uprobe_events 中存在 geektrace/* 定义，仅 root 可读",
        },
        {
            "surface": "共享库代码页断点",
            "visible": shared > 0,
            "note": (
                f"{shared} 份共享库副本被打了断点，完整性校验可发现"
                if shared
                else "只使用 App 私有副本或未挂载，代码页不被改动"
            ),
        },
        {
            "surface": "目标进程内 agent/线程",
            "visible": False,
            "note": "无注入、无新线程、TracerPid=0",
        },
        {
            "surface": "目标文件与内存写入",
            "visible": False,
            "note": "只读；不修改目标文件、不写目标内存、不改返回值",
        },
        {
            "surface": "时序与 CPU 扰动",
            "visible": probes > 0,
            "note": f"{probes} 个探针实例；高频加密会放大开销",
        },
    ]
    return {
        "library_copies": copies,
        "shared_copies": shared,
        "lib_copy_limit": last.get("lib_copy_limit"),
        "probes_attached": probes,
        "uprobe_mode": uprobe_mode,
        "payload_limit": payload_limit,
        "surfaces": surfaces,
        "note": (
            "足迹清单是事实汇总，不是隐身证明；绝对无痕不成立。"
            "减少副本数、payload 上限与观测窗口只能降低命中概率。"
        ),
    }


def _network_ledger(events: list[dict[str, Any]]) -> dict[str, Any]:
    connections = []
    http = []
    tls = []
    hosts: set[str] = set()
    for event in events:
        if event["layer"] != "net":
            continue
        entry = _event_entry(event)
        connection = _connection_id(event)
        if connection:
            entry["connection_id"] = connection
        kind = event["kind"]
        if kind == "net.connect":
            address = _first_arg(event, ("address", "host", "ip"))
            port = _arg(event, "port")
            if address:
                hosts.add(str(address))
            entry["address"] = address
            entry["port"] = port
            connections.append(entry)
        elif kind.startswith("net.http_"):
            http_data = _arg(event, "http") or {}
            if not isinstance(http_data, dict):
                http_data = {}
            entry["http"] = http_data
            for key in ("host", "url"):
                if http_data.get(key):
                    hosts.add(str(http_data[key]))
            entry["method"] = _first_arg(event, ("method",), http_data.get("method"))
            entry["path"] = _arg(event, "path") or http_data.get("path")
            entry["status"] = _arg(event, "status") or http_data.get("status")
            http.append(entry)
        elif kind.startswith("net.tls_"):
            sni = _arg(event, "sni")
            if sni:
                hosts.add(str(sni))
            entry["sni"] = sni
            tls.append(entry)
    return {
        "connections": _cap(connections),
        "http": _cap(http),
        "tls": _cap(tls),
        "hosts": sorted(hosts),
    }


def _file_ledger(events: list[dict[str, Any]]) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    events_count = {"open": 0, "read": 0, "write": 0, "meta": 0, "other": 0}
    private_paths: set[str] = set()
    for event in events:
        if event["layer"] != "file":
            continue
        path = str(_first_arg(event, ("path", "file", "target"), ""))
        kind = event["kind"].split(".", 1)[-1]
        events_count[kind if kind in events_count else "other"] += 1
        if not path:
            continue
        record = paths.setdefault(
            path,
            {
                "path": path,
                "first_seq": event["seq"],
                "last_seq": event["seq"],
                "open": 0,
                "read": 0,
                "write": 0,
                "meta": 0,
                "bytes_read": 0,
                "bytes_written": 0,
                "sha256": None,
                "private": False,
            },
        )
        record[kind if kind in ("open", "read", "write", "meta") else "meta"] += 1
        record["last_seq"] = event["seq"]
        length = _first_arg(event, ("len", "bytes", "size", "count"))
        if _is_number(length):
            if kind == "read":
                record["bytes_read"] += int(length)
            elif kind == "write":
                record["bytes_written"] += int(length)
        sha = _arg(event, "sha256")
        if sha:
            record["sha256"] = sha
        if path.startswith(("/data/user/0/", "/data/data/", "/data/user_de/0/")):
            record["private"] = True
            private_paths.add(path)
    entries = sorted(paths.values(), key=lambda item: item["last_seq"])
    return {
        "events": events_count,
        "paths": _cap(entries),
        "private_paths": sorted(private_paths)[:200],
    }


def _detections(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_seq = {event["seq"]: event for event in events}
    findings = []
    for event in events:
        if event["kind"] != "detect.finding":
            continue
        evidence = []
        for evidence_id in event.get("evidence_ids") or []:
            target = by_seq.get(evidence_id)
            if target:
                evidence.append(_event_entry(target))
        findings.append(
            {
                "seq": event["seq"],
                "ts": event["ts"],
                "category": _arg(event, "category"),
                "verdict": _arg(event, "verdict", "observed"),
                "confidence": event["confidence"],
                "summary": summarize_event(event),
                "evidence_ids": event.get("evidence_ids") or [],
                "evidence": evidence,
                "args": event.get("args") or {},
            }
        )
    return findings


def _tools(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    gaps = []
    drops = []
    for event in events:
        if event["kind"] == "tool.gap":
            gaps.append(_event_entry(event))
        elif event["kind"] == "tool.drop":
            drops.append(_event_entry(event))
    return gaps, drops


def _integrity(data: RunData, events: list[dict[str, Any]]) -> dict[str, Any]:
    seqs = [event["seq"] for event in events]
    missing = []
    for previous, current in zip(seqs, seqs[1:]):
        if current > previous + 1:
            missing.append(f"{previous + 1}-{current - 1}")
    confidence: dict[str, int] = {}
    for event in events:
        confidence[event["confidence"]] = confidence.get(event["confidence"], 0) + 1
    policy_counts = {
        "truncated": sum(1 for event in events if (event.get("policy") or {}).get("truncated")),
        "redacted": sum(1 for event in events if (event.get("policy") or {}).get("redacted")),
        "sensitive": sum(1 for event in events if (event.get("policy") or {}).get("sensitive")),
        "sampled": sum(1 for event in events if (event.get("policy") or {}).get("sampled")),
    }
    return {
        "event_count": len(events),
        "parse_errors": data.parse_errors,
        "validation_errors": data.validation_errors,
        "seq_duplicates": data.seq_duplicates,
        "seq_out_of_order": data.seq_out_of_order,
        "seq_gaps": missing[:200],
        "seq_gaps_truncated": len(missing) > 200,
        "confidence": confidence,
        "policy": policy_counts,
    }


def build_summary(data: RunData) -> dict[str, Any]:
    events = data.events
    ordered = data.events_by_time or events
    counts_by_layer: dict[str, int] = {}
    counts_by_kind: dict[str, int] = {}
    for event in events:
        counts_by_layer[event["layer"]] = counts_by_layer.get(event["layer"], 0) + 1
        counts_by_kind[event["kind"]] = counts_by_kind.get(event["kind"], 0) + 1

    start = ordered[0] if ordered else None
    end = ordered[-1] if ordered else None
    duration_ms = None
    if start and end:
        duration_ms = round(
            (end["mono_ns"] - start["mono_ns"]) / 1_000_000, 3
        )

    gaps, drops = _tools(events)
    detections = _detections(events)
    crypto = _crypto_ledger(events)
    network = _network_ledger(events)
    files = _file_ledger(events)
    capabilities = _capabilities(events)

    timeline = [
        _event_entry(event)
        for event in ordered
        if event["layer"] in FOCUS_LAYERS and event["kind"] in KEY_KINDS
    ]

    manifest = data.manifest
    summary = {
        "schema": SUMMARY_SCHEMA_ID,
        "session": manifest.get("session"),
        "generated_at": utc_now(),
        "demo": bool(manifest.get("demo")),
        "status": manifest.get("status"),
        "app": manifest.get("app"),
        "profile": manifest.get("profile"),
        "mode": manifest.get("mode"),
        "backend": manifest.get("backend"),
        "transport": manifest.get("transport"),
        "device": manifest.get("device"),
        "target": manifest.get("target"),
        "environment_modified": manifest.get("environment_modified"),
        "artifacts": {
            "events": "events.jsonl",
            "event_index": "events/index.json",
            "readme": "README.log.md",
        },
        "time_range": {
            "start_ts": start["ts"] if start else None,
            "end_ts": end["ts"] if end else None,
            "duration_ms": duration_ms,
        },
        "counts": {
            "events": len(events),
            "by_layer": dict(sorted(counts_by_layer.items())),
            "by_kind": dict(sorted(counts_by_kind.items())),
        },
        "crypto": crypto,
        "network": network,
        "files": files,
        "detections": detections,
        "gaps": _cap(gaps),
        "drops": _cap(drops),
        "capture": _capture_integrity(events),
        "capability": capabilities,
        "footprint": _footprint(events),
        "timeline": {
            "count": len(timeline),
            "truncated": len(timeline) > MAX_TIMELINE_ENTRIES,
            "entries": timeline[:MAX_TIMELINE_ENTRIES],
        },
        "integrity": _integrity(data, events),
        "analysis_hints": _analysis_hints(crypto, network, files, detections, gaps, drops),
    }
    return summary


def _analysis_hints(
    crypto: dict[str, Any],
    network: dict[str, Any],
    files: dict[str, Any],
    detections: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
    drops: list[dict[str, Any]],
) -> list[str]:
    hints = []
    if crypto["algorithms"]:
        hints.append(
            "Crypto algorithms observed: " + ", ".join(crypto["algorithms"])
        )
    elif crypto["operations"]["count"]:
        hints.append(
            f"Crypto operations observed: {crypto['operations']['count']}, "
            "but algorithm names were not resolved"
        )
    network_events = (
        network["connections"]["count"]
        + network["http"]["count"]
        + network["tls"]["count"]
    )
    if network["hosts"]:
        hints.append("Network hosts observed: " + ", ".join(network["hosts"][:10]))
    elif network_events:
        hints.append(
            f"Network/TLS events observed: {network_events}, "
            "but hosts and HTTP metadata were not resolved"
        )
    if files["private_paths"]:
        hints.append(
            f"Private-directory paths observed: {len(files['private_paths'])}"
        )
    if detections:
        categories = sorted({str(item.get("category")) for item in detections})
        hints.append("Detection checks observed: " + ", ".join(categories))
    if gaps:
        hints.append(f"Capability gaps recorded: {len(gaps)}; read gaps before conclusions")
    if drops:
        hints.append(f"Event drops recorded: {len(drops)}; coverage may be incomplete")
    if not hints:
        hints.append("No crypto/network/detection events in this run")
    return hints


def _md_cell(value: Any, limit: int = 100) -> str:
    if value is None:
        return ""
    text = str(value).replace("\n", " ").replace("|", "\\|")
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _fmt_len(value: Any) -> str:
    return str(value) if value is not None else ""


def _render_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    demo = summary["demo"]
    lines.append(f"# geektrace session `{summary['session']}`")
    lines.append("")
    if demo:
        lines.append(
            "> **DEMO DATA**: this run is synthetic and was not captured from a device."
        )
        lines.append("")
    lines.append(f"- App: `{summary['app']}`")
    lines.append(
        f"- Profile: `{summary['profile']}` | Backend: `{summary['backend']}` | "
        f"Mode: `{summary['mode']}` | Status: `{summary['status']}`"
    )
    device = summary.get("device") or {}
    lines.append(
        f"- Device: `{device.get('serial')}` | model: `{device.get('model')}` | "
        f"Android: `{device.get('android')}` | kernel: `{device.get('kernel')}`"
    )
    target = summary.get("target") or {}
    if target:
        tracer = target.get("tracer_pid")
        tracer_note = " (sampled; no debugger at that instant)" if tracer == 0 else ""
        lines.append(
            f"- Target: `{target.get('name')}` pid: `{target.get('pid')}` | "
            f"TracerPid: `{tracer}`{tracer_note} | threads: `{target.get('threads')}`"
        )
    time_range = summary["time_range"]
    lines.append(
        f"- Events: **{summary['counts']['events']}** | duration: "
        f"**{time_range['duration_ms']} ms** | window: `{time_range['start_ts']}` -> "
        f"`{time_range['end_ts']}`"
    )
    lines.append(
        f"- Environment modified: `{summary['environment_modified']}` | "
        f"Generated: `{summary['generated_at']}`"
    )
    lines.append("")

    lines.append("## 1. 关键结论")
    lines.append("")
    lines.append(
        f"1. 观察到 {summary['counts']['events']} 条事件；"
        f"其中 exact={summary['integrity']['confidence'].get('exact', 0)}，"
        f"inferred={summary['integrity']['confidence'].get('inferred', 0)}，"
        f"partial={summary['integrity']['confidence'].get('partial', 0)}。"
    )
    if summary["crypto"]["algorithms"]:
        lines.append(
            "2. Crypto 算法：`"
            + "`, `".join(summary["crypto"]["algorithms"])
            + "`；key/明文原值见 events.jsonl（受 policy 控制）。"
        )
    elif summary["crypto"]["operations"]["count"]:
        lines.append(
            f"2. 观察到 {summary['crypto']['operations']['count']} 条 crypto 操作，"
            "但算法名尚未解析（PoC 仅记录函数/方向/长度）；明细见 Crypto Ledger。"
        )
    else:
        lines.append("2. 未观察到 crypto 事件。")
    network_seen = (
        summary["network"]["connections"]["count"]
        + summary["network"]["http"]["count"]
        + summary["network"]["tls"]["count"]
    )
    if summary["network"]["hosts"]:
        lines.append(
            "3. 网络目标：`"
            + "`, `".join(summary["network"]["hosts"][:12])
            + "`，HTTP 事件 "
            + str(summary["network"]["http"]["count"])
            + " 条。"
        )
    elif network_seen:
        lines.append(
            f"3. 观察到 {network_seen} 条网络/TLS 事件，但未解析 host/HTTP"
            "（PoC 仅记录 SSL_write/read 长度与明文头）；明细见 Network Ledger。"
        )
    else:
        lines.append("3. 未观察到网络事件。")
    if summary["detections"]:
        lines.append(
            "4. 检测行为："
            + "；".join(
                f"{item.get('category')}({item.get('verdict')}, seq={item['seq']})"
                for item in summary["detections"][:10]
            )
            + "。"
        )
    else:
        lines.append("4. 未观察到 detect.finding。")
    hint_text = "；".join(summary["analysis_hints"])
    lines.append(f"5. 分析提示：{hint_text}。")
    lines.append("")

    lines.append("## 2. 启动与加载链")
    lines.append("")
    startup = [
        entry
        for entry in summary["timeline"]["entries"]
        if entry["layer"] in ("session", "process", "loader", "art", "jni")
    ]
    if startup:
        lines.append("| seq | ts | layer | kind | detail | location |")
        lines.append("|---:|---|---|---|---|---|")
        for entry in startup[:MAX_MARKDOWN_TIMELINE]:
            lines.append(
                f"| {entry['seq']} | {_md_cell(entry['ts'], 30)} | {entry['layer']} | "
                f"{entry['kind']} | {_md_cell(entry['summary'], 120)} | "
                f"{_md_cell(entry['location'], 80)} |"
            )
    else:
        lines.append("_No startup/loader events._")
    lines.append("")

    lines.append("## 3. Crypto Ledger")
    lines.append("")
    ops = summary["crypto"]["operations"]
    if ops["entries"]:
        lines.append("| seq | fn | dir | in | out | state | capture | location |")
        lines.append("|---:|---|---|---:|---:|---|---|---|")
        for op in ops["entries"][:MAX_MARKDOWN_TIMELINE]:
            state = "complete" if op.get("complete") else "partial"
            capture = ",".join(op.get("capture_status") or []) or "-"
            lines.append(
                f"| {op['seq']} | {_md_cell(op.get('fn'), 28)} | "
                f"{_md_cell(op.get('dir'), 12)} | "
                f"{_fmt_len(op.get('input_len'))} | {_fmt_len(op.get('output_len'))} | "
                f"{state} | {capture} | {_md_cell(op.get('location'), 70)} |"
            )
        if ops["truncated"]:
            lines.append("")
            lines.append(
                f"_Showing {len(ops['entries'])} of {ops['count']} operations._"
            )
    else:
        lines.append("_No crypto events._")
    lines.append("")

    lines.append("## 4. Network Ledger")
    lines.append("")
    network = summary["network"]
    if (
        network["http"]["entries"]
        or network["connections"]["entries"]
        or network["tls"]["count"]
    ):
        if network["http"]["entries"] or network["connections"]["entries"]:
            lines.append("| seq | kind | summary | connection | confidence |")
            lines.append("|---:|---|---|---|---|")
            for entry in network["connections"]["entries"][:40]:
                lines.append(
                    f"| {entry['seq']} | {entry['kind']} | {_md_cell(entry['summary'], 80)} | "
                    f"{_md_cell(entry.get('connection_id'), 20)} | {entry['confidence']} |"
                )
            for entry in network["http"]["entries"][:60]:
                lines.append(
                    f"| {entry['seq']} | {entry['kind']} | {_md_cell(entry['summary'], 90)} | "
                    f"{_md_cell(entry.get('connection_id'), 20)} | {entry['confidence']} |"
                )
        if network["tls"]["count"]:
            if network["http"]["entries"] or network["connections"]["entries"]:
                lines.append("")
            lines.append(f"TLS events: {network['tls']['count']} (details in events.jsonl).")
    else:
        lines.append("_No network events._")
    lines.append("")

    lines.append("## 5. File Ledger")
    lines.append("")
    file_paths = summary["files"]["paths"]
    if file_paths["entries"]:
        lines.append("| path | open | read | write | bytes_r | bytes_w | sha256 | private |")
        lines.append("|---|---:|---:|---:|---:|---:|---|---|")
        for record in file_paths["entries"][:MAX_MARKDOWN_TIMELINE]:
            lines.append(
                f"| {_md_cell(record['path'], 100)} | {record['open']} | "
                f"{record['read']} | {record['write']} | {record['bytes_read']} | "
                f"{record['bytes_written']} | {_md_cell(record['sha256'], 18)} | "
                f"{record['private']} |"
            )
    else:
        lines.append("_No file events._")
    lines.append("")

    lines.append("## 6. Detection Findings")
    lines.append("")
    if summary["detections"]:
        lines.append("| seq | category | verdict | confidence | evidence |")
        lines.append("|---:|---|---|---|---|")
        for finding in summary["detections"]:
            evidence = ", ".join(
                f"{item['seq']}:{item['kind']}" for item in finding.get("evidence", [])
            )
            lines.append(
                f"| {finding['seq']} | {_md_cell(finding.get('category'), 30)} | "
                f"{_md_cell(finding.get('verdict'), 20)} | {finding['confidence']} | "
                f"{_md_cell(evidence, 100)} |"
            )
    else:
        lines.append("_No detection findings._")
    lines.append("")

    lines.append("## 7. Gaps and Drops")
    lines.append("")
    if summary["gaps"]["entries"] or summary["drops"]["entries"]:
        lines.append("| seq | kind | detail |")
        lines.append("|---:|---|---|")
        for entry in summary["gaps"]["entries"][:40] + summary["drops"]["entries"][:40]:
            lines.append(
                f"| {entry['seq']} | {entry['kind']} | {_md_cell(entry['summary'], 140)} |"
            )
    else:
        lines.append("_No gaps or drops recorded._")
    lines.append("")

    lines.append("## 8. Integrity")
    lines.append("")
    integrity = summary["integrity"]
    lines.append(f"- Parse errors: {len(integrity['parse_errors'])}")
    lines.append(f"- Schema errors: {len(integrity['validation_errors'])}")
    lines.append(f"- Duplicate seq: {len(integrity['seq_duplicates'])}")
    lines.append(f"- Out-of-order seq: {len(integrity['seq_out_of_order'])}")
    lines.append(f"- Seq gaps: {', '.join(integrity['seq_gaps']) or 'none'}")
    lines.append(
        f"- Truncated events: {integrity['policy']['truncated']} | "
        f"redacted: {integrity['policy']['redacted']} | "
        f"sensitive: {integrity['policy']['sensitive']}"
    )
    capture = summary.get("capture") or {}
    if capture.get("counts"):
        lines.append(
            "- Capture status: "
            + ", ".join(
                f"{key}={value}"
                for key, value in sorted(capture["counts"].items())
            )
        )
    if capture.get("without_status"):
        lines.append(
            f"- Events without capture status: {capture['without_status']}"
        )
    if integrity["parse_errors"]:
        lines.append("")
        lines.append("Parse errors are listed in summary.json; do not trust missing data.")
    lines.append("")

    capabilities = summary.get("capability") or []
    if capabilities:
        lines.append("## 8.1 Device capability")
        lines.append("")
        lines.append(
            "| seq | transport | user read | uprobe mode | payload limit | "
            "stack | probes | library copies | libs |"
        )
        lines.append("|---:|---|---|---|---:|---|---:|---:|---|")
        for item in capabilities:
            libs = item.get("libraries") or ", ".join(
                str(value)
                for value in (item.get("libssl"), item.get("libcrypto"))
                if value
            )
            lines.append(
                f"| {item.get('seq')} | {item.get('transport')} | "
                f"{item.get('user_read')} | {item.get('uprobe_mode')} | "
                f"{item.get('payload_limit')} | {item.get('stack')} | "
                f"{item.get('probes_attached')}/{item.get('probes_total')} | "
                f"{item.get('library_copies', '-')} | "
                f"{_md_cell(libs, 60)} |"
            )
        lines.append("")

    footprint = summary.get("footprint") or {}
    if footprint:
        lines.append("## 8.2 Footprint / 可见面")
        lines.append("")
        lines.append(
            f"- 库副本: {footprint.get('library_copies')} 份，其中共享 "
            f"{footprint.get('shared_copies')} 份（crypto 上限 "
            f"{footprint.get('lib_copy_limit')}/类，TLS 固定 1 份） | 探针: "
            f"{footprint.get('probes_attached')} | uprobe 模式: "
            f"`{footprint.get('uprobe_mode')}` | payload 上限: "
            f"{footprint.get('payload_limit')}B"
        )
        lines.append("")
        lines.append("| 可见面 | 本次可见 | 说明 |")
        lines.append("|---|---|---|")
        for item in footprint.get("surfaces") or []:
            lines.append(
                f"| {item.get('surface')} | {'是' if item.get('visible') else '否'} | "
                f"{_md_cell(item.get('note'), 140)} |"
            )
        lines.append("")
        lines.append(f"_{_md_cell(footprint.get('note'), 200)}_")
        lines.append("")

    lines.append("## 9. 读取方式")
    lines.append("")
    lines.append(
        "`events.jsonl` 是唯一事实源；本摘要和 `summary.json` 是派生视图。"
        "先用本文件定位 seq，再按 seq 回查原始事件、`policy` 与 `evidence_ids`。"
        "字段含义与筛选示例见 `README.log.md`。"
    )
    lines.append("")
    return "\n".join(lines)


def _render_readme(summary: dict[str, Any]) -> str:
    demo_note = (
        "\n> **DEMO DATA**: this run is synthetic and was not captured from a device.\n"
        if summary["demo"]
        else ""
    )
    return f"""# geektrace log guide

Session: `{summary['session']}`  
App: `{summary['app']}`  
Profile: `{summary['profile']}` | Backend: `{summary['backend']}`  
{demo_note}
## Files

| File | Purpose |
|---|---|
| `manifest.json` | Session/device/config/status; authoritative metadata |
| `events.jsonl` | Canonical event stream, one JSON object per line |
| `events/part-*.jsonl` | Continuation parts after the primary file reaches the configured size limit |
| `events/part-*.jsonl.gz` | Compressed continuation parts after `geektrace compact`; the primary file stays plain |
| `events/index.json` | Per-part seq/ts ranges, counts, sizes, and SHA-256 for navigating large runs |
| `summary.md` | Human/AI short report; start here |
| `summary.json` | Machine-readable counts, ledgers, findings, gaps, integrity |
| `README.log.md` | This guide |
| `schema/event.v1.json` | JSON Schema for events |
| `logs/geektrace.log` | Human log, lines start with `{LOG_PREFIX}` |

Large runs: `geektrace compact <run_dir>` gzips only `events/part-*.jsonl` and rebuilds
`events/index.json`; `events.jsonl` remains directly readable. Seq ids are unchanged, so
summary findings still resolve against the raw stream.

## Event fields

| Field | Meaning |
|---|---|
| `schema` | Always `geektrace.event.v1` |
| `seq` | Monotonic event id within the session |
| `session` | Run id |
| `ts` | RFC3339 UTC, for pcap/logcat alignment |
| `mono_ns` | Monotonic nanoseconds, for ordering |
| `layer` | `session/process/loader/art/jni/syscall/file/net/crypto/binder/detect/coverage/stack/tool` |
| `kind` | Dotted event name, e.g. `crypto.evp_update` |
| `backend` | `ebpf/kpm/qbdi/import/demo` |
| `confidence` | `exact` directly observed, `inferred` from cross-event evidence, `partial` missing fields |
| `pid/tid/uid/comm/thread` | Process/thread context; null when not applicable |
| `location` | Module/build-id/file offset/symbol |
| `args` | Layer-specific payload |
| `correlation` | `call_id`, `connection_id`, `parent_id`, `request_id` |
| `stack` | Optional frames; empty when stack capture is off |
| `policy` | `redacted/sensitive/truncated/sampled/omitted_bytes`; distinguishes "not captured" from "empty" |
| `evidence_ids` | Seq ids backing a finding |

## Reading recipes

Python (works on any OS):

```python
import json

for line in open("events.jsonl", encoding="utf-8"):
    event = json.loads(line)
    if event["layer"] in ("crypto", "net"):
        print(event["seq"], event["kind"], event["args"])
```

Navigate a large or compacted run without loading all events:

```python
import gzip
import json

index = json.load(open("events/index.json", encoding="utf-8"))
for part in index["parts"]:
    print(part["file"], part["first_seq"], part["last_seq"], part["events"], part["compressed"])

# Compressed continuation part:
for line in gzip.open("events/part-00002.jsonl.gz", "rt", encoding="utf-8"):
    event = json.loads(line)
```

Filter a finding's evidence:

```python
import json

events = [json.loads(line) for line in open("events.jsonl", encoding="utf-8")]
by_seq = {{event["seq"]: event for event in events}}
for event in events:
    if event["kind"] == "detect.finding":
        print(event["args"])
        for evidence_id in event.get("evidence_ids", []):
            print("  ", json.dumps(by_seq[evidence_id], ensure_ascii=False))
```

With `jq` (optional):

```bash
jq -c 'select(.layer=="crypto")' events.jsonl
```

## Interpretation rules

- `confidence=inferred` is a hypothesis from timing/ids; verify against raw events.
- A missing event is not proof of absence if `tool.gap`, `tool.drop`, or `policy` says data was lost/omitted.
- `manifest.json` `budget_exceeded` or status `budget_exceeded` means capture stopped at a configured cap; do not treat the tail as complete.
- Demo runs (`backend=demo`, manifest `demo=true`) are synthetic fixtures; never treat them as device evidence.
"""


def generate_summary(run_dir: Path) -> dict[str, Path]:
    data = load_run(run_dir)
    summary = build_summary(data)
    index_path = build_event_index(run_dir)
    summary_md = run_dir / "summary.md"
    summary_json = run_dir / "summary.json"
    readme = run_dir / "README.log.md"
    _atomic_write(summary_md, _render_markdown(summary))
    _atomic_write(
        summary_json,
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
    )
    _atomic_write(readme, _render_readme(summary))
    return {
        "summary_md": summary_md,
        "summary_json": summary_json,
        "readme": readme,
        "index": index_path,
    }


def summary_as_json(run_dir: Path) -> str:
    data = load_run(run_dir)
    return json.dumps(build_summary(data), ensure_ascii=False, indent=2) + "\n"
