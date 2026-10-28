import base64
import binascii
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .event import validate_event
from .runstore import iter_event_lines

DEFAULT_WINDOW_MS = 250.0


def parse_keyword(value: str) -> tuple[bytes, str]:
    if value.startswith("base64:"):
        try:
            decoded = base64.b64decode(value[7:], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("invalid base64 keyword") from exc
        encoding = "base64"
    elif value.startswith(("hex:", "0x")):
        text = value[4:] if value.startswith("hex:") else value[2:]
        if not text or len(text) % 2:
            raise ValueError("hex keyword must contain complete bytes")
        try:
            decoded = bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError("invalid hex keyword") from exc
        encoding = "hex"
    else:
        decoded = value.encode("utf-8")
        encoding = "utf8"
    if not decoded:
        raise ValueError("keyword must not be empty")
    return decoded, encoding


def _walk_payloads(value: Any, prefix: str = "") -> Iterator[tuple[str, bytes, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(item, str) and key.endswith("_hex"):
                try:
                    decoded = bytes.fromhex(item)
                except ValueError:
                    continue
                yield path, decoded, "hex"
            elif isinstance(item, str) and key.endswith("_b64"):
                try:
                    decoded = base64.b64decode(item, validate=True)
                except (ValueError, binascii.Error):
                    continue
                yield path, decoded, "base64"
            else:
                yield from _walk_payloads(item, path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_payloads(item, f"{prefix}[{index}]")


def _event_ref(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "seq": event["seq"],
        "kind": event["kind"],
        "ts": event["ts"],
        "mono_ns": event["mono_ns"],
        "pid": event.get("pid"),
        "tid": event.get("tid"),
        "location": event.get("location"),
        "correlation": event.get("correlation") or {},
        "stack": event.get("stack") or [],
        "policy": event.get("policy") or {},
        "input_len": (event.get("args") or {}).get("input_len"),
        "output_len": (event.get("args") or {}).get("output_len"),
        "dir": (event.get("args") or {}).get("dir"),
        "fn": (event.get("args") or {}).get("fn"),
    }


def _direct_match(event: dict[str, Any], keyword: bytes) -> dict[str, Any] | None:
    fields = []
    for path, payload, encoding in _walk_payloads(event.get("args") or {}, "args"):
        offset = payload.find(keyword)
        if offset >= 0:
            fields.append({"field": path, "encoding": encoding, "byte_offset": offset})
    if not fields:
        return None
    result = _event_ref(event)
    result["matches"] = fields
    return result


def _realtime_ns(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1_000_000_000)


def _pcap_matches(path: Path, keyword: bytes, limit: int) -> tuple[list[dict[str, Any]], str]:
    data = path.read_bytes()
    if len(data) >= 24:
        magic = data[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
        }
        if magic in formats:
            endian, fraction = formats[magic]
            matches = []
            offset = 24
            packet_index = 0
            while offset + 16 <= len(data):
                sec, frac, captured_len, _ = struct.unpack_from(endian + "IIII", data, offset)
                offset += 16
                if captured_len > len(data) - offset:
                    break
                packet = data[offset:offset + captured_len]
                byte_offset = packet.find(keyword)
                if byte_offset >= 0 and len(matches) < limit:
                    ts_ns = sec * 1_000_000_000 + frac * (1_000_000_000 // fraction)
                    matches.append({
                        "packet_index": packet_index,
                        "packet_offset": offset,
                        "byte_offset": byte_offset,
                        "captured_len": captured_len,
                        "ts": datetime.fromtimestamp(ts_ns / 1_000_000_000, timezone.utc).isoformat().replace("+00:00", "Z"),
                        "realtime_ns": ts_ns,
                    })
                offset += captured_len
                packet_index += 1
            return matches, "pcap_packet"
    matches = []
    start = 0
    while len(matches) < limit:
        found = data.find(keyword, start)
        if found < 0:
            break
        matches.append({"file_offset": found})
        start = found + 1
    return matches, "raw_bytes"


def _event_time(event: dict[str, Any], clock: str) -> int:
    return event["mono_ns"] if clock == "mono_ns" else _realtime_ns(event["ts"])


def _score(anchor: dict[str, Any], candidate: dict[str, Any], clock: str, window_ns: int) -> tuple[int, int, list[str]] | None:
    delta = _event_time(candidate, clock) - anchor["time"]
    if abs(delta) > window_ns:
        return None
    score = 30
    reasons = [f"within_{clock}_window"]
    if anchor.get("pid") is not None and anchor.get("pid") == candidate.get("pid"):
        score += 20
        reasons.append("same_pid")
    if anchor.get("tid") is not None and anchor.get("tid") == candidate.get("tid"):
        score += 25
        reasons.append("same_tid")
    score += max(0, 15 - int(abs(delta) * 15 / max(window_ns, 1)))
    anchor_len = anchor.get("length")
    candidate_args = candidate.get("args") or {}
    lengths = {candidate_args.get("input_len"), candidate_args.get("output_len"), candidate_args.get("len")}
    if anchor_len is not None and anchor_len in lengths:
        score += 10
        reasons.append("length_match")
    return score, delta, reasons


def _chain(anchor: dict[str, Any], candidate: dict[str, Any], clock: str, window_ns: int) -> dict[str, Any] | None:
    scored = _score(anchor, candidate, clock, window_ns)
    if not scored:
        return None
    score, delta, reasons = scored
    result = {
        "confidence": "temporal_inferred",
        "score": score,
        "reasons": reasons,
        "delta_ms": round(delta / 1_000_000, 6),
        "network": None,
        "crypto": None,
        "capture": anchor.get("capture"),
    }
    anchor_key = "network" if anchor["layer"] == "net" else "crypto"
    candidate_key = "network" if candidate["layer"] == "net" else "crypto"
    result[anchor_key] = _event_ref(anchor["event"]) if anchor.get("event") else None
    result[candidate_key] = _event_ref(candidate)
    return result


def locate_keyword(run_dir: Path, keyword_text: str, *, capture: Path | None = None,
                   window_ms: float = DEFAULT_WINDOW_MS, limit: int = 50) -> dict[str, Any]:
    keyword, encoding = parse_keyword(keyword_text)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"run directory not found: {run_dir}")
    if window_ms <= 0 or limit <= 0:
        raise ValueError("window and limit must be positive")
    events = []
    errors = []
    for path, line_no, line in iter_event_lines(run_dir):
        try:
            event = json.loads(line)
            event_errors = validate_event(event)
            if event_errors:
                errors.append(f"{path.name}:{line_no}: {'; '.join(event_errors)}")
                continue
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{line_no}: {exc.msg}")
            continue
        if event.get("layer") in ("net", "crypto"):
            events.append(event)
    if not events and not list(iter_event_lines(run_dir)):
        raise FileNotFoundError(f"no event files under {run_dir}")

    network_matches = []
    crypto_matches = []
    for event in events:
        match = _direct_match(event, keyword)
        if not match:
            continue
        target = network_matches if event["layer"] == "net" else crypto_matches
        if len(target) < limit:
            target.append(match)

    capture_matches = []
    capture_mode = None
    if capture:
        if not capture.is_file():
            raise FileNotFoundError(f"capture file not found: {capture}")
        capture_matches, capture_mode = _pcap_matches(capture, keyword, limit)

    window_ns = int(window_ms * 1_000_000)
    nets = [event for event in events if event["layer"] == "net"]
    cryptos = [event for event in events if event["layer"] == "crypto"]
    chains = []
    for match in network_matches:
        event = next(event for event in nets if event["seq"] == match["seq"])
        args = event.get("args") or {}
        anchor = {"layer": "net", "event": event, "time": event["mono_ns"], "pid": event.get("pid"),
                  "tid": event.get("tid"), "length": args.get("len") or args.get("output_len")}
        for candidate in cryptos:
            chain = _chain(anchor, candidate, "mono_ns", window_ns)
            if chain:
                chains.append(chain)
    direct_network_seqs = {match["seq"] for match in network_matches}
    for match in crypto_matches:
        event = next(event for event in cryptos if event["seq"] == match["seq"])
        chains.append({
            "confidence": "payload_exact",
            "score": 100,
            "reasons": ["keyword_in_crypto_payload"],
            "delta_ms": 0.0,
            "network": None,
            "crypto": _event_ref(event),
            "capture": None,
        })
        args = event.get("args") or {}
        anchor = {"layer": "crypto", "event": event, "time": event["mono_ns"], "pid": event.get("pid"),
                  "tid": event.get("tid"), "length": args.get("output_len") or args.get("input_len")}
        for candidate in nets:
            if candidate["seq"] in direct_network_seqs:
                continue
            chain = _chain(anchor, candidate, "mono_ns", window_ns)
            if chain:
                chain["reasons"].append("network_association_inferred")
                chains.append(chain)
    for capture_match in capture_matches:
        if "realtime_ns" not in capture_match:
            continue
        anchor = {"layer": "net", "time": capture_match["realtime_ns"], "length": capture_match.get("captured_len"),
                  "capture": capture_match}
        for candidate in nets:
            chain = _chain(anchor, candidate, "realtime_ns", window_ns)
            if chain:
                chains.append(chain)
    chains.sort(key=lambda item: (-item["score"], abs(item["delta_ms"]),
                                  (item.get("crypto") or {}).get("seq") or 0))
    chains = chains[:limit]

    gaps = []
    located_crypto = [item["crypto"] for item in chains if item.get("crypto")]
    if located_crypto and all(not item.get("stack") for item in located_crypto):
        gaps.append("No captured stack on located crypto events; rerun with stack=true for native PCs.")
    if capture_mode == "raw_bytes" and capture_matches:
        gaps.append("Capture hits are file byte offsets, not packet/connection matches; supply classic pcap for time alignment.")
    if any((item.get("policy") or {}).get("truncated") for item in network_matches + crypto_matches):
        gaps.append("A matched payload was truncated; absence of later bytes cannot be used as negative evidence.")
    gaps.append("Temporal chains are candidates, not proof of causality; payload_exact proves only the bytes in the cited event.")
    return {
        "schema": "geektrace.locate.v1",
        "run_dir": str(run_dir),
        "query": {"encoding": encoding, "length": len(keyword), "window_ms": window_ms},
        "capture": {"path": str(capture) if capture else None, "mode": capture_mode},
        "capture_matches": capture_matches,
        "network_matches": network_matches,
        "crypto_matches": crypto_matches,
        "chains": chains,
        "counts": {"capture": len(capture_matches), "network": len(network_matches),
                   "crypto": len(crypto_matches), "chains": len(chains)},
        "parse_errors": errors,
        "gaps": gaps,
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = ["# geektrace keyword locate", "",
             f"- Query: `{result['query']['encoding']}`, {result['query']['length']} bytes",
             f"- Hits: capture={result['counts']['capture']} network={result['counts']['network']} crypto={result['counts']['crypto']}", "",
             "| confidence | score | network seq | crypto seq | delta ms | location | reasons |",
             "|---|---:|---:|---:|---:|---|---|"]
    for chain in result["chains"]:
        crypto = chain.get("crypto") or {}
        network = chain.get("network") or {}
        location = crypto.get("location") or {}
        place = location.get("symbol") or location.get("module") or ""
        lines.append(f"| {chain['confidence']} | {chain['score']} | {network.get('seq') or ''} | "
                     f"{crypto.get('seq') or ''} | {chain['delta_ms']} | {place} | {', '.join(chain['reasons'])} |")
    if not result["chains"]:
        lines.append("| _no chains_ | | | | | | |")
    lines.extend(["", "## Gaps", ""] + [f"- {gap}" for gap in result["gaps"]])
    return "\n".join(lines) + "\n"
