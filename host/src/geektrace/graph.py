"""Build an evidence graph for one run.

The graph is the answer to "which request carried this value, which crypto
call produced it, and where does that call live". Every edge carries an
explicit confidence: ``exact`` means the two events share an identifier or a
byte, ``inferred`` means they only agree in time and size, which is a
candidate and never proof.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .crypto_ops import build_crypto_operations
from .event import validate_event
from .runstore import iter_event_lines

DEFAULT_WINDOW_MS = 250.0

NODE_TYPES = ("connection", "request", "response", "crypto", "detection", "gap")


def _args(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("args")
    return value if isinstance(value, dict) else {}


def _correlation(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("correlation")
    return value if isinstance(value, dict) else {}


def _location_text(event: dict[str, Any]) -> str:
    location = event.get("location") or {}
    module = location.get("module")
    symbol = location.get("symbol")
    if module and symbol:
        return f"{module}({symbol})"
    return module or symbol or ""


def _node(
    node_id: str,
    node_type: str,
    event: dict[str, Any],
    summary: str,
    **extra: Any,
) -> dict[str, Any]:
    node = {
        "id": node_id,
        "type": node_type,
        "seq": event.get("seq"),
        "ts": event.get("ts"),
        "mono_ns": event.get("mono_ns"),
        "pid": event.get("pid"),
        "tid": event.get("tid"),
        "comm": event.get("comm"),
        "summary": summary,
        "location": _location_text(event),
    }
    node.update(extra)
    return node


def _net_summary(event: dict[str, Any]) -> str:
    args = _args(event)
    kind = event.get("kind")
    if kind == "net.connect":
        address = args.get("address")
        port = args.get("port")
        return f"connect {address or '?'}:{port or '?'}"
    length = args.get("len")
    return f"{args.get('dir') or '?'} {length if length is not None else '?'}B"


def build_graph(
    events: Iterable[dict[str, Any]], *, window_ms: float = DEFAULT_WINDOW_MS
) -> dict[str, Any]:
    """Create the node/edge graph for a list of events."""
    window_ns = int(window_ms * 1_000_000)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_index: dict[str, dict[str, Any]] = {}

    def add_node(node: dict[str, Any]) -> dict[str, Any]:
        existing = node_index.get(node["id"])
        if existing is not None:
            return existing
        node_index[node["id"]] = node
        nodes.append(node)
        return node

    def add_edge(
        source: str,
        target: str,
        kind: str,
        confidence: str,
        reasons: list[str],
        evidence_ids: list[int] | None = None,
    ) -> None:
        edges.append(
            {
                "from": source,
                "to": target,
                "kind": kind,
                "confidence": confidence,
                "reasons": reasons,
                "evidence_ids": evidence_ids or [],
            }
        )

    ordered = sorted(events, key=lambda item: (item.get("mono_ns") or 0, item.get("seq") or 0))
    by_seq = {event.get("seq"): event for event in ordered}

    connection_nodes: dict[str, str] = {}
    request_nodes: list[dict[str, Any]] = []
    crypto_nodes: list[dict[str, Any]] = []

    for event in ordered:
        kind = event.get("kind")
        if kind == "net.connect":
            socket_id = _correlation(event).get("socket_id")
            node_id = f"conn:{socket_id}" if socket_id else f"conn:seq:{event.get('seq')}"
            add_node(
                _node(
                    node_id,
                    "connection",
                    event,
                    _net_summary(event),
                    socket_id=socket_id,
                    address=_args(event).get("address"),
                    port=_args(event).get("port"),
                )
            )
            continue

        if kind in ("net.tls_write", "net.tls_read"):
            correlation = _correlation(event)
            connection_id = correlation.get("connection_id")
            node_type = "request" if kind == "net.tls_write" else "response"
            node_id = f"{node_type}:seq:{event.get('seq')}"
            node = add_node(
                _node(
                    node_id,
                    node_type,
                    event,
                    _net_summary(event),
                    connection_id=connection_id,
                    call_id=correlation.get("call_id"),
                    payload_len=_args(event).get("len"),
                    payload_status=(event.get("policy") or {}).get("capture_status"),
                    stack_frames=len(event.get("stack") or []),
                )
            )
            if connection_id:
                connection_nodes.setdefault(connection_id, node_id)
                add_edge(
                    node_id,
                    connection_nodes[connection_id],
                    "same_connection",
                    "exact",
                    [f"connection_id={connection_id}"],
                    [event.get("seq")],
                )
            if node_type == "request":
                request_nodes.append(node)

    for event in ordered:
        if event.get("kind") != "detect.finding":
            continue
        args = _args(event)
        node_id = f"detect:seq:{event.get('seq')}"
        add_node(
            _node(
                node_id,
                "detection",
                event,
                f"{args.get('category') or 'detection'} ({args.get('verdict') or 'observed'})",
                category=args.get("category"),
                rule=args.get("rule"),
                confidence=event.get("confidence"),
            )
        )
        for evidence_id in event.get("evidence_ids") or []:
            target = by_seq.get(evidence_id)
            if target is None:
                continue
            add_edge(
                node_id,
                f"file:seq:{evidence_id}",
                "evidence",
                "exact",
                [f"evidence_ids={evidence_id}"],
                [evidence_id],
            )
            if not node_index.get(f"file:seq:{evidence_id}"):
                add_node(
                    _node(
                        f"file:seq:{evidence_id}",
                        "file",
                        target,
                        str(_args(target).get("path") or ""),
                        path=_args(target).get("path"),
                    )
                )

    for event in ordered:
        if event.get("kind") != "tool.gap":
            continue
        args = _args(event)
        node_id = f"gap:seq:{event.get('seq')}"
        add_node(
            _node(
                node_id,
                "gap",
                event,
                str(args.get("reason") or "gap"),
                reason=args.get("reason"),
                message=args.get("message"),
            )
        )

    operations = build_crypto_operations(ordered)
    for operation in operations:
        node_id = operation["op_id"]
        location = operation.get("location") or {}
        crypto_nodes.append(
            add_node(
                {
                    "id": node_id,
                    "type": "crypto",
                    "seq": (operation.get("seqs") or [None])[0],
                    "ts": operation.get("ts"),
                    "mono_ns": operation.get("mono_ns"),
                    "pid": operation.get("pid"),
                    "tid": operation.get("tid"),
                    "comm": operation.get("comm"),
                    "summary": f"{operation.get('fn')} {operation.get('dir')} "
                    f"in={operation.get('input_len')} out={operation.get('output_len')}",
                    "location": location.get("text") or "",
                    "fn": operation.get("fn"),
                    "dir": operation.get("dir"),
                    "input_len": operation.get("input_len"),
                    "output_len": operation.get("output_len"),
                    "complete": operation.get("complete"),
                    "stack_frames": operation.get("stack_frames"),
                    "capture_status": operation.get("capture_status"),
                    "seqs": operation.get("seqs"),
                }
            )
        )

    # Crypto -> request candidates. Same thread plus a matching length plus a
    # close timestamp is a candidate; it is never promoted to exact.
    for operation in crypto_nodes:
        mono = operation.get("mono_ns")
        tid = operation.get("tid")
        lengths = {
            value
            for value in (operation.get("input_len"), operation.get("output_len"))
            if isinstance(value, int)
        }
        for request in request_nodes:
            if operation.get("tid") is not None and request.get("tid") != operation.get("tid"):
                continue
            if mono is None or request.get("mono_ns") is None:
                continue
            delta = abs(int(request["mono_ns"]) - int(mono))
            if delta > window_ns:
                continue
            reasons = [f"same_thread={tid}", f"delta_ms={delta / 1_000_000:.3f}"]
            request_length = request.get("payload_len")
            if lengths and isinstance(request_length, int) and request_length in lengths:
                reasons.append(f"length_match={request_length}")
            add_edge(
                operation["id"],
                request["id"],
                "crypto_candidate",
                "inferred",
                reasons + ["temporal_and_thread_match"],
                [seq for seq in (operation.get("seqs") or []) if seq is not None],
            )

    # Requests that never matched a crypto call are still worth surfacing.
    linked = {edge["from"] for edge in edges if edge["kind"] == "crypto_candidate"}
    for request in request_nodes:
        if request["id"] in linked:
            continue
        request["unlinked_crypto"] = True

    counts = {node_type: 0 for node_type in NODE_TYPES}
    for node in nodes:
        counts[node["type"]] = counts.get(node["type"], 0) + 1

    return {
        "schema": "geektrace.graph.v1",
        "window_ms": window_ms,
        "nodes": nodes,
        "edges": edges,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_type": counts,
            "crypto_operations": len(crypto_nodes),
            "requests": len(request_nodes),
            "unlinked_requests": sum(
                1 for request in request_nodes if request.get("unlinked_crypto")
            ),
        },
    }


def load_events(run_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    for path, line_no, line in iter_event_lines(run_dir):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{line_no}: {exc.msg}")
            continue
        event_errors = validate_event(event)
        if event_errors:
            errors.append(f"{path.name}:{line_no}: {'; '.join(event_errors)}")
            continue
        events.append(event)
    return events, errors


def graph_for_run(run_dir: Path, *, window_ms: float = DEFAULT_WINDOW_MS) -> dict[str, Any]:
    events, errors = load_events(run_dir)
    result = build_graph(events, window_ms=window_ms)
    result["run_dir"] = str(run_dir)
    result["parse_errors"] = errors
    return result


def render_markdown(result: dict[str, Any]) -> str:
    counts = result.get("counts") or {}
    lines = ["# geektrace evidence graph", ""]
    lines.append(f"- Run: `{result.get('run_dir')}`")
    lines.append(
        f"- Nodes: {counts.get('nodes', 0)} | edges: {counts.get('edges', 0)} | "
        f"crypto operations: {counts.get('crypto_operations', 0)}"
    )
    lines.append(
        f"- Requests: {counts.get('requests', 0)} "
        f"(without crypto candidate: {counts.get('unlinked_requests', 0)})"
    )
    lines.append("")
    lines.append("## Crypto operations")
    lines.append("")
    lines.append("| op | fn | dir | in | out | code location | seqs | status |")
    lines.append("|---|---|---|---:|---:|---|---|---|")
    for node in result.get("nodes") or []:
        if node.get("type") != "crypto":
            continue
        lines.append(
            f"| `{node.get('id')}` | {node.get('fn')} | {node.get('dir')} | "
            f"{node.get('input_len')} | {node.get('output_len')} | "
            f"{node.get('location') or ''} | {node.get('seqs')} | "
            f"{'complete' if node.get('complete') else 'partial'}"
        )
    lines.append("")
    lines.append("## Candidate links")
    lines.append("")
    lines.append("| from | to | kind | confidence | reasons |")
    lines.append("|---|---|---|---|---|")
    for edge in result.get("edges") or []:
        if edge.get("kind") != "crypto_candidate":
            continue
        lines.append(
            f"| `{edge.get('from')}` | `{edge.get('to')}` | {edge.get('kind')} | "
            f"{edge.get('confidence')} | {', '.join(edge.get('reasons') or [])} |"
        )
    if not result.get("edges"):
        lines.append("| _no edges_ | | | | |")
    lines.append("")
    lines.append(
        "> `exact` means the two events share an identifier or a byte. "
        "`inferred` means they only agree in time and size, so it is a "
        "candidate and not a causal proof."
    )
    lines.append("")
    return "\n".join(lines)
