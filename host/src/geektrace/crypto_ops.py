"""Aggregate raw crypto events into one record per crypto call.

The device emits an entry event and a return event for the same call. The
return event carries the produced bytes, so an operation only counts as
complete when both halves are present. Nothing here guesses an algorithm or a
key: the events carry function, direction and lengths only, and a missing
half stays visible as ``partial``.

Pairing is done by ``correlation.call_id``. Captures produced by older
firmware derive that id from two slightly different timestamps, so a return
event without an exact match is re-attached to the closest preceding entry
with the same thread, function and context.
"""

from __future__ import annotations

from typing import Any, Iterable

RETURN_MATCH_WINDOW_NS = 50_000_000


def _args(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("args")
    return value if isinstance(value, dict) else {}


def _call_id(event: dict[str, Any]) -> str | None:
    correlation = event.get("correlation") or {}
    value = correlation.get("call_id")
    return str(value) if value else None


def _location(event: dict[str, Any]) -> dict[str, Any] | None:
    location = event.get("location") or {}
    module = location.get("module")
    symbol = location.get("symbol")
    if not module and not symbol:
        return None
    if module and symbol:
        text = f"{module}({symbol})"
    else:
        text = module or symbol
    return {
        "text": text,
        "module": module,
        "symbol": symbol,
        "file_offset": location.get("file_offset"),
    }


def _capture_status(event: dict[str, Any]) -> str:
    policy = event.get("policy") or {}
    status = policy.get("capture_status")
    return str(status) if status else "unknown"


def _key_for(event: dict[str, Any]) -> str:
    call_id = _call_id(event)
    if call_id:
        return call_id
    args = _args(event)
    return "seq:{seq}:{fn}".format(
        seq=event.get("seq"), fn=args.get("fn") or event.get("kind")
    )


def _context_key(event: dict[str, Any]) -> tuple[Any, ...]:
    args = _args(event)
    return (
        event.get("pid"),
        event.get("tid"),
        args.get("fn"),
        args.get("ctx"),
    )


def _context_key_of(operation: dict[str, Any]) -> tuple[Any, ...]:
    return (
        operation.get("pid"),
        operation.get("tid"),
        operation.get("fn"),
        operation.get("ctx"),
    )


def _new_operation(event: dict[str, Any], key: str) -> dict[str, Any]:
    args = _args(event)
    location = _location(event)
    return {
        "op_id": f"crypto:{key}",
        "call_id": _call_id(event),
        "fn": args.get("fn") or (location or {}).get("symbol"),
        "dir": args.get("dir"),
        "ctx": args.get("ctx"),
        "pid": event.get("pid"),
        "tid": event.get("tid"),
        "comm": event.get("comm"),
        "mono_ns": event.get("mono_ns"),
        "ts": event.get("ts"),
        "input_len": None,
        "output_len": None,
        "ret": None,
        "input_head_hex": None,
        "output_head_hex": None,
        "location": location,
        "stack_frames": len(event.get("stack") or []),
        "seqs": [],
        "phases": [],
        "capture_status": [],
        "confidence": "partial",
        "complete": False,
        "matched_by": "call_id",
    }


def _apply(
    operation: dict[str, Any],
    event: dict[str, Any],
    args: dict[str, Any],
    phase: str,
) -> None:
    operation["seqs"].append(event.get("seq"))
    if phase not in operation["phases"]:
        operation["phases"].append(phase)
    status = _capture_status(event)
    if status not in operation["capture_status"]:
        operation["capture_status"].append(status)

    if phase == "entry":
        if args.get("input_len") is not None:
            operation["input_len"] = args.get("input_len")
        if args.get("input_head_hex") is not None:
            operation["input_head_hex"] = args.get("input_head_hex")
    else:
        if args.get("output_len") is not None:
            operation["output_len"] = args.get("output_len")
        if args.get("output_head_hex") is not None:
            operation["output_head_hex"] = args.get("output_head_hex")
        if args.get("ret") is not None:
            operation["ret"] = args.get("ret")
        operation["complete"] = True
        operation["confidence"] = "exact"
    if operation.get("location") is None:
        operation["location"] = _location(event)
    if not operation.get("stack_frames"):
        operation["stack_frames"] = len(event.get("stack") or [])
    if operation.get("mono_ns") is None:
        operation["mono_ns"] = event.get("mono_ns")


def _match_return(
    operations: list[dict[str, Any]], event: dict[str, Any]
) -> dict[str, Any] | None:
    """Find the entry a return event belongs to when the call id differs."""
    context = _context_key(event)
    mono = event.get("mono_ns")
    if mono is None:
        return None
    best = None
    for operation in operations:
        if operation.get("complete"):
            continue
        if "entry" not in (operation.get("phases") or []):
            continue
        if _context_key_of(operation) != context:
            continue
        entry_mono = operation.get("mono_ns")
        if entry_mono is None or entry_mono > mono:
            continue
        if mono - entry_mono > RETURN_MATCH_WINDOW_NS:
            continue
        if best is None or entry_mono > (best.get("mono_ns") or 0):
            best = operation
    return best


def build_crypto_operations(
    events: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge entry/return crypto events into one operation per call."""
    crypto_events = [event for event in events if event.get("layer") == "crypto"]
    operations: list[dict[str, Any]] = []
    index: dict[str, dict[str, Any]] = {}

    for event in crypto_events:
        args = _args(event)
        if str(args.get("phase") or "entry") != "entry":
            continue
        key = _key_for(event)
        operation = index.get(key)
        if operation is None:
            operation = _new_operation(event, key)
            index[key] = operation
            operations.append(operation)
        _apply(operation, event, args, "entry")

    for event in crypto_events:
        args = _args(event)
        if str(args.get("phase") or "entry") != "return":
            continue
        key = _key_for(event)
        operation = index.get(key)
        if operation is None:
            operation = _match_return(operations, event)
            if operation is not None:
                operation["matched_by"] = "context"
        if operation is None:
            operation = _new_operation(event, key)
            index[key] = operation
            operations.append(operation)
        _apply(operation, event, args, "return")

    for operation in operations:
        if operation["complete"] and "return" not in operation["phases"]:
            operation["complete"] = False
            operation["confidence"] = "partial"
    return operations


def summarize_operations(operations: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate counters used by the report and the CLI."""
    functions: dict[str, int] = {}
    directions: dict[str, int] = {}
    complete = 0
    with_stack = 0
    matched_by_context = 0
    for operation in operations:
        fn = str(operation.get("fn") or "unknown")
        functions[fn] = functions.get(fn, 0) + 1
        direction = str(operation.get("dir") or "unknown")
        directions[direction] = directions.get(direction, 0) + 1
        if operation.get("complete"):
            complete += 1
        if operation.get("stack_frames"):
            with_stack += 1
        if operation.get("matched_by") == "context":
            matched_by_context += 1
    return {
        "count": len(operations),
        "complete": complete,
        "partial": len(operations) - complete,
        "with_stack": with_stack,
        "matched_by_context": matched_by_context,
        "functions": dict(sorted(functions.items())),
        "directions": dict(sorted(directions.items())),
    }
