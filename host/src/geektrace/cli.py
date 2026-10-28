import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .constants import LOG_PREFIX, PROFILE_NAMES
from .demo import create_demo_run
from .doctor import doctor_json, doctor_report, find_adb, human_lines, write_report
from .event import utc_now, validate_jsonl_files
from .graph import graph_for_run
from .graph import render_markdown as render_graph_markdown
from .importer import import_capture
from .locate import locate_keyword, render_markdown
from .output import log
from .preflight import build_preflight
from .preflight import render_markdown as render_preflight_markdown
from .profiles import device_options, device_supported, get_profile
from .report import generate_summary
from .runner import (
    DEFAULT_REMOTE_DIR,
    ACTIVITY_RE,
    PACKAGE_RE,
    CaptureOptions,
    DeviceRunError,
    execute_capture,
    parse_duration,
)
from .runstore import (
    DEFAULT_MAX_PART_BYTES,
    RunWriter,
    compact_event_parts,
    iter_event_files,
    load_manifest,
    save_manifest,
)
from .schema import schema_json, write_schema

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_DEVICE = 3
EXIT_DATA = 5

SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an integer: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="geektrace",
        description="External, root-only Android observation tool. No target injection by default.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check host/device capabilities")
    doctor.add_argument("--serial", help="adb serial; auto-selects the only online device")
    doctor.add_argument("--out", type=Path, help="write JSON report to this path")
    doctor.add_argument("--json", action="store_true", help="print JSON only")
    doctor.add_argument("--require-device", action="store_true", help="exit 3 without a ready device")
    doctor.add_argument(
        "--no-root-check",
        action="store_true",
        help="skip `su -c id` (root status becomes unknown)",
    )

    schema = sub.add_parser("schema", help="Print or validate the JSONL event schema")
    schema.add_argument("--validate", type=Path, help="validate a run directory or JSONL file")
    schema.add_argument("--out", type=Path, help="write the schema JSON to this path")
    schema.add_argument("--json", action="store_true", help="machine-readable validation result")

    demo = sub.add_parser("demo", help="Create a synthetic run to inspect the output format")
    demo.add_argument("--runs-root", type=Path, default=Path("runs"))
    demo.add_argument("--session-id", help="fixed session id (testing only)")

    capture = sub.add_parser(
        "import", help="Adopt a raw device capture and generate manifest plus reports"
    )
    capture.add_argument("run_dir", type=Path, help="directory containing events.jsonl")
    capture.add_argument("--app", required=True, help="target package name")
    capture.add_argument("--profile", default="ai", choices=PROFILE_NAMES)
    capture.add_argument("--session", help="session id; must match events if present")
    capture.add_argument("--serial")
    capture.add_argument("--device-model")
    capture.add_argument("--android")
    capture.add_argument("--kernel")
    capture.add_argument("--abi")

    run = sub.add_parser("run", help="Plan or start a capture session")
    run.add_argument("--app", required=True, help="target package name")
    run.add_argument("--profile", default="ai", choices=PROFILE_NAMES)
    run.add_argument("--backend", default="ebpf", choices=("ebpf", "kpm", "qbdi", "auto"))
    run.add_argument("--mode", default="cold-start", choices=("cold-start", "attach", "wait"))
    run.add_argument("--serial", help="adb serial")
    run.add_argument("--runs-root", type=Path, default=Path("runs"))
    run.add_argument("--duration", default="120s", help="capture duration, e.g. 30s, 2m, 1h")
    run.add_argument(
        "--activity",
        help="explicit launcher activity (package/.Activity); default uses monkey",
    )
    run.add_argument("--libssl", help="device path to libssl.so (default: auto)")
    run.add_argument("--libcrypto", help="device path to libcrypto.so (default: auto)")
    run.add_argument("--tracefs", help="tracefs mount path (default: auto-detect)")
    run.add_argument(
        "--remote-dir",
        default=DEFAULT_REMOTE_DIR,
        help="device staging directory (must be under /data/local/tmp)",
    )
    run.add_argument("--session", help="fixed session id (testing/reproducibility)")
    run.add_argument(
        "--max-part-bytes",
        type=_non_negative_int,
        default=DEFAULT_MAX_PART_BYTES,
        help="rotate events.jsonl after this many bytes",
    )
    run.add_argument(
        "--max-events",
        type=_non_negative_int,
        default=0,
        help="stop after N events (0 = unlimited)",
    )
    run.add_argument(
        "--max-total-bytes",
        type=_non_negative_int,
        default=0,
        help="stop after this many event bytes (0 = unlimited)",
    )
    run.add_argument("--dry-run", action="store_true", help="create a plan/manifest without a device")
    run.add_argument(
        "--payload-limit",
        type=_non_negative_int,
        default=None,
        help=(
            "max bytes copied out of the target per event "
            "(0 = metadata only, no target memory is read)"
        ),
    )
    run.add_argument(
        "--stack",
        dest="stack",
        action="store_true",
        default=None,
        help="capture user stacks for focus events (higher overhead)",
    )
    run.add_argument(
        "--no-stack",
        dest="stack",
        action="store_false",
        help="disable user stack capture",
    )
    run.add_argument(
        "--eager-uprobes",
        action="store_true",
        help=(
            "attach library probes at startup instead of waiting until the "
            "target maps the library"
        ),
    )
    run.add_argument(
        "--uid",
        type=int,
        default=None,
        help=(
            "target uid; default is resolved from the package. 0 captures "
            "every root process and is only useful for diagnostics"
        ),
    )
    run.add_argument(
        "--pre-arm",
        choices=("on-sight", "eager", "lazy"),
        default="on-sight",
        help=(
            "when the library probes are installed: on-sight (as soon as the "
            "target exists), eager (at broker start) or lazy (only after the "
            "target maps the library)"
        ),
    )
    run.add_argument(
        "--lib-copies",
        type=int,
        default=2,
        help=(
            "max library copies probed per kind (1-4). 2 covers the Java and "
            "the native crypto library; 1 patches fewer code pages but can "
            "miss the crypto entirely"
        ),
    )

    report = sub.add_parser("report", help="Regenerate and print a run summary")
    report.add_argument("run_dir", type=Path)
    report.add_argument(
        "--format",
        default="both",
        choices=("md", "json", "both"),
        help="print summary markdown, JSON, or only paths",
    )

    compact = sub.add_parser("compact", help="Gzip rotated event parts and rebuild the index")
    compact.add_argument("run_dir", type=Path)

    locate = sub.add_parser("locate", help="Locate network/crypto evidence by payload keyword")
    locate.add_argument("run_dir", type=Path)
    locate.add_argument("keyword", help="UTF-8 text, hex:deadbeef, 0xdeadbeef, or base64:...")
    locate.add_argument("--capture", type=Path, help="optional classic pcap or raw capture to scan")
    locate.add_argument("--window-ms", type=float, default=250.0)
    locate.add_argument("--limit", type=_non_negative_int, default=50)
    locate.add_argument("--format", choices=("json", "md"), default="json")

    graph = sub.add_parser(
        "graph", help="Build a request/crypto/code evidence graph for a run"
    )
    graph.add_argument("run_dir", type=Path)
    graph.add_argument(
        "--window-ms",
        type=float,
        default=250.0,
        help="time window used to propose crypto/request candidates",
    )
    graph.add_argument("--format", choices=("json", "md"), default="md")
    graph.add_argument("--out", type=Path, help="write the graph JSON to this path")

    preflight = sub.add_parser(
        "preflight",
        help="Static app inventory plus device readiness before a capture",
    )
    preflight.add_argument("--app", help="target package name")
    preflight.add_argument("--apk", type=Path, help="APK to inventory (optional)")
    preflight.add_argument("--serial", help="adb serial for the readiness check")
    preflight.add_argument("--profile", default="ai", choices=PROFILE_NAMES)
    preflight.add_argument(
        "--out", type=Path, help="directory for preflight.json and preflight.md"
    )
    preflight.add_argument("--format", choices=("md", "json"), default="md")

    return parser


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = doctor_report(serial=args.serial, check_root=not args.no_root_check)
    if args.out:
        write_report(report, args.out)
        log(f"doctor: wrote {args.out}")
    if args.json:
        sys.stdout.write(doctor_json(report))
    else:
        for line in human_lines(report):
            print(f"{LOG_PREFIX} {line}")
        if args.out:
            print(f"{LOG_PREFIX} doctor: json={args.out}")
    if args.require_device and not report["ready"]:
        return EXIT_DEVICE
    if report["status"] in ("adb_error", "invalid_serial", "device_not_found", "device_unauthorized"):
        return EXIT_DEVICE
    return EXIT_OK


def _cmd_schema(args: argparse.Namespace) -> int:
    if args.out:
        write_schema(args.out)
        log(f"schema: wrote {args.out}")
    if not args.validate:
        if not args.out:
            sys.stdout.write(schema_json())
        return EXIT_OK

    target: Path = args.validate
    if not target.exists():
        log(f"schema: path not found: {target}")
        return EXIT_DATA
    if target.is_dir():
        files = iter_event_files(target)
        if not files:
            log(f"schema: no events.jsonl or events/part-*.jsonl under {target}")
            return EXIT_DATA
    else:
        files = [target]
    result = validate_jsonl_files(files)
    payload = {
        "ok": result.ok,
        "files": result.files,
        "lines": result.lines,
        "events": result.events,
        "errors": result.errors,
        "seq_duplicates": result.seq_duplicates,
        "seq_out_of_order": result.seq_out_of_order,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(
            f"{LOG_PREFIX} schema: files={result.files} events={result.events} "
            f"errors={len(result.errors)} duplicates={len(result.seq_duplicates)} "
            f"out_of_order={len(result.seq_out_of_order)}"
        )
        for error in result.errors[:50]:
            print(f"{LOG_PREFIX} schema error: {error}")
    return EXIT_OK if result.ok else EXIT_DATA


def _cmd_demo(args: argparse.Namespace) -> int:
    if args.session_id and not SESSION_RE.match(args.session_id):
        log("demo: --session-id must match [A-Za-z0-9._-]{1,63}")
        return EXIT_USAGE
    try:
        run_dir, paths = create_demo_run(args.runs_root, session_id=args.session_id)
    except (FileExistsError, OSError) as exc:
        log(f"demo: {exc}")
        return EXIT_DATA
    log(f"demo: synthetic run created at {run_dir}")
    print(f"run_dir={run_dir}")
    print(f"summary_md={paths['summary_md']}")
    print(f"summary_json={paths['summary_json']}")
    print(f"index={paths['index']}")
    print(f"events={run_dir / 'events.jsonl'}")
    return EXIT_OK


def _cmd_import(args: argparse.Namespace) -> int:
    if args.session and not SESSION_RE.match(args.session):
        log("import: --session must match [A-Za-z0-9._-]{1,63}")
        return EXIT_USAGE
    try:
        result = import_capture(
            args.run_dir,
            app=args.app,
            profile=args.profile,
            session=args.session,
            serial=args.serial,
            model=args.device_model,
            android=args.android,
            kernel=args.kernel,
            abi=args.abi,
        )
    except (OSError, ValueError) as exc:
        log(f"import: {exc}")
        return EXIT_DATA
    validation = result["validation"]
    log(
        f"import: session={result['session']} events={validation['valid_events']} "
        f"lines={validation['lines']} errors={validation['errors']}"
    )
    if validation["errors"]:
        log("import: invalid lines were skipped; see manifest.json validation section")
    paths = result["paths"]
    print(f"run_dir={result['run_dir']}")
    print(f"summary_md={paths['summary_md']}")
    print(f"summary_json={paths['summary_json']}")
    print(f"index={paths['index']}")
    print(f"readme={paths['readme']}")
    return EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        profile_config = get_profile(args.profile)
        duration_seconds = parse_duration(args.duration)
    except ValueError as exc:
        log(f"run: {exc}")
        return EXIT_USAGE
    if not PACKAGE_RE.match(args.app):
        log(f"run: invalid package name: {args.app!r}")
        return EXIT_USAGE
    if args.activity and not ACTIVITY_RE.match(args.activity):
        log(f"run: invalid --activity {args.activity!r}; use package/.Activity")
        return EXIT_USAGE
    if args.session and not SESSION_RE.match(args.session):
        log("run: --session must match [A-Za-z0-9._-]{1,63}")
        return EXIT_USAGE
    if not args.remote_dir.startswith("/data/local/tmp/"):
        log("run: --remote-dir must be under /data/local/tmp")
        return EXIT_USAGE
    for label, value in (
        ("--libssl", args.libssl),
        ("--libcrypto", args.libcrypto),
        ("--tracefs", args.tracefs),
    ):
        if value and not value.startswith("/"):
            log(f"run: {label} must be an absolute device path")
            return EXIT_USAGE

    if not device_supported(args.profile):
        log(
            f"run: profile {args.profile} is not implemented by the device broker; "
            "use ai, stealth or safe"
        )
        return EXIT_USAGE
    device_profile = device_options(args.profile)
    payload_limit = (
        args.payload_limit
        if args.payload_limit is not None
        else int(device_profile["payload_limit"])
    )
    if payload_limit > 255:
        log("run: --payload-limit must be between 0 and 255")
        return EXIT_USAGE
    stack = bool(device_profile["stack"]) if args.stack is None else bool(args.stack)
    eager_uprobes = bool(device_profile.get("eager_uprobes")) or bool(
        args.eager_uprobes
    )

    options = {
        "duration": args.duration,
        "duration_seconds": duration_seconds,
        "dry_run": bool(args.dry_run),
        "max_part_bytes": args.max_part_bytes,
        "max_events": args.max_events,
        "max_total_bytes": args.max_total_bytes,
        "activity": args.activity,
        "libssl": args.libssl,
        "libcrypto": args.libcrypto,
        "tracefs": args.tracefs,
        "profile_config": profile_config,
        "payload_limit": payload_limit,
        "stack": stack,
        "eager_uprobes": eager_uprobes,
    }

    if args.dry_run:
        try:
            writer = RunWriter(
                args.runs_root,
                app=args.app,
                profile=args.profile,
                backend=args.backend,
                transport="adb",
                mode=args.mode,
                serial=args.serial,
                demo=False,
                options=options,
                session_id=args.session,
                max_part_bytes=args.max_part_bytes,
                max_events=args.max_events,
                max_total_bytes=args.max_total_bytes,
            )
        except (FileExistsError, OSError) as exc:
            log(f"run: {exc}")
            return EXIT_DATA
        try:
            writer.log(
                f"run: dry-run plan app={args.app} profile={args.profile} "
                f"duration={args.duration}"
            )
            writer.close(status="planned")
            paths = generate_summary(writer.run_dir)
            log(f"run: plan written to {writer.run_dir}")
            print(f"run_dir={writer.run_dir}")
            print(f"summary_md={paths['summary_md']}")
            print(f"summary_json={paths['summary_json']}")
            return EXIT_OK
        finally:
            writer.close(status="aborted")

    if args.backend != "ebpf":
        log("run: v0.1.0 only implements --backend ebpf; kpm/qbdi/auto are planned")
        return EXIT_USAGE
    if args.mode != "cold-start":
        log("run: v0.1.0 only implements --mode cold-start")
        return EXIT_USAGE
    if (
        args.max_events
        or args.max_total_bytes
        or args.max_part_bytes != DEFAULT_MAX_PART_BYTES
    ):
        log("run: warning: --max-* budgets apply to host runs only and are ignored on device")

    report = doctor_report(serial=args.serial, check_root=True)
    if not report["ready"]:
        for line in human_lines(report):
            print(f"{LOG_PREFIX} {line}")
        log("run: device is not ready; fix the warnings or connect a rooted device")
        return EXIT_DEVICE
    device = report.get("device") or {}
    adb = report["host"].get("adb") or find_adb()
    if not adb:
        log("run: adb not found; set ANDROID_HOME or add platform-tools to PATH")
        return EXIT_DEVICE

    capture = CaptureOptions(
        adb=adb,
        serial=device.get("serial") or args.serial or "",
        app=args.app,
        duration_seconds=duration_seconds,
        duration_label=args.duration,
        runs_root=args.runs_root,
        profile=args.profile,
        mode=args.mode,
        activity=args.activity,
        libssl=args.libssl,
        libcrypto=args.libcrypto,
        tracefs=args.tracefs,
        session=args.session,
        remote_dir=args.remote_dir,
        payload_limit=payload_limit,
        stack=stack,
        eager_uprobes=eager_uprobes,
        uid=args.uid,
        prearm=args.pre_arm,
        lib_copies=args.lib_copies,
    )
    try:
        result = execute_capture(capture, device)
    except KeyboardInterrupt:
        log("run: interrupted; partial artifacts remain under the run directory")
        return 130
    except ValueError as exc:
        log(f"run: {exc}")
        return EXIT_USAGE
    except DeviceRunError as exc:
        log(f"run: {exc}")
        return EXIT_DEVICE

    log(f"run: completed session={result.session} events={result.events}")
    print(f"run_dir={result.run_dir}")
    print(f"events={result.run_dir / 'events.jsonl'}")
    print(f"summary_md={result.paths.get('summary_md')}")
    print(f"summary_json={result.paths.get('summary_json')}")
    print(f"index={result.paths.get('index')}")
    print(f"readme={result.paths.get('readme')}")
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    if not args.run_dir.is_dir():
        log(f"report: run directory not found: {args.run_dir}")
        return EXIT_DATA
    try:
        paths = generate_summary(args.run_dir)
    except FileNotFoundError as exc:
        log(f"report: {exc}")
        return EXIT_DATA
    if args.format == "md":
        sys.stdout.write(Path(paths["summary_md"]).read_text(encoding="utf-8"))
    elif args.format == "json":
        sys.stdout.write(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    else:
        log(f"report: summary_md={paths['summary_md']}")
        log(f"report: summary_json={paths['summary_json']}")
        log(f"report: index={paths['index']}")
        log(f"report: readme={paths['readme']}")
    return EXIT_OK


def _cmd_locate(args: argparse.Namespace) -> int:
    try:
        result = locate_keyword(
            args.run_dir,
            args.keyword,
            capture=args.capture,
            window_ms=args.window_ms,
            limit=args.limit,
        )
    except (OSError, ValueError) as exc:
        log(f"locate: {exc}")
        return EXIT_DATA
    if args.format == "md":
        sys.stdout.write(render_markdown(result))
    else:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return EXIT_OK


def _cmd_compact(args: argparse.Namespace) -> int:
    if not args.run_dir.is_dir():
        log(f"compact: run directory not found: {args.run_dir}")
        return EXIT_DATA
    try:
        compacted = compact_event_parts(args.run_dir)
        manifest = load_manifest(args.run_dir)
        manifest.setdefault("counts", {})["compressed_parts"] = len(compacted)
        manifest["compacted_at"] = utc_now()
        save_manifest(args.run_dir, manifest)
        paths = generate_summary(args.run_dir)
    except (FileNotFoundError, FileExistsError, OSError, ValueError) as exc:
        log(f"compact: {exc}")
        return EXIT_DATA
    for path in compacted:
        log(f"compact: {path}")
    log(f"compact: parts={len(compacted)} index={paths['index']}")
    return EXIT_OK


def _cmd_graph(args: argparse.Namespace) -> int:
    if not args.run_dir.is_dir():
        log(f"graph: run directory not found: {args.run_dir}")
        return EXIT_DATA
    try:
        result = graph_for_run(args.run_dir, window_ms=args.window_ms)
    except (OSError, ValueError) as exc:
        log(f"graph: {exc}")
        return EXIT_DATA
    if args.out:
        try:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            log(f"graph: {exc}")
            return EXIT_DATA
    if args.format == "md":
        sys.stdout.write(render_graph_markdown(result))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


def _cmd_preflight(args: argparse.Namespace) -> int:
    try:
        report = build_preflight(
            args.apk,
            app=args.app,
            serial=args.serial,
            profile=args.profile,
        )
    except (OSError, ValueError) as exc:
        log(f"preflight: {exc}")
        return EXIT_DATA
    if args.out:
        try:
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / "preflight.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (args.out / "preflight.md").write_text(
                render_preflight_markdown(report), encoding="utf-8"
            )
            log(f"preflight: written to {args.out}")
        except OSError as exc:
            log(f"preflight: {exc}")
            return EXIT_DATA
    if args.format == "md":
        sys.stdout.write(render_preflight_markdown(report))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "schema":
        return _cmd_schema(args)
    if args.command == "demo":
        return _cmd_demo(args)
    if args.command == "import":
        return _cmd_import(args)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "compact":
        return _cmd_compact(args)
    if args.command == "locate":
        return _cmd_locate(args)
    if args.command == "graph":
        return _cmd_graph(args)
    if args.command == "preflight":
        return _cmd_preflight(args)
    parser.error("unknown command")
    return EXIT_USAGE
