#!/usr/bin/env python3
"""Assemble the unsigned bench APK from an aapt2 base and staged payloads.

Keeps ``classes.dex`` and native libraries uncompressed so zipalign can page
align them; assets stay deflated. The output is deterministic apart from the
input file contents.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)

REQUIRED = (
    "classes.dex",
    "assets/bench-tls.p12",
    "lib/arm64-v8a/libbench.so",
    "lib/x86_64/libbench.so",
)


def _entry(name: str, compress_type: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
    info.compress_type = compress_type
    info.external_attr = (0o644 & 0xFFFF) << 16
    return info


def _add(out: zipfile.ZipFile, seen: set[str], name: str, source: Path, compress: int) -> None:
    if name in seen:
        raise SystemExit(f"duplicate entry: {name}")
    seen.add(name)
    out.writestr(_entry(name, compress), source.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description="Package the geektrace bench APK.")
    parser.add_argument("--base", required=True, type=Path, help="aapt2 link output")
    parser.add_argument("--staging", required=True, type=Path, help="staged dex/assets/libs")
    parser.add_argument("--output", required=True, type=Path, help="unsigned APK to write")
    args = parser.parse_args()

    if not args.base.is_file():
        print(f"error: missing base APK: {args.base}", file=sys.stderr)
        return 2
    if not args.staging.is_dir():
        print(f"error: missing staging directory: {args.staging}", file=sys.stderr)
        return 2

    missing = [name for name in REQUIRED if not (args.staging / name).is_file()]
    if missing:
        print(f"error: staged payload missing: {', '.join(missing)}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        args.output.unlink()

    seen: set[str] = set()
    with zipfile.ZipFile(args.base, "r") as base, zipfile.ZipFile(
        args.output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
    ) as out:
        for info in base.infolist():
            if info.is_dir():
                continue
            seen.add(info.filename)
            out.writestr(
                _entry(info.filename, info.compress_type),
                base.read(info.filename),
            )

        _add(out, seen, "classes.dex", args.staging / "classes.dex", zipfile.ZIP_STORED)

        for path in sorted((args.staging / "assets").rglob("*")):
            if path.is_file():
                name = path.relative_to(args.staging).as_posix()
                _add(out, seen, name, path, zipfile.ZIP_DEFLATED)

        for path in sorted((args.staging / "lib").rglob("*.so")):
            if path.is_file():
                name = path.relative_to(args.staging).as_posix()
                _add(out, seen, name, path, zipfile.ZIP_STORED)

        for path in sorted(args.staging.rglob("*")):
            if not path.is_file():
                continue
            name = path.relative_to(args.staging).as_posix()
            if name in seen or name == "classes.dex":
                continue
            if name.startswith("assets/") or name.startswith("lib/"):
                continue
            _add(out, seen, name, path, zipfile.ZIP_DEFLATED)

    with zipfile.ZipFile(args.output, "r") as apk:
        present = {info.filename for info in apk.infolist()}
        missing = [name for name in REQUIRED if name not in present]
        if missing:
            print(f"error: packaged APK missing: {', '.join(missing)}", file=sys.stderr)
            return 3

    print(f"packaged {args.output} entries={len(seen)} bytes={args.output.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
