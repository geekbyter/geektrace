#!/usr/bin/env python3
import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--symbol", default="gt_embedded_bpf")
    parser.add_argument("--guard", default=None)
    args = parser.parse_args()

    if not args.symbol.isidentifier():
        parser.error(f"invalid C symbol: {args.symbol!r}")
    guard = args.guard or f"{args.symbol.upper()}_H"

    data = args.input.read_bytes()
    lines = []
    for offset in range(0, len(data), 12):
        chunk = data[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    content = (
        f"#ifndef {guard}\n"
        f"#define {guard}\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        f"static const uint8_t {args.symbol}[] = {{\n"
        + "\n".join(lines)
        + "\n};\n"
        + f"static const size_t {args.symbol}_size = {len(data)}u;\n"
        + "#endif\n"
    )
    args.output.write_text(content, encoding="ascii", newline="\n")


if __name__ == "__main__":
    main()
