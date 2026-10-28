#!/usr/bin/env bash
# Build the geektrace device PoC: BPF probe objects + standalone broker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/device/build"
API="${GT_API:-31}"

find_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then
    printf '%s\n' "$ANDROID_NDK_HOME"
    return
  fi
  if [[ -n "${ANDROID_NDK_ROOT:-}" && -d "$ANDROID_NDK_ROOT" ]]; then
    printf '%s\n' "$ANDROID_NDK_ROOT"
    return
  fi
  local bases=()
  [[ -n "${LOCALAPPDATA:-}" ]] && bases+=("$LOCALAPPDATA/Android/Sdk/ndk")
  [[ -n "${HOME:-}" ]] && bases+=("$HOME/Android/Sdk/ndk" "$HOME/Library/Android/sdk/ndk")
  local base
  for base in "${bases[@]}"; do
    [[ -d "$base" ]] || continue
    local latest
    latest="$(ls -1 "$base" 2>/dev/null | sort -V | tail -1)"
    if [[ -n "$latest" && -d "$base/$latest" ]]; then
      printf '%s\n' "$base/$latest"
      return
    fi
  done
  return 1
}

NDK="$(find_ndk || true)"
if [[ -z "$NDK" ]]; then
  echo "Android NDK not found; set ANDROID_NDK_HOME" >&2
  exit 1
fi

PYTHON_BIN="${GT_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1 && \
       "$candidate" -c 'import sys; sys.exit(0)' >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi
if [[ -z "$PYTHON_BIN" ]]; then
  echo "Python 3 is required at build time only (set GT_PYTHON)" >&2
  exit 1
fi

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) HOST_TAG=windows-x86_64 ;;
  Darwin) HOST_TAG=darwin-x86_64 ;;
  *) HOST_TAG=linux-x86_64 ;;
esac
BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
CLANG="$BIN/clang"
STRIP="$BIN/llvm-strip"

for tool in "$CLANG" "$STRIP"; do
  if [[ ! -x "$tool" && ! -x "$tool.cmd" && ! -x "$tool.exe" ]]; then
    echo "missing NDK tool: $tool" >&2
    exit 1
  fi
done

mkdir -p "$OUT"

for arch in arm64 x86_64; do
  echo "==> bpf $arch (modern)"
  "$CLANG" -target bpfel -D"__TARGET_ARCH_$arch" -mcpu=v1 -O2 -Wall -Wextra \
    -c "$ROOT/device/ebpf/geektrace_poc.bpf.c" \
    -o "$OUT/gtpoc_$arch.bpf.o"
  echo "==> bpf $arch (legacy)"
  # -mcpu=v1 keeps 32-bit JMP32 out of the image: Linux 4.19 rejects it.
  "$CLANG" -target bpfel -D"__TARGET_ARCH_$arch" -DGT_LEGACY -mcpu=v1 \
    -O2 -Wall -Wextra \
    -c "$ROOT/device/ebpf/geektrace_poc.bpf.c" \
    -o "$OUT/gtpoc_${arch}_legacy.bpf.o"
  echo "==> bpf $arch (legacy, no stack helper)"
  "$CLANG" -target bpfel -D"__TARGET_ARCH_$arch" -DGT_LEGACY -DGT_NO_STACK \
    -mcpu=v1 -O2 -Wall -Wextra \
    -c "$ROOT/device/ebpf/geektrace_poc.bpf.c" \
    -o "$OUT/gtpoc_${arch}_legacy_nostack.bpf.o"
done

for abi in aarch64 x86_64; do
  case "$abi" in
    aarch64) tag=arm64 ;;
    *) tag=x86_64 ;;
  esac
  echo "==> broker $tag (embedded BPF)"
  EMBED_DIR="$OUT/embedded_$tag"
  mkdir -p "$EMBED_DIR"
  "$PYTHON_BIN" "$ROOT/device/embed_bpf.py" "$OUT/gtpoc_$tag.bpf.o" \
    "$EMBED_DIR/geektrace_embedded_bpf.h" \
    --symbol gt_embedded_bpf --guard GEETRACE_EMBEDDED_BPF_H
  "$PYTHON_BIN" "$ROOT/device/embed_bpf.py" \
    "$OUT/gtpoc_${tag}_legacy.bpf.o" \
    "$EMBED_DIR/geektrace_embedded_bpf_legacy.h" \
    --symbol gt_embedded_bpf_legacy --guard GEETRACE_EMBEDDED_BPF_LEGACY_H
  "$PYTHON_BIN" "$ROOT/device/embed_bpf.py" \
    "$OUT/gtpoc_${tag}_legacy_nostack.bpf.o" \
    "$EMBED_DIR/geektrace_embedded_bpf_legacy_nostack.h" \
    --symbol gt_embedded_bpf_legacy_nostack \
    --guard GEETRACE_EMBEDDED_BPF_LEGACY_NOSTACK_H
  "$BIN/${abi}-linux-android${API}-clang" \
    -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter \
    -DGEETRACE_EMBEDDED_BPF -I"$EMBED_DIR" \
    -Wl,-z,max-page-size=16384 \
    "$ROOT/device/broker/geektraced.c" \
    -o "$OUT/geektraced_$tag"
  "$STRIP" --strip-all "$OUT/geektraced_$tag"
done

echo
echo "built:"
ls -l "$OUT"/gtpoc_*.bpf.o "$OUT"/geektraced_*
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUT"/gtpoc_*.bpf.o "$OUT"/geektraced_*
fi

ASSET_ROOT="$ROOT/host/src/geektrace/assets/device"
for tag in arm64 x86_64; do
  mkdir -p "$ASSET_ROOT/$tag"
  cp "$OUT/geektraced_$tag" "$ASSET_ROOT/$tag/geektraced"
  cp "$OUT/gtpoc_$tag.bpf.o" "$ASSET_ROOT/$tag/gtpoc.bpf.o"
  cp "$OUT/gtpoc_${tag}_legacy.bpf.o" "$ASSET_ROOT/$tag/gtpoc_legacy.bpf.o"
  cp "$OUT/gtpoc_${tag}_legacy_nostack.bpf.o" \
    "$ASSET_ROOT/$tag/gtpoc_legacy_nostack.bpf.o"
done
echo "wheel assets: $ASSET_ROOT"
