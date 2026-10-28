#!/usr/bin/env bash
# Run the geektrace device PoC against the bench app over ADB.
#
# Requires: rooted device, adb, bench app installed, device build output.
# The broker starts before the app and exits by itself after --duration.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="${GT_PACKAGE:-com.geektrace.bench}"
DURATION="${GT_DURATION:-25}"
OUT_DIR="${GT_OUT:-$ROOT/runs/poc-$(date +%Y%m%d-%H%M%S)}"
REMOTE_DIR="${GT_REMOTE_DIR:-/data/local/tmp/geektrace-poc}"
ADB=(adb)
if [[ -n "${ANDROID_SERIAL:-}" ]]; then
  ADB+=(-s "$ANDROID_SERIAL")
fi

step() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v adb >/dev/null 2>&1 || fail "adb not found"
"${ADB[@]}" get-state >/dev/null 2>&1 || fail "no device (check adb devices)"

ABI="$("${ADB[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
  arm64-v8a) TAG=arm64 ;;
  x86_64) TAG=x86_64 ;;
  *) fail "unsupported ABI: $ABI (need arm64-v8a or x86_64)" ;;
esac
SERIAL="$("${ADB[@]}" get-serialno 2>/dev/null | tr -d '\r' || true)"
MODEL="$("${ADB[@]}" shell getprop ro.product.model | tr -d '\r')"
ANDROID_REL="$("${ADB[@]}" shell getprop ro.build.version.release | tr -d '\r')"
KERNEL="$("${ADB[@]}" shell uname -r | tr -d '\r')"

"${ADB[@]}" shell su -c id 2>/dev/null | tr -d '\r' | grep -q 'uid=0' \
  || fail "root (su) is not available"

"${ADB[@]}" shell pm path "$PKG" >/dev/null 2>&1 \
  || fail "$PKG is not installed (run tests/benchapp/build.sh --install)"

if [[ ! -x "$ROOT/device/build/geektraced_$TAG" ]]; then
  step "building device PoC"
  bash "$ROOT/device/build.sh"
fi

mkdir -p "$OUT_DIR"
step "device: $MODEL / $ABI"
step "output: $OUT_DIR"

step "stage binaries"
"${ADB[@]}" shell mkdir -p "$REMOTE_DIR"
"${ADB[@]}" push "$ROOT/device/build/geektraced_$TAG" \
  "$REMOTE_DIR/geektraced" >/dev/null
"${ADB[@]}" shell chmod 755 "$REMOTE_DIR/geektraced"

UID_ARG=()
APP_UID="$("${ADB[@]}" shell cmd package list packages -U 2>/dev/null \
  | tr -d '\r' | awk -v p="package:$PKG" '$1==p {sub("uid:", "", $2); print $2; exit}')"
if [[ -n "$APP_UID" ]]; then
  UID_ARG=(--uid "$APP_UID")
  step "target uid: $APP_UID"
fi

step "force-stop $PKG"
"${ADB[@]}" shell am force-stop "$PKG"

REMOTE_CMD="su -c '$REMOTE_DIR/geektraced --package $PKG --duration $DURATION --out - --zygote-forks ${UID_ARG[*]:-} 2>$REMOTE_DIR/broker.log'"
step "start broker (${DURATION}s)"
"${ADB[@]}" shell "$REMOTE_CMD" >"$OUT_DIR/events.jsonl" 2>"$OUT_DIR/adb.log" &
BROKER_PID=$!

sleep 1
step "launch $PKG"
"${ADB[@]}" shell am start -W -n "$PKG/.MainActivity" >"$OUT_DIR/start.log" 2>&1 || true

sleep 3
TARGET_PID="$("${ADB[@]}" shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
if [[ -n "$TARGET_PID" ]]; then
  "${ADB[@]}" shell su -c "grep -E '^(Name|Pid|TracerPid|Threads):' /proc/$TARGET_PID/status" \
    >"$OUT_DIR/target-status.txt" 2>/dev/null || true
  step "target pid: $TARGET_PID (status: $OUT_DIR/target-status.txt)"
fi

if ! wait "$BROKER_PID"; then
  step "broker exited non-zero (see adb.log / broker.log)"
fi

"${ADB[@]}" pull "$REMOTE_DIR/broker.log" "$OUT_DIR/broker.log" >/dev/null 2>&1 || true

EVENTS=0
if [[ -s "$OUT_DIR/events.jsonl" ]]; then
  EVENTS="$(wc -l <"$OUT_DIR/events.jsonl" | tr -d ' ')"
fi
step "events: $EVENTS"
if [[ "$EVENTS" == "0" ]]; then
  echo "no events captured; inspect $OUT_DIR/broker.log and $OUT_DIR/adb.log" >&2
fi

PYTHON_BIN="${GT_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi
if [[ -n "$PYTHON_BIN" ]]; then
  IMPORT_ARGS=(import "$OUT_DIR" --app "$PKG")
  [[ -n "$SERIAL" ]] && IMPORT_ARGS+=(--serial "$SERIAL")
  [[ -n "$MODEL" ]] && IMPORT_ARGS+=(--device-model "$MODEL")
  [[ -n "$ANDROID_REL" ]] && IMPORT_ARGS+=(--android "$ANDROID_REL")
  [[ -n "$KERNEL" ]] && IMPORT_ARGS+=(--kernel "$KERNEL")
  [[ -n "$ABI" ]] && IMPORT_ARGS+=(--abi "$ABI")
  step "host import (manifest + summary)"
  if ! PYTHONPATH="$ROOT/host/src" "$PYTHON_BIN" -m geektrace "${IMPORT_ARGS[@]}"; then
    echo "warning: import failed; raw events remain in $OUT_DIR" >&2
  fi
else
  echo "warning: python3/python not found; raw events.jsonl only (set GT_PYTHON)" >&2
fi

step "done: $OUT_DIR/events.jsonl"
if [[ -f "$OUT_DIR/summary.md" ]]; then
  step "summary: $OUT_DIR/summary.md"
fi
