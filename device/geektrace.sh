#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Git Bash on Windows otherwise rewrites /data/local/tmp/... into C:/...
export MSYS_NO_PATHCONV=1
REMOTE_DIR="${GT_REMOTE_DIR:-/data/local/tmp/geektrace}"
LOCAL_OUT="${GT_OUT:-$ROOT/runs/device-latest}"
BENCH_APK="$ROOT/tests/benchapp/build/GeekTraceBench.apk"
ADB=(adb)
[[ -n "${ANDROID_SERIAL:-}" ]] && ADB+=(-s "$ANDROID_SERIAL")

CAPTURE_ACTIVE=0
TMP_CONFIG=
fail() { printf 'geektrace: %s\n' "$*" >&2; exit 1; }

native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

case "$REMOTE_DIR" in
  /data/local/tmp/*) ;;
  *) fail "GT_REMOTE_DIR must be under /data/local/tmp" ;;
esac
case "$REMOTE_DIR" in
  *..*|*" "*|*"'"*) fail "unsafe GT_REMOTE_DIR" ;;
esac

command -v adb >/dev/null 2>&1 || fail "adb not found"
"${ADB[@]}" get-state >/dev/null 2>&1 || fail "no device (check adb devices)"

remote_ctl() {
  "${ADB[@]}" shell su -c "$REMOTE_DIR/geektracectl $1"
}

pull_capture() {
  mkdir -p "$LOCAL_OUT"
  if ! "${ADB[@]}" shell su -c "test -f '$REMOTE_DIR/events.jsonl'" >/dev/null 2>&1; then
    printf 'geektrace: no events.jsonl on device; see broker.log\n' >&2
    "${ADB[@]}" pull "$REMOTE_DIR/broker.log" "$(native_path "$LOCAL_OUT/broker.log")" >/dev/null 2>&1 || true
    return 0
  fi
  "${ADB[@]}" pull "$REMOTE_DIR/events.jsonl" "$(native_path "$LOCAL_OUT/events.jsonl")" >/dev/null
  "${ADB[@]}" pull "$REMOTE_DIR/broker.log" "$(native_path "$LOCAL_OUT/broker.log")" >/dev/null 2>&1 || true
  if [ -s "$LOCAL_OUT/events.jsonl" ]; then
    printf 'events=%s/events.jsonl\n' "$LOCAL_OUT"
  else
    printf 'geektrace: no events were captured; inspect broker.log\n' >&2
    printf 'events_empty=%s/events.jsonl\n' "$LOCAL_OUT"
  fi
  if [ -f "$LOCAL_OUT/broker.log" ]; then
    if grep -q 'event transport: perf buffer' "$LOCAL_OUT/broker.log"; then
      printf 'transport=perf-buffer\n'
    elif grep -q 'event transport: ringbuf' "$LOCAL_OUT/broker.log"; then
      printf 'transport=ringbuf\n'
    fi
  fi
  printf 'broker_log=%s/broker.log\n' "$LOCAL_OUT"
}

cleanup() {
  status=$1
  trap - EXIT INT TERM
  set +e
  if [ "$CAPTURE_ACTIVE" -eq 1 ]; then
    remote_ctl stop
    CAPTURE_ACTIVE=0
    pull_capture
  fi
  [ -z "$TMP_CONFIG" ] || rm -f "$TMP_CONFIG"
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

install_device() {
  local config_file=$1
  "${ADB[@]}" shell su -c id 2>/dev/null | tr -d '\r' | grep -q 'uid=0' \
    || fail "root (su) is not available"
  ABI="$("${ADB[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
  case "$ABI" in
    arm64-v8a) TAG=arm64 ;;
    x86_64) TAG=x86_64 ;;
    *) fail "unsupported ABI: $ABI" ;;
  esac
  BINARY="$ROOT/device/build/geektraced_$TAG"
  [ -f "$BINARY" ] || fail "missing $BINARY; run device/build.sh"
  "${ADB[@]}" shell mkdir -p "$REMOTE_DIR"
  "${ADB[@]}" push "$(native_path "$BINARY")" "$REMOTE_DIR/geektraced" >/dev/null
  "${ADB[@]}" push "$(native_path "$ROOT/device/geektracectl")" "$REMOTE_DIR/geektracectl" >/dev/null
  "${ADB[@]}" push "$(native_path "$config_file")" "$REMOTE_DIR/geektrace.conf" >/dev/null
  "${ADB[@]}" shell chmod 755 "$REMOTE_DIR/geektraced" "$REMOTE_DIR/geektracectl"
  printf 'geektrace: installed %s in %s\n' "$ABI" "$REMOTE_DIR"
}

validate_package() {
  case "$1" in
    ''|*[!A-Za-z0-9._]*) fail "invalid package name: $1" ;;
  esac
}

validate_seconds() {
  case "$1" in
    ''|*[!0-9]*|0) fail "seconds must be a positive integer" ;;
  esac
}

set_run_out() {
  if [ -z "${GT_OUT:-}" ]; then
    LOCAL_OUT="$ROOT/runs/$1-$(date +%Y%m%d-%H%M%S)"
  fi
}

render_config() {
  local package=$1
  TMP_CONFIG="$(mktemp "${TMPDIR:-/tmp}/geektrace.conf.XXXXXX")"
  awk -v package="$package" '
    /^[[:space:]]*package[[:space:]]*=/ {
      print "package = " package
      found = 1
      next
    }
    { print }
    END {
      if (!found)
        print "package = " package
    }
  ' "$ROOT/device/geektrace.conf" > "$TMP_CONFIG"
}

start_capture() {
  local package=$1
  render_config "$package"
  install_device "$TMP_CONFIG"
  CAPTURE_ACTIVE=1
  remote_ctl start
}

finish_capture() {
  remote_ctl stop
  CAPTURE_ACTIVE=0
  pull_capture
}

run_bench() {
  local seconds=${1:-20}
  validate_seconds "$seconds"
  [ -f "$BENCH_APK" ] || fail "missing $BENCH_APK; run tests/benchapp/build.sh"
  set_run_out bench
  printf 'geektrace: installing bench APK\n'
  "${ADB[@]}" install -r "$(native_path "$BENCH_APK")" >/dev/null
  start_capture com.geektrace.bench
  remote_ctl launch
  printf 'geektrace: benchmark is running; capture ends automatically in %ss\n' "$seconds"
  printf 'geektrace: output will be %s\n' "$LOCAL_OUT"
  sleep "$seconds"
  finish_capture
}

run_trace() {
  local package=${1:-}
  local seconds=${2:-30}
  validate_package "$package"
  validate_seconds "$seconds"
  set_run_out trace
  start_capture "$package"
  if ! remote_ctl launch; then
    printf 'geektrace: could not launch %s; launch it manually now\n' "$package" >&2
  fi
  printf 'geektrace: operate %s now; capture ends automatically in %ss\n' "$package" "$seconds"
  printf 'geektrace: output will be %s\n' "$LOCAL_OUT"
  sleep "$seconds"
  finish_capture
}

case "${1:-}" in
  bench) run_bench "${2:-20}" ;;
  trace) run_trace "${2:-}" "${3:-30}" ;;
  install) install_device "$ROOT/device/geektrace.conf"; printf 'Target package: %s\n' "$(awk -F= '/^[[:space:]]*package[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2}' "$ROOT/device/geektrace.conf")" ;;
  start|stop|status|restart|launch) remote_ctl "$1" ;;
  pull) pull_capture ;;
  *)
    printf 'usage: %s {bench [SECONDS] | trace PACKAGE [SECONDS] | install | start | stop | status | restart | launch | pull}\n' "$0" >&2
    printf '  bench  install bench + tracer, launch it, record, stop and pull automatically\n'
    printf '  trace  configure PACKAGE, launch it, record, stop and pull automatically\n'
    exit 2
    ;;
esac
