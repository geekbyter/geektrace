#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
  if [ -n "${LOCALAPPDATA:-}" ] && [ -d "$LOCALAPPDATA/Android/Sdk" ]; then
    SDK="$LOCALAPPDATA/Android/Sdk"
  elif [ -d "$HOME/Android/Sdk" ]; then
    SDK="$HOME/Android/Sdk"
  else
    echo "error: Android SDK not found; set ANDROID_SDK_ROOT" >&2
    exit 1
  fi
fi

BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-36.1.0}"
NDK_VERSION="${NDK_VERSION:-28.2.13676358}"
PLATFORM="${PLATFORM:-android-35}"
API_LEVEL="${API_LEVEL:-31}"
TARGET_LEVEL="${TARGET_LEVEL:-35}"

BUILD_TOOLS="$SDK/build-tools/$BUILD_TOOLS_VERSION"
ANDROID_JAR="$SDK/platforms/$PLATFORM/android.jar"
NDK_BIN="$SDK/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/windows-x86_64/bin"

if [ ! -d "$NDK_BIN" ]; then
  NDK_BIN="$SDK/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin"
fi
if [ ! -d "$NDK_BIN" ]; then
  NDK_BIN="$SDK/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/darwin-x86_64/bin"
fi

for path in "$BUILD_TOOLS" "$ANDROID_JAR" "$NDK_BIN"; do
  if [ ! -e "$path" ]; then
    echo "error: missing $path" >&2
    exit 1
  fi
done
for tool in javac jar keytool python; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: missing $tool in PATH" >&2
    exit 1
  }
done

D8="$BUILD_TOOLS/d8"
[ -f "$D8.bat" ] && D8="$D8.bat"
APKSIGNER="$BUILD_TOOLS/apksigner"
[ -f "$APKSIGNER.bat" ] && APKSIGNER="$APKSIGNER.bat"
AAPT2="$BUILD_TOOLS/aapt2"
[ -f "$AAPT2.exe" ] && AAPT2="$AAPT2.exe"
ZIPALIGN="$BUILD_TOOLS/zipalign"
[ -f "$ZIPALIGN.exe" ] && ZIPALIGN="$ZIPALIGN.exe"

OUT="$ROOT/build"
rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex" "$OUT/native/arm64-v8a" "$OUT/native/x86_64" \
  "$OUT/stage/assets" "$OUT/stage/lib/arm64-v8a" "$OUT/stage/lib/x86_64" "$ROOT/keys"

echo "==> compile java"
find java -name '*.java' -print | sort > "$OUT/sources.txt"
javac --release 8 -Xlint:-options -classpath "$ANDROID_JAR" \
  -d "$OUT/classes" @"$OUT/sources.txt"
jar cf "$OUT/classes.jar" -C "$OUT/classes" .

echo "==> dex"
"$D8" --release --min-api "$API_LEVEL" --lib "$ANDROID_JAR" \
  --output "$OUT/dex" "$OUT/classes.jar"

echo "==> native"
compile_native() {
  abi="$1"
  target="$2"
  clang="$NDK_BIN/${target}${API_LEVEL}-clang"
  [ -f "$clang.cmd" ] && clang="$clang.cmd"
  if [ ! -f "$clang" ]; then
    echo "error: missing clang wrapper $clang" >&2
    exit 1
  fi
  "$clang" -shared -fPIC -O2 -g -Wall -Wextra \
    -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 \
    -o "$OUT/native/$abi/libbench.so" jni/bench.c -llog
}
compile_native arm64-v8a aarch64-linux-android
compile_native x86_64 x86_64-linux-android

SIGNING_KEY="$ROOT/keys/bench-signing.p12"
TLS_KEYSTORE="$ROOT/keys/bench-tls.p12"
if [ ! -f "$SIGNING_KEY" ]; then
  echo "==> generate signing key"
  keytool -genkeypair -keystore "$SIGNING_KEY" -storetype PKCS12 \
    -storepass android -keypass android -alias bench \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=GeekTrace Bench, OU=Testing, O=GeekTrace, L=Local, ST=Local, C=ZZ" \
    >"$OUT/keytool-signing.log" 2>&1
fi
if [ ! -f "$TLS_KEYSTORE" ]; then
  echo "==> generate tls key"
  keytool -genkeypair -keystore "$TLS_KEYSTORE" -storetype PKCS12 \
    -storepass changeit -keypass changeit -alias bench-tls \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=localhost, OU=Testing, O=GeekTrace, L=Local, ST=Local, C=ZZ" \
    -ext "SAN=dns:localhost,ip:127.0.0.1" \
    -ext "ku=digitalSignature,keyEncipherment" \
    -ext "eku=serverAuth" \
    >"$OUT/keytool-tls.log" 2>&1
fi

echo "==> aapt2 link"
"$AAPT2" link -o "$OUT/base.apk" -I "$ANDROID_JAR" \
  --manifest AndroidManifest.xml \
  --min-sdk-version "$API_LEVEL" --target-sdk-version "$TARGET_LEVEL" \
  --version-code 1 --version-name 1.0

echo "==> stage"
cp "$OUT/dex/classes.dex" "$OUT/stage/classes.dex"
cp "$TLS_KEYSTORE" "$OUT/stage/assets/bench-tls.p12"
cp "$OUT/native/arm64-v8a/libbench.so" "$OUT/stage/lib/arm64-v8a/"
cp "$OUT/native/x86_64/libbench.so" "$OUT/stage/lib/x86_64/"
python tools/package_apk.py \
  --base "$OUT/base.apk" --staging "$OUT/stage" \
  --output "$OUT/GeekTraceBench-unaligned.apk"

echo "==> align"
"$ZIPALIGN" -P 16 -f 4 \
  "$OUT/GeekTraceBench-unaligned.apk" "$OUT/GeekTraceBench-aligned.apk"

echo "==> sign"
"$APKSIGNER" sign --ks "$SIGNING_KEY" --ks-key-alias bench \
  --ks-pass pass:android --key-pass pass:android \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --out "$OUT/GeekTraceBench.apk" "$OUT/GeekTraceBench-aligned.apk"
"$APKSIGNER" verify --verbose --print-certs "$OUT/GeekTraceBench.apk"

echo "==> badging"
"$AAPT2" dump badging "$OUT/GeekTraceBench.apk" | head -n 12
ls -lh "$OUT/GeekTraceBench.apk"

if [ "${1:-}" = "--install" ]; then
  command -v adb >/dev/null 2>&1 || {
    echo "error: adb not found in PATH" >&2
    exit 1
  }
  adb install -r "$OUT/GeekTraceBench.apk"
  adb shell am start -n com.geektrace.bench/.MainActivity
fi
