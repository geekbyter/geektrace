import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .event import default_policy
from .report import generate_summary
from .runstore import RunWriter

APP = "com.example.bench"
PID = 4242
UID = 10123
COMM = "com.example.bench"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.base = datetime.now(timezone.utc).replace(microsecond=0)
        self.offset_ms = 0

    def tick(self, step_ms: int = 3) -> tuple[str, int]:
        self.offset_ms += step_ms
        moment = self.base + timedelta(milliseconds=self.offset_ms)
        return (
            moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            1_000_000_000 + self.offset_ms * 1_000_000,
        )


def create_demo_run(
    runs_root: Path, *, session_id: str | None = None
) -> tuple[Path, dict[str, Path]]:
    writer = RunWriter(
        runs_root,
        app=APP,
        profile="ai",
        backend="demo",
        transport="synthetic",
        mode="cold-start",
        serial="demo-synthetic",
        demo=True,
        options={"demo": True, "note": "synthetic bench session"},
        session_id=session_id,
    )
    writer.set_device(
        {
            "serial": "demo-synthetic",
            "model": "geektrace bench",
            "manufacturer": "geektrace",
            "android": "14",
            "sdk": 34,
            "kernel": "6.1.99-demo",
            "abi": "arm64-v8a",
        }
    )
    clock = _Clock()

    def emit(layer: str, kind: str, **fields: Any) -> dict[str, Any]:
        ts, mono_ns = clock.tick()
        fields.setdefault("pid", PID)
        fields.setdefault("tid", PID)
        fields.setdefault("uid", UID)
        fields.setdefault("comm", COMM)
        fields.setdefault("thread", "main")
        return writer.emit(layer, kind, ts=ts, mono_ns=mono_ns, **fields)

    emit(
        "session",
        "session.start",
        pid=None,
        tid=None,
        uid=None,
        comm=None,
        thread=None,
        args={"app": APP, "profile": "ai", "mode": "cold-start", "backend": "demo"},
    )
    emit(
        "process",
        "process.fork",
        comm="zygote64",
        thread="main",
        args={"ppid": 812, "child_comm": COMM, "uid": UID},
    )
    emit(
        "process",
        "process.rename",
        args={"name": COMM, "from": "zygote64"},
    )
    emit(
        "loader",
        "loader.apk_open",
        args={
            "path": "/data/app/~~demo/base.apk",
            "sha256": _sha256(b"demo-apk"),
            "size": 9_437_184,
        },
    )
    emit(
        "loader",
        "loader.dex_magic",
        args={"path": "base.apk!classes.dex", "magic": "dex\\n035", "size": 184_320},
    )
    emit(
        "loader",
        "loader.dlopen",
        args={
            "path": "/data/app/~~demo/lib/arm64/libbench.so",
            "handle": "0x7f4a2c0000",
            "caller": "System.loadLibrary",
            "sha256": _sha256(b"demo-native"),
        },
    )
    emit(
        "jni",
        "jni.register",
        args={
            "name": "nativeAesGcm",
            "signature": "([B[B[B)[B",
            "fn_ptr": "0x7f4a2c41d0",
            "module": "libbench.so",
        },
    )
    emit(
        "art",
        "art.method_enter",
        confidence="inferred",
        args={
            "method": "MainActivity.onCreate",
            "signature": "(Landroid/os/Bundle;)V",
            "dex": "classes.dex",
        },
        policy=default_policy(reason="nterp entry observation; AOT bodies are not visible"),
    )

    su_event = emit(
        "file",
        "file.open",
        args={
            "path": "/system/bin/su",
            "flags": "O_RDONLY",
            "result": "ENOENT",
            "purpose": "root_check_probe",
        },
    )
    getprop_event = emit(
        "file",
        "file.open",
        args={
            "path": "/system/bin/getprop",
            "flags": "O_RDONLY",
            "result": "OK",
            "purpose": "adb_property_probe",
        },
    )
    tracer_event = emit(
        "file",
        "file.read",
        args={
            "path": "/proc/self/status",
            "len": 1536,
            "field": "TracerPid",
            "value": "0",
            "sha256": _sha256(b"demo-status"),
        },
    )
    binder_event = emit(
        "binder",
        "binder.transaction",
        confidence="inferred",
        args={
            "interface": "android.content.pm.IPackageManager",
            "code": "getInstalledPackages",
            "flags": 0,
            "parcel_bytes": 16_384,
        },
        policy=default_policy(reason="transaction code decoded from Binder schema"),
    )
    emit(
        "detect",
        "detect.finding",
        args={
            "category": "root",
            "verdict": "observed",
            "checks": ["openat /system/bin/su", "access /sbin/su"],
            "result": "not_found",
        },
        evidence_ids=[su_event["seq"]],
    )
    emit(
        "detect",
        "detect.finding",
        args={
            "category": "adb",
            "verdict": "observed",
            "property": "service.adb.tcp.port",
            "value": "0",
        },
        evidence_ids=[getprop_event["seq"]],
        confidence="partial",
    )
    emit(
        "detect",
        "detect.finding",
        args={"category": "debugger", "verdict": "observed", "field": "TracerPid", "value": 0},
        evidence_ids=[tracer_event["seq"]],
    )
    emit(
        "detect",
        "detect.finding",
        args={
            "category": "installed_apps",
            "verdict": "observed",
            "query": "getInstalledPackages",
            "result_count": 143,
        },
        evidence_ids=[binder_event["seq"]],
        confidence="partial",
    )

    token = b"demo-token-0123456789abcdef"
    emit(
        "file",
        "file.open",
        args={
            "path": "/data/user/0/com.example.bench/files/token.bin",
            "flags": "O_WRONLY|O_CREAT|O_TRUNC",
            "result": "OK",
        },
    )
    emit(
        "file",
        "file.write",
        args={
            "path": "/data/user/0/com.example.bench/files/token.bin",
            "len": len(token),
            "sha256": _sha256(token),
        },
    )
    emit(
        "file",
        "file.read",
        args={
            "path": "/data/user/0/com.example.bench/files/token.bin",
            "len": len(token),
            "sha256": _sha256(token),
        },
    )

    aes_key = bytes(range(32))
    aes_iv = bytes(range(12))
    plaintext = b'{"password":"demo-pass","token":"' + token + b'","padding":"' + b"x" * 64 + b'"}'
    ciphertext = _sha256(plaintext)[:32].encode("ascii")
    aes_location = {
        "module": "libcrypto.so",
        "build_id": "demo-build-id",
        "file_offset": "0x4a120",
        "symbol": "EVP_EncryptInit_ex",
    }
    emit(
        "crypto",
        "crypto.evp_init",
        location=aes_location,
        args={
            "alg": "AES-256-GCM",
            "dir": "encrypt",
            "key_b64": _b64(aes_key),
            "key_sha256": _sha256(aes_key),
            "iv_b64": _b64(aes_iv),
            "iv_sha256": _sha256(aes_iv),
        },
        correlation={"call_id": "call-aes-1"},
        policy=default_policy(sensitive=True),
    )
    emit(
        "crypto",
        "crypto.evp_update",
        location=aes_location,
        args={
            "alg": "AES-256-GCM",
            "dir": "encrypt",
            "input_len": len(plaintext),
            "input_head_b64": _b64(plaintext[:64]),
            "input_sha256": _sha256(plaintext),
            "output_len": len(ciphertext),
            "output_sha256": _sha256(ciphertext),
        },
        correlation={"call_id": "call-aes-1"},
        policy=default_policy(
            sensitive=True,
            truncated=True,
            omitted_bytes=max(0, len(plaintext) - 64),
        ),
    )
    emit(
        "crypto",
        "crypto.evp_final",
        location=aes_location,
        args={"alg": "AES-256-GCM", "dir": "encrypt", "output_len": 16, "tag_sha256": _sha256(b"demo-tag")},
        correlation={"call_id": "call-aes-1"},
        policy=default_policy(sensitive=True),
    )
    digest_input = b"demo-token-0123456789abcdef"
    digest = hashlib.sha256(digest_input).digest()
    emit(
        "crypto",
        "crypto.digest",
        location={
            "module": "libcrypto.so",
            "build_id": "demo-build-id",
            "file_offset": "0x3b220",
            "symbol": "EVP_DigestUpdate",
        },
        args={
            "alg": "SHA-256",
            "input_len": len(digest_input),
            "input_sha256": _sha256(digest_input),
            "digest_b64": _b64(digest),
        },
        correlation={"call_id": "call-sha-1"},
    )
    emit(
        "crypto",
        "crypto.op",
        location={
            "module": "libcrypto.so",
            "build_id": "demo-build-id",
            "file_offset": "0x5c010",
            "symbol": "RSA_public_encrypt",
        },
        args={
            "alg": "RSA-2048",
            "dir": "encrypt",
            "padding": "OAEP",
            "key_sha256": _sha256(b"demo-rsa-public-key"),
            "input_len": 32,
            "output_len": 256,
        },
        correlation={"call_id": "call-rsa-1"},
    )
    emit(
        "crypto",
        "crypto.sign",
        location={
            "module": "libcrypto.so",
            "build_id": "demo-build-id",
            "file_offset": "0x61240",
            "symbol": "EVP_DigestSignFinal",
        },
        args={
            "alg": "ECDSA-with-SHA256",
            "dir": "sign",
            "key_sha256": _sha256(b"demo-ec-public-key"),
            "digest_sha256": _sha256(digest_input),
            "signature_b64": _b64(b"demo-ecdsa-signature"),
        },
        correlation={"call_id": "call-ecdsa-1"},
    )

    connection_id = "conn-51-203.0.113.10-443"
    emit(
        "net",
        "net.connect",
        thread="OkHttp",
        args={
            "fd": 51,
            "address": "203.0.113.10",
            "port": 443,
            "sni": "api.example.com",
            "family": "AF_INET",
            "sock_type": "SOCK_STREAM",
        },
        correlation={"connection_id": connection_id},
    )
    emit(
        "net",
        "net.dns",
        thread="OkHttp",
        args={
            "query": "api.example.com",
            "answers": ["203.0.113.10"],
            "query_type": "A",
        },
        correlation={"connection_id": connection_id},
        confidence="inferred",
    )
    emit(
        "net",
        "net.tls_handshake",
        thread="OkHttp",
        args={
            "fd": 51,
            "sni": "api.example.com",
            "version": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "alpn": "h2",
        },
        correlation={"connection_id": connection_id},
    )
    request_body = json.dumps(
        {"username": "demo", "password": "demo-pass"}, separators=(",", ":")
    ).encode()
    emit(
        "net",
        "net.tls_write",
        thread="OkHttp",
        args={
            "fd": 51,
            "sni": "api.example.com",
            "plaintext_len": 512,
            "plaintext_head_b64": _b64(
                b"POST /v1/login HTTP/2\r\nhost: api.example.com\r\n"
                b"content-type: application/json\r\n\r\n" + request_body
            ),
            "http": {
                "method": "POST",
                "path": "/v1/login",
                "host": "api.example.com",
                "body_sha256": _sha256(request_body),
            },
        },
        correlation={"connection_id": connection_id},
        policy=default_policy(sensitive=True, truncated=True, omitted_bytes=128),
    )
    emit(
        "net",
        "net.http_request",
        thread="OkHttp",
        args={
            "method": "POST",
            "url": "https://api.example.com/v1/login",
            "host": "api.example.com",
            "path": "/v1/login",
            "body_len": len(request_body),
            "body_sha256": _sha256(request_body),
        },
        correlation={"connection_id": connection_id, "request_id": "req-1"},
        confidence="inferred",
        policy=default_policy(sensitive=True),
    )
    emit(
        "net",
        "net.tls_read",
        thread="OkHttp",
        args={
            "fd": 51,
            "sni": "api.example.com",
            "plaintext_len": 188,
            "http": {"status": 200, "content_type": "application/json"},
        },
        correlation={"connection_id": connection_id},
    )
    response_body = b'{"code":0,"token":"demo-session-token"}'
    emit(
        "net",
        "net.http_response",
        thread="OkHttp",
        args={
            "status": 200,
            "content_type": "application/json",
            "body_len": len(response_body),
            "body_sha256": _sha256(response_body),
        },
        correlation={"connection_id": connection_id, "request_id": "req-1"},
        confidence="inferred",
    )

    emit(
        "coverage",
        "coverage.snapshot",
        thread="main",
        args={
            "module": "libbench.so",
            "blocks_seen": 54,
            "blocks_total": 128,
            "percent": 42.19,
            "probes": 128,
        },
    )
    emit(
        "tool",
        "tool.gap",
        pid=None,
        tid=None,
        uid=None,
        comm=None,
        thread=None,
        args={
            "component": "art",
            "reason": "aot_method_not_visible",
            "message": "MainActivity.onCreate is AOT-compiled; default backend cannot see Java branches",
        },
    )
    emit(
        "tool",
        "tool.drop",
        pid=None,
        tid=None,
        uid=None,
        comm=None,
        thread=None,
        args={
            "count": 3,
            "layer": "syscall",
            "reason": "ringbuf_full",
            "message": "3 ambient syscall events dropped during crypto burst",
        },
    )
    emit(
        "session",
        "session.stop",
        pid=None,
        tid=None,
        uid=None,
        comm=None,
        thread=None,
        args={"status": "ok", "reason": "demo_complete"},
    )

    writer.close(status="completed")
    paths = generate_summary(writer.run_dir)
    return writer.run_dir, paths
