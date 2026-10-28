import hashlib
import hmac
import json
from pathlib import Path

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "tests" / "golden" / "bench-crypto-vectors.json"
)
BENCH_ROOT = Path(__file__).resolve().parents[2] / "tests" / "benchapp"


def _fnv1a64(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def _control_flow(seed: int) -> int:
    acc = seed + 11 if seed & 1 else seed - 7
    i = 0
    while i < 5:
        acc += i * i
        i += 1
    while True:
        acc ^= acc << 3
        acc &= 0x7FFFFFFF
        i -= 1
        if i <= 0:
            break
    kind = seed & 3
    if kind == 0:
        acc += 100
    elif kind == 1:
        acc += 200
    elif kind == 2:
        acc -= 50
    else:
        acc ^= 0x1234
    if seed & 4:
        acc = (acc * 3 + 1) & 0x7FFFFFFF
    else:
        acc = ((acc ^ 0x5A5A5A5A) + 7) & 0x7FFFFFFF
    for j in range(4):
        if acc & (1 << j):
            acc += j * 3
        else:
            acc -= j
    return acc & 0x7FFFFFFF


def test_bench_vectors_are_self_consistent():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    assert _fnv1a64(b"geektrace-bench") == int(
        vectors["fnv1a64"]["expected_hex"], 16
    )
    control = vectors["control_flow"]
    assert [
        _control_flow(seed) for seed in control["seeds"]
    ] == control["expected_results"]

    hashes = vectors["hashes"]
    assert hashlib.sha1(b"abc").hexdigest() == hashes["sha1_abc"]
    assert hashlib.sha256(b"abc").hexdigest() == hashes["sha256_abc"]
    assert hashlib.md5(b"abc").hexdigest() == hashes["md5_abc"]
    assert hashes["md4_abc"] == "a448017aaf21d8525fc10ae87aa6729d"

    hmac_vector = vectors["hmac_sha256"]
    assert (
        hmac.new(
            hmac_vector["key_ascii"].encode(),
            hmac_vector["message_ascii"].encode(),
            hashlib.sha256,
        ).hexdigest()
        == hmac_vector["expected_hex"]
    )

    token = vectors["files"]["token_bin"]
    assert (
        hashlib.sha256(token["content_ascii"].encode()).hexdigest() == token["sha256"]
    )
    payload = vectors["files"]["final_bin"]
    assert (
        hashlib.sha256(payload["content_ascii"].encode()).hexdigest()
        == payload["sha256"]
    )

    gcm = vectors["aes_gcm_128"]
    assert len(bytes.fromhex(gcm["ciphertext_hex"])) == 16
    assert len(bytes.fromhex(gcm["tag_hex"])) == 16
    assert len(bytes.fromhex(vectors["aes_cbc_128"]["ciphertext_hex"])) == 16
    assert vectors["des_ecb"]["ciphertext_hex"] == "85e813540f0ab405"


def test_bench_sources_use_fixture_constants():
    native = (BENCH_ROOT / "jni" / "bench.c").read_text(encoding="utf-8")
    activity = (
        BENCH_ROOT / "java" / "com" / "geektrace" / "bench" / "MainActivity.java"
    ).read_text(encoding="utf-8")
    assert "14695981039346656037ULL" in native
    assert "5323407" in activity
    assert "1515236178" in activity
    assert "978154e456c326bd" in activity
    assert "ab6e47d42cec13bdf53a67b21257bddf" in activity
