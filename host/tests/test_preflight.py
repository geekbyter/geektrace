import zipfile

from geektrace.preflight import (
    axml_strings,
    build_preflight,
    build_probe_plan,
    detection_candidates,
    inspect_apk,
)


def _make_apk(path):
    dex = (
        b"dex\n035\x00"
        b"/system/bin/su"
        b"isDebuggerConnected"
        b"AES/CBC/PKCS5Padding"
        b"https://api.example.com/v1/login"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", dex)
        archive.writestr("lib/arm64-v8a/libapp.so", b"\x7fELF" + b"\x00" * 32)
        archive.writestr("lib/armeabi-v7a/libapp.so", b"\x7fELF" + b"\x00" * 16)
        archive.writestr("assets/config.json", b"{}")
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
    return path


def test_inspect_apk_lists_payload_and_markers(tmp_path):
    apk = inspect_apk(_make_apk(tmp_path / "app.apk"))
    assert apk["entries"] == 5
    assert apk["dex_files"] == ["classes.dex"]
    assert sorted(apk["abis"]) == ["arm64-v8a", "armeabi-v7a"]
    assert len(apk["native_libs"]) == 2
    assert all(item["elf"] for item in apk["native_libs"])
    assert apk["asset_entries"] == 1
    assert apk["detection_markers"]["/system/bin/su"] == 1
    assert "isDebuggerConnected" in apk["detection_markers"]
    assert "AES/CBC" in apk["crypto_markers"]
    assert apk["errors"] == []


def test_detection_candidates_are_static_only(tmp_path):
    apk = inspect_apk(_make_apk(tmp_path / "app.apk"))
    candidates = detection_candidates(apk)
    categories = {item["category"] for item in candidates}
    assert "root" in categories
    assert "debugger" in categories
    for item in candidates:
        assert item["status"] == "static_candidate"
        assert item["confidence"] == "inferred"


def test_missing_apk_is_reported_not_raised(tmp_path):
    apk = inspect_apk(tmp_path / "nope.apk")
    assert apk["errors"] == ["apk not found"]
    assert apk["detection_markers"] == {}


def test_probe_plan_scales_payload_with_profile():
    assert build_probe_plan("ai")["payload_limit"] == 255
    assert build_probe_plan("stealth")["payload_limit"] == 64
    safe = build_probe_plan("safe")
    assert safe["payload_limit"] == 0
    assert safe["stack"] is False
    assert safe["probes"]


def test_axml_string_pool_round_trip():
    import struct

    strings = ["com.example.app", "android.permission.INTERNET"]
    encoded = b""
    offsets = []
    for value in strings:
        offsets.append(len(encoded))
        raw = value.encode("utf-8")
        encoded += struct.pack("<BB", len(value), len(raw)) + raw + b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    chunk_size = strings_start + len(encoded)
    chunk = struct.pack(
        "<HHIIIIII",
        0x0001,
        header_size,
        chunk_size,
        len(strings),
        0,
        0x100,
        strings_start,
        0,
    )
    chunk += b"".join(struct.pack("<I", offset) for offset in offsets)
    chunk += encoded
    document = struct.pack("<HHI", 0x0003, 8, 8 + len(chunk)) + chunk
    assert axml_strings(document) == strings


def test_build_preflight_without_device_is_static_only(tmp_path):
    report = build_preflight(
        _make_apk(tmp_path / "app.apk"),
        app="com.example.app",
        device={"capabilities": {}, "unsupported": ["root"]},
    )
    assert report["schema"] == "geektrace.preflight.v1"
    assert report["app"] == "com.example.app"
    assert report["static_detections"]
    assert report["limits"]
    assert report["plan"]["probes"]
