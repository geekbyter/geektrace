import json
import struct

from geektrace.cli import main
from geektrace.event import new_event
from geektrace.locate import locate_keyword, parse_keyword


def make_run(tmp_path, events):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    lines = []
    for index, (layer, kind, args) in enumerate(events, 1):
        event = new_event(
            session="locate-test",
            seq=index,
            layer=layer,
            kind=kind,
            backend="ebpf",
            ts=f"2026-10-26T00:00:00.{index:03d}Z",
            mono_ns=index * 1_000_000,
            pid=100,
            tid=200,
            args=args,
            location={"module": "libcrypto.so", "file_offset": "0x1234", "symbol": "EVP_EncryptUpdate"},
            stack=[{"pc": "0x7000", "module": "libapp.so", "file_offset": "0x456"}],
        )
        lines.append(json.dumps(event))
    (run_dir / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return run_dir


def test_direct_ciphertext_hit_is_exact(tmp_path):
    run_dir = make_run(tmp_path, [
        ("crypto", "crypto.evp_update", {"dir": "encrypt", "phase": "return", "output_head_hex": "aabbccdd"}),
    ])
    result = locate_keyword(run_dir, "hex:bbcc")
    assert result["counts"]["crypto"] == 1
    exact = next(chain for chain in result["chains"] if chain["confidence"] == "payload_exact")
    assert exact["crypto"]["seq"] == 1
    assert exact["crypto"]["stack"][0]["file_offset"] == "0x456"
    assert exact["crypto"]["location"]["file_offset"] == "0x1234"


def test_plaintext_network_hit_ranks_same_thread_crypto(tmp_path):
    run_dir = make_run(tmp_path, [
        ("net", "net.tls_write", {"dir": "out", "len": 4, "plaintext_head_hex": "736563726574"}),
        ("crypto", "crypto.evp_update", {"dir": "encrypt", "input_len": 4, "input_head_hex": "736563726574"}),
    ])
    result = locate_keyword(run_dir, "secret", window_ms=5)
    assert result["counts"]["network"] == 1
    assert result["counts"]["crypto"] == 1
    inferred = [chain for chain in result["chains"] if chain["confidence"] == "temporal_inferred"]
    assert inferred[0]["network"]["seq"] == 1
    assert inferred[0]["crypto"]["seq"] == 2
    assert "same_tid" in inferred[0]["reasons"]


def test_capture_pcap_hit_aligns_network_by_time(tmp_path):
    run_dir = make_run(tmp_path, [
        ("net", "net.tls_write", {"dir": "out", "len": 8, "plaintext_head_hex": "00"}),
    ])
    pcap = tmp_path / "capture.pcap"
    packet = b"xxciphertextyy"
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    pcap.write_bytes(header + struct.pack("<IIII", 1792972800, 1_000, len(packet), len(packet)) + packet)
    result = locate_keyword(run_dir, "cipher", capture=pcap, window_ms=10)
    assert result["capture"]["mode"] == "pcap_packet"
    assert result["capture_matches"][0]["packet_index"] == 0
    assert result["chains"][0]["network"]["seq"] == 1


def test_window_excludes_temporal_candidate(tmp_path):
    run_dir = make_run(tmp_path, [
        ("net", "net.tls_write", {"plaintext_head_hex": "736563726574"}),
        ("crypto", "crypto.evp_update", {"input_head_hex": "00"}),
    ])
    result = locate_keyword(run_dir, "secret", window_ms=0.5)
    assert result["counts"]["network"] == 1
    assert result["chains"] == []


def test_no_stack_and_keyword_decodings(tmp_path):
    run_dir = make_run(tmp_path, [
        ("crypto", "crypto.digest", {"input_head_b64": "c2VjcmV0"}),
    ])
    (run_dir / "events.jsonl").write_text(
        (run_dir / "events.jsonl").read_text(encoding="utf-8").replace(
            '"stack": [{"pc": "0x7000", "module": "libapp.so", "file_offset": "0x456"}]',
            '"stack": []',
        ),
        encoding="utf-8",
    )
    assert parse_keyword("0x736563726574")[0] == b"secret"
    assert parse_keyword("base64:c2VjcmV0")[0] == b"secret"
    result = locate_keyword(run_dir, "secret")
    assert result["counts"]["crypto"] == 1
    assert any("No captured stack" in gap for gap in result["gaps"])


def test_cli_locate_json(tmp_path, capsys):
    run_dir = make_run(tmp_path, [
        ("crypto", "crypto.evp_update", {"output_head_hex": "aabbcc"}),
    ])
    assert main(["locate", str(run_dir), "hex:aabb"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "geektrace.locate.v1"
    assert payload["counts"]["crypto"] == 1


def test_raw_capture_offsets_and_no_hit_are_explicit(tmp_path):
    run_dir = make_run(tmp_path, [
        ("net", "net.tls_write", {"plaintext_head_hex": "736563726574"}),
    ])
    capture = tmp_path / "capture.bin"
    capture.write_bytes(b"xxciphertextyy")
    result = locate_keyword(run_dir, "cipher", capture=capture)
    assert result["capture"]["mode"] == "raw_bytes"
    assert result["capture_matches"] == [{"file_offset": 2}]
    assert result["chains"] == []
    assert any("not packet/connection matches" in gap for gap in result["gaps"])

    missing = locate_keyword(run_dir, "absent", capture=capture)
    assert missing["counts"] == {"capture": 0, "network": 0, "crypto": 0, "chains": 0}
    assert missing["parse_errors"] == []
