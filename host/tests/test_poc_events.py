import json
from pathlib import Path

from geektrace.report import generate_summary, load_run, summarize_event


def _event(seq, layer, kind, pid, tid, comm, args, location=None):
    event = {
        "schema": "geektrace.event.v1",
        "seq": seq,
        "session": "poc-shape-test",
        "ts": f"2026-10-26T00:00:{seq:02d}.000Z",
        "mono_ns": seq * 1_000_000,
        "layer": layer,
        "kind": kind,
        "backend": "ebpf",
        "confidence": "exact",
        "pid": pid,
        "tid": tid,
        "uid": 10234,
        "comm": comm,
        "args": args,
        "policy": {"redacted": False, "truncated": False},
    }
    if location:
        event["location"] = location
    return event


def test_broker_event_shapes_reach_host_ledgers(tmp_path):
    run_dir = tmp_path / "poc-run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "session": "poc-shape-test",
                "app": "com.geektrace.bench",
                "profile": "ai",
                "mode": "cold-start",
                "backend": "ebpf",
                "status": "completed",
            }
        ),
        encoding="utf-8",
    )
    events = [
        _event(
            1,
            "process",
            "process.fork",
            1234,
            1234,
            "zygote64",
            {
                "ppid": 1234,
                "parent_pid": 1234,
                "child_pid": 4321,
                "parent_comm": "zygote64",
                "child_comm": "zygote64",
            },
        ),
        _event(
            2,
            "file",
            "file.open",
            4321,
            4321,
            "geektrace.bench",
            {
                "dfd": -100,
                "flags": "0x0",
                "path": "/data/user/0/com.geektrace.bench/files/bench.log",
            },
        ),
        _event(
            3,
            "net",
            "net.tls_write",
            4321,
            4400,
            "bench-workload",
            {
                "dir": "out",
                "len": 96,
                "input_len": 96,
                "ssl": "0x7f00000000",
                "head_hex": "474554202f",
            },
            {"module": "libssl.so", "symbol": "SSL_write"},
        ),
        _event(
            4,
            "net",
            "net.tls_read",
            4321,
            4400,
            "bench-workload",
            {"dir": "in", "len": 2048, "input_len": 2048, "ssl": "0x7f00000000"},
            {"module": "libssl.so", "symbol": "SSL_read"},
        ),
        _event(
            5,
            "crypto",
            "crypto.evp_update",
            4321,
            4400,
            "bench-workload",
            {
                "fn": "EVP_EncryptUpdate",
                "dir": "encrypt",
                "input_len": 64,
                "ctx": "0x7e00000000",
                "head_hex": "00010203",
            },
            {"module": "libcrypto.so", "symbol": "EVP_EncryptUpdate"},
        ),
        _event(
            6,
            "crypto",
            "crypto.evp_update",
            4321,
            4400,
            "bench-workload",
            {
                "fn": "EVP_DigestUpdate",
                "dir": "digest",
                "input_len": 16,
                "ctx": "0x7e00001000",
                "head_hex": "61626364",
            },
            {"module": "libcrypto.so", "symbol": "EVP_DigestUpdate"},
        ),
        _event(
            7,
            "crypto",
            "crypto.evp_update",
            4321,
            4400,
            "bench-workload",
            {
                "fn": "EVP_DecryptUpdate",
                "dir": "decrypt",
                "input_len": 32,
                "ctx": "0x7e00002000",
                "head_hex": "00010203",
            },
            {"module": "libcrypto.so", "symbol": "EVP_DecryptUpdate"},
        ),
        _event(
            8,
            "crypto",
            "crypto.digest",
            4321,
            4400,
            "bench-workload",
            {
                "fn": "EVP_Digest",
                "dir": "digest",
                "input_len": 8,
                "data": "0x7e00003000",
                "head_hex": "61626364",
            },
            {"module": "libcrypto.so", "symbol": "EVP_Digest"},
        ),
        _event(
            9,
            "crypto",
            "crypto.sign_update",
            4321,
            4400,
            "bench-workload",
            {
                "fn": "EVP_DigestSignUpdate",
                "dir": "sign",
                "input_len": 32,
                "ctx": "0x7e00004000",
                "head_hex": "00010203",
            },
            {"module": "libcrypto.so", "symbol": "EVP_DigestSignUpdate"},
        ),
        _event(
            10,
            "crypto",
            "crypto.verify_update",
            4321,
            4400,
            "bench-workload",
            {
                "fn": "EVP_DigestVerifyUpdate",
                "dir": "verify",
                "input_len": 32,
                "ctx": "0x7e00005000",
                "head_hex": "00010203",
            },
            {"module": "libcrypto.so", "symbol": "EVP_DigestVerifyUpdate"},
        ),
    ]
    (run_dir / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )

    paths = generate_summary(run_dir)
    summary = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    data = load_run(run_dir)
    assert data.validation_errors == []
    assert summary["counts"]["events"] == 10

    assert summary["files"]["events"]["open"] == 1
    assert summary["files"]["paths"]["entries"][0]["path"].endswith("bench.log")
    assert summary["files"]["private_paths"] == [
        "/data/user/0/com.geektrace.bench/files/bench.log"
    ]

    assert summary["network"]["tls"]["count"] == 2
    assert summary["crypto"]["operations"]["count"] == 6
    operations = summary["crypto"]["operations"]["entries"]
    assert (operations[0]["dir"], operations[0]["input_len"]) == ("encrypt", 64)
    assert (operations[1]["dir"], operations[1]["input_len"]) == ("digest", 16)
    assert (operations[2]["dir"], operations[2]["input_len"]) == ("decrypt", 32)
    assert (operations[3]["dir"], operations[3]["input_len"]) == ("digest", 8)
    assert (operations[4]["dir"], operations[4]["input_len"]) == ("sign", 32)
    assert (operations[5]["dir"], operations[5]["input_len"]) == ("verify", 32)
    assert operations[0]["location"] == "libcrypto.so(EVP_EncryptUpdate)"

    timeline = {entry["seq"]: entry for entry in summary["timeline"]["entries"]}
    assert timeline[1]["summary"] == "fork pid=4321 ppid=1234 comm=zygote64"
    assert timeline[3]["summary"] == "out 96"
    assert timeline[4]["summary"] == "in 2048"
    assert timeline[5]["summary"] == "encrypt 64"
    assert timeline[6]["summary"] == "digest 16"
    assert timeline[7]["summary"] == "decrypt 32"
    assert timeline[8]["summary"] == "digest 8"
    assert timeline[9]["summary"] == "sign 32"
    assert timeline[10]["summary"] == "verify 32"

    tls_write = next(event for event in data.events if event["kind"] == "net.tls_write")
    assert summarize_event(tls_write) == "out 96"

    text = Path(paths["summary_md"]).read_text(encoding="utf-8")
    assert "TLS events: 2" in text
    assert "bench.log" in text
    assert "观察到 6 条 crypto 操作" in text
    assert "观察到 2 条网络/TLS 事件" in text
    assert "未观察到 crypto 事件" not in text
    assert "未观察到网络事件" not in text
    assert "Crypto operations observed: 6" in text
    assert "Network/TLS events observed: 2" in text


def test_return_connect_and_detection_shapes_are_traceable(tmp_path):
    run_dir = tmp_path / "poc-new-shapes"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "session": "poc-shape-test",
                "app": "com.geektrace.bench",
                "profile": "ai",
                "mode": "cold-start",
                "backend": "ebpf",
                "status": "completed",
            }
        ),
        encoding="utf-8",
    )
    connect = _event(
        1,
        "net",
        "net.connect",
        4321,
        4400,
        "bench-workload",
        {"fd": 7, "family": 2, "address": "127.0.0.1", "port": 4443},
    )
    connect["correlation"] = {"call_id": "4321:4400:11", "socket_id": "fd:4321:7"}
    opened = _event(
        2,
        "file",
        "file.open",
        4321,
        4400,
        "bench-workload",
        {"dfd": -100, "flags": "0x0", "path": "/proc/self/status"},
    )
    finding = _event(
        3,
        "detect",
        "detect.finding",
        4321,
        4400,
        "bench-workload",
        {
            "category": "debugger",
            "verdict": "observed",
            "rule": "proc_status_open",
            "path": "/proc/self/status",
        },
    )
    finding["confidence"] = "inferred"
    finding["evidence_ids"] = [2]
    entry = _event(
        4,
        "crypto",
        "crypto.evp_update",
        4321,
        4400,
        "bench-workload",
        {
            "fn": "EVP_EncryptUpdate",
            "dir": "encrypt",
            "phase": "entry",
            "input_len": 4,
            "ctx": "0x7e00000000",
            "input_head_hex": "73656374",
        },
        {"module": "libcrypto.so", "file_offset": "0x1234", "symbol": "EVP_EncryptUpdate"},
    )
    entry["correlation"] = {"call_id": "4321:4400:20", "context_id": "ctx:4321:0x7e00000000"}
    returned = _event(
        5,
        "crypto",
        "crypto.evp_update",
        4321,
        4400,
        "bench-workload",
        {
            "fn": "EVP_EncryptUpdate",
            "dir": "encrypt",
            "phase": "return",
            "ret": 1,
            "output_len": 4,
            "ctx": "0x7e00000000",
            "output_head_hex": "aabbccdd",
        },
        {"module": "libcrypto.so", "file_offset": "0x1234", "symbol": "EVP_EncryptUpdate"},
    )
    returned["correlation"] = entry["correlation"]
    returned["stack"] = [{"pc": "0x7000", "resolved": True, "module": "libapp.so", "file_offset": "0x456"}]
    tls_read = _event(
        6,
        "net",
        "net.tls_read",
        4321,
        4400,
        "bench-workload",
        {
            "dir": "in",
            "phase": "return",
            "len": 4,
            "ret": 4,
            "output_len": 4,
            "ssl": "0x7f00000000",
            "plaintext_head_hex": "48545450",
        },
    )
    events = [connect, opened, finding, entry, returned, tls_read]
    (run_dir / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )

    paths = generate_summary(run_dir)
    summary = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    data = load_run(run_dir)
    assert data.validation_errors == []
    assert summary["counts"]["events"] == 6
    assert summary["network"]["connections"]["entries"][0]["address"] == "127.0.0.1"
    assert summary["network"]["connections"]["entries"][0]["port"] == 4443
    assert summary["network"]["tls"]["entries"][0]["args"]["output_len"] == 4
    assert summary["detections"][0]["category"] == "debugger"
    assert summary["detections"][0]["evidence"][0]["seq"] == 2
    # The entry and the return event describe one crypto call, so the ledger
    # reports one operation with both halves filled in.
    assert summary["crypto"]["operations"]["count"] == 1
    operation = summary["crypto"]["operations"]["entries"][0]
    assert operation["input_len"] == 4
    assert operation["output_len"] == 4
    assert operation["complete"] is True
    assert operation["confidence"] == "exact"
    assert data.events[3]["correlation"]["call_id"] == data.events[4]["correlation"]["call_id"]
    assert data.events[4]["stack"][0]["file_offset"] == "0x456"
    assert summarize_event(connect) == "127.0.0.1:4443"
    assert summarize_event(returned) == "encrypt 4"
    assert summarize_event(tls_read) == "in 4"
