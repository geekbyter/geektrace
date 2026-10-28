from geektrace.crypto_ops import build_crypto_operations, summarize_operations


def _event(seq, phase, **args):
    args = dict(args)
    args.setdefault("phase", phase)
    return {
        "schema": "geektrace.event.v1",
        "seq": seq,
        "session": "session",
        "ts": "2026-10-27T00:00:00.000Z",
        "mono_ns": seq * 1_000,
        "layer": "crypto",
        "kind": "crypto.evp_update",
        "backend": "ebpf",
        "confidence": "exact",
        "pid": 4242,
        "tid": 4300,
        "uid": 10234,
        "comm": "app",
        "args": args,
        "correlation": {"call_id": "4242-4300-500"},
        "location": {"module": "libcrypto.so", "symbol": "EVP_EncryptUpdate"},
        "policy": {"capture_status": "captured"},
        "stack": [],
    }


def test_entry_and_return_merge_into_one_operation():
    events = [
        _event(1, "entry", fn="EVP_EncryptUpdate", dir="encrypt", input_len=8),
        _event(2, "return", fn="EVP_EncryptUpdate", dir="encrypt", output_len=8, ret=1),
    ]
    operations = build_crypto_operations(events)
    assert len(operations) == 1
    operation = operations[0]
    assert operation["input_len"] == 8
    assert operation["output_len"] == 8
    assert operation["complete"] is True
    assert operation["confidence"] == "exact"
    assert operation["location"]["text"] == "libcrypto.so(EVP_EncryptUpdate)"
    assert operation["seqs"] == [1, 2]
    summary = summarize_operations(operations)
    assert summary["count"] == 1
    assert summary["complete"] == 1
    assert summary["functions"]["EVP_EncryptUpdate"] == 1


def test_missing_return_stays_partial():
    events = [_event(1, "entry", fn="EVP_DigestUpdate", dir="digest", input_len=4)]
    operations = build_crypto_operations(events)
    assert operations[0]["complete"] is False
    assert operations[0]["confidence"] == "partial"
    assert summarize_operations(operations)["partial"] == 1


def test_events_without_call_id_are_not_merged():
    first = _event(1, "entry", fn="EVP_DigestUpdate", dir="digest", input_len=4)
    second = _event(2, "entry", fn="EVP_DigestUpdate", dir="digest", input_len=4)
    for event in (first, second):
        event.pop("correlation")
    operations = build_crypto_operations([first, second])
    assert len(operations) == 2


def test_non_crypto_events_are_ignored():
    event = _event(1, "entry", fn="EVP_DigestUpdate", dir="digest", input_len=4)
    event["layer"] = "net"
    assert build_crypto_operations([event]) == []


def test_return_is_matched_by_context_when_call_id_differs():
    entry = _event(1, "entry", fn="EVP_EncryptUpdate", dir="encrypt", input_len=8)
    entry["args"]["ctx"] = "0x7e00000000"
    entry["correlation"] = {"call_id": "4242-4300-1000"}
    returned = _event(
        2, "return", fn="EVP_EncryptUpdate", dir="encrypt", output_len=8, ret=1
    )
    returned["args"]["ctx"] = "0x7e00000000"
    # Older firmware builds the call id from a slightly different timestamp.
    returned["correlation"] = {"call_id": "4242-4300-1010"}
    returned["mono_ns"] = entry["mono_ns"] + 4_000
    operations = build_crypto_operations([entry, returned])
    assert len(operations) == 1
    assert operations[0]["complete"] is True
    assert operations[0]["matched_by"] == "context"
    assert operations[0]["input_len"] == 8
    assert operations[0]["output_len"] == 8
