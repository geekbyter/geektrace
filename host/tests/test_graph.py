import json

from geektrace.graph import build_graph, graph_for_run, render_markdown


def _event(seq, layer, kind, args, **extra):
    event = {
        "schema": "geektrace.event.v1",
        "seq": seq,
        "session": "session",
        "ts": "2026-10-27T00:00:00.000Z",
        "mono_ns": seq * 1_000_000,
        "layer": layer,
        "kind": kind,
        "backend": "ebpf",
        "confidence": "exact",
        "pid": 4242,
        "tid": 4300,
        "uid": 10234,
        "comm": "app",
        "args": args,
        "policy": {"capture_status": "captured"},
        "stack": [],
    }
    event.update(extra)
    return event


def _tls_write(seq, mono_ns):
    event = _event(seq, "net", "net.tls_write", {"dir": "out", "len": 32})
    event["mono_ns"] = mono_ns
    event["correlation"] = {"connection_id": "ssl:4242:0x7f00"}
    return event


def _crypto_entry(seq, mono_ns):
    event = _event(
        seq,
        "crypto",
        "crypto.evp_update",
        {
            "fn": "EVP_EncryptUpdate",
            "dir": "encrypt",
            "phase": "entry",
            "input_len": 32,
        },
    )
    event["mono_ns"] = mono_ns
    event["correlation"] = {"call_id": "4242-4300-1000"}
    event["location"] = {"module": "libcrypto.so", "symbol": "EVP_EncryptUpdate"}
    return event


def test_graph_links_crypto_to_request_as_candidate():
    events = [_tls_write(1, 1_000_000), _crypto_entry(2, 1_100_000)]
    graph = build_graph(events)
    assert graph["counts"]["requests"] == 1
    assert graph["counts"]["crypto_operations"] == 1
    candidates = [edge for edge in graph["edges"] if edge["kind"] == "crypto_candidate"]
    assert len(candidates) == 1
    assert candidates[0]["confidence"] == "inferred"
    assert "same_thread=4300" in candidates[0]["reasons"]


def test_graph_keeps_far_events_unlinked():
    events = [_tls_write(1, 1_000_000), _crypto_entry(2, 9_000_000_000)]
    graph = build_graph(events)
    candidates = [edge for edge in graph["edges"] if edge["kind"] == "crypto_candidate"]
    assert candidates == []
    assert graph["counts"]["unlinked_requests"] == 1


def test_graph_links_detection_to_evidence():
    opened = _event(1, "file", "file.open", {"path": "/proc/self/status"})
    finding = _event(
        2,
        "detect",
        "detect.finding",
        {"category": "debugger", "verdict": "observed", "rule": "proc_status_open"},
    )
    finding["evidence_ids"] = [1]
    graph = build_graph([opened, finding])
    evidence_edges = [edge for edge in graph["edges"] if edge["kind"] == "evidence"]
    assert len(evidence_edges) == 1
    assert evidence_edges[0]["confidence"] == "exact"
    assert evidence_edges[0]["evidence_ids"] == [1]


def test_graph_for_run_reads_events(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in [_tls_write(1, 1_000_000)]),
        encoding="utf-8",
    )
    graph = graph_for_run(run_dir)
    assert graph["schema"] == "geektrace.graph.v1"
    assert graph["counts"]["requests"] == 1
    assert "evidence graph" in render_markdown(graph)
