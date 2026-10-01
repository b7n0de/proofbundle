"""The replay runner, offline, against a stand-in service that answers with round 3's stored responses.

tools/scitt_ccf_external/replay_earlier_build/replay_run.py reuses round 3's `register` and writes one row per
vector. These tests drive it with a stand-in that accepts the stored round 3 vectors that have a receipt and
refuses the others with round 3's own error, and check what a row carries: the request digest, the predicted and
the measured outcome, the refusal stage and raw error for a refusal, the returned-statement digest, the receipt's
data-hash, and C(n) from the oracle. A refused row carries no commitment result, and without committed
predictions the runner registers nothing.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "scitt_ccf_external"
REPLAY = TOOLS / "replay_earlier_build"

needs_reader = pytest.mark.skipif(any(importlib.util.find_spec(m) is None for m in ("cbor2", "cryptography")),
                                  reason="round 3's register and receipt check need cbor2 and cryptography")

STORED = {  # replay vector -> stored round 3 vector with a receipt
    "r3-control": "control", "r3-r-a10-cwt-claims-unprotected": "r-a10-cwt-claims-unprotected",
    "r3-x-pa-ub-sig-a": "x-pa-ub-sig-a", "r3-x-pb-ua-sig-b": "x-pb-ua-sig-b",
}


def _load(name: str, path: Path):
    if name not in sys.modules:
        if str(TOOLS) not in sys.path:
            sys.path.insert(0, str(TOOLS))
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _hex(p: Path) -> bytes:
    return bytes.fromhex(p.read_text(encoding="ascii").strip())


class StandIn:
    """Answers like the round 3 service did, from the stored bytes."""

    def __init__(self, oracle):
        self.o = oracle
        self.by_request = {}
        for name in json.loads((REPLAY / "vectors.json").read_text(encoding="utf-8"))["vectors"]:
            req = _hex(REPLAY / "vectors" / name["name"] / "request.hex")
            self.by_request[req] = name["name"]
        self.txids = {}

    def call(self, method, path, body=None, ctype=None):
        r3 = TOOLS / "differential_corpus_round3"
        if path == "/node/version":
            return 200, {}, b'{"ccf_version": "ccf-stand-in"}'
        if path == "/configuration":
            return 200, {}, b'{"authentication": {"allowUnauthenticated": true}}'
        if path == "/.well-known/scitt-keys":
            return 200, {}, _hex(r3 / "scitt-keys.hex")
        if method == "POST" and path == "/entries":
            name = self.by_request[body]
            if name in STORED:
                txid = f"2.{len(self.txids) + 100}"
                self.txids[txid] = STORED[name]
                return 202, {}, self.o.encode({"OperationId": txid})
            return 400, {}, self.o.encode({"-1": "InvalidInput", "-2": "Signature verification failed"})
        if path.startswith("/operations/"):
            return 200, {}, self.o.encode({"Status": "succeeded", "EntryId": path.rsplit("/", 1)[-1]})
        if path.startswith("/entries/") and path.endswith("/statement"):
            return 200, {}, _hex(r3 / "vectors" / self.txids[path.split("/")[2]] / "statement.hex")
        if path.startswith("/entries/"):
            return 200, {}, _hex(r3 / "vectors" / self.txids[path.split("/")[2]] / "receipt.hex")
        return 404, {}, b""


def _predictions(tmp_path: Path) -> Path:
    vectors = json.loads((REPLAY / "vectors.json").read_text(encoding="utf-8"))["vectors"]
    p = tmp_path / "predictions.json"
    p.write_text(json.dumps({"vectors": [{"name": v["name"], "predicted": {"outcome": "stand-in"}} for v in vectors]}),
                 encoding="utf-8")
    return p


@needs_reader
def test_the_runner_writes_one_row_per_vector_in_the_replay_columns(tmp_path):
    runner = _load("_replay_run", REPLAY / "replay_run.py")
    oracle = _load("_replay_oracle", REPLAY / "oracle.py")
    s = runner.run(StandIn(oracle), tmp_path / "out", "commit-x", "image-y", "stand-in", _predictions(tmp_path))
    rows = {r["vector"]: r for r in s["rows"]}
    assert len(rows) == 9
    for name, stored in STORED.items():
        r = rows[name]
        assert r["measured_outcome"] == "registered", r
        assert r["data_hash_match"] is True and r["receipt_signature_valid"] is True
        assert r["rebuilt_cn_sha256"] == r["receipt_data_hash"]
        assert r["rebuilt_equals_returned_minus_394"] is True
        assert r["returned_statement_sha256"] is not None
        assert (tmp_path / "out" / name / "receipt.hex").is_file()
    for name in set(rows) - set(STORED):
        r = rows[name]
        assert r["measured_outcome"] == "refused" and r["refusal_stage"] == "POST /entries"
        assert "Signature verification failed" in r["raw_service_error"]
        assert r["receipt_data_hash"] is None and r["data_hash_match"] is None
        assert r["returned_statement_sha256"] is None
        assert not (tmp_path / "out" / name / "receipt.hex").exists()
    for r in rows.values():
        assert r["predicted"] == {"outcome": "stand-in"}
        assert r["service_commit"] == "commit-x" and r["image_id"] == "image-y" and r["ccf_version"] == "ccf-stand-in"
        assert len(r["request_sha256"]) == 64 and r["http"]
    assert json.loads((tmp_path / "out" / "rows.json").read_text(encoding="utf-8"))["rows"] == s["rows"]


@needs_reader
def test_without_predictions_the_runner_registers_nothing(tmp_path):
    runner = _load("_replay_run", REPLAY / "replay_run.py")
    oracle = _load("_replay_oracle", REPLAY / "oracle.py")
    svc = StandIn(oracle)
    with pytest.raises(SystemExit, match="no predictions"):
        runner.run(svc, tmp_path / "out", "c", "i", "l", tmp_path / "absent.json")
    assert svc.txids == {}
    assert not (tmp_path / "out").exists()
