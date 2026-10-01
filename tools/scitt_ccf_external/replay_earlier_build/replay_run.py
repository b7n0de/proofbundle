#!/usr/bin/env python3
"""Register the nine replay vectors on a running scitt-ccf-ledger and record one row per vector.

    python3 replay_run.py --url https://127.0.0.1:8000 --service-cert CERT --service-commit SHA --image-id ID \\
        --label NAME [--out runs/NAME]

It reuses `register` of round 3 (differential_corpus_round3.py), the exchange that ran against the real service
on 2026-09-27, so the API steps do not change between the rounds and the replay. Per vector it keeps the request,
the receipt and the returned statement as hex, the HTTP exchanges' status and body digests, and a row in the
columns of the replay: request digest, service commit and image digest, CCF version, configuration digest,
predicted outcome (from predictions.json, committed before any registration), measured registration outcome,
refusal stage and raw service error, returned-statement digest, receipt data-hash where present, and C(n) as
rebuilt by the independent oracle. A refused row has no receipt and no commitment result.

The oracle (oracle.py) is called on the stored bytes after the run; it imports nothing from proofbundle. This
runner may: it measures, it does not judge.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sha(b: bytes | None) -> str | None:
    return None if b is None else hashlib.sha256(b).hexdigest()


def _write_hex(path: Path, data: bytes) -> None:
    path.write_text(data.hex() + "\n", encoding="ascii")


def run(svc, out: Path, service_commit: str, image_id: str, label: str,
        predictions_path: Path = HERE / "predictions.json") -> dict:
    """Register every vector of vectors.json with `svc` (an object with call(method, path, body, ctype)).

    Without the committed predictions it refuses to register anything: an outcome measured before its
    prediction was fixed is not a replay of round 3's method."""
    if not predictions_path.is_file():
        raise SystemExit(f"no predictions at {predictions_path}: commit them before the first registration")
    r3 = _load("_replay_round3", TOOLS / "differential_corpus_round3.py")
    oracle = _load("_replay_oracle", HERE / "oracle.py")
    vectors = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))["vectors"]
    predictions = {p["name"]: p for p in json.loads(predictions_path.read_text(encoding="utf-8"))["vectors"]}
    out.mkdir(parents=True, exist_ok=True)
    _c, _h, version = svc.call("GET", "/node/version")
    _c, _h, cfg = svc.call("GET", "/configuration")
    _c, _h, keys = svc.call("GET", "/.well-known/scitt-keys")
    _write_hex(out / "scitt-keys.hex", keys)
    (out / "configuration.json").write_bytes(cfg)
    try:
        ccf_version = json.loads(version).get("ccf_version")
    except ValueError:
        ccf_version = None
    keyset = r3.R.cose_keyset(keys)
    rows = []
    for v in vectors:
        name = v["name"]
        request = bytes.fromhex((HERE / "vectors" / name / "request.hex").read_text(encoding="ascii").strip())
        assert _sha(request) == v["request_sha256"], name
        started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        exchanges, outcome = r3.register(svc, request, keyset)
        d = out / name
        d.mkdir(exist_ok=True)
        _write_hex(d / "request.hex", request)
        receipt, statement = outcome.get("receipt"), outcome.get("statement")
        if receipt is not None:
            _write_hex(d / "receipt.hex", receipt)
        if statement is not None:
            _write_hex(d / "statement.hex", statement)
        o = oracle.check(request, receipt=receipt, returned=statement, keyset=keys)
        row = {
            "vector": name,
            "request_sha256": _sha(request),
            "service_commit": service_commit,
            "image_id": image_id,
            "ccf_version": ccf_version,
            "configuration_sha256": _sha(cfg),
            "predicted": predictions[name]["predicted"],
            "measured_outcome": outcome.get("state"),
            "refusal_stage": outcome.get("error_stage"),
            "raw_service_error": outcome.get("api_detail"),
            "api_status": outcome.get("api_status"),
            "txid": outcome.get("txid"),
            "returned_statement_sha256": _sha(statement),
            "receipt_data_hash": o["receipt_data_hash"],
            "rebuilt_cn_sha256": o["rebuilt_sha256"],
            "data_hash_match": o["data_hash_match"],
            "receipt_signature_valid": o["receipt_signature_valid"],
            "rebuilt_equals_returned_minus_394": o["rebuilt_equals_returned_minus_394"],
            "started": started,
            "http": [{"step": s, "method": m, "path": p, "status": c, "body_sha256": _sha(b)}
                     for s, m, p, c, _hd, b in exchanges],
        }
        (d / "row.json").write_text(json.dumps(row, indent=1) + "\n", encoding="utf-8")
        rows.append(row)
    summary = {"label": label, "service_commit": service_commit, "image_id": image_id, "ccf_version": ccf_version,
               "configuration_sha256": _sha(cfg), "scitt_keys_sha256": _sha(keys), "rows": rows}
    (out / "rows.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--service-cert", type=Path, required=True)
    ap.add_argument("--service-commit", required=True)
    ap.add_argument("--image-id", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    probe = _load("_replay_probe", TOOLS / "local_ledger_probe.py")
    s = run(probe.Service(a.url, a.service_cert), a.out or HERE / "runs" / a.label, a.service_commit, a.image_id, a.label)
    for r in s["rows"]:
        print(f"{r['vector']:34s} predicted {r['predicted']['outcome']:10s} measured {r['measured_outcome']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
