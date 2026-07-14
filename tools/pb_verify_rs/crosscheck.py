#!/usr/bin/env python3
"""Cross-implementation conformance harness (3.2.0 O8).

Drives the independent Rust verifier (`pb_verify_rs`, built with cargo) against fixtures that the
Python implementation produces, and asserts AGREEMENT on the core verifier properties — with NO
shared canonicalization or parser code between the two implementations:

  1. jcs-sha256-v1 content root of a signed statement (RFC 8785)  -> Rust == Python
  2. DSSE / Ed25519 signature verify over the exact PAE bytes      -> Rust OK on a Python-signed env
  3. a flipped payload byte                                         -> Rust FAIL (negative vector)
  4. a duplicate JSON key                                           -> Rust REJECT (parser-differential)
  5. RFC 6962 Merkle tree head                                      -> Rust == Python

Exit 0 iff every property agrees; non-zero (and a printed diff) on the first mismatch. Read-only:
writes only to a temp dir, no network.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
BIN = ROOT / "tools" / "pb_verify_rs" / "target" / "debug" / "pb_verify_rs"
if not BIN.exists():
    BIN = ROOT / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"

sys.path.insert(0, str(SRC))


def _run(*args: str) -> tuple[int, str]:
    p = subprocess.run([str(BIN), *args], capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip()


def main() -> int:
    if not BIN.exists():
        print(f"FAIL: rust binary not built ({BIN}) — run `cargo build` in tools/pb_verify_rs first")
        return 2

    from proofbundle import canonical
    from proofbundle.emit import generate_signer
    from proofbundle.outcome import build_outcome_statement, emit_outcome_receipt

    failures: list[str] = []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="pb_crosscheck_"))

    pred = {
        "schemaVersion": "0.1.0", "outcomeId": "o-crosscheck",
        "decisionRef": {"sha256": "a" * 64}, "executor": {"id": "exec:1", "keyId": "k"},
        "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
    }
    sk = generate_signer()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()

    # (1) content root
    stmt = build_outcome_statement(pred)
    stmt_bytes = canonical.canonicalize_statement(stmt)
    (tmp / "stmt.json").write_bytes(stmt_bytes)
    py_root = hashlib.sha256(stmt_bytes).hexdigest()
    _, rust_root = _run("content-root", str(tmp / "stmt.json"))
    if rust_root != py_root:
        failures.append(f"content-root mismatch: py={py_root} rust={rust_root}")

    # (2) real DSSE verify
    env = emit_outcome_receipt(pred, sk)
    (tmp / "env.json").write_text(json.dumps(env))
    code, out = _run("verify-dsse", str(tmp / "env.json"), pub)
    if not (code == 0 and out == "OK"):
        failures.append(f"real DSSE verify should be OK/exit0, got {out}/exit{code}")

    # (3) tampered payload -> FAIL
    body = json.loads(base64.b64decode(env["payload"]))
    body["predicate"]["outcomeId"] = "EVIL"
    env_t = dict(env)
    env_t["payload"] = base64.b64encode(json.dumps(body).encode()).decode()
    (tmp / "env_t.json").write_text(json.dumps(env_t))
    code, out = _run("verify-dsse", str(tmp / "env_t.json"), pub)
    if not (code == 1 and out == "FAIL"):
        failures.append(f"tampered payload should FAIL/exit1, got {out}/exit{code}")

    # (4) duplicate JSON key -> REJECT
    (tmp / "dup.json").write_text('{"a":1,"a":2}')
    code, out = _run("strict-parse", str(tmp / "dup.json"))
    if not (code == 1 and out.startswith("REJECT")):
        failures.append(f"duplicate key should REJECT/exit1, got {out}/exit{code}")

    # (5) RFC 6962 Merkle head
    la = hashlib.sha256(b"leafA").hexdigest()
    lb = hashlib.sha256(b"leafB").hexdigest()
    py_merkle = hashlib.sha256(bytes([1]) + bytes.fromhex(la) + bytes.fromhex(lb)).hexdigest()
    _, rust_merkle = _run("merkle-root", la, lb)
    if rust_merkle != py_merkle:
        failures.append(f"merkle mismatch: py={py_merkle} rust={rust_merkle}")

    # (6) reproduce the actual conformance corpus (§7 "Zweitverifier reproduziert den Conformance-Corpus")
    corpus = ROOT / "conformance"
    manifest = json.loads((corpus / "manifest.json").read_text())
    reproduced = 0
    for cid in manifest.get("cases", []):
        cdir = corpus / cid
        case = json.loads((cdir / "case.json").read_text())
        kind, expected = case.get("kind"), case.get("expected", {})
        if kind == "decision_crossimpl":
            # independent Rust content root of the decision statement == the pinned corpus value,
            # and the committed .jcs bytes hash to the same root (byte-identical canonicalization).
            want = expected.get("decision_content_root")
            _, got = _run("content-root", str(cdir / "decision_receipt.json"))
            if want and got != want:
                failures.append(f"corpus {cid}: content root py-pinned={want} rust={got}")
            jcs_hash = hashlib.sha256((cdir / "decision_receipt.jcs").read_bytes()).hexdigest()
            if want and jcs_hash != want:
                failures.append(f"corpus {cid}: committed .jcs hash {jcs_hash} != pinned root {want}")
            reproduced += 1
        elif kind == "native_bundle" and cid.endswith("duplicate-json-key"):
            # the exit-2 malformed contract for a duplicate JSON key, reproduced by the Rust strict parser.
            code, out = _run("strict-parse", str(cdir / "bundle.json"))
            if not (code == 1 and out.startswith("REJECT")):
                failures.append(f"corpus {cid}: dup-key should REJECT, got {out}/exit{code}")
            reproduced += 1

    if failures:
        print("CROSS-IMPL DISAGREEMENT:")
        for f in failures:
            print("  -", f)
        return 1
    print("CROSS-IMPL OK: content-root, DSSE verify (real+tampered), dup-key reject, RFC6962 merkle agree; "
          f"{reproduced} conformance-corpus case(s) reproduced independently")
    return 0


if __name__ == "__main__":
    sys.exit(main())
