#!/usr/bin/env python3
"""Hold proofbundle's scitt-ccf reader against the Rust verifier of microsoft/scitt-verifier, offline.

WHY (owner decision Q7 c, ADR 0009). A second reader from another code base, in another language,
run on the same bytes. The comparison is per receipt and per statement: the Merkle root (value 4),
the data-hash in the leaf, the data-hash recomputed from the statement (value 3), whether the
receipt signature verifies under the given key set, and whether the receipt is bound to the
statement. Verdicts and exit codes are recorded but not compared: the two tools answer different
questions (scitt-verifier appraises the signer chain and a relying-party policy; proofbundle's
profile requires an RFC 9995 hash envelope over a proofbundle root).

THE RUST SIDE IS PINNED. ``--verifier-clone`` must be a checkout of microsoft/scitt-verifier at
``PINNED_COMMIT``; the script refuses another commit, and builds the binary with
``cargo build --release --locked -p scitt-verifier`` when it is missing. Its run is offline: the
verify command is given local key sets and never ``--online``.

INPUTS: the files of ``fetch_external.py`` in ``./fetched`` and the local-ledger vector in
``tests/fixtures/scitt_ccf/local_ledger_control.json``. The production trust store is a JSON list
of certificates; it is turned into a COSE_KeySet here (EC2, kid = hex(SHA-256(SPKI)) as the
receipts use), and that conversion is recorded.

Output: ``rust_crosscheck.json`` next to this file.
"""
from __future__ import annotations

import argparse
import datetime
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FETCHED = HERE / "fetched"
VECTOR = REPO / "tests" / "fixtures" / "scitt_ccf" / "local_ledger_control.json"
RESULT = HERE / "rust_crosscheck.json"
PINNED_COMMIT = "bd6fb8ba79dbb521257b7f09682c03c6681dc3d0"
sys.path.insert(0, str(HERE))
import recompute as R  # noqa: E402 - encoder for the converted key set

#: proofbundle._wire_b64.decode_b64, the one strict base64 decoder the tools tree may use
b64d = R._strict_b64()


def keyset_from_trust_store(raw: bytes) -> bytes:
    """The trust store's distinct keys as a COSE_KeySet: EC2, kid = hex(SHA-256(SPKI))."""
    store = R.service_trust_store(raw)
    keys = []
    for kid, (pub, _spki) in sorted(store["keys"].items()):
        nums = pub.public_numbers()
        n = (pub.curve.key_size + 7) // 8
        crv = {"secp256r1": 1, "secp384r1": 2}[pub.curve.name]
        keys.append({1: 2, 2: kid, -1: crv, -2: nums.x.to_bytes(n, "big"),
                     -3: nums.y.to_bytes(n, "big")})
    return R.encode(keys)


def cases() -> list:
    f = {p.name: p.read_bytes() for p in FETCHED.glob("*") if p.is_file()}
    mst = "mst-test-scitt-verifier.confidential-ledger.azure.com"
    out = []
    for name in ("transparent-statement.cose", "cbor-header.cose", "nested-sign1.cose",
                 "appended-receipt.cose", "payload-tampered.cose", "tampered-statement.cose",
                 "cts-hashv-cwtclaims-b64url.cose"):
        out.append({"name": name, "source": "fetched", "statement": f[name],
                    "keyset": f["mst-test-scitt-keys.cbor"], "issuer": mst})
    out.append({"name": "uvm_0.2.10.cose", "source": "fetched (production)",
                "statement": f["uvm_0.2.10.cose"],
                "keyset": keyset_from_trust_store(f["esrp-cts-db.json"]),
                "keyset_note": "COSE_KeySet built here from esrp-cts-db.json: EC2 keys, "
                               "kid = hex(SHA-256(SPKI))",
                "issuer": "esrp-cts-db.confidential-ledger.azure.com"})
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    ks = b64d(v["service_keyset_b64"])
    out.append({"name": "local ledger: control", "source": "tests/fixtures/scitt_ccf",
                "statement": b64d(v["transparent_statement_b64"]), "keyset": ks,
                "issuer": v["issuer"], "canonical_root": bytes.fromhex(v["canonical_root_hex"]),
                "statement_key": b64d(v["statement_signer_spki_b64"])})
    for n, b in sorted(v["accepted_variants_b64"].items()):
        out.append({"name": f"local ledger: {n}", "source": "tests/fixtures/scitt_ccf",
                    "statement": b64d(b), "keyset": ks, "issuer": v["issuer"],
                    "canonical_root": bytes.fromhex(v["canonical_root_hex"]),
                    "statement_key": b64d(v["statement_signer_spki_b64"])})
    return out


def run_rust(binary: Path, case: dict, tmp: Path) -> dict:
    st, ks, pol = tmp / "statement.cose", tmp / "keys.cbor", tmp / "policy.json"
    st.write_bytes(case["statement"])
    ks.write_bytes(case["keyset"])
    pol.write_text(json.dumps({"policyId": "proofbundle/rust-crosscheck", "policyVersion": "1",
                               "assertions": {"issuer": [case["issuer"]]}}), encoding="utf-8")
    p = subprocess.run([str(binary), "verify", "--statement", str(st), "--scitt-keys", str(ks),
                        "--policy", str(pol), "--format", "json"],
                       capture_output=True, text=True, timeout=60)
    out = {"exit_code": p.returncode}
    try:
        d = json.loads(p.stdout)
    except json.JSONDecodeError:
        out["stdout_not_json"] = p.stdout[:300] + p.stderr[:300]
        return out
    out["verdict"] = d.get("appraisal", {}).get("verdict")
    ss = d.get("signedStatement") or {}
    out["statement_claim_digest"] = ss.get("claimDigest")
    out["receipts"] = [{"root": e.get("verifiableDataStructureRoot"), "leaf_data_hash": e.get("claimsDigest"),
                        "root_signature_valid": e.get("rootSignatureValid"),
                        "bound": e.get("boundToStatement"), "kid_bound": e.get("kidBoundToKey")}
                       for e in (d.get("receipts") or {}).get("entries", [])]
    out["problems"] = [x.get("code") for x in (d.get("appraisal") or {}).get("diagnostics", [])
                       if x.get("severity") == "error"][:5]
    return out


def run_ours(case: dict) -> dict:
    from proofbundle import scitt_ccf as S
    services = {case["issuer"]: S.load_cose_keyset(case["keyset"])}
    trust = {"scitt_ccf_services": services}
    if "statement_key" in case:
        trust["scitt_statement_keys"] = [case["statement_key"]]
    r = S.verify_transparent_statement(case["statement"],
                                       canonical_root=case.get("canonical_root", b"\0" * 32),
                                       rp_trust=trust)
    return {"status": r.status, "statement_status": r.statement_status,
            "data_hash": r.data_hash.hex() if r.data_hash else None,
            "receipts": [{"status": c.status,
                          "root": c.merkle_root.hex() if c.merkle_root else None,
                          "leaf_data_hash": c.data_hashes[0].hex() if c.data_hashes else None,
                          "signature_valid": c.signature_valid, "bound": c.bound,
                          "kid_bound": c.kid_bound_to_key} for c in r.receipts],
            "detail": r.detail[:160]}


def compare(ours: dict, rust: dict) -> dict:
    agree, differ, not_comparable = [], [], []

    def cmp(label, a, b):
        if a is None or b is None:
            not_comparable.append(label)
        elif a == b:
            agree.append(label)
        else:
            differ.append({"field": label, "proofbundle": a, "scitt-verifier": b})
    cmp("statement data-hash (value 3)", ours["data_hash"], rust.get("statement_claim_digest"))
    rr = rust.get("receipts") or []
    for i, o in enumerate(ours["receipts"]):
        x = rr[i] if i < len(rr) else {}
        cmp(f"receipt {i} Merkle root (value 4)", o["root"], x.get("root"))
        cmp(f"receipt {i} leaf data-hash", o["leaf_data_hash"], x.get("leaf_data_hash"))
        cmp(f"receipt {i} signature valid", o["signature_valid"], x.get("root_signature_valid"))
        cmp(f"receipt {i} bound to statement", o["bound"], x.get("bound"))
        cmp(f"receipt {i} kid bound to key", o["kid_bound"], x.get("kid_bound"))
    return {"agree": agree, "differ": differ, "not_comparable": not_comparable}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="proofbundle scitt-ccf against microsoft/scitt-verifier")
    ap.add_argument("--verifier-clone", required=True, type=Path)
    args = ap.parse_args(argv)
    head = subprocess.run(["git", "-C", str(args.verifier_clone), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    if head != PINNED_COMMIT:
        print(f"REFUSED: the clone is at {head or 'no commit'}, not {PINNED_COMMIT}.", file=sys.stderr)
        return 1
    binary = args.verifier_clone / "target" / "release" / "scitt-verifier"
    if not binary.is_file():
        b = subprocess.run(["cargo", "build", "--release", "--locked", "-p", "scitt-verifier"],
                           cwd=args.verifier_clone)
        if b.returncode != 0 or not binary.is_file():
            print("NOT MEASURABLE: the Rust verifier did not build.", file=sys.stderr)
            return 2
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True).stdout.strip()
    rows = []
    with tempfile.TemporaryDirectory() as t:
        for case in cases():
            rust = run_rust(binary, case, Path(t))
            ours = run_ours(case)
            rows.append({"case": case["name"], "source": case["source"],
                         "keyset_note": case.get("keyset_note"), "proofbundle": ours,
                         "scitt_verifier": rust, "comparison": compare(ours, rust)})
    import cryptography
    doc = {"tool": "tools/scitt_ccf_external/rust_crosscheck.py",
           "measured_on": datetime.date.today().isoformat(),
           "scitt_verifier": {"repository": "https://github.com/microsoft/scitt-verifier",
                              "commit": PINNED_COMMIT, "version": version, "mode": "offline, --scitt-keys"},
           "environment": {"python": platform.python_version(), "cryptography": cryptography.__version__},
           "rows": rows,
           "totals": {"agree": sum(len(r["comparison"]["agree"]) for r in rows),
                      "differ": sum(len(r["comparison"]["differ"]) for r in rows),
                      "not_comparable": sum(len(r["comparison"]["not_comparable"]) for r in rows)}}
    RESULT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    for r in rows:
        c = r["comparison"]
        print(f"  {r['case']:36s} ours={r['proofbundle']['status']:22s} rust={str(r['scitt_verifier'].get('verdict')):22s} "
              f"agree={len(c['agree'])} differ={len(c['differ'])} n/a={len(c['not_comparable'])}")
    print("totals", doc["totals"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
