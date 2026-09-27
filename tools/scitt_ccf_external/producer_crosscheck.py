#!/usr/bin/env python3
"""The 6.4.0 producer's statements, registered on a local scitt-ccf-ledger and read by three verifiers.

WHY. Owner order of 2026-09-27, 6.4.0 producer part 4: our statements must pass our v1 reader, and
they are cross-verified with microsoft/scitt-verifier, recorded as a FOREIGN TOOL. Owner decision B:
the ES256 path with a protected x5chain exists for exactly this; the EdDSA default is measured the
same way and is expected to stay outside the v1 reader (owner answer N7 b) and outside scitt-verifier
(which, by its source, verifies ECDSA and RSA-PSS only).

WHAT RUNS, per statement (ES256 with a did:x509 chain made for the run, and EdDSA with a seed made
for the run), over examples/example_bundle.json:

1. ``proofbundle scitt sign`` writes it (a subprocess, the command a user runs);
2. offline, before registration: ``proofbundle verify --scitt-statement``, the producer's
   ``check_signed_statement`` and, for the statement signature, the v1 reader;
3. the local ledger registers it or refuses it (the client of local_ledger_probe.py, which never uses
   a proxy); this is a measurement, not the producer's ``scitt register`` step, which is not built;
4. on the Transparent Statement the ledger returns: the v1 reader
   (``verify_transparent_statement`` with the service's key set and the statement key),
   ``proofbundle verify --scitt-statement`` with ``--scitt-service-keys``, and scitt-verifier
   ``verify`` offline with the service's key set and an issuer policy.

THE FOREIGN TOOL IS PINNED: ``--verifier-clone`` must be microsoft/scitt-verifier at
``PINNED_COMMIT``, built with ``cargo build --release --locked -p scitt-verifier``.

Output: ``producer_crosscheck.json`` next to this file: the bytes as hex, every exit code and verdict,
and the pins. The private keys are not written anywhere that outlives the run.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import local_ledger_probe as P  # noqa: E402 - the did:x509 signer profile and the service client

RESULT = HERE / "producer_crosscheck.json"
PINNED_COMMIT = "bd6fb8ba79dbb521257b7f09682c03c6681dc3d0"
BUNDLE = REPO / "examples" / "example_bundle.json"
SUBJECT = "proofbundle 6.4.0 producer cross-check"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git(*a) -> str:
    return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True, check=True).stdout.strip()


def cli(*argv) -> dict:
    p = subprocess.run([sys.executable, "-m", "proofbundle.cli", *argv], capture_output=True, text=True,
                       timeout=120, env={**os.environ, "PYTHONPATH": str(REPO / "src")})
    return {"argv": ["proofbundle", *[a if not a.startswith("/") else Path(a).name for a in argv]],
            "exit_code": p.returncode, "stdout": p.stdout.strip().splitlines()[-4:],
            "stderr": p.stderr.strip()[:300]}


def scitt_verifier(binary: Path, statement: bytes, keyset: bytes, issuer: str, tmp: Path) -> dict:
    st, ks, pol = tmp / "sv-statement.cose", tmp / "sv-keys.cbor", tmp / "sv-policy.json"
    st.write_bytes(statement)
    ks.write_bytes(keyset)
    pol.write_text(json.dumps({"policyId": "proofbundle/producer-crosscheck", "policyVersion": "1",
                               "assertions": {"issuer": [issuer]}}), encoding="utf-8")
    p = subprocess.run([str(binary), "verify", "--statement", str(st), "--scitt-keys", str(ks),
                        "--policy", str(pol), "--format", "json"], capture_output=True, text=True, timeout=60)
    out = {"exit_code": p.returncode}
    try:
        d = json.loads(p.stdout)
    except json.JSONDecodeError:
        out["stdout_not_json"] = (p.stdout[:300] + p.stderr[:300]).strip()
        return out
    appraisal = d.get("appraisal") or {}
    ss = d.get("signedStatement") or {}
    out.update({
        "verdict": appraisal.get("verdict"),
        "signed_statement": {k: ss.get(k) for k in ("algorithm", "issuer", "subject", "signatureValid",
                                                     "claimDigest") if k in ss},
        "receipts": [{"root_signature_valid": e.get("rootSignatureValid"), "bound": e.get("boundToStatement"),
                      "kid_bound": e.get("kidBoundToKey"), "leaf_data_hash": e.get("claimsDigest")}
                     for e in (d.get("receipts") or {}).get("entries", [])],
        "errors": [{"code": x.get("code"), "message": (x.get("message") or "")[:160]}
                   for x in appraisal.get("diagnostics", []) if x.get("severity") == "error"][:6],
    })
    return out


def make_statements(tmp: Path) -> dict:
    """Both statements through the command, with keys made for the run."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    key, chain, did, spki = P.make_signer()
    key_pem, chain_pem, pub_es = tmp / "leaf.key.pem", tmp / "chain.pem", tmp / "leaf.pub.pem"
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    chain_pem.write_bytes(b"".join(x509.load_der_x509_certificate(c).public_bytes(serialization.Encoding.PEM)
                                   for c in chain))
    seed, pub_ed = tmp / "seed.key", tmp / "ed.pub.pem"
    seed.write_bytes(os.urandom(32))
    out = {}
    es, ed = tmp / "es256.cose", tmp / "eddsa.cose"
    out["es256"] = {"sign": cli("scitt", "sign", str(BUNDLE), "--out", str(es), "--issuer", did, "--subject",
                                SUBJECT, "--ec-key", str(key_pem), "--x5chain", str(chain_pem),
                                "--public-key-out", str(pub_es)),
                    "path": es, "pub": pub_es, "spki": spki, "issuer": did}
    out["eddsa"] = {"sign": cli("scitt", "sign", str(BUNDLE), "--out", str(ed), "--issuer", did, "--subject",
                                SUBJECT, "--key", str(seed), "--public-key-out", str(pub_ed)),
                    "path": ed, "pub": pub_ed, "issuer": did}
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    out["eddsa"]["spki"] = load_pem_public_key(pub_ed.read_bytes()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="the 6.4.0 producer's statements against three verifiers")
    ap.add_argument("--url", default="https://127.0.0.1:8000")
    ap.add_argument("--service-cert", type=Path, required=True)
    ap.add_argument("--verifier-clone", type=Path, required=True)
    ap.add_argument("--cohort-pins", type=Path, required=True, help="the ledger's pins (image, commit, config)")
    args = ap.parse_args(argv)
    head = subprocess.run(["git", "-C", str(args.verifier_clone), "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    if head != PINNED_COMMIT:
        raise SystemExit(f"REFUSED: scitt-verifier is at {head}, not {PINNED_COMMIT}")
    binary = args.verifier_clone / "target" / "release" / "scitt-verifier"
    if not binary.exists():
        raise SystemExit("NOT MEASURABLE: build it first: cargo build --release --locked -p scitt-verifier")

    from proofbundle import scitt_ccf as S
    from proofbundle.anchors import receipt_canonical_root
    from proofbundle.scitt_statement import check_signed_statement
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    root = receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})
    svc = P.Service(args.url, args.service_cert)
    code, _h, keys_raw = svc.call("GET", "/.well-known/scitt-keys")
    if code != 200:
        raise SystemExit(f"NOT MEASURABLE: the service did not serve its keys ({code})")
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    results = {}
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        ks_file = tmp / "scitt-keys.cbor"
        ks_file.write_bytes(keys_raw)
        for name, s in make_statements(tmp).items():
            r: dict = {"sign": s["sign"]}
            results[name] = r
            if s["sign"]["exit_code"] != 0:
                continue
            data = s["path"].read_bytes()
            r["statement_hex"] = data.hex()
            r["statement_sha256"] = sha(data)
            r["statement_key_spki_hex"] = s["spki"].hex()
            c = check_signed_statement(data, canonical_root=root, statement_keys=[s["spki"]])
            r["offline"] = {
                "check_signed_statement": {"status": c.status, "signature_valid": c.signature_valid,
                                           "registration": c.registration, "detail": c.detail},
                "v1_reader_statement_signature": list(S.verify_statement_signature(data,
                                                                                   statement_keys=[s["spki"]])),
                "proofbundle_verify": cli("verify", str(BUNDLE), "--scitt-statement", str(s["path"]),
                                          "--scitt-statement-key", str(s["pub"])),
                "scitt_verifier_on_the_signed_statement": scitt_verifier(binary, data, keys_raw, s["issuer"], tmp),
            }
            rec = svc.register(data)
            r["ledger"] = {"post_status": rec.get("post_status"), "accepted": bool(rec.get("accepted")),
                           "txid": rec.get("txid"), "error": rec.get("error")}
            served, receipt = rec.get("transparent_statement"), rec.get("receipt")
            if not (served and receipt):
                continue
            r["ledger"].update({"receipt_hex": receipt.hex(), "returned_statement_hex": served.hex(),
                                "returned_statement_sha256": sha(served)})
            issuer = S.decode_cose_sign1(receipt, role="receipt").protected[15][1]
            r["ledger"]["service_issuer"] = issuer
            ts_file = tmp / f"{name}.transparent.cose"
            ts_file.write_bytes(served)
            trust = {"scitt_ccf_services": {issuer: S.load_cose_keyset(keys_raw)},
                     "scitt_statement_keys": [s["spki"]]}
            v1 = S.verify_transparent_statement(served, canonical_root=root, rp_trust=trust)
            r["returned"] = {
                "v1_reader": {"status": v1.status, "readable": v1.readable, "signature_valid": v1.signature_valid,
                              "profile_satisfied": v1.profile_satisfied, "statement_status": v1.statement_status,
                              "detail": v1.detail[:200]},
                "proofbundle_verify": cli("verify", str(BUNDLE), "--scitt-statement", str(ts_file),
                                          "--scitt-statement-key", str(s["pub"]), "--scitt-service-keys",
                                          str(ks_file), "--scitt-service-issuer", issuer),
                "scitt_verifier": scitt_verifier(binary, served, keys_raw, issuer, tmp),
            }
    pins = json.loads(args.cohort_pins.read_text(encoding="utf-8"))
    doc = {"tool": "tools/scitt_ccf_external/producer_crosscheck.py", "started": started,
           "producer": {"repository": "https://github.com/b7n0de/proofbundle", "commit": git("rev-parse", "HEAD"),
                        "tree_clean": git("status", "--porcelain", "--", ".", ":(exclude)tools/scitt_ccf_external/"
                                          "producer_crosscheck.json") == "",
                        "python": platform.python_version()},
           "foreign_tool": {"name": "microsoft/scitt-verifier", "repository": "https://github.com/microsoft/scitt-verifier",
                            "commit": PINNED_COMMIT, "build": "cargo build --release --locked -p scitt-verifier",
                            "mode": "offline: local key set, never --online"},
           "ledger": pins, "service_keyset_hex": keys_raw.hex(), "service_keyset_sha256": sha(keys_raw),
           "target": {"bundle": str(BUNDLE.relative_to(REPO)), "receipt_canonical_root": root.hex()},
           "statements": results}
    RESULT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    for name, r in results.items():
        led = r.get("ledger", {})
        ret = r.get("returned", {})
        print(f"{name}: sign {r['sign']['exit_code']}, ledger {led.get('post_status')} "
              f"accepted={led.get('accepted')}, v1 {ret.get('v1_reader', {}).get('status')}, "
              f"scitt-verifier {ret.get('scitt_verifier', {}).get('verdict')} "
              f"exit {ret.get('scitt_verifier', {}).get('exit_code')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
