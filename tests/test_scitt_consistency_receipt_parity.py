"""The Python and the Rust verifier give one result on every shared consistency receipt vector.

AGENTS.md: Python and the Rust verifier in tools/pb_verify_rs must agree on the same bytes; a divergence
in verdict or exit code is a finding. The surface is `proofbundle.scitt_ccf.verify_consistency_receipt`,
the Rust side `pb_verify_rs verify-scitt-consistency-receipt` (tools/pb_verify_rs/src/scitt_consistency.rs
over the receipt pass of src/scitt_transparent.rs, which share no reading code with the Python module).

The vectors are tests/fixtures/scitt_consistency_receipt/vectors.json, written by
tools/scitt_ccf_external/consistency_receipt_vectors.py: consistency receipts over three signed states of
one local scitt-ccf-ledger, and synthetic ones for every rule of the receipt pass and the status logic of
draft-ietf-scitt-receipts-ccf-profile-05 section 4. Each vector carries the verdict it is built to
produce (the oracle). Both verifiers are held to it, and to each other on every field of the result but
its prose.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VECTORS = Path(__file__).resolve().parent / "fixtures" / "scitt_consistency_receipt" / "vectors.json"
RUST = [REPO / "tools" / "pb_verify_rs" / "target" / build / "pb_verify_rs" for build in ("release", "debug")]
HAS_CBOR2 = importlib.util.find_spec("cbor2") is not None
STATUSES = {"confirmed", "malformed", "outside_profile", "consistency_proof_missing",
            "consistency_payload_attached", "consistency_newer_roots_differ", "consistency_anchor_not_canonical",
            "consistency_older_root_mismatch", "consistency_issuer_mismatch", "signature_invalid", "needs_rp_trust"}
#: The exit class of the Rust subcommand, by status: 0 confirmed, 1 a check over the evidence failed.
FAILED = {"consistency_newer_roots_differ", "consistency_anchor_not_canonical", "consistency_older_root_mismatch",
          "consistency_issuer_mismatch", "signature_invalid"}


def _generator():
    """The generator module: the one reading of the file (parts, refs, trust) both sides use."""
    name = "_scitt_consistency_receipt_vectors"
    if name not in sys.modules:
        tools = str(REPO / "tools" / "scitt_ccf_external")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "scitt_ccf_external"
                                                      / "consistency_receipt_vectors.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _doc() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def exit_class(status: str) -> int:
    return 0 if status == "confirmed" else 1 if status in FAILED else 3


def run_rust(binary: Path, tmp: Path, receipt: bytes, older_root: bytes, older_issuer: str, trust) -> tuple:
    """-> (the result as JSON, the exit code, stderr)."""
    (tmp / "receipt.cbor").write_bytes(receipt)
    argv = [str(binary), "verify-scitt-consistency-receipt", str(tmp / "receipt.cbor"), older_root.hex(),
            older_issuer]
    if trust is not None:
        (tmp / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
        argv.append(str(tmp / "trust.json"))
    p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    return (json.loads(p.stdout) if p.stdout.strip() else None), p.returncode, p.stderr


class TheVectors(unittest.TestCase):
    def test_every_status_the_surface_returns_is_built(self):
        self.assertEqual({v["want"]["status"] for v in _doc()["vectors"]}, STATUSES)

    def test_the_local_ledger_is_in(self):
        real = [v for v in _doc()["vectors"] if v["origin"].startswith("scitt-ccf-ledger")]
        self.assertGreaterEqual(len(real), 10)
        self.assertIn("confirmed", {v["want"]["status"] for v in real})


@unittest.skipUnless(HAS_CBOR2, "the [scitt] extra is not installed")
class PythonGivesEveryBuiltVerdict(unittest.TestCase):
    def test_python(self):
        g, doc = _generator(), _doc()
        for v in doc["vectors"]:
            with self.subTest(v["id"]):
                self.assertEqual(g.mismatch(v["want"], g.python_result(doc, v)), {}, v["what"])


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class RustGivesEveryBuiltVerdictAndPythonsResult(unittest.TestCase):
    def test_rust(self):
        binary = next(b for b in RUST if b.exists())
        g, doc = _generator(), _doc()
        with tempfile.TemporaryDirectory() as tmp:
            for v in doc["vectors"]:
                with self.subTest(v["id"]):
                    got, code, err = run_rust(binary, Path(tmp), g.assemble(v["receipt"], doc["refs"]),
                                              g.assemble(v["older_root"], doc["refs"]), v["older_issuer"],
                                              g.trust_of(doc, v))
                    self.assertIsNotNone(got, err)
                    self.assertEqual(g.mismatch(v["want"], got), {}, v["what"])
                    self.assertEqual(code, exit_class(v["want"]["status"]), err)
                    if HAS_CBOR2:
                        self.assertEqual(got, g.python_result(doc, v), v["what"])


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class AFileOverTheRustInputBudget(unittest.TestCase):
    """The confirmed control receipt padded with zeros to the budget the binary reports and one byte past
    it, made at run time: `malformed` in both verifiers, Rust exit 3, never `fatal`."""

    def test_both_verifiers_read_it_as_malformed(self):
        binary = next(b for b in RUST if b.exists())
        budget = json.loads(subprocess.run([str(binary), "budget"], capture_output=True, text=True,
                                           check=True).stdout)["input_bytes"]
        g, doc = _generator(), _doc()
        v = next(v for v in doc["vectors"] if v["id"] == "s01-control")
        receipt, older = g.assemble(v["receipt"], doc["refs"]), g.assemble(v["older_root"], doc["refs"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.cbor"
            for size in (budget, budget + 1):
                with self.subTest(size=size):
                    with path.open("wb") as f:
                        f.write(receipt)
                        f.truncate(size)
                    p = subprocess.run([str(binary), "verify-scitt-consistency-receipt", str(path), older.hex(),
                                        v["older_issuer"]], capture_output=True, text=True, timeout=60)
                    self.assertEqual((json.loads(p.stdout or "null") or {}).get("status"), "malformed", p.stderr)
                    self.assertEqual(p.returncode, 3, p.stderr)
                    if HAS_CBOR2:
                        from proofbundle.scitt_ccf import verify_consistency_receipt  # noqa: PLC0415
                        self.assertEqual(verify_consistency_receipt(path.read_bytes(), older_root=older,
                                                                    older_issuer=v["older_issuer"]).status,
                                         "malformed")


if __name__ == "__main__":
    unittest.main()
