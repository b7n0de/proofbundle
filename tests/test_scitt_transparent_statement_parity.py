"""The Python and the Rust verifier give one result on every shared Transparent Statement vector.

AGENTS.md: Python and the Rust verifier in tools/pb_verify_rs must agree on the same bytes; a divergence
in verdict or exit code is a finding. The surface is `proofbundle.scitt_ccf.verify_transparent_statement`,
the Rust side `pb_verify_rs verify-scitt-transparent-statement` (tools/pb_verify_rs/src/scitt_transparent.rs
over src/scitt.rs, which share no reading code with the Python module).

The vectors are tests/fixtures/scitt_transparent_statement/vectors.json, written by
tools/scitt_ccf_external/transparent_statement_vectors.py: every Transparent Statement a local
scitt-ccf-ledger served in the two differential-corpus rounds, under the keysets and signers of their
round, and synthetic ones for every rule of the receipt pass and the status logic. Each vector carries
the verdict it is built to produce (the oracle). Both verifiers are held to it, and to each other on
every field of the result but its prose.
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
VECTORS = Path(__file__).resolve().parent / "fixtures" / "scitt_transparent_statement" / "vectors.json"
RUST = [REPO / "tools" / "pb_verify_rs" / "target" / build / "pb_verify_rs" for build in ("release", "debug")]
HAS_CBOR2 = importlib.util.find_spec("cbor2") is not None
STATUSES = {"confirmed", "malformed", "outside_profile", "unbound", "statement_signature_invalid",
            "root_mismatch", "signature_invalid", "receipt_not_bound", "needs_rp_trust"}
#: The exit class of the Rust subcommand, by status: 0 confirmed, 1 a check over the evidence failed.
FAILED = {"unbound", "statement_signature_invalid", "root_mismatch", "signature_invalid", "receipt_not_bound"}


def _generator():
    """The generator module: the one reading of the file (parts, refs, trust) both sides use."""
    name = "_scitt_transparent_statement_vectors"
    if name not in sys.modules:
        tools = str(REPO / "tools" / "scitt_ccf_external")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "scitt_ccf_external"
                                                      / "transparent_statement_vectors.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _doc() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def exit_class(status: str) -> int:
    return 0 if status == "confirmed" else 1 if status in FAILED else 3


def run_rust(binary: Path, tmp: Path, statement: bytes, root: bytes, trust) -> tuple:
    """-> (the result as JSON, the exit code, stderr)."""
    (tmp / "statement.cbor").write_bytes(statement)
    argv = [str(binary), "verify-scitt-transparent-statement", str(tmp / "statement.cbor"), root.hex()]
    if trust is not None:
        (tmp / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
        argv.append(str(tmp / "trust.json"))
    p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    return (json.loads(p.stdout) if p.stdout.strip() else None), p.returncode, p.stderr


class TheVectors(unittest.TestCase):
    def test_every_status_the_surface_returns_is_built(self):
        self.assertEqual({v["want"]["status"] for v in _doc()["vectors"]}, STATUSES)

    def test_both_rounds_of_the_ledger_are_in(self):
        origins = {v["origin"] for v in _doc()["vectors"]}
        self.assertTrue({"scitt-ccf-ledger, round1", "scitt-ccf-ledger, round2"} <= origins)
        refs = _doc()["refs"]
        self.assertNotEqual(refs["spki_round1_signer"], refs["spki_round2_signer"])


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
                    got, code, err = run_rust(binary, Path(tmp), g.assemble(v["statement"], doc["refs"]),
                                              g.assemble(v["root"], doc["refs"]), g.trust_of(doc, v))
                    self.assertIsNotNone(got, err)
                    self.assertEqual(g.mismatch(v["want"], got), {}, v["what"])
                    self.assertEqual(code, exit_class(v["want"]["status"]), err)
                    if HAS_CBOR2:
                        self.assertEqual(got, g.python_result(doc, v), v["what"])


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class AFileOverTheRustInputBudget(unittest.TestCase):
    """A confirmed statement padded with zeros to the budget the binary reports and one byte past it,
    made at run time: `malformed` in both verifiers, Rust exit 3, never `fatal`."""

    def test_both_verifiers_read_it_as_malformed(self):
        binary = next(b for b in RUST if b.exists())
        budget = json.loads(subprocess.run([str(binary), "budget"], capture_output=True, text=True,
                                           check=True).stdout)["input_bytes"]
        g, doc = _generator(), _doc()
        v = next(v for v in doc["vectors"] if v["id"] == "s01-confirmed")
        statement, root = g.assemble(v["statement"], doc["refs"]), g.assemble(v["root"], doc["refs"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "statement.cbor"
            for size in (budget, budget + 1):
                with self.subTest(size=size):
                    with path.open("wb") as f:
                        f.write(statement)
                        f.truncate(size)
                    p = subprocess.run([str(binary), "verify-scitt-transparent-statement", str(path), root.hex()],
                                       capture_output=True, text=True, timeout=60)
                    self.assertEqual((json.loads(p.stdout or "null") or {}).get("status"), "malformed", p.stderr)
                    self.assertEqual(p.returncode, 3, p.stderr)
                    if HAS_CBOR2:
                        from proofbundle.scitt_ccf import verify_transparent_statement  # noqa: PLC0415
                        self.assertEqual(verify_transparent_statement(path.read_bytes(),
                                                                      canonical_root=root).status, "malformed")


if __name__ == "__main__":
    unittest.main()
