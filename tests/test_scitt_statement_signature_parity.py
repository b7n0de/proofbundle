"""The Python and the Rust verifier give one verdict on every shared statement-signature vector.

AGENTS.md: Python and the Rust verifier in tools/pb_verify_rs must agree on the same bytes; a divergence
in verdict or exit code is a finding. The surface is `proofbundle.scitt_ccf.verify_statement_signature`,
the Rust side `pb_verify_rs verify-scitt-statement-signature` (tools/pb_verify_rs/src/scitt.rs, which
shares no reading code with the Python module).

The vectors are tests/fixtures/scitt_statement_signature/vectors.json, written by
tools/scitt_ccf_external/statement_signature_vectors.py: real statements a local scitt-ccf-ledger
accepted in the two differential-corpus rounds (two different ES256 signers), and synthetic ones for
every rule on the path, from the CBOR reader to the curve an algorithm names. Each vector carries the
status and verdict it is built to produce (the oracle), and both verifiers are held to it.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VECTORS = Path(__file__).resolve().parent / "fixtures" / "scitt_statement_signature" / "vectors.json"
RUST = [REPO / "tools" / "pb_verify_rs" / "target" / build / "pb_verify_rs" for build in ("release", "debug")]
HAS_CBOR2 = importlib.util.find_spec("cbor2") is not None

#: The exit class of the Rust subcommand, by status.
EXIT = {"confirmed": 0, "statement_signature_invalid": 1}
SHOWN = {True: "true", False: "false", None: "none"}


def _doc() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _assemble(parts: list, refs: dict) -> bytes:
    out = b""
    for p in parts:
        if isinstance(p, str):
            out += bytes.fromhex(p)
        elif "ref" in p:
            out += bytes.fromhex(refs[p["ref"]])
        else:
            out += bytes(p["zeros"])
    return out


class TheVectors(unittest.TestCase):
    def test_every_status_the_surface_returns_is_covered(self):
        want = {v["want"]["status"] for v in _doc()["vectors"]}
        self.assertEqual(want, {"confirmed", "statement_signature_invalid", "needs_rp_trust",
                                "outside_profile", "malformed"})

    def test_both_signers_of_the_corpus_are_named(self):
        refs = _doc()["refs"]
        self.assertNotEqual(refs["spki_round1_signer"], refs["spki_round2_signer"])


@unittest.skipUnless(HAS_CBOR2, "the [scitt] extra is not installed")
class PythonGivesEveryBuiltVerdict(unittest.TestCase):
    def test_python(self):
        from proofbundle.scitt_ccf import verify_statement_signature  # noqa: PLC0415
        doc = _doc()
        for v in doc["vectors"]:
            with self.subTest(v["id"]):
                got = verify_statement_signature(_assemble(v["statement"], doc["refs"]),
                                                 statement_keys=[_assemble(k, doc["refs"]) for k in v["keys"]])
                self.assertEqual(got, (v["want"]["status"], v["want"]["valid"]), v["what"])


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class RustGivesEveryBuiltVerdict(unittest.TestCase):
    def test_rust(self):
        binary = next(b for b in RUST if b.exists())
        doc = _doc()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "statement.cbor"
            for v in doc["vectors"]:
                with self.subTest(v["id"]):
                    path.write_bytes(_assemble(v["statement"], doc["refs"]))
                    keys = [_assemble(k, doc["refs"]).hex() for k in v["keys"]]
                    p = subprocess.run([str(binary), "verify-scitt-statement-signature", str(path), *keys],
                                       capture_output=True, text=True, timeout=60)
                    want = v["want"]
                    self.assertEqual((p.stdout.split(), p.returncode),
                                     ([want["status"], SHOWN[want["valid"]]], EXIT.get(want["status"], 3)),
                                     (v["what"], p.stderr))


if __name__ == "__main__":
    unittest.main()
