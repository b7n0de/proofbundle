"""An edge's `declaredAt` takes ASCII digits only, in Python as in Rust.

WHERE THIS COMES FROM. Measured 2026-09-28 on main 86671552: `relation._RFC3339_Z` read the timestamp
with `\\d`, which in a str pattern is every Unicode decimal digit. An Arabic-Indic year, a fullwidth
year and Devanagari seconds passed `validate_relationships`, and a signed decision receipt carrying
such an edge verified in Python with exit 0, while the Rust verifier refused the same bytes with exit 2
("edge.declaredAt must be RFC3339 Z"): `is_rfc3339_z` in tools/pb_verify_rs takes ASCII digits only.
Same bytes, two verdicts, against the parity rule of AGENTS.md. The released 6.0.0 and 6.1.0 carry the
same pattern.

WHAT IS PINNED. The three values are refused by the validator, by the emitter and by
`verify_decision_receipt`; ASCII timestamps with and without a fraction still pass; and one signed
receipt per value runs through both verifiers, which must give the same exit code, with the ASCII
receipt as the positive control.

WHAT IS NOT PINNED. Six more modules hold the same `\\d` pattern for their own timestamps and versions
(`decision`, `outcome`, `run_ledger`, `verification_summary`, `agent_review`, `relation_statement`).
They are named in RESTRISIKO_620 and fixed after 6.2.0.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from proofbundle.relation import validate_relationships

REPO = Path(__file__).resolve().parents[1]
RUST_DIR = REPO / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"

ARABISCH_INDISCH = "".join(chr(0x0660 + d) for d in (2, 0, 2, 6))    # the year 2026 in U+0660..U+0669
VOLLBREITE = "".join(chr(0xFF10 + d) for d in (2, 0, 2, 6))          # the year 2026 in U+FF10..U+FF19
DEVANAGARI = "".join(chr(0x0966 + d) for d in (0, 5))                # the seconds 05 in U+0966..U+096F

NICHT_ASCII = {
    "arabic-indic year": ARABISCH_INDISCH + "-07-16T00:00:00Z",
    "fullwidth year": VOLLBREITE + "-07-16T00:00:00Z",
    "devanagari seconds": "2026-07-16T00:00:" + DEVANAGARI + "Z",
}
ASCII = ("2026-07-16T00:00:00Z", "2026-07-16T00:00:00.123456Z")


def _edge(declared_at: str) -> dict:
    return {"relation": "supersedes",
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "b" * 64},
            "declaredAt": declared_at}


def _predicate(declared_at: str) -> dict:
    pred = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    pred["relationships"] = [_edge(declared_at)]
    return pred


def _signed_without_the_emitter(declared_at: str):
    """A signed decision receipt carrying the edge, built past the package's own checks, the way a
    producer that is not this package would sign it: the statement is assembled here in the form
    `build_decision_statement` gives it, because that builder refuses the predicate itself."""
    import hashlib  # noqa: PLC0415

    from proofbundle import dsse  # noqa: PLC0415
    from proofbundle.decision import (  # noqa: PLC0415
        DECISION_RECEIPT_PREDICATE_TYPE,
        INTOTO_STATEMENT_PAYLOAD_TYPE,
        STATEMENT_TYPE,
        _rfc8785_bytes,
    )
    from proofbundle.emit import generate_signer  # noqa: PLC0415
    signer = generate_signer()
    pred = _predicate(declared_at)
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": f"decision:{pred['decisionId']}",
                     "digest": {"sha256": hashlib.sha256(_rfc8785_bytes(pred)).hexdigest()}}],
        "predicateType": DECISION_RECEIPT_PREDICATE_TYPE,
        "predicate": pred,
    }
    body = _rfc8785_bytes(statement)
    env = dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
    return env, signer.public_key().public_bytes_raw()


class ADeclaredAtTakesOnlyAsciiDigits(unittest.TestCase):

    def test_the_validator_refuses_each_non_ascii_digit(self):
        for name, value in NICHT_ASCII.items():
            with self.subTest(value=name):
                errors = validate_relationships([_edge(value)])
                self.assertTrue(any("declaredAt" in e for e in errors), errors)

    def test_ascii_timestamps_still_pass(self):
        for value in ASCII:
            with self.subTest(value=value):
                self.assertEqual(validate_relationships([_edge(value)]), [])

    def test_the_emitter_refuses_to_sign_it(self):
        from proofbundle.decision import DecisionReceiptError, emit_decision_receipt  # noqa: PLC0415
        from proofbundle.emit import generate_signer  # noqa: PLC0415
        for name, value in NICHT_ASCII.items():
            with self.subTest(value=name):
                with self.assertRaises(DecisionReceiptError) as cm:
                    emit_decision_receipt(_predicate(value), generate_signer(), strict=True)
                self.assertIn("declaredAt", str(cm.exception))

    def test_a_receipt_signed_elsewhere_does_not_verify(self):
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        for name, value in NICHT_ASCII.items():
            with self.subTest(value=name):
                env, pub = _signed_without_the_emitter(value)
                r = verify_decision_receipt(env, pub)
                self.assertIs(r["ok"], False, r)
        env, pub = _signed_without_the_emitter(ASCII[0])
        self.assertIs(verify_decision_receipt(env, pub)["ok"], True)


def _rust_binary():
    """Same lookup as tests/test_rust_policy_reader_judges_the_relations_section.py."""
    if RUST_BIN.exists():
        return RUST_BIN
    if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
        return None
    b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                       capture_output=True, text=True, timeout=1800)
    return RUST_BIN if b.returncode == 0 and RUST_BIN.exists() else None


class BothVerifiersGiveTheSameExitCode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rust = _rust_binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs is missing or cargo is absent — "
                                    "the parity cases did NOT run (env_blocked, never green)")

    def _both(self, declared_at: str):
        env, pub = _signed_without_the_emitter(declared_at)
        pub_b64 = base64.b64encode(pub).decode("ascii")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "receipt.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            py = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); from proofbundle.cli import main; "
                 "sys.exit(main(sys.argv[1:]))" % str(REPO / "src"),
                 "decision", "verify", str(path), "--pub", pub_b64],
                capture_output=True, text=True, timeout=120)
            rs = subprocess.run([str(self.rust), "verify-relation", str(path), pub_b64],  # noqa: S603
                                capture_output=True, text=True, timeout=120)
        return py, rs

    def test_positive_control_an_ascii_timestamp_verifies_in_both(self):
        py, rs = self._both(ASCII[0])
        self.assertEqual(py.returncode, 0, py.stdout + py.stderr)
        self.assertEqual(rs.returncode, 0, rs.stdout + rs.stderr)

    def test_a_non_ascii_digit_gets_the_same_exit_code_in_both(self):
        for name, value in NICHT_ASCII.items():
            with self.subTest(value=name):
                py, rs = self._both(value)
                self.assertEqual(rs.returncode, 2, rs.stdout + rs.stderr)
                self.assertIn("edge.declaredAt must be RFC3339 Z", rs.stdout + rs.stderr)
                self.assertEqual(py.returncode, rs.returncode, py.stdout + py.stderr)
                self.assertIn("declaredAt must be RFC3339", py.stdout + py.stderr)


if __name__ == "__main__":
    unittest.main()
