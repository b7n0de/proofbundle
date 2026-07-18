"""RT-10 / PB-2026-0718-14: the SIGNED structured findings register is fail-closed and anti-tautological.

The old audit_candidate_matrix C12.2 granted a FALSE PASS from a lexical "0 open P0/P1" substring in a
possibly-stale .md. The replacement counts from a signed, structured register. This guard proves BOTH
directions: the real committed register verifies (control), and every tampering vector (absent, byte-flip,
foreign key, empty, contradiction) is caught fail-closed — so a "0 open" claim can never be forged.

CI note: the register PRIVATE key is gitignored and absent here, so a test cannot mint a validly-signed
register with arbitrary content. The signature-path tests therefore use the committed register + tampering
(any byte change breaks the pinned-key signature), and the supersession/contradiction logic is exercised
directly on the pure ``_resolve_current`` helper (no signature needed).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class TestFindingsRegisterVerify(unittest.TestCase):
    def setUp(self):
        self.fr = _load("fr_rt10", "scripts/findings_register.py")
        self.real = REPO / "audit_artifacts" / "findings_register_361.json"

    def _run_with(self, register_obj):
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "findings_register_361.json").write_text(json.dumps(register_obj))
            return self.fr.verify_and_count(Path(td))

    def test_control_real_register_verifies(self):
        r = self.fr.verify_and_count(REPO)
        self.assertTrue(r["ok"], r["reason"])
        self.assertEqual(r["open_ids"], [])
        self.assertGreater(r["evaluated_count"], 0)
        self.assertTrue(str(r["source_digest"]).startswith("sha256:"))

    def test_absent_register_fails(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.fr.verify_and_count(Path(td))
        self.assertFalse(r["ok"])
        self.assertEqual(r["evaluated_count"], 0)

    def test_tampered_status_fails(self):
        reg = json.loads(self.real.read_text(encoding="utf-8"))
        reg["findings"][0]["status"] = "open"  # break a closed P0 without re-signing
        r = self._run_with(reg)
        self.assertFalse(r["ok"])
        self.assertIn("signature", r["reason"].lower())

    def test_emptied_findings_fails(self):
        reg = json.loads(self.real.read_text(encoding="utf-8"))
        reg["findings"] = []  # a stale-zero analogue: no findings at all
        r = self._run_with(reg)
        self.assertFalse(r["ok"])

    def test_foreign_key_fails(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from proofbundle import canonical
        body = {k: v for k, v in json.loads(self.real.read_text(encoding="utf-8")).items()
                if k != "signature"}
        k = Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                          format=serialization.PublicFormat.Raw)
        forged = dict(body)
        forged["signature"] = {
            "alg": "ed25519",
            "public_key_b64": base64.b64encode(pub).decode(),
            "sig_b64": base64.b64encode(k.sign(canonical.canonicalize_statement(body))).decode(),
        }
        r = self._run_with(forged)
        self.assertFalse(r["ok"])
        self.assertIn("pinned", r["reason"].lower())


class TestResolveCurrent(unittest.TestCase):
    """Pure supersession + contradiction logic (no signature needed)."""

    def setUp(self):
        self.fr = _load("fr_rt10_b", "scripts/findings_register.py")

    def test_supersession_current_wins(self):
        findings = [
            {"id": "A", "severity": "P1", "status": "open", "superseded_by": "A2"},
            {"id": "A2", "severity": "P1", "status": "closed"},
        ]
        effective, contradictions = self.fr._resolve_current(findings)
        self.assertNotIn("A", effective)       # superseded entry drops out
        self.assertEqual(effective["A2"]["status"], "closed")
        self.assertEqual(contradictions, [])

    def test_contradiction_detected(self):
        findings = [
            {"id": "B", "severity": "P0", "status": "closed"},
            {"id": "B", "severity": "P0", "status": "open"},  # same id, conflicting, no supersession
        ]
        _effective, contradictions = self.fr._resolve_current(findings)
        self.assertIn("B", contradictions)


if __name__ == "__main__":
    unittest.main()
