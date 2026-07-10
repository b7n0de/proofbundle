"""Regression tests for the defects the 6-lens adversarial review found in the PR #45 course-correction.

Each was a real fail-open uncovered by the existing suite: crypto->policy fail-open (a wrong key returned
policy_ok True), --aud/--nonce replay exiting 0, the No-Overclaim trailer firing on a crypto FAIL, privacy={}
passing strict, a FULL anchor wrongly rejected when bundled with a pending one, and schema<->validator drift.
unittest-style to match `python -m unittest`."""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from proofbundle import anchors, dsse
from proofbundle.cli import main
from proofbundle.decision import (
    _REQUIRED_ALWAYS,
    emit_decision_receipt,
    validate_decision_predicate,
    verify_decision_receipt,
)
from proofbundle.emit import generate_signer
from proofbundle.policy import load_policy

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _hardening_verifier(proof, canonical_root, *, frozen, now):
    if proof == b"PENDING":
        return {"ok": False, "warn": True, "status": "warn", "detail": "pending"}
    return {"ok": proof == b"OK", "detail": "t"}


def _run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, buf.getvalue()


class TestDecisionHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        anchors.register_anchor_type("test-anchor2", _hardening_verifier)

    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.pub_b64 = base64.b64encode(self.pub).decode()
        self.env = emit_decision_receipt(_pred("deny"), self.signer, strict=True)
        self.content_root = hashlib.sha256(dsse.load_payload(self.env)).digest()
        self.tmp = Path(tempfile.mkdtemp())

    def _anchor(self, proof=b"OK"):
        return {"type": "test-anchor2", "target": "statement",
                "canonicalRoot": base64.b64encode(self.content_root).decode(),
                "proof": base64.b64encode(proof).decode(), "anchoredAt": "2026-07-10T09:00:00Z"}

    def _write_env(self, env):
        p = self.tmp / "r.json"
        p.write_text(json.dumps(env), encoding="utf-8")
        return str(p)

    def test_crypto_policy_fail_open_closed(self):
        other = generate_signer().public_key().public_bytes_raw()
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                           "decision_receipt": {"allowed_verdicts": ["ALLOW"]}})  # DENY would fail IF evaluated
        r = verify_decision_receipt(self.env, other, policy=pol)
        self.assertIs(r["crypto_ok"], False)
        self.assertIsNone(r["policy_ok"])      # policy NOT evaluated on unverified bytes (was True: fail-open)
        self.assertIsNone(r["signer_trusted"])

    def test_audience_mismatch_gated_and_cli_exits_2(self):
        r = verify_decision_receipt(self.env, self.pub, expected_audience="https://evil.example")
        self.assertIs(r["audience_ok"], False)
        rc, out = _run(["decision", "verify", self._write_env(self.env), "--pub", self.pub_b64,
                        "--aud", "https://evil.example"])
        self.assertEqual(rc, 2)
        self.assertIn("AUDIENCE: MISMATCH", out)

    def test_nonce_mismatch_cli_exits_2(self):
        rc, _ = _run(["decision", "verify", self._write_env(self.env), "--pub", self.pub_b64,
                      "--nonce", "deadbeefdeadbeef"])
        self.assertEqual(rc, 2)

    def test_crypto_fail_has_no_positive_trailer(self):
        env = copy.deepcopy(self.env)
        body = json.loads(base64.b64decode(env["payload"]))
        body["predicate"]["decision"]["verdict"] = "ALLOW"
        env["payload"] = base64.b64encode(json.dumps(body).encode()).decode()
        rc, out = _run(["decision", "verify", self._write_env(env), "--pub", self.pub_b64])
        self.assertEqual(rc, 1)
        self.assertIn("did NOT verify", out)
        self.assertNotIn("has not been altered", out)

    def test_privacy_empty_object_fails_strict(self):
        p = _pred("deny")
        p["privacy"] = {}
        self.assertTrue(any("rawInputsIncluded" in e for e in validate_decision_predicate(p, strict=True)))
        p["privacy"] = {"rawInputsIncluded": "no"}  # wrong type
        self.assertTrue(any("rawInputsIncluded" in e for e in validate_decision_predicate(p, strict=True)))

    def test_full_anchor_with_pending_still_satisfies(self):
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                           "decision_receipt": {"require_external_anchor": True, "allow_pending": False}})
        r = verify_decision_receipt(self.env, self.pub, anchors=[self._anchor(b"OK"), self._anchor(b"PENDING")],
                                    policy=pol)
        self.assertIs(r["anchors_ok"], True)   # a full anchor is present, aggregate WARN must not reject it
        self.assertIs(r["policy_ok"], True)

    def test_broken_anchor_still_fails_even_with_full(self):
        wrong = {"type": "test-anchor2", "target": "statement",
                 "canonicalRoot": base64.b64encode(hashlib.sha256(b"x").digest()).decode(),
                 "proof": base64.b64encode(b"OK").decode(), "anchoredAt": "2026-07-10T09:00:00Z"}
        r = verify_decision_receipt(self.env, self.pub, anchors=[self._anchor(b"OK"), wrong])
        self.assertIs(r["anchors_ok"], False)  # a broken anchor is a tamper signal, fail-closed

    def test_schema_required_matches_validator(self):
        schema = json.loads((ROOT / "schemas/decision-receipt-v0.1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(schema["required"]), sorted(_REQUIRED_ALWAYS))


if __name__ == "__main__":
    unittest.main()
