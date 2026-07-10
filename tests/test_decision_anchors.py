"""Fix 2 (proofbundle#7): detached anchor evidence for a decision statement's OWN content root.

An anchor commits the content root = sha256 over the exact signed payload bytes, so it CANNOT live inside the
signed predicate (it would be part of the bytes whose hash it commits — resolvable only by forbidden subset
canonicalization). Anchor evidence for the statement's own root is therefore DETACHED (a sibling of the DSSE
envelope) and verified against the recomputed content root via the shared anchors layer. Mandatory cases:
(a) a detached anchor verifies offline incl. root match; (b) a wrong root fails; (c) an `anchors` field inside
the predicate is a fail-closed error; (d) a pending anchor + require_external_anchor + !allow_pending → policy
fail (exit 3), while allow_pending accepts it. unittest-style to match `python -m unittest`."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path

from proofbundle import anchors, dsse
from proofbundle.decision import emit_decision_receipt, validate_decision_predicate, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.policy import load_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _test_verifier(proof, canonical_root, *, frozen, now):
    """A deterministic test anchor verifier: proof b"OK" = a full anchor, b"PENDING" = pending (warn). It is
    never reached with a wrong root — verify_anchor checks canonicalRoot == content_root before calling it."""
    if proof == b"PENDING":
        return {"ok": False, "warn": True, "status": "warn", "detail": "calendar-only (pending)"}
    return {"ok": proof == b"OK", "detail": "test anchor"}


class TestDecisionAnchors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        anchors.register_anchor_type("test-anchor", _test_verifier)

    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.env = emit_decision_receipt(_pred("deny"), self.signer, strict=True)
        self.content_root = hashlib.sha256(dsse.load_payload(self.env)).digest()

    def _anchor(self, root_bytes, proof=b"OK"):
        return {"type": "test-anchor", "target": "statement",
                "canonicalRoot": base64.b64encode(root_bytes).decode(),
                "proof": base64.b64encode(proof).decode(),
                "anchoredAt": "2026-07-10T09:00:00Z"}

    def test_a_detached_anchor_verifies_with_root_match(self):
        r = verify_decision_receipt(self.env, self.pub, anchors=[self._anchor(self.content_root)])
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["anchors_ok"], True)

    def test_b_wrong_root_fails(self):
        wrong = hashlib.sha256(b"not the content root").digest()
        r = verify_decision_receipt(self.env, self.pub, anchors=[self._anchor(wrong)])
        self.assertIs(r["anchors_ok"], False)

    def test_c_anchors_inside_predicate_is_rejected(self):
        p = _pred("deny")
        p["anchors"] = [self._anchor(self.content_root)]
        errs = validate_decision_predicate(p)
        self.assertTrue(any("unknown top-level field" in e and "anchors" in e for e in errs))

    def test_d_pending_anchor_requires_allow_pending(self):
        pending = self._anchor(self.content_root, proof=b"PENDING")
        strict_pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                                  "decision_receipt": {"require_external_anchor": True, "allow_pending": False}})
        r = verify_decision_receipt(self.env, self.pub, anchors=[pending], policy=strict_pol)
        self.assertIs(r["policy_ok"], False)  # pending is the absence of a time anchor → exit 3
        lax_pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                               "decision_receipt": {"require_external_anchor": True, "allow_pending": True}})
        r2 = verify_decision_receipt(self.env, self.pub, anchors=[pending], policy=lax_pol)
        self.assertIs(r2["policy_ok"], True)

    def test_require_external_anchor_with_no_anchor_fails(self):
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                           "decision_receipt": {"require_external_anchor": True}})
        r = verify_decision_receipt(self.env, self.pub, policy=pol)
        self.assertIs(r["policy_ok"], False)

    def test_full_anchor_satisfies_require_external_anchor(self):
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                           "decision_receipt": {"require_external_anchor": True}})
        r = verify_decision_receipt(self.env, self.pub, anchors=[self._anchor(self.content_root)], policy=pol)
        self.assertIs(r["anchors_ok"], True)
        self.assertIs(r["policy_ok"], True)


if __name__ == "__main__":
    unittest.main()
