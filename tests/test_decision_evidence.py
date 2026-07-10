"""Fix 1 (proofbundle#7): evidenceRefs[].digest is the CONTENT ROOT of the referenced evidence Statement —
sha256 over its RFC-8785 canonical Statement bytes — not an envelope/file hash and not the bare predicate
hash. So the reference survives counter-signing / key rotation of the evidence (the payload bytes do not
change) and breaks only when the evidence CONTENT changes. Optional artifactDigest pins an exact stored blob.
unittest-style to match `python -m unittest`."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from proofbundle import dsse
from proofbundle.decision import (
    _rfc8785_bytes,
    build_decision_statement,
    emit_decision_receipt,
    resolve_evidence_ref,
    validate_decision_predicate,
)
from proofbundle.emit import generate_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


class TestDecisionEvidenceContentRoot(unittest.TestCase):
    def setUp(self):
        # Any in-toto Statement can be evidence; a decision statement stands in for an eval-result statement.
        self.evidence_pred = _pred("allow")
        self.env_evidence = emit_decision_receipt(self.evidence_pred, generate_signer(), strict=True)
        self.evidence_payload = dsse.load_payload(self.env_evidence)
        self.content_root_hex = hashlib.sha256(self.evidence_payload).hexdigest()

    def _ref(self, digest_hex, artifact_hex=None):
        ref = {"relation": "evalResult", "uri": "urn:x", "digest": {"sha256": digest_hex}}
        if artifact_hex is not None:
            ref["artifactDigest"] = {"sha256": artifact_hex}
        return ref

    def test_a_resign_evidence_keeps_content_root(self):
        # Re-sign the SAME evidence statement with a DIFFERENT key. The payload bytes are byte-identical
        # (canonical emission), so the content root — and the evidenceRef digest — still match. Signer trust
        # is a separate Trust-Policy question, decoupled from the content reference.
        env_resigned = emit_decision_receipt(self.evidence_pred, generate_signer(), strict=True)
        payload_resigned = dsse.load_payload(env_resigned)
        self.assertEqual(payload_resigned, self.evidence_payload)
        res = resolve_evidence_ref(self._ref(self.content_root_hex), evidence_payload=payload_resigned)
        self.assertIs(res["content_root_ok"], True)

    def test_b_changed_content_breaks_content_root(self):
        mutated = copy.deepcopy(self.evidence_pred)
        mutated["decisionId"] = "urn:uuid:00000000-0000-4000-8000-000000000000"
        payload_mut = dsse.load_payload(emit_decision_receipt(mutated, generate_signer(), strict=True))
        res = resolve_evidence_ref(self._ref(self.content_root_hex), evidence_payload=payload_mut)
        self.assertIs(res["content_root_ok"], False)

    def test_b2_subject_only_change_breaks_content_root(self):
        # Even a subject-only change (same predicate) changes the Statement bytes → content-root mismatch,
        # which is exactly why the ref binds the STATEMENT content root and not the bare predicate hash.
        payload_alt = _rfc8785_bytes(build_decision_statement(self.evidence_pred, subject_name="decision:tampered"))
        res = resolve_evidence_ref(self._ref(self.content_root_hex), evidence_payload=payload_alt)
        self.assertIs(res["content_root_ok"], False)

    def test_c_artifact_digest_pins_exact_blob(self):
        blob = b"the stored evidence bytes"
        ref = self._ref(self.content_root_hex, artifact_hex=hashlib.sha256(blob).hexdigest())
        self.assertIs(resolve_evidence_ref(ref, artifact_bytes=blob)["artifact_ok"], True)
        self.assertIs(resolve_evidence_ref(ref, artifact_bytes=b"different blob")["artifact_ok"], False)

    def test_artifact_digest_validates_in_predicate(self):
        p = _pred("deny")
        p["evidenceRefs"][0]["artifactDigest"] = {"sha256": self.content_root_hex}
        self.assertEqual(validate_decision_predicate(p, strict=True), [])
        p["evidenceRefs"][0]["artifactDigest"] = {"sha256": "tooshort"}
        self.assertTrue(any("artifactDigest" in e for e in validate_decision_predicate(p)))


if __name__ == "__main__":
    unittest.main()
