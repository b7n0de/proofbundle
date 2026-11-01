"""`decision verify --evidence`: the command line binds `evidenceRefs` to the evidence a relying party holds.

SOURCE. Measured on 2026-11-01 while an example for a draft appendix was built: a decision receipt signed again over
a wrong evidence digest passed `proofbundle decision verify` with exit 0, because the command line took no evidence
at all. Only the library bound it, `verify_decision_receipt(evidence_resolver=...)` and `resolve_evidence_ref`.

THE RULE (docs/predicates/decision-receipt.md section 3). `evidenceRefs[].digest` is the content root of the
evidence statement, SHA-256 over its exact payload bytes; for a DSSE envelope that is its decoded payload, for any
other file its exact bytes. `artifactDigest` pins a stored blob, SHA-256 over the exact file bytes.

THE PROPERTY. With `--evidence`, each `evidenceRefs` entry is bound by a given file whose content root equals its
digest, and each given file binds an entry, by its content root or as the blob of an `artifactDigest`; otherwise
the command exits 1. Without the option the output says that only the form of the entries was checked, and the
exit code is the one it was.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle import dsse
from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _pred() -> dict:
    return json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))


class DecisionVerifyBindsTheEvidenceGiven(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pb_evidence_files_"))
        self.signer = generate_signer()
        self.pub = base64.b64encode(self.signer.public_key().public_bytes_raw()).decode("ascii")
        # The evidence: a signed statement of its own (here a decision receipt), held as its DSSE envelope.
        self.evidence_env = emit_decision_receipt(_pred(), generate_signer(), strict=True)
        self.evidence = self._schreibe("evidence.json", self.evidence_env)
        self.payload = dsse.load_payload(self.evidence_env)
        self.root = hashlib.sha256(self.payload).hexdigest()
        self.blob = hashlib.sha256(Path(self.evidence).read_bytes()).hexdigest()
        self.payload_file = self.tmp / "evidence.payload"
        self.payload_file.write_bytes(self.payload)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _schreibe(self, name: str, obj) -> str:
        p = self.tmp / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def _receipt(self, digest: str, *, artifact: str | None = None, name: str = "receipt.json") -> str:
        pred = copy.deepcopy(_pred())
        ref = {"relation": "evalResult", "uri": "urn:example:evidence", "digest": {"sha256": digest}}
        if artifact is not None:
            ref["artifactDigest"] = {"sha256": artifact}
        pred["evidenceRefs"] = [ref]
        return self._schreibe(name, emit_decision_receipt(pred, self.signer, strict=True))

    def _verify(self, receipt: str, *extra: str) -> tuple[int, str, str]:
        return _run(["decision", "verify", receipt, "--pub", self.pub, "--strict", *extra])

    def _fremd(self) -> str:
        """Evidence of ANOTHER statement: another decisionId, so other payload bytes and another content root. The
        same predicate under another key would be no other statement (see the control at the end)."""
        pred = dict(_pred(), decisionId="urn:example:another-decision")
        return self._schreibe("other.json", emit_decision_receipt(pred, generate_signer(), strict=True))

    # ── red on the code before: the option did not exist, and the receipt of S5 passed ──────────────

    def test_red_first_a_receipt_signed_over_a_wrong_digest_fails_against_the_true_evidence(self) -> None:
        falsch = self.root[:-1] + ("0" if self.root[-1] != "0" else "1")
        receipt = self._receipt(falsch, artifact=self.blob)
        rc_ohne, _, _ = self._verify(receipt)
        self.assertEqual(rc_ohne, 0, "the case of S5: without evidence the signed receipt passes")
        rc, out, err = self._verify(receipt, "--evidence", self.evidence)
        self.assertEqual(rc, 1, (out, err))
        self.assertIn("EVIDENCE: FAIL", out)

    def test_red_first_the_true_evidence_binds_the_receipt(self) -> None:
        receipt = self._receipt(self.root, artifact=self.blob)
        rc, out, err = self._verify(receipt, "--evidence", self.evidence)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("EVIDENCE: BOUND (1 of 1", out)

    def test_red_first_the_exact_payload_bytes_bind_like_the_envelope(self) -> None:
        receipt = self._receipt(self.root)
        rc, out, err = self._verify(receipt, "--evidence", str(self.payload_file))
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("EVIDENCE: BOUND (1 of 1", out)

    def test_red_first_evidence_of_another_statement_fails(self) -> None:
        receipt = self._receipt(self.root)
        rc, out, _ = self._verify(receipt, "--evidence", self._fremd())
        self.assertEqual(rc, 1)
        self.assertIn("EVIDENCE: FAIL", out)

    def test_red_first_a_file_that_binds_no_entry_fails_beside_one_that_does(self) -> None:
        receipt = self._receipt(self.root)
        rc, out, err = self._verify(receipt, "--evidence", self.evidence, "--evidence", self._fremd())
        self.assertEqual(rc, 1, (out, err))
        self.assertIn("binds no evidenceRefs entry", err)

    def test_red_first_an_entry_no_file_binds_fails(self) -> None:
        pred = copy.deepcopy(_pred())
        pred["evidenceRefs"] = [{"relation": "evalResult", "digest": {"sha256": self.root}},
                                {"relation": "evalResult", "digest": {"sha256": "e" * 64}}]
        receipt = self._schreibe("two_refs.json", emit_decision_receipt(pred, self.signer, strict=True))
        rc, out, err = self._verify(receipt, "--evidence", self.evidence)
        self.assertEqual(rc, 1, (out, err))
        self.assertIn("EVIDENCE: FAIL (1 of 2", out)

    def test_red_first_the_stored_blob_binds_through_the_artifact_digest(self) -> None:
        """The payload binds the content root, the stored envelope the artifactDigest; both files bind."""
        receipt = self._receipt(self.root, artifact=self.blob)
        rc, out, err = self._verify(receipt, "--evidence", str(self.payload_file), "--evidence", self.evidence)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("EVIDENCE: BOUND (1 of 1", out)

    def test_red_first_without_evidence_the_output_says_only_the_form_was_checked(self) -> None:
        receipt = self._receipt(self.root)
        rc, out, _ = self._verify(receipt)
        self.assertEqual(rc, 0)
        self.assertIn("EVIDENCE: FORM ONLY", out)

    def test_red_first_the_json_report_carries_the_binding(self) -> None:
        falsch = "e" * 64
        receipt = self._receipt(falsch)
        rc, out, _ = self._verify(receipt, "--evidence", self.evidence, "--json")
        self.assertEqual(rc, 1)
        bindung = json.loads(out)["evidence_files"]
        self.assertIs(bindung["ok"], False)
        self.assertEqual(bindung["entries"][0]["content_root_ok"], False)
        self.assertEqual(bindung["unbound_files"], [0])
        rc, out, _ = self._verify(self._receipt(self.root, name="good.json"), "--evidence", self.evidence, "--json")
        self.assertEqual(rc, 0)
        bindung = json.loads(out)["evidence_files"]
        self.assertIs(bindung["ok"], True)
        self.assertEqual(json.loads(out)["evidence_levels"]["evidenceRefs"]["level_name"], "CONTENT_RESOLVED")

    # ── controls ────────────────────────────────────────────────────────────────────────────────────────

    def test_control_without_the_option_the_json_report_is_unchanged(self) -> None:
        rc, out, _ = self._verify(self._receipt(self.root), "--json")
        self.assertEqual(rc, 0)
        self.assertNotIn("evidence_files", json.loads(out))

    def test_control_a_file_that_cannot_be_read_is_malformed_input(self) -> None:
        receipt = self._receipt(self.root)
        for wert in ("", str(self.tmp / "missing.json"), str(self.tmp)):
            with self.subTest(value=wert):
                self.assertEqual(self._verify(receipt, "--evidence", wert)[0], 2)

    def test_control_an_envelope_whose_payload_does_not_decode_is_malformed_input(self) -> None:
        kaputt = dict(self.evidence_env, payload="not base64!")
        rc, _, _ = self._verify(self._receipt(self.root), "--evidence", self._schreibe("broken.json", kaputt))
        self.assertEqual(rc, 2)

    def test_control_the_same_statement_signed_by_another_key_binds(self) -> None:
        """The content root is over the payload, never the signature (section 3: it survives counter-signing and key
        rotation of the evidence); WHO signed the evidence is a trust-policy question, not this binding."""
        receipt = self._receipt(self.root)
        anders = self._schreibe("countersigned.json", emit_decision_receipt(_pred(), generate_signer(), strict=True))
        self.assertEqual(dsse.load_payload(json.loads(Path(anders).read_text(encoding="utf-8"))), self.payload)
        rc, out, err = self._verify(receipt, "--evidence", anders)
        self.assertEqual(rc, 0, (out, err))

    def test_control_a_crypto_failure_stays_exit_1_and_claims_no_binding(self) -> None:
        receipt = self._receipt(self.root)
        anderer = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode("ascii")
        rc, out, _ = _run(["decision", "verify", receipt, "--pub", anderer, "--evidence", self.evidence])
        self.assertEqual(rc, 1)
        self.assertNotIn("EVIDENCE: BOUND", out)


if __name__ == "__main__":
    unittest.main()
