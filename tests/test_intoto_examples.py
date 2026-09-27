"""The committed examples/intoto/*.statement.json are REAL and reproducible: this test regenerates each
from a fixed throwaway example key + fixed salt and asserts byte-equality, then validates every one
(predicateType, subject shape, no secret leak). If an example drifts from the code, CI goes red.

The example key (seed = bytes(range(32))) is a documented THROWAWAY that signs only these examples — it is
NOT a real signing identity and never leaves this test.

The eval-result examples are in the v0.2 shape (the revised in-toto/attestation#575 draft): an
`evaluator`, each of model and dataset identified once, and `evidence[]` in place of the `receipt` block.
`examples/intoto/eval-receipt.json` is the receipt they reference, written the way `proofbundle emit`
writes a receipt file, so a reader can check the evidence digest against real bytes."""
import base64
import hashlib
import json
import pathlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.bundle import recompute_merkle_root_b64
from proofbundle.intoto import (
    EVAL_RESULT_V02_PREDICATE_TYPE,
    SVR_PREDICATE_TYPE,
    classify_eval_result_v02_predicate,
    export_svr_dsse,
    receipt_evidence,
    resolve_subject,
    to_eval_result_v02_statement,
)

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "intoto"
_SALT = b"\x11" * 16
_SEED = bytes(range(32))
_EVALUATOR = "https://example.com/evaluator"
_RECEIPT_URI = "https://example.com/receipts/eval-receipt.json"
# The plaintext identifiers that must NEVER appear in any example (they live only here + as commitments).
_SECRETS = ("acme/secret-model-7b", "acme/internal-redteam-set", _SALT.hex())


def _build_examples() -> dict:
    signer = Ed25519PrivateKey.from_private_bytes(_SEED)
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
        comparator=">=", threshold="0.98", score="0.994", n=500,
        model_id="acme/secret-model-7b", dataset_id="acme/internal-redteam-set",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-05T12:00:00Z",
        model_salt=_SALT, dataset_salt=_SALT)
    bundle = emit_eval_receipt(claim, signer)
    receipt_text = json.dumps(bundle, indent=2) + "\n"
    root = recompute_merkle_root_b64(bundle)["stated_b64"]
    evidence = [receipt_evidence(receipt_text.encode("utf-8"), root_b64=root, uri=_RECEIPT_URI)]
    out = {"eval-receipt.json": receipt_text}
    out["private-model-commitment.statement.json"] = to_eval_result_v02_statement(
        claim, subject=resolve_subject("receipt", claim, root_b64=root), evaluator_id=_EVALUATOR,
        evidence=evidence, harness={"name": "inspect_ai", "version": "0.3.244"})
    out["public-model.statement.json"] = to_eval_result_v02_statement(
        claim, subject=resolve_subject("public-model", claim, subject_name="acme/open-model-7b",
                                       subject_sha256="a" * 64),
        evaluator_id=_EVALUATOR, subject_profile="public-model", evidence=evidence,
        model={"name": "acme/open-model-7b", "digest": {"sha256": "a" * 64},
               "uri": "https://example.com/models/acme/open-model-7b"})
    out["release-gate.statement.json"] = to_eval_result_v02_statement(
        claim, subject=resolve_subject("release-gate", claim, subject_name="acme/inference-service:1.4.2",
                                       subject_sha256="b" * 64),
        evaluator_id=_EVALUATOR, subject_profile="release-gate", evidence=evidence)
    env = export_svr_dsse(bundle, signer, time_created="2026-07-05T12:34:56Z")
    out["svr.statement.json"] = json.loads(base64.b64decode(env["payload"]))
    return out


def _statements() -> dict:
    return {name: stmt for name, stmt in _build_examples().items() if name.endswith(".statement.json")}


class TestIntotoExamples(unittest.TestCase):
    def test_committed_examples_match_the_code(self):
        for name, stmt in _build_examples().items():
            path = EXAMPLES / name
            self.assertTrue(path.exists(), f"missing example {name}")
            if isinstance(stmt, str):
                self.assertEqual(path.read_text(encoding="utf-8"), stmt, f"{name} drifted — regenerate it")
                continue
            committed = json.loads(path.read_text())
            self.assertEqual(committed, stmt, f"{name} drifted from the generator — regenerate it")

    def test_every_example_is_a_valid_statement_with_no_secret(self):
        for name, stmt in _statements().items():
            self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
            self.assertIn(stmt["predicateType"], (EVAL_RESULT_V02_PREDICATE_TYPE, SVR_PREDICATE_TYPE))
            self.assertTrue(stmt["subject"] and stmt["subject"][0]["digest"], name)
            body = json.dumps(stmt)
            for secret in _SECRETS:
                self.assertNotIn(secret, body, f"{name} leaks {secret!r}")

    def test_every_eval_result_example_passes_the_v02_shape_check(self):
        for name, stmt in _statements().items():
            if stmt["predicateType"] == EVAL_RESULT_V02_PREDICATE_TYPE:
                with self.subTest(example=name):
                    self.assertEqual(classify_eval_result_v02_predicate(stmt), (True, ""))

    def test_the_evidence_digest_names_the_committed_receipt(self):
        receipt = (EXAMPLES / "eval-receipt.json").read_bytes()
        for name, stmt in _statements().items():
            if stmt["predicateType"] == EVAL_RESULT_V02_PREDICATE_TYPE:
                with self.subTest(example=name):
                    self.assertEqual(stmt["predicate"]["evidence"][0]["digest"],
                                     {"sha256": hashlib.sha256(receipt).hexdigest()})

    def test_the_public_model_example_identifies_the_model_by_descriptor(self):
        pred = _statements()["public-model.statement.json"]["predicate"]
        self.assertEqual(pred["model"]["digest"], {"sha256": "a" * 64})
        self.assertNotIn("model", pred["commitments"])
        self.assertIn("dataset", pred["commitments"])

    def test_subject_profiles_are_distinct(self):
        ex = _statements()
        self.assertEqual(ex["public-model.statement.json"]["subject"][0]["digest"]["sha256"], "a" * 64)
        self.assertEqual(ex["release-gate.statement.json"]["subject"][0]["digest"]["sha256"], "b" * 64)
        self.assertEqual(ex["private-model-commitment.statement.json"]["subject"][0]["name"], "eval-receipt")

    def test_svr_example_carries_passing_properties_only(self):
        props = _statements()["svr.statement.json"]["predicate"]["properties"]
        self.assertIn("PROOFBUNDLE_THRESHOLD_MET", props)
        self.assertTrue(all(p.startswith("PROOFBUNDLE_") for p in props))


if __name__ == "__main__":
    unittest.main()
