"""The committed examples/intoto/*.statement.json are REAL and reproducible: this test regenerates each
from a fixed throwaway example key + fixed salt and asserts byte-equality, then validates every one
(predicateType, subject shape, no secret leak). If an example drifts from the code, CI goes red.

The example key (seed = bytes(range(32))) is a documented THROWAWAY that signs only these examples — it is
NOT a real signing identity and never leaves this test."""
import base64
import json
import pathlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.intoto import (
    EVAL_RESULT_PREDICATE_TYPE,
    SVR_PREDICATE_TYPE,
    export_svr_dsse,
    resolve_subject,
    to_eval_result_statement,
)

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "intoto"
_SALT = b"\x11" * 16
_SEED = bytes(range(32))
_ROOT = "cmVjZWlwdC1tZXJrbGUtcm9vdA=="
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
    out = {}
    out["private-model-commitment.statement.json"] = to_eval_result_statement(
        claim, subject=resolve_subject("receipt", claim, root_b64=_ROOT),
        root_b64=_ROOT, harness={"name": "inspect_ai", "version": "0.3.244"})
    out["public-model.statement.json"] = to_eval_result_statement(
        claim, subject=resolve_subject("public-model", claim, subject_name="acme/open-model-7b",
                                       subject_sha256="a" * 64),
        root_b64=_ROOT, subject_profile="public-model")
    out["release-gate.statement.json"] = to_eval_result_statement(
        claim, subject=resolve_subject("release-gate", claim, subject_name="acme/inference-service:1.4.2",
                                       subject_sha256="b" * 64),
        root_b64=_ROOT, subject_profile="release-gate")
    env = export_svr_dsse(emit_eval_receipt(claim, signer), signer, time_created="2026-07-05T12:34:56Z")
    out["svr.statement.json"] = json.loads(base64.b64decode(env["payload"]))
    return out


class TestIntotoExamples(unittest.TestCase):
    def test_committed_examples_match_the_code(self):
        for name, stmt in _build_examples().items():
            path = EXAMPLES / name
            self.assertTrue(path.exists(), f"missing example {name}")
            committed = json.loads(path.read_text())
            self.assertEqual(committed, stmt, f"{name} drifted from the generator — regenerate it")

    def test_every_example_is_a_valid_statement_with_no_secret(self):
        for name, stmt in _build_examples().items():
            self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
            self.assertIn(stmt["predicateType"], (EVAL_RESULT_PREDICATE_TYPE, SVR_PREDICATE_TYPE))
            self.assertTrue(stmt["subject"] and stmt["subject"][0]["digest"], name)
            body = json.dumps(stmt)
            for secret in _SECRETS:
                self.assertNotIn(secret, body, f"{name} leaks {secret!r}")

    def test_subject_profiles_are_distinct(self):
        ex = _build_examples()
        self.assertEqual(ex["public-model.statement.json"]["subject"][0]["digest"]["sha256"], "a" * 64)
        self.assertEqual(ex["release-gate.statement.json"]["subject"][0]["digest"]["sha256"], "b" * 64)
        self.assertEqual(ex["private-model-commitment.statement.json"]["subject"][0]["name"], "eval-receipt")

    def test_svr_example_carries_passing_properties_only(self):
        props = _build_examples()["svr.statement.json"]["predicate"]["properties"]
        self.assertIn("PROOFBUNDLE_THRESHOLD_MET", props)
        self.assertTrue(all(p.startswith("PROOFBUNDLE_") for p in props))


if __name__ == "__main__":
    unittest.main()
