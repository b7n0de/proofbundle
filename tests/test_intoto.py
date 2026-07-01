"""in-toto Statement v1 view of an eval receipt — structurally valid + honest salted-commitment digest."""
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.intoto import MODEL_COMMIT_DIGEST_KEY, PREDICATE_TYPE, to_intoto_statement

ROOT = Path(__file__).resolve().parents[1]
TS = "2026-07-01T12:00:00Z"


def _claim():
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="accuracy", comparator=">=",
        threshold="0.65", score="0.92", n=500, model_id="acme/model-x", dataset_id="acme/set",
        issuer=issuer_fingerprint(signer), timestamp=TS, model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class TestInToto(unittest.TestCase):
    def test_structure(self):
        stmt = to_intoto_statement(_claim(), root_b64="cm9vdA==",
                                   harness={"name": "inspect_ai", "version": "0.3.217"})
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], PREDICATE_TYPE)
        self.assertEqual(len(stmt["subject"]), 1)
        self.assertIn("digest", stmt["subject"][0])
        # honest custom digest key, NOT sha256 (would mislead generic verifiers about an artifact hash)
        self.assertIn(MODEL_COMMIT_DIGEST_KEY, stmt["subject"][0]["digest"])
        self.assertNotIn("sha256", stmt["subject"][0]["digest"])
        self.assertIn("salted commitment", stmt["predicate"]["subject_digest_note"])
        self.assertEqual(stmt["predicate"]["receipt"]["root_b64"], "cm9vdA==")

    def test_digest_is_commit_hex(self):
        claim = _claim()
        stmt = to_intoto_statement(claim)
        expected_hex = claim["model_id_commit"].split(":", 1)[1]
        self.assertEqual(stmt["subject"][0]["digest"][MODEL_COMMIT_DIGEST_KEY], expected_hex)

    @unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install proofbundle[dev])")
    def test_validates_against_official_intoto_v1_schema(self):
        schema = json.loads((ROOT / "schemas" / "in_toto_statement_v1.schema.json").read_text(encoding="utf-8"))
        stmt = to_intoto_statement(_claim(), root_b64="cm9vdA==")
        jsonschema.validate(instance=stmt, schema=schema)  # raises if invalid

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_schema_rejects_missing_subject(self):
        schema = json.loads((ROOT / "schemas" / "in_toto_statement_v1.schema.json").read_text(encoding="utf-8"))
        bad = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "x", "subject": []}
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=bad, schema=schema)


if __name__ == "__main__":
    unittest.main()
