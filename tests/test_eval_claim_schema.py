"""An emitted eval claim validates against schemas/eval_claim_v0_1.schema.json."""
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "eval_claim_v0_1.schema.json"


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestEvalClaimSchema(unittest.TestCase):
    def test_schema_valid(self):
        jsonschema.Draft202012Validator.check_schema(json.loads(SCHEMA.read_text(encoding="utf-8")))

    def test_built_claim_matches_schema(self):
        signer = generate_signer()
        claim, _ = build_eval_claim(
            suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80",
            score="0.92", n=500, model_id="m", dataset_id="d",
            issuer=issuer_fingerprint(signer), timestamp="2026-07-01T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        jsonschema.validate(instance=claim, schema=json.loads(SCHEMA.read_text(encoding="utf-8")))

    def test_schema_rejects_float_threshold(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        bad = {"schema": "proofbundle/eval-claim/v0.1", "threshold": 0.80}
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=bad, schema=schema)

    def test_built_claim_with_evaluation_card_sha256_matches_schema(self):
        # Finding 18 (additive): the new optional evaluation_card_sha256 field is schema-valid.
        signer = generate_signer()
        claim, _ = build_eval_claim(
            suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80",
            score="0.92", n=500, model_id="m", dataset_id="d",
            issuer=issuer_fingerprint(signer), timestamp="2026-07-01T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16, evaluation_card_sha256="ab" * 32)
        jsonschema.validate(instance=claim, schema=json.loads(SCHEMA.read_text(encoding="utf-8")))
