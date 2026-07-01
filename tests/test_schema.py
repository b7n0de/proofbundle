"""The example bundle validates against the published JSON Schema.

This keeps schemas/proofbundle_v0_1.schema.json honest: if the bundle format and
the schema ever drift apart, this test goes red. jsonschema is a dev dependency
only, never required at runtime.
"""
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "proofbundle_v0_1.schema.json"
EXAMPLE = ROOT / "examples" / "example_bundle.json"


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestSchema(unittest.TestCase):
    def test_schema_is_valid_json_schema(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_example_bundle_matches_schema(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        bundle = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        jsonschema.validate(instance=bundle, schema=schema)

    def test_schema_rejects_bundle_without_signature(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        bad = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        del bad["signature"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=bad, schema=schema)


if __name__ == "__main__":
    unittest.main()
