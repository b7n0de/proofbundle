"""WP-W2 — the offline conformance corpus runs green, and its anchor checks are real.

The harness lives in `conformance/run_conformance.py`. In the base test job (no
`[anchors]` extra) the canonicalization / content-root / validator checks run for every
case and the anchor sub-checks skip. The `_HAS_OTS` test runs the full anchor-required
pass — it executes in the dedicated `anchors` CI job, mirroring tests/test_anchors_ots.py.
"""
import importlib.util
import pathlib
import unittest

_CONF = pathlib.Path(__file__).resolve().parents[1] / "conformance"

_spec = importlib.util.spec_from_file_location("run_conformance", _CONF / "run_conformance.py")
_rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rc)


class TestConformanceCorpus(unittest.TestCase):
    def test_corpus_passes_offline(self):
        # Non-anchor checks (canonicalization, content roots, evidenceRef binding, validator
        # finding counts) run for every case regardless of the [anchors] extra.
        self.assertEqual(_rc.run(require_anchors=False), 0)

    @unittest.skipUnless(_rc._HAS_OTS, "needs [anchors]/opentimestamps for the anchor sub-checks")
    def test_corpus_passes_with_anchors_required(self):
        # The full run: a confirmed anchor must verify offline against its frozen block header,
        # a pending anchor must report pending. Runs in the anchors CI job.
        self.assertEqual(_rc.run(require_anchors=True), 0)

    def test_manifest_and_cases_are_wellformed(self):
        import json
        manifest = json.loads((_CONF / "manifest.json").read_text())
        self.assertTrue(manifest.get("cases"))
        for rel in manifest["cases"]:
            case = json.loads((_CONF / rel / "case.json").read_text())
            for key in ("caseId", "kind", "expected", "specRefs", "rationale", "attribution"):
                self.assertIn(key, case, f"{rel} case.json missing {key}")


if __name__ == "__main__":
    unittest.main()
