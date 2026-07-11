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
            # every shipped decision_crossimpl case must fully declare its bindings (the floor):
            if case["kind"] == "decision_crossimpl":
                exp = case["expected"]
                for k in ("jcs_byte_identical", "content_roots_match_manifest", "decision_content_root",
                          "evidence_content_root", "evidence_ref_binds_content_root",
                          "decision_predicate_findings", "schema_conformant"):
                    self.assertIn(k, exp, f"{rel} expected under-declares {k}")
                if (_CONF / rel / "decision_receipt.jcs.ots").is_file():
                    self.assertIn("anchor", exp, f"{rel} ships a .ots but declares no anchor")


class TestHarnessFailsClosed(unittest.TestCase):
    """WP-W2 review (harness-soundness lens): a case that UNDER-DECLARES its expectations must FAIL,
    not pass green asserting nothing (fake-PASS-by-omission), and a missing fixture must be a per-case
    FAIL, not a run-aborting crash."""

    def _copy_corpus(self):
        import shutil
        import tempfile
        dst = pathlib.Path(tempfile.mkdtemp()) / "conformance"
        shutil.copytree(_CONF, dst)
        return dst

    def _run_on(self, root, **kw):
        import importlib.util
        spec = importlib.util.spec_from_file_location("rc_tmp", root / "run_conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.ROOT = root
        return m.run(**kw)

    def test_empty_expected_fails(self):
        import json
        root = self._copy_corpus()
        case_path = next(root.glob("decision/crossimpl/*/case.json"))
        case = json.loads(case_path.read_text())
        case["expected"] = {}
        case_path.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "a case declaring no expectations must FAIL")

    def test_dropping_a_binding_key_fails(self):
        import json
        root = self._copy_corpus()
        case_path = next(root.glob("decision/crossimpl/*/case.json"))
        case = json.loads(case_path.read_text())
        del case["expected"]["content_roots_match_manifest"]
        case_path.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "dropping a mandatory binding key must FAIL")

    def test_dropping_anchor_on_anchored_case_fails(self):
        import json
        root = self._copy_corpus()
        # the confirmed-anchor case ships a .ots — dropping its anchor expectation must fail
        cdir = root / "decision/crossimpl/confirmed-anchor-lifecycle"
        case = json.loads((cdir / "case.json").read_text())
        case["expected"].pop("anchor", None)
        (cdir / "case.json").write_text(json.dumps(case))
        self.assertEqual(self._run_on(root, require_anchors=_rc._HAS_OTS), 1,
                         "an anchored case that drops its anchor expectation must FAIL")

    def test_missing_fixture_is_per_case_fail_not_crash(self):
        root = self._copy_corpus()
        (next(root.glob("decision/crossimpl/*/evidence_eval_result.json"))).unlink()
        # must return 1 (a FAIL), not raise
        self.assertEqual(self._run_on(root), 1)

    def test_native_bundle_wrong_expected_exitcode_fails(self):
        import json
        root = self._copy_corpus()
        # the valid bundle verifies with exit 0; asserting it must exit 2 must FAIL
        cp = root / "bundle/valid-minimal/case.json"
        case = json.loads(cp.read_text())
        case["expected"]["exitCode"] = 2
        cp.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1)

    def test_native_bundle_missing_exitcode_fails(self):
        import json
        root = self._copy_corpus()
        cp = root / "bundle/valid-minimal/case.json"
        case = json.loads(cp.read_text())
        case["expected"] = {}
        cp.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "a native_bundle case without exitCode must FAIL (floor)")

    def test_duplicate_key_bundle_is_rejected(self):
        # the C1 defense as a conformance property: the dup-key fixture MUST verify to exit 2
        from proofbundle.cli import main as cli_main
        import contextlib
        import io
        p = _CONF / "bundle/duplicate-json-key/bundle.json"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli_main(["verify", str(p)])
        self.assertEqual(rc, 2, "a bundle with a duplicate JSON key must be rejected as malformed")


if __name__ == "__main__":
    unittest.main()
