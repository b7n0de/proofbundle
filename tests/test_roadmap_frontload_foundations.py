"""Tests for the five roadmap front-load foundations (GO_OWNER_PB_ROADMAP_FRONTLOAD_20260716).

F1 vector corpus + one comparator · F2 reproducible build normaliser · F3 formal model ·
F4 type-confusion generator · F5 readiness pack · F7 pre-tag audit gate. Bidirectional where it
matters (a broken input must be CAUGHT, not just a green happy path)."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for sub in ("src", "conformance", "scripts", "formal"):
    p = str(REPO / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(mod_name: str, rel: str):
    spec = importlib.util.spec_from_file_location(mod_name, REPO / rel)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class TestF1CommonVocabulary(unittest.TestCase):
    def setUp(self):
        import common_vocabulary as cv
        self.cv = cv

    def test_exit_class_names_the_contract(self):
        self.assertEqual(self.cv.exit_class(0), "VERIFIED")
        self.assertEqual(self.cv.exit_class(1), "CRYPTO_FAIL")
        self.assertEqual(self.cv.exit_class(2), "MALFORMED")
        self.assertEqual(self.cv.exit_class(3), "POLICY_UNMET")
        self.assertTrue(self.cv.exit_class(7).startswith("EXIT:"))  # out-of-contract is a finding

    def test_label_and_compare_pinned_axes_only(self):
        want = self.cv.expected_label({"exitCode": 0, "lineage": "VERIFIED"})
        got = self.cv.label_from_verify(0, {"lineage": {"lineage": "VERIFIED"}})
        ok, diffs = self.cv.compare(want, got)
        self.assertTrue(ok, diffs)

    def test_null_lineage_equals_not_evaluated(self):
        want = self.cv.expected_label({"exitCode": 0, "lineage": None})
        got = self.cv.label_from_verify(0, {"lineage": "NOT_EVALUATED"})
        self.assertTrue(self.cv.compare(want, got)[0])

    def test_mismatch_is_caught(self):
        want = self.cv.expected_label({"exitCode": 0, "lineage": "VERIFIED"})
        got = self.cv.label_from_verify(0, {"lineage": "FAIL"})
        ok, diffs = self.cv.compare(want, got)
        self.assertFalse(ok)
        self.assertTrue(any("lineage" in d for d in diffs))


class TestF1CrossFormatCorpus(unittest.TestCase):
    def setUp(self):
        # L6-02 follow-up: cross_format validates against JSON Schema (needs jsonschema, a [test]-extra dep) —
        # skip cleanly on a bare `[eval]` sdist install instead of erroring at `import cross_format`.
        import pytest
        pytest.importorskip("jsonschema")

    def test_real_corpus_is_schema_valid_and_consistent(self):
        import cross_format
        ok, problems = cross_format.run()
        self.assertTrue(ok, f"corpus integrity problems: {problems}")

    def test_contradictory_cross_format_id_is_caught(self):
        import cross_format
        cases = [
            ("a/case.json", {"caseId": "a", "kind": "native_bundle",
                             "expected": {"exitCode": 0}, "crossFormatId": "xfmt-z"}),
            ("b/case.json", {"caseId": "b", "kind": "native_bundle",
                             "expected": {"exitCode": 1}, "crossFormatId": "xfmt-z"}),
        ]
        problems = cross_format.check_cross_format(cases)
        self.assertTrue(problems, "a contradictory crossFormatId must be caught")
        self.assertIn("xfmt-z", problems[0])

    def test_schema_rejects_underdeclared_case(self):
        import cross_format
        bad = [("x/case.json", {"caseId": "x", "kind": "native_bundle", "expected": {}})]
        problems = cross_format.validate_schema(bad)
        self.assertTrue(problems, "an empty expected block must be rejected (fail-closed)")


class TestF3FormalModel(unittest.TestCase):
    def setUp(self):
        self.model = _load("frontload_formal_model", "formal/model.py")

    def test_all_non_reserved_obligations_proven(self):
        result = self.model.prove_all(bound=5)
        self.assertTrue(result["all_proven"], result)
        self.assertTrue(result["implementation_crosscheck"]["ok"])

    def test_reserved_slots_are_honest_not_faked(self):
        result = self.model.prove_all(bound=3)
        reserved = [o for o in result["obligations"] if o["status"] == "RESERVED"]
        self.assertGreaterEqual(len(reserved), 3)  # O5/O6/O7 for 3.4/3.5/3.6
        for o in reserved:
            self.assertIn(o["version_added"], {"3.4.0", "3.5.0", "3.6.0"})

    def test_ladder_join_matches_max_rank(self):
        self.assertEqual(self.model.aggregate_rank([0, 1, 3, 2]), 3)  # FAIL dominates
        self.assertEqual(self.model.aggregate_rank([1, 1]), 1)        # all verified
        self.assertEqual(self.model.aggregate_rank([]), 0)            # empty -> NOT_EVALUATED


class TestF4TypeConfusion(unittest.TestCase):
    def setUp(self):
        self.gate = _load("frontload_type_confusion", "scripts/type_confusion_gate.py")

    def test_no_public_verifier_raw_crashes(self):
        result = self.gate.evaluate()
        self.assertTrue(result["never_raise_ok"], result["violations"])
        self.assertGreater(result["in_scope"], 0)
        self.assertEqual(result["total_verify_surfaces"], self.gate.discover_python_verify_functions().__len__())

    def test_exercise_catches_a_raw_raiser(self):
        # bidirectional: a deliberately raw-crashing verifier MUST be reported as a violation.
        def broken(x):
            return x["missing"]  # raw KeyError/TypeError on type confusion
        violations = self.gate._exercise(broken, {}, [None, {}, 5, "s"])
        self.assertTrue(violations, "a raw-raising verifier must be caught")

    def test_defended_verifier_is_clean(self):
        from proofbundle.errors import BundleFormatError

        def defended(x):
            if not isinstance(x, dict):
                raise BundleFormatError("not an object")
            return {"ok": False}
        self.assertEqual(self.gate._exercise(defended, {}, [None, 5, {}, "s"]), [])


class TestF5ReadinessPack(unittest.TestCase):
    def setUp(self):
        self.gate = _load("frontload_readiness_gate", "scripts/readiness_pack_gate.py")

    def test_pack_is_grounded_in_real_artifacts(self):
        result = self.gate.evaluate()
        self.assertTrue(result["ok"], result["problems"])
        self.assertGreaterEqual(result["conclusions"], 4)
        self.assertGreaterEqual(result["release_slots"], 4)


class TestF7PreTagAudit(unittest.TestCase):
    def setUp(self):
        self.gate = _load("frontload_pretag_gate", "scripts/pre_tag_audit_gate.py")

    def test_released_version_has_audit_record(self):
        result = self.gate.evaluate(REPO)
        self.assertTrue(result["ok"], result)

    def test_missing_audit_is_caught(self):
        result = self.gate.evaluate(REPO, version="9.9.9")
        self.assertFalse(result["ok"])
        self.assertIn("9.9.9", result["reason"])

    def test_negated_marker_does_not_grant_pass(self):
        # RT10-PRETAG-02: a version-scoped record whose only audit-marker line NEGATES having run the audit
        # ("the adversarial audit did NOT run") must NOT satisfy the gate — a marker substring is not proof.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rec = Path(td) / "audit_artifacts" / "770"
            rec.mkdir(parents=True)
            (rec / "note.md").write_text("# 7.7.0\n\nThe 6-lens adversarial audit did NOT run yet (pending).\n")
            self.assertEqual(self.gate.audit_records_for(Path(td), "7.7.0"), [])
            self.assertFalse(self.gate.evaluate(Path(td), version="7.7.0")["ok"])

    def test_negation_covers_never_deferred_postponed(self):
        # 6-lens gate: the negation guard must also reject 'never ran' / 'deferred' / 'postponed' /
        # 'noch nicht durchgeführt', not only 'not/pending'.
        import tempfile
        for concession in ("The 6-lens adversarial audit never ran.",
                           "6-lens adversarial review deferred to 3.6.2.",
                           "Adversarial audit postponed.",
                           "The adversarial audit was cancelled.",
                           "6-lens adversarial review aborted.",
                           "Adversarial audit waived.",
                           "Adversarial audit incomplete.",
                           "Adversariales 6-Linsen-Review noch nicht durchgeführt."):
            with tempfile.TemporaryDirectory() as td:
                rec = Path(td) / "audit_artifacts" / "770"
                rec.mkdir(parents=True)
                (rec / "note.md").write_text(f"# 7.7.0\n\n{concession}\n")
                self.assertFalse(self.gate.evaluate(Path(td), version="7.7.0")["ok"], concession)

    def test_positive_marker_still_passes(self):
        # counterpart: a genuine positive audit note IS accepted (discriminates the negation guard from a
        # blanket reject).
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rec = Path(td) / "audit_artifacts" / "770"
            rec.mkdir(parents=True)
            (rec / "note.md").write_text("# 7.7.0\n\nRan a 6-lens adversarial audit; all findings fixed.\n")
            self.assertTrue(self.gate.evaluate(Path(td), version="7.7.0")["ok"])


if __name__ == "__main__":
    unittest.main()
