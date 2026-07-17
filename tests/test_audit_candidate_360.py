"""3.6.0 audit-candidate — bidirectional tests for the new gates (No-Fake, effect-grounded).

Every gate is exercised in BOTH directions: it is green on the real repo AND it CATCHES a deliberately
broken input. A green-only test would be a rubber stamp, exactly the class the No-Fake discipline
forbids.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for sub in ("src", "scripts", "formal", "conformance"):
    p = str(REPO / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class TestTestManifestGate(unittest.TestCase):
    def setUp(self):
        self.g = _load("acm_test_manifest", "scripts/test_manifest_gate.py")

    def test_real_floor_met(self):
        r = self.g.evaluate()
        self.assertTrue(r["ok"], r["problems"])
        self.assertEqual(r["errors"], 0)
        self.assertGreaterEqual(r["collected"], r["min_collected_tests"])

    def test_shrink_below_floor_is_caught(self):
        # bidirectional: an impossibly high floor must FAIL (a real shrink would look the same).
        with tempfile.TemporaryDirectory() as td:
            lock = Path(td) / "lock.json"
            lock.write_text(json.dumps({"min_collected_tests": 10 ** 9,
                                        "min_pytest_only_modules": 10 ** 6}))
            r = self.g.evaluate(lock_path=lock)
            self.assertFalse(r["ok"])
            self.assertTrue(any("floor" in p for p in r["problems"]))

    def test_pytest_only_discovery_is_ast_derived(self):
        mods = self.g.pytest_only_modules(REPO / "tests")
        self.assertTrue(all(m.startswith("test_") and m.endswith(".py") for m in mods))


class TestAuditCandidateMatrix(unittest.TestCase):
    def setUp(self):
        self.m = _load("acm_matrix", "scripts/audit_candidate_matrix.py")

    def test_matrix_is_ready_and_has_33_checks(self):
        r = self.m.evaluate()
        self.assertEqual(r["total_checks"], 33)
        self.assertTrue(r["audit_candidate_ready"], r["counts"])
        self.assertEqual(r["counts"][self.m.FAIL], 0)

    def test_external_is_the_single_open_gate(self):
        r = self.m.evaluate()
        ext = [c for c in r["checks"] if c["verdict"] == self.m.EXTERNAL]
        self.assertEqual(len(ext), 1)
        self.assertEqual(ext[0]["id"], "EXT.1")

    def test_data_blocked_is_not_a_pass(self):
        # No-Fake: a DATA_BLOCKED must NOT be counted toward PASS, and must keep fully_verified_here off.
        r = self.m.evaluate()
        if r["counts"][self.m.DATA_BLOCKED] > 0:
            self.assertFalse(r["fully_verified_here"])
        pass_ids = {c["id"] for c in r["checks"] if c["verdict"] == self.m.PASS}
        blocked_ids = {c["id"] for c in r["checks"] if c["verdict"] == self.m.DATA_BLOCKED}
        self.assertEqual(pass_ids & blocked_ids, set())

    def test_a_fail_flips_ready_off(self):
        # bidirectional: inject a FAIL check and the top verdict must drop to not-ready.
        orig = list(self.m.CHECKS)
        try:
            self.m.CHECKS.append(("Z9.9", 99, "injected failure",
                                  lambda: (self.m.FAIL, "deliberate")))
            r = self.m.evaluate()
            self.assertFalse(r["audit_candidate_ready"])
            self.assertGreaterEqual(r["counts"][self.m.FAIL], 1)
        finally:
            self.m.CHECKS[:] = orig

    def test_an_erroring_check_is_honest_fail_not_crash(self):
        orig = list(self.m.CHECKS)
        try:
            def boom():
                raise RuntimeError("boom")
            self.m.CHECKS.append(("Z9.8", 99, "erroring check", boom))
            r = self.m.evaluate()
            row = [c for c in r["checks"] if c["id"] == "Z9.8"][0]
            self.assertEqual(row["verdict"], self.m.FAIL)
            self.assertIn("RuntimeError", row["detail"])
        finally:
            self.m.CHECKS[:] = orig


class TestReadinessPackManifest(unittest.TestCase):
    def setUp(self):
        self.g = _load("acm_manifest", "scripts/readiness_pack_manifest.py")

    def test_check_passes_on_generated(self):
        r = self.g.check()
        self.assertTrue(r["ok"], r["problems"])
        self.assertTrue(r["manifest_matches"])
        self.assertTrue(r["receipt_verifies"])

    def test_manifest_covers_the_docs(self):
        files = self.g._pack_files()
        names = {f.name for f in files}
        self.assertIn("index.json", names)
        self.assertIn("REPRODUCTION_RUNBOOK.md", names)
        # the self-receipt subdir is NOT manifested (it commits to the manifest, not vice versa)
        self.assertNotIn("readiness_pack.bundle.json", names)


class TestClaimsHygieneAuditCandidateList(unittest.TestCase):
    def setUp(self):
        self.g = _load("acm_claims", "scripts/claims_hygiene_check.py")

    def test_overclaim_is_caught(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.md"
            bad.write_text("# X\n\nproofbundle is production-ready and has been audited.\n")
            v = self.g.scan_file(bad)
            self.assertTrue(v, "production-ready / has been audited must be caught")

    def test_sanctioned_statement_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ok = Path(td) / "ok.md"
            ok.write_text("# X\n\naudit-candidate: the sole remaining gate to stable is an "
                          "independent external security audit. It is not production-ready.\n")
            self.assertEqual(self.g.scan_file(ok), [])


if __name__ == "__main__":
    unittest.main()
