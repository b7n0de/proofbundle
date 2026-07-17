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


class TestCheckDiscrimination(unittest.TestCase):
    """Per-check red/green discrimination (FIX 3): each check must FAIL when its own obligation is
    genuinely broken/absent, not only pass in aggregate. Modelled on
    TestTestManifestGate.test_shrink_below_floor_is_caught."""

    def setUp(self):
        self.m = _load("acm_matrix_disc", "scripts/audit_candidate_matrix.py")

    # --- C1.1 'two named CI gates' — falsifiable when the second (repository/test) gate is gone ---

    def test_c1_1_green_on_real_repo(self):
        verdict, _ = self.m.c1_1_two_ci_gates()
        self.assertEqual(verdict, self.m.PASS)

    def test_c1_1_fails_when_second_gate_missing(self):
        # published-artifact-gate present, but ci.yml (the repository/test gate) deleted -> FAIL.
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "published-artifact-gate.yml").write_text(
                "jobs:\n  x:\n    steps:\n      - run: build sdist cleanroom\n")
            verdict, detail = self.m.c1_1_two_ci_gates(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)
            self.assertIn("ci.yml", detail)

    def test_c1_1_fails_when_second_gate_is_not_a_test_gate(self):
        # ci.yml exists but carries neither `name: CI` nor a pytest/test step -> FAIL (not a real gate).
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "published-artifact-gate.yml").write_text(
                "jobs:\n  x:\n    steps:\n      - run: build sdist cleanroom\n")
            (wf / "ci.yml").write_text("name: nope\njobs:\n  x:\n    steps:\n      - run: echo hi\n")
            verdict, detail = self.m.c1_1_two_ci_gates(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

    # --- C12.2 '0 open P0/P1' — falsifiable: a fabricated/unbound note must not satisfy it ---

    def test_c12_2_green_on_real_repo(self):
        verdict, _ = self.m.c12_2_audit_pack_zero_p0p1()
        self.assertEqual(verdict, self.m.PASS)

    def test_c12_2_rejects_fabricated_unbound_note(self):
        # the OLD broad-glob regex passed on ANY *.md; an unrelated md carrying '3.6.0' + '0 P0/P1'
        # but NO lens/adversarial marker (not a version-scoped audit record) must now go PENDING.
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "worklog.md").write_text("# notes\n\nWorked on 3.6.0. 0 open P0/P1 issues.\n")
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertNotEqual(verdict, self.m.PASS, detail)
            self.assertEqual(verdict, self.m.PENDING, detail)

    def test_c12_2_pending_when_record_absent(self):
        with tempfile.TemporaryDirectory() as td:
            verdict, _ = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.PENDING)

    def test_c12_2_pending_when_record_lacks_zero_p0p1_line(self):
        # a genuine version-scoped adversarial record, but WITHOUT the '0 open P0/P1' obligation line.
        with tempfile.TemporaryDirectory() as td:
            rec = Path(td) / "audit_artifacts" / "360"
            rec.mkdir(parents=True)
            (rec / "pre_tag_adversarial_audit_360.md").write_text(
                "# 3.6.0 six-lens adversarial audit\n\nOne P1 still open.\n")
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.PENDING, detail)

    # --- 6-lens reverify: the four named adversarial variants, each must catch the fake (live) ---

    def test_variant1_marker_note_outside_subfolder_satisfies_neither_gate(self):
        # Variant 1: a fake note carrying BOTH an audit marker AND '0 open P0/P1', placed OUTSIDE the
        # version-scoped audit_artifacts/360/ subfolder and sorting before it in a whole-tree glob,
        # must NOT satisfy C12.1 or C12.2 when no genuine 360-record exists (subfolder anchor excludes
        # it; sort order across the tree can no longer let a foreign file win).
        import pre_tag_audit_gate as pta
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "000_marker_fake.md").write_text(  # '000_' sorts before '360/' in an rglob
                "# six-lens adversarial notes touching 3.6.0\n\n**0 open P0 / P1.**\n")
            # C12.1: the existence locator finds no version-scoped record, evaluate() is not ok
            self.assertIsNone(pta.audit_artifact_for(Path(td), "3.6.0"))
            self.assertFalse(pta.evaluate(Path(td), version="3.6.0")["ok"])
            # C12.2: not PASS (PENDING — no version-scoped record)
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.PENDING, detail)

    def test_variant2_decoy_in_subfolder_does_not_mask_real_record(self):
        # Variant 2: two records IN the version-scoped subfolder — a decoy that matches the locator
        # (audit marker) but omits the '0 open P0/P1' line and sorts FIRST, plus the genuine record
        # carrying the line. C12.2 must scan past the decoy and PASS on the real record (no silent
        # PENDING while a real 0-P0/P1 record exists).
        with tempfile.TemporaryDirectory() as td:
            rec = Path(td) / "audit_artifacts" / "360"
            rec.mkdir(parents=True)
            (rec / "aaa_decoy.md").write_text(  # 'aaa' sorts before 'pre_tag'
                "# 3.6.0 six-lens adversarial scratch\n\nStill triaging; P1 count TBD.\n")
            (rec / "pre_tag_adversarial_audit_360.md").write_text(
                "# 3.6.0 six-lens adversarial audit\n\n**0 open P0 / P1.** All findings fixed.\n")
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.PASS, detail)
            self.assertIn("pre_tag_adversarial_audit_360.md", detail)

    def test_variant3_pytest_only_in_comment_echo_or_disabled_job_fails_c1_1(self):
        # Variant 3: ci.yml names CI but 'pytest' appears ONLY in a YAML comment, an echo argument, a
        # shell #TODO, and an if:false (disabled) job — no run: step actually executes it -> FAIL.
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "published-artifact-gate.yml").write_text(
                "jobs:\n  x:\n    steps:\n      - run: build sdist cleanroom\n")
            (wf / "ci.yml").write_text(
                "# this workflow will run pytest one day\n"
                "name: CI\n"
                "on: [push]\n"
                "jobs:\n"
                "  disabled-real-tests:\n"
                "    if: false\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: python -m pytest tests/ -q\n"
                "  notes:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo \"we should add pytest here\"\n"
                "      - run: |\n"
                "          # TODO: run pytest in the future\n"
                "          echo done\n")
            verdict, detail = self.m.c1_1_two_ci_gates(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

    def test_variant3b_real_executing_run_step_passes_c1_1(self):
        # counterpart to variant 3: a genuine executing run: step (python -m unittest discover) PASSes,
        # so the FAIL above discriminates on real execution, it is not a blanket reject.
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "published-artifact-gate.yml").write_text(
                "jobs:\n  x:\n    steps:\n      - run: build sdist cleanroom\n")
            (wf / "ci.yml").write_text(
                "name: CI\non: [push]\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: python -m unittest discover -s tests -v\n")
            verdict, detail = self.m.c1_1_two_ci_gates(repo=Path(td))
            self.assertEqual(verdict, self.m.PASS, detail)

    def test_variant4_version_token_1360_not_selected_as_360(self):
        # Variant 4: '360' must not match '1360'. Neither a sibling audit_artifacts/1360/ record nor a
        # top-level review_1360_notes.md whose name embeds the digits may be selected as the 3.6.0
        # record — the anchor is the exact directory '360', never a raw substring.
        import pre_tag_audit_gate as pta
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            sib = art / "1360"
            sib.mkdir(parents=True)
            (sib / "pre_tag_adversarial_audit_1360.md").write_text(
                "# 13.6.0 six-lens adversarial audit\n\n**0 open P0 / P1.**\n")
            (art / "review_1360_notes.md").write_text(
                "# review 1360 notes — adversarial\n\n0 open P0 / P1 for 3.6.0.\n")
            self.assertEqual(pta.audit_records_for(Path(td), "3.6.0"), [])
            self.assertIsNone(pta.audit_artifact_for(Path(td), "3.6.0"))
            verdict, _ = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.PENDING)


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
