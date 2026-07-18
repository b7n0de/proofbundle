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

    # --- C12.2 '0 open P0/P1' — RT-10 / PB-2026-0718-14: the SIGNED structured findings register, NOT a
    # substring scan. The old lexical '0 open P0/P1' md-scan granted a FALSE PASS from a stale record; it is
    # replaced by a fail-closed signed register (absent/tampered/foreign-key/empty -> FAIL, never PENDING). ---

    def test_c12_2_green_on_real_repo(self):
        verdict, _ = self.m.c12_2_audit_pack_zero_p0p1()
        self.assertEqual(verdict, self.m.PASS)

    def test_c12_2_fails_when_register_absent(self):
        # RT-10: absence of the register is FAIL, not PASS and not PENDING (assertion-by-absence guard).
        # A fabricated '0 open P0/P1' note in a bare .md no longer grants anything — only the register counts.
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "worklog.md").write_text("# notes\n\nWorked on 3.6.1. 0 open P0/P1 issues.\n")
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

    def test_c12_2_fails_on_tampered_register(self):
        # a copy of the real register with a P0 flipped to 'open' breaks the pinned-key signature -> FAIL
        # (the same guard rejects an injected-open-finding, an emptied findings list, or any byte change).
        import json
        real = Path(REPO) / "audit_artifacts" / "findings_register_361.json"
        reg = json.loads(real.read_text(encoding="utf-8"))
        reg["findings"][0]["status"] = "open"  # tamper: does not re-sign
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "findings_register_361.json").write_text(json.dumps(reg))
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

    def test_c12_2_fails_on_foreign_key_register(self):
        # a register validly signed by a DIFFERENT key must be rejected by the committed pin -> FAIL.
        import base64
        import json
        import sys as _sys
        _sys.path.insert(0, str(Path(REPO) / "src"))
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from proofbundle import canonical
        real = Path(REPO) / "audit_artifacts" / "findings_register_361.json"
        body = {k: v for k, v in json.loads(real.read_text(encoding="utf-8")).items() if k != "signature"}
        k = Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                          format=serialization.PublicFormat.Raw)
        forged = dict(body)
        forged["signature"] = {"alg": "ed25519",
                               "public_key_b64": base64.b64encode(pub).decode(),
                               "sig_b64": base64.b64encode(k.sign(canonical.canonicalize_statement(body))).decode()}
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "findings_register_361.json").write_text(json.dumps(forged))
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

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
            # C12.2 (RT-10): no signed register in the temp repo -> FAIL (a fake note grants nothing)
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

    def test_variant2_decoy_md_does_not_grant_pass_only_register_does(self):
        # RT-10 (was: substring scan-past-decoy): the register is the SINGLE source. Even a genuine-looking
        # version-scoped .md carrying '0 open P0/P1' grants NOTHING now — with no signed register present,
        # C12.2 is FAIL. This is the anti-gaming improvement: a stale/forged .md can no longer mask reality.
        with tempfile.TemporaryDirectory() as td:
            rec = Path(td) / "audit_artifacts" / "360"
            rec.mkdir(parents=True)
            (rec / "pre_tag_adversarial_audit_360.md").write_text(
                "# 3.6.0 six-lens adversarial audit\n\n**0 open P0 / P1.** All findings fixed.\n")
            verdict, detail = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL, detail)

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

    # --- FIX 1: C1.1 test-runner recognition verges on the EXECUTED head, not a bare mention ---

    def _c1_1_with_test_step(self, run_line: str):
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "published-artifact-gate.yml").write_text(
                "jobs:\n  x:\n    steps:\n      - run: build sdist cleanroom\n")
            (wf / "ci.yml").write_text(
                "name: CI\non: [push]\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
                f"      - run: {run_line}\n")
            return self.m.c1_1_two_ci_gates(repo=Path(td))

    def test_c1_1_which_pytest_is_not_a_test_run(self):
        # a bare mention that never executes the suite -> FAIL (single step `run: which pytest`).
        verdict, detail = self._c1_1_with_test_step("which pytest")
        self.assertEqual(verdict, self.m.FAIL, detail)

    def test_c1_1_collect_only_is_not_a_test_run(self):
        # collect-only imports the tests but runs none -> FAIL.
        verdict, detail = self._c1_1_with_test_step("pytest --collect-only")
        self.assertEqual(verdict, self.m.FAIL, detail)

    def test_c1_1_real_unittest_discover_passes(self):
        # a genuine executing run -> PASS (discriminates the FAILs above from a blanket reject).
        verdict, detail = self._c1_1_with_test_step("python -m unittest discover -s tests")
        self.assertEqual(verdict, self.m.PASS, detail)

    def test_ci_run_is_test_rejects_inspection_commands(self):
        # unit-level: commands that only NAME pytest (head is which/command/pip/grep/find/ls) are not runs
        for line in ("which pytest", "command -v pytest", "pip show pytest", "grep -r pytest src",
                     "find . -iname pytest.ini", "ls pytest", "pytest --collect-only",
                     "pytest --co", "python -m pytest --collect-only"):
            self.assertFalse(self.m._ci_run_is_test(line), line)
        for line in ("pytest", "pytest tests/ -q", "py.test", "python -m pytest -q",
                     "python3 -m pytest", "python -m unittest discover -s tests",
                     "PYTHONPATH=src pytest -q", "echo start && pytest tests/"):
            self.assertTrue(self.m._ci_run_is_test(line), line)

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
            # C12.2 (RT-10): no signed register in the temp repo -> FAIL (the 1360 decoys grant nothing)
            verdict, _ = self.m.c12_2_audit_pack_zero_p0p1(repo=Path(td))
            self.assertEqual(verdict, self.m.FAIL)


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
