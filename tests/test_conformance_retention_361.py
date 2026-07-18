"""3.6.1 — the conformance corpus MUST retain the subject-pin negative-state vectors (Berkeley residual c).

The Berkeley-Gate v2 verdict (WITHSTANDS_BERKELEY) named one out-of-threat-model residual: the Python==Rust
differential safety net for PB-2026-0717-01 depends on the conformance corpus KEEPING the missing / ambiguous
/ mismatch target-subject vectors — silently pruning them would thin the guard without any test failing. This
guard closes that hole: a future edit that drops (or renames away) any of the load-bearing subject-pin
negative-state vectors fails here, so the differential net cannot be quietly weakened.
"""
import json
import pathlib
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_MANIFEST = _REPO / "conformance" / "manifest.json"

# The load-bearing subject-pin vectors: the differential Rust==Python net + the SPEC oracle both rely on
# these being present. present-equal (pass) + present-mismatch + absent + ambiguous cover the states.
_REQUIRED_SUBJECT_PIN_CASES = (
    "relation/target-subject-correct-pass",   # present-equal -> VERIFIED (the accept anchor)
    "relation/target-subject-mismatch",       # present-but-wrong -> FAIL (pre-3.6.1)
    "relation/target-subject-missing",        # absent -> FAIL (PB-2026-0717-01 / -05)
    "relation/target-subject-ambiguous",      # >1 subject -> FAIL (PB-2026-0717-01 / -05)
)


class ConformanceRetention(unittest.TestCase):
    def setUp(self):
        self.cases = set(json.loads(_MANIFEST.read_text(encoding="utf-8")).get("cases", []))

    def test_manifest_retains_subject_pin_negative_state_vectors(self):
        for case in _REQUIRED_SUBJECT_PIN_CASES:
            self.assertIn(
                case, self.cases,
                f"conformance/manifest.json must retain {case!r} — it is load-bearing for the "
                "PB-2026-0717-01 subject-pin guard (SPEC oracle + Python==Rust differential). Pruning it "
                "silently thins the fail-closed net (Berkeley-Gate residual c).")

    def test_each_required_case_directory_exists_and_is_self_contained(self):
        # a manifest entry with no on-disk vector is a dead reference — the differential would skip it.
        for case in _REQUIRED_SUBJECT_PIN_CASES:
            d = _REPO / "conformance" / case
            self.assertTrue((d / "case.json").is_file(), f"{case}/case.json missing")
            self.assertTrue((d / "receipt.json").is_file(), f"{case}/receipt.json missing")

    def test_missing_and_ambiguous_expect_fail_closed(self):
        # the two 3.6.1 additions must keep their fail-closed expectation (exit 2 / FAIL) — an edit that
        # flipped them to accept would be exactly the regression the guard exists to catch.
        for case in ("relation/target-subject-missing", "relation/target-subject-ambiguous"):
            cj = json.loads((_REPO / "conformance" / case / "case.json").read_text(encoding="utf-8"))
            exp = cj.get("expected", {})
            self.assertEqual(exp.get("exitCode"), 2, f"{case} must expect exit 2 (fail-closed)")
            self.assertEqual(exp.get("lineage"), "FAIL", f"{case} must expect lineage FAIL")


if __name__ == "__main__":
    unittest.main()
