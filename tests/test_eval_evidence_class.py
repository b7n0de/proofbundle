"""P0-B (Hardening 3.0.1 §7) — score-vs-threshold evidence classes.

A receipt today signs a THRESHOLD VERDICT (`passed` against the signed `comparator`/`threshold`), never
an exact score (the score is discarded at emit). These tests pin that the classifier declares the honest
class and that show-eval never implies an exact score. The exact-score / commitment / withheld classes
are forward-compatible (the optional additive exact-score profile §7.2) and are tested on the classifier
directly, since the frozen v0.1 schema does not yet carry those fields."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from proofbundle.evalclaim import (
    EXACT_SCORE_VERIFIED, METHODOLOGY_NOT_EVALUATED, SCORE_COMMITMENT_PRESENT, SCORE_WITHHELD,
    THRESHOLD_VERDICT_VERIFIED, eval_evidence_class,
)

REPO = Path(__file__).resolve().parents[1]


def _run(*args):
    return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args],
                          capture_output=True, text=True, cwd=REPO,
                          env={"PYTHONPATH": str(REPO / "src")})


class TestEvidenceClassifier(unittest.TestCase):
    BASE = {"comparator": ">=", "threshold": "0.85", "passed": True}

    def test_threshold_only_is_the_default_class(self):
        ev = eval_evidence_class(dict(self.BASE))
        self.assertEqual(ev["score_evidence"], THRESHOLD_VERDICT_VERIFIED)
        self.assertEqual(ev["methodology"], METHODOLOGY_NOT_EVALUATED)
        self.assertIn("not an exact score", ev["detail"].lower())

    def test_methodology_is_always_not_evaluated(self):
        for claim in (dict(self.BASE), {**self.BASE, "score": "0.90"},
                      {**self.BASE, "score_withheld": True}):
            self.assertEqual(eval_evidence_class(claim)["methodology"], METHODOLOGY_NOT_EVALUATED)

    def test_exact_score_consistent_is_exact(self):
        # score just above and exactly at the threshold, passed computed consistently
        self.assertEqual(eval_evidence_class({**self.BASE, "score": "0.90"})["score_evidence"],
                         EXACT_SCORE_VERIFIED)
        self.assertEqual(eval_evidence_class({**self.BASE, "score": "0.85"})["score_evidence"],
                         EXACT_SCORE_VERIFIED)  # 0.85 >= 0.85 → passed True, consistent

    def test_score_just_under_threshold_with_passed_false_is_exact(self):
        ev = eval_evidence_class({"comparator": ">=", "threshold": "0.85", "passed": False, "score": "0.849"})
        self.assertEqual(ev["score_evidence"], EXACT_SCORE_VERIFIED)  # 0.849 >= 0.85 → False, consistent

    def test_score_contradicts_passed_degrades_never_false_exact(self):
        # passed=True but 0.10 >= 0.85 is False → NEVER claim EXACT; fall back to the threshold verdict.
        ev = eval_evidence_class({**self.BASE, "score": "0.10"})
        self.assertEqual(ev["score_evidence"], THRESHOLD_VERDICT_VERIFIED)

    def test_decimal_precision_boundaries(self):
        # §7.4 decimal-precision boundaries: trailing zeros, differing precision score vs threshold,
        # and long decimals compare by VALUE (Decimal), so a consistent exact score stays EXACT.
        for thr, score, passed in (("0.85", "0.850", True), ("0.850", "0.85", True),
                                    ("0.8500000000000000001", "0.85", False),
                                    ("0.85", "0.8500000000000000001", True)):
            ev = eval_evidence_class({"comparator": ">=", "threshold": thr, "score": score, "passed": passed})
            self.assertEqual(ev["score_evidence"], EXACT_SCORE_VERIFIED,
                             f"precision boundary {score} >= {thr} (passed={passed}) must stay EXACT")

    def test_malformed_score_decimal_degrades_to_threshold(self):
        for bad in ("inf", "1e2", "NaN", "0,85", "abc", "+5"):
            self.assertEqual(eval_evidence_class({**self.BASE, "score": bad})["score_evidence"],
                             THRESHOLD_VERDICT_VERIFIED, f"malformed score {bad!r} must not be EXACT")

    def test_comparator_variants(self):
        for comp, thr, score, passed in ((">", "0.5", "0.6", True), ("<", "0.5", "0.4", True),
                                         ("<=", "0.5", "0.5", True), (">=", "0.5", "0.4", False)):
            ev = eval_evidence_class({"comparator": comp, "threshold": thr, "score": score, "passed": passed})
            self.assertEqual(ev["score_evidence"], EXACT_SCORE_VERIFIED, f"{comp} {score} vs {thr}")

    def test_commitment_and_withheld_forward_classes(self):
        self.assertEqual(eval_evidence_class({**self.BASE, "score_commit": "sha256:x"})["score_evidence"],
                         SCORE_COMMITMENT_PRESENT)
        ev = eval_evidence_class({**self.BASE, "score_commit": "sha256:x"})
        self.assertIn("not a range proof", ev["detail"].lower())
        self.assertEqual(eval_evidence_class({**self.BASE, "score_withheld": True})["score_evidence"],
                         SCORE_WITHHELD)


class TestShowEvalDeclaresClass(unittest.TestCase):
    def test_show_eval_declares_threshold_verdict_never_exact_score(self):
        with tempfile.TemporaryDirectory() as d:
            claim = os.path.join(d, "claim.json")
            Path(claim).write_text(json.dumps({
                "schema": "proofbundle/eval-claim/v0.1", "suite": "s", "suite_version": "v1",
                "metric": "acc", "comparator": ">=", "threshold": "0.80", "passed": True, "n": 100,
                "model_id_commit": "sha256:x", "dataset_id_commit": "sha256:y",
                "commit_alg": "sha256-salted-v1", "issuer": "ed25519:z",
                "timestamp": "2026-07-01T12:00:00Z"}), encoding="utf-8")
            out = os.path.join(d, "receipt.json")
            key = os.path.join(d, "k.key")
            self.assertEqual(_run("emit-eval", "--claim", claim, "--out", out, "--new-key", key).returncode, 0)
            show = _run("show-eval", out)
            self.assertEqual(show.returncode, 0)
            self.assertIn("THRESHOLD_VERDICT_VERIFIED", show.stdout)
            self.assertIn("METHODOLOGY_NOT_EVALUATED", show.stdout)
            # the honesty guarantee: never imply an exact score was verified
            self.assertNotIn("EXACT_SCORE_VERIFIED", show.stdout)
            self.assertNotIn("verified score", show.stdout.lower())


if __name__ == "__main__":
    unittest.main()
