"""Nachtrag 51 (`KRAXO-CLOUD-N51-STRIKTER-JSON-LESER-IN-ADAPTERN-01`, Z309 / 6.2.0).

Codex class search K6 (ambiguous inputs / duplicate JSON keys), reproduced by Cowork at the base
`e37e872bbe03e349ae14f6dc70eff0f4572ce6fb`. Defect class: a PRODUCER-side reader parses an untrusted
results file with lax ``json.loads`` (last-wins on a duplicated key) before a signable/positive statement,
so a duplicated key makes the signed ``passed`` / verifier-block assurance reflect the LAST value while
another JSON reader (first-wins or reject) would disagree — the signature afterwards no longer discovers the
parser differential.

Fix (pure narrowing): each such site reads through ``_strict_json.loads_reject_duplicate_keys`` — duplicate
object keys are rejected fail-closed at any depth, with NO new size/structure cap (a dup-free file of ANY
size parses exactly as ``json.loads`` did before; the verify-path DoS budget is deliberately NOT imposed on
these producer reads, so no legitimate large eval file is false-closed).

In each injected probe the LAST value equals the original, so the ONLY reason the call changes is the
duplicated key itself (not a changed value). RED at the base (the dup key is accepted, last-wins), GREEN
after. Controls parse the unmodified repository fixtures and must keep working.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.adapters import (  # noqa: E402
    from_eee_dataset, from_lm_eval_results, from_promptfoo_results,
    samples_from_lm_eval_jsonl, samples_from_promptfoo_results,
)
from proofbundle.verifier_block import measure_vector_set  # noqa: E402

FX = REPO / "tests" / "fixtures"
TS = "2026-07-01T12:00:00Z"
SALTS = {"model_salt": b"0" * 16, "dataset_salt": b"1" * 16}


def _write(tmp: str, name: str, text: str) -> str:
    p = os.path.join(tmp, name)
    Path(p).write_text(text, encoding="utf-8")
    return p


def _inject_once(path: Path, target: str, dup: str) -> str:
    """Return the fixture text with the first ``target`` replaced by ``dup`` + ``target`` (a duplicate
    key whose LAST occurrence keeps the original value)."""
    text = path.read_text(encoding="utf-8")
    assert text.count(target) == 1, f"anchor {target!r} not unique in {path.name}"
    return text.replace(target, dup + target, 1)


class K6DuplicateJsonKeyIsRejectedBeforeASignableStatement(unittest.TestCase):

    def _assert_duplicate_rejected(self, fn):
        with self.assertRaises(Exception) as cm:  # noqa: PT011 - message asserted below
            fn()
        self.assertIn("duplicate", str(cm.exception).lower(),
                      f"expected a duplicate-key fail-closed error, got: {cm.exception!r}")

    # ---- K6-01: verifier-block conformance manifest -------------------------------------------------
    def _conformance_root(self, tmp: str, manifest_text: str) -> str:
        root = os.path.join(tmp, "corpus")
        case = os.path.join(root, "valid-minimal")
        os.makedirs(case, exist_ok=True)
        Path(os.path.join(case, "case.json")).write_text('{"a": 1}', encoding="utf-8")
        Path(os.path.join(root, "manifest.json")).write_text(manifest_text, encoding="utf-8")
        return root

    def test_k6_01_manifest_duplicate_cases_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._conformance_root(
                tmp, '{"schema":"x","cases":["valid-minimal"],"cases":["valid-minimal"]}')
            self._assert_duplicate_rejected(lambda: measure_vector_set(root))

    def test_k6_01_control_single_cases_key_is_measured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._conformance_root(tmp, '{"schema":"x","cases":["valid-minimal"]}')
            res = measure_vector_set(root)
            self.assertEqual(res["cases"], 1)

    # ---- K6-02: EEE score ---------------------------------------------------------------------------
    def test_k6_02_eee_duplicate_score_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            amb = _inject_once(FX / "eee_arc_easy.json", '"score": 0.5567', '"score": 0, ')
            p = _write(tmp, "eee_amb.json", amb)
            self._assert_duplicate_rejected(
                lambda: from_eee_dataset(p, comparator=">=", threshold="0.30", **SALTS))

    def test_k6_02_control_unmodified_eee_builds_a_claim(self):
        claim, _ = from_eee_dataset(FX / "eee_arc_easy.json", comparator=">=", threshold="0.30", **SALTS)
        self.assertEqual(claim["metric"], "acc")

    # ---- K6-03: promptfoo successes -----------------------------------------------------------------
    def test_k6_03_promptfoo_duplicate_successes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            amb = _inject_once(FX / "promptfoo_results_v3.json",
                               '"successes": 2', '"successes": 0, ')
            p = _write(tmp, "promptfoo_amb.json", amb)
            self._assert_duplicate_rejected(
                lambda: from_promptfoo_results(p, comparator=">=", threshold="0.60", timestamp=TS, **SALTS))

    def test_k6_03_control_unmodified_promptfoo_builds_a_claim(self):
        claim, _ = from_promptfoo_results(FX / "promptfoo_results_v3.json",
                                          comparator=">=", threshold="0.60", timestamp=TS, **SALTS)
        self.assertEqual(claim["metric"], "pass_rate")

    # ---- K6-04: lm-eval metric ----------------------------------------------------------------------
    def test_k6_04_lm_eval_duplicate_metric_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            amb = _inject_once(FX / "lm_eval_arc_easy_real.json",
                               '"acc,none": 0.5', '"acc,none": 0, ')
            p = _write(tmp, "lm_eval_amb.json", amb)
            self._assert_duplicate_rejected(
                lambda: from_lm_eval_results(p, "arc_easy", "acc",
                                             comparator=">=", threshold="0.30", timestamp=TS, **SALTS))

    def test_k6_04_control_unmodified_lm_eval_builds_a_claim(self):
        claim, _ = from_lm_eval_results(FX / "lm_eval_arc_easy_real.json", "arc_easy", "acc",
                                        comparator=">=", threshold="0.30", timestamp=TS, **SALTS)
        self.assertEqual(claim["suite"], "arc_easy")

    # ---- siblings: per-sample leaves ----------------------------------------------------------------
    def test_sibling_lm_eval_jsonl_duplicate_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            line = '{"doc_id":0,"filter":"none","metrics":["acc"],"acc":false,"acc":true}'
            p = _write(tmp, "s.jsonl", line + "\n")
            self._assert_duplicate_rejected(lambda: samples_from_lm_eval_jsonl(p))

    def test_sibling_lm_eval_jsonl_control_single_key_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            line = '{"doc_id":0,"filter":"none","metrics":["acc"],"acc":true}'
            p = _write(tmp, "s.jsonl", line + "\n")
            records = samples_from_lm_eval_jsonl(p)
            self.assertEqual(records[0]["metrics"], {"acc": "True"})

    def test_sibling_promptfoo_samples_duplicate_success_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            amb = ('{"results":{"version":3,"results":['
                   '{"testIdx":0,"promptIdx":0,"provider":{"id":"p"},'
                   '"success":false,"success":true,"score":1}]}}')
            p = _write(tmp, "pf_amb.json", amb)
            self._assert_duplicate_rejected(lambda: samples_from_promptfoo_results(p))

    def test_sibling_promptfoo_samples_control_parses(self):
        records = samples_from_promptfoo_results(FX / "promptfoo_results_v3.json")
        self.assertEqual([r["id"] for r in records], [0, 1, 2])

    # ---- budget: a large dup-free fixture is NOT false-closed ---------------------------------------
    def test_large_dupfree_fixture_still_parses_through_the_strict_reader(self):
        # The strict reader for these producer paths must impose NO new size/structure cap: the largest
        # repository JSON fixture (well under any default verify budget, but far larger than the adapter
        # fixtures) parses without error, so a legitimate large eval file keeps behaving as today.
        from proofbundle._strict_json import loads_reject_duplicate_keys  # noqa: PLC0415
        big = FX / "mldsa_acvp" / "mldsa_sigver_slice.json"
        text = big.read_text(encoding="utf-8")
        self.assertGreater(len(text), 40_000)
        self.assertEqual(loads_reject_duplicate_keys(text), json.loads(text))


if __name__ == "__main__":
    unittest.main()
