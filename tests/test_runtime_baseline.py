"""The runtime baseline's recorded runs are what the harness measured, and the README shows them as recorded.

benchmarks/runtime_baseline/results/<run>/ holds raw.json (every sample, in nanoseconds) and summary.json.
These cases hold each summary to its raw samples through nearest-rank percentiles computed here, on their
own, not through the harness; each run to one commit, a clean tree and the script committed at that
commit; the README's tables to the renderer's output; and the text to its rule that nothing is compared
with a target. A number in the README that was typed by hand, or a summary that no longer follows from
its samples, fails here.
"""
from __future__ import annotations

import importlib.util
import json
import math
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_RESULTS = REPO / "benchmarks/runtime_baseline/results"
_README = REPO / "benchmarks/runtime_baseline/README.md"
_RENDER = REPO / "benchmarks/runtime_baseline/render.py"
_RUN = REPO / "benchmarks/runtime_baseline/run.py"


def _runs() -> list:
    return [(d.name, json.loads((d / "summary.json").read_text(encoding="utf-8")),
             json.loads((d / "raw.json").read_text(encoding="utf-8")))
            for d in sorted(_RESULTS.iterdir()) if (d / "summary.json").is_file()]


def _nearest_rank(werte: list, p: float) -> int:
    """The ceil(p/100 * N)-th smallest value, written here independently of the harness."""
    geordnet = sorted(werte)
    return geordnet[math.ceil(p / 100 * len(geordnet)) - 1]


def _expected(werte: list) -> dict:
    return {"n": len(werte), "p50": _nearest_rank(werte, 50), "p95": _nearest_rank(werte, 95),
            "p99": _nearest_rank(werte, 99), "max": max(werte), "min": min(werte)}


def _render_module():
    spec = importlib.util.spec_from_file_location("_runtime_baseline_render", _RENDER)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


class TheRecordedRuns(unittest.TestCase):
    def setUp(self) -> None:
        self.laeufe = _runs()

    def test_three_runs_at_one_commit_each_on_a_clean_tree(self) -> None:
        self.assertEqual(len(self.laeufe), 3)
        commits = {s["environment"]["package"]["commit"] for _, s, _ in self.laeufe}
        self.assertEqual(len(commits), 1, commits)
        self.assertRegex(commits.pop(), r"^[0-9a-f]{40}$")
        for name, s, r in self.laeufe:
            with self.subTest(run=name):
                self.assertIs(s["environment"]["package"]["tree_clean_for_src_benchmarks_tools"], True)
                self.assertEqual((s["format"], r["format"]), ("runtime-baseline/1", "runtime-baseline/1"))
                self.assertEqual(s["settings"], self.laeufe[0][1]["settings"])
                self.assertEqual((s["settings"], s["environment"]), (r["settings"], r["environment"]))

    def test_every_summary_is_nearest_rank_over_its_own_samples(self) -> None:
        for name, s, r in self.laeufe:
            anzahl = s["settings"]["samples"]
            for stufe, werte in r["raw_ns"].items():
                if not isinstance(werte, list):
                    continue
                with self.subTest(run=name, stage=stufe):
                    self.assertEqual(len(werte), anzahl)
                    self.assertEqual(s["summary"][stufe], _expected(werte))
            for n, eintrag in r["raw_ns"]["emit_growing_history"].items():
                zus = s["summary"]["emit_growing_history"][n]
                for teil in ("emit", "merkle_part", "sign_part"):
                    with self.subTest(run=name, n=n, part=teil):
                        self.assertEqual(len(eintrag[teil]), anzahl)
                        self.assertEqual(zus[teil], _expected(eintrag[teil]))
                self.assertEqual(zus["hash_calls_per_emit"], eintrag["hash_calls_per_emit"])

    def test_an_emit_makes_four_hash_calls_per_prior_leaf_at_every_size_measured(self) -> None:
        """The README's reading of the counts: 1 call with no history, 4n for n prior leaves."""
        for name, s, _ in self.laeufe:
            for n, zus in s["summary"]["emit_growing_history"].items():
                with self.subTest(run=name, n=n):
                    self.assertEqual(zus["hash_calls_per_emit"]["total"], 4 * int(n) if int(n) else 1)

    def test_the_script_that_measured_is_the_script_committed(self) -> None:
        if shutil.which("git") is None or not (REPO / ".git").exists():
            self.skipTest("NOT MEASURABLE: no git checkout, so the measured commit cannot be read")
        kopf = self.laeufe[0][1]["environment"]["package"]["commit"]
        vorfahr = subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor", kopf, "HEAD"])
        if vorfahr.returncode not in (0, 1):
            self.skipTest(f"NOT MEASURABLE: the measured commit {kopf} is not in this clone's history")
        self.assertEqual(vorfahr.returncode, 0, f"{kopf} is not an ancestor of HEAD")
        damals = subprocess.run(["git", "-C", str(REPO), "show", f"{kopf}:benchmarks/runtime_baseline/run.py"],
                                capture_output=True, check=True).stdout
        self.assertEqual(damals, _RUN.read_bytes())


class TheReadme(unittest.TestCase):
    def test_its_tables_are_rendered_from_the_runs(self) -> None:
        render = _render_module()
        text = _README.read_text(encoding="utf-8")
        self.assertEqual(render.render(text, render.runs()), text)

    def test_it_compares_nothing_with_a_target(self) -> None:
        self.assertIn("Nothing here is compared with a target", _README.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
