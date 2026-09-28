"""The accumulator's before-and-after runs are what the harness measured, and the README shows them as recorded.

docs/merkle_accumulator/runs/<run>/ holds what benchmarks/runtime_baseline/run.py wrote with
tools/merkle_accumulator/accumulator.py present: every sample (raw.json) and its percentiles
(summary.json), for emit_bundle over a growing history and for the accumulator at the same sizes. These
cases hold each summary to its samples through nearest-rank percentiles computed here, the runs to one
commit and a clean tree, the counted hash calls of an append to the bound the accumulator states, and the
README's tables to the renderer's output.
"""
from __future__ import annotations

import importlib.util
import json
import math
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_RUNS = REPO / "docs/merkle_accumulator/runs"
_README = REPO / "docs/merkle_accumulator/README.md"
_RENDER = REPO / "tools/merkle_accumulator/render_runs.py"


def _runs() -> list:
    return [(d.name, json.loads((d / "summary.json").read_text(encoding="utf-8")),
             json.loads((d / "raw.json").read_text(encoding="utf-8")))
            for d in sorted(_RUNS.iterdir()) if (d / "summary.json").is_file()]


def _nearest_rank(werte: list, p: float) -> int:
    """The ceil(p/100 * N)-th smallest value, written here independently of the harness."""
    geordnet = sorted(werte)
    return geordnet[math.ceil(p / 100 * len(geordnet)) - 1]


def _expected(werte: list) -> dict:
    return {"n": len(werte), "p50": _nearest_rank(werte, 50), "p95": _nearest_rank(werte, 95),
            "p99": _nearest_rank(werte, 99), "max": max(werte), "min": min(werte)}


class TheRecordedRuns(unittest.TestCase):
    def setUp(self) -> None:
        self.laeufe = _runs()

    def test_three_runs_at_one_commit_each_on_a_clean_tree_with_the_accumulator(self) -> None:
        self.assertEqual(len(self.laeufe), 3)
        commits = {s["environment"]["package"]["commit"] for _, s, _ in self.laeufe}
        self.assertEqual(len(commits), 1, commits)
        for name, s, r in self.laeufe:
            with self.subTest(run=name):
                self.assertIs(s["environment"]["package"]["tree_clean_for_src_benchmarks_tools"], True)
                self.assertEqual((s["settings"], s["environment"]), (r["settings"], r["environment"]))
                self.assertEqual(set(r["raw_ns"]["accumulator_growing_history"]),
                                 set(r["raw_ns"]["emit_growing_history"]))

    def test_every_summary_is_nearest_rank_over_its_own_samples(self) -> None:
        for name, s, r in self.laeufe:
            anzahl = s["settings"]["samples"]
            for fall, teile, zaehl in (("emit_growing_history", ("emit", "merkle_part", "sign_part"),
                                        "hash_calls_per_emit"),
                                       ("accumulator_growing_history", ("append", "emit_through_accumulator",
                                                                        "copy_only"), "hash_calls_per_append")):
                for n, eintrag in r["raw_ns"][fall].items():
                    zus = s["summary"][fall][n]
                    for teil in teile:
                        with self.subTest(run=name, case=fall, n=n, part=teil):
                            self.assertEqual(len(eintrag[teil]), anzahl)
                            self.assertEqual(zus[teil], _expected(eintrag[teil]))
                    self.assertEqual(zus[zaehl], eintrag[zaehl])

    def test_an_append_stays_within_the_bound_the_accumulator_states(self) -> None:
        """At most 1 + 2 * floor(log2(size)) + 1 hash calls for the tree size after the append, whatever
        the history; emit_bundle makes 4n with n prior leaves."""
        for name, s, _ in self.laeufe:
            for n, zus in s["summary"]["accumulator_growing_history"].items():
                groesse = int(n) + 1
                with self.subTest(run=name, n=n):
                    self.assertLessEqual(zus["hash_calls_per_append"]["total"],
                                         2 + 2 * (groesse.bit_length() - 1))
                    self.assertEqual(s["summary"]["emit_growing_history"][n]["hash_calls_per_emit"]["total"],
                                     4 * int(n) if int(n) else 1)


class TheReadme(unittest.TestCase):
    def test_its_tables_are_rendered_from_the_runs(self) -> None:
        spec = importlib.util.spec_from_file_location("_accumulator_render_runs", _RENDER)
        render = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(render)
        text = _README.read_text(encoding="utf-8")
        self.assertEqual(render.render(text, render.runs()), text)


if __name__ == "__main__":
    unittest.main()
