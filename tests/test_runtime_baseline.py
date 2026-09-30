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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
_RESULTS = REPO / "benchmarks/runtime_baseline/results"
_README = REPO / "benchmarks/runtime_baseline/README.md"
_RENDER = REPO / "benchmarks/runtime_baseline/render.py"
_RUN = REPO / "benchmarks/runtime_baseline/run.py"
_HISTORY = REPO / "scripts/b7_historie.py"


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


def _history_cut(repo: Path):
    """Why the history of `repo` is truncated, or None when it is complete.

    Measured where the repository measures it once, scripts/b7_historie.py: a graft that the history of
    HEAD ends on is a cut, an empty or unresolvable shallow marker is not.
    """
    spec = importlib.util.spec_from_file_location("_runtime_baseline_history", _HISTORY)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul.historie_abgeschnitten(repo)


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
        present = subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{kopf}^{{commit}}"], capture_output=True)
        if present.returncode != 0:
            # A complete history holds every ancestor of HEAD, so an absent commit lies outside it. Only a
            # history measured as truncated leaves the question open; a shallow marker alone does not.
            cut = _history_cut(REPO)
            if cut is not None:
                self.skipTest(f"NOT MEASURABLE: the measured commit {kopf} is not in this clone ({cut})")
            self.fail(f"the measured commit {kopf} is not in this clone, whose history is complete: the "
                      "recorded measurement names a commit outside the reviewed history")
        vorfahr = subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor", kopf, "HEAD"])
        self.assertEqual(vorfahr.returncode, 0, f"{kopf} is not an ancestor of HEAD")
        damals = subprocess.run(["git", "-C", str(REPO), "show", f"{kopf}:benchmarks/runtime_baseline/run.py"],
                                capture_output=True, check=True).stdout
        self.assertEqual(damals, _RUN.read_bytes())


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


class TheMeasuredCommitCheck(unittest.TestCase):
    """The provenance check above, run on small repositories whose history is known.

    A review of this pull request measured a squash of the branch. There the recorded commit was either
    present and not an ancestor, which fails, or absent from a clone whose history is complete, which the
    check read as NOT MEASURABLE and skipped. In a complete history every ancestor of HEAD is present, so an
    absent recorded commit is outside the reviewed history: that is a finding, not a blind spot. Only a
    truncated history leaves the question open.
    """

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("git") is None:
            raise unittest.SkipTest("NOT MEASURABLE: no git")
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        source = root / "source"
        source.mkdir()
        _git(source, "init", "-q", "-b", "main")
        (source / "base.txt").write_text("base\n", encoding="utf-8")
        _git(source, "add", "base.txt")
        _git(source, "commit", "-q", "-m", "base")
        script = source / "benchmarks/runtime_baseline/run.py"
        # The branch: the measured commit carries the script, a later commit carries the results.
        _git(source, "checkout", "-q", "-b", "side")
        script.parent.mkdir(parents=True)
        script.write_bytes(_RUN.read_bytes())
        _git(source, "add", "benchmarks")
        _git(source, "commit", "-q", "-m", "measured")
        cls.measured = _git(source, "rev-parse", "HEAD")
        (source / "results.txt").write_text("results\n", encoding="utf-8")
        _git(source, "add", "results.txt")
        _git(source, "commit", "-q", "-m", "results")
        # The squash of that branch onto main: the same tree, one commit, the measured commit not in it.
        _git(source, "checkout", "-q", "main")
        _git(source, "merge", "-q", "--squash", "side")
        _git(source, "commit", "-q", "-m", "squash")
        cls.source = source
        cls.branch = root / "branch"
        _git(root, "clone", "-q", "--branch", "side", source.as_uri(), str(cls.branch))
        cls.complete = root / "complete"
        _git(root, "clone", "-q", "--single-branch", "--branch", "main", source.as_uri(), str(cls.complete))
        cls.truncated = root / "truncated"
        _git(root, "clone", "-q", "--depth", "1", "--single-branch", "--branch", "main", source.as_uri(),
             str(cls.truncated))
        # A complete clone with an empty shallow marker: git calls it shallow, yet nothing is cut off.
        cls.marked = root / "marked"
        _git(root, "clone", "-q", "--single-branch", "--branch", "main", source.as_uri(), str(cls.marked))
        (cls.marked / ".git" / "shallow").write_text("", encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _verdict_in(self, repo: Path) -> tuple:
        case = TheRecordedRuns("test_the_script_that_measured_is_the_script_committed")
        case.laeufe = [("toy", {"environment": {"package": {"commit": self.measured}}}, {})]
        try:
            with mock.patch.object(sys.modules[__name__], "REPO", repo):
                case.test_the_script_that_measured_is_the_script_committed()
        except unittest.SkipTest as skip:
            return "skipped", str(skip)
        except AssertionError as fail:
            return "failed", str(fail)
        return "passed", ""

    def test_an_ancestor_that_carries_the_same_script_passes(self) -> None:
        self.assertEqual(self._verdict_in(self.branch), ("passed", ""))

    def test_a_squash_that_still_holds_the_measured_commit_fails(self) -> None:
        self.assertEqual(self._verdict_in(self.source)[0], "failed")

    def test_a_complete_clone_of_the_squash_without_the_measured_commit_fails(self) -> None:
        """The case the review named: an absent commit in a complete history is not a blind spot."""
        outcome = self._verdict_in(self.complete)
        self.assertEqual(outcome[0], "failed", outcome[1])

    def test_an_empty_shallow_marker_does_not_turn_the_finding_into_a_skip(self) -> None:
        """Catch: the marker alone is not a truncated history, so the finding stands."""
        self.assertEqual(_git(self.marked, "rev-parse", "--is-shallow-repository"), "true")
        outcome = self._verdict_in(self.marked)
        self.assertEqual(outcome[0], "failed", outcome[1])

    def test_a_truncated_clone_without_the_measured_commit_is_not_measurable(self) -> None:
        """The other direction: a shallow clone cannot see the commit, and says so instead of failing."""
        outcome = self._verdict_in(self.truncated)
        self.assertEqual(outcome[0], "skipped", outcome[1])
        self.assertIn("NOT MEASURABLE", outcome[1])


class TheReadme(unittest.TestCase):
    def test_its_tables_are_rendered_from_the_runs(self) -> None:
        render = _render_module()
        text = _README.read_text(encoding="utf-8")
        self.assertEqual(render.render(text, render.runs()), text)

    def test_it_compares_nothing_with_a_target(self) -> None:
        self.assertIn("Nothing here is compared with a target", _README.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
