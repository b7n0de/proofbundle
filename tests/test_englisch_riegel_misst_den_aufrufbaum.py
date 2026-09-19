"""The English gate judges the tree it was CALLED in, not the tree it lives in.

MEASURED 2026-09-19: `REPO` came from `__file__`, so every git command and every file read went to
the checkout the script sits in. Calling the script by an absolute path to judge a different
worktree returned, word for word, the verdict of the tool's own tree -- green, 758 added lines,
7 files -- while that tree's true verdict was ROT. The numbers happened to be familiar, which is
the only reason it was caught; a checker that answers about itself is not a weaker checker, it is
a confident wrong one.

Each case below is derived from a throwaway repository built here, so the expected answer is known
independently of the tool. The control arm is the clean repository: without it a rejection would
prove nothing.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

WERKZEUG = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = WERKZEUG / "scripts" / "neue_zeilen_sind_englisch.py"


def _git(cwd, *args):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


def _repo(zeilen: str):
    """A throwaway repository whose SECOND commit adds `zeilen` to mod.py. Returns (path, base)."""
    d = tempfile.mkdtemp()
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@example.invalid")
    _git(d, "config", "user.name", "t")
    (pathlib.Path(d) / "mod.py").write_text("VALUE = 1\n")
    _git(d, "add", "mod.py")
    _git(d, "commit", "-q", "-m", "base")
    basis = _git(d, "rev-parse", "HEAD")
    (pathlib.Path(d) / "mod.py").write_text("VALUE = 1\n" + zeilen)
    _git(d, "add", "mod.py")
    _git(d, "commit", "-q", "-m", "second")
    return d, basis


def _lauf(cwd, *args):
    umgebung = dict(os.environ, PYTHONPATH=str(WERKZEUG / "src"))
    r = subprocess.run([sys.executable, str(SKRIPT), "--json", *args],
                       cwd=cwd, capture_output=True, text=True, env=umgebung)
    return r.returncode, json.loads(r.stdout)


DEUTSCH = "# Diese Zeile ist deutsche Prosa und gehoert nicht in neue Zeilen.\n"
ENGLISCH = "# This line is English prose and is allowed in new lines.\n"


class TestTheGateJudgesTheCallingTree(unittest.TestCase):
    def test_control_the_tool_still_judges_its_own_tree_when_called_there(self):
        """The real control arm: green BEFORE and AFTER the fix, by construction.

        Its first version was not one. It ran the gate in a throwaway repository and asserted
        green -- but before the fix that case could not be measured AT ALL (the base sha was
        resolved against the tool's checkout, which does not know it), so it went red with the
        others. A control that falls with the cases it is meant to control proves nothing about
        the harness. This one calls the gate where it has always worked, so a red here means the
        harness broke, not that the defect returned.
        """
        rc, antwort = _lauf(WERKZEUG, "--base", "HEAD")
        self.assertIn(antwort["urteil"], ("gruen", "ROT"), antwort)
        self.assertIn(rc, (0, 1))
        self.assertNotEqual(antwort["urteil"], "NOT MEASURABLE", antwort)

    def test_a_clean_foreign_repository_is_green(self):
        # Counts as a catch-proof, not as a control: before the fix this answered NOT MEASURABLE.
        d, basis = _repo(ENGLISCH)
        rc, antwort = _lauf(d, "--base", basis)
        self.assertEqual(antwort["urteil"], "gruen", antwort)
        self.assertEqual(rc, 0)

    def test_german_prose_in_a_foreign_repository_is_found(self):
        # Before the fix this could not be reached at all: the range `<sha>...HEAD` was resolved
        # against the TOOL's checkout, which does not know that sha, so the answer was
        # NOT MEASURABLE -- a fail-closed non-answer standing in for a real red.
        d, basis = _repo(DEUTSCH)
        rc, antwort = _lauf(d, "--base", basis)
        self.assertEqual(antwort["urteil"], "ROT", antwort)
        self.assertEqual(rc, 1)
        self.assertEqual([b["datei"] for b in antwort["befunde"]], ["mod.py"])

    def test_the_answer_names_the_tree_it_measured(self):
        # A verdict that does not say what it looked at cannot be checked, and the whole defect
        # hid in exactly that silence.
        d, basis = _repo(ENGLISCH)
        _, antwort = _lauf(d, "--base", basis)
        self.assertEqual(pathlib.Path(antwort["gemessener_baum"]).resolve(),
                         pathlib.Path(d).resolve(), antwort)
        self.assertNotEqual(pathlib.Path(antwort["gemessener_baum"]).resolve(), WERKZEUG)

    def test_repo_overrides_the_working_directory(self):
        # The explicit form, so a caller who means another tree can say so instead of relying on
        # where the process happens to stand.
        d, basis = _repo(DEUTSCH)
        sauber = tempfile.mkdtemp()
        rc, antwort = _lauf(sauber, "--base", basis, "--repo", d)
        self.assertEqual(antwort["urteil"], "ROT", antwort)
        self.assertEqual(rc, 1)

    def test_a_not_measurable_answer_also_names_the_tree(self):
        # Fail-closed is where a wrong tree is most expensive: the caller sees a refusal and has
        # no way to tell WHICH tree refused.
        d, _ = _repo(ENGLISCH)
        rc, antwort = _lauf(d, "--base", "no-such-ref-here")
        self.assertEqual(antwort["urteil"], "NOT MEASURABLE", antwort)
        self.assertEqual(rc, 2)
        self.assertIn("gemessener_baum", antwort)


if __name__ == "__main__":
    unittest.main()
