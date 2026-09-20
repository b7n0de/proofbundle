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


class TestDerRueckfallAntwortetNichtEreGibtAuf(unittest.TestCase):
    """A fallback that answers is the defect this file exists against, one layer in.

    The first fix bound the measured tree to the working directory instead of to `__file__`, and
    named the tree in the answer. Measured afterwards from a directory that is not a repository:
    the run fell back to the TOOL's tree and printed `gruen`, 163 added lines, exit 0. The tree was
    named, so it was not silent -- but a caller who asked whether THEIR tree is clean got a green
    verdict with a zero exit, and only a careful reader notices the name is not theirs.

    A counter-reading from another model family named it before this test existed: the caller
    cannot tell a valid measurement from a fallback, so the fallback has to refuse rather than
    answer. It now returns NOT MEASURABLE with rc 2, and still says which tree it would have taken.
    """

    def _lauf(self, cwd: pathlib.Path, *args: str) -> dict:
        r = subprocess.run([sys.executable, str(WERKZEUG / "scripts" / "neue_zeilen_sind_englisch.py"),
                            "--json", *args],
                           cwd=str(cwd), capture_output=True, text=True)
        return json.loads(r.stdout), r.returncode

    def test_aus_einem_nicht_repo_gibt_es_kein_urteil(self):
        with tempfile.TemporaryDirectory() as d:
            kein_repo = pathlib.Path(d) / "kein_repo"
            kein_repo.mkdir()
            antwort, rc = self._lauf(kein_repo)
        self.assertEqual(antwort["urteil"], "NOT MEASURABLE",
                         "a run with no tree to judge must not report a verdict")
        self.assertEqual(rc, 2, "and it must not exit zero")
        # THE KIND, NOT THE SENTENCE. The field carries git's own reason after the kind, so an
        # equality check here would pin the wording of a message this tool does not own and would
        # go red the next time git rephrases it.
        self.assertTrue(antwort["baum_herkunft"].startswith("rueckfall"),
                        antwort["baum_herkunft"])
        self.assertIn("--repo", antwort["grund"], "the answer names the way out")

    def test_die_herkunft_des_baums_steht_in_der_antwort(self):
        """Three origins, three names. Without this a reader cannot tell them apart."""
        with tempfile.TemporaryDirectory() as d:
            kein_repo = pathlib.Path(d) / "leer"
            kein_repo.mkdir()
            aus_fremdem, _ = self._lauf(kein_repo, "--repo", str(WERKZEUG))
        self.assertEqual(aus_fremdem["baum_herkunft"], "vorgabe")
        eigener, _ = self._lauf(WERKZEUG)
        self.assertEqual(eigener["baum_herkunft"], "arbeitsverzeichnis")

    def test_die_antwort_nennt_den_baum_der_die_wortlisten_stellt(self):
        """The list comes from the TOOL's tree while another tree is judged, and that is named."""
        eigener, _ = self._lauf(WERKZEUG)
        self.assertEqual(eigener["wortlisten_baum"], str(WERKZEUG),
                         "the word list's origin must be stated, not assumed to be the judged tree")

    def test_KONTROLLE_ein_echter_baum_bekommt_weiterhin_ein_urteil(self):
        """A guard that refuses everything is an outage. This falls if the refusal is too wide."""
        antwort, rc = self._lauf(WERKZEUG)
        self.assertIn(antwort["urteil"], ("gruen", "ROT"),
                      "a real repository must still get a real verdict")
        self.assertIn(rc, (0, 1))


class TestWennGitSelbstNichtLaeuft(unittest.TestCase):
    """The call can fail, not only the command, and a crash must not look like a finding.

    An adversarial reading ran the tool with `git` unresolvable. The module-level
    `subprocess.run` raised FileNotFoundError before `main()` was ever entered: a traceback, no
    answer, and exit 1 -- the SAME exit code this tool uses for a real ROT verdict. A caller that
    only reads the exit code cannot tell a crash from a finding, which is the failure this whole
    file exists against, arriving through a channel nobody had opened.
    """

    def test_ohne_git_gibt_es_eine_antwort_und_keinen_absturz(self):
        umgebung = dict(os.environ, PATH="/nonexistent")
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run(
                [sys.executable, str(WERKZEUG / "scripts" / "neue_zeilen_sind_englisch.py"),
                 "--json"],
                cwd=d, env=umgebung, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2,
                         f"a tool that cannot run git must refuse, not crash: {r.stderr[-300:]}")
        antwort = json.loads(r.stdout)
        self.assertEqual(antwort["urteil"], "NOT MEASURABLE")
        self.assertIn("git is not runnable", antwort["baum_herkunft"])

    def test_die_zwei_ruecksfallgruende_sind_unterscheidbar(self):
        """`no repository here` and `git is missing` are different facts, not one sentence."""
        with tempfile.TemporaryDirectory() as d:
            ohne_repo = subprocess.run(
                [sys.executable, str(WERKZEUG / "scripts" / "neue_zeilen_sind_englisch.py"),
                 "--json"], cwd=d, capture_output=True, text=True)
            ohne_git = subprocess.run(
                [sys.executable, str(WERKZEUG / "scripts" / "neue_zeilen_sind_englisch.py"),
                 "--json"], cwd=d, env=dict(os.environ, PATH="/nonexistent"),
                capture_output=True, text=True)
        a = json.loads(ohne_repo.stdout)["baum_herkunft"]
        b = json.loads(ohne_git.stdout)["baum_herkunft"]
        self.assertNotEqual(a, b, "two different causes must not collapse into one sentence")
        self.assertIn("not a git repository", a)
        self.assertIn("not runnable", b)
