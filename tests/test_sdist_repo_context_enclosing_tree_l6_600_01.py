"""An extracted sdist behaves the same wherever it is unpacked — including inside someone else's repo.

THE CLASS (deep gate 2026-09-05, finding L6-600-01, P2). ``tests/conftest.py`` decides which test
modules are repo-context (and therefore SKIP outside a checkout) by asking whether an absent
root-relative path is merely an unbuilt BUILD ARTIFACT — via ``git -C <sdist root> check-ignore``. That
question is answered by whatever repository CONTAINS the directory, and a downstream packager extracts
an sdist exactly where one does: ``vendor/``, ``build/``, ``.tox/`` inside their own checkout. There
every path is reported ignored, every pruned path read as "unbuilt", the derived skip switched off, and
the shipped suite ran tests that cannot pass from a distributed artifact. Measured, same sdist bytes:

    plain dir                              0 failed
    gitignored vendor/ of a foreign repo   40 failed
    non-ignored src_deps/ of a foreign repo 1 failed

The documented invariant is ``pip install <sdist>[test] && pytest`` green — and it held only in the one
layout CI happens to use (/tmp).

THE PROPERTY: a repo-context derivation consults git ONLY when this tree is itself the repository
(``rev-parse --show-toplevel`` equals the root); otherwise it behaves exactly as with no git at all —
the stricter pre-fix behaviour. Consequence, asserted below: the three layouts answer identically.

The three-layout matrix here works on the DERIVATION (fast, hermetic, no build). The full
``pytest`` × three-layout run over a built sdist is the lane's separate measurement; it needs a build
and ~15 minutes per layout and is reported in the lane report rather than run on every commit.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_cf_l6", REPO / "tests" / "conftest.py")
cf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cf)


def _git(*args, cwd=None):
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd, timeout=30)


def _have_git() -> bool:
    try:
        return _git("--version").returncode == 0
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return False


class DreiLayoutsEineAntwort(unittest.TestCase):
    """The same extracted tree, in three places, must derive the same repo-context answer."""

    def setUp(self):
        if not _have_git():  # pragma: no cover - git is present in CI and locally
            self.skipTest("no git binary — the ignore rule is not measurable here, and not "
                          "measurable is not a pass")
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="l6_600_"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # A consumer repository that ignores vendor/ — the ordinary place a packager unpacks a dep.
        self.consumer = self.tmp / "consumer"
        self.consumer.mkdir()
        _git("init", "-q", str(self.consumer))
        (self.consumer / ".gitignore").write_text("vendor/\n", encoding="utf-8")
        _git("-C", str(self.consumer), "add", ".gitignore")
        _git("-C", str(self.consumer), "-c", "user.email=x@y", "-c", "user.name=x",
             "commit", "-qm", "init")

    def _extracted_tree(self, where: pathlib.Path) -> pathlib.Path:
        """A minimal stand-in for an extracted sdist: a tests/ module that reads a root-relative path
        the sdist prunes (docs/IN_TOTO_PROFILE.md), and NO .github/tools/SPEC.md markers."""
        where.mkdir(parents=True, exist_ok=True)
        root = where / "proofbundle-6.0.0"
        (root / "tests").mkdir(parents=True)
        (root / "tests" / "test_liest_geprunte_datei.py").write_text(
            'from pathlib import Path\n'
            'REPO = Path(__file__).resolve().parents[1]\n'
            'def test_x():\n'
            '    assert (REPO / "docs/IN_TOTO_PROFILE.md").is_file()\n', encoding="utf-8")
        return root

    def test_the_derivation_answers_identically_in_all_three_layouts(self):
        layouts = {
            "plain": self.tmp / "plain",
            "ignored_vendor": self.consumer / "vendor",
            "not_ignored_src_deps": self.consumer / "src_deps",
        }
        answers = {}
        for label, where in layouts.items():
            root = self._extracted_tree(where)
            modul = root / "tests" / "test_liest_geprunte_datei.py"
            answers[label] = cf.modul_ist_repo_kontext(modul, wurzel=root)
        self.assertEqual(set(answers.values()), {True},
                         f"the extracted tree derives different answers per layout: {answers}")

    def test_an_enclosing_repository_is_not_this_tree(self):
        """The discriminator itself: inside a foreign checkout, git must not be asked about our files."""
        root = self._extracted_tree(self.consumer / "vendor")
        self.assertFalse(cf._dieser_baum_ist_das_repo(root),
                         "an extracted tree inside a foreign repository claimed to BE that repository")
        self.assertFalse(cf._ist_bauartefakt(root, "docs/IN_TOTO_PROFILE.md"),
                         "the enclosing repository's ignore rules were used to excuse a pruned file")

    def test_our_own_checkout_is_still_the_repository(self):
        """ANTI-PARITY: a guard that answered False everywhere would pass everything above and switch
        the build-artifact discrimination off inside the real repository.

        ONLY MEANINGFUL IN A CHECKOUT, and this test learned that the hard way: run from an EXTRACTED
        SDIST (the very situation this file is about) there is no repository to recognise, and the
        assertion below failed — measured in the three-layout suite run, 1 failed in every layout.
        The property has no object outside a checkout, so it announces that instead of failing. The
        sibling in `test_sdist_selftest_derivation.py` already carries the same guard; mine did not.
        """
        if not cf._dieser_baum_ist_das_repo(REPO):
            self.skipTest("kein git-Checkout (entpacktes sdist) — 'erkennt sich das Repositorium "
                          "selbst' hat hier keinen Gegenstand; nicht messbar ist keine Freigabe, "
                          "aber auch kein Fehlschlag")
        self.assertTrue(cf._dieser_baum_ist_das_repo(REPO),
                        "the repository no longer recognises itself — the derivation goes blind")
        self.assertTrue(cf._ist_bauartefakt(REPO, "tools/pb_verify_rs/target/release/pb_verify_rs"),
                        "an unbuilt Rust binary no longer counts as a build artifact")
        self.assertFalse(cf._ist_bauartefakt(REPO, "docs/IN_TOTO_PROFILE.md"),
                         "the pruned-leaf case stopped being a signal")

    def test_a_subdirectory_of_our_own_repo_is_not_the_root_either(self):
        """The comparison is toplevel EQUALITY, not membership — `tests/` is inside the repository and
        is still not the repository."""
        self.assertFalse(cf._dieser_baum_ist_das_repo(REPO / "tests"))

    def test_META_the_pre_fix_question_would_answer_differently(self):
        """PLANT-AND-MUST-CATCH, measured rather than asserted: `--is-inside-work-tree` (the question the
        code used to ask, and the one the sibling test asked) says YES for the extracted tree inside the
        consumer repo. That divergence IS the finding; if it ever stops reproducing, this test says so."""
        root = self._extracted_tree(self.consumer / "vendor")
        inside = _git("-C", str(root), "rev-parse", "--is-inside-work-tree").returncode == 0
        self.assertTrue(inside, "the pre-fix question no longer reproduces — this meta-test is blind")
        self.assertFalse(cf._dieser_baum_ist_das_repo(root),
                         "the shipped question agrees with the pre-fix one — the fix is not in effect")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
