"""The top level git names for `--repo` is compared with `--repo` as a path, not as text.

Codex on PR 249, round four (P1, estimated there: no Windows runner). Both funnels of the pre-tag
receipt chain, `pre_tag_receipt_lib.git_run` and the verifier's copy `_git`, ask git for
`--show-toplevel` before any question and refuse unless it names `--repo`. They compared git's
answer with `str(root)` as text. Git for Windows prints the top level with forward slashes
(`C:/repo`) where the resolved `--repo` reads `C:\\repo`, so every repository was refused on that
platform, by the release gate, the producer and the third-party verifier alike.

No Windows runner is available here either, so the property is measured with its POSIX form: a
`git` placed first on `PATH` (which the funnel passes through) that answers the same directory in
another spelling, `<root>/`. On the head before this change both funnels refused it, exactly as
they refused `C:/repo`; now both accept it. The same shim answering the parent directory is still
refused, so the shim is live and the check did not turn into "any answer".

The comparison must not become more permissive than "names the same directory": an answer that is
empty or relative names nothing, and resolved against the working directory of the process it
would be `--repo` itself whenever the caller runs from there. Those cases run with the working
directory at the root.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"


def _load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(cwd, *args) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                    *args], cwd=str(cwd), check=True, capture_output=True, env=env)


@unittest.skipUnless(os.name == "posix", "the shim is a POSIX shell script")
class TheTopLevelIsComparedAsAPath(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        for rel in ("pre_tag_receipt_lib.py", "verify_pre_tag_receipt.py"):
            if not (SCRIPTS / rel).is_file():
                raise unittest.SkipTest(f"scripts/{rel} is not in this tree")
        cls.lib = _load("pre_tag_receipt_lib.py", "_top_level_lib")
        cls.verifier = _load("verify_pre_tag_receipt.py", "_top_level_verifier")

    def setUp(self):
        d = tempfile.mkdtemp(prefix="pre-tag-top-level-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d).resolve()
        self.root = self.base / "repo"
        (self.root / "sub").mkdir(parents=True)
        (self.root / "sub" / "a.txt").write_text("a\n", encoding="utf-8")
        _git(self.root, "init", "-q")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-qm", "base")

    def _shim(self, sed_expression: str) -> dict:
        """PATH with a `git` in front that rewrites the first line of `--show-toplevel`'s answer and
        passes every other call to the real git unchanged."""
        real = shutil.which("git")
        self.assertIsNotNone(real, "no git on PATH")
        shim_dir = self.base / "shim"
        shim_dir.mkdir()
        shim = shim_dir / "git"
        shim.write_text(
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            f"  *' --show-toplevel '*) out=$(mktemp); \"{real}\" \"$@\" > \"$out\"; rc=$?;\n"
            f"    sed '{sed_expression}' \"$out\"; rm -f \"$out\"; exit $rc;;\n"
            "esac\n"
            f"exec \"{real}\" \"$@\"\n", encoding="utf-8")
        os.chmod(shim, 0o700)
        return {"PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

    def _both(self):
        """(label, callable) for each funnel: True when git was asked, False when it refused."""
        def lib_call():
            try:
                return self.lib.git_run(self.root, "rev-parse", "HEAD").returncode == 0
            except self.lib.BaumNichtLesbar:
                return False

        def verifier_call():
            return self.verifier._git(self.root, "rev-parse", "HEAD")[0] == 0

        return (("library git_run", lib_call), ("verifier _git", verifier_call))

    def test_control_the_plain_answer_is_accepted(self):
        for label, call in self._both():
            with self.subTest(funnel=label):
                self.assertTrue(call())

    def test_RED_the_same_directory_in_another_spelling_is_accepted(self):
        """Red on 0b7252c6: both funnels compared `<root>/` with `<root>` as text and refused."""
        with mock.patch.dict(os.environ, self._shim("1s#$#/#")):
            for label, call in self._both():
                with self.subTest(funnel=label):
                    self.assertTrue(call(), "the real top level in another spelling was refused")

    def test_the_shim_is_live_another_directory_is_still_refused(self):
        with mock.patch.dict(os.environ, self._shim(f"1s#.*#{self.base}#")):
            for label, call in self._both():
                with self.subTest(funnel=label):
                    self.assertFalse(call(), "the parent directory was taken for the top level")

    def test_an_empty_or_relative_answer_names_no_directory(self):
        """With the working directory at the root, an answer that resolves against it would equal
        the root; it must be refused all the same."""
        keep = os.getcwd()
        self.addCleanup(os.chdir, keep)
        os.chdir(self.root)
        for answer in (b"", b".", b"./", b"sub/..", os.fsencode(self.root.name)):
            for label, funktion in (("library", self.lib._nennt_die_wurzel),
                                    ("verifier", self.verifier._nennt_die_wurzel)):
                with self.subTest(answer=answer, copy=label):
                    self.assertFalse(funktion(answer, self.root))
        os.chdir(self.base)
        for label, funktion in (("library", self.lib._nennt_die_wurzel),
                                ("verifier", self.verifier._nennt_die_wurzel)):
            with self.subTest(answer="repo from its parent", copy=label):
                self.assertFalse(funktion(b"repo", self.root))

    def test_the_two_copies_give_one_answer(self):
        """The verifier carries a copy of the check, as it carries a copy of the funnel; derived
        over the same answers, the two must agree."""
        link = self.base / "link-to-repo"
        link.symlink_to(self.root, target_is_directory=True)
        answers = [os.fsencode(p) for p in (
            str(self.root), f"{self.root}/", f"{self.root}/.", f"{self.root}//", str(link),
            str(self.root / "sub"), str(self.base), str(self.base / "absent"), "", ".", "repo")]
        for answer in answers:
            with self.subTest(answer=answer):
                self.assertEqual(self.lib._nennt_die_wurzel(answer, self.root),
                                 self.verifier._nennt_die_wurzel(answer, self.root))
        self.assertTrue(self.lib._nennt_die_wurzel(os.fsencode(link), self.root),
                        "a link to the root names the same directory")
        self.assertFalse(self.lib._nennt_die_wurzel(os.fsencode(self.root / "sub"), self.root))


if __name__ == "__main__":
    unittest.main()
