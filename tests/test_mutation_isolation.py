"""Mutation-harness isolation contract (v1.4, incident 2026-07-23): probes mutate a throwaway
tempdir copy, the REAL working tree is never written to, and a left-over working tree change
after a run fails closed. Exercised against a mini fixture repo (a full pb mutation run takes
hours; the contract itself is what these tests pin)."""
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "mutation_check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("mutation_check_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          timeout=30)


class _MiniRepo(unittest.TestCase):
    """A tiny git repo with one guarded module, one killing test, one mutation operator."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mutiso-test-")
        self.repo = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@t.local")
        _git(self.repo, "config", "user.name", "t")
        src = self.repo / "src" / "mini"
        src.mkdir(parents=True)
        (src / "__init__.py").write_text("", encoding="utf-8")
        (src / "core.py").write_text(
            "def check(x):\n    if x is None:\n        return False\n    return True\n",
            encoding="utf-8")
        tests = self.repo / "tests"
        tests.mkdir()
        (tests / "test_core.py").write_text(
            "import unittest\nfrom mini.core import check\n\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_none_is_rejected(self):\n"
            "        self.assertFalse(check(None))\n",
            encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base")
        self.mod = _load_module()
        self.mod.ROOT = self.repo
        self.mod.MUTATIONS = [
            ("src/mini/core.py", "if x is None:", "if False:", "mini: check disabled", True),
        ]

    def _real_tree_digest(self):
        return {p: p.read_bytes() for p in sorted(self.repo.rglob("*.py"))}


class TestIsolationProperty(_MiniRepo):
    def test_workdir_copy_mutation_never_touches_real_tree(self):
        before = self._real_tree_digest()
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp) / "tree"
            self.mod._prepare_workdir(self.repo, work)
            copied = work / "src" / "mini" / "core.py"
            self.assertTrue(copied.is_file())
            copied.write_text("if False:  # mutated in the copy\n", encoding="utf-8")
            self.assertEqual(before, self._real_tree_digest())

    def test_untracked_files_are_not_copied(self):
        (self.repo / "leftover.mutbak").write_text("junk", encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp) / "tree"
            self.mod._prepare_workdir(self.repo, work)
            self.assertFalse((work / "leftover.mutbak").exists())

    def test_full_run_kills_mutant_and_leaves_real_tree_clean(self):
        status_before = self.mod._worktree_status(self.repo)
        rc = self.mod.main()
        self.assertEqual(rc, 0)
        self.assertEqual(status_before, self.mod._worktree_status(self.repo))
        self.assertEqual(_git(self.repo, "status", "--porcelain").stdout, "")

    def test_stale_operator_is_a_gap(self):
        self.mod.MUTATIONS = [
            ("src/mini/core.py", "NOT PRESENT", "if False:", "mini: stale", True),
        ]
        self.assertEqual(self.mod.main(), 1)


class TestLeftoverFailClosed(_MiniRepo):
    def test_leftover_working_tree_change_fails_the_run(self):
        def dirty_and_pass(work):
            (self.repo / "planted_leftover.py").write_text("x = 1\n", encoding="utf-8")
            return 0

        with mock.patch.object(self.mod, "_run_operators", dirty_and_pass):
            rc = self.mod.main()
        self.assertEqual(rc, 1)

    def test_clean_run_with_no_gaps_passes(self):
        with mock.patch.object(self.mod, "_run_operators", lambda work: 0):
            self.assertEqual(self.mod.main(), 0)


if __name__ == "__main__":
    unittest.main()
