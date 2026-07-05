"""FEHLER D: the branch-base advisory must be exactly that — ADVISORY. It warns on a tag-based fork
but must NEVER fail the build (always exit 0)."""
import os
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "branch_base_check.py"


def _run(env_extra):
    env = {**os.environ, **env_extra}
    return subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT),
                          capture_output=True, text=True, env=env, timeout=30)


class TestBranchBaseCheck(unittest.TestCase):
    def test_main_based_branch_is_ok_exit_0(self):
        r = _run({"BRANCH_BASE_REF": "main"})
        self.assertEqual(r.returncode, 0)

    def test_tag_based_fork_warns_but_still_exit_0(self):
        # A branch whose head IS a release-tag commit forks from that tag → WARN, but exit 0.
        tag = subprocess.run(["git", "-C", str(ROOT), "tag", "--list", "v*"],
                             capture_output=True, text=True).stdout.split()
        if not tag:
            self.skipTest("no release tags present")
        tag = sorted(tag)[-1]
        head = subprocess.run(["git", "-C", str(ROOT), "rev-list", "-n1", tag],
                              capture_output=True, text=True).stdout.strip()
        r = _run({"BRANCH_BASE_REF": "main", "BRANCH_HEAD_SHA": head})
        self.assertEqual(r.returncode, 0, "advisory check must never fail the build")
        self.assertIn("::warning", r.stdout)
        self.assertIn("release tag", r.stdout)

    def test_never_nonzero_even_on_garbage_base(self):
        r = _run({"BRANCH_BASE_REF": "does-not-exist-ref"})
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
