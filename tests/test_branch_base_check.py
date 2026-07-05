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
        # Pick a tag that is BEHIND main (a proper ancestor, not the current tip) — only a behind
        # branch re-conflicts, so only a behind tag warns. The newest tag can sit at main's tip right
        # after a release (no warning, correctly), so this test must not depend on 'newest'.
        main_tip = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "origin/main"],
                                  capture_output=True, text=True).stdout.strip()
        behind = None
        for t in sorted(tag):
            c = subprocess.run(["git", "-C", str(ROOT), "rev-list", "-n1", t],
                               capture_output=True, text=True).stdout.strip()
            is_anc = subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", c, main_tip],
                                    capture_output=True).returncode == 0
            if c and c != main_tip and is_anc:
                behind = c
                break
        if not behind:
            self.skipTest("no release tag that is behind main (e.g. shallow checkout)")
        r = _run({"BRANCH_BASE_REF": "main", "BRANCH_HEAD_SHA": behind})
        self.assertEqual(r.returncode, 0, "advisory check must never fail the build")
        self.assertIn("::warning", r.stdout)
        self.assertIn("release tag", r.stdout)

    def test_never_nonzero_even_on_garbage_base(self):
        r = _run({"BRANCH_BASE_REF": "does-not-exist-ref"})
        self.assertEqual(r.returncode, 0)

    def test_up_to_date_branch_at_base_tip_does_not_warn(self):
        # 6-lens L1: a branch whose fork point IS the current base tip is up to date → NO warning,
        # even if that commit carries a release tag (no CHANGELOG re-conflict when up to date).
        tip = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "origin/main"],
                             capture_output=True, text=True).stdout.strip()
        # In a shallow CI checkout the merge-base may be uncomputable → the check safely skips; either
        # way the CONTRACT is: exit 0 and NO warning (no false positive on an up-to-date/tagged tip).
        if not tip:
            self.skipTest("no origin/main")
        r = _run({"BRANCH_BASE_REF": "main", "BRANCH_HEAD_SHA": tip})
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("::warning", r.stdout)


if __name__ == "__main__":
    unittest.main()
