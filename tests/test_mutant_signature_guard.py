"""Mutant-signature guard (incident 2026-07-23): each signature class a left-over mutation
probe takes must be CAUGHT on security paths, and the negative controls must stay quiet,
in both the pre-commit (--staged) and the CI (--base) mode. Runs the real script via
subprocess against throwaway git repos, per the scripts-test convention."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "mutant_signature_guard.py"

BENIGN = '''def verify_thing(data):
    """Real check."""
    if not isinstance(data, dict):
        return False
    return bool(data.get("ok"))
'''


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          timeout=30)


def _guard(repo, *args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=str(repo),
                          capture_output=True, text=True, timeout=60)


class _RepoFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-test-")
        self.repo = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@t.local")
        _git(self.repo, "config", "user.name", "t")
        self.target = self.repo / "src" / "proofbundle" / "guarded.py"
        self.target.parent.mkdir(parents=True)
        self.target.write_text(BENIGN, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base")

    def _stage(self, content, path=None):
        (path or self.target).write_text(content, encoding="utf-8")
        _git(self.repo, "add", "-A")


class TestStagedMode(_RepoFixture):
    def test_class_a_trivial_truth_branch_is_blocked_exit_1(self):
        self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("trivial-truth branch", r.stdout)

    def test_class_b_commented_out_verification_is_blocked(self):
        self._stage(BENIGN.replace('    return bool(data.get("ok"))',
                                   "    # ok = hmac.compare_digest(a, b)\n    return True"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("commented-out verification call", r.stdout)

    def test_class_c_return_true_verify_function_is_blocked(self):
        self._stage("def verify_thing(data):\n    return True\n")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("return True", r.stdout)

    def test_benign_edit_stays_quiet_exit_0(self):
        self._stage(BENIGN.replace('data.get("ok")', 'data.get("okay")'))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_prose_comment_mentioning_verify_stays_quiet(self):
        self._stage(BENIGN.replace('    """Real check."""',
                                   '    """Real check."""\n    # verify the payload first'))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_non_security_path_is_ignored(self):
        other = self.repo / "scripts" / "tool.py"
        other.parent.mkdir(exist_ok=True)
        self._stage("if False:\n    pass\n", path=other)
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_visible_allow_marker_suppresses(self):
        self._stage(BENIGN.replace("if not isinstance(data, dict):",
                                   "if True:  # mutant-guard: allow (fixture, reviewed)"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestBaseMode(_RepoFixture):
    def test_committed_mutant_in_range_is_blocked(self):
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.target.write_text(BENIGN.replace("if not isinstance(data, dict):", "if False:"),
                               encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "mutant slips in")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("trivial-truth branch", r.stdout)

    def test_all_zero_base_falls_back_to_parent(self):
        self.target.write_text(BENIGN.replace("if not isinstance(data, dict):", "if False:"),
                               encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "mutant slips in")
        r = _guard(self.repo, "--base", "0" * 40)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_root_commit_without_base_skips_honestly_exit_0(self):
        r = _guard(self.repo, "--base", "0" * 40)  # only one commit, HEAD~1 missing
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("scan skipped honestly", r.stdout)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("self-test: OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
