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

    def test_a_path_git_quotes_is_read_as_the_path_it_names(self):
        """A byte outside ASCII, a double quote and a backslash in a name make git quote the diff
        header. Each planted mutant is caught and named by its real path (2026-09-26: the first one
        was reported clean with exit 0)."""
        for name in ("pr\u00fcfung.py", 'a"b.py', "a\\b.py"):
            with self.subTest(name=name):
                p = self.repo / "src" / "proofbundle" / name
                self._stage("if False:\n    pass\n", path=p)
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(f"src/proofbundle/{name}:1", r.stdout)
                _git(self.repo, "rm", "-q", "--cached", "--", f"src/proofbundle/{name}")
                p.unlink()

    def test_visible_allow_marker_suppresses(self):
        self._stage(BENIGN.replace("if not isinstance(data, dict):",
                                   "if True:  # mutant-guard: allow (fixture, reviewed)"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    # The diff is read in git's grammar and judged in Python's (2026-09-26). Each case below was
    # reported clean with exit 0 before, measured in a throwaway repository.

    def test_a_line_that_looks_like_a_diff_header_does_not_end_the_hunk(self):
        """`++ 1` is valid Python; its diff line `+++ 1` was read as a header naming the path `1`."""
        self._stage(BENIGN + "++ 1\nif False:\n    pass\n")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:7", r.stdout)

    def test_a_lone_cr_ends_a_line_as_python_reads_it(self):
        """git ends a line at LF only, Python at a lone CR too: `x = 1<CR>if False:` is one git line
        and two statements. The finding carries Python's line number."""
        self.target.write_bytes(BENIGN.replace("    if not isinstance(data, dict):",
                                               "    x = 1\r    if False:").encode())
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:4: trivial-truth branch", r.stdout)

    def test_configuration_does_not_rewrite_the_grammar_the_guard_reads(self):
        """`diff.mnemonicPrefix` writes `i/` instead of `b/`, and `diff.external` hands the diff to
        another program."""
        for key in ("diff.mnemonicPrefix", "diff.external"):
            with self.subTest(key=key):
                _git(self.repo, "config", key, "true")
                self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                _git(self.repo, "config", "--unset", key)

    def test_an_attribute_that_makes_git_skip_the_lines_does_not_hide_them(self):
        """With `-diff` or `binary` git writes `Binary files ... differ` instead of the lines; a
        committed `.gitattributes` reaches CI as well."""
        for attribute in ("-diff", "binary"):
            with self.subTest(attribute=attribute):
                (self.repo / ".gitattributes").write_text(f"*.py {attribute}\n", encoding="utf-8")
                self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("trivial-truth branch", r.stdout)

    def test_a_bom_before_the_first_line_is_skipped_as_python_skips_it(self):
        self.target.write_bytes(b"\xef\xbb\xbfif False:\n    pass\n")
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:1: trivial-truth branch", r.stdout)

    def test_a_textconv_filter_does_not_replace_the_source(self):
        """A diff driver's textconv hands git converted text; the guard reads the source itself."""
        _git(self.repo, "config", "diff.upper.textconv", "tr a-z A-Z")
        (self.repo / ".gitattributes").write_text("*.py diff=upper\n", encoding="utf-8")
        self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("trivial-truth branch", r.stdout)

    def test_a_diff_that_disagrees_with_the_file_is_not_judged(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("_msg_guard_disagree", SCRIPT)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        self._stage("x = 1\n")
        lie = ("diff --git a/src/proofbundle/guarded.py b/src/proofbundle/guarded.py\n"
               "+++ b/src/proofbundle/guarded.py\n@@ -0,0 +1 @@\n+y = 2\n")
        with self.assertRaises(SystemExit) as caught:
            guard.scan(lie, staged=True, cwd=self.repo)
        self.assertIn("disagree", str(caught.exception))

    def test_the_allow_marker_is_read_on_python_lines(self):
        """A U+2028 in a comment is no line end for Python, and `splitlines()` read it as one, so a
        marker two lines above a finding counted as the line directly above it."""
        self._stage("# a\u2028b\ny = 2  # mutant-guard: allow\nz = 3\nif False:\n    pass\n")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:4", r.stdout)

    def test_a_symlink_on_a_security_path_is_a_finding(self):
        """The diff under src/proofbundle shows the link's text; Python runs its target. Before this,
        a mutant in a file outside the security path, linked in, was reported clean with exit 0."""
        outside = self.repo / "scripts" / "impl.py"
        outside.parent.mkdir(exist_ok=True)
        outside.write_text(BENIGN.replace("if not isinstance(data, dict):", "if False:"), encoding="utf-8")
        (self.target.parent / "evil.py").symlink_to("../../scripts/impl.py")
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/evil.py: a symlink on a security path", r.stdout)
        # a link carries no comment, so the output names the way out instead of the marker
        self.assertIn("put the file itself there", r.stdout)
        self.assertNotIn("If this is intentional", r.stdout)

    def _link_src_to_a_mutant(self):
        """`src` becomes a symlink to a copy whose guarded.py carries the mutant: no path under
        src/proofbundle is tracked any more, and Python imports the package through the link."""
        _git(self.repo, "rm", "-r", "-q", "--cached", "src")
        (self.repo / "src").rename(self.repo / "real_src")
        (self.repo / "real_src" / "proofbundle" / "guarded.py").write_text(
            BENIGN.replace("if not isinstance(data, dict):", "if False:"), encoding="utf-8")
        (self.repo / "src").symlink_to("real_src")
        _git(self.repo, "add", "-A")

    def test_a_symlinked_src_is_a_finding(self):
        self._link_src_to_a_mutant()
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src: a symlink on a security path", r.stdout)

    def test_a_gitlink_under_the_package_is_a_finding(self):
        head = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        _git(self.repo, "update-index", "--add", "--cacheinfo", f"160000,{head},src/proofbundle/sub")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/sub: a gitlink (a submodule) on a security path", r.stdout)
        self.assertNotIn("If this is intentional", r.stdout)

    def test_a_verify_name_given_to_a_function_whose_return_true_stays_is_caught(self):
        """Class C when only the `def` line is new: the `return True` below it is not an added line."""
        _git(self.repo, "rm", "-q", "--cached", "--", "src/proofbundle/guarded.py")
        self.target.write_text("def helper(data):\n    return True\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "a helper that is not a check")
        self._stage("def verify_helper(data):\n    return True\n")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("return True` opens verification function `verify_helper`", r.stdout)

    def test_control_a_marker_directly_above_still_suppresses(self):
        self._stage("y = 2\nz = 3  # mutant-guard: allow\nif False:\n    pass\n")
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

    def test_committed_mutant_under_a_quoted_path_is_blocked(self):
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        (self.repo / "src" / "proofbundle" / "pr\u00fcfung.py").write_text("if False:\n    pass\n",
                                                                         encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "mutant under a quoted path")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/pr\u00fcfung.py:1", r.stdout)

    def test_committed_mutants_in_both_grammar_cases_are_blocked(self):
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.target.write_bytes((BENIGN + "++ 1\nif False:\n    pass\n"
                                 + "x = 1\r" + "while False:\n    pass\n").encode())
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "two mutants git and Python number differently")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:7", r.stdout)
        self.assertIn("src/proofbundle/guarded.py:10", r.stdout)

    def test_an_existing_symlink_hides_no_later_change_to_its_target(self):
        """A link committed earlier and a mutant planted in its target later: the range holds no line
        under src/proofbundle, and the link is still a finding."""
        outside = self.repo / "scripts" / "impl.py"
        outside.parent.mkdir(exist_ok=True)
        outside.write_text(BENIGN, encoding="utf-8")
        (self.target.parent / "linked.py").symlink_to("../../scripts/impl.py")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "a link, before this guard knew links")
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        outside.write_text(BENIGN.replace("if not isinstance(data, dict):", "if False:"), encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "the mutant goes into the target")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/linked.py: a symlink on a security path", r.stdout)

    def test_a_symlinked_src_in_the_range_is_a_finding(self):
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        TestStagedMode._link_src_to_a_mutant(self)
        _git(self.repo, "commit", "-q", "-m", "src becomes a link")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src: a symlink on a security path", r.stdout)

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


class TestTheHeaderPathIsDecoded(unittest.TestCase):
    """The decoder itself, over the forms git writes (C escapes, octal bytes) and one it does not."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("_msg_guard", SCRIPT)
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)

    def test_the_forms(self):
        gp = self.guard._git_path
        self.assertEqual(gp('"b/src/proofbundle/pr\\303\\274fung.py"'), "b/src/proofbundle/pr\u00fcfung.py")
        self.assertEqual(gp('"b/src/proofbundle/a\\"b.py"'), 'b/src/proofbundle/a"b.py')
        self.assertEqual(gp('"b/src/proofbundle/a\\\\b.py"'), "b/src/proofbundle/a\\b.py")
        self.assertEqual(gp("b/src/proofbundle/with space.py\t"), "b/src/proofbundle/with space.py")
        self.assertEqual(gp('"b/x\\q"'), "b/x\\q")  # an escape git does not write stays as it stands


class TestTheDiffIsReadInGitsGrammar(unittest.TestCase):
    """The parser itself: position by the hunk counts, and a text that is not git's diff refused."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("_msg_guard_grammar", SCRIPT)
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)

    def test_the_counts_decide_what_is_a_hunk_line(self):
        diff = ("diff --git a/p.py b/p.py\n--- a/p.py\n+++ b/p.py\n"
                "@@ -1,0 +2,3 @@\n+++ 1\n+--- 2\n+@@ 3\n"
                "@@ -9 +11 @@\n-old\n+new\n\\ No newline at end of file\n")
        self.assertEqual(self.guard._added_lines_by_file(diff),
                         {"p.py": [(2, "++ 1"), (3, "--- 2"), (4, "@@ 3"), (11, "new")]})

    def test_a_hunk_that_ends_before_its_count_is_refused(self):
        with self.assertRaises(ValueError):
            self.guard._added_lines_by_file("+++ b/p.py\n@@ -0,0 +1,2 @@\n+one\n")
        with self.assertRaises(ValueError):
            self.guard._added_lines_by_file("+++ b/p.py\n@@ -0,0 +1,2 @@\n+one\nnot a hunk line\n")

    def test_a_hunk_header_of_another_form_is_refused(self):
        with self.assertRaises(ValueError):
            self.guard._added_lines_by_file("+++ b/p.py\n@@@ -1 -1 +1 @@@\n+x\n")

    def test_python_numbers_the_lines_a_git_line_holds(self):
        lines, spans = self.guard._python_lines_of("a\r\nb\rc\nd\u2028e\n")
        self.assertEqual(lines, ["a\r", "b", "c", "d\u2028e", ""])
        self.assertEqual([list(s) for s in spans], [[1], [2, 3], [4], [5]])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("self-test: OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
