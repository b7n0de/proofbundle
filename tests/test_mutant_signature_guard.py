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
        """A byte outside ASCII, a double quote, a backslash or a newline in a name make git quote the
        diff header. Each planted mutant is caught and named by its real path (2026-09-26: the first
        and the last were reported clean with exit 0)."""
        for name in ("pr\u00fcfung.py", 'a"b.py', "a\\b.py", "a\nb.py"):
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

    def test_a_mutant_under_a_name_that_is_not_utf8_is_reported(self):
        """The name carries a surrogate; the report names it escaped instead of raising on it."""
        import os
        try:
            fd = os.open(os.fsencode(self.repo) + b"/src/proofbundle/\xff.py", os.O_WRONLY | os.O_CREAT, 0o644)
        except OSError as exc:
            self.skipTest(f"this file system refuses a name that is not UTF-8: {exc}")
        os.write(fd, b"if False:\n    pass\n")
        os.close(fd)
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/" + chr(92) + "udcff.py:1", r.stdout)

    def test_a_null_byte_in_the_file_is_a_verdict_not_a_crash(self):
        """ast.parse raises ValueError for a NUL byte, not SyntaxError: the guard ended with a
        traceback. Python itself refuses to import such a file, so the guard cannot say what Python
        would run: the verdict is the fail-closed stop, exit 2 with the reason."""
        self.target.write_bytes(b"if False:\n    pass\n# ok = verify(x)\x00\n")
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py: Python cannot read this file as source", r.stderr)
        self.assertIn("(fail closed)", r.stderr)

    # The file is read as Python reads it, from its bytes (2026-09-26). Each case below was reported
    # clean with exit 0 at 1ecc2aca, measured in a throwaway repository.

    LATIN_1 = b"# -*- coding: latin-1 -*-\ns = '\xfc'\ndef verify_signature(data):\n    return True\n"
    UTF_7 = b"# coding: utf-7\n+AGkAZg- True:\n    pass\n"

    def test_a_latin_1_cookie_is_honoured(self):
        """Read as UTF-8, the byte 0xfc became a surrogate, the parser refused the text, and the
        `return True` was never seen."""
        self.target.write_bytes(self.LATIN_1)
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:4: `return True` opens verification function "
                      "`verify_signature`", r.stdout)

    def test_a_utf_7_cookie_is_honoured(self):
        """`+AGkAZg- True:` is `if True:` to Python."""
        self.target.write_bytes(self.UTF_7)
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:2: trivial-truth branch", r.stdout)
        self.assertIn("    if True:", r.stdout)

    def test_a_line_end_that_exists_only_in_the_decoded_text_starts_a_python_line(self):
        """`+AAo-` is a newline under UTF-7: one git line, two Python lines, as with a lone CR."""
        self.target.write_bytes(b"# coding: utf-7\nx = 1+AAo-if False:\n    pass\n")
        _git(self.repo, "add", "-A")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:3: trivial-truth branch", r.stdout)

    def test_a_branch_over_a_backslash_continuation_is_one_branch(self):
        """Judged per physical line, `if \\` and `True:` matched nothing; the tree holds one `if`."""
        self._stage(BENIGN.replace("    if not isinstance(data, dict):", "    if \\\n       True:"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:3: trivial-truth branch", r.stdout)

    def test_a_changed_continuation_line_alone_is_enough(self):
        """Only the `True:` line is new; the `if \\` above it was committed before."""
        self._stage("def f(x):\n    if \\\n       x:\n        return 1\n")
        _git(self.repo, "commit", "-q", "-m", "a branch over two lines")
        self._stage("def f(x):\n    if \\\n       True:\n        return 1\n")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.py:2: trivial-truth branch", r.stdout)

    def test_control_a_marker_on_the_continued_header_suppresses(self):
        self._stage("def f(x):\n    if \\\n       True:  # mutant-guard: allow (reviewed)\n"
                    "        return 1\n")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_control_a_trivial_truth_inside_a_string_is_no_branch(self):
        """The line pattern read `if False:` inside a docstring as a branch; the tree does not."""
        self._stage('def f():\n    """Example:\n    if False:\n        pass\n    """\n')
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_file_python_cannot_read_stops_fail_closed(self):
        """A file Python cannot decode or parse is not judged, and never reported clean."""
        cases = {"no cookie, a byte that is not UTF-8": b"s = '\xfc'\n",
                 "a cookie Python does not know": b"# coding: no-such-codec\nx = 1\n",
                 "a syntax error": b"def broken(:\n    pass\n"}
        for label, content in cases.items():
            with self.subTest(label):
                self.target.write_bytes(content)
                _git(self.repo, "add", "-A")
                r = _guard(self.repo, "--staged")
                self.assertNotIn("Traceback", r.stderr)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("Python cannot read this file as source", r.stderr)
                self.assertNotIn("clean", r.stdout)

    def test_compiled_code_on_a_security_path_is_a_finding(self):
        """Python imports bytecode and extension modules; no scan reads them as source."""
        for rel in ("src/proofbundle/__pycache__/guarded.cpython-310.pyc", "src/proofbundle/evil.pyc",
                    "src/proofbundle/evil.pyo", "src/proofbundle/evil.cpython-310-x86_64-linux-gnu.so",
                    "src/proofbundle/evil.pyd", "src/proofbundle/__pycache__/notes.txt"):
            with self.subTest(rel=rel):
                p = self.repo / rel
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(b"\x6f\x0d\x0d\x0a" + bytes(12) + b"code")
                _git(self.repo, "add", "-f", "--", rel)
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(f"{rel}: compiled code on a security path", r.stdout)
                self.assertNotIn("If this is intentional", r.stdout)
                _git(self.repo, "rm", "-q", "--cached", "--", rel)
                p.unlink()

    def test_a_pyw_file_is_judged_as_source(self):
        """Python imports `.pyw` as source on Windows."""
        self._stage("if False:\n    pass\n", path=self.target.with_suffix(".pyw"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/guarded.pyw:1: trivial-truth branch", r.stdout)

    def test_control_a_data_file_under_the_package_is_no_finding(self):
        self._stage('{"k": 1}\n', path=self.repo / "src" / "proofbundle" / "data.json")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

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
        """The same names as in the staged form: a byte outside ASCII, a double quote, a backslash
        and a newline (review lenses, 2026-09-26: the base form had only the first, and a newline
        stopped the path pattern)."""
        for name in ("pr\u00fcfung.py", 'a"b.py', "a\\b.py", "a\nb.py"):
            with self.subTest(name=name):
                base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
                (self.repo / "src" / "proofbundle" / name).write_text("if False:\n    pass\n",
                                                                     encoding="utf-8")
                _git(self.repo, "add", "-A")
                _git(self.repo, "commit", "-q", "-m", "mutant under a quoted path")
                r = _guard(self.repo, "--base", base)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(f"src/proofbundle/{name}:1", r.stdout)

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

    def test_a_copy_that_drops_an_allow_marker_is_judged_whatever_diff_renames_says(self):
        """With `diff.renames=copies` git wrote the new file as a copy of a changed one and showed only
        the dropped marker line, so the `if True:` it no longer covers was clean with exit 0 (measured
        2026-09-26 at 1ecc2aca and at main)."""
        allowed = ('def f(x):\n    """A helper whose branch was reviewed."""\n'
                   "    # mutant-guard: allow (reviewed fixture)\n    if True:\n        return 1\n    return 2\n")
        (self.repo / "src" / "proofbundle" / "a.py").write_text(allowed, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "an allowed branch")
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        (self.repo / "src" / "proofbundle" / "a.py").write_text(allowed + "y = 1\n", encoding="utf-8")
        (self.repo / "src" / "proofbundle" / "b.py").write_text(
            allowed.replace("    # mutant-guard: allow (reviewed fixture)\n", ""), encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "a copy without the marker")
        _git(self.repo, "config", "diff.renames", "copies")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("src/proofbundle/b.py:3: trivial-truth branch", r.stdout)

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

    def test_a_base_this_clone_does_not_have_stops_fail_closed(self):
        """It printed "scan skipped honestly" and then "clean", exit 0 (measured 2026-09-26)."""
        self.target.write_text(BENIGN.replace("if not isinstance(data, dict):", "if False:"),
                               encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "mutant slips in")
        r = _guard(self.repo, "--base", "1234567890abcdef1234567890abcdef12345678")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("is no commit in this clone", r.stderr)
        self.assertNotIn("clean", r.stdout)

    def test_a_base_that_shares_no_history_stops_fail_closed(self):
        branch = _git(self.repo, "symbolic-ref", "--short", "HEAD").stdout.strip()
        _git(self.repo, "checkout", "-q", "--orphan", "other")
        _git(self.repo, "commit", "-q", "-m", "unrelated root")
        other = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(_git(self.repo, "checkout", "-q", branch).returncode, 0)
        self.target.write_text(BENIGN + "x = 1\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "a second commit")
        r = _guard(self.repo, "--base", other)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("shares no history with HEAD", r.stderr)

    def test_committed_cookie_continuation_and_bytecode_cases_are_blocked(self):
        """The staged cases, committed and read from HEAD in the range form."""
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        pkg = self.repo / "src" / "proofbundle"
        (pkg / "latin.py").write_bytes(TestStagedMode.LATIN_1)
        (pkg / "seven.py").write_bytes(TestStagedMode.UTF_7)
        (pkg / "cont.py").write_text("def f(x):\n    if \\\n       True:\n        return 1\n",
                                     encoding="utf-8")
        (pkg / "evil.pyc").write_bytes(b"\x6f\x0d\x0d\x0a" + bytes(12))
        _git(self.repo, "add", "-A")
        _git(self.repo, "add", "-f", "--", "src/proofbundle/evil.pyc")
        _git(self.repo, "commit", "-q", "-m", "four ways past a line-based reading")
        r = _guard(self.repo, "--base", base)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        for expected in ("src/proofbundle/latin.py:4: `return True`", "src/proofbundle/seven.py:2: "
                         "trivial-truth", "src/proofbundle/cont.py:2: trivial-truth",
                         "src/proofbundle/evil.pyc: compiled code on a security path"):
            self.assertIn(expected, r.stdout)


class TestAStopIsNotAFinding(_RepoFixture):
    """Exit 2 for a fail-closed stop, as the docstring says; `SystemExit(<text>)` exits 1, the code
    of a finding (a review lens of another model family, measured 2026-09-26)."""

    def test_outside_a_repository_it_exits_2(self):
        import os
        with tempfile.TemporaryDirectory(prefix="guard-no-repo-") as tmp:
            r = subprocess.run([sys.executable, str(SCRIPT), "--staged"], cwd=tmp, capture_output=True,
                               text=True, timeout=60,
                               env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(pathlib.Path(tmp).parent)))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("not inside a git repository", r.stderr)

    def test_a_git_call_that_fails_under_it_exits_2(self):
        self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
        (self.repo / ".git" / "index").write_bytes(b"not an index")
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("(fail closed)", r.stderr)

    def test_control_a_finding_still_exits_1(self):
        self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
        self.assertEqual(_guard(self.repo, "--staged").returncode, 1)


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

    def test_the_bytes_are_decoded_by_their_cookie_one_git_line_at_a_time(self):
        tree, lines, spans = self.guard._read_as_python("p.py", b"# coding: utf-7\nx = 1+AAo-y = 2\r\n")
        self.assertEqual(lines, ["# coding: utf-7", "x = 1", "y = 2\r", ""])
        self.assertEqual([list(s) for s in spans], [[1], [2, 3], [4]])
        self.assertEqual([n.lineno for n in tree.body], [2, 3])
        _, lines, _ = self.guard._read_as_python("p.py", b"\xef\xbb\xbfx = '\xc3\xbc'\n")
        self.assertEqual(lines, ["x = '\u00fc'", ""])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("self-test: OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
