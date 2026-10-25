"""Mutant-signature guard (incident 2026-07-23): each signature class a left-over mutation
probe takes must be CAUGHT on security paths, and the negative controls must stay quiet,
in both the pre-commit (--staged) and the CI (--base) mode. Runs the real script via
subprocess against throwaway git repos, per the scripts-test convention."""
import os
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


def _shown(path):
    """A name as the guard's report shows it: a name with a newline in git's quoted form (F4)."""
    return '"' + path.replace("\n", "\\n") + '"' if "\n" in path else path


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
        was reported clean with exit 0). A newline in the name is the fourth form: decoded, it stopped
        the `.` of the scope pattern, and the mutant under it was clean (Codex on 375, 2026-10-17)."""
        for name in ("pr\u00fcfung.py", 'a"b.py', "a\\b.py", "a\nb.py"):
            with self.subTest(name=name):
                p = self.repo / "src" / "proofbundle" / name
                self._stage("if False:\n    pass\n", path=p)
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(f"{_shown(f'src/proofbundle/{name}')}:1", r.stdout)
                _git(self.repo, "rm", "-q", "--cached", "--", f"src/proofbundle/{name}")
                p.unlink()

    def test_a_configured_header_prefix_does_not_blind_the_guard(self):
        """Counter-reading of pull request 375, F10a (P2): with `diff.mnemonicPrefix` the staged diff
        names its new side `i/`, the guard stripped only `b/`, and a staged `if False:` was reported
        clean with exit 0. `diff.noprefix` is the other setting that moves the prefix."""
        for key in ("diff.mnemonicPrefix", "diff.noprefix"):
            with self.subTest(key=key):
                _git(self.repo, "config", key, "true")
                self._stage(BENIGN.replace("if not isinstance(data, dict):", "if False:"))
                r = _guard(self.repo, "--staged")
                _git(self.repo, "config", "--unset", key)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("src/proofbundle/guarded.py:3", r.stdout)

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

    def test_committed_mutant_under_a_quoted_path_is_blocked(self):
        """The same three names as in the staged form: a byte outside ASCII, a double quote and a
        backslash (a review lens, 2026-09-26: the base form had only the first), and a newline."""
        for name in ("pr\u00fcfung.py", 'a"b.py', "a\\b.py", "a\nb.py"):
            with self.subTest(name=name):
                base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
                (self.repo / "src" / "proofbundle" / name).write_text("if False:\n    pass\n",
                                                                     encoding="utf-8")
                _git(self.repo, "add", "-A")
                _git(self.repo, "commit", "-q", "-m", "mutant under a quoted path")
                r = _guard(self.repo, "--base", base)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(f"{_shown(f'src/proofbundle/{name}')}:1", r.stdout)

    def test_a_configured_header_prefix_does_not_blind_the_base_form(self):
        """The same two settings in the CI form. A commit range keeps `a/` and `b/` under
        `diff.mnemonicPrefix`, and `diff.noprefix` drops them; both are caught before and after the
        fix of F10a, and this case holds that a repair of the staged form keeps it so."""
        base = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.target.write_text(BENIGN.replace("if not isinstance(data, dict):", "if False:"),
                               encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "mutant slips in")
        for key in ("diff.mnemonicPrefix", "diff.noprefix"):
            with self.subTest(key=key):
                _git(self.repo, "config", key, "true")
                r = _guard(self.repo, "--base", base)
                _git(self.repo, "config", "--unset", key)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("src/proofbundle/guarded.py:3", r.stdout)

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
        self.assertEqual(gp('"b/src/proofbundle/a\\nb.py"'), "b/src/proofbundle/a\nb.py")

    def test_the_scope_holds_a_decoded_newline(self):
        scope = self.guard._SECURITY_PATH
        self.assertTrue(scope.match("src/proofbundle/a\nb.py"))
        self.assertFalse(scope.match("src/proofbundle/a.py\nx"))
        self.assertFalse(scope.match("scripts/a\nsrc/proofbundle/b.py"))


class TestTheCounterReadingFollowUp(_RepoFixture):
    """The findings of the counter-reading of pull request 375 at b493f939 that went into a follow-up:
    F1b, F2, F3, F4 and F10b to F10d. Each case was red at 29dfe412."""

    MUTANT = BENIGN.replace("if not isinstance(data, dict):", "if False:")

    def test_F10b_an_added_line_that_begins_with_two_plus_signs_is_no_header(self):
        """F10b (P3, also on main): an added line `++ 1` stands in the diff as `+++ 1`, the guard read it
        as a file header, and every added line after it went to that path, outside the scope, so a
        staged `if False:` below it was reported clean with exit 0. A header stands outside a hunk."""
        for line in ("++ 1", "++ scripts/zz.py"):
            with self.subTest(line=line):
                mutant = self.MUTANT.replace('    """Real check."""',
                                             f'    """Real check.\n{line}\n    """')
                if line == "++ 1":
                    mutant = self.MUTANT.replace("def verify_thing(data):",
                                                 "++ 1\ndef verify_thing(data):")
                self._stage(mutant)
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("trivial-truth branch", r.stdout)

    def test_F10c_a_form_feed_before_the_mutant_does_not_split_the_line(self):
        """F10c (P3, also on main): `splitlines()` also splits at a form feed, so an added
        `\x0cif False:`, which Python reads as `if False:`, reached the guard as `+` and `if False:`
        and was reported clean with exit 0. The diff is split at its line feeds only."""
        self._stage(BENIGN.replace("    if not isinstance(data, dict):", "\x0cif False:\n        pass"))
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("trivial-truth branch", r.stdout)

    def test_F10d_a_line_separator_in_a_name_under_quotepath_false(self):
        """F10d (P3, also on main): with `core.quotePath=false` git writes U+2028 and U+0085 in a header
        as they are, `splitlines()` cut the header there, and the mutant under the name was clean. The
        guard reads the header in git's quoted form whatever the configuration says."""
        _git(self.repo, "config", "core.quotePath", "false")
        for name in ("a\u2028b.py", "a\u0085b.py"):
            with self.subTest(name=repr(name)):
                p = self.repo / "src" / "proofbundle" / name
                self._stage("if False:\n    pass\n", path=p)
                r = _guard(self.repo, "--staged")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                _git(self.repo, "rm", "-q", "--cached", "--", f"src/proofbundle/{name}")
                p.unlink()

    def test_F3_a_finding_under_a_name_that_is_not_utf8_is_reported(self):
        """F3 (P3): the guard printed a name that is not UTF-8 with its lone surrogate, and stdout
        raised `UnicodeEncodeError`: exit 1 held, the report with the file did not. Under an output
        encoding without the letter, a name with `ü` did the same."""
        raw = os.fsencode(self.repo) + b"/src/proofbundle/p\xff.py"
        try:
            with open(raw, "wb") as fh:
                fh.write(b"if False:\n    pass\n")
        except OSError as exc:
            self.skipTest(f"this file system refuses a name that is not UTF-8: {exc}")
        _git(self.repo, "add", "-A")
        # A strict UTF-8 stdout, as under a UTF-8 locale (a GitHub runner); under the C locale Python
        # writes the surrogate back as the raw byte instead of raising.
        b = subprocess.run([sys.executable, str(SCRIPT), "--staged"], cwd=str(self.repo),
                           capture_output=True, timeout=60, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        out, err = b.stdout.decode("utf-8", "replace"), b.stderr.decode("utf-8", "replace")
        self.assertEqual(b.returncode, 1, out + err)
        self.assertNotIn("Traceback", err)
        self.assertIn('"src/proofbundle/p\\377.py":1', out)
        os.remove(raw)
        _git(self.repo, "add", "-A")
        self._stage("if False:\n    pass\n", path=self.repo / "src" / "proofbundle" / "prüfung.py")
        r = subprocess.run([sys.executable, str(SCRIPT), "--staged"], cwd=str(self.repo),
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, PYTHONIOENCODING="ascii"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("src/proofbundle/pr\\xfcfung.py:1", r.stdout)

    def test_F4_a_name_cannot_write_a_line_of_its_own_into_the_log(self):
        """F4 (P3): the decoded name was printed as it is, so a newline in it began a line of its own,
        and `::warning::...` at the start of a line is a workflow command in a GitHub Actions log. A
        name that holds a character that is not printable is shown in git's quoted form."""
        name = "a\n::warning::injected line.py"
        self._stage("if False:\n    pass\n", path=self.repo / "src" / "proofbundle" / name)
        r = _guard(self.repo, "--staged")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertFalse([ln for ln in r.stdout.splitlines() if ln.startswith("::")], r.stdout)
        self.assertIn('"src/proofbundle/a\\n::warning::injected line.py":1', r.stdout)

    def test_F1b_the_self_test_proves_the_decoder_under_any_configuration(self):
        """F1b (P3): with `core.quotePath=false` in the global configuration the self-test said OK
        without its decoder case reaching the decoder, because the header was not quoted. A self-test
        that passes with the decoder taken out proves nothing about it. The guard asks git for the
        quoted form itself now."""
        cfg = self.repo.parent / f"{self.repo.name}-gitconfig"
        cfg.write_text("[core]\n\tquotePath = false\n", encoding="utf-8")
        code = ("import importlib.util, sys\n"
                f"spec = importlib.util.spec_from_file_location('g', {str(SCRIPT)!r})\n"
                "g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)\n"
                "g._git_path = lambda field: field.strip()\n"
                "sys.exit(g.self_test())\n")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, GIT_CONFIG_GLOBAL=str(cfg)))
        cfg.unlink()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL [A: a security path git quotes (non-ASCII name)]", r.stdout)


class TestTheDecoderKeepsWhatGitDoesNotWrite(unittest.TestCase):
    def test_F2_an_octal_escape_above_one_byte_stays_as_it_stands(self):
        """F2 (P3): `int(..., 8)` read `\\400` to `\\777`, which are no byte, and `bytearray.append`
        raised ValueError: the guard and the language gate, which loads this decoder, stopped with a
        traceback and exit 1, in the language gate the exit code of a red verdict. git writes at most
        `\\377`; a larger escape is kept as it stands, as an escape git does not write."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("_msg_guard_f2", SCRIPT)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        self.assertEqual(guard._git_path('"b/x\\777"'), "b/x\\777")
        self.assertEqual(guard._git_path('"b/x\\400y"'), "b/x\\400y")
        self.assertEqual(guard._git_path('"b/x\\377"'), "b/x\udcff")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("self-test: OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
