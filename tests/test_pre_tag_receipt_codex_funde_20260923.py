"""Catch proofs for the three Codex findings on PR #249 (review of 2026-09-23 on `308b76b`).

Each case reproduces the reported sequence against the REAL script through `--emit-payload`, the
path the release chain takes. A gate that exists and is never called is the defect it was written
against, and a case that exercises a helper instead of the entry point measures the wrong thing.

WHY THE SUITE DID NOT SEE THE SECOND FINDING, and it is worth naming because it is the sharpest
instance of the class this release keeps meeting: the sibling file
`test_pre_tag_receipt_refuses_a_dirty_tree.py` strips `GIT_DIR`, `GIT_WORK_TREE` and
`GIT_INDEX_FILE` from the child environment on purpose, so that the environment cannot answer for
the production code. That is right for what it measures — and it means the suite removed the very
variable the production code failed to remove. The test sanitised the attack out of existence, so
the missing sanitisation upstream stayed invisible. The case below therefore sets the variable ON
PURPOSE; it is the one place where doing so is the measurement.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "pre_tag_receipt.py"

#: Only the bytecode pair here. The GIT_ names are stripped to establish a KNOWN-CLEAN starting
#: point; the one case that needs such a variable sets it explicitly, which is the measurement.
_ENVIRONMENT_MAY_NOT_ANSWER = ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX",
                               "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")


def _child_env(**extra) -> dict:
    e = dict(os.environ)
    for name in _ENVIRONMENT_MAY_NOT_ANSWER:
        e.pop(name, None)
    e.update(extra)
    return e


def _git(cwd, *args) -> str:
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


def _set_time(path: pathlib.Path, epoch: float, link: bool = False) -> None:
    os.utime(path, (epoch, epoch), follow_symlinks=not link)


class CodexFindingsOf23September(unittest.TestCase):
    """One throwaway repository per case. No case touches the real tree."""

    AUDIT_TIME = 1_790_000_000.0        # any fixed instant; only the ORDER matters
    EARLIER = AUDIT_TIME - 3600

    def setUp(self):
        if not SKRIPT.is_file():
            self.skipTest("scripts/pre_tag_receipt.py is not in this tree — a distributed "
                          "artefact prunes scripts/, and a tool that is not here cannot be judged")
        d = tempfile.mkdtemp(prefix="pre-tag-codex-")
        self.base = pathlib.Path(d)
        self.repo = self.base / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        _git(self.repo.parent, "init", "-q", str(self.repo))
        _git(self.repo, "config", "user.email", "t@t")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / "datei.txt").write_text("original\n", encoding="utf-8")
        (self.repo / "scripts" / "pre_tag_audit_gate.py").write_text("# gate\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "first")
        self.audit = self.base / "audit.txt"
        self.audit.write_text("audit output\n", encoding="utf-8")
        _set_time(self.audit, self.AUDIT_TIME)

    def _all_before_the_audit(self):
        """Every tracked file explicitly OLDER than the audit output.

        Without it a case measures the order check against some other file — exactly the setup
        mistake that made the first attempt at the P1 reproduction look green while it actually
        failed on `scripts/pre_tag_audit_gate.py` and never reached the reported case at all.
        """
        for raw in _git(self.repo, "ls-files").splitlines():
            p = self.repo / raw
            _set_time(p, self.EARLIER, link=p.is_symlink())

    def _emit(self, name="a", **env):
        return subprocess.run(
            [sys.executable, str(SKRIPT), "--repo", str(self.repo), "--version", "9.9.9",
             "--audit-command", "cmd", "--audit-exit", "0",
             "--audit-output-file", str(self.audit), "--runner-identity", "t",
             "--produced-at", "2026-09-23T00:00:00Z",
             "--emit-payload", str(self.base / f"{name}.bin"),
             "--context-out", str(self.base / f"{name}.json")],
            capture_output=True, text=True, timeout=300, env=_child_env(**env))

    # ───────────── P1: an equal timestamp is not an order ─────────────

    def test_catch_restore_with_an_EQUAL_timestamp_is_refused(self):
        """The reported case. Before the fix: exit 0, payload written.

        Measured in a throwaway repository: `subject_tree_digest` of the CLEAN head bound to an
        `audit_output_digest` over the dirty bytes. A strict `>` reads equality as "not after",
        and a coarse filesystem or a fast sequence produces equality constantly.
        """
        self._all_before_the_audit()
        (self.repo / "datei.txt").write_text("dirty\n", encoding="utf-8")
        _git(self.repo, "checkout", "--", "datei.txt")
        _set_time(self.repo / "datei.txt", self.AUDIT_TIME)      # EXACTLY the audit time
        r = self._emit()
        self.assertNotEqual(r.returncode, 0, f"equality let it through:\n{r.stdout}{r.stderr}")
        self.assertIn("NOT OLDER", r.stdout + r.stderr)

    def test_counter_direction_everything_older_than_the_audit_passes(self):
        """Without this the catch proves nothing: a check that ALWAYS refuses catches every
        mutation and makes the tool unusable."""
        self._all_before_the_audit()
        r = self._emit()
        self.assertEqual(r.returncode, 0, f"clean older tree refused:\n{r.stdout}{r.stderr}")

    # ───────────── P1: the environment may not reselect the repository ─────────────

    def test_catch_GIT_WORK_TREE_cannot_redirect_the_cleanliness_check(self):
        """The reported case. Before the fix: exit 1 without the variable, exit 0 with it.

        `git -C <repo>` sets the working directory and nothing else; an inherited `GIT_WORK_TREE`
        still wins. The check then answered about a different checkout while the receipt described
        the requested repository.
        """
        self._all_before_the_audit()
        (self.repo / "evil.py").write_text("evil\n", encoding="utf-8")   # untracked -> dirty
        _set_time(self.repo / "evil.py", self.EARLIER)

        without = self._emit("without")
        self.assertNotEqual(without.returncode, 0,
                            "the dirty tree passed even without the variable")

        clean = self.base / "clean_substitute"
        (clean / "scripts").mkdir(parents=True)
        for raw in _git(self.repo, "ls-files").splitlines():
            target = clean / raw
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_git(self.repo, "show", f"HEAD:{raw}") + "\n", encoding="utf-8")

        with_var = self._emit("with", GIT_WORK_TREE=str(clean))
        self.assertNotEqual(
            with_var.returncode, 0,
            f"GIT_WORK_TREE redirected the cleanliness check:\n{with_var.stdout}{with_var.stderr}")

    def test_every_git_call_of_the_file_goes_through_the_funnel(self):
        """Structural, not only behavioural: ONE raw `subprocess.run(["git" …])`, and it is the
        funnel itself.

        The behavioural case above covers `status`. `ls-tree`, `ls-files` and `hash-object` share
        the weakness, and a later fifth call would have it again. So the PROPERTY bound here is
        that there is exactly one place where git is called.
        """
        import ast
        source = SKRIPT.read_text(encoding="utf-8")
        raw = [z for z in source.splitlines() if 'subprocess.run(["git"' in z]
        self.assertEqual(len(raw), 1, f"git is called raw in {len(raw)} places:\n" + "\n".join(raw))
        self.assertIn("*argumente", raw[0], "the single raw call is not the funnel")
        # OVER THE WHOLE FUNCTION, not over one line. The call is wrapped and `env=` sits on the
        # second line — a line-wise check would report red here while the code is correct. A
        # contract that hangs on formatting measures the formatting.
        tree = ast.parse(source)
        funnel = [k for k in ast.walk(tree)
                  if isinstance(k, ast.FunctionDef) and k.name == "_git"]
        self.assertEqual(len(funnel), 1, "the function `_git` does not exist exactly once")
        body = ast.get_source_segment(source, funnel[0]) or ""
        self.assertIn("env=_git_umgebung()", body,
                      "the funnel passes the environment through unfiltered")

    # ───────────── P2: a symlink is checked by its link text ─────────────

    def _with_symlink(self, target_bytes: str = "BYTES OTHER THAN THE NAME\n"):
        (self.repo / "target").write_text(target_bytes, encoding="utf-8")
        os.symlink("target", self.repo / "link")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "symlink")
        self._all_before_the_audit()

    def test_catch_a_clean_tree_with_a_symlink_can_produce_a_receipt(self):
        """The reported case. Before the fix: `differs: link`, exit 1, with an empty `git status`.

        `git ls-tree` carries the hash of the LINK TEXT; `git hash-object --stdin-paths` follows
        the link and hashes the TARGET. A valid clean tree containing a symlink could therefore
        produce no receipt at all.
        """
        self._with_symlink()
        r = self._emit()
        self.assertEqual(r.returncode, 0,
                         f"clean tree with a symlink refused:\n{r.stdout}{r.stderr}")

    def test_catch_a_repointed_link_is_caught_even_when_git_status_is_silent(self):
        """THE COUNTER-DIRECTION THAT ACTUALLY MEASURES THE NEW PATH.

        Merely repointing the link is caught by `git status` already, so it proves nothing about
        the new code — which could be a no-op. With `assume-unchanged` set, `git status` stays
        silent and only the hash over the link text can still see the change. That is exactly what
        the function these lines live in exists for.
        """
        self._with_symlink()
        _git(self.repo, "update-index", "--assume-unchanged", "link")
        (self.repo / "link").unlink()
        os.symlink("datei.txt", self.repo / "link")
        _set_time(self.repo / "link", self.EARLIER, link=True)

        self.assertEqual(_git(self.repo, "status", "--porcelain"), "",
                         "git status does see the change — then this case does not measure it")
        r = self._emit("b")
        self.assertNotEqual(r.returncode, 0, f"repointed link not caught:\n{r.stdout}{r.stderr}")
        self.assertIn("differs: link", r.stdout + r.stderr)

    def test_a_broken_link_is_not_a_missing_path(self):
        """The sibling class from the same finding: `is_file()` is False for a broken link, which
        was therefore reported as `missing`. A broken link is a valid tracked object, and
        `os.path.islink` is the question that fits it.

        A side effect the fix brings with it: the order check called `stat()` on the link, which
        raises for a broken link and was silently skipped — the least inspectable case was the
        quietest one. `lstat()` makes it visible.
        """
        os.symlink("does_not_exist", self.repo / "broken")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "broken")
        self._all_before_the_audit()
        r = self._emit()
        self.assertEqual(r.returncode, 0,
                         f"broken link reported as missing:\n{r.stdout}{r.stderr}")


if __name__ == "__main__":
    unittest.main()
