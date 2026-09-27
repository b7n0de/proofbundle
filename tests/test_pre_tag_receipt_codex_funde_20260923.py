"""Catch proofs for the three Codex findings on PR #249 (review of 2026-09-23 on `308b76b`).

Each case reproduces the reported sequence against the REAL script through `--emit-payload`, the
path the release chain takes. A gate that exists and is never called is the defect it was written
against, and a case that exercises a helper instead of the entry point measures the wrong thing.

THE MECHANISM THESE FINDINGS WERE MEASURED ON IS GONE, THE FINDINGS ARE NOT. The three findings
were reported against this branch's own version of the tool, which took the audit output as a file
and checked the order of audit and receipt by modification times. Main replaced that version on
2026-09-21 (A-70): the tool now starts the audit itself between two measurements of the tree, a
supplied record is refused, the redirecting `GIT_*` names leave the process before its first git
call, and every tracked entry is compared from the bytes on disk. Merging main therefore changed
HOW each finding is closed. The cases below keep the reported scenario and drive the merged tool
with the command line it now has; each one was red against `308b76b` in the form it had there.

WHY THE SUITE DID NOT SEE THE SECOND FINDING, and it is worth naming because it is the sharpest
instance of the class this release keeps meeting: the sibling file
`test_pre_tag_receipt_refuses_a_dirty_tree.py` strips `GIT_DIR`, `GIT_WORK_TREE` and
`GIT_INDEX_FILE` from the child environment on purpose, so that the environment cannot answer for
the production code. That is right for what it measures, and it means the suite removed the very
variable the production code failed to remove. The case below therefore sets the variable ON
PURPOSE; it is the one place where doing so is the measurement.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "pre_tag_receipt.py"

#: The bytecode pair and the redirecting GIT_ names are stripped to establish a KNOWN-CLEAN
#: starting point; the one case that needs such a variable sets it explicitly, which is the
#: measurement. `GIT_NO_REPLACE_OBJECTS` is on the list because an in-process import of the tool
#: sets it for the whole test process, and a fixture must not depend on which case ran first.
_ENVIRONMENT_MAY_NOT_ANSWER = ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX",
                               "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                               "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE")


def _child_env(**extra) -> dict:
    e = dict(os.environ)
    for name in _ENVIRONMENT_MAY_NOT_ANSWER:
        e.pop(name, None)
    e.update(extra)
    return e


def _git(cwd, *args) -> str:
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True,
                       env=_child_env())
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


def _set_time(path: pathlib.Path, epoch: float, link: bool = False) -> None:
    os.utime(path, (epoch, epoch), follow_symlinks=not link)


def _python(code: str) -> str:
    """An audit command that runs `code` in this interpreter, as one shell-quoted line."""
    return shlex.join([sys.executable, "-c", code])


class CodexFindingsOf23September(unittest.TestCase):
    """One throwaway repository per case. No case touches the real tree."""

    AUDIT_TIME = 1_790_000_000.0        # any fixed instant; only equality with it matters

    def setUp(self):
        if not SKRIPT.is_file():
            self.skipTest("scripts/pre_tag_receipt.py is not in this tree — a distributed "
                          "artefact prunes scripts/, and a tool that is not here cannot be judged")
        d = tempfile.mkdtemp(prefix="pre-tag-codex-")
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)
        self.repo = self.base / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        _git(self.repo.parent, "init", "-q", str(self.repo))
        _git(self.repo, "config", "user.email", "t@t")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / "datei.txt").write_text("original\n", encoding="utf-8")
        (self.repo / "scripts" / "pre_tag_audit_gate.py").write_text("# gate\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "commit.gpgsign=false", "commit", "-qm", "first")
        self._number = 0

    def _record(self) -> pathlib.Path:
        """A fresh record path OUTSIDE the tree; the tool refuses one that already exists."""
        self._number += 1
        return self.base / f"audit_{self._number}.txt"

    def _emit(self, name="a", command=None, record=None, **env):
        self.payload = self.base / f"{name}.bin"
        self.context = self.base / f"{name}.json"
        return subprocess.run(
            [sys.executable, str(SKRIPT), "--repo", str(self.repo), "--version", "9.9.9",
             "--audit-command", command or _python("print('audit ran')"),
             "--audit-output-file", str(record or self._record()), "--runner-identity", "t",
             "--produced-at", "2026-09-23T00:00:00Z",
             "--emit-payload", str(self.payload), "--context-out", str(self.context)],
            capture_output=True, text=True, timeout=300, env=_child_env(**env))

    def _refused(self, r, *expected: str) -> str:
        message = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, f"a payload was produced:\n{message[-800:]}")
        self.assertFalse(self.payload.exists(), "a payload was written despite the refusal")
        for e in expected:
            self.assertIn(e, message, f"the refusal does not say {e!r}: {message[-800:]}")
        self.assertNotIn("Traceback", message, f"a refusal is a decision, not a crash: {message[-800:]}")
        return message

    # ───────────── P1: an equal timestamp is not an order ─────────────

    def test_catch_a_record_from_a_restored_tree_with_an_EQUAL_timestamp_is_refused(self):
        """The reported sequence. At `308b76b`: exit 0, payload written.

        Measured there in a throwaway repository: `subject_tree_digest` of the CLEAN head bound to
        an `audit_output_digest` over the dirty bytes, because the order check compared strictly
        `>` and read the shared timestamp as "not after". The merged tool has no order check to
        get wrong: it does not accept a record it did not write, whatever its timestamp.
        """
        (self.repo / "datei.txt").write_text("dirty\n", encoding="utf-8")
        record = self._record()
        record.write_bytes((self.repo / "datei.txt").read_bytes())     # the audit of dirty bytes
        _git(self.repo, "checkout", "--", "datei.txt")
        _set_time(self.repo / "datei.txt", self.AUDIT_TIME)
        _set_time(record, self.AUDIT_TIME)                             # EXACTLY the same stamp
        self.assertEqual(_git(self.repo, "status", "--porcelain", "--untracked-files=all"), "",
                         "the restored tree is not clean, so another guard would refuse it")
        self._refused(self._emit(record=record), "already exists")
        self.assertEqual(record.read_bytes(), b"dirty\n", "the supplied record was touched")

    def test_counter_direction_the_record_bound_is_the_one_this_run_wrote(self):
        """Without this the catch proves nothing: a tool that ALWAYS refuses catches every case.

        Same restored tree, same shared timestamp. The tool runs the audit itself, so the record
        it binds is over the bytes it measured, not over the bytes of an earlier run.
        """
        (self.repo / "datei.txt").write_text("dirty\n", encoding="utf-8")
        _git(self.repo, "checkout", "--", "datei.txt")
        _set_time(self.repo / "datei.txt", self.AUDIT_TIME)
        record = self._record()
        r = self._emit(command=_python("print(open('datei.txt').read(), end='')"), record=record)
        self.assertEqual(r.returncode, 0, f"clean tree refused:\n{r.stdout}{r.stderr}")
        self.assertEqual(record.read_bytes(), b"original\n", "the record is not the clean bytes")
        context = json.loads(self.context.read_text(encoding="utf-8"))
        self.assertEqual(context["audit_output_digest"], hashlib.sha256(b"original\n").hexdigest())

    # ───────────── P1: the environment may not reselect the repository ─────────────

    def test_catch_GIT_WORK_TREE_cannot_redirect_the_cleanliness_check(self):
        """The reported case. At `308b76b`: exit 1 without the variable, exit 0 with it.

        `git -C <repo>` sets the working directory and nothing else; an inherited `GIT_WORK_TREE`
        still wins. The check then answered about a different checkout while the receipt described
        the requested repository.
        """
        (self.repo / "evil.py").write_text("evil\n", encoding="utf-8")   # untracked -> dirty

        without = self._emit("without")
        self._refused(without, "evil.py")

        clean = self.base / "clean_substitute"
        for raw in _git(self.repo, "ls-files").splitlines():
            target = clean / raw
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_git(self.repo, "show", f"HEAD:{raw}") + "\n", encoding="utf-8")
        # anti-vacuity: under the variable a plain status of the dirty tree is clean
        plain = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain"],
                               capture_output=True, text=True,
                               env=_child_env(GIT_WORK_TREE=str(clean)))
        self.assertEqual(plain.stdout.strip(), "", "the variable did not redirect git here")

        self._refused(self._emit("with", GIT_WORK_TREE=str(clean)), "evil.py")

    def test_the_redirecting_names_leave_the_process_before_its_first_git_call(self):
        """Not one call site, the process: every git the tool starts, the library's tree digest
        and the audit program included, inherits an environment without the family.

        The branch version isolated the calls of this file through one funnel, and the library's
        own `ls-tree` stayed outside it. The merged tool removes the names from its own process at
        import, before any of those can run, so there is no call site left to forget.
        """
        family = {"GIT_WORK_TREE": "/nonexistent", "GIT_DIR": "/nonexistent/.git",
                  "GIT_INDEX_FILE": "/nonexistent/index", "GIT_COMMON_DIR": "/nonexistent",
                  "GIT_OBJECT_DIRECTORY": "/nonexistent/objects",
                  "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/nonexistent/objects",
                  "GIT_CEILING_DIRECTORIES": "/", "GIT_CONFIG_COUNT": "1",
                  "GIT_CONFIG_KEY_0": "core.excludesFile", "GIT_CONFIG_VALUE_0": "/nonexistent",
                  "GIT_CONFIG_PARAMETERS": "'core.excludesfile'='/nonexistent'",
                  "GIT_CONFIG_GLOBAL": "/nonexistent", "GIT_CONFIG_SYSTEM": "/nonexistent"}
        probe = ("import importlib.util, json, os, sys\n"
                 f"spec = importlib.util.spec_from_file_location('_ptr_probe', {str(SKRIPT)!r})\n"
                 "mod = importlib.util.module_from_spec(spec)\n"
                 "spec.loader.exec_module(mod)\n"
                 f"print(json.dumps(sorted(n for n in {sorted(family)!r} if n in os.environ)))\n")
        r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                           timeout=120, env=_child_env(**family))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1]), [],
                         "names that reselect the repository survived the import of the tool")

    # ───────────── P2: a symlink is checked by its link text ─────────────

    def _with_symlink(self, name: str, target: str) -> None:
        os.symlink(target, self.repo / name)
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "commit.gpgsign=false", "commit", "-qm", f"symlink {name}")

    def test_catch_a_clean_tree_with_a_symlink_can_produce_a_receipt(self):
        """The reported case. At `308b76b`: `differs: link`, exit 1, with an empty `git status`.

        `git ls-tree` carries the hash of the LINK TEXT; `git hash-object --stdin-paths` follows
        the link and hashes the TARGET. A valid clean tree containing a symlink could therefore
        produce no receipt at all.
        """
        (self.repo / "target").write_text("BYTES OTHER THAN THE NAME\n", encoding="utf-8")
        self._with_symlink("link", "target")
        r = self._emit()
        self.assertEqual(r.returncode, 0, f"clean tree with a symlink refused:\n{r.stdout}{r.stderr}")

    def test_catch_a_symlink_to_a_directory_can_produce_a_receipt(self):
        """Codex's second shape of the same finding. At `308b76b`: `missing: dirlink`, exit 1,
        because `is_file()` is False for a link whose target is a directory."""
        (self.repo / "dir").mkdir()
        (self.repo / "dir" / "inner.txt").write_text("inner\n", encoding="utf-8")
        self._with_symlink("dirlink", "dir")
        r = self._emit()
        self.assertEqual(r.returncode, 0,
                         f"clean tree with a directory symlink refused:\n{r.stdout}{r.stderr}")

    def test_catch_a_broken_link_is_not_a_missing_path(self):
        """The sibling from the same finding: `is_file()` is False for a broken link, which was
        therefore reported as `missing`. A broken link is a valid tracked object. At `308b76b`:
        `missing: broken`, exit 1."""
        self._with_symlink("broken", "does_not_exist")
        r = self._emit()
        self.assertEqual(r.returncode, 0, f"broken link refused:\n{r.stdout}{r.stderr}")

    def test_a_repointed_link_is_caught_even_when_git_status_is_silent(self):
        """THE COUNTER-DIRECTION THAT MEASURES THE LINK PATH.

        Merely repointing the link is caught by `git status` already, so that would prove nothing
        about the comparison, which could be a no-op for links. With `assume-unchanged` set,
        `git status` stays silent and only the hash over the link text can still see the change.
        Green at `308b76b` as well (the target's bytes differed there too), so it is a control,
        not a catch proof.
        """
        (self.repo / "target").write_text("BYTES OTHER THAN THE NAME\n", encoding="utf-8")
        self._with_symlink("link", "target")
        _git(self.repo, "update-index", "--assume-unchanged", "link")
        (self.repo / "link").unlink()
        os.symlink("datei.txt", self.repo / "link")
        self.assertEqual(_git(self.repo, "status", "--porcelain"), "",
                         "git status does see the change — then this case does not measure it")
        self._refused(self._emit("b"), "M link")


if __name__ == "__main__":
    unittest.main()
