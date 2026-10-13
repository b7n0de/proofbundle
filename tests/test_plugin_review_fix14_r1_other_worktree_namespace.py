"""Review round 14 of 2026-10-13, R14-1: a record of another worktree is resolved in that worktree's namespace.

Measured by the reviewer at f3b898bc with git 2.51.1 and 2.43.0: a clean repository with no declaration, a bare remote
origin, a clean commit A, main pushable from the main worktree; a second worktree other, detached at A; there `git
symbolic-ref ORIG_HEAD refs/bisect/present_here`, a target that does not exist there. The real Level 1 hook for `git push
origin main` in the main worktree asked. After `git update-ref refs/bisect/present_here A` in the main worktree only, the
same hook answered inactive/nothing_declared_locally with no permissionDecision, while `git -C other rev-parse --verify
ORIG_HEAD` still ended with 128. The same for the HEAD and for refs/bisect/alias of the other worktree:
_refs_beside_the_listing matched the target's name against the refs of the current worktree.

Property (contract D5, condition d: the present records of other worktrees are read, and one that does not resolve leaves
the exception unapplied): a symbolic record resolves in the namespace of its own worktree; a per-worktree target (refs/bisect/,
refs/worktree/, refs/rewritten/, a root ref) only among that worktree's records, a shared one among the shared refs; a
chain is followed within that namespace and a cycle does not resolve. A ref of the same name in the current worktree does
not clear the refusal. Red against f3b898bc.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

NOT_RESOLVED = "is present, but git does not resolve it"
FORMS = {"ORIG_HEAD": "worktrees/other/ORIG_HEAD", "HEAD": "worktrees/other/HEAD",
         "refs/bisect/alias": "worktrees/other/refs/bisect/alias"}


def _other(work, tmp_path, a):
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    return other


def _unresolved_there(other, name):
    probe = subprocess.run(["git", "-C", str(other), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    assert probe.returncode != 0 and probe.stdout == "", probe


@pytest.mark.parametrize("form", sorted(FORMS))
def test_the_reviewers_case_a_ref_of_the_same_name_here_does_not_clear_it(env, tmp_path, form):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(other, "symbolic-ref", form, "refs/bisect/present_here")
    _unresolved_there(other, form)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref {FORMS[form]} {NOT_RESOLVED}")
    w1._git(work, "update-ref", "refs/bisect/present_here", a)          # only in the main worktree
    _unresolved_there(other, form)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref {FORMS[form]} {NOT_RESOLVED}")


def test_from_a_linked_worktree_a_ref_there_does_not_clear_one_of_the_main_worktree(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    linked = tmp_path / "linked"
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(linked))
    w1._git(work, "symbolic-ref", "ORIG_HEAD", "refs/bisect/only_in_linked")
    w1._git(linked, "update-ref", "refs/bisect/only_in_linked", a)
    _unresolved_there(work, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, linked, "git push origin side")
    w1._assert_exception_refused(answer, entry, text, f"the local ref main-worktree/ORIG_HEAD {NOT_RESOLVED}")


def test_a_cycle_in_another_worktree_does_not_resolve(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    bisect = work / ".git" / "worktrees" / "other" / "refs" / "bisect"
    bisect.mkdir(parents=True, exist_ok=True)
    (bisect / "one").write_text("ref: refs/bisect/two\n", encoding="utf-8")
    (bisect / "two").write_text("ref: refs/bisect/one\n", encoding="utf-8")
    _unresolved_there(other, "refs/bisect/one")
    w1._git(work, "update-ref", "refs/bisect/one", a)                   # the same names here resolve
    w1._git(work, "update-ref", "refs/bisect/two", a)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref worktrees/other/refs/bisect/one {NOT_RESOLVED}")


def test_control_a_chain_that_resolves_in_its_own_worktree_keeps_the_exception(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(other, "update-ref", "refs/bisect/good", a)
    w1._git(other, "symbolic-ref", "refs/bisect/alias", "refs/bisect/good")
    w1._git(other, "symbolic-ref", "ORIG_HEAD", "refs/bisect/alias")
    w1._git(other, "symbolic-ref", "refs/bisect/to_main", "refs/heads/main")
    assert w1.n2c._rev(other, "ORIG_HEAD") == a
    w1._assert_inactive(*w1._l1(env, work))
