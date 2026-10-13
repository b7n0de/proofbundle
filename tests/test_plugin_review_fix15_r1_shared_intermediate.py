"""Review round 15 of 2026-10-13, R15-1: a shared symbolic step keeps the worktree of the record it starts from.

Measured by the reviewer at 947d9f26 and at f3b898bc with git 2.51.1 and 2.43.0: a clean repository work with no
declaration, a bare remote origin, a clean commit A; a second worktree other, detached at A; `git -C work symbolic-ref
refs/heads/bridge refs/bisect/here`, `git -C other symbolic-ref ORIG_HEAD refs/heads/bridge`, `git -C work update-ref
refs/bisect/here A`. `git -C other rev-parse --verify --quiet ORIG_HEAD` ended with 1 and no object, and the real Level 1
hook from work for `git push origin main` answered inactive with no permissionDecision; without the update-ref it asked.
Under 2.51.1 the same with the HEAD and with refs/bisect/alias of other as the record it starts from. _resolves had ended
at the shared name refs/heads/bridge with its membership in the listing of the current worktree.

Property (contract D5, condition d): a record is resolved in its own worktree along the whole chain; a shared symbolic step
is followed there too, so a per-worktree name after it is read in that worktree. Where the chain does not reach an object
there, the exception does not apply. The class: a shared symbolic ref is present in every worktree, so it is resolved in
each other worktree as well. Red against b9bed806.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

NOT_ESTABLISHED = ("The gate cannot establish how this local record resolves in its worktree, so the exception does "
                   "not apply: ")
FORMS = ["HEAD", "ORIG_HEAD", "refs/bisect/alias"]


def _other(work, tmp_path, a):
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    return other


def _resolves_there(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


@pytest.mark.parametrize("form", FORMS)
def test_the_reviewers_case_a_shared_step_to_a_name_the_other_worktree_lacks(env, tmp_path, form):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(work, "symbolic-ref", "refs/heads/bridge", "refs/bisect/here")
    w1._git(other, "symbolic-ref", form, "refs/heads/bridge")
    w1._git(work, "update-ref", "refs/bisect/here", a)
    assert not _resolves_there(other, form) and _resolves_there(work, "refs/heads/bridge")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


def test_from_a_linked_worktree_a_shared_step_of_the_main_worktrees_record(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    linked = tmp_path / "linked"
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(linked))
    w1._git(work, "symbolic-ref", "refs/heads/bridge", "refs/bisect/here")
    w1._git(work, "symbolic-ref", "ORIG_HEAD", "refs/heads/bridge")
    w1._git(linked, "update-ref", "refs/bisect/here", a)
    assert not _resolves_there(work, "ORIG_HEAD") and _resolves_there(linked, "refs/heads/bridge")
    answer, entry, text = w1._l1(env, linked, "git push origin side")
    # Narrow contract of 2026-10-13, 17:0x: a linked worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a linked worktree", str(linked))


def test_a_shared_symbolic_ref_that_another_worktree_does_not_resolve(env, tmp_path):
    """The class: no record of the other worktree points at the shared ref, which is present there all the same."""
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(work, "symbolic-ref", "refs/heads/bridge", "refs/bisect/here")
    w1._git(work, "update-ref", "refs/bisect/here", a)
    assert not _resolves_there(other, "refs/heads/bridge") and _resolves_there(work, "refs/heads/bridge")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


@pytest.mark.parametrize("form", FORMS)
def test_control_the_target_in_the_other_worktree_too_keeps_the_exception(env, tmp_path, form):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(work, "symbolic-ref", "refs/heads/bridge", "refs/bisect/here")
    w1._git(other, "symbolic-ref", form, "refs/heads/bridge")
    w1._git(work, "update-ref", "refs/bisect/here", a)
    w1._git(other, "update-ref", "refs/bisect/here", a)
    assert _resolves_there(other, form)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/other")
