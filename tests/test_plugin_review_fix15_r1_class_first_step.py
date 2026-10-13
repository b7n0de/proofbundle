"""Review round 15 of 2026-10-13, the class of R15-1: a shared symbolic ref is resolved in another worktree from its first
step, read from the ref store.

Found here at 485df5d0 with git 2.43.0, while writing the catch cases of the mutation probe: git's listing names, as
%(symref), the end of a chain of symbolic refs, not its first step (refs/heads/s1 -> s2 -> s3 -> refs/bisect/x lists
refs/bisect/x). The check of 8bb74c81, which resolves a shared symbolic ref in each other worktree, had started from that
end, so it skipped the steps before it and counted too few refs. Two cases were inactive while git in the other worktree
does not resolve refs/heads/s1: a chain one ref too long there, and a per-worktree step the other worktree does not hold.

Property (contract D5, condition d; R15-1 and R15-2): the first step of a shared symbolic ref is read from the ref store,
and the chain is resolved from there in each other worktree, counted as git counts. Red against 485df5d0.
"""
from __future__ import annotations

import subprocess

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

NOT_ESTABLISHED = ("The gate cannot establish how this local record resolves in its worktree, so the exception does "
                   "not apply: ")


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _other(work, tmp_path, a):
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    return other


def test_the_listing_names_the_end_of_the_chain(tmp_path):
    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    a = w1._commit(work, "a.txt")
    w1._git(work, "update-ref", "refs/bisect/x", a)
    w1._git(work, "symbolic-ref", "refs/heads/s2", "refs/bisect/x")
    w1._git(work, "symbolic-ref", "refs/heads/s1", "refs/heads/s2")
    listed = w1._git(work, "for-each-ref", "--format=%(refname) %(symref)", "refs/heads/s1").stdout.split()
    assert listed == ["refs/heads/s1", "refs/bisect/x"], listed


def test_a_shared_symbolic_ref_one_ref_too_long_in_another_worktree(env, tmp_path):
    """refs/heads/s1 -> s2 -> s3 -> refs/bisect/x: here x is the object (four refs read); in other, x -> y -> z, which
    would be the sixth."""
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(work, "update-ref", "refs/bisect/x", a)
    for here, there in (("refs/heads/s3", "refs/bisect/x"), ("refs/heads/s2", "refs/heads/s3"),
                        ("refs/heads/s1", "refs/heads/s2")):
        w1._git(work, "symbolic-ref", here, there)
    w1._git(other, "update-ref", "refs/bisect/z", a)
    w1._git(other, "symbolic-ref", "refs/bisect/y", "refs/bisect/z")
    w1._git(other, "symbolic-ref", "refs/bisect/x", "refs/bisect/y")
    assert _git_resolves(work, "refs/heads/s1") and not _git_resolves(other, "refs/heads/s1")
    assert _git_resolves(other, "refs/bisect/x")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


def test_a_per_worktree_step_the_other_worktree_does_not_hold(env, tmp_path):
    """refs/heads/s1 -> refs/bisect/m -> refs/heads/t: here m is a symbolic ref to the shared t; other holds no m."""
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(work, "branch", "t", a)
    w1._git(work, "symbolic-ref", "refs/bisect/m", "refs/heads/t")
    w1._git(work, "symbolic-ref", "refs/heads/s1", "refs/bisect/m")
    assert _git_resolves(work, "refs/heads/s1") and not _git_resolves(other, "refs/heads/s1")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")
