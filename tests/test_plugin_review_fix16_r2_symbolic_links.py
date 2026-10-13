"""Review round 16 of 2026-10-13, R16-2: a filesystem symbolic link in the ref store.

Measured by the reviewer at 101bd167: a clean repository work with no declaration, a bare remote origin, a clean commit
A; a second worktree other, detached at A; refs/heads/side at A, packed; `git -C other symbolic-ref ORIG_HEAD
refs/heads/side`; a symbolic link at work/.git/refs/heads/side to no-target. The real Level 1 hook for `git push origin
main` answered inactive: the gate had read the link to nothing as a missing file and taken side from packed-refs, where
git does not resolve the name. The same with the link to refs/bisect/here, which git reads as a symbolic ref.

Property (contract D5, condition d, owner choice of 2026-10-13, 16:4x Berlin, A): the exception applies only to a ref
store in the normal form the gate reads; no filesystem symbolic link in the ref store of any worktree, a loose entry
included. Each case first takes git's own answer in other with `git rev-parse --verify`. Red against 101bd167.
"""
from __future__ import annotations

import os
import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

OFF_FORM = "the ref store is not in the form the gate reads"


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _side_packed_and_named_by_other(tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "branch", "side", a)
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    w1._git(work, "pack-refs", "--all")
    w1._git(other, "symbolic-ref", "ORIG_HEAD", "refs/heads/side")
    return work, other


@pytest.mark.parametrize("target", ["no-target", "refs/bisect/here"])
def test_the_reviewers_case_a_loose_entry_that_is_a_symbolic_link(env, tmp_path, target):
    work, other = _side_packed_and_named_by_other(tmp_path)
    link = work / ".git" / "refs" / "heads" / "side"
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, link)
    assert not _git_resolves(other, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a symbolic link): refs/heads/side")


def test_control_without_the_link_keeps_the_exception(env, tmp_path):
    work, other = _side_packed_and_named_by_other(tmp_path)
    assert _git_resolves(other, "ORIG_HEAD")
    w1._assert_inactive(*w1._l1(env, work))
