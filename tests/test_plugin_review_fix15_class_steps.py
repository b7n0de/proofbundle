"""Review round 15 of 2026-10-13, R15-1 and R15-2: steps of a chain the catch cases of both had left uncovered.

Found by the mutation probe of review fix 15 at 8bb74c81 and 240220c2 with git 2.43.0: mutants of _resolves and _shared_ref
survived that read no packed-refs for a shared name, read no per-worktree ref of this worktree as a step, counted those
steps or a detached HEAD among the records, or let a name leave the ref store. Each case below first takes git's own
answer with `git rev-parse --verify` where it names a record, and requires the gate to agree with it. The fifth surviving
mutant, a shared symbolic ref not counted as the first ref read in another worktree, led to the defect the catch cases of
tests/test_plugin_review_fix15_r1_class_first_step.py hold.
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


def test_control_a_shared_step_that_stands_only_in_packed_refs(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "branch", "side", a)
    other = _other(work, tmp_path, a)
    w1._git(work, "pack-refs", "--all")
    assert not (work / ".git" / "refs" / "heads" / "side").exists()
    w1._git(other, "symbolic-ref", "ORIG_HEAD", "refs/heads/side")
    assert _git_resolves(other, "ORIG_HEAD")
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/other")


def test_control_a_root_ref_of_this_worktree_to_its_own_per_worktree_ref(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "update-ref", "refs/bisect/good", a)
    w1._git(work, "symbolic-ref", "ORIG_HEAD", "refs/bisect/good")
    assert _git_resolves(work, "ORIG_HEAD")
    # Narrow contract of 2026-10-13, 17:0x: a symbolic ref other than HEAD and refs/remotes/<remote>/HEAD is asked.
    w1._assert_outside(*w1._l1(env, work), "a symbolic ref other than HEAD and refs/remotes/<remote>/HEAD", "ORIG_HEAD")


def test_control_the_steps_of_this_worktree_are_not_counted_twice(env, tmp_path):
    """A detached HEAD and a per-worktree ref of this worktree: git's listing counts the second, condition b the first."""
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "update-ref", "refs/bisect/good", a)
    w1._git(work, "checkout", "-q", "--detach")
    answer, entry, text = w1._l1(env, work, "git push origin HEAD:refs/heads/main")
    w1._assert_inactive(answer, entry, text)
    listed = len(w1._git(work, "for-each-ref", "--format=%(refname)").stdout.split())
    fetched = len((work / ".git" / "FETCH_HEAD").read_text(encoding="utf-8").splitlines())
    assert f"at any of the {listed + fetched} local refs of this repository" in text, text


def test_a_name_that_leaves_the_ref_store_does_not_resolve(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    (work / "outside").write_text(f"{a}\n", encoding="utf-8")         # work/.git/refs/../../outside
    (work / ".git" / "worktrees" / "other" / "ORIG_HEAD").write_text("ref: refs/../../outside\n", encoding="utf-8")
    assert not _git_resolves(other, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    # Since review round 16 of 2026-10-13 a target git's ref rules refuse is off the normal form of the ref store.
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")
