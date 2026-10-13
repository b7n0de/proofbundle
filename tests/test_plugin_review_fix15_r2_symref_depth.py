"""Review round 15 of 2026-10-13, R15-2: the gate follows no longer a chain of symbolic refs than git does.

Measured by the reviewer at 947d9f26 with git 2.51.1 and 2.43.0: in the other worktree, refs/bisect/end at a clean commit
A and refs/bisect/link4 -> end, link3 -> link4, link2 -> link3, link1 -> link2, ORIG_HEAD -> link1. git resolves 3 and 4
symbolic steps, ORIG_HEAD included; with 5 `git -C other rev-parse --verify --quiet ORIG_HEAD` ends with 1 and no object,
and Level 1 answered inactive (at f3b898bc it asked); with 6 it asked. git reads at most SYMREF_MAXDEPTH (5) refs for one
resolution, the record it starts from among them, and the gate had allowed the reading of the object at step five.

Property (contract D5, condition d): a record resolves for the gate only where git resolves it, counted as git counts:
every ref read, the first included. The same through shared names in the current worktree. Red against 8bb74c81.
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


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _chain(where, start, links, end):
    """start -> links[0] -> ... -> links[-1] -> end, written backwards; symbolic steps: len(links) + 1."""
    names = [*links, end]
    for here, there in reversed(list(zip([start, *links], names))):
        w1._git(where, "symbolic-ref", here, there)


@pytest.mark.parametrize("steps", [3, 4, 5, 6])
def test_the_reviewers_case_in_another_worktree(env, tmp_path, steps):
    work, _remote, a = w1._undeclared(tmp_path)
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    w1._git(other, "update-ref", "refs/bisect/end", a)
    _chain(other, "ORIG_HEAD", [f"refs/bisect/link{i}" for i in range(1, steps)], "refs/bisect/end")
    resolves = _git_resolves(other, "ORIG_HEAD")
    assert resolves == (steps <= 4), (steps, resolves)          # git's own answer, measured here
    answer, entry, text = w1._l1(env, work)
    if resolves:
        w1._assert_inactive(answer, entry, text)
    else:
        w1._assert_exception_refused(answer, entry, text, f"{NOT_ESTABLISHED}worktrees/other/ORIG_HEAD")


@pytest.mark.parametrize("steps", [4, 5])
def test_a_root_ref_of_this_worktree_through_shared_names(env, tmp_path, steps):
    """The shared refs of the chain resolve on their own, each within git's limit; the root ref does not."""
    work, _remote, _a = w1._undeclared(tmp_path)
    _chain(work, "ORIG_HEAD", [f"refs/heads/s{i}" for i in range(1, steps)], "refs/heads/main")
    assert _git_resolves(work, "refs/heads/s1")
    resolves = _git_resolves(work, "ORIG_HEAD")
    assert resolves == (steps <= 4), (steps, resolves)
    answer, entry, text = w1._l1(env, work)
    if resolves:
        w1._assert_inactive(answer, entry, text)
    else:
        w1._assert_exception_refused(answer, entry, text, f"{NOT_ESTABLISHED}ORIG_HEAD")
