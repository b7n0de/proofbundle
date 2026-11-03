"""Review round 16 of 2026-10-13, R16-4: a root record whose bytes the gate read past.

Measured by the reviewer at 101bd167: a clean repository work with no declaration, a bare remote origin, a clean commit
A; work/.git/ORIG_HEAD holding a line feed, A and a line feed. `git rev-parse ORIG_HEAD` ended with 1, and the real
Level 1 hook for `git push origin main` answered inactive: the gate had skipped the empty line and read A. The same
under worktrees/other/ of a second worktree other, detached at A.

Property (contract D5, condition d, owner choice of 2026-10-13, 16:4x Berlin, A): every root record and loose ref file
holds exactly `<oid>LF` or `ref: <name>LF`, with no empty line before, no blank and no line after; FETCH_HEAD keeps its
own rule of lines. Any other form gives ask with the reason and the entry. Each case first takes git's own answer with
`git rev-parse --verify`. Red against 101bd167.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

OFF_FORM = "the ref store is not in the form the gate reads"
PLACES = ["work", "other"]


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _orig_head(tmp_path, place, content):
    work, _remote, a = w1._undeclared(tmp_path)
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    folder = work / ".git" if place == "work" else work / ".git" / "worktrees" / "other"
    (folder / "ORIG_HEAD").write_bytes(content(a).encode("ascii"))
    return work, (work if place == "work" else other), ("ORIG_HEAD" if place == "work" else "worktrees/other/ORIG_HEAD")


@pytest.mark.parametrize("place", PLACES)
def test_the_reviewers_case_an_empty_line_before_the_object(env, tmp_path, place):
    work, where, label = _orig_head(tmp_path, place, lambda a: f"\n{a}\n")
    assert not _git_resolves(where, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


@pytest.mark.parametrize("place", PLACES)
def test_control_the_object_alone_keeps_the_exception(env, tmp_path, place):
    work, where, _label = _orig_head(tmp_path, place, lambda a: f"{a}\n")
    assert _git_resolves(where, "ORIG_HEAD")
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/other")
