"""Review round 16 of 2026-10-13, R16-3: a name git's ref rules refuse on the worktree's own branch of a resolution.

Measured by the reviewer at 101bd167: a clean repository work with no declaration, a bare remote origin, a clean commit
A; a second worktree other, detached at A; work/.git/worktrees/other/refs/bisect/foo..bar holding A and a line feed,
and worktrees/other/ORIG_HEAD holding "ref: refs/bisect/foo..bar" and a line feed. The real Level 1 hook for `git push
origin main` answered inactive; git check-ref-format refuses the name, and git does not resolve ORIG_HEAD there. The
same for each name below.

Property (contract D5, condition d, owner choice of 2026-10-13, 16:4x Berlin, A): every name on every branch of a
resolution, the worktree's own branch included, passes git's ref rules (git check-ref-format); a name the gate does not
model gives ask with the reason and the entry. Each case first takes git's own answer with git check-ref-format and with
`git rev-parse --verify` in other. Red against 101bd167.
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
REFUSED = [".hidden", "foo..bar", "foo.lock", "foo~bar", "foo?bar", "foo[bar", "foo:bar", "foo@{bar", "foo bar",
           "foo\\bar", "foo."]


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _git_takes(name):
    return subprocess.run(["git", "check-ref-format", name], capture_output=True, check=False).returncode == 0


def _named_by_other(tmp_path, name):
    work, _remote, a = w1._undeclared(tmp_path)
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    folder = work / ".git" / "worktrees" / "other"
    (folder / "refs" / "bisect").mkdir(parents=True, exist_ok=True)
    (folder / "refs" / "bisect" / name).write_bytes(f"{a}\n".encode())
    (folder / "ORIG_HEAD").write_bytes(f"ref: refs/bisect/{name}\n".encode())
    return work, other


@pytest.mark.parametrize("name", REFUSED)
def test_the_reviewers_case_a_name_git_s_rules_refuse(env, tmp_path, name):
    work, other = _named_by_other(tmp_path, name)
    assert not _git_takes(f"refs/bisect/{name}") and not _git_resolves(other, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text,
                                 f"{OFF_FORM} (a name git's ref rules refuse): worktrees/other/refs/bisect/{name}")


def test_control_a_name_git_takes_keeps_the_exception(env, tmp_path):
    work, other = _named_by_other(tmp_path, "good")
    assert _git_takes("refs/bisect/good") and _git_resolves(other, "ORIG_HEAD")
    w1._assert_inactive(*w1._l1(env, work))
