"""Owner choice of 2026-10-13, 15:1x Berlin, on W-3 of review round 14: the reason names the gate's missing resolution.

Measured at 947d9f26 with git 2.43.0 (class search of R14-1, W-3): another worktree's refs/bisect/alias, a symbolic ref to
refs/bisect/packed, a name that stands only in packed-refs. git there resolves it (`git -C other rev-parse --verify
refs/bisect/alias` gives the commit); the gate, which reads that worktree's own records, does not, and its ask said "is
present, but git does not resolve it", a claim about git that does not hold.

Property: the ask stays, and its reason says that the gate cannot establish how the record resolves in its worktree,
with the record named; it claims nothing about git's resolution. Red against 947d9f26.
"""
from __future__ import annotations

import subprocess

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment

WORDING = ("The gate cannot establish how this local record resolves in its worktree, so the exception does not apply: "
           "worktrees/other/refs/bisect/alias")


def test_a_record_git_resolves_and_the_gate_does_not_is_named_without_a_claim_about_git(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    with open(work / ".git" / "packed-refs", "a", encoding="utf-8") as handle:
        handle.write(f"{a} refs/bisect/packed\n")
    w1._git(other, "symbolic-ref", "refs/bisect/alias", "refs/bisect/packed")
    there = subprocess.run(["git", "-C", str(other), "rev-parse", "--verify", "--quiet", "refs/bisect/alias"],
                           capture_output=True, text=True, check=False)
    assert (there.returncode, there.stdout.strip()) == (0, a), there
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, WORDING)
    assert "git does not resolve" not in text, text
