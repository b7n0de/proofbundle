"""Review round 6 of 2026-10-10, R6-5: the remote list keeps a name's bytes, and a test says so.

Measured by the reviewer at b513ff5a: with the remote named `ori` + U+0085 + `gin`, the head answered `git push` to it
with pass and done, while mutation M1h of R5-1 (the remote list split on whitespace again) asked, and `git push
--dry-run` exited 0. M1h was not caught: no test pushed to a remote whose name holds a character str.split() takes for
whitespace, so the R5-1 report's "no verdict effect" held for its four measured cases only.

Property: a push to a configured remote whose name holds U+0085 is judged as git pushes it, pass where the receipt is
valid. Green at the head, red under M1h (the mutation run of this round).
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

NAME = "ori\u0085gin"


def _renamed(tmp_path) -> n2c.Repo:
    """main tracks the remote, now named ori<U+0085>gin (git moves its tracking refs and branch.main.remote along),
    one commit of work with a valid receipt."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "remote", "rename", "origin", NAME)
    return r


def test_git_lists_and_pushes_to_the_remote_of_that_name(tmp_path):
    """Non-vacuous: git lists the name with its bytes, str.split() makes two names of it, and git pushes to it."""
    r = _renamed(tmp_path)
    listed = subprocess.run(["git", "-C", str(r.path), "remote"], capture_output=True, timeout=60, check=True).stdout
    assert listed == NAME.encode("utf-8") + b"\n"
    assert listed.decode().split() == ["ori", "gin"]   # what M1h reads
    for args in ((NAME, "main"), ()):
        dry = subprocess.run(["git", "-C", str(r.path), "push", "--dry-run", "--no-verify", *args],
                             capture_output=True, text=True, timeout=60, check=False)
        assert dry.returncode == 0 and "main -> main" in dry.stderr, (args, dry.stderr)


@pytest.mark.parametrize("command", [f"git push {NAME} main", f"git push '{NAME}' main", "git push"])
def test_a_push_to_the_remote_of_that_name_passes(env, tmp_path, command):
    r = _renamed(tmp_path)
    answer, entry = n2c._level1(env, r.path, command=command)
    assert answer["hookSpecificOutput"].get("permissionDecision") is None, answer
    assert (entry["verdict"], entry["reason_ids"]) == ("pass", ["done"]), entry
