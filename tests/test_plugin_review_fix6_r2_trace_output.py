"""Review round 6 of 2026-10-10, class search of R6-2: git's trace output does not make an absent key unreadable.

Found in this round's own class search, measured at 5714030c: R6-2 reads a key as absent only where git exits 1 and
says nothing, so that a key git cannot parse (exit 1 with "error: invalid key") is not read as unset. git's trace
variables write to stderr on every command, `git config --get` of an absent key included, so with GIT_TRACE=1 every
absent key read as unreadable and every push went NOT MEASURED; at b513ff5a the same pushes passed. The trace
variables change what git prints, not what it reads, so the gate's own reads run without them, as they run without
GIT_CONFIG and the pathspec names (R6-1 class). Red against 5714030c for GIT_TRACE, GIT_TRACE_SETUP, GIT_TRACE2,
GIT_TRACE2_EVENT and GIT_TRACE_PERFORMANCE.
"""
from __future__ import annotations

import json
import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment

TRACE = [("GIT_TRACE", "1"), ("GIT_TRACE", "2"), ("GIT_TRACE_SETUP", "1"), ("GIT_TRACE2", "1"),
         ("GIT_TRACE2_EVENT", "1"), ("GIT_TRACE_PERFORMANCE", "1"), ("GIT_TRACE_REFS", "1"),
         ("GIT_TRACE_SHALLOW", "1")]


def _outcome(answer: dict, entry: dict) -> tuple:
    """The full outcome of a Level 1 push: decision, reason ids, and whether it reached the destination check."""
    return (answer["hookSpecificOutput"].get("permissionDecision"), entry["verdict"], entry["reason_ids"],
            n2c.reached_destination(json.dumps(answer, ensure_ascii=False)))


def test_git_says_something_for_an_absent_key_under_trace(tmp_path):
    """Non-vacuous: under GIT_TRACE git exits 1 for an absent key and writes its trace to stderr."""
    r = n2c.Repo(tmp_path)
    out = subprocess.run(["git", "-C", str(r.path), "config", "--get", "branch.main.nothing"], capture_output=True,
                         env=dict(n2c.os.environ, GIT_TRACE="1"), timeout=60, check=False)
    assert out.returncode == 1 and out.stdout == b"" and b"trace: " in out.stderr, out


@pytest.mark.parametrize("command", ["git push", "git push origin main"])
@pytest.mark.parametrize("name,value", TRACE)
def test_a_push_under_a_trace_variable_is_judged_as_without_it(env, tmp_path, name, value, command):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    answer, entry = n2c._level1(dict(env, **{name: value}), r.path, command=command)
    n2c.assert_destination_not_measured(answer, entry)   # since R9-1 the destination check leaves it NOT MEASURED
    assert _outcome(answer, entry) == _outcome(*n2c._level1(env, r.path, command=command))
    assert n2c._level2(dict(env, **{name: value}), r.path).returncode == 0


@pytest.mark.parametrize("name,value", TRACE[:2])
def test_control_a_failed_done_check_under_trace_still_denies(env, tmp_path, name, value):
    r = n2c.Repo(tmp_path)   # no receipt
    _answer, entry = n2c._level1(dict(env, **{name: value}), r.path)
    assert (entry["verdict"], entry["reason_ids"]) == ("deny", ["no_receipt"]), entry
