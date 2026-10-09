"""Review round 5 of 2026-10-09, the class of R5-1 in the push path: a fetch refspec is read as git reads it.

_fetch_maps_cleanly removed every leading + of a fetch refspec (spec.lstrip("+")). git removes one, the force flag,
and reads a second as part of the source: measured with git 2.43.0, `++refs/heads/*:refs/remotes/origin/*` maps
nothing, so a fetch neither writes nor updates refs/remotes/origin/main. The gate read the same refspec as mapping
refs/heads/main onto origin/main and compared the push with a tracking ref git no longer keeps. Property (R3-2): the
tracking ref the comparison uses is the one the remote's fetch refspecs map the destination to; otherwise the target
is NOT MEASURED. Red against 3b1b4346.
"""
from __future__ import annotations

import subprocess

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

DOUBLE = "++refs/heads/*:refs/remotes/origin/*"


def test_git_maps_nothing_with_a_double_force_sign(tmp_path):
    """Non-vacuous: with the refspec, a fetch does not write the tracking ref again once it is gone."""
    r = n2c.Repo(tmp_path)
    _git(r.path, "config", "remote.origin.fetch", DOUBLE)
    _git(r.path, "update-ref", "-d", "refs/remotes/origin/main")
    _git(r.path, "fetch", "-q", "origin")
    listed = subprocess.run(["git", "-C", str(r.path), "for-each-ref", "refs/remotes"], capture_output=True, text=True,
                            timeout=60, check=True).stdout
    assert listed == "", listed


def test_a_push_compared_with_a_tracking_ref_git_does_not_keep_is_not_measured(env, tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "config", "remote.origin.fetch", DOUBLE)
    answer, entry = n2c._level1(env, r.path)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert entry["verdict"] != "pass", entry


def test_control_one_force_sign_maps_as_before(env, tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    answer, entry = n2c._level1(env, r.path)
    assert answer["hookSpecificOutput"].get("permissionDecision") is None, answer
    assert (entry["verdict"], entry["reason_ids"]) == ("pass", ["done"]), entry
