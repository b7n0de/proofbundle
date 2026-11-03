"""Review round 7 of 2026-10-10, R7-3: every push value git reads is read, whatever the case needs.

Measured by the reviewer at 0c88746f: push.default simple, an upstream set, push.autoSetupRemote=invalid. `git push
--dry-run` exits 128 ("bad boolean config value"), the gate passed the bare push with done: _default_push read the key
only where the branch had no upstream. Suspected by the reviewer: the returns for `current` and for `simple` to another
remote skip the check as well.

Property: the gate reads every input from the same source and in the same meaning as git. git parses the push
configuration at the start of every push, every value of every key, whatever the push needs (measured with git 2.43.0
and 2.51.1, the push names compiled into both): push.autoSetupRemote, followTags, useForceIfIncludes, negotiate,
useBitmaps, submodule.recurse as booleans, push.gpgSign as a boolean or if-asked, push.recurseSubmodules as false,
check, on-demand or only, push.pushOption with a value, color.push and color.push.<slot>. A value git refuses stops the
push, an invalid value before a valid one too, and on-demand or only push the submodules' commits besides. The keys of
remotes, branches and URL rewrites stop `git remote get-url`, and push.default, core.* and advice.* every read of the
gate, so those were NOT MEASURED already (controls below). Red against 0c88746f.
"""
from __future__ import annotations

import json
import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git


def _repo(tmp_path, lines: str = "") -> n2c.Repo:
    """main tracks origin/main (upstream set by `push -u`), one commit of work with a valid receipt; `lines` appended
    to .git/config as written, so a key without `=` and a value before another stay as they are."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    if lines:
        with open(r.path / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write(lines)
    return r


def _git_push(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "push", "--dry-run", "--porcelain", "--no-verify", *args],
                          capture_output=True, text=True, timeout=60, check=False)


def _verdict(env, repo, command: str) -> tuple[str, list, bool]:
    """The verdict, its reasons, and whether the resolution reached the destination check (R9-1)."""
    answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"], n2c.reached_destination(json.dumps(answer, ensure_ascii=False))


#: NOT MEASURED at the push configuration, before the destination check.
NOT_MEASURED = ("ask", ["push_not_measured"], False)
#: Every earlier step resolved; the destination check leaves the push NOT MEASURED since R9-1.
DESTINATION = ("ask", ["push_not_measured"], True)

STOPS = {   # each stops `git push` with exit 128 under 2.43.0 and 2.51.1
    "autoSetupRemote_invalid": "[push]\n\tautoSetupRemote = invalid\n",
    "autoSetupRemote_invalid_then_true": "[push]\n\tautoSetupRemote = invalid\n\tautoSetupRemote = true\n",
    "followTags_invalid_then_false": "[push]\n\tfollowTags = invalid\n\tfollowTags = false\n",
    "useForceIfIncludes_invalid": "[push]\n\tuseForceIfIncludes = invalid\n",
    "negotiate_invalid": "[push]\n\tnegotiate = invalid\n",
    "useBitmaps_invalid": "[push]\n\tuseBitmaps = invalid\n",
    "submodule_recurse_invalid": "[submodule]\n\trecurse = invalid\n",
    "gpgSign_invalid": "[push]\n\tgpgSign = invalid\n",
    "recurseSubmodules_invalid": "[push]\n\trecurseSubmodules = invalid\n",
    "recurseSubmodules_true": "[push]\n\trecurseSubmodules = true\n",
    "recurseSubmodules_without_value": "[push]\n\trecurseSubmodules\n",
    "recurseSubmodules_case": "[push]\n\trecurseSubmodules = On-Demand\n",
    "pushOption_without_value": "[push]\n\tpushOption\n",
    "color_push_invalid": "[color]\n\tpush = invalid\n",
    "color_push_error_invalid": "[color \"push\"]\n\terror = invalid\n",
}


@pytest.mark.parametrize("case", STOPS)
def test_git_stops_the_push_at_the_value(tmp_path, case):
    """Non-vacuous: git refuses the bare push and the explicit one alike, whatever the push needs."""
    r = _repo(tmp_path, STOPS[case])
    assert _git_push(r.path).returncode == 128, case
    assert _git_push(r.path, "origin", "main").returncode == 128, case


@pytest.mark.parametrize("case", STOPS)
def test_a_push_git_stops_at_its_configuration_is_not_measured(env, tmp_path, case):
    r = _repo(tmp_path, STOPS[case])
    assert _verdict(env, r.path, "git push") == NOT_MEASURED, case
    assert _verdict(env, r.path, "git push origin main") == NOT_MEASURED, case


@pytest.mark.parametrize("config", [
    "[push]\n\tdefault = current\n",                                  # the return for current
    "[push]\n\tdefault = simple\n[branch \"main\"]\n\tpushRemote = other\n",   # simple to another remote
])
def test_the_returns_without_an_upstream_read_check_the_value_too(env, tmp_path, config):
    """The reviewer's suspicion, measured: `current` and `simple` to another remote returned their target before
    push.autoSetupRemote was read."""
    r = _repo(tmp_path)
    subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "other.git")], check=True, timeout=60)
    _git(r.path, "remote", "add", "other", str(tmp_path / "other.git"))
    _git(r.path, "push", "-q", "--no-verify", "other", "origin/main:refs/heads/main")
    _git(r.path, "fetch", "-q", "other")
    with open(r.path / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write(config)
    assert _verdict(env, r.path, "git push") == DESTINATION   # the case resolves without the invalid value
    with open(r.path / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write("[push]\n\tautoSetupRemote = invalid\n")
    assert _git_push(r.path).returncode == 128
    assert _verdict(env, r.path, "git push") == NOT_MEASURED


@pytest.mark.parametrize("value", ["on-demand", "only"])
def test_a_push_that_also_pushes_submodules_is_not_measured(env, tmp_path, value):
    """Valid values that make git push the submodules' commits to their own remotes besides."""
    r = _repo(tmp_path, f"[push]\n\trecurseSubmodules = {value}\n")
    assert _verdict(env, r.path, "git push origin main") == NOT_MEASURED
    (tmp_path / "b").mkdir()
    r2 = _repo(tmp_path / "b", "[submodule]\n\trecurse = true\n")
    assert _verdict(env, r2.path, "git push origin main") == NOT_MEASURED


@pytest.mark.parametrize("lines", [
    "",
    "[push]\n\tautoSetupRemote = true\n",
    "[push]\n\tautoSetupRemote\n",                    # a key without `=` is true
    "[push]\n\tautoSetupRemote =\n",                  # an empty value is false
    "[push]\n\tfollowTags = false\n\tuseForceIfIncludes = yes\n\tnegotiate = off\n\tuseBitmaps = 0\n",
    "[push]\n\tgpgSign = false\n",
    "[push]\n\tgpgSign = IF-ASKED\n",
    "[push]\n\trecurseSubmodules = check\n",
    "[push]\n\trecurseSubmodules = no\n",
    "[submodule]\n\trecurse = false\n",
    "[color]\n\tpush = auto\n[color \"push\"]\n\terror = red bold\n",
])
def test_control_values_git_reads_leave_the_valid_push_passing(env, tmp_path, lines):
    """The valid push resolves past its configuration up to the destination check (since R9-1 that leaves it NOT
    MEASURED); the pre-push hook passes it."""
    r = _repo(tmp_path, lines)
    assert _git_push(r.path, "origin", "main").returncode == 0, lines
    for command in ("git push origin main", "git push"):
        n2c.assert_destination_not_measured(*n2c._level1(env, r.path, command=command))
    assert n2c._level2(env, r.path).returncode == 0, lines


@pytest.mark.parametrize("lines", [
    "[remote \"other\"]\n\turl = /nonexistent\n\tmirror = invalid\n",
    "[branch \"other\"]\n\tmerge\n",
    "[url \"x\"]\n\tinsteadOf\n",
    "[push]\n\tdefault = invalid\n\tdefault = simple\n",
    "[advice]\n\tpushNonFFCurrent = invalid\n",
])
def test_control_values_another_read_of_the_gate_stops_at_were_not_measured_already(env, tmp_path, lines):
    """remote.c keys stop `git remote get-url`, push.default and advice.* stop every read (the work tree read among
    them): NOT MEASURED before the fix, and still."""
    r = _repo(tmp_path, lines)
    assert _git_push(r.path).returncode == 128
    for command in ("git push", "git push origin main"):
        verdict, reasons, reached = _verdict(env, r.path, command)
        assert verdict == "ask" and reasons in (["push_not_measured"], ["not_a_work_tree"]), (command, reasons)
        assert not reached, command
