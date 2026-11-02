"""Review round 5 of 2026-10-09, R5-1, the siblings in the push path: every name and list git prints keeps its bytes.

The class search after R5-1 found the same reading in the push resolution: a configuration value through
decode().strip() (`_config`), the remote list split on whitespace (`_remote_names`), the branch name of HEAD through
decode().strip(), and value lists, URLs and fetch refspecs through str.splitlines with blank lines dropped. Measured
with git 2.43.0 here: a pushRemote `origin ` (trailing blank, a configured remote) makes git push to that remote; a
branch `main` + U+0085 under push.default current makes git create that branch on the remote; a second pushurl of one
blank makes git push to both URLs; an insteadOf rule whose prefix holds U+0085 rewrites the URL git uses. In each
case the gate judged the push against origin/main as a resolved push and let it pass (the done check passed at the
pushed commit), where the target git writes to is not that ref: NOT MEASURED. Red against 9799a48e.
"""
from __future__ import annotations

import json
import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

NEL = "\u0085"


def _valid(tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    return r


def _remote_with_blank(r, tmp_path):
    other = tmp_path / "other.git"
    subprocess.run(["git", "init", "--bare", "-q", str(other)], check=True, timeout=60)
    _git(r.path, "config", "remote.origin .url", str(other))
    _git(r.path, "config", "remote.origin .fetch", "+refs/heads/*:refs/remotes/origin/*")
    _git(r.path, "config", "branch.main.pushRemote", "origin ")
    return "git push"


def _branch_with_nel(r, tmp_path):
    _git(r.path, "branch", "-m", "main", "main" + NEL)
    _git(r.path, "config", "push.default", "current")
    return "git push"


def _blank_pushurl(r, tmp_path):
    _git(r.path, "config", "--add", "remote.origin.pushurl", str(tmp_path / "remote.git"))
    _git(r.path, "config", "--add", "remote.origin.pushurl", " ")
    return "git push origin main"


def _rewrite_with_nel(r, tmp_path):
    """The remote's URL holds U+0085; the tracking ref was fetched before a rule that rewrites that URL appeared."""
    moved = tmp_path / ("o" + NEL + "rigin.git")
    (tmp_path / "remote.git").rename(moved)
    _git(r.path, "config", "remote.origin.url", str(moved))
    _git(r.path, "fetch", "-q", "origin")
    _git(r.path, "config", f"url.{tmp_path / 'elsewhere.git'}.insteadOf", str(tmp_path / ("o" + NEL)))
    return "git push origin main"


CASES = {"remote_name_blank": _remote_with_blank, "branch_name_nel": _branch_with_nel,
         "pushurl_blank": _blank_pushurl, "rewrite_prefix_nel": _rewrite_with_nel}


@pytest.mark.parametrize("case", list(CASES))
def test_the_push_is_not_judged_against_a_ref_git_does_not_write(env, tmp_path, case):
    r = _valid(tmp_path)
    command = CASES[case](r, tmp_path)
    answer, entry = n2c._level1(env, r.path, command=command)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", (case, answer)
    assert entry["verdict"] != "pass", entry
    assert not n2c.reached_destination(json.dumps(answer, ensure_ascii=False)), (case, answer)


def test_git_pushes_where_the_cases_say(tmp_path):
    """Non-vacuous: git itself sends each push to the target the case names."""
    seen = {}
    for case, make in CASES.items():
        base = tmp_path / case
        base.mkdir()
        r = n2c.Repo(base)
        command = make(r, base)
        out = subprocess.run(["git", "-C", str(r.path), *command.split()[1:], "--dry-run"], capture_output=True,
                             text=True, timeout=60, check=False)
        seen[case] = out.stderr
    assert "other.git" in seen["remote_name_blank"] and "remote.git" not in seen["remote_name_blank"]
    assert f"[new branch]      main{NEL} -> main{NEL}" in seen["branch_name_nel"]
    assert "' ' does not appear to be a git repository" in seen["pushurl_blank"]
    assert "elsewhere.git" in seen["rewrite_prefix_nel"]


def test_control_the_plain_push_with_a_valid_receipt_passes(env, tmp_path):
    """The plain push resolves up to the destination check, which since R9-1 leaves it NOT MEASURED; the pre-push
    hook passes it."""
    r = _valid(tmp_path)
    for command in ("git push", "git push origin main"):
        answer, entry = n2c._level1(env, r.path, command=command)
        n2c.assert_destination_not_measured(answer, entry)
    assert n2c._level2(env, r.path).returncode == 0
