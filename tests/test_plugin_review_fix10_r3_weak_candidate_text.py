"""Review round 10 of 2026-10-11, R10-3: the answer keeps a weak candidate weak and does not call it a refusal by git.

Measured by the reviewer at 1698db61: the fixture repository of test_plugin_gate_n2c_push_done, the remote's main at A,
local main at B; on the remote refs/remotes/refs/heads/main at A, the fetch rule
+refs/remotes/*:refs/recorded/origin/remotes/*, a fetch; Level 1 for `git push origin main`, then `git push --porcelain
--no-verify origin main`. Under git 2.43.0 and 2.51.1, also with refs/remotes/refs/heads/main/HEAD: the answer said git
refuses the push; git moved main from A to B with exit 0. The verdict ask/push_not_measured stays right.

Measured here as well (both versions): with main missing on the remote, git writes the weak candidate instead of main.
Property: the answer keeps whether git counts a recorded candidate as a strong or a weak match; a weak one is not
described as a refusal. Red against 1698db61.
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

WEAK = ("refs/remotes/refs/heads/main", "refs/remotes/refs/heads/main/HEAD")
RULE = "+refs/remotes/*:refs/recorded/origin/remotes/*"


def _on_remote(tmp_path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "--git-dir", str(tmp_path / "remote.git"), *args], capture_output=True, text=True,
                          timeout=60, check=False)


def _recorded_beside(env, tmp_path, name: str) -> n2c.Repo:
    r = n2c.Repo(tmp_path)
    r.make("valid")
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert _on_remote(tmp_path, "update-ref", name, a).returncode == 0
    _git(r.path, "config", "--add", "remote.origin.fetch", RULE)
    _git(r.path, "fetch", "-q", "origin")
    return r


@pytest.mark.parametrize("name", WEAK)
def test_git_pushes_main_beside_a_weak_candidate(env, tmp_path, name):
    """Non-vacuous: git moves main with exit 0 and leaves the weak candidate."""
    r = _recorded_beside(env, tmp_path, name)
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    b = n2c._rev(r.path, "HEAD")
    push = subprocess.run(["git", "-C", str(r.path), "push", "--porcelain", "--no-verify", "origin", "main"],
                          capture_output=True, text=True, timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    assert _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip() == b
    assert _on_remote(tmp_path, "rev-parse", name).stdout.strip() == a


@pytest.mark.parametrize("name", WEAK)
def test_git_writes_the_weak_candidate_where_main_is_missing(env, tmp_path, name):
    """Non-vacuous for the wording: a weak match counts where the remote holds no strong one."""
    r = _recorded_beside(env, tmp_path, name)
    assert _on_remote(tmp_path, "update-ref", "-d", "refs/heads/main").returncode == 0
    push = subprocess.run(["git", "-C", str(r.path), "push", "--porcelain", "--no-verify", "origin", "main"],
                          capture_output=True, text=True, timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    assert _on_remote(tmp_path, "rev-parse", name).stdout.strip() == n2c._rev(r.path, "HEAD")


@pytest.mark.parametrize("name", WEAK)
def test_the_answer_does_not_call_a_weak_candidate_a_refusal(env, tmp_path, name):
    r = _recorded_beside(env, tmp_path, name)
    answer, entry = n2c._level1(env, r.path, command="git push origin main")
    text = json.dumps(answer, ensure_ascii=False)
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    assert f"this repository records {name}" in text, text
    assert "refuses the push" not in text, text
    assert "weak" in text, text


def test_control_a_strong_recorded_candidate_is_still_named_as_one_git_refuses_beside_main(env, tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert _on_remote(tmp_path, "update-ref", "refs/tags/refs/heads/main", a).returncode == 0
    _git(r.path, "fetch", "-q", "origin")
    answer, _entry = n2c._level1(env, r.path, command="git push origin main")
    text = json.dumps(answer, ensure_ascii=False)
    assert "this repository records refs/tags/refs/heads/main" in text and "refuses the push" in text, text
