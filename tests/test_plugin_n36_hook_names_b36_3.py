"""B36-3, Nachtrag 36: for a read form only a hook counts that git starts for exactly this form, by its name in githooks(5).

At delta (Cowork, 2026-10-18 19:4xZ, gate 89d2e8b7 at the Farmer) `git status` kept asking in 2bedone: the hook directory
holds `pre-commit.local`, which the read profile counted as a hook of a name git does not document (D78). git never starts
such a file itself; only the dispatcher pre-commit calls it, and status starts no pre-commit.

Measured with git 2.43.0 under GIT_TRACE2_EVENT, each hook writing a marker (truth_hooks_n36.py of the delivery, 840 runs:
seven states of the work tree and the index, with and without GIT_OPTIONAL_LOCKS=0, in the hook directory, through
core.hooksPath and in a linked work tree, every name of githooks(5) and pre-commit.local, pre-push.vor-ruff-20260919,
post-index-change.local, post-index-change.sample and zz-unknown-name beside them): status and diff started
post-index-change in every state without GIT_OPTIONAL_LOCKS=0, and nothing else; no form started a file of another name.

The rule: for a form that walks the work tree, a file of the hook directory counts where its name, in lower case, is a
hook git starts for that form (_HOOKS_STARTED_BY_READ). Lower case, because git finds `Post-Index-Change` on a file system
that does not tell the cases apart. A file of any other name does not count. The other forms that read hooks (the state
check of add and commit, D40; fetch, D45; worktree add) keep counting such a name: that is point 5 of Nachtrag 33.

RED at 9e0d071b (the head of Nachtrag 34): status and diff with a file of a name git does not document. The counter cases
(post-index-change in either case, a sample, Codex, the siblings of point 5 of Nachtrag 33) are controls, green at both.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

WALKS = ["git status", "git status --short", "git -C {R} status --porcelain", "git diff", "git diff --stat",
         "git -C {R} diff --name-only", "git grep -n readme", "git ls-files"]
#: Files git never started in the 840 runs: delta's names and names like them.
OTHER_NAMES = ["pre-commit.local", "pre-push.vor-ruff-20260919", "post-index-change.local", "zz-unknown-name",
               "pre-commit.bak", "my-hook", "post-index-change~", "post-index-change.orig"]


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path))
    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60)
    (repo / "readme.md").write_text("readme\n")
    subprocess.run(["git", "-C", str(repo), "add", "readme.md"], check=True, timeout=60)
    return repo


def _hook(folder, name, body="#!/bin/sh\nexit 0\n"):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(body)
    (folder / name).chmod(0o755)


def decided(repo, form, host="claude"):
    out = gate.decide(form.replace("{R}", str(repo)), str(repo), time.monotonic() + 60, host)
    return None if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("name", OTHER_NAMES)
@pytest.mark.parametrize("form", WALKS)
def test_B36_3_a_file_git_does_not_start_does_not_count_for_a_read_form(repo, form, name):
    _hook(repo / ".git" / "hooks", name)
    assert decided(repo, form) == ("pass", ["free_after_read_profile"]), (form, name)


@pytest.mark.parametrize("form", ["git status", "git diff"])
def test_B36_3_through_core_hooks_path_and_beside_a_dispatcher(repo, tmp_path, form):
    """delta's layout: a dispatcher pre-commit that calls pre-commit.local, in a folder core.hooksPath names."""
    folder = tmp_path / "hooks"
    _hook(folder, "pre-commit", "#!/bin/sh\nexec \"$(dirname \"$0\")/pre-commit.local\" \"$@\"\n")
    _hook(folder, "pre-commit.local")
    _hook(folder, "pre-push.vor-ruff-20260919")
    subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", str(folder)], check=True, timeout=60)
    assert decided(repo, form) == ("pass", ["free_after_read_profile"]), form


@pytest.mark.parametrize("name", ["post-index-change", "Post-Index-Change", "POST-INDEX-CHANGE"])
@pytest.mark.parametrize("form", ["git status", "git status --short", "git diff", "git -C {R} diff --stat"])
def test_B36_3_control_post_index_change_keeps_status_and_diff_asking_in_any_case(repo, form, name):
    """status and diff start post-index-change (measured); a file system that does not tell the cases apart finds it
    under another case, so the name counts in lower case."""
    _hook(repo / ".git" / "hooks", name)
    decision, reasons = decided(repo, form)
    assert decision == "ask" and "free_after_read_profile" not in reasons, (form, name, reasons)


@pytest.mark.parametrize("form", ["git status", "git diff"])
def test_B36_3_control_a_sample_never_counts_and_codex_keeps_its_answer(repo, form):
    _hook(repo / ".git" / "hooks", "post-index-change.sample")
    assert decided(repo, form) == ("pass", ["free_after_read_profile"])
    _hook(repo / ".git" / "hooks", "pre-commit.local")
    decision, reasons = decided(repo, form, "codex")
    assert decision in ("ask", "deny") and not any(r.startswith("free_") for r in reasons), reasons


def test_B36_3_the_siblings_of_point_5_of_nachtrag_33_follow_d107(repo):
    """Changed in Nachtrag 33 (D107): point 5 settled the names for every count, so the state check of add and commit
    (D40) no longer counts a file of a name git does not document; a real pre-commit still counts."""
    _hook(repo / ".git" / "hooks", "pre-commit.local")
    decision, _reasons = decided(repo, "git add readme.md")
    assert decision == "pass", decision
    _hook(repo / ".git" / "hooks", "pre-commit")
    decision, _reasons = decided(repo, "git add readme.md")
    assert decision == "ask", decision


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_B36_3_truth_status_starts_post_index_change_and_no_file_of_another_name(tmp_path):
    """The truth the rule stands on, run here: git status in a work tree whose stat changed, every hook a marker."""
    repo = tmp_path / "t"
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, env=env, timeout=60)
    (repo / "a.txt").write_text("a\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, env=env, timeout=60)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "A"], check=True, env=env, timeout=60)
    marker = tmp_path / "marker"
    marker.mkdir()
    for name in ("post-index-change", "pre-commit", "pre-commit.local", "pre-push.vor-ruff-20260919",
                 "post-index-change.local"):
        _hook(repo / ".git" / "hooks", name, f"#!/bin/sh\necho x >> {marker}/{name}\nexit 0\n")
    then = time.time() - 100
    os.utime(repo / "a.txt", (then, then))
    trace = tmp_path / "trace.json"
    subprocess.run(["git", "status"], cwd=repo, env=dict(env, GIT_TRACE2_EVENT=str(trace)), check=True,
                   capture_output=True, timeout=60)
    traced = {json.loads(line).get("hook_name") for line in trace.read_text().splitlines()
              if json.loads(line).get("child_class") == "hook"}
    assert sorted(os.listdir(marker)) == ["post-index-change"] and traced == {"post-index-change"}
