"""D78, Ergänzung 1 to Nachtrag 31, point 2: for a read form only a hook counts that this form starts.

At delta (Cowork, 2026-10-18, list 1442Z) the three asks of D34 at `git status` and `git diff` came from the pre-commit
hook of the clone. Measured with git 2.43.0 under GIT_TRACE2_EVENT, every hook githooks(5) documents and one of another
name in place, each writing a marker (truth_hooks_e1.py of the delivery, 840 runs: seven states of the work tree and the
index, with and without GIT_OPTIONAL_LOCKS=0, in the hook directory, through core.hooksPath and in a linked work tree):
status and diff started post-index-change and nothing else, grep and ls-files no hook, log, show and stash list no hook
either; no form started pre-commit or the hook of the other name.

The rule: the read profile counts, for a form that walks the work tree, a hook that form starts (post-index-change for
status and diff) and a hook of a name git does not document; every other documented hook does not count for it.

RED at 0c4e10e8 (the head of Nachtrag 31 before Ergänzung 1): the read forms with a documented hook they do not start.
The counter cases (post-index-change, a name git does not document, Codex, a sample) are controls, green at both.
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

READS = ["git status", "git status --short", "git -C {R} status --porcelain", "git diff", "git diff --stat",
         "git -C {R} diff --name-only", "git grep -n readme", "git ls-files"]
NOT_STARTED = ["pre-commit", "commit-msg", "prepare-commit-msg", "post-commit", "pre-push", "post-checkout",
               "post-merge", "reference-transaction", "pre-auto-gc", "fsmonitor-watchman", "pre-rebase"]


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path))
    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60)
    (repo / "readme.md").write_text("readme\n")
    subprocess.run(["git", "-C", str(repo), "add", "readme.md"], check=True, timeout=60)
    return repo


def _hook(folder, name):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text("#!/bin/sh\nexit 0\n")
    (folder / name).chmod(0o755)


def decided(repo, form, host="claude"):
    out = gate.decide(form.replace("{R}", str(repo)), str(repo), time.monotonic() + 60, host)
    return None if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("hook", NOT_STARTED)
@pytest.mark.parametrize("form", READS)
def test_D78_a_hook_the_read_form_does_not_start_does_not_count(repo, form, hook):
    _hook(repo / ".git" / "hooks", hook)
    assert decided(repo, form) == ("pass", ["free_after_read_profile"]), (form, hook)


@pytest.mark.parametrize("form", READS)
def test_D78_through_core_hooks_path_too(repo, tmp_path, form):
    _hook(tmp_path / "hooks", "pre-commit")
    subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", str(tmp_path / "hooks")], check=True)
    assert decided(repo, form) == ("pass", ["free_after_read_profile"]), form


@pytest.mark.parametrize("form", ["git status", "git status --short", "git -C {R} status --porcelain", "git diff",
                                  "git diff --stat", "git -C {R} diff --name-only"])
@pytest.mark.parametrize("where", ["hook directory", "core.hooksPath"])
def test_D78_control_post_index_change_keeps_status_and_diff_asking(repo, tmp_path, form, where):
    folder = repo / ".git" / "hooks" if where == "hook directory" else tmp_path / "hooks"
    _hook(folder, "post-index-change")
    if where == "core.hooksPath":
        subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", str(folder)], check=True)
    decision, reasons = decided(repo, form)
    assert decision == "ask" and "free_after_read_profile" not in reasons, (form, reasons)


@pytest.mark.parametrize("form", ["git grep -n readme", "git ls-files"])
def test_D78_post_index_change_does_not_count_for_grep_and_ls_files(repo, form):
    """Measured: neither started it in any of the seven states."""
    _hook(repo / ".git" / "hooks", "post-index-change")
    assert decided(repo, form) == ("pass", ["free_after_read_profile"]), form


@pytest.mark.parametrize("hook", ["pre-push.vor-ruff-20260919", "my-hook", "pre-commit.bak", "Pre-Commit"])
@pytest.mark.parametrize("form", ["git status", "git diff"])
def test_D78_control_a_hook_of_a_name_git_does_not_document_still_counts(repo, form, hook):
    _hook(repo / ".git" / "hooks", hook)
    decision, reasons = decided(repo, form)
    assert decision == "ask" and "free_after_read_profile" not in reasons, (form, hook, reasons)


@pytest.mark.parametrize("form", ["git status", "git diff"])
def test_D78_control_under_codex_the_read_form_is_not_free(repo, form):
    _hook(repo / ".git" / "hooks", "pre-commit")
    decision, reasons = decided(repo, form, "codex")
    assert decision in ("ask", "deny") and not any(r.startswith("free_") for r in reasons), reasons


def test_D78_a_sample_never_counts(repo):
    _hook(repo / ".git" / "hooks", "post-index-change.sample")
    assert decided(repo, "git status") == ("pass", ["free_after_read_profile"])


def test_D78_the_sets_are_what_the_decision_names():
    assert gate._HOOKS_STARTED_BY_READ == {"status": {"post-index-change"}, "diff": {"post-index-change"},
                                           "grep": set(), "ls-files": set()}
    assert set(gate._HOOKS_STARTED_BY_READ) == gate._READ_WALKS
    assert len(gate._GIT_HOOK_NAMES) == 28 and "pre-commit" in gate._GIT_HOOK_NAMES
    assert gate._HOOKS_NOT_RUN_BY_FETCH < gate._GIT_HOOK_NAMES
