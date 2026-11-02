"""Review round 5 of 2026-10-09, R5-2: a hook whose bytes the digest does not read makes the state unknown.

Measured by the reviewer at 9d333d1c: above MAX_HOOK_BYTES (4 MiB) _bound_state_digest put the fixed marker
`toolarge` where the content digest belongs. An executable .git/hooks/post-commit that writes `one` to a marker file,
padded by a comment to 4194433 bytes, was approved by a rule for `git commit --allow-empty -m approved`; replacing
`one` by `two` (same length, same mode) left the digest as it was, both real Claude hook processes answered
pass/approved_by_rule with state_match true, and git ran the changed hook.

Property: changed effective hook bytes change the bound state or make it unknown. A hook entry the digest does not
read in full is now unknown, so there is no digest, no rule acts and the form asks. Red against 9d333d1c. Codex never
frees a form by rule, so its lane is a control.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import time

import _git_version as _gv
import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's mode and rules are read

import test_plugin_gate_n24 as n24
from _plugin_env import plugin_env

gate = n24.gate
_clean_git_config = n24._clean_git_config

FORM = "git commit --allow-empty -m approved"


def _hook(repo: pathlib.Path, marker: pathlib.Path, word: str, size: int) -> pathlib.Path:
    head = f"#!/bin/sh\nprintf {word} > '{marker}'\n# "
    body = head + "x" * (size - len(head) - 1) + "\n"
    hook = repo / ".git" / "hooks" / "post-commit"
    hook.write_text(body, encoding="ascii")
    hook.chmod(0o755)
    assert hook.stat().st_size == size
    return hook


def _swap(hook: pathlib.Path) -> None:
    data = hook.read_bytes()
    assert data.count(b"printf one") == 1
    hook.write_bytes(data.replace(b"printf one", b"printf two"))


def _digest(repo: pathlib.Path) -> str | None:
    return gate._bound_state_digest(str(repo), time.monotonic() + 60, plugin_env())


def _commit(repo: pathlib.Path) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
                    "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "approved"], check=True, timeout=60)


@pytest.fixture
def large(tmp_path):
    repo = n24._repo(tmp_path)
    marker = tmp_path / "marker"
    return repo, marker, _hook(repo, marker, "one", 4194433)


def test_git_runs_the_large_hook_with_its_changed_bytes(large):
    """Non-vacuous: git starts the hook of 4194433 bytes, and after the swap it starts the changed one."""
    repo, marker, hook = large
    _commit(repo)
    assert marker.read_text() == "one"
    _swap(hook)
    assert hook.stat().st_size == 4194433 and os.access(hook, os.X_OK)
    _commit(repo)
    assert marker.read_text() == "two"


def test_the_digest_of_a_large_hook_is_unknown_or_follows_its_bytes(large):
    repo, _marker, hook = large
    before = _digest(repo)
    _swap(hook)
    after = _digest(repo)
    assert before is None or before != after, "a hook the digest did not read must not leave the digest as it was"
    assert after is None


def test_a_rule_does_not_free_the_commit_after_the_large_hook_changed(tmp_path, large):
    repo, _marker, hook = large
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    digest = _digest(repo) or "0" * 64
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": FORM, "effect": "free", "state_digest": digest}])
    _swap(hook)
    decision, entry = n24._hook(env, repo, "claude", FORM)
    assert decision == "ask" and "approved_by_rule" not in entry["reason_ids"], entry


def test_no_rule_frees_a_form_while_a_hook_is_too_large_to_read(tmp_path, large):
    """Before any change: with a hook the digest cannot read, the state is unknown and the form asks."""
    repo, _marker, _hook_path = large
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": FORM, "effect": "free",
                               "state_digest": _digest(repo) or "0" * 64}])
    decision, entry = n24._hook(env, repo, "claude", FORM)
    assert decision == "ask" and "approved_by_rule" not in entry["reason_ids"], entry


def test_codex_denies_before_and_after_the_change(tmp_path, large):
    repo, _marker, hook = large
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": FORM, "effect": "free",
                               "state_digest": _digest(repo) or "0" * 64}])
    before, _ = n24._hook(env, repo, "codex", FORM)
    _swap(hook)
    after, entry = n24._hook(env, repo, "codex", FORM)
    assert before == "deny" and after == "deny" and "approved_by_rule" not in entry["reason_ids"], entry


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
@pytest.mark.parametrize("size", [4096, gate.MAX_HOOK_BYTES])
def test_control_a_hook_read_in_full_is_bound_by_its_bytes(tmp_path, size):
    """The reviewer's control and the bound itself: a hook up to MAX_HOOK_BYTES is hashed, and a swap changes the
    digest; with a rule written before, the form asks again (git_form_not_free)."""
    repo = n24._repo(tmp_path)
    hook = _hook(repo, tmp_path / "marker", "one", size)
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    before = _digest(repo)
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": FORM, "effect": "free", "state_digest": before}])
    decision, entry = n24._hook(env, repo, "claude", FORM)
    assert decision is None and "approved_by_rule" in entry["reason_ids"], entry
    _swap(hook)
    assert before is not None and _digest(repo) not in (None, before)
    decision, entry = n24._hook(env, repo, "claude", FORM)
    assert decision == "ask" and "git_form_not_free" in entry["reason_ids"], entry


def test_one_byte_over_the_bound_is_unknown(tmp_path):
    repo = n24._repo(tmp_path)
    _hook(repo, tmp_path / "marker", "one", gate.MAX_HOOK_BYTES + 1)
    assert _digest(repo) is None


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_a_hook_entry_git_cannot_exec_is_bound_by_name_and_mode(tmp_path):
    """The other fixed marker of the digest, measured: git cannot exec a directory as a hook ("cannot exec ...
    Permission denied"), so a change inside it changes nothing git runs and the digest may stay; turning the entry into
    an executable file changes the digest."""
    repo = n24._repo(tmp_path)
    marker = tmp_path / "marker"
    entry = repo / ".git" / "hooks" / "post-commit"
    entry.mkdir(mode=0o755)
    (entry / "run").write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="ascii")
    (entry / "run").chmod(0o755)
    before = _digest(repo)
    out = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
                          "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "x"], capture_output=True,
                         text=True, timeout=60)
    assert "cannot exec" in out.stderr and not marker.exists(), out.stderr
    (entry / "run").write_text(f"#!/bin/sh\ntouch '{marker}' # changed\n", encoding="ascii")
    assert _digest(repo) == before is not None
    (entry / "run").unlink()
    entry.rmdir()
    _hook(repo, marker, "one", 4096)
    assert _digest(repo) not in (None, before)
