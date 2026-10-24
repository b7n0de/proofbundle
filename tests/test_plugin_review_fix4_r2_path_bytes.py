"""Review round 4 of 2026-10-09, R4-2: a name git reads keeps its bytes through the gate's whole reading chain.

Measured by the reviewer at f0e25574: _config_entries decoded git's output with errors="replace", so a byte that is
not UTF-8 became U+FFFD (EF BF BD) before the gate resolved anything. With core.attributesFile naming `attr-<FF>`,
git read that file and followed its change from `one` to `two`, while the gate bound `attr-<EF BF BD>`, a file that
does not exist, as absent; the digest stayed and the real Claude hook process answered pass/approved_by_rule before
and after. Sibling: include.path naming a missing `included-<FF>.cfg` put the replaced name into the protected files
without a problem, decide_write returned None and the Claude write hook did not stop the write that git then read.
Asking git again afterwards does not help: the bytes were already replaced.

Property: a security-relevant name denotes the same filesystem bytes as it does for git, and a name the gate cannot
read without loss never enters a positive verdict as another, absent path. The gate now decodes git's paths,
configuration and repository layout with surrogateescape (os.fsdecode), so os.open and every git argument get the
original bytes back, and the digest serialises them as those bytes. Red against f0e25574: the digest, rule, include,
repository-path, value and rewrite-rule tests. Codex never frees a form by rule and denies every file-tool write, so
its lanes are controls that are the same before and after.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

import _git_version as _gv
import pytest

import test_plugin_gate_n24 as n24
from _plugin_env import plugin_env

gate = n24.gate
_clean_git_config = n24._clean_git_config

FF = b"\xff"


def _name(base: pathlib.Path, leaf: bytes) -> str:
    """A path whose last part carries a byte that is not UTF-8, as Python names it (os.fsdecode)."""
    return os.fsdecode(os.fsencode(str(base)) + b"/" + leaf)


def _git_bytes(repo: str, *args: str) -> bytes:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, timeout=60, check=True).stdout


def _attr(repo: str) -> bytes:
    return _git_bytes(repo, "check-attr", "review", "--", "a.txt").strip()


@pytest.fixture
def ff_attributes(tmp_path, monkeypatch) -> tuple[pathlib.Path, str]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    repo = n24._repo(tmp_path)
    attrs = _name(tmp_path, b"attr-" + FF)
    with open(attrs, "w", encoding="utf-8") as handle:
        handle.write("a.txt review=one\n")
    subprocess.run(["git", "-C", str(repo), "config", "core.attributesFile", attrs], check=True, timeout=60)
    return repo, attrs


def _rewrite(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _digest(repo: pathlib.Path | str) -> str | None:
    return gate._bound_state_digest(str(repo), time.monotonic() + 30, plugin_env())


def test_git_reads_the_file_with_the_byte(ff_attributes):
    """Non-vacuous: the configured name carries FF, the file on disk carries FF, and git follows its content."""
    repo, attrs = ff_attributes
    assert _git_bytes(str(repo), "config", "--get", "core.attributesFile").rstrip(b"\n").endswith(b"attr-" + FF)
    assert os.fsencode(attrs).endswith(b"attr-" + FF) and os.path.isfile(attrs)
    assert _attr(str(repo)).endswith(b"review: one")
    _rewrite(attrs, "a.txt review=two\n")
    assert _attr(str(repo)).endswith(b"review: two")


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_the_digest_binds_the_file_with_the_byte(ff_attributes):
    repo, attrs = ff_attributes
    before = _digest(repo)
    _rewrite(attrs, "a.txt review=two\n")
    after = _digest(repo)
    assert before is not None and after is not None and before != after


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_a_rule_bound_before_the_change_no_longer_frees(tmp_path, ff_attributes):
    repo, attrs = ff_attributes
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": "git status", "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    decision, entry = n24._hook(env, repo, "claude", "git status")
    assert decision is None and "approved_by_rule" in entry["reason_ids"], entry
    _rewrite(attrs, "a.txt review=two\n")
    decision, entry = n24._hook(env, repo, "claude", "git status")
    assert decision == "ask" and "approved_by_rule" not in entry["reason_ids"], entry


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_codex_denies_before_and_after_the_change(tmp_path, ff_attributes):
    repo, attrs = ff_attributes
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": "git status", "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    before, _ = n24._hook(env, repo, "codex", "git status")
    _rewrite(attrs, "a.txt review=two\n")
    after, entry = n24._hook(env, repo, "codex", "git status")
    assert before == "deny" and after == "deny" and "approved_by_rule" not in entry["reason_ids"], entry


# --- sibling: include.path onto a missing file whose name carries the byte -----------------------------------------
@pytest.fixture
def ff_include(tmp_path) -> tuple[pathlib.Path, str]:
    repo = n24._repo(tmp_path)
    included = _name(tmp_path, b"included-" + FF + b".cfg")
    subprocess.run(["git", "-C", str(repo), "config", "include.path", included], check=True, timeout=60)
    return repo, included


def _write_event(repo: pathlib.Path, target: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(repo),
                       "tool_input": {"file_path": target, "content": "[review]\n\tmarker = added\n"}})


def _write_hook(tmp_path: pathlib.Path, repo: pathlib.Path, target: str, host: str) -> str | None:
    env, _gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    proc = subprocess.run([sys.executable, "-I", str(n24.GATE), "--host", host], input=_write_event(repo, target),
                          capture_output=True, text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return answer.get("hookSpecificOutput", {}).get("permissionDecision")


def test_the_protected_files_name_the_include_with_its_bytes(ff_include):
    repo, included = ff_include
    files, _dirs, problem = gate._state_files(str(repo), time.monotonic() + 30)
    assert not problem
    assert included in files, ascii(sorted(f for f in files if "included" in f))
    assert not any("�" in f for f in files)


def test_decide_write_gates_the_include(ff_include):
    repo, included = ff_include
    outcome = gate.decide_write("Write", {"file_path": included, "content": "[review]\n\tmarker = added\n"},
                                str(repo), time.monotonic() + 30, host="claude")
    assert outcome is not None, "a write that adds configuration git reads is gated"
    assert gate.answer(outcome.decision, outcome.text, host="claude")["hookSpecificOutput"]["permissionDecision"] \
        == "ask"


def test_the_claude_write_hook_asks_for_the_include(tmp_path, ff_include):
    repo, included = ff_include
    assert _write_hook(tmp_path, repo, included, "claude") == "ask"


def test_the_codex_write_hook_denies_the_include(tmp_path, ff_include):
    """Control: Codex denies every file-tool write (review Runde 7, R7-6), before and after."""
    repo, included = ff_include
    assert _write_hook(tmp_path, repo, included, "codex") == "deny"


def test_git_reads_the_include_once_it_exists(ff_include):
    """Non-vacuous: once the file exists, git reads the marker from exactly that file."""
    repo, included = ff_include
    _rewrite(included, "[review]\n\tmarker = added\n")
    out = _git_bytes(str(repo), "config", "--show-origin", "--null", "--get", "review.marker")
    assert out.split(b"\0") == [b"file:" + os.fsencode(included), b"added", b""], out


# --- siblings: the repository layout, a configuration value and a rewrite rule --------------------------------------
@pytest.fixture
def ff_repo(tmp_path) -> pathlib.Path:
    repo = pathlib.Path(_name(tmp_path, b"r-" + FF))
    repo.mkdir()
    for args in (("init", "-q", "-b", "main"),):
        subprocess.run(["git", "-C", str(repo), *args], check=True, timeout=60)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True, timeout=60)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
                    "commit.gpgsign=false", "commit", "-q", "-m", "base"], check=True, timeout=60)
    return repo


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_a_new_hook_changes_the_digest_of_a_repository_whose_path_has_the_byte(ff_repo):
    before = _digest(ff_repo)
    hook = ff_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)
    after = _digest(ff_repo)
    assert before is not None and after is not None and before != after


@pytest.mark.parametrize("leaf", ["config", "hooks/pre-commit"])
def test_a_write_into_the_git_directory_of_that_repository_is_gated(ff_repo, leaf):
    target = str(ff_repo / ".git" / leaf)
    outcome = gate.decide_write("Write", {"file_path": target, "content": "x\n"}, str(ff_repo),
                                time.monotonic() + 30, host="claude")
    assert outcome is not None, ascii(target)
    assert gate.answer(outcome.decision, outcome.text, host="claude")["hookSpecificOutput"]["permissionDecision"] \
        == "ask"


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_a_value_changed_from_the_byte_to_the_replacement_character_changes_the_digest(tmp_path):
    repo = n24._repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "config", "review.value", os.fsdecode(b"x" + FF)], check=True,
                   timeout=60)
    before = _digest(repo)
    subprocess.run(["git", "-C", str(repo), "config", "review.value", "x�"], check=True, timeout=60)
    assert _git_bytes(str(repo), "config", "--get", "review.value") == b"x\xef\xbf\xbd\n"
    after = _digest(repo)
    assert before is not None and after is not None and before != after


def test_a_rewrite_rule_keeps_its_bytes(tmp_path):
    """A url.<base>.insteadOf prefix with FF does not match a URL that carries EF BF BD there, for git or the gate."""
    repo = n24._repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "config", "url.https://example.invalid/.insteadOf",
                    os.fsdecode(b"pb" + FF + b":")], check=True, timeout=60)
    rules = gate._rewrite_rules(str(repo), time.monotonic() + 30)
    assert [(kind, prefix) for kind, _base, prefix in rules] == [("insteadOf", os.fsdecode(b"pb" + FF + b":"))]
    assert gate._longest_rule("pb�:x", [(base, prefix) for _kind, base, prefix in rules]) is None
