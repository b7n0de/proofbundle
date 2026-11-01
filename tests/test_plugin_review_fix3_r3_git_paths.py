"""Review round 3 of 2026-10-09, R3-3: a path value of git's configuration is read with git's own interpolation.

Measured by the reviewer at 273763c3: core.attributesFile=%(prefix)/... named an attribute file A outside the
repository (git config --path --get gives exactly A). Changing A from `a review=one` to `a review=two` changed
git check-attr, while the state digest stayed the same, so a human rule for `git status` with that digest stayed
pass/approved_by_rule. And include.path=%(prefix)/... on a file that does not exist yet: decide_write for a Write to
exactly that file gave None, the file was missing from _state_files, and once created git read configuration from it.
os.path.expanduser reads `~` only; git also interpolates `%(prefix)/` and reads a relative value against its own base.

The class: four places that resolved a git path value with os.path.expanduser. Now the attribute file and every
include are resolved by git itself (git config --type=path), a relative attribute file against the work tree and a
relative include against the file that includes it; the origin of a configuration file is taken as git names it, and
the standard global files are protected under HOME as git reads it. A value git cannot resolve leaves the digest
unknown and the write NOT MEASURED. Red against 252333ec.
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


def _git_prefix() -> str:
    """git's runtime prefix, as git itself interpolates `%(prefix)/`."""
    out = subprocess.run(["git", "config", "--file", os.devnull, "--type=path", "--default", "%(prefix)/", "--get",
                          "pb.prefix"], capture_output=True, text=True, timeout=30, check=True)
    return out.stdout.rstrip("\n")


def _prefixed(path: pathlib.Path) -> str:
    return "%(prefix)/" + os.path.relpath(str(path), _git_prefix())


def _attr(repo: pathlib.Path) -> str:
    return n24._git(repo, "check-attr", "review", "--", "a.txt").stdout.strip()


def _digest(repo: pathlib.Path) -> str | None:
    return gate._bound_state_digest(str(repo), time.monotonic() + 30, plugin_env())


@pytest.fixture
def prefixed_attributes(tmp_path) -> tuple[pathlib.Path, pathlib.Path]:
    repo = n24._repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    attrs = outside / "attributes"
    attrs.write_text("a.txt review=one\n", encoding="utf-8")
    n24._git(repo, "config", "core.attributesFile", _prefixed(attrs))
    return repo, attrs


def test_git_reads_the_prefixed_attribute_file(prefixed_attributes):
    """Non-vacuous: git resolves the value to A and reads it."""
    repo, attrs = prefixed_attributes
    resolved = n24._git(repo, "config", "--path", "--get", "core.attributesFile").stdout.strip()
    assert os.path.realpath(resolved) == os.path.realpath(attrs)
    assert _attr(repo).endswith("review: one")


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_the_digest_binds_the_prefixed_attribute_file(prefixed_attributes):
    repo, attrs = prefixed_attributes
    before = _digest(repo)
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    assert _attr(repo).endswith("review: two")
    after = _digest(repo)
    assert before is not None and after is not None and before != after


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_a_rule_bound_before_the_attribute_change_no_longer_frees(tmp_path, prefixed_attributes):
    repo, attrs = prefixed_attributes
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": "git status", "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    assert n24._hook(env, repo, "claude", "git status")[0] is None          # the rule acts
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    decision, entry = n24._hook(env, repo, "claude", "git status")
    assert decision == "ask" and "approved_by_rule" not in entry["reason_ids"], entry


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_the_digest_binds_a_relative_attribute_file_under_the_work_tree(tmp_path):
    repo = n24._repo(tmp_path)
    (repo / "rel").mkdir()
    (repo / "rel" / "attrs").write_text("a.txt review=one\n", encoding="utf-8")
    n24._git(repo, "config", "core.attributesFile", "rel/attrs")
    assert _attr(repo).endswith("review: one")
    before = _digest(repo)
    (repo / "rel" / "attrs").write_text("a.txt review=two\n", encoding="utf-8")
    assert _attr(repo).endswith("review: two")
    assert before != _digest(repo)


@pytest.mark.parametrize("host,answer", [("claude", "ask"), ("codex", "deny")])
def test_a_missing_prefixed_include_is_write_protected(tmp_path, host, answer):
    repo = n24._repo(tmp_path)
    include = tmp_path / "outside" / "included.cfg"
    include.parent.mkdir()
    n24._git(repo, "config", "include.path", _prefixed(include))
    outcome = gate.decide_write("Write", {"file_path": str(include), "content": "[review]\n\tmarker = x\n"},
                                str(repo), time.monotonic() + 30, host=host)
    assert outcome is not None, "a write that adds configuration git reads is gated"
    assert gate.answer(outcome.decision, outcome.text, host=host)["hookSpecificOutput"]["permissionDecision"] == answer
    files, _dirs, problem = gate._state_files(str(repo), time.monotonic() + 30)
    assert not problem and os.path.realpath(str(include)) in {os.path.realpath(f) for f in files}
    include.write_text("[review]\n\tmarker = x\n", encoding="utf-8")
    assert n24._git(repo, "config", "--get", "review.marker").stdout.strip() == "x", "non-vacuous: git reads it"


def test_control_a_relative_include_names_the_file_beside_the_including_one(tmp_path):
    repo = n24._repo(tmp_path)
    n24._git(repo, "config", "include.path", "extra.cfg")
    files, _dirs, problem = gate._state_files(str(repo), time.monotonic() + 30)
    common = n24._common(repo)
    assert not problem and os.path.join(common, "extra.cfg") in {os.path.realpath(f) for f in files}


def test_a_value_git_cannot_resolve_leaves_the_digest_unknown(tmp_path):
    repo = n24._repo(tmp_path)
    n24._git(repo, "config", "core.attributesFile", "~no-such-user-pb-review/attrs")
    assert _digest(repo) is None
