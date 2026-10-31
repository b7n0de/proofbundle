"""Review round 4 of 2026-10-09, R4-1: the attribute files git reads without being told are part of the state digest.

Measured by the reviewer at f0e25574: with core.attributesFile unset, git reads $XDG_CONFIG_HOME/git/attributes, or
$HOME/.config/git/attributes when XDG_CONFIG_HOME is unset or empty. The digest bound only info/attributes and an
explicit core.attributesFile, so an unset key counted as "no attribute file". After a rule had freed `git status`,
changing that file moved `git check-attr` from `one` to `two` while the digest stayed and the real hook process still
answered pass/approved_by_rule. The same holds for the system file git reads unless GIT_ATTR_NOSYSTEM is set.

Property: a state approval is bound to the attribute sources git actually reads; a change of their bytes ends the old
state comparison, and a source the gate cannot name for sure leaves the digest unknown (the gate asks). The gate now
asks git itself (`git var GIT_ATTR_SYSTEM` and `git var GIT_ATTR_GLOBAL`, git 2.42 and later) which files those are.
Red against f0e25574: the digest, rule and system-file tests. Codex never frees a form by rule, so its lane is a
control that is the same before and after.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import time

import _git_version as _gv
import pytest

import test_plugin_gate_n24 as n24
from _plugin_env import plugin_env

gate = n24.gate
_clean_git_config = n24._clean_git_config


@pytest.fixture(params=["home", "xdg"])
def default_attributes(request, tmp_path, monkeypatch) -> tuple[pathlib.Path, pathlib.Path]:
    """A neutral repository with a committed a.txt, HOME on an empty test folder, global and system configuration on
    the null device, core.attributesFile unset, and the default attribute file git reads in this lane."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    if request.param == "home":
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        attrs = home / ".config" / "git" / "attributes"
    else:
        xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        attrs = xdg / "git" / "attributes"
    attrs.parent.mkdir(parents=True)
    attrs.write_text("a.txt review=one\n", encoding="utf-8")
    repo = n24._repo(tmp_path)
    return repo, attrs


def _attr(repo: pathlib.Path) -> str:
    return subprocess.run(["git", "-C", str(repo), "check-attr", "review", "--", "a.txt"], capture_output=True,
                          text=True, timeout=60, check=True).stdout.strip()


def _digest(repo: pathlib.Path) -> str | None:
    return gate._bound_state_digest(str(repo), time.monotonic() + 30,
                                    plugin_env(XDG_CONFIG_HOME=os.environ.get("XDG_CONFIG_HOME")))


def _gate_env(tmp_path: pathlib.Path) -> tuple[dict, pathlib.Path]:
    """n24's hook environment and the XDG_CONFIG_HOME this case set, so git in the hook reads the same attribute file
    as git in this process."""
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    return plugin_env(**env, XDG_CONFIG_HOME=os.environ.get("XDG_CONFIG_HOME")), gate_dir


def test_git_reads_the_default_attribute_file(default_attributes):
    """Non-vacuous: core.attributesFile is unset and git still reads the default file, and follows its change."""
    repo, attrs = default_attributes
    unset = subprocess.run(["git", "-C", str(repo), "config", "--get", "core.attributesFile"], capture_output=True,
                           timeout=60, check=False)
    assert unset.returncode == 1 and unset.stdout == b""
    assert _attr(repo).endswith("review: one")
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    assert _attr(repo).endswith("review: two")


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_the_digest_binds_the_default_attribute_file(default_attributes):
    repo, attrs = default_attributes
    before = _digest(repo)
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    after = _digest(repo)
    assert before is not None and after is not None
    assert before != after, "a change of the attribute file git reads must change the digest"


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_a_rule_bound_before_the_change_no_longer_frees(tmp_path, default_attributes):
    """The form is `git stash list`, which asks without a rule; `git status` was the form until review fix 18 part B, and
    class a (D34) frees it after the read profile without any rule."""
    repo, attrs = default_attributes
    env, gate_dir = _gate_env(tmp_path)
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": "git stash list", "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    decision, entry = n24._hook(env, repo, "claude", "git stash list")
    assert decision is None and "approved_by_rule" in entry["reason_ids"], entry
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    decision, entry = n24._hook(env, repo, "claude", "git stash list")
    assert decision == "ask", entry
    assert "approved_by_rule" not in entry["reason_ids"] and "git_form_not_free" in entry["reason_ids"], entry


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_codex_denies_before_and_after_the_change(tmp_path, default_attributes):
    """Control: under Codex no rule frees a form (D12/D16), so the answer is deny either side of the change."""
    repo, attrs = default_attributes
    env, gate_dir = _gate_env(tmp_path)
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": "git stash list", "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    before, _ = n24._hook(env, repo, "codex", "git stash list")
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    after, entry = n24._hook(env, repo, "codex", "git stash list")
    assert before == "deny" and after == "deny", entry
    assert "approved_by_rule" not in entry["reason_ids"]


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_control_an_explicit_utf8_attribute_file_changes_the_digest(tmp_path, monkeypatch):
    """The reviewer's control, green before and after: an explicit core.attributesFile was already bound."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    repo = n24._repo(tmp_path)
    attrs = tmp_path / "explicit-attributes"
    attrs.write_text("a.txt review=one\n", encoding="utf-8")
    n24._git(repo, "config", "core.attributesFile", str(attrs))
    before = _digest(repo)
    attrs.write_text("a.txt review=two\n", encoding="utf-8")
    assert _attr(repo).endswith("review: two")
    assert before is not None and before != _digest(repo)


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_without_home_and_xdg_git_reads_no_global_file_and_the_digest_stands(tmp_path, monkeypatch):
    """git var exits 1 with no value where git reads no global attribute file (measured with git 2.43): that is a
    known absence, not an unknown state, so the digest is computed."""
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    repo = n24._repo(tmp_path)
    probe = subprocess.run(["git", "-C", str(repo), "var", "GIT_ATTR_GLOBAL"], capture_output=True, timeout=60,
                           check=False)
    assert probe.returncode == 1 and probe.stdout == b""
    assert _digest(repo) is not None


class _FakeVar:
    """Answers the two attribute variables as given and passes every other git call through."""

    def __init__(self, answers: dict[str, subprocess.CompletedProcess]):
        self.answers = answers
        self.real = gate._git

    def __call__(self, repo, *args, deadline):
        if len(args) == 2 and args[0] == "var" and args[1] in self.answers:
            return self.answers[args[1]]
        return self.real(repo, *args, deadline=deadline)


def _answer(code: int, out: bytes) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["git"], code, out, b"")


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_the_digest_binds_the_system_attribute_file_git_names(tmp_path, monkeypatch):
    """Sibling: git reads $(prefix)/etc/gitattributes unless GIT_ATTR_NOSYSTEM is set; the test cannot write the
    real one, so git var's answer is pointed at a test file. Red at f0e25574, which never read the system file."""
    repo = n24._repo(tmp_path)
    system = tmp_path / "system-gitattributes"
    system.write_text("a.txt review=one\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_git", _FakeVar({"GIT_ATTR_SYSTEM": _answer(0, os.fsencode(system) + b"\n")}))
    before = _digest(repo)
    system.write_text("a.txt review=two\n", encoding="utf-8")
    after = _digest(repo)
    assert before is not None and after is not None and before != after


@pytest.mark.parametrize("name", ["GIT_ATTR_SYSTEM", "GIT_ATTR_GLOBAL"])
@pytest.mark.parametrize("answer", [_answer(129, b""), _answer(128, b""), _answer(0, b""), _answer(0, b"a\nb\n"),
                                    _answer(1, b"/x\n")])
def test_an_attribute_source_git_cannot_name_leaves_the_digest_unknown(tmp_path, monkeypatch, name, answer):
    """A git older than 2.42 does not know the variable (exit 129), a broken configuration exits 128, and an answer
    that is not one line or a value with exit 1 is not readable: the state is not determined, so the gate asks."""
    repo = n24._repo(tmp_path)
    monkeypatch.setattr(gate, "_git", _FakeVar({name: answer}))
    assert _digest(repo) is None


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_with_git_attr_nosystem_git_reads_no_system_file(tmp_path, monkeypatch):
    """Control: git var exits 1 for the system file under GIT_ATTR_NOSYSTEM (measured), and the digest stands."""
    monkeypatch.setenv("GIT_ATTR_NOSYSTEM", "1")
    repo = n24._repo(tmp_path)
    probe = subprocess.run(["git", "-C", str(repo), "var", "GIT_ATTR_SYSTEM"], capture_output=True, timeout=60,
                           check=False)
    assert probe.returncode == 1 and probe.stdout == b""
    assert _digest(repo) is not None
