"""Review round 9 of 2026-10-11, R9-2: the self-test checks the target ref its offered push actually writes.

Measured by the reviewer at b288ee66: GIT_NAMESPACE=selftest-ns in the same environment for the server, the gate and the
host's push. gate_selftest_prepare, the command shown to the real PreToolUse gate, the stale_subject denial logged, then
the push run anyway as a host that does not enforce the denial would: exit 0, refs/namespaces/selftest-ns/refs/heads/main
became B, refs/heads/main stayed A, and gate_selftest_check reported target_changed=false and "Expected denial logged;
test target unchanged." Without the namespace the control reported target_changed=true. Under git 2.43.0 and 2.51.1.

Property: the target ref the self-test checks is the target ref of the push it hands out; equal paths and an equal URL do
not show that. A namespace in the server's environment is refused before the command is handed out (NOT MEASURABLE), and
so is a configured push mapping of the self-test's origin, which sends `push origin main` to another ref. The check
compares every ref of the throwaway remote with the state prepare recorded, so a push that wrote any other ref (a
namespace or a mapping only the host's shell carries) is a changed target, never an unchanged one. Red against b288ee66.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

import test_plugin_gate_log as gl

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


def _pair(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """A work repository whose main is pushed to a bare remote, and one more commit on main."""
    bare, work = tmp_path / "pair" / "remote.git", tmp_path / "pair" / "work"
    work.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    gl._git(work, "init", "-q", "-b", "main")
    (work / "a.txt").write_text("a\n", encoding="utf-8")
    gl._git(work, "add", "-A")
    gl._git(work, "commit", "-q", "-m", "a")
    gl._git(work, "remote", "add", "origin", str(bare))
    gl._git(work, "push", "-q", "origin", "HEAD:refs/heads/main")
    (work / "b.txt").write_text("b\n", encoding="utf-8")
    gl._git(work, "add", "-A")
    gl._git(work, "commit", "-q", "-m", "b")
    return work, bare


def _refs(bare: pathlib.Path) -> dict:
    out = subprocess.run(["git", "--git-dir", str(bare), "for-each-ref", "--format=%(refname) %(objectname)"],
                         capture_output=True, text=True, check=True).stdout
    return dict(line.split(" ", 1) for line in out.splitlines())


def test_git_writes_a_namespaced_push_under_refs_namespaces_and_leaves_main(tmp_path):
    """Non-vacuous: the namespace moves the ref the push writes."""
    work, bare = _pair(tmp_path)
    before = _refs(bare)
    head = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], check=True, capture_output=True,
                   env=dict(os.environ, GIT_NAMESPACE="selftest-ns"))
    after = _refs(bare)
    assert after["refs/heads/main"] == before["refs/heads/main"]
    assert after["refs/namespaces/selftest-ns/refs/heads/main"] == head


def test_git_sends_push_origin_main_to_the_ref_a_push_mapping_names(tmp_path):
    """Non-vacuous: a configured remote.origin.push maps `push origin main` to another ref."""
    work, bare = _pair(tmp_path)
    before = _refs(bare)
    subprocess.run(["git", "-C", str(work), "-c", "remote.origin.push=refs/heads/main:refs/heads/elsewhere", "push",
                    "-q", "origin", "main"], check=True, capture_output=True)
    after = _refs(bare)
    assert after["refs/heads/main"] == before["refs/heads/main"] and "refs/heads/elsewhere" in after


def _prepare(env: dict, tmp_path: pathlib.Path, **names: str) -> dict:
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    (prepared,) = gl._server(dict(env, TMPDIR=str(temp), **names), [("gate_selftest_prepare", {})])
    return prepared


def _left_behind(tmp_path: pathlib.Path) -> list[str]:
    return sorted(p.name for p in (tmp_path / "temp").iterdir())


@pytest.mark.parametrize("names", [
    {"GIT_NAMESPACE": "selftest-ns"},
    {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.push",
     "GIT_CONFIG_VALUE_0": "refs/heads/main:refs/heads/elsewhere"},
], ids=["namespace", "push-mapping"])
def test_a_setting_that_moves_the_target_ref_makes_the_selftest_not_measurable(env, tmp_path, names):
    prepared = _prepare(env, tmp_path, **names)
    assert prepared["is_error"] and prepared["error"].startswith("NOT MEASURABLE: "), prepared
    assert "command" not in prepared
    assert _left_behind(tmp_path) == [], names


def test_control_an_empty_namespace_is_no_namespace(env, tmp_path):
    """git reads an empty GIT_NAMESPACE as none, so the self-test is measurable."""
    prepared = _prepare(env, tmp_path, GIT_NAMESPACE="")
    assert not prepared["is_error"], prepared
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)


def _flow(env: dict, tmp_path: pathlib.Path, **shell: str) -> dict:
    """The review's flow: prepare, the gate denies the command, the push runs anyway in a shell with `shell` added to
    the environment (a host whose shell carries settings the server's environment does not), then the check."""
    data = tmp_path / "data"
    server_env = dict(env, CLAUDE_PLUGIN_DATA=str(data))
    (prepared,) = gl._server(server_env, [("gate_selftest_prepare", {})])
    assert not prepared["is_error"], prepared
    answer, _ = gl._gate(dict(server_env, **shell), tmp_path, prepared["command"])
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny"
    subprocess.run(prepared["command"], shell=True, check=True, capture_output=True, env=dict(server_env, **shell))
    (checked,) = gl._server(server_env, [("gate_selftest_check", {"work": prepared["work"],
                                                                  "started_at": prepared["started_at"]})])
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    return checked


@pytest.mark.parametrize("shell", [
    {"GIT_NAMESPACE": "selftest-ns"},
    {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.push",
     "GIT_CONFIG_VALUE_0": "refs/heads/main:refs/heads/elsewhere"},
], ids=["namespace", "push-mapping"])
def test_a_push_that_wrote_another_ref_of_the_throwaway_remote_is_a_changed_target(env, tmp_path, shell):
    checked = _flow(env, tmp_path, **shell)
    assert checked["target_changed"] is True, checked
    assert checked["result"] == "Expected denial logged; test target changed.", checked


def test_control_without_a_namespace_the_unenforced_push_changes_the_target(env, tmp_path):
    checked = _flow(env, tmp_path)
    assert (checked["target_changed"], checked["result"]) == (True, "Expected denial logged; test target changed.")
