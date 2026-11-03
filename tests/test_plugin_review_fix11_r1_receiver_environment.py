"""Review round 11 of 2026-10-12, R11-1: prepare reads the receiver's settings where the receiver reads them.

Measured by the reviewer at 3bbbf66f: an isolated HOME whose global core.hooksPath names a folder with an executable
post-receive that moves each updated ref back to its old value, and in the same environment for prepare, gate and push
GIT_CONFIG_COUNT=1, GIT_CONFIG_KEY_0=core.hooksPath, GIT_CONFIG_VALUE_0=<a path that does not exist>. Prepare handed out
its command, the gate denied it (stale_subject), git cleared the environment's configuration for the local receive-pack,
the global hook ran and moved main back, the push exited 0, and the check said "Expected denial logged; test target
unchanged." with target_changed=false and other_refs_changed=false. The same through GIT_CONFIG_PARAMETERS.

The class, measured here at 3bbbf66f with git 2.43.0: GIT_CONFIG names a file that only `git config` itself reads, so
prepare's `git config --get-all remote.origin.receivepack` read that file and not the HOME configuration the push reads;
with GIT_CONFIG=/dev/null and a receivepack in the HOME configuration the push wrote main into another repository, exit 0,
and the check reported the same "unchanged".

Property: before the command is handed out, the settings of the actual receiver are bound or refused as not
measurable. A `git config` query runs without GIT_CONFIG, as the push and the receiver read, and the hooks folder is
asked for both in the server's environment and in the one git gives a local receive-pack (git's local_repo_env cleared).
Each catch case runs the whole chain where prepare hands out the command: the real Level 1 hook, the push run anyway,
the check. Red against 3bbbf66f.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess

import pytest

import test_plugin_gate_log as gl
import test_plugin_review_fix10_r1_selftest_receiver as r1
from _plugin_env import plugin_env

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config

RESET = '#!/bin/sh\necho post-receive >> "{log}"\nwhile read old new ref; do git update-ref "$ref" "$old"; done\n'


def _reset_hooks(folder: pathlib.Path, log: pathlib.Path) -> pathlib.Path:
    folder.mkdir(parents=True)
    (folder / "post-receive").write_text(RESET.format(log=log), encoding="utf-8")
    (folder / "post-receive").chmod(0o755)
    return folder


def _home(tmp_path: pathlib.Path, text: str) -> pathlib.Path:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(text, encoding="utf-8")
    return home


def chain(env: dict, tmp_path: pathlib.Path, **names) -> dict:
    """gate_selftest_prepare in an environment; where it hands out the command, the real Level 1 hook over it, the push
    run anyway in the same environment, as a host that ignores the deny would, and gate_selftest_check. The server, the
    hook and the push share the environment, as in the review."""
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    full = dict(env, TMPDIR=str(temp), CLAUDE_PLUGIN_DATA=str(tmp_path / "data"),
                **{k: v for k, v in names.items() if v is not None})
    for key in [k for k, v in names.items() if v is None]:
        full.pop(key, None)
    (prepared,) = gl._server(full, [("gate_selftest_prepare", {})])
    if prepared["is_error"]:
        return {"refused": prepared["error"]}
    answer, _ = gl._gate(full, tmp_path, prepared["command"])
    push = subprocess.run(prepared["command"], shell=True, capture_output=True, text=True, env=full, timeout=60)
    (checked,) = gl._server(full, [("gate_selftest_check", {"work": prepared["work"],
                                                            "started_at": prepared["started_at"]})])
    shutil.rmtree(pathlib.Path(prepared["work"]).parent, ignore_errors=True)
    return {"gate": (answer or {}).get("hookSpecificOutput", {}).get("permissionDecision"),
            "push_exit": push.returncode, "result": checked["result"], "target_changed": checked["target_changed"],
            "other_refs_changed": checked["other_refs_changed"]}


def _refused(outcome: dict, tmp_path: pathlib.Path) -> None:
    assert "refused" in outcome, "prepare handed out the command: " + json.dumps(outcome)
    assert outcome["refused"].startswith("NOT MEASURABLE: "), outcome
    assert sorted(p.name for p in (tmp_path / "temp").iterdir()) == []


def test_git_gives_a_local_receive_pack_no_configuration_from_the_environment(tmp_path):
    """Non-vacuous: with the global hook and core.hooksPath pointed elsewhere through GIT_CONFIG_COUNT, the push exits
    0, the global hook runs in the receiver and moves main back."""
    work, bare = r1._pair(tmp_path)
    log = tmp_path / "hook.log"
    home = _home(tmp_path, f"[core]\n\thooksPath = {_reset_hooks(tmp_path / 'hk', log)}\n")
    before = r1._main(bare)
    environ = plugin_env(without=("GIT_CONFIG_GLOBAL",))
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], capture_output=True, text=True,
                          env=dict(environ, HOME=str(home), GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
                                   GIT_CONFIG_VALUE_0=str(tmp_path / "missing")), timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    assert r1._main(bare) == before and log.exists()


def test_git_config_reads_a_file_no_push_reads(tmp_path):
    """Non-vacuous: GIT_CONFIG=/dev/null empties `git config --get-all`, and the push still takes the receivepack of the
    HOME configuration and writes into another repository."""
    work, bare = r1._pair(tmp_path)
    other, wrapper, log = r1._wrapper(tmp_path)
    home = _home(tmp_path, f'[remote "origin"]\n\treceivepack = {wrapper}\n')
    environ = plugin_env(without=("GIT_CONFIG_GLOBAL",), HOME=str(home), GIT_CONFIG=os.devnull)
    asked = subprocess.run(["git", "-C", str(work), "config", "--get-all", "remote.origin.receivepack"],
                           capture_output=True, text=True, env=environ, timeout=60, check=False)
    assert (asked.returncode, asked.stdout) == (1, "")
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], capture_output=True, text=True,
                          env=environ, timeout=60, check=False)
    assert push.returncode == 0 and r1._main(other) and log.exists(), push.stderr


@pytest.mark.parametrize("carrier", ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"])
def test_the_reviewers_case_a_global_hook_behind_an_environment_value_is_not_measurable(env, tmp_path, carrier):
    hooks = _reset_hooks(tmp_path / "hk", tmp_path / "hook.log")
    home = _home(tmp_path, f"[core]\n\thooksPath = {hooks}\n")
    missing = str(tmp_path / "does" / "not" / "exist")
    names = ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": missing}
             if carrier == "GIT_CONFIG_COUNT" else {"GIT_CONFIG_PARAMETERS": f"'core.hooksPath'='{missing}'"})
    _refused(chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None, **names), tmp_path)


@pytest.mark.parametrize("key", ["remote.origin.receivepack", "remote.origin.vcs", "receive.procReceiveRefs",
                                 "remote.origin.push"])
def test_a_home_setting_behind_git_config_is_not_measurable(env, tmp_path, key):
    """GIT_CONFIG names a file only `git config` reads; the push and the receiver read the HOME configuration."""
    _other, wrapper, _log = r1._wrapper(tmp_path)
    section, _, name = key.rpartition(".")
    head = '[remote "origin"]' if section == "remote.origin" else f"[{section}]"
    value = {"receivepack": str(wrapper), "vcs": "probe", "procReceiveRefs": "refs/heads",
             "push": "refs/heads/main:refs/heads/elsewhere"}[name]
    home = _home(tmp_path, f"{head}\n\t{name} = {value}\n")
    _refused(chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None, GIT_CONFIG=os.devnull), tmp_path)


def test_control_an_environment_hooks_path_alone_is_measurable(env, tmp_path):
    """No hook anywhere: the environment names a folder that does not exist, the receiver takes its own hooks folder."""
    outcome = chain(env, tmp_path, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
                    GIT_CONFIG_VALUE_0=str(tmp_path / "missing"))
    assert "refused" not in outcome and outcome["target_changed"] is True, outcome


def test_control_git_config_naming_an_empty_file_is_measurable(env, tmp_path):
    (tmp_path / "empty.cfg").write_text("", encoding="utf-8")
    outcome = chain(env, tmp_path, GIT_CONFIG=str(tmp_path / "empty.cfg"))
    assert "refused" not in outcome and outcome["target_changed"] is True, outcome
