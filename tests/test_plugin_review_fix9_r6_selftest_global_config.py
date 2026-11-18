"""Review round 9 of 2026-10-11, R9-6: the self-test's throwaway git calls keep a switched-off global configuration off.

Measured by the reviewer at b288ee66: a test HOME with a .gitconfig whose core.hooksPath names a test folder, where a
post-commit and a pre-push hook append their names to a marker file; the server with that HOME and
GIT_CONFIG_GLOBAL=/dev/null. gate_selftest_prepare answered is_error=false and ran two post-commit hooks and one pre-push
hook: dropping every GIT_ name had dropped GIT_CONFIG_GLOBAL too. Under git 2.43.0 and 2.51.1.

Property: the throwaway calls run with the global and system configuration switched off explicitly and without anyone's
hooks; the check of the command handed to the host keeps the host's real environment. Red against b288ee66.
"""
from __future__ import annotations

import os
import pathlib
import shutil

import test_plugin_gate_log as gl

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


def _home(tmp_path: pathlib.Path, extra: str = "") -> tuple[pathlib.Path, pathlib.Path]:
    home, hooks, marker = tmp_path / "home", tmp_path / "hooks", tmp_path / "marker"
    hooks.mkdir()
    home.mkdir()
    for name in ("post-commit", "pre-push", "pre-commit", "commit-msg", "post-checkout", "reference-transaction"):
        (hooks / name).write_text(f'#!/bin/sh\necho {name} >> "{marker}"\n', encoding="utf-8")
        (hooks / name).chmod(0o755)
    (home / ".gitconfig").write_text(f"[core]\n\thooksPath = {hooks}\n{extra}", encoding="utf-8")
    return home, marker


def _prepare(env: dict, tmp_path: pathlib.Path, **names) -> dict:
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    server_env = dict(env, TMPDIR=str(temp), **names)
    for key in [k for k, v in names.items() if v is None]:
        server_env.pop(key)
    (prepared,) = gl._server(server_env, [("gate_selftest_prepare", {})])
    return prepared


def test_a_switched_off_global_configuration_starts_no_hook_of_it(env, tmp_path):
    home, marker = _home(tmp_path)
    prepared = _prepare(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=os.devnull)
    assert not prepared["is_error"], prepared
    assert not marker.exists(), marker.read_text(encoding="utf-8")
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)


def test_the_throwaway_calls_take_no_global_hooks_even_where_the_host_reads_its_global_configuration(env, tmp_path):
    home, marker = _home(tmp_path)
    prepared = _prepare(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None)
    assert not marker.exists(), marker.read_text(encoding="utf-8")
    if not prepared["is_error"]:
        shutil.rmtree(pathlib.Path(prepared["work"]).parent)


def test_the_check_of_the_offered_command_keeps_the_hosts_real_environment(env, tmp_path):
    """A global push rewrite the host reads sends the offered command elsewhere: the self-test is NOT MEASURABLE, and
    its own throwaway calls, which do not read it, got that far."""
    temp = tmp_path / "temp"
    home, marker = _home(tmp_path, f'[url "{tmp_path / "elsewhere"}/"]\n\tpushInsteadOf = {temp}/\n')
    prepared = _prepare(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None)
    assert prepared["is_error"] and prepared["error"].startswith("NOT MEASURABLE: "), prepared
    assert "another URL" in prepared["error"], prepared
    assert not marker.exists()
