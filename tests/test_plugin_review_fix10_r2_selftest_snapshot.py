"""Review round 10 of 2026-10-11, R10-2: a failed initial snapshot of the throwaway remote is no empty one.

Measured by the reviewer at 1698db61: only the first for-each-ref of prepare made to exit 128 with an empty stdout,
everything else real, the gate denying, the push not run, then check. Under git 2.43.0 and 2.51.1: _remote_refs returned
None, prepare stored an empty file through `or ""`, and check reported both change fields false.

Property: a snapshot that could not be taken stops prepare before the command is handed out (NOT MEASURABLE), and an
empty or foreign recorded listing, which cannot be the state after prepare's own push wrote main, makes the check NOT
MEASURABLE, never "unchanged", and its reason does not say that the target still equals the base. Red against
1698db61.
"""
from __future__ import annotations

import os
import pathlib
import shutil

import test_plugin_gate_log as gl

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


def _failing_first_listing(tmp_path: pathlib.Path) -> pathlib.Path:
    """A git on PATH that fails the first `for-each-ref` (exit 128, nothing on stdout) and runs every other call."""
    real = shutil.which("git")
    bin_dir, marker = tmp_path / "gitbin", tmp_path / "failed-once"
    bin_dir.mkdir()
    (bin_dir / "git").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do if [ "$a" = for-each-ref ] && [ ! -e "' + str(marker) + '" ]; then\n'
        '  : > "' + str(marker) + '"; echo "fatal: injected" >&2; exit 128; fi; done\n'
        f'exec "{real}" "$@"\n', encoding="utf-8")
    (bin_dir / "git").chmod(0o755)
    return bin_dir


def _temp(tmp_path: pathlib.Path) -> pathlib.Path:
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    return temp


def test_a_failed_first_snapshot_stops_prepare_before_the_command(env, tmp_path):
    bin_dir = _failing_first_listing(tmp_path)
    server_env = dict(env, TMPDIR=str(_temp(tmp_path)), PATH=f"{bin_dir}{os.pathsep}{env['PATH']}")
    (prepared,) = gl._server(server_env, [("gate_selftest_prepare", {})])
    assert (tmp_path / "failed-once").exists(), "the injection did not fire"
    assert prepared["is_error"] and prepared["error"].startswith("NOT MEASURABLE: "), prepared
    assert "command" not in prepared
    assert sorted(p.name for p in (tmp_path / "temp").iterdir()) == []


def _prepared(env: dict, tmp_path: pathlib.Path) -> tuple[dict, dict]:
    server_env = dict(env, TMPDIR=str(_temp(tmp_path)), CLAUDE_PLUGIN_DATA=str(tmp_path / "data"))
    (prepared,) = gl._server(server_env, [("gate_selftest_prepare", {})])
    assert not prepared["is_error"], prepared
    return prepared, server_env


def _check(server_env: dict, prepared: dict) -> dict:
    (checked,) = gl._server(server_env, [("gate_selftest_check", {"work": prepared["work"],
                                                                  "started_at": prepared["started_at"]})])
    return checked


def test_an_empty_recorded_snapshot_is_not_measurable(env, tmp_path):
    prepared, server_env = _prepared(env, tmp_path)
    (pathlib.Path(prepared["work"]).parent / "remote_refs").write_text("", encoding="utf-8")
    checked = _check(server_env, prepared)
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert checked["target_changed"] is None and checked["other_refs_changed"] is None, checked
    assert checked["result"] == "NOT MEASURABLE", checked
    assert "still equals" not in checked["reason"] and "could not be read or compared" in checked["reason"], checked


def test_a_recorded_snapshot_without_the_base_on_main_is_not_measurable(env, tmp_path):
    prepared, server_env = _prepared(env, tmp_path)
    path = pathlib.Path(prepared["work"]).parent / "remote_refs"
    path.write_text("refs/heads/other " + "1" * 40 + "\n", encoding="utf-8")
    checked = _check(server_env, prepared)
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert checked["target_changed"] is None and checked["result"] == "NOT MEASURABLE", checked


def test_control_the_recorded_snapshot_names_main_at_the_base(env, tmp_path):
    prepared, server_env = _prepared(env, tmp_path)
    root = pathlib.Path(prepared["work"]).parent
    base = (root / "base_oid").read_text(encoding="utf-8").strip()
    assert f"refs/heads/main {base}\n" in (root / "remote_refs").read_text(encoding="utf-8")
    checked = _check(server_env, prepared)
    shutil.rmtree(root)
    assert checked["target_changed"] is False and checked["other_refs_changed"] is False, checked
