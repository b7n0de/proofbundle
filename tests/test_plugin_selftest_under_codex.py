"""The gate self-test under Codex reports NOT MEASURABLE and says why (finding 7 of review package -1, review A-7).

server/proofbundle_mcp.py said the self-test push is denied for a stale subject "under both hosts". Measured on
2026-10-26: under Codex (`--host codex`, PROOFBUNDLE_PLUGIN_HOST=codex) the gate denies the handed-out command
`git -C <work> push origin main` with reason codex_push_not_plain, before any evidence check, and gate_selftest_check
reports NOT MEASURABLE. The external review of -1 (A-7, AUSWERTUNGEN finding 3) keeps that result: a Codex form denial
does not test the stale-subject evidence check, so the check must not count it. The property held here: the note
prepare returns says which host is expected to reach the stale subject and that Codex does not; under Codex the
result stays NOT MEASURABLE with the target unchanged; under Claude Code the stale-subject deny is still found. A
deny logged before the self-test started, without a gate run, or by the other host is not counted.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import time

import test_plugin_gate_log as gl

pytestmark = gl.pytestmark
env = gl.env

CLAUDE_NOTE = "Claude Code is expected to deny it for a stale subject."
CODEX_NOTE = ("Codex rejects this command form before that evidence check, so the current self-test reports NOT "
              "MEASURABLE there.")


def _prepared(server_env: dict) -> dict:
    (prepared,) = gl._server(server_env, [("gate_selftest_prepare", {})])
    assert not prepared["is_error"], prepared
    return prepared


def _check(server_env: dict, prepared: dict) -> dict:
    (checked,) = gl._server(server_env, [("gate_selftest_check", {"work": prepared["work"],
                                                                  "started_at": prepared["started_at"]})])
    return checked


def _host_env(env: dict, tmp_path: pathlib.Path, host: str | None) -> dict:
    data = tmp_path / "data"
    server_env = dict(env, CLAUDE_PLUGIN_DATA=str(data), PLUGIN_DATA=str(data))
    if host:
        server_env["PROOFBUNDLE_PLUGIN_HOST"] = host
    return server_env


def test_under_codex_the_selftest_stays_not_measurable_and_its_note_says_why(env, tmp_path):
    server_env = _host_env(env, tmp_path, "codex")
    prepared = _prepared(server_env)
    answer, _ = gl._gate(server_env, tmp_path, prepared["command"], "--host", "codex")
    checked = _check(server_env, prepared)
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    logged = [json.loads(line) for line in pathlib.Path(checked["log_path"]).read_text(encoding="utf-8").splitlines()]
    assert [entry["reason_ids"] for entry in logged] == [["codex_push_not_plain"]], logged
    assert checked["result"] == "NOT MEASURABLE", checked
    assert checked["target_changed"] is False, checked
    assert CODEX_NOTE in " ".join(prepared["note"].split()), prepared["note"]


def test_under_claude_code_the_selftest_finds_the_stale_subject_deny(env, tmp_path):
    server_env = _host_env(env, tmp_path, None)
    prepared = _prepared(server_env)
    answer, _ = gl._gate(server_env, tmp_path, prepared["command"])
    checked = _check(server_env, prepared)
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    assert checked["result"] == "Expected denial logged; test target unchanged.", checked
    assert CLAUDE_NOTE in " ".join(prepared["note"].split()), prepared["note"]


def test_under_codex_without_a_gate_run_nothing_is_counted(env, tmp_path):
    server_env = _host_env(env, tmp_path, "codex")
    prepared = _prepared(server_env)
    checked = _check(server_env, prepared)
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert not checked["result"].startswith("Expected denial logged"), checked


def test_a_codex_deny_logged_before_the_selftest_started_is_not_counted(env, tmp_path):
    server_env = _host_env(env, tmp_path, "codex")
    earlier = _prepared(server_env)
    gl._gate(server_env, tmp_path, earlier["command"], "--host", "codex")
    time.sleep(1.1)                    # the log and started_at count whole seconds
    later = _prepared(server_env)
    checked = _check(server_env, later)
    for prepared in (earlier, later):
        shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert not checked["result"].startswith("Expected denial logged"), checked


def test_a_codex_deny_does_not_count_for_a_selftest_under_claude_code(env, tmp_path):
    server_env = _host_env(env, tmp_path, None)
    prepared = _prepared(server_env)
    gl._gate(server_env, tmp_path, prepared["command"], "--host", "codex")
    checked = _check(server_env, prepared)
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    assert not checked["result"].startswith("Expected denial logged"), checked
