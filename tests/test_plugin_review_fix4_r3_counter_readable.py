"""Review round 4 of 2026-10-09, R4-3: the counter the hook writes stays within the bound it reads with.

Measured by the reviewer at f0e25574: a valid order with max_blocks=1 and no receipt committed, three identical stops
with the same cwd and session_id="s" * 65536. Both host adapters answered block three times: done-state.json held the
session id verbatim, came to 65684 bytes, always said blocks=1, and the next read discarded it silently because it
exceeded MAX_STATE_BYTES (65536). No blocker, no counting warning. With a short id the second stop ended NOT DONE.

Property: a refusal with a known repository is counted or the failed count is visible, and the hook's own record stays
readable for the next count. The state file now binds the session by its sha256 (fixed length, whatever the host
sends), a done file that would exceed the read bound is never written (the write names why), and a present state file
the hook cannot read is named in the block instead of counting from one in silence. Red against f0e25574.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment

LONG = "s" * 65536


def _ordered(tmp_path: pathlib.Path, keys) -> pathlib.Path:
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._commit(repo, "the order")
    return repo


def stop(env: dict, cwd: pathlib.Path, host: str, session: str) -> dict | None:
    event = {"hook_event_name": "Stop", "session_id": session, "cwd": str(cwd), "stop_hook_active": False}
    argv = [sys.executable, "-I", str(dc.GATE), "stop"] + (["--host", "codex"] if host == "codex" else [])
    proc = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, cwd=cwd, timeout=180,
                          check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def _state(repo: pathlib.Path) -> pathlib.Path:
    return repo / gate.DONE_STATE


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_long_session_id_still_ends_in_the_blocker(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    first = stop(env, repo, host, LONG)
    assert first is not None and first.get("decision") == "block", first
    assert "could not count" not in first["reason"], first
    assert os.path.getsize(_state(repo)) <= gate.MAX_STATE_BYTES
    second = stop(env, repo, host, LONG)
    assert second is not None and set(second) == {"systemMessage"}, second
    assert second["systemMessage"].startswith("proofbundle done check: NOT DONE. The same open points stayed open "
                                              "through 1 blocks"), second
    blocker = json.loads((repo / gate.DONE_BLOCKER).read_text(encoding="utf-8"))
    assert blocker["verdict"] == "NOT DONE"
    assert os.path.getsize(repo / gate.DONE_BLOCKER) <= gate.MAX_STATE_BYTES


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_state_the_hook_writes_is_read_back_by_the_hook(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    stop(env, repo, host, LONG)
    doc = gate._read_done_file(str(repo), gate.DONE_STATE, "state")
    assert doc is not None and doc["blocks"] == 1, "the record the hook wrote must be readable for the next count"


def test_another_long_session_does_not_continue_the_count(env, tmp_path, keys):
    """The session binding stays exact: a different id of the same length starts its own count."""
    repo = _ordered(tmp_path, keys)
    stop(env, repo, "claude", LONG)
    other = stop(env, repo, "claude", "t" + LONG[1:])
    assert other is not None and other.get("decision") == "block", other


def test_a_present_state_file_the_hook_cannot_read_is_named(env, tmp_path, keys):
    """A state file that is too large to read (one an older gate wrote, or any other) does not restart the count in
    silence: the block names it, and the hook's own rewrite makes the next stop count again."""
    repo = _ordered(tmp_path, keys)
    (repo / ".proofbundle").mkdir(exist_ok=True)
    _state(repo).write_text(json.dumps({"schema": gate.DONE_FILES_SCHEMA.format("state"), "session": LONG,
                                        "open": [], "blocks": 1, "blocker": False}), encoding="utf-8")
    assert os.path.getsize(_state(repo)) > gate.MAX_STATE_BYTES
    answer = stop(env, repo, "claude", "s")
    assert answer is not None and answer.get("decision") == "block", answer
    assert "could not be read" in answer["reason"] and gate.DONE_STATE in answer["reason"], answer
    second = stop(env, repo, "claude", "s")
    assert second is not None and set(second) == {"systemMessage"}, second


def test_write_done_file_refuses_a_document_beyond_the_read_bound(tmp_path):
    """The writer's own check: a document whose bytes exceed MAX_STATE_BYTES is not written, and the caller is told."""
    repo = tmp_path / "repo"
    (repo / ".proofbundle").mkdir(parents=True)
    problem = gate._write_done_file(str(repo), gate.DONE_METRICS, {"schema": "x", "pad": "p" * gate.MAX_STATE_BYTES})
    assert problem is not None and "bytes" in problem, problem
    assert not (repo / gate.DONE_METRICS).exists()


def test_control_a_short_session_id_ends_in_the_blocker_at_the_second_stop(env, tmp_path, keys):
    repo = _ordered(tmp_path, keys)
    first = stop(env, repo, "claude", "s")
    assert first is not None and first.get("decision") == "block" and "could not count" not in first["reason"]
    second = stop(env, repo, "claude", "s")
    assert second is not None and set(second) == {"systemMessage"}, second
