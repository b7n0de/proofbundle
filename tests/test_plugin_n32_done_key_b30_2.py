"""B30-2, follow-up note 32, point 1: the block of the Stop hook names the key file `done-init --key` made.

Measured in follow-up note 30 (messung/stop_hook, with_key_option): `done-init --key <path>` made the key at that path, and
the block of the Stop hook named the default key file of the gate directory, a file that did not exist, so the command
the block named could not close the check. The rule: done-init records in the gate directory the key file it made for
the repository (a path, never a key), and the command of a block names, in this order, PROOFBUNDLE_KEY where it is an
absolute path, the recorded key file, and the default key file of the gate directory.

RED at 89d2e8b7 (the head of follow-up note 31): the block after `done-init --key` and the record. The default and
PROOFBUNDLE_KEY are controls, green at both.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import test_plugin_done_check as dc
from _owner_state import owner_state_protected  # noqa: F401 - D128: a person's record of the key file is read

gate = dc.gate
env = dc.env
repo = dc.repo
GATE = dc.GATE
#: The name of the record in the gate directory, written out so that the controls also run where the gate has none.
RECORD = "done-keys.json"


def _init(env: dict, repo: pathlib.Path, *key: str) -> subprocess.CompletedProcess:
    args = ["--key", key[0]] if key else []
    proc = subprocess.run([sys.executable, "-I", str(GATE), "done-init", "--repo", str(repo), *args],
                          capture_output=True, text=True, env=env, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    dc._git(repo, "commit", "-q", "-m", "declare the done check")
    return proc


def _named_key(answer: dict | None) -> str:
    reason = dc.blocked(answer)
    marker = "PROOFBUNDLE_KEY="
    assert marker in reason, reason
    return reason.split(marker, 1)[1].split(" ", 1)[0]


def test_B30_2_the_block_names_the_key_file_done_init_made_elsewhere(env, repo, tmp_path):
    key = tmp_path / "keys" / "my-done.key"
    key.parent.mkdir()
    _init(env, repo, str(key))
    assert key.is_file() and not (pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_KEY_FILE).exists()
    assert _named_key(dc.stop(env, repo)[1]) == str(key)


def test_B30_2_the_record_holds_a_path_per_repository_and_no_key(env, repo, tmp_path):
    key = tmp_path / "keys" / "my-done.key"
    key.parent.mkdir()
    _init(env, repo, str(key))
    assert gate.DONE_KEYS_RECORD == RECORD
    record = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / RECORD
    assert json.loads(record.read_text()) == {os.path.realpath(repo): str(key)}
    assert record.stat().st_mode & 0o777 == 0o600
    assert key.read_bytes() not in record.read_bytes()


def test_B30_2_control_without_key_the_default_key_file_is_named(env, repo):
    _init(env, repo)
    assert _named_key(dc.stop(env, repo)[1]) == str(pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_KEY_FILE)


def test_B30_2_control_proofbundle_key_goes_first(env, repo, tmp_path):
    key = tmp_path / "keys" / "my-done.key"
    key.parent.mkdir()
    _init(env, repo, str(key))
    named = dict(env, PROOFBUNDLE_KEY=str(tmp_path / "other.key"))
    assert _named_key(dc.stop(named, repo)[1]) == str(tmp_path / "other.key")


def test_B30_2_control_a_record_for_another_repository_is_not_used(env, repo, tmp_path):
    _init(env, repo)
    record = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / RECORD
    record.write_text(json.dumps({str(tmp_path / "elsewhere"): str(tmp_path / "x.key")}))
    assert _named_key(dc.stop(env, repo)[1]) == str(pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_KEY_FILE)


def test_B30_2_control_a_record_the_gate_does_not_read_names_the_default(env, repo, tmp_path):
    _init(env, repo)
    record = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / RECORD
    default = str(pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_KEY_FILE)
    for n, content in enumerate(("not json", json.dumps([str(tmp_path / "x.key")]),
                                 json.dumps({os.path.realpath(repo): "relative.key"}))):
        record.write_text(content)
        assert _named_key(dc.stop(env, repo, _event(repo, n))[1]) == default, content
    record.unlink()
    os.mkfifo(record)
    assert _named_key(dc.stop(env, repo, _event(repo, 9))[1]) == default


def _event(repo: pathlib.Path, n: int) -> dict:
    """A Stop event of a session of its own, so the end after three blocks of one session does not take part."""
    return {"hook_event_name": "Stop", "session_id": f"s{n}", "cwd": str(repo), "stop_hook_active": False}


def test_B30_2_the_output_of_done_init_names_the_key_it_made(env, repo, tmp_path):
    key = tmp_path / "keys" / "my-done.key"
    key.parent.mkdir()
    proc = _init(env, repo, str(key))
    assert "PROOFBUNDLE_KEY=" + str(key) in proc.stdout and "does not record" not in proc.stdout
