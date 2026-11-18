"""Review round 7 of 2026-10-10, R7-5: a count the hook could not record is named, on the end that writes the blocker too.

Measured by the reviewer at 0c88746f: after the blocker was written, the write of the count record failed and nothing
said so (_account_block dropped the return value of the second _write_done_file; the blocker's message named neither
a counting problem nor anything else). The next stop then reads the record from before that end.

Property: a write of the hook's own files that fails is named in the answer that depends on it, as R3-4 made the block
name a count it could not record. The class, found in the search: the blocker that could not be written dropped a
failed count write beside it, and a done end dropped a blocker it could not remove (the earlier NOT DONE then stood
beside done). A write failure is injected through the gate's own writer in a child process, since a root test process
can write any file. Red against 26d3397f. Both hosts.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6
import test_plugin_review_fix4_r3_counter_readable as r43
import test_plugin_review_fix6_r4_pass_names_record as r64

gate = dc.gate
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment

#: The Stop hook as the gate runs it, with one failure injected into the gate's own file writes or removals.
INJECTED = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import proofbundle_gate as g
mode = sys.argv[2]
real_write, real_unlink = g._write_done_file, os.unlink
def write(repo, name, doc):
    if mode in ("state", "both") and name == g.DONE_STATE and doc.get("blocker") is (mode == "state"):
        return f"{name} could not be written: injected failure"
    if mode == "both" and name == g.DONE_BLOCKER:
        return f"{name} could not be written: injected failure"
    return real_write(repo, name, doc)
def unlink(path, *args, **kwargs):
    if mode == "unlink" and path.endswith(g.DONE_BLOCKER.split("/")[-1]):
        raise PermissionError(1, "Operation not permitted (injected)", path)
    return real_unlink(path, *args, **kwargs)
g._write_done_file = write
g.os.unlink = unlink
sys.exit(g.main(sys.argv[3:]))
'''


def _stop(env: dict, repo: pathlib.Path, host: str, mode: str) -> dict | None:
    event = {"hook_event_name": "Stop", "session_id": "s", "cwd": str(repo), "stop_hook_active": False}
    argv = [sys.executable, "-I", "-c", INJECTED, str(dc.GATE.parent), mode, "stop"] + \
        (["--host", "codex"] if host == "codex" else [])
    proc = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, cwd=repo,
                          timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_blocker_end_names_a_count_it_could_not_record(env, tmp_path, keys, host):
    """max_blocks 1: the first stop blocks, the second writes the blocker and the count record fails."""
    repo = r43._ordered(tmp_path, keys)
    first = r43.stop(env, repo, host, "s")
    assert first is not None and first.get("decision") == "block", first
    answer = _stop(env, repo, host, "state")
    assert answer is not None and set(answer) == {"systemMessage"}, answer   # the end stands: the blocker is written
    message = answer["systemMessage"]
    assert message.startswith("proofbundle done check: NOT DONE.") and (repo / gate.DONE_BLOCKER).is_file(), message
    assert "could not record this end in its count" in message and "injected failure" in message, message
    assert json.loads((repo / gate.DONE_STATE).read_text(encoding="utf-8"))["blocker"] is False   # the old record


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_blocker_that_could_not_be_written_names_the_count_beside_it(env, tmp_path, keys, host):
    repo = r43._ordered(tmp_path, keys)
    r43.stop(env, repo, host, "s")
    answer = _stop(env, repo, host, "both")
    assert answer is not None and answer.get("decision") == "block", answer   # no blocker: the end does not stand
    assert "the blocker could not be written" in answer["reason"], answer
    assert "nor the block count" in answer["reason"], answer


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_done_end_names_an_earlier_blocker_it_could_not_remove(env, tmp_path, keys, host):
    repo = r64._done_repo(tmp_path, keys)
    (repo / ".proofbundle").mkdir(exist_ok=True)
    (repo / gate.DONE_BLOCKER).write_text("{}\n", encoding="utf-8")
    message = r64._message(_stop(env, repo, host, "unlink"))
    assert "could not be removed" in message and gate.DONE_BLOCKER in message, message


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_without_a_failure_the_blocker_end_and_the_done_end_say_nothing_more(env, tmp_path, keys, host):
    repo = r43._ordered(tmp_path, keys)
    r43.stop(env, repo, host, "s")
    message = _stop(env, repo, host, "none")["systemMessage"]
    assert "could not" not in message, message
    assert json.loads((repo / gate.DONE_STATE).read_text(encoding="utf-8"))["blocker"] is True
    (tmp_path / "done").mkdir()
    done = r64._done_repo(tmp_path / "done", keys)
    (done / ".proofbundle").mkdir(exist_ok=True)
    (done / gate.DONE_BLOCKER).write_text("{}\n", encoding="utf-8")
    message = r64._message(_stop(env, done, host, "none"))
    assert "could not" not in message and not (done / gate.DONE_BLOCKER).exists(), message
