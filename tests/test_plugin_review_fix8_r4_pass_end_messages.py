"""Review round 8 of 2026-10-10, R8-4: a done end names each failure of its own files for what it is.

Measured by the reviewer at 1fc58527: the done fixture, an earlier blocker, a count record with blocks "1" as a string,
and only the removal of the blocker failing with PermissionError. Afterwards the record held a valid blocks 0, yet the
answer said the end could not be counted, and the note that an unreadable record had been replaced was missing; under
Claude Code and Codex alike. _account_pass joined the failed removal into the count problem, and stop_command dropped
the unread record whenever any problem was named.

Property: a write of the hook's own files that fails is named in the answer that depends on it, and only a failure that
happened is named. A failed write of the record, a failed removal of the blocker and a record the hook could not read
are three facts, each named on its own; that the hook wrote its own record is said only where it did. The failures are
injected through the gate's own writer and os.unlink in a child process, since a root test process can write any file.
Red against fc679bfc. Both hosts.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6
import test_plugin_review_fix6_r4_pass_names_record as r64

gate = dc.gate
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment

#: The Stop hook as the gate runs it, with the write of the count record, the removal of the blocker, or both failing.
INJECTED = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import proofbundle_gate as g
mode = sys.argv[2]
real_write, real_unlink = g._write_done_file, os.unlink
def write(repo, name, doc):
    if mode in ("write", "both") and name == g.DONE_STATE:
        return f"{name} could not be written: injected failure"
    return real_write(repo, name, doc)
def unlink(path, *args, **kwargs):
    if mode in ("unlink", "both") and path.endswith(g.DONE_BLOCKER.split("/")[-1]):
        raise PermissionError(1, "Operation not permitted (injected)", path)
    return real_unlink(path, *args, **kwargs)
g._write_done_file = write
g.os.unlink = unlink
sys.exit(g.main(sys.argv[3:]))
'''

COUNT_FAILED = "could not record this end in its count"
UNREAD = "could not be read"
REPLACED = "the hook wrote its own record in its place"


def _stop(env: dict, repo: pathlib.Path, host: str, mode: str) -> str:
    event = {"hook_event_name": "Stop", "session_id": "s", "cwd": str(repo), "stop_hook_active": False}
    argv = [sys.executable, "-I", "-c", INJECTED, str(dc.GATE.parent), mode, "stop"] + \
        (["--host", "codex"] if host == "codex" else [])
    proc = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, cwd=repo,
                          timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    return r64._message(json.loads(proc.stdout) if proc.stdout.strip() else None)


def _repo(tmp_path: pathlib.Path, keys, record: bytes | None) -> pathlib.Path:
    """A done end with an earlier blocker in place and, optionally, a count record as given."""
    repo = r64._done_repo(tmp_path, keys)
    (repo / ".proofbundle").mkdir(exist_ok=True)
    (repo / gate.DONE_BLOCKER).write_text("{}\n", encoding="utf-8")
    if record is not None:
        r64._record(repo, record)
    return repo


def _record(repo: pathlib.Path) -> dict:
    return json.loads((repo / gate.DONE_STATE).read_text(encoding="utf-8"))


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_failed_removal_beside_an_unread_record_is_named_and_the_count_stands(env, tmp_path, keys, host):
    """The review's case: the record is written (blocks 0), so the end is counted; the removal failed and the unread
    record was replaced, and the answer says exactly that."""
    repo = _repo(tmp_path, keys, r64._doc(blocks="1"))
    message = _stop(env, repo, host, "unlink")
    assert _record(repo)["blocks"] == 0 and (repo / gate.DONE_BLOCKER).exists()
    assert COUNT_FAILED not in message, message
    assert "could not be removed" in message and gate.DONE_BLOCKER in message and "injected" in message, message
    assert UNREAD in message and gate.DONE_STATE in message, message
    assert "its block count is not a whole number" in message and REPLACED in message, message


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_failed_removal_alone_is_not_a_count_that_failed(env, tmp_path, keys, host):
    repo = _repo(tmp_path, keys, None)
    message = _stop(env, repo, host, "unlink")
    assert _record(repo)["blocks"] == 0
    assert COUNT_FAILED not in message and UNREAD not in message, message
    assert "could not be removed" in message and gate.DONE_BLOCKER in message, message


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_failed_write_beside_an_unread_record_names_both_and_claims_no_replacement(env, tmp_path, keys, host):
    """The hook could not write its record: the end is not counted, the unread record still stands, and the answer
    says both, without claiming a replacement it did not write."""
    repo = _repo(tmp_path, keys, r64._doc(blocks="1"))
    message = _stop(env, repo, host, "write")
    assert _record(repo)["blocks"] == "1"   # the record from before stands
    assert COUNT_FAILED in message and "injected failure" in message, message
    assert UNREAD in message and gate.DONE_STATE in message and REPLACED not in message, message
    assert "could not be removed" not in message and not (repo / gate.DONE_BLOCKER).exists(), message


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_failed_write_and_a_failed_removal_are_named_apart(env, tmp_path, keys, host):
    repo = _repo(tmp_path, keys, None)
    message = _stop(env, repo, host, "both")
    assert COUNT_FAILED in message and "could not be removed" in message, message
    count_part = message.split(COUNT_FAILED, 1)[1].split(".", 1)[0]
    assert "blocker" not in count_part, message   # the removal is not reported as part of the count


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_without_a_failure_the_done_end_says_nothing_more(env, tmp_path, keys, host):
    repo = _repo(tmp_path, keys, None)
    message = _stop(env, repo, host, "none")
    assert "could not" not in message and not (repo / gate.DONE_BLOCKER).exists(), message
    assert _record(repo)["blocks"] == 0
