"""Review round 18 of 2026-10-14, the class of R18-2: no reader of the gate waits on an entry that is no regular file.

Measured at 3604ba53 (class search, git 2.43.0): a FIFO with no writer as the gate directory's `mode` or `rules.json`
blocked `_read_mode`, `_read_rules` and the stamp of a freed call, and so every whole `decide` of a gated command; the
readers that checked the type with lstat or stat before their open (the receipt, the done check's files, the working
tree, the hooks) read a FIFO that took the place of the file after that check; the gate's log, a FIFO with no reader,
blocked the hook at its end; done-init blocked on a FIFO in place of the declaration. Each case runs in its own process;
one still running after WAIT seconds is blocked. The behaviour of a real host after its outer time-out is not measured.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's files are read

import test_plugin_owner_choice1_undeclared_push as w1
from _plugin_env import plugin_env

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

WAIT = 5.0
GATE_FILE = pathlib.Path(gate.__file__)
PROBE = r'''
import importlib.util, json, os, sys, time
spec = importlib.util.spec_from_file_location("probe_gate", sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
what, work, place = sys.argv[2], sys.argv[3], sys.argv[4]
if what == "mode":
    print(json.dumps(g._read_mode({"PROOFBUNDLE_GATE_DIR": place, "PROOFBUNDLE_OWNER_STATE": "protected"})))
elif what == "rules":
    print(json.dumps(g._read_rules({"PROOFBUNDLE_GATE_DIR": place, "PROOFBUNDLE_OWNER_STATE": "protected"})))
elif what == "stamp":
    print(json.dumps(g._gate_files_stamp({"PROOFBUNDLE_GATE_DIR": place})))
elif what == "decide":
    os.environ["PROOFBUNDLE_GATE_DIR"] = place
    out = g.decide("git status", work, time.monotonic() + 30, "claude")
    print(json.dumps(out.decision if out is not None else None))
elif what == "receipt":
    # the receipt turns into a FIFO after the lstat check: lstat still reports the regular file it was
    real_lstat = os.lstat
    regular = real_lstat(os.path.join(work, "a.txt"))
    os.lstat = lambda p, *a, **k: regular if os.fspath(p) == place else real_lstat(p, *a, **k)
    try:
        g._receipt_bytes(place)
        print(json.dumps("read"))
    except g.GateError as exc:
        print(json.dumps(str(exc)))
elif what == "done_init":
    try:
        g.done_init(work, place, time.monotonic() + 30, {})
        print(json.dumps("written"))
    except g.GateError as exc:
        print(json.dumps(str(exc)))
'''


def _probe(what: str, work: pathlib.Path, place: str) -> object:
    proc = subprocess.Popen([sys.executable, "-c", PROBE, str(GATE_FILE), what, str(work), place],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return "BLOCKED"
    assert proc.returncode == 0, err
    return json.loads(out)


def _gate_dir_with_fifo(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    folder = tmp_path / "gate-dir"
    folder.mkdir()
    os.mkfifo(folder / name)
    return folder


def test_RED_a_fifo_as_the_mode_reads_as_strict(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    assert _probe("mode", work, str(_gate_dir_with_fifo(tmp_path, "mode"))) == "strict"


def test_RED_a_fifo_as_the_rules_frees_nothing(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    assert _probe("rules", work, str(_gate_dir_with_fifo(tmp_path, "rules.json"))) == []


def test_RED_a_fifo_in_the_gate_directory_is_named_unreadable_in_the_stamp(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    answer = _probe("stamp", work, str(_gate_dir_with_fifo(tmp_path, "rules.json")))
    assert answer != "BLOCKED" and "rules.json cannot be read" in answer, answer


def test_RED_a_fifo_as_the_mode_does_not_block_the_decision(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    # the answer the decision gives without the FIFO: `git status` asked until review fix 18 part B, and class a (D34) frees it
    # after the read profile since; what the case shows is that the FIFO does not block the decision
    assert _probe("decide", work, str(_gate_dir_with_fifo(tmp_path, "mode"))) == "pass"


def test_RED_a_receipt_that_turns_into_a_fifo_after_its_check_is_not_read(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / "a.txt").write_text("a\n")
    receipt = tmp_path / "receipt.json"
    os.mkfifo(receipt)
    answer = _probe("receipt", work, str(receipt))
    assert answer != "BLOCKED" and "is not a regular file" in answer, answer


def test_RED_done_init_does_not_wait_on_a_fifo_as_the_declaration(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".proofbundle").mkdir()
    os.mkfifo(work / ".proofbundle" / "evidence.json")
    answer = _probe("done_init", work, str(tmp_path / "done.key"))
    assert answer != "BLOCKED" and "is not a regular file" in answer, answer


def test_RED_a_fifo_as_the_log_does_not_block_the_hook(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    os.mkfifo(data / gate.LOG_NAME)
    environ = plugin_env(without=("GIT_",))
    environ.update(CLAUDE_PLUGIN_DATA=str(data), PROOFBUNDLE_GATE_DIR=str(tmp_path / "gate-dir"))
    # a form that asks whatever the system file holds: `git status` asked here only through the git-lfs block of
    # this machine's system file, which D74 knows; `git stash list` is no read form of class a
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(work),
                        "tool_input": {"command": "git stash list"}})
    try:
        proc = subprocess.run([sys.executable, "-I", str(GATE_FILE)], input=event, capture_output=True, text=True,
                              env=environ, timeout=WAIT * 3)
    except subprocess.TimeoutExpired:
        pytest.fail(f"the hook was still blocked after {WAIT * 3} s on a FIFO as its log")
    answer = json.loads(proc.stdout)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer


def test_CONTROL_regular_files_read_as_before(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    folder = tmp_path / "gate-dir"
    folder.mkdir()
    (folder / "mode").write_text("with-approvals\n")
    (folder / "rules.json").write_text("[]")
    assert _probe("mode", work, str(folder)) == "with-approvals"
    assert _probe("rules", work, str(folder)) == []
    stamp = _probe("stamp", work, str(folder))
    assert "mode last changed" in stamp and "rules.json last changed" in stamp, stamp
    data = tmp_path / "data"
    environ = plugin_env(without=("GIT_",))
    environ.update(CLAUDE_PLUGIN_DATA=str(data), PROOFBUNDLE_GATE_DIR=str(tmp_path / "other-gate-dir"))
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(work),
                        "tool_input": {"command": "git stash list"}})   # asks whatever the system file holds (D74)
    subprocess.run([sys.executable, "-I", str(GATE_FILE)], input=event, capture_output=True, text=True, env=environ,
                   timeout=60, check=True)
    lines = (data / gate.LOG_NAME).read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["reason_ids"] == ["git_form_not_free"], lines
