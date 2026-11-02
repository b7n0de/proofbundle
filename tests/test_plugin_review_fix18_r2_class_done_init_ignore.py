"""Review round 18 of 2026-10-14, the class of R18-2, second pass: done-init read `.proofbundle/.gitignore` with a
blocking open and no type check.

Measured at 3604ba53 and at 0ef0653f with git 2.43.0: with `.proofbundle/.gitignore` a FIFO and no writer, done-init
was still blocked after 4 s, after it had written the policy and the declaration. Each case runs in its own process; one
still running after WAIT seconds is blocked. The probe process answers for the `uv` the done check would start with a
32-byte public key, so the reading of .gitignore is reached without the package; nothing else is replaced.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

WAIT = 5.0
GATE_FILE = pathlib.Path(gate.__file__)
PROBE = r'''
import base64, importlib.util, json, os, subprocess, sys, time
spec = importlib.util.spec_from_file_location("probe_gate", sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
work, key = sys.argv[2], sys.argv[3]
real_run = g.subprocess.run
def run(argv, *a, **k):
    if argv and argv[0] == "/fake/uv":
        return subprocess.CompletedProcess(argv, 0, base64.b64encode(bytes(32)).decode() + "\n", "")
    return real_run(argv, *a, **k)
g.subprocess.run = run
g.shutil.which = lambda name, *a, **k: "/fake/uv" if name == "uv" else None
try:
    g.done_init(work, key, time.monotonic() + 30, {})
    print(json.dumps("set up"))
except g.GateError as exc:
    print(json.dumps(str(exc)))
'''


def _probe(work: pathlib.Path, key: pathlib.Path) -> object:
    proc = subprocess.Popen([sys.executable, "-c", PROBE, str(GATE_FILE), str(work), str(key)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return "BLOCKED"
    assert proc.returncode == 0, err
    return json.loads(out)


def test_RED_done_init_does_not_wait_on_a_fifo_as_the_gitignore_and_writes_nothing(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".proofbundle").mkdir()
    ignore = work / ".proofbundle" / ".gitignore"
    os.mkfifo(ignore)
    try:
        answer = _probe(work, tmp_path / "done.key")
    finally:
        ignore.unlink()
    assert answer == ".proofbundle/.gitignore is not a regular file", answer
    assert sorted(p.name for p in (work / ".proofbundle").iterdir()) == [], "nothing is written before the reading"


def test_CONTROL_a_regular_gitignore_is_read_and_completed_as_before(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".proofbundle").mkdir()
    (work / ".proofbundle" / ".gitignore").write_text("own-line\n")
    answer = _probe(work, tmp_path / "done.key")
    assert answer == "set up", answer
    lines = (work / ".proofbundle" / ".gitignore").read_text().splitlines()
    assert lines[0] == "own-line" and "receipts/" in lines, lines
    assert (work / gate.DECLARATION).is_file()


def test_CONTROL_without_a_gitignore_done_init_writes_one(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    assert _probe(work, tmp_path / "done.key") == "set up"
    assert "receipts/" in (work / ".proofbundle" / ".gitignore").read_text().splitlines()
