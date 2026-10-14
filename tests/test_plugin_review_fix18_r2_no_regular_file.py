"""Review round 18 of 2026-10-14, R18-2: an entry of the ref store that is no regular file leaves the exception
unapplied instead of blocking the reading.

Measured by the reviewer at 3604ba53 with git 2.43.0 and 2.51.1: with `.git/info/refs` a FIFO and no writer,
`_present_refs` in a separate process with 0.5 s of its deadline left was still blocked after a second; the same FIFO as
`.git/pipe` was refused at once by the general reader. The special reader checked only for a symbolic link before the
blocking open. Measured here at 3604ba53 (class search): FETCH_HEAD, ORIG_HEAD, MERGE_HEAD and a loose ref file as a
FIFO blocked the same way. Each case runs in its own process; a reading still running after WAIT seconds is blocked.
The behaviour of a real host after its outer time-out is not measured. Run with git 2.43.0.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

WAIT = 5.0
GATE_FILE = pathlib.Path(gate.__file__)
NO_REGULAR = "an entry that is no regular file"
PROBE = r'''
import importlib.util, json, os, stat, sys, time
spec = importlib.util.spec_from_file_location("probe_gate", sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
work, how = sys.argv[2], sys.argv[3]
if how == "lstat_says_regular":
    # the entry turns into a FIFO between the check before the open and the open itself: os.lstat still reports the
    # regular file it was, so only a check at the opened descriptor sees the FIFO
    tail, real_lstat = os.sep + os.path.join(".git", sys.argv[4]), os.lstat
    regular = real_lstat(os.path.join(work, "a.txt"))
    os.lstat = lambda p, *a, **k: regular if os.fspath(p).endswith(tail) else real_lstat(p, *a, **k)
present, why = g._present_refs(work, time.monotonic() + 0.5)
print(json.dumps({"present": present is not None, "why": why if isinstance(why, str) else sorted(why)}))
'''


def _probe(work: pathlib.Path, how: str = "plain", extra: str = "") -> dict | None:
    """The answer of `_present_refs` with 0.5 s of its deadline left, in a process of its own; None where the reading
    was still running after WAIT seconds and was ended."""
    proc = subprocess.Popen([sys.executable, "-c", PROBE, str(GATE_FILE), str(work), how, extra],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None
    assert proc.returncode == 0, err
    return json.loads(out)


def _fifo(work: pathlib.Path, rel: str) -> pathlib.Path:
    path = work / ".git" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    os.mkfifo(path)
    return path


@pytest.mark.parametrize("rel", ["info/refs", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "refs/heads/fifo"])
def test_RED_a_fifo_in_the_ref_store_or_beside_it_does_not_block(tmp_path, rel):
    work, _remote, _a = w1._undeclared(tmp_path)
    _fifo(work, rel)
    answer = _probe(work)
    assert answer is not None, f"the reading of .git/{rel} as a FIFO was still blocked after {WAIT} s"
    assert answer["present"] is False and NO_REGULAR in answer["why"] and rel in answer["why"], answer


def test_RED_a_further_file_that_turns_into_a_fifo_after_its_check_does_not_block(tmp_path):
    """The general reader checked with lstat before its open; the check at the descriptor holds where the entry is
    a FIFO when it is opened."""
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / "a.txt").write_text("a\n")
    _fifo(work, "pipe")
    answer = _probe(work, "lstat_says_regular", "pipe")
    assert answer is not None, f"the reading of .git/pipe was still blocked after {WAIT} s"
    assert answer["present"] is False and NO_REGULAR in answer["why"] and "pipe" in answer["why"], answer


def test_CONTROL_the_general_reader_refuses_a_fifo_at_once(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    _fifo(work, "pipe")
    answer = _probe(work)
    assert answer is not None and answer["present"] is False and NO_REGULAR in answer["why"], answer


@pytest.mark.parametrize("content", ["", "{a}\trefs/heads/main\n{a}\trefs/remotes/origin/main\n"], ids=["empty", "lines"])
def test_CONTROL_an_empty_or_multi_line_info_refs_is_read_as_before(tmp_path, content):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "info").mkdir(exist_ok=True)
    (work / ".git" / "info" / "refs").write_text(content.format(a=a))
    answer = _probe(work)
    assert answer is not None and answer["present"] is True and answer["why"] == [], answer


@pytest.mark.parametrize("content", ["", "{a}\trefs/heads/main\n{a}\trefs/remotes/origin/main\n"], ids=["empty", "lines"])
def test_CONTROL_the_exception_stays_reachable_with_a_regular_info_refs(env, tmp_path, content):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "info").mkdir(exist_ok=True)
    (work / ".git" / "info" / "refs").write_text(content.format(a=a))
    answer, entry, text = w1._l1(env, work)
    w1._assert_inactive(answer, entry, text)
