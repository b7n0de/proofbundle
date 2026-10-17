"""D60, Nachtrag 23 part 1: the shell's test command `[` is no glob, so the safety net (D27) does not ask for it.

Counted at delta (gate log 09:33Z, balance 07:32Z): `until [ -s <file> ]; do sleep 3; done` asked with D27, and so did
`while [ … ]` and `if [ … ]`, with no git or gh word in them, while `test -s <file>`, a for loop and `head` stayed
silent. The net read the word `[` as an active pathname glob in the program position, which could name git; bash
matches a `[` with no `]` after it in the same word literally, so `[` is the test command and `[[` the keyword.

The rule: a `[` is an active glob only where a `]` follows it in the word (_unquoted_active_expansion). A bracket test
with git or gh in it asks as before, and so does every form in which the gate cannot read whether a git or gh call is
in it (a glob in the program word, an expansion there). RED at 9f578c2a and ab14e1ae: the silent forms; the asks are
controls, green at both.
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

SILENT = ["until [ -s f.txt ]; do sleep 3; done", "until [ -s out/result.json ]; do sleep 3; done",
          "while [ ! -s f.txt ]; do sleep 1; done", "if [ -s f.txt ]; then echo y; fi",
          "if [ -s f.txt ]; then echo y; else echo n; fi", "[ -s f.txt ] && echo y", "[ -d out ] || mkdir out",
          "[[ -s f.txt ]] && echo y", "until [ -s \"$F\" ]; do sleep 3; done", "test -s f.txt"]
ASKS = ["[ -n \"$(git status)\" ]", "if [ -s f.txt ]; then git push origin main; fi",
        "until [ -s f.txt ]; do git fetch; done", "[ -s f.txt ] && git status", "[ -x git ]",
        "[ -s f.txt ] && gi[t] status", "g[i]t status", "[ -s f.txt ] && gh pr view 1"]
# Not among the controls: a parameter expansion as the program word (`$CMD status`, `CMD=git; $CMD push origin main`)
# is silent at 9f578c2a and ab14e1ae already, with or without a bracket test before it; the bracket test had made the
# longer command ask only by accident. Named as a finding of its own in the delivery, not changed here.


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    (tmp_path / "r" / "f.txt").write_text("x\n")
    return tmp_path / "r"


@pytest.mark.parametrize("command", SILENT)
def test_D60_a_bracket_test_without_git_or_gh_is_silent(repo, command):
    out = gate.decide(command, str(repo), time.monotonic() + 60, "claude")
    assert out is None, (command, out and [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("command", SILENT)
def test_D60_and_under_codex(repo, command):
    out = gate.decide(command, str(repo), time.monotonic() + 60, "codex")
    assert out is None, (command, out and [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("command", ASKS)
def test_D60_control_git_or_gh_in_or_beside_it_or_an_unreadable_program_asks(repo, command):
    out = gate.decide(command, str(repo), time.monotonic() + 60, "claude")
    assert out is not None and out.decision in ("ask", "deny"), command


@pytest.mark.parametrize("raw, active", [("[", False), ("[[", False), ("]", False), ("]]", False), ("gi[", False),
                                         ("gi[t]", True), ("[a-z]*", True), ("*", True), ("?", True), ("'['", False),
                                         ("x[y]", True), ("{a,b}", True)])
def test_D60_a_bracket_is_a_glob_only_with_a_closing_bracket(raw, active):
    assert gate._unquoted_active_expansion(raw) is active, raw
