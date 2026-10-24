"""D84, Nachtrag 34, point 6: the test builtin like `[` under Claude Code (owner choice O31E1-5, after the fix of D82).

Measured under strace -f in bash -c (truth_test_n34.py, 44 runs under four sources): test with -f, -d, -n, -e, a string
comparison with a substitution, -lt, `!` -s, -x, -v before a plain name, -z and -nt started no program besides bash,
opened no file for writing, made no socket and changed no file, as `[` did in Ergänzung 1 to Nachtrag 31. D82 holds
`-v` before a word that is no plain name, for test as for `[`.

RED at c55eb2a8 (D83): test in a chain the steps of D72 do not free (xargs grep, a while loop, an if). test -v with an
index and the same chains under Codex are controls, green at both.

Changed in Nachtrag 38, point 4: the first free case starts head, whose version the gate reads from the host; at the
Farmer (GNU coreutils 8.32, delta's run of 2026-10-18) it was red, where the gate rightly keeps the chain (B36-1). The free
cases now name the measured version themselves (_measured_coreutils), and that case with a head of 8.32 is the catch case.
"""
from __future__ import annotations

import time

import pytest

import _measured_coreutils as mc
import test_plugin_n26_read_only_d66 as d66

gate = d66.gate
pytestmark = d66.pytestmark
_clean_git_environment = d66._clean_git_environment
repo = d66.repo

FREE = ["find src | xargs grep -l git | head -1; test -s README.md",
        "find src | while read f; do test -s \"$f\" && grep -c git \"$f\"; done",
        "if test -f .git/hooks/pre-push; then grep -c git README.md; fi",
        "find src | xargs grep -l git && test -x .git/hooks/pre-push",
        "find src | xargs grep -l git || test -d .git",
        "if test ! -e .git/hooks/pre-commit; then grep -c 'gh pr' README.md; fi",
        "find src | xargs grep -l git; test -d .git"]
HELD = ["find src | xargs grep -l git; test -v 'a[$(git push origin main)]'",
        "test -v 'a[$(git push origin main)]'",
        "find src | xargs grep -l git; test -v \"a[\\$(git push origin main)]\"",
        "find src | xargs grep -l git; test \"$(git push origin main)\" = x"]


def decided(repo, command, host):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("command", FREE)
def test_D84_test_is_a_read_form_like_the_bracket_under_claude_code(repo, tmp_path_factory, monkeypatch, command):
    mc.version_on_path(tmp_path_factory.mktemp("coreutils"), monkeypatch)
    out = decided(repo, command, "claude")
    assert out is None, (command, out and [v.reason_id for v in out.verdicts])


def test_D84_control_a_head_of_a_version_not_measured_keeps_the_answer(repo, tmp_path_factory, monkeypatch):
    """B36-1 from the other side (Nachtrag 38, point 4): test needs no version, the head beside it does."""
    mc.version_on_path(tmp_path_factory.mktemp("coreutils"), monkeypatch, "8.32")
    out = decided(repo, FREE[0], "claude")
    assert out is not None and out.decision in ("ask", "deny"), FREE[0]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", HELD)
def test_D84_control_test_v_before_an_index_or_a_substitution_keeps_the_answer(repo, command, host):
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), (host, command)


@pytest.mark.parametrize("command", FREE)
def test_D84_control_codex_keeps_the_answer(repo, command):
    out = decided(repo, command, "codex")
    assert out is not None and out.decision in ("ask", "deny"), command
