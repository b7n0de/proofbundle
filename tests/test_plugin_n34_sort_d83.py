"""D83, Nachtrag 34, point 6: sort in a read-only chain under Claude Code (owner choice O31E1-1 A).

Measured in Ergänzung 1 to Nachtrag 31 under strace -f (truth_readprog_e1.py, GNU coreutils 9.4): sort with -b, -c, -f,
-n, -r, -s, -u, -V, -z, -k and -t started only itself, opened no file for writing and made no socket; from a pipe of
0.8 MB on it writes temporary files of its own in TMPDIR, opened with O_EXCL and mode 0600 and removed by sort itself
(truth_sort_temp_e1.sh). Owner choice O31E1-1 A: sort is free like the other read programs, the temporary files are the
named exception; -o, -T, -S, -m, the long options and every option not measured stay out.

RED at 9f1ef309 (D82): sort with each measured option behind a chain the steps of D72 do not free (xargs grep, a while
loop), naming git only as data; a chain of data steps alone (`grep -rln git src | sort`) was free there already. The
options left out, sort under Codex and sort behind xargs are controls, green at both.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_n26_read_only_d66 as d66

gate = d66.gate
pytestmark = d66.pytestmark
_clean_git_environment = d66._clean_git_environment
repo = d66.repo

#: Chains the steps of D72 do not free (xargs is a carrier there, a while loop is not modeled): sort decides them.
FREE = ["find src -name '*.py' | xargs grep -l git | sort", "find src | xargs grep -c git | sort -n | tail -1",
        "find src -print0 | xargs -0 grep -l git | sort -u", "find src | xargs grep -l 'gh pr' | sort -t: -k2 -n",
        "find src | while read f; do grep -c git \"$f\"; done | sort -rn",
        "find src | xargs grep -l git | sort -V", "find src | xargs grep -lZ git | sort -z",
        "find src | xargs grep -l git | sort -f -b", "find src | xargs grep -l git | sort -s -k1,1",
        "find src | xargs grep -l git | sort -c", "find src | xargs grep -l git | sort -uf"]
HELD = ["find src | xargs grep -l git | sort -o found.txt", "find src | xargs grep -l git | sort -T /tmp",
        "find src | xargs grep -l git | sort -S 1G", "find src | xargs grep -l git | sort -m a b",
        "find src | xargs grep -l git | sort -h", "find src | xargs grep -l git | sort --unique",
        "find src | xargs grep -l git | sort --output=found.txt", "find src | xargs grep -l git | sort -R",
        "find src | xargs grep -l git | sort -k$(git push origin main)", "find src | xargs grep -l git | xargs sort"]


def decided(repo, command, host):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("command", FREE)
def test_D83_sort_with_a_measured_option_is_a_read_form_under_claude_code(repo, command):
    out = decided(repo, command, "claude")
    assert out is None, (command, out and [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("command", HELD)
def test_D83_control_an_option_left_out_keeps_the_answer(repo, command):
    out = decided(repo, command, "claude")
    assert out is not None and out.decision in ("ask", "deny"), command


@pytest.mark.parametrize("command", FREE)
def test_D83_control_codex_keeps_the_answer(repo, command):
    out = decided(repo, command, "codex")
    assert out is not None and out.decision in ("ask", "deny"), command


def test_D83_sort_is_measured_by_its_version_like_the_others():
    assert "sort" in gate._READ_PROGRAMS and "sort" not in gate._READ_XARGS_PROGRAMS
    assert gate._READ_PROGRAMS["sort"].values == frozenset("kt")
