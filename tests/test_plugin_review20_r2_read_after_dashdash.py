"""R20-2 of review round 20 (Nachtrag 10 to FIX-18): `--` ends only the options for describe, merge-base and ls-tree.

Class a (D34) frees a read form that reads no index entry; reading the index queries fsmonitor for every form. For log,
show, rev-list and the other forms of the grammar a word after `--` is a path; for describe, merge-base and ls-tree it
is still a revision, so `git describe --always -- :0:a.txt` reads the index and starts core.fsmonitor while the gate
answered pass, free_after_read_profile, under Claude Code.

RED at b34ba9a2 for the reviewer's five forms, `describe -- :a.txt` and a word the shell may rewrite after `--`; green
after. Each form runs as well through real git with a marker program as core.fsmonitor: the gate is free exactly where
git starts no marker. The ordinary forms of the reviewer's table keep their answer.
"""
from __future__ import annotations

import os
import subprocess

import pytest

import test_plugin_ask_load_a_read as a

pytestmark = a.pytestmark
_clean = a._clean

#: The reviewer's reproduction and siblings: a revision after `--` that names an index entry.
INDEX_AFTER_DASHDASH = ["git describe --always -- :0:a.txt", "git describe --always -- :a.txt",
                        "git merge-base -- :a.txt HEAD", "git merge-base -- HEAD :0:a.txt",
                        "git ls-tree -- :a.txt", "git ls-tree -- :0:a.txt", "git ls-tree -r -- :0:a.txt"]
#: Words after `--` that are paths, or revisions that name no index entry: free, and git starts nothing.
FREE_AFTER_DASHDASH = ["git log --oneline -- :a.txt", "git log --oneline -1 -- :0:a.txt", "git show -- :0:a.txt",
                       "git rev-list HEAD -- :0:a.txt", "git ls-tree HEAD -- :a.txt", "git describe --always -- HEAD",
                       "git merge-base -- HEAD HEAD", "git ls-tree -- HEAD", "git ls-tree -- HEAD :a.txt"]
#: The reviewer's table of ordinary forms (fsmonitor set): free where git starts no marker, an ask where it does.
ORDINARY_FREE = ["git log --oneline -1", "git show HEAD", "git branch", "git ls-tree HEAD"]
ORDINARY_ASK = ["git status --short", "git diff", "git rev-parse :a.txt", "git show :a.txt"]


def _with_fsmonitor(tmp_path):
    repo = a._repo(tmp_path)
    a._config(repo, ("core.fsmonitor", a._marker(tmp_path, "fsmonitor")))
    return repo


def _git_starts_fsmonitor(tmp_path, repo, command: str) -> bool:
    a._clear(tmp_path)
    subprocess.run(command.split(), cwd=repo, capture_output=True, timeout=60, check=False,
                   env={"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_SYSTEM": os.devnull, "LC_ALL": "C"})
    started = "fsmonitor" in a._started(tmp_path)
    a._clear(tmp_path)
    return started


@pytest.mark.parametrize("command", INDEX_AFTER_DASHDASH)
def test_R20_2_a_revision_after_the_double_dash_that_names_an_index_entry_keeps_the_ask(tmp_path, command):
    repo = _with_fsmonitor(tmp_path)
    decision, reasons = a._decide(repo, command)
    assert decision not in a.FREE, (command, decision, reasons)
    assert a._started(tmp_path) == [], "the gate's own check starts no fsmonitor"
    assert _git_starts_fsmonitor(tmp_path, repo, command), command


@pytest.mark.parametrize("command", ["git describe --always -- HEA?", "git merge-base -- HEAD ma*",
                                     "git ls-tree -- HEA[D]"])
def test_R20_2_a_word_the_shell_may_rewrite_after_the_double_dash_keeps_the_ask(tmp_path, command):
    """The shell rewrites such a word before git reads it as a revision; the gate does not know what it becomes."""
    repo = a._repo(tmp_path)
    decision, reasons = a._decide(repo, command)
    assert decision not in a.FREE, (command, decision, reasons)


@pytest.mark.parametrize("command", FREE_AFTER_DASHDASH)
def test_R20_2_control_a_path_or_a_plain_revision_after_the_double_dash_stays_free(tmp_path, command):
    repo = _with_fsmonitor(tmp_path)
    decision, reasons = a._decide(repo, command)
    assert decision == "pass" and reasons == ["free_after_read_profile"], (command, decision, reasons)
    assert not _git_starts_fsmonitor(tmp_path, repo, command), command


@pytest.mark.parametrize("command", ORDINARY_FREE + ORDINARY_ASK)
def test_R20_2_control_the_ordinary_forms_keep_the_reversal_to_fsmonitor(tmp_path, command):
    repo = _with_fsmonitor(tmp_path)
    decision, _reasons = a._decide(repo, command)
    starts = _git_starts_fsmonitor(tmp_path, repo, command)
    assert starts == (command in ORDINARY_ASK), command
    assert (decision == "pass") == (not starts), (command, decision)
