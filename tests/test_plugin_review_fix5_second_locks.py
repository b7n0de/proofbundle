"""Review round 5 of 2026-10-09: the second lock the mutation run against 3b1b4346 asked for.

M1f (the gate's git reads translated again, LC_ALL=C removed) was caught by no test: git on the test machine has no
translations installed, so its messages are English whatever the locale, and git's answer for no work tree
(_NO_WORK_TREE) is read either way. Where a git with translations runs, a translated answer would read as a failed read
and block the Stop hook in every directory outside a repository. The lock is a function contract, said as such: the
environment of every git read sets LC_ALL=C and drops LANGUAGE (gettext ignores LANGUAGE under the C locale). The
behaviour itself is NOT MEASURED here.
"""
from __future__ import annotations

import test_plugin_done_check as dc

gate = dc.gate


def test_m1f_every_git_read_of_the_gate_runs_untranslated(monkeypatch):
    monkeypatch.setenv("LANGUAGE", "de")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    env = gate._read_env()
    assert env["LC_ALL"] == "C" and "LANGUAGE" not in env


def test_m1f_git_s_answer_outside_a_repository_is_no_work_tree_under_a_foreign_locale(tmp_path, monkeypatch):
    """The answer the contract protects: outside every repository the work tree is (None, ""), not a failed read."""
    monkeypatch.setenv("LANGUAGE", "de")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    outside = tmp_path / "plain"
    outside.mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    assert gate._work_tree(str(outside), gate.time.monotonic() + 30) == (None, "")
