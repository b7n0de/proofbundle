"""D62, corrected in follow-up note 28 (O27-2): a word after the name of `git config` is a value, never a switch.

Measured with git 2.43.0 in a fresh repository (config_position_n27.sh): `git config core.hooksPath
--show-origin`, `--null`, `-z` and `--get` after the name each set core.hooksPath to that word. D62 read them as a read
with a switch (_config_reads_only took a switch wherever it stood), so the gate asked with D3 under Claude Code instead
of denying with D24, and under Codex denied with D3. Now a switch counts only before the first name, as _config_read_form
of D68 reads it: the four forms, and any other word after the name, deny with D24 (hooks_disabled) under both hosts. A
word after the name of a read with an action is its value pattern, as git reads it, and stays no hook-disabling form.

RED at 0efaf38d (the head of follow-up note 27): the four setting forms and their unit rows; the reads are controls, green at
both.
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

#: Setting forms: git reads the word after the name as the value (measured), so each sets core.hooksPath.
SETS = ["config core.hooksPath --show-origin", "config core.hooksPath --null", "config core.hooksPath -z",
        "config core.hooksPath --get", "config core.hookspath --show-scope", "config core.hooksPath --list",
        "config --local core.hooksPath --show-origin", "config core.hooksPath --type=path"]
#: Reads: the switches stand before the name, or the word after the name is the value pattern of an action.
READS = ["config --show-origin --get core.hooksPath", "config --null --get core.hooksPath",
         "config --get core.hooksPath --null", "config --get-all core.hooksPath -z", "config core.hooksPath"]


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    return tmp_path / "r"


def _ids(out):
    return [v.reason_id for v in out.verdicts]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("prefix", ["-C", "bare"])
@pytest.mark.parametrize("words", SETS)
def test_D62_a_word_after_the_name_sets_core_hookspath_and_denies(repo, words, prefix, host):
    command = f"git -C {repo} {words}" if prefix == "-C" else f"git {words}"
    out = gate.decide(command, str(repo), time.monotonic() + 60, host)
    assert out is not None and (out.decision, _ids(out)) == ("deny", ["hooks_disabled"]), (words, out and _ids(out))


@pytest.mark.parametrize("words", READS)
def test_D62_control_a_read_stays_no_hook_disabling_form(repo, words):
    out = gate.decide(f"git {words}", str(repo), time.monotonic() + 60, "claude")
    assert out is not None and "hooks_disabled" not in _ids(out), (words, _ids(out))


@pytest.mark.parametrize("args, read", [
    (["core.hooksPath", "--show-origin"], False), (["core.hooksPath", "--null"], False), (["core.hooksPath", "-z"], False),
    (["core.hooksPath", "--get"], False), (["--show-origin", "--get", "core.hooksPath"], True),
    (["--get", "core.hooksPath", "--null"], True), (["core.hooksPath"], True), (["--list"], True),
    (["--list", "core.hooksPath"], False), (["--get", "core.hooksPath", "a", "--add"], False)])
def test_D62_the_reads_the_gate_knows_count_switches_only_before_the_name(args, read):
    assert gate._config_reads_only(args) is read, args
