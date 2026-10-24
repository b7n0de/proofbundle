"""D68, added in Nachtrag 28 (O27-4): -l, -z, --show-scope, --name-only and the scope switches of git config reads.

Measured first with git 2.43.0 under strace (truth_config_n28.py of the delivery, sixteen forms by 30 sources, the system
configuration a file of the case's own): with standard output a pipe none of `-l`, `-z`, `--show-scope`, `--name-only`,
`--local`, `--global`, `--system` and `--worktree` started a program or wrote a file, but the trace targets, which keep
asking; on a terminal the list forms start the pager as before. So they join the read forms of D68: `-l` as the list
action, the other seven as switches before the name. Every write form keeps its answer, with a scope switch or without.

RED at 0efaf38d (the head of Nachtrag 27): the reads with the new switches; the write forms and the other options are
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

READS = [
    "git config -l",
    "git config -z --list",
    "git config -z --get-all user.name",
    "git config --show-scope --list",
    "git config --show-scope --get user.name",
    "git config --name-only --list",
    "git config --name-only --get-regexp '^user'",
    "git config --local --list",
    "git config --local --get user.name",
    "git config --global --list",
    "git config --global --get user.name",
    "git config --system --list",
    "git config --worktree --get user.name",
    "git config --show-origin --show-scope --name-only -z -l",
]
#: Write forms with the new switches, and options still off the list: each keeps its answer.
OTHERS = [
    "git config --local user.name x",
    "git config --global --add a.b c",
    "git config --system --unset a.b",
    "git config --worktree a.b c",
    "git config -z a.b c",
    "git config --local --replace-all a.b c",
    "git config --global --edit",
    "git config --local -e",
    "git config --show-scope user.name x",
    "git config user.name --local",
    "git config -l x",
    "git config -lz",
    "git config --includes --list",
    "git config --type=bool --get a.b",
    "git config --file x.cfg --list",
    "git config --blob HEAD:x -l",
    "git config --default x --get a.b",
    "git config --local --get --list",
]


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True, timeout=60)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "t"], check=True, timeout=60)
    return path


def decided(repo, command, host="claude"):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("command", READS)
def test_D68_a_read_with_a_measured_switch_is_free_after_the_read_profile(repo, command):
    out = decided(repo, command)
    assert out is not None and out.decision == "pass", (command, out and out.text)
    assert [v.reason_id for v in out.verdicts] == ["free_after_read_profile"], command


@pytest.mark.parametrize("command", READS[:4])
def test_D68_class_a_stays_off_under_codex(repo, command):
    out = decided(repo, command, host="codex")
    assert out is not None and out.decision in ("ask", "deny"), command


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", OTHERS)
def test_D68_control_every_write_and_every_other_option_keeps_its_answer(repo, command, host):
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.decision)
    assert "free_after_read_profile" not in [v.reason_id for v in out.verdicts], command


@pytest.mark.parametrize("args, read", [
    (["-l"], True), (["-z", "--list"], True), (["--local", "--get", "a.b"], True), (["--worktree", "-l"], True),
    (["--show-scope", "--name-only", "--get-regexp", "a"], True), (["-l", "x"], False), (["-lz"], False),
    (["--local", "a.b", "c"], False), (["--local", "--get", "-l"], False), (["--get", "a.b", "--local"], False)])
def test_D68_the_reads_of_the_form_with_the_new_switches(args, read):
    assert gate._config_read_form(args, [False] * len(args)) is read, args
