"""D68, Nachtrag 27 (O23-7): `git config --get`, `--get-all`, `--get-regexp` and `--list` are read forms of class a.

Measured first, with git 2.43.0 under strace (truth_config_n27.py of the delivery, fourteen forms by 30 sources,
standard output a pipe or the terminal of script(1)): with a pipe no read started a program or wrote a file, whatever
pager, hook, fsmonitor, editor, credential, signing, diff, alias, filter or include was set; a trace target (trace2.*,
GIT_TRACE) writes its file, and the read profile, which does not know those names, keeps asking. On a terminal
--get-all, --get-regexp and --list start the pager, the default one as `git log` does, and a configured one (core.pager,
pager.config, PAGER, GIT_PAGER, an include) counts in the read profile as for every read form (D34, D42).

The rule: one of the four actions, beside it only --show-origin and --null, every option before the first other word
(git reads each word after it as a name or a value: `git config user.name --get` sets user.name), with --get, --get-all
or --get-regexp one name and at most one value pattern, with --list no word. Class a frees it under Claude Code after
the read profile of its repository, never under Codex. Every write form keeps its answer: a value, --add, --unset,
--unset-all, --replace-all, --rename-section, --remove-section, --edit and -e. The deny of core.hooksPath stays as D62
leaves it: a read of it is a read form here, setting it denies.

RED at 76dc0cfc: the read forms in a clean repository; the write forms, the other spellings and the profile's findings
are controls, green at both.
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
    "git config --get user.name",
    "git config --get-all user.name",
    "git config --get-regexp '^user'",
    "git config --list",
    "git config --list --show-origin",
    "git config --list --null",
    "git config --show-origin --get user.name",
    "git config --null --get-all user.name",
    "git config --show-origin --null --get-regexp '^user\\.'",
    "git config --get user.name '^t'",
    "git config --get-all remote.origin.url 'github'",
    "git config --get core.hooksPath",
    "git config --list --show-origin --null",
]

#: Every write form Nachtrag 27 names, each still asked (denied under Codex).
WRITES = [
    "git config user.name t",
    "git config --add a.b c",
    "git config --unset a.b",
    "git config --unset-all a.b",
    "git config --replace-all a.b c",
    "git config --rename-section a b",
    "git config --remove-section a",
    "git config --edit",
    "git config -e",
]

#: Not the form of D68: another spelling, an option outside the two, a word after the first name read as an option, a
#: word the shell builds or rewrites, a redirection, a git 2.46 subcommand.
OTHERS = [
    "git config user.name",                         # no action: the name alone
    "git config user.name --get",                   # sets user.name to --get (measured)
    "git config a.b --list",                        # sets a.b to --list (measured)
    "git config --get user.name --show-origin",     # --show-origin after the name is a value pattern
    "git config --get user.name --add",
    "git config -l",
    "git config -z --get user.name",
    "git config --show-scope --get user.name",
    "git config --name-only --list",
    "git config --includes --get user.name",
    "git config --type=bool --get a.b",
    "git config --bool --get a.b",
    "git config --local --get user.name",
    "git config --global --list",
    "git config --file other.cfg --get a.b",
    "git config --blob HEAD:x --list",
    "git config --default x --get a.b",
    "git config --get-urlmatch http https://github.com",
    "git config --get-color color.diff.new",
    "git config --get --list",
    "git config --get",
    "git config --list user.name",
    "git config --get a.b c d",
    "git config --get -- a.b",
    "git config --get $KEY",
    "git config --g* user.name",
    "git config --get-regexp ^user",                # `^` the shell may rewrite (zsh), as for every read form
    "git config --list > /tmp/config.txt",
    "git config get user.name",
    "git -c core.pager=cat config --list",
]


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True, timeout=60)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "t"], check=True, timeout=60)
    subprocess.run(["git", "-C", str(path), "remote", "add", "origin", "https://github.com/o/r"], check=True,
                   timeout=60)
    return path


def decided(repo, command, host="claude"):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("command", READS)
def test_D68_a_config_read_is_free_after_the_read_profile(repo, command):
    out = decided(repo, command)
    assert out is not None and out.decision == "pass", (command, out and out.text)
    assert [v.reason_id for v in out.verdicts] == ["free_after_read_profile"], command


def test_D68_with_one_absolute_C_as_for_every_read_form(repo):
    out = decided(repo, f"git -C {repo} config --get-regexp remote")
    assert out is not None and out.decision == "pass", out and out.text


@pytest.mark.parametrize("command", READS[:6])
def test_D68_class_a_stays_off_under_codex(repo, command):
    out = decided(repo, command, host="codex")
    assert out is not None and out.decision in ("ask", "deny"), command


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", WRITES)
def test_D68_control_every_write_form_keeps_its_answer(repo, command, host):
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), command
    assert "free_after_read_profile" not in [v.reason_id for v in out.verdicts], command


@pytest.mark.parametrize("command", OTHERS)
def test_D68_control_every_other_form_keeps_its_answer(repo, command):
    out = decided(repo, command)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.decision)


@pytest.mark.parametrize("key, value", [("pager.config", "less"), ("core.pager", "less"),
                                        ("trace2.eventTarget", "/tmp/trace2.json"),
                                        ("remote.origin.promisor", "true"), ("diff.external", "/bin/true")])
def test_D68_control_the_read_profile_still_counts(repo, key, value):
    subprocess.run(["git", "-C", str(repo), "config", key, value], check=True, timeout=60)
    out = decided(repo, "git config --list")
    assert out is not None and out.decision == "ask", (key, out and out.decision)


@pytest.mark.parametrize("name", ["PAGER", "GIT_PAGER", "GIT_TRACE"])
def test_D68_control_a_pager_or_trace_in_the_hooks_environment_counts(repo, monkeypatch, name):
    monkeypatch.setenv(name, "/tmp/x")
    out = decided(repo, "git config --get-all user.name")
    assert out is not None and out.decision == "ask", (name, out and out.decision)


def test_D68_control_the_deny_of_core_hookspath_stays_as_d62_leaves_it(repo):
    for command in ("git config core.hooksPath /x", "git config --add core.hooksPath /x",
                    "git config --unset core.hooksPath"):
        out = decided(repo, command)
        assert (out.decision, [v.reason_id for v in out.verdicts]) == ("deny", ["hooks_disabled"]), command


@pytest.mark.parametrize("args, read", [
    (["--get", "a.b"], True), (["--get-all", "a.b", "x"], True), (["--get-regexp", "^a"], True), (["--list"], True),
    (["--show-origin", "--null", "--list"], True), (["--add", "a.b", "c"], False), (["a.b", "--get"], False),
    (["--get", "a.b", "--null"], False), (["--list", "x"], False), (["--get"], False), (["-l"], False),
    (["--get", "--get-all", "a.b"], False), (["--get", "$X"], False), (["--get", "a", "b", "c"], False)])
def test_D68_the_reads_of_the_form(args, read):
    assert gate._config_read_form(args, [False] * len(args)) is read, args
    assert gate._read_form("config", args) is read, args


def test_D68_the_closed_sets_are_what_the_decision_names():
    assert gate._CONFIG_FREE_ACTIONS == {"--get", "--get-all", "--get-regexp", "--list"}
    assert gate._CONFIG_FREE_SWITCHES == {"--show-origin", "--null"}
