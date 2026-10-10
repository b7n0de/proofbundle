"""Review round 8 of 2026-10-10, R8-3: the push option list git checks is the effective one.

Measured by the reviewer at 1fc58527: the done fixture with the pattern rule, a test remote that advertises push
options, and at the end of .git/config `[push] pushOption = "one\\ntwo"` (backslash and n, which git decodes to LF).
_push_config_problem returned None and the gate passed with done; the real push and the dry run exited 128 and the
remote stayed as it was. Without the value, and with a valid option, the control was green. A later empty `pushOption =`
clears the list with the LF value, and git accepts the push again.

Property: a push option value that stops git locally gets no green verdict. git keeps push.pushOption as a list: every
value is appended, an empty value clears what came before, a key without a value stops every push, and any `-o` or
`--push-option` on the command line replaces the configured list for that push; git then refuses the push when an
option of the list it uses holds a newline (measured with git 2.43.0 and 2.51.1). A NUL can stand in neither a
configuration value nor an argument. Red against 1fc58527.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

NOT_MEASURED = ("ask", ["push_not_measured"])
PASS = ("pass", ["done"])


def _repo(tmp_path, lines: str = "") -> n2c.Repo:
    """main tracks origin/main, one commit of work with a valid receipt, a remote that advertises push options; `lines`
    appended to .git/config as written."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(tmp_path / "remote.git", "config", "receive.advertisePushOptions", "true")
    if lines:
        with open(r.path / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write(lines)
    return r


def _git_push(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "push", "--porcelain", "--no-verify", *args],
                          capture_output=True, text=True, timeout=60, check=False)


def _verdict(env, repo, command: str) -> tuple[str, list]:
    _answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"]


LF = '[push]\n\tpushOption = "one\\ntwo"\n'
#: Configurations under which git refuses the push, and the command lines it refuses them with.
REFUSED = {
    "review": (LF, ()),
    "valid_then_lf": ('[push]\n\tpushOption = one\n\tpushOption = "two\\nthree"\n', ()),
    "lf_reset_then_lf": (LF + "\tpushOption =\n" + '\tpushOption = "four\\nfive"\n', ()),
    "lf_with_cleared_command_line": (LF, ("--no-push-option",)),
}
#: Configurations under which git accepts the push: the LF value is not in the list git uses.
ACCEPTED = {
    "no_option": ("", ()),
    "valid_option": ("[push]\n\tpushOption = one\n", ()),
    "lf_then_empty": (LF + "\tpushOption =\n", ()),
    "lf_then_empty_then_valid": (LF + "\tpushOption =\n\tpushOption = three\n", ()),
    "lf_replaced_by_short_option": (LF, ("-o", "x")),
    "lf_replaced_by_long_option": (LF, ("--push-option=x",)),
    "lf_replaced_by_long_option_with_value": (LF, ("--push-option", "x")),
}


def _command(options: tuple) -> str:
    return " ".join(("git", "push", *options, "origin", "main"))


@pytest.mark.parametrize("case", REFUSED)
def test_git_refuses_the_push_and_leaves_the_remote(tmp_path, case):
    """Non-vacuous: the real push exits 128 and both refs stay where they were."""
    lines, options = REFUSED[case]
    r = _repo(tmp_path, lines)
    before = _git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout
    push = _git_push(r.path, *options, "origin", "main")
    assert push.returncode == 128 and "push options must not have new line characters" in push.stderr, push.stderr
    assert _git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout == before


@pytest.mark.parametrize("case", REFUSED)
def test_a_push_git_refuses_for_its_push_options_is_not_measured(env, tmp_path, case):
    lines, options = REFUSED[case]
    r = _repo(tmp_path, lines)
    assert _verdict(env, r.path, _command(options)) == NOT_MEASURED, case


def test_a_bare_push_git_refuses_for_its_push_options_is_not_measured(env, tmp_path):
    r = _repo(tmp_path, LF)
    assert subprocess.run(["git", "-C", str(r.path), "push", "--dry-run", "--no-verify"], capture_output=True,
                          timeout=60, check=False).returncode == 128
    assert _verdict(env, r.path, "git push") == NOT_MEASURED


@pytest.mark.parametrize("case", ACCEPTED)
def test_git_accepts_the_push_where_the_lf_value_is_not_in_the_list_it_uses(tmp_path, case):
    """A real push, not a dry run: a dry run that sends push options to a local remote can die of SIGPIPE (exit -13,
    seen once in five parallel runs) when the receiving end closes early, which is git's race, not the case."""
    lines, options = ACCEPTED[case]
    r = _repo(tmp_path, lines)
    push = _git_push(r.path, *options, "origin", "main")
    assert push.returncode == 0, (case, push.returncode, push.stdout, push.stderr)
    assert _git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout == _git(r.path, "rev-parse", "HEAD").stdout


@pytest.mark.parametrize("case", ACCEPTED)
def test_control_a_push_git_accepts_keeps_its_verdict(env, tmp_path, case):
    """A cleared LF value and a list the command line replaces are not effective: the push is judged as without them."""
    lines, options = ACCEPTED[case]
    r = _repo(tmp_path, lines)
    assert _verdict(env, r.path, _command(options)) == PASS, case


def test_a_newline_in_a_command_line_option_gets_no_green_verdict(env, tmp_path):
    """The command line sibling: git refuses an option with a newline from the command line as from the list."""
    r = _repo(tmp_path)
    assert _git_push(r.path, "--dry-run", "-o", "a\nb", "origin", "main").returncode == 128
    assert _verdict(env, r.path, "git push -o 'a\nb' origin main") != PASS
