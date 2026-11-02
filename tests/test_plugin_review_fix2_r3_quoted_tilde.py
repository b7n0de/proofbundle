"""Review round 2 of 2026-10-09, R2-3: the repository the gate judges is the one git runs the command in.

Measured by the reviewer at 87dcbed8: `git -C '~' push origin main` was judged at the home repository (inactive,
nothing_declared), while git itself works in the directory cwd/~ (where the gate would deny, gate_error); the same
for "~" and \\~. The lexer removes the quotes, and the value reached os.path.expanduser without them.

The class: a value the shell keeps literal that the gate expanded. Now a `-C` value is expanded only where the shell
expands it: a tilde at the very start of the word as written, unquoted and unescaped, in a form expanduser reads like
the shell (`~`, `~name`, then a slash or the end). A quoted or escaped tilde is the literal directory `~` under the
command's directory. Red against 87dcbed8.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

import test_plugin_review_fix_f2_globs as f2

gate = f2.gate
pytestmark = f2.pytestmark
_clean_git_environment = f2._clean_git_environment

QUOTED = {"single quotes": "'~'", "double quotes": '"~"', "backslash": "\\~",
          "quoted with a path": "'~/x'", "escaped with a path": "\\~/x"}


@pytest.mark.parametrize("value", QUOTED.values(), ids=QUOTED.keys())
def test_a_quoted_tilde_names_the_directory_under_the_command_directory(value):
    calls = gate.gated_calls(f"git -C {value} push origin main", "/work")
    literal = value.strip("'\"").removeprefix("\\")
    assert [directory for _n, directory, _d in calls] == [os.path.join("/work", literal)], calls


@pytest.mark.parametrize("value,expected", [("~", "~"), ("~/x", "~/x")])
def test_control_an_unquoted_tilde_is_the_home_directory_as_before(value, expected):
    calls = gate.gated_calls(f"git -C {value} push origin main", "/work")
    assert [directory for _n, directory, _d in calls] == [os.path.expanduser(expected)], calls


@pytest.fixture
def home_repo(tmp_path, monkeypatch) -> pathlib.Path:
    """HOME is a repository with nothing declared; the command runs in another directory with no `~` in it."""
    home = tmp_path / "home"
    home.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(home)], check=True, timeout=60)
    (home / "a.txt").write_text("a\n", encoding="utf-8")
    f2._git(home, "add", "a.txt")
    f2._git(home, "commit", "-q", "-m", "home")
    monkeypatch.setenv("HOME", str(home))
    work = tmp_path / "work"
    work.mkdir()
    return work


@pytest.mark.parametrize("shell", ["bash", "zsh"])
@pytest.mark.parametrize("value", ["'~'", '"~"', "\\~"])
def test_claude_code_never_judges_the_home_repository_for_a_quoted_tilde(home_repo, value, shell):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    command = f"git -C {value} push origin main"
    proc = subprocess.run([shell, "-c", f"git -C {value} rev-parse --show-toplevel"], cwd=home_repo,
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode != 0 and "~" in proc.stderr, proc  # non-vacuous: git looks for cwd/~, not for HOME
    outcome = f2._decide(command, home_repo, "claude")
    home = os.path.realpath(os.environ["HOME"])
    judged = [getattr(v, "repo", None) for v in outcome.verdicts]
    assert all(r is None or os.path.realpath(r) != home for r in judged), (outcome.decision, judged)
    assert outcome.decision in ("deny", "ask"), outcome.decision
