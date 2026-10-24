"""Review round 3 of 2026-10-09, R3-2: a `~name` in a `-C` value is not resolved by the gate.

Measured by the reviewer at 273763c3: in the running zsh `hash -d pb_review_named=/absolute/B`, under the command's
directory a literal folder `~pb_review_named` as a repository without a declaration, B with a committed declaration
that is not valid. `git -C ~pb_review_named push origin main` was inactive/nothing_declared for the literal folder,
while zsh runs git in B, where the gate would deny with gate_error. os.path.expanduser does not know zsh's named
directories.

The class: a `-C` value treated as resolved that is not the repository of the actual call. Now only the plain `~`
(alone or before a slash) is modelled; `~name` is state of the running shell, so the call is NOT MEASURED and no verdict
is given about either directory. Red against 273763c3.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

import test_plugin_review_fix3_r1_shell_words as r1
import test_plugin_review_fix_f2_globs as f2

gate = f2.gate
pytestmark = f2.pytestmark
_clean_git_environment = f2._clean_git_environment

NAMED = "git -C ~pb_review_named push origin main"


@pytest.fixture
def named(tmp_path) -> tuple[pathlib.Path, pathlib.Path]:
    """(work, B): work holds the literal folder `~pb_review_named` (no declaration); B has a declaration that is not
    valid. Both have main, an origin with a fetch refspec and refs/remotes/origin/main at the base commit."""
    work = tmp_path / "work"
    work.mkdir()
    r1._tracked(work / "~pb_review_named", tmp_path / "literal.git", None)
    b = tmp_path / "B"
    r1._tracked(b, tmp_path / "b.git", "this is not a valid declaration\n")
    return work, b


def _toplevel(shell: str, prefix: str, cwd: pathlib.Path) -> str:
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    proc = subprocess.run([shell, "-c", prefix + "git -C ~pb_review_named rev-parse --show-toplevel"], cwd=cwd,
                          capture_output=True, text=True, timeout=60, check=True)
    return os.path.realpath(proc.stdout.strip())


def test_zsh_runs_the_push_in_b_and_bash_in_the_literal_folder(named):
    """Non-vacuous: the two shells name different repositories, so the gate cannot pick one."""
    work, b = named
    assert _toplevel("zsh", f"hash -d pb_review_named={b}; ", work) == os.path.realpath(b)
    assert _toplevel("bash", "", work) == os.path.realpath(work / "~pb_review_named")


@pytest.mark.parametrize("value", ["~pb_review_named", "~root", "~root/x", "~nobody-such-user"])
def test_a_named_tilde_leaves_the_push_not_measured(value):
    calls = gate.gated_calls(f"git -C {value} push origin main", "/work")
    assert calls and all(directory is gate.UNKNOWN for _n, directory, _d in calls), calls


def test_under_claude_code_no_verdict_names_the_literal_folder(named):
    work, _b = named
    outcome = f2._decide(NAMED, work, "claude")
    assert outcome.decision not in ("pass", "inactive"), (outcome.decision, [v.reason_id for v in outcome.verdicts])
    literal = os.path.realpath(work / "~pb_review_named")
    judged = [getattr(v, "repo", None) for v in outcome.verdicts]
    assert all(r is None or os.path.realpath(r) != literal for r in judged), judged
    assert f2._host_answer(outcome, "claude") == "ask"


def test_under_codex_the_push_is_denied(named):
    work, _b = named
    assert f2._host_answer(f2._decide(NAMED, work, "codex"), "codex") == "deny"


@pytest.mark.parametrize("value,expected", [("~", "~"), ("~/x", "~/x")])
def test_control_the_plain_tilde_still_resolves(value, expected):
    (_name, directory, _detail), = gate.gated_calls(f"git -C {value} push origin main", "/work")
    assert directory == os.path.expanduser(expected)


def test_the_decisions_no_longer_call_the_named_form_modelled():
    text = (pathlib.Path(__file__).resolve().parents[1] / "plugins" / "proofbundle" / "DECISIONS.md").read_text(
        encoding="utf-8")
    assert "keeps the plain `~` and `~name` the gate joins" not in text
    assert "`~name` is not modelled" in text
