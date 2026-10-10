"""Review round 8 of 2026-10-10, R8-5: the reason for a submodule setting names what is present, not what git does.

Measured by the reviewer at 1fc58527: `git config --add submodule.recurse true`, then `--add submodule.recurse false`.
The gate found the earlier true and said git push also pushes the submodules' commits; under git 2.43.0 and 2.51.1 the
later false (and push.recurseSubmodules=false) keeps the transport off. No false green: the push stays NOT MEASURED.

Owner choice B: A (2026-10-10): submodule.recurse true and push.recurseSubmodules on-demand or only stay NOT MEASURED
wherever such a value is present; only the reason is corrected. Verbatim for submodule.recurse: "The configuration
contains submodule.recurse=true; submodule push behavior is NOT MEASURED." Red against b1bd8824 (the reason).
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

NOT_MEASURED = ("ask", ["push_not_measured"])
VERBATIM = "The configuration contains submodule.recurse=true; submodule push behavior is NOT MEASURED."


def _repo(tmp_path, *pairs: tuple[str, str]) -> n2c.Repo:
    r = n2c.Repo(tmp_path)
    r.make("valid")
    for key, value in pairs:
        _git(r.path, "config", "--add", key, value)
    return r


def _effective(repo, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "config", *args], capture_output=True, text=True, timeout=60,
                          check=False).stdout.strip()


def _reason(repo) -> str | None:
    return gate._push_config_problem(str(repo), time.monotonic() + 60)


def _verdict(env, repo) -> tuple[str, list]:
    _answer, entry = n2c._level1(env, repo, command="git push origin main")
    return entry["verdict"], entry["reason_ids"]


def test_git_takes_the_last_value_of_submodule_recurse(tmp_path):
    """Non-vacuous: both values are present, the effective one is the later false."""
    r = _repo(tmp_path, ("submodule.recurse", "true"), ("submodule.recurse", "false"))
    assert _effective(r.path, "--get-all", "submodule.recurse").split("\n") == ["true", "false"]
    assert _effective(r.path, "--type=bool", "--get", "submodule.recurse") == "false"


@pytest.mark.parametrize("values", [("true",), ("true", "false"), ("false", "true")], ids="-".join)
def test_a_present_true_is_named_as_present_and_stays_not_measured(env, tmp_path, values):
    r = _repo(tmp_path, *(("submodule.recurse", v) for v in values))
    assert _reason(r.path) == VERBATIM
    assert _verdict(env, r.path) == NOT_MEASURED


@pytest.mark.parametrize("values", [("on-demand",), ("on-demand", "check"), ("only", "false")], ids="-".join)
def test_a_present_recursion_word_is_named_as_present_and_stays_not_measured(env, tmp_path, values):
    """The sibling: push.recurseSubmodules, where git also takes the last value (on-demand, then check, pushes no
    submodule commit)."""
    r = _repo(tmp_path, *(("push.recurseSubmodules", v) for v in values))
    assert _reason(r.path) == (f"The configuration contains push.recurseSubmodules={values[0]}; submodule push "
                               "behavior is NOT MEASURED.")
    assert _verdict(env, r.path) == NOT_MEASURED


def test_no_reason_claims_a_submodule_push(tmp_path):
    r = _repo(tmp_path, ("submodule.recurse", "true"), ("submodule.recurse", "false"))
    assert "pushes the submodules" not in (_reason(r.path) or "")


@pytest.mark.parametrize("pairs", [(), (("submodule.recurse", "false"),), (("push.recurseSubmodules", "check"),)],
                         ids=["none", "recurse_false", "check"])
def test_control_no_true_and_no_recursion_word_keeps_the_pass(env, tmp_path, pairs):
    r = _repo(tmp_path, *pairs)
    assert _reason(r.path) is None
    assert _verdict(env, r.path) == ("pass", ["done"])
