"""Review round 8 of 2026-10-10, R8-5: the reason for a submodule setting names what is present, not what git does.

Measured by the reviewer at 1fc58527: `git config --add submodule.recurse true`, then `--add submodule.recurse false`.
The gate found the earlier true and said git push also pushes the submodules' commits; under git 2.43.0 and 2.51.1 the
later false (and push.recurseSubmodules=false) keeps the transport off. No false green: the push stays NOT MEASURED.

Owner choice B: A (2026-10-10): submodule.recurse true and push.recurseSubmodules on-demand or only stay NOT MEASURED
wherever such a value is present; only the reason is corrected. Verbatim for submodule.recurse: "The configuration
contains submodule.recurse=true; submodule push behavior is NOT MEASURED." Red against b1bd8824 (the reason).
"""
from __future__ import annotations

import json
import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

#: NOT MEASURED at the submodule setting, before the destination check.
NOT_MEASURED = ("ask", ["push_not_measured"], False)
#: The wording of R8-5 named the value read ("contains submodule.recurse=true"); D63 (O22-2 of R25-1)
#: names the key and keeps the verdict, NOT MEASURED.
VERBATIM = "The configuration sets submodule.recurse; submodule push behavior is NOT MEASURED."


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


def _verdict(env, repo) -> tuple[str, list, bool]:
    """The verdict, its reasons, and whether the resolution reached the destination check (R9-1)."""
    answer, entry = n2c._level1(env, repo, command="git push origin main")
    return entry["verdict"], entry["reason_ids"], n2c.reached_destination(json.dumps(answer, ensure_ascii=False))


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
    assert _reason(r.path) == ("The configuration sets push.recurseSubmodules to a value that recurses; submodule push "
                               "behavior is NOT MEASURED.")
    assert _verdict(env, r.path) == NOT_MEASURED


def test_no_reason_claims_a_submodule_push(tmp_path):
    r = _repo(tmp_path, ("submodule.recurse", "true"), ("submodule.recurse", "false"))
    assert "pushes the submodules" not in (_reason(r.path) or "")


@pytest.mark.parametrize("pairs", [(), (("submodule.recurse", "false"),), (("push.recurseSubmodules", "check"),)],
                         ids=["none", "recurse_false", "check"])
def test_control_no_true_and_no_recursion_word_keeps_the_pass(env, tmp_path, pairs):
    """No reason at the submodule setting: the push resolves up to the destination check (since R9-1 that leaves it
    NOT MEASURED); the pre-push hook passes it."""
    r = _repo(tmp_path, *pairs)
    assert _reason(r.path) is None
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path, command="git push origin main"))
    assert n2c._level2(env, r.path).returncode == 0


def test_the_answer_carries_the_reason_verbatim(env, tmp_path):
    """The wording is for the user: the answer carries it, with a next step for that value. Until 87dd0d5d the reason
    stayed inside the gate and the answer named other causes (a URL remote, --all, a wildcard). Under Codex every push
    is NOT MEASURED before its configuration is read (D12), so this is Claude Code's answer."""
    r = _repo(tmp_path, ("submodule.recurse", "true"))
    answer, _entry = n2c._level1(env, r.path, command="git push origin main")
    text = json.dumps(answer, ensure_ascii=False)
    assert VERBATIM in text, text
    assert "fix or remove that configuration value" in text and "a wildcard refspec" not in text, text
    assert not n2c.reached_destination(text), text
