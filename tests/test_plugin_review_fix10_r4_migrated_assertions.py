"""Review round 10 of 2026-10-11, R10-4: a migrated assertion requires the concrete reason, not only an exit code or ask.

Measured by the reviewer at 1698db61 (git 2.51.1): with only run_level2 replaced by exit 1 and "NOT MEASURED: the gate ran
out of time", both assertions of test_a_graft_does_not_hide_a_commit_the_push_sends passed. Commit 25718967 changed 28
existing test files when every Level 1 push came to end at the destination check (R9-1). An audit of all 28 found, where
a concrete reason or value had stood before: three assertions in test_claude_code_plugin_gate.py (the two of the graft
test, and the double-dash test comparing only that both pushes reach the destination check), four in
test_plugin_review_fix7_r2_short_refname.py that assert rules_changed at neither level any more, and three Level 1
checks of ask alone (test_codex_plugin.py twice, test_claude_code_plugin_gate.py once). In the same class, unchanged
assertions that R9-1 made non-discriminating: four `resolve_push_targets(...) is None` in test_plugin_gate_runde5.py and
test_plugin_gate_runde6.py, which every push now satisfies.

Property: each of these tests fails when the answer it checks is replaced by an unrelated one of the same exit code or
decision. Each case below substitutes such an answer and expects the migrated test to fail. Red against 9aee00c0, whose
tests are those of 1698db61.
"""
from __future__ import annotations

import subprocess

import pytest

import test_claude_code_plugin_gate as cg
import test_codex_plugin as cx
import test_plugin_gate_n2c_push_done as n2c
import test_plugin_gate_runde5 as r5
import test_plugin_gate_runde6 as r6
import test_plugin_review_fix7_r2_short_refname as r72
from test_claude_code_plugin_gate import _clean_git_config, repo, shim  # noqa: F401  (fixtures)

pytestmark = cg.pytestmark if hasattr(cg, "pytestmark") else []
env = n2c.env
gate = cg.gate

TIMEOUT = "NOT MEASURED: the gate ran out of time"


def _timeout(*_args, **_kwargs) -> subprocess.CompletedProcess:
    """Level 2 failing for a reason that has nothing to do with the case: exit 1 and a time-out."""
    return subprocess.CompletedProcess(args=["pre-push"], returncode=1, stdout="", stderr=TIMEOUT)


def _unrelated_ask(*_args, **_kwargs) -> dict:
    """A Level 1 answer of the right shape (ask, NOT MEASURED, every part decision() checks) for an unrelated reason."""
    text = (f"{TIMEOUT}: Evidence: none, the gate ran out of time. Failed: the gate ran out of time. Next step: retry "
            f"the call. {cg.WEAKEN_RULE} Details: the gate ran out of time.")
    short = "Gate asks at git push because the gate reached no verdict (D10)."   # D53: the user's short line
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": short, "additionalContext": text},
            "systemMessage": short}


def test_the_graft_test_fails_on_an_unrelated_level_2_failure(shim, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(cg, "run_level2", _timeout)
    with pytest.raises(AssertionError):
        cg.test_a_graft_does_not_hide_a_commit_the_push_sends(shim, tmp_path)


def test_the_double_dash_test_fails_where_the_two_pushes_resolve_to_different_destinations(repo, monkeypatch):  # noqa: F811
    real = gate.resolve_push_targets

    def other_destination(directory, args, deadline, reasons=None):
        result = real(directory, args, deadline, reasons)
        if args and args[0] == "--" and reasons:
            reasons[0] = ("git push also matches refs/tags/elsewhere for refs/heads/elsewhere, and whether the remote "
                          "holds one of them is not known here", reasons[0][1])
        return result

    monkeypatch.setattr(gate, "resolve_push_targets", other_destination)
    with pytest.raises(AssertionError):
        cg.test_options_after_a_double_dash_are_the_remote_and_refspec(repo)


def test_the_working_tree_declaration_test_fails_on_an_unrelated_level_1_ask(shim, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(cg, "run_gate", _unrelated_ask)
    with pytest.raises(AssertionError):
        cg.test_a_declaration_only_in_the_working_tree_is_not_measured_and_asks(shim, tmp_path)


@pytest.mark.parametrize("name", ["test_under_codex_a_declaration_only_in_the_working_tree_is_not_measured_and_warns",
                                  "test_under_codex_a_rules_change_push_is_not_measured_while_claude_asks"])
def test_the_codex_tests_fail_on_an_unrelated_claude_ask(shim, tmp_path, monkeypatch, name):  # noqa: F811
    real = cx._run

    def claude_unrelated(env, folder, *args, **kwargs):
        return real(env, folder, *args, **kwargs) if "--host" in args else _unrelated_ask()

    monkeypatch.setattr(cx, "_run", claude_unrelated)
    with pytest.raises(AssertionError):
        getattr(cx, name)(shim, tmp_path)


@pytest.mark.parametrize("call", [
    lambda env, tmp_path: r72.test_the_bare_push_is_judged_as_the_push_git_performs(env, tmp_path, "upstream"),
    lambda env, tmp_path: r72.test_control_a_source_that_names_one_ref_is_judged(
        env, tmp_path, "git push origin HEAD:refs/heads/main"),
    lambda env, tmp_path: r72.test_control_without_the_tag_the_short_source_is_judged(env, tmp_path),
], ids=["bare-push", "one-ref", "without-tag"])
def test_the_short_refname_tests_fail_where_level_2_does_not_report_the_rules_change(env, tmp_path, monkeypatch, call):
    monkeypatch.setattr(n2c, "_level2", _timeout)
    with pytest.raises(AssertionError):
        call(env, tmp_path)


@pytest.mark.parametrize("call", [
    lambda tmp_path, monkeypatch: r5.test_r4_7_an_insteadof_rewrite_makes_ebene_1_not_measured(
        tmp_path, "url.https://mirror/.insteadOf"),
    lambda tmp_path, monkeypatch: r6.test_p2_a_rule_that_rewrites_this_remote_stays_not_measured(
        tmp_path, monkeypatch, "insteadOf"),
    lambda tmp_path, monkeypatch: r6.test_p2_insteadof_applies_to_an_explicit_pushurl(tmp_path),
    lambda tmp_path, monkeypatch: r6.test_r6_2_sibling_push_receive_pack_is_not_measured(
        tmp_path, ["--receive-pack=/tmp/ship.sh", "origin", "main"]),
], ids=["r5-insteadof", "r6-global-rule", "r6-pushurl-insteadof", "r6-receive-pack"])
def test_the_resolution_tests_fail_where_the_push_reaches_the_destination_check(tmp_path, monkeypatch, call):
    """Every push satisfies `resolve_push_targets(...) is None` since R9-1; these cases stop at an earlier step, so a
    resolution that reaches the destination check instead must fail them."""
    real = gate.resolve_push_targets

    def to_destination(directory, args, deadline, reasons=None):
        result = real(directory, args, deadline, reasons)
        if reasons is not None and not reasons:
            reasons.append(("git push also matches refs/refs/heads/main for refs/heads/main, and whether the remote "
                            "holds one of them is not known here", "have a person review the push"))
        return result

    monkeypatch.setattr(gate, "resolve_push_targets", to_destination)
    with pytest.raises(AssertionError):
        call(tmp_path, monkeypatch)
