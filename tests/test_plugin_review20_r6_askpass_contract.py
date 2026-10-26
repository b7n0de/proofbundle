"""R20-6 of review round 20 (Nachtrag 10 to FIX-18), owner choice 1 of 2026-10-15: the ASKPASS contract of D35.

An ASKPASS program that was set when the transport was approved and is unchanged belongs, with its sha256, to the
approved transport, and the hand-over is then allowed. There is no hand-over for a value that changed, is empty, cannot
be modelled, or was set only after the approval. The approved case is the control; the four others ask and write no
record. The approved case also runs the push through both levels.
"""
from __future__ import annotations

import pathlib

import pytest

import test_plugin_gate_push_destination_18 as g18

pytestmark = g18.pytestmark
_clean_git_environment = g18._clean_git_environment
env = g18.env
base = g18.base


def _program(tmp_path: pathlib.Path, name: str = "askpass.sh") -> pathlib.Path:
    program = tmp_path / name
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o755)
    return program


@pytest.mark.parametrize("name", ["GIT_ASKPASS", "SSH_ASKPASS"])
def test_R20_6_control_an_askpass_approved_and_unchanged_is_handed_over_and_pushed(env, tmp_path, name):
    program = _program(tmp_path)
    run_env = dict(env, **{name: str(program)})
    r = g18._repo(tmp_path, run_env, approve=False)
    g18._approve(run_env, r.path)
    before = g18._remote(tmp_path)
    answer, entry = g18._level1(run_env, r.path)
    g18.assert_handed_over(answer, entry)
    assert len(g18._records(run_env)) == 1
    proc = g18._push(run_env, r.path)
    assert proc.returncode == 0, proc.stderr
    assert g18._remote(tmp_path) == base._rev(r.path, "HEAD") != before
    assert "checked the update set of hand-over" in proc.stderr


@pytest.mark.parametrize("case", ["changed_bytes", "other_program", "empty", "not_modelled", "set_after_approval"])
def test_R20_6_an_askpass_that_is_not_the_approved_one_gets_no_hand_over(env, tmp_path, case):
    program = _program(tmp_path)
    approved_value = {"empty": "", "not_modelled": "askpass-helper-not-on-path",
                      "set_after_approval": None}.get(case, str(program))
    approval_env = dict(env) if approved_value is None else dict(env, GIT_ASKPASS=approved_value)
    r = g18._repo(tmp_path, approval_env, approve=False)
    g18._approve(approval_env, r.path)
    hook_value = {"other_program": str(_program(tmp_path, "other.sh")), "set_after_approval": str(program)}.get(
        case, approved_value)
    if case == "changed_bytes":
        program.write_text("#!/bin/sh\necho changed\nexit 0\n", encoding="utf-8")
    run_env = dict(env, GIT_ASKPASS=hook_value)
    answer, entry = g18._level1(run_env, r.path)
    why = {"empty": "GIT_ASKPASS names a program path the gate does not model",
           "not_modelled": "GIT_ASKPASS"}.get(case, "the transport is not approved")
    g18.assert_asked_without_handover(answer, entry, why)
    assert not g18._pointer(r.path).exists() and g18._records(run_env) == []
