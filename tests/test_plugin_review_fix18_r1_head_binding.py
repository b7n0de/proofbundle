"""Review round 18 of 2026-10-14, R18-1: HEAD is read in each inventory, and the binding read there must fit the HEAD
the gate checked.

Measured by the reviewer at 3604ba53 with git 2.43.0 and 2.51.1: `_root_records` read the HEAD file, checked its form
and dropped its value (`continue`). A real `git update-ref --no-deref HEAD D` right before the third original reading
moved HEAD to a declared commit D that nothing else names; the reading got `D\\n` and the exception stayed `inactive`,
also for the push of `HEAD:refs/heads/main`. A change before the second reading was passed over as well. The wrapper
below only fixes the moment of a real change; every git answer is git's own. Condition b names HEAD, so HEAD's direct
form and the allowed symbolic form belong to the comparison; a contradiction leaves the exception unapplied. Handled is
a difference the gate has read, not every later change of the repository. Run with git 2.43.0.
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_owner_choice1_ask_names_the_record_20261013 as a1
import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

HEAD_CHANGED = "so HEAD changed while the gate read it and its reading is no finished measurement that nothing is declared"


def _move_direct(work, declared):
    subprocess.run(["git", "-C", str(work), "update-ref", "--no-deref", "HEAD", declared], check=True)


def _move_symbolic(work, declared):
    subprocess.run(["git", "-C", str(work), "branch", "other", declared], check=True)
    subprocess.run(["git", "-C", str(work), "symbolic-ref", "HEAD", "refs/heads/other"], check=True)


def _setup(tmp_path, detached: bool):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    if detached:
        w1._git(work, "checkout", "-q", "--detach")
    return work, declared


def _wrap(monkeypatch, work, declared, at_call, move):
    """Run `move` right before the original HEAD reading of call `at_call` (the inventories read HEAD in _root_records)."""
    real, calls = gate._root_records, []

    def reading(*args, **kwargs):
        calls.append(1)
        if len(calls) == at_call:
            move(work, declared)
        return real(*args, **kwargs)

    monkeypatch.setattr(gate, "_root_records", reading)
    return calls


def _inactivity(work, head, push_args=("origin", "main")):
    return gate._local_inactivity(str(work), head, list(push_args), [head], time.monotonic() + 120)


@pytest.mark.parametrize("at_call", [2, 3], ids=["before_second", "before_third"])
@pytest.mark.parametrize("detached", [False, True], ids=["symbolic_head", "direct_head"])
def test_RED_a_head_moved_to_a_declared_commit_while_the_inventory_reads_it(tmp_path, monkeypatch, at_call, detached):
    work, declared = _setup(tmp_path, detached)
    head = w1.n2c._rev(work, "HEAD")
    calls = _wrap(monkeypatch, work, declared, at_call, _move_direct)
    verdict, why = _inactivity(work, head)
    assert len(calls) >= at_call, "precondition: the reading where HEAD moved ran"
    assert w1.n2c._rev(work, "HEAD") == declared, "precondition: HEAD resolves to the declared D now"
    assert verdict is None and why is not None and HEAD_CHANGED in why, why


def test_RED_the_symbolic_head_switched_to_another_listed_branch(tmp_path, monkeypatch):
    """HEAD names refs/heads/main at the start and refs/heads/side, a branch git lists at the clean A, in the third
    reading: the binding read contradicts the one checked, so the exception does not hold (3604ba53: inactive)."""
    work, declared = _setup(tmp_path, detached=False)
    a = w1.n2c._rev(work, "HEAD~1")
    w1._git(work, "branch", "side", a)
    head = w1.n2c._rev(work, "HEAD")

    def switch(work, _declared):
        subprocess.run(["git", "-C", str(work), "symbolic-ref", "HEAD", "refs/heads/side"], check=True)

    calls = _wrap(monkeypatch, work, declared, 3, switch)
    verdict, why = _inactivity(work, head)
    assert len(calls) >= 3, "precondition: the third reading ran"
    assert w1._git(work, "symbolic-ref", "HEAD").stdout.strip() == "refs/heads/side"
    assert verdict is None and why is not None and HEAD_CHANGED in why, why


def test_CONTROL_a_switch_to_a_ref_the_listing_does_not_hold_is_asked_as_before(tmp_path, monkeypatch):
    """A branch created at D during the third reading is not in git's listing of that inventory: HEAD naming it is
    outside the narrow contract, asked at 3604ba53 already."""
    work, declared = _setup(tmp_path, detached=False)
    head = w1.n2c._rev(work, "HEAD")
    _wrap(monkeypatch, work, declared, 3, _move_symbolic)
    verdict, why = _inactivity(work, head)
    assert verdict is None and why is not None and "a symbolic ref whose target is not a ref git lists" in why, why


def test_RED_the_push_of_a_head_refspec_is_not_inactive_after_a_read_move(tmp_path, monkeypatch):
    """The reviewer's reproduction at evaluate_push: `origin HEAD:refs/heads/main`, HEAD moved before the third reading."""
    work, declared = _setup(tmp_path, detached=False)
    _wrap(monkeypatch, work, declared, 3, _move_direct)
    verdict = gate.evaluate_push(str(work), ["origin", "HEAD:refs/heads/main"], time.monotonic() + 120)
    assert w1.n2c._rev(work, "HEAD") == declared, "precondition: a later resolution of HEAD gives D"
    assert verdict.decision != "inactive", verdict.text()
    assert verdict.decision == "ask" and HEAD_CHANGED in verdict.text(), verdict.text()


@pytest.mark.parametrize("detached", [False, True], ids=["symbolic_head", "direct_head"])
def test_CONTROL_a_stable_head_keeps_the_exception(tmp_path, monkeypatch, detached):
    work, declared = _setup(tmp_path, detached)
    head = w1.n2c._rev(work, "HEAD")
    calls = _wrap(monkeypatch, work, declared, None, _move_direct)
    verdict, why = _inactivity(work, head)
    assert len(calls) >= 3
    assert why is None and verdict is not None and verdict.decision == "inactive", why


def test_CONTROL_a_stable_head_refspec_push_stays_inactive(tmp_path):
    work, _declared = _setup(tmp_path, detached=False)
    verdict = gate.evaluate_push(str(work), ["origin", "HEAD:refs/heads/main"], time.monotonic() + 120)
    assert verdict.decision == "inactive" and verdict.reason_id == "nothing_declared_locally", verdict.text()
