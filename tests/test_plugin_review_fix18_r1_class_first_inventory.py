"""Review round 18 of 2026-10-14, the class of R18-1: the first inventory read values and dropped them after their form
checks.

Measured here at 3604ba53 and at bab25ff2 with git 2.43.0: `_destination_records` runs the first inventory of the local
refs, keeps only the records of the destination and dropped everything else it read, HEAD included. A real change made
right before that reading and taken back right after it (HEAD detached at a declared D, a branch, a tag or ORIG_HEAD at
D, a further record naming D, or HEAD naming another listed branch) left the exception `inactive`, although the first
inventory had read it. The wrapper below only fixes the moment of a real change; every git answer is git's own. Handled
is a difference the gate has read, not every later change of the repository. Run with git 2.43.0.
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
REFS_CHANGED = ("the local refs changed while the gate read them, so its reading is no finished measurement that nothing "
                "is declared")


def _git(work, *args):
    subprocess.run(["git", "-C", str(work), *args], check=True, capture_output=True)


def _setup(tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    _git(work, "branch", "side", a)
    return work, a, declared


def _moves(work, a, declared):
    further = work / ".git" / "custom" / "rec"
    return {
        "head_direct": (lambda: _git(work, "update-ref", "--no-deref", "HEAD", declared),
                        lambda: _git(work, "symbolic-ref", "HEAD", "refs/heads/main"), HEAD_CHANGED),
        "head_symbolic_listed": (lambda: _git(work, "symbolic-ref", "HEAD", "refs/heads/side"),
                                 lambda: _git(work, "symbolic-ref", "HEAD", "refs/heads/main"), HEAD_CHANGED),
        "branch": (lambda: _git(work, "update-ref", "refs/heads/side", declared),
                   lambda: _git(work, "update-ref", "refs/heads/side", a), REFS_CHANGED),
        "tag": (lambda: _git(work, "tag", "t1", declared), lambda: _git(work, "tag", "-d", "t1"), REFS_CHANGED),
        "orig_head": (lambda: _git(work, "update-ref", "--no-deref", "ORIG_HEAD", declared),
                      lambda: _git(work, "update-ref", "-d", "--no-deref", "ORIG_HEAD"), REFS_CHANGED),
        "further_record": (lambda: (further.parent.mkdir(exist_ok=True), further.write_text(f"{declared}\n")),
                           lambda: further.unlink(), REFS_CHANGED),
    }


def _wrap(monkeypatch, before, after):
    """Run `before` right before the first inventory and `after` right after it."""
    real, calls = gate._present_refs, []

    def reading(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            before()
        answer = real(*args, **kwargs)
        if len(calls) == 1:
            after()
        return answer

    monkeypatch.setattr(gate, "_present_refs", reading)
    return calls


def _inactivity(work, head):
    return gate._local_inactivity(str(work), head, ["origin", "main"], [head], time.monotonic() + 120)


@pytest.mark.parametrize("what", ["head_direct", "head_symbolic_listed", "branch", "tag", "orig_head",
                                  "further_record"])
def test_RED_a_change_only_the_first_inventory_read_is_not_dropped(tmp_path, monkeypatch, what):
    work, a, declared = _setup(tmp_path)
    head = w1.n2c._rev(work, "HEAD")
    before, after, expected = _moves(work, a, declared)[what]
    calls = _wrap(monkeypatch, before, after)
    verdict, why = _inactivity(work, head)
    assert len(calls) >= 1, "precondition: the first inventory ran"
    assert w1.n2c._rev(work, "HEAD") == head, "precondition: the change was taken back after the first inventory"
    assert verdict is None and why is not None and expected in why, why


def test_RED_a_head_read_otherwise_in_the_first_inventory_stops_there(tmp_path, monkeypatch):
    """The HEAD the first inventory read is compared at once, so the reading may stop after the first inventory."""
    work, a, declared = _setup(tmp_path)
    head = w1.n2c._rev(work, "HEAD")
    before, after, _expected = _moves(work, a, declared)["head_direct"]
    calls = _wrap(monkeypatch, before, after)
    verdict, why = _inactivity(work, head)
    assert len(calls) == 1 and verdict is None and HEAD_CHANGED in why, (len(calls), why)


def test_CONTROL_a_stable_repository_keeps_the_exception(tmp_path, monkeypatch):
    work, _a, _declared = _setup(tmp_path)
    head = w1.n2c._rev(work, "HEAD")
    calls = _wrap(monkeypatch, lambda: None, lambda: None)
    verdict, why = _inactivity(work, head)
    assert len(calls) == 3 and why is None and verdict is not None and verdict.decision == "inactive", why


def test_CONTROL_a_change_that_stays_is_named_by_the_inventory_of_the_present_refs_as_before(tmp_path, monkeypatch):
    work, a, declared = _setup(tmp_path)
    head = w1.n2c._rev(work, "HEAD")
    _wrap(monkeypatch, lambda: _git(work, "update-ref", "refs/heads/side", declared), lambda: None)
    verdict, why = _inactivity(work, head)
    assert verdict is None and why is not None and why.startswith("the local ref refs/heads/side holds something at"), why


def test_CONTROL_the_level_1_answer_stays_inactive_for_a_stable_repository(env, tmp_path):
    work, _a, _declared = _setup(tmp_path)
    answer, entry, text = w1._l1(env, work)
    w1._assert_inactive(answer, entry, text)
