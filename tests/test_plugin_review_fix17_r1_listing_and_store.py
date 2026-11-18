"""Review round 17 of 2026-10-13, R17-1: every inventory compares the object git lists for a direct ref with the object
the ref store holds, a valid loose file before its packed entry.

Measured by the reviewer at a85ac78e with git 2.43.0 and 2.51.1: condition d reads the inventory three times (the
destination's records, the present refs, and the final reading after the objects). Between git's listing and the reading
of the store in the third one, a real `git update-ref refs/heads/side D` moved a record to a declared commit D that
nothing else names. The store then held D, git's listing had given the clean commit A, the gate compared only the names,
and the map of the final reading still held A: `_local_inactivity` answered inactive. With `git pack-refs --all` after the
move the same held for a packed record. The same move at the second reading was refused. The wrapper below only fixes
the moment of a real ref change; every git answer is git's own. Run with git 2.43.0.
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

MOVED = ("names another object in git's listing than in the ref store, so the refs changed while the gate read them "
         "and its reading is no finished measurement that nothing is declared")
CHANGED = ("the local refs changed while the gate read them, so its reading is no finished measurement that nothing is "
           "declared")


def _case(tmp_path, monkeypatch, at_call: int | None, packed: bool):
    """The reviewer's case: refs/heads/side at the clean A, a declared D nothing names; at the store reading of call
    `at_call` side moves to D (and is packed), right before the original reading of the store."""
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "branch", "side", a)
    if packed:
        w1._git(work, "pack-refs", "--all")
    real, calls, seen = gate._stored_refs, [], []

    def store_reading(repo, paths, deadline):
        calls.append(1)
        if len(calls) == at_call:
            subprocess.run(["git", "-C", str(work), "update-ref", "refs/heads/side", declared], check=True)
            if packed:
                subprocess.run(["git", "-C", str(work), "pack-refs", "--all"], check=True)
        store, why = real(repo, paths, deadline)
        if store is not None and len(calls) == at_call:
            held = store["loose"].get("refs/heads/side")
            seen.append(held[1] if held is not None else store["packed"].get("refs/heads/side"))
        return store, why

    monkeypatch.setattr(gate, "_stored_refs", store_reading)
    head = w1.n2c._rev(work, "HEAD")
    verdict, why = gate._local_inactivity(str(work), head, ["origin", "main"], [head], time.monotonic() + 120)
    return work, declared, verdict, why, calls, seen


@pytest.mark.parametrize("packed", [False, True], ids=["loose", "packed"])
def test_RED_a_move_between_git_s_listing_and_the_store_in_the_final_reading(tmp_path, monkeypatch, packed):
    work, declared, verdict, why, calls, seen = _case(tmp_path, monkeypatch, 3, packed)
    assert len(calls) >= 3, "precondition: the third inventory ran"
    assert seen == [declared], "precondition: the original reading of the store gave D"
    assert w1.n2c._rev(work, "refs/heads/side") == declared, "precondition: the record still resolves to D"
    if packed:
        assert not (work / ".git" / "refs" / "heads" / "side").exists(), "precondition: the record is packed"
    assert verdict is None and why == f"the local ref refs/heads/side {MOVED}", why


@pytest.mark.parametrize("packed", [False, True], ids=["loose", "packed"])
def test_CONTROL_without_a_move_the_exception_holds(tmp_path, monkeypatch, packed):
    _work, _declared, verdict, why, _calls, _seen = _case(tmp_path, monkeypatch, None, packed)
    assert why is None and verdict is not None and verdict.decision == "inactive", why


@pytest.mark.parametrize("packed", [False, True], ids=["loose", "packed"])
def test_CONTROL_the_same_move_at_the_second_reading_is_refused(tmp_path, monkeypatch, packed):
    _work, declared, verdict, why, _calls, seen = _case(tmp_path, monkeypatch, 2, packed)
    assert seen == [declared]
    assert verdict is None and why in (f"the local ref refs/heads/side {MOVED}", CHANGED), why


def test_CONTROL_a_valid_loose_file_before_its_packed_entry_is_git_s_precedence(tmp_path):
    """The loose file wins over its packed predecessor in git's listing and in the gate's comparison alike."""
    work, _remote, a = w1._undeclared(tmp_path)
    c = w1.n2c._rev(work, "HEAD")
    w1._git(work, "branch", "side", a)
    w1._git(work, "pack-refs", "--all")
    w1._git(work, "update-ref", "refs/heads/side", c)               # a loose file now stands before the packed A
    assert (work / ".git" / "refs" / "heads" / "side").read_text().strip() == c
    assert f"{a} refs/heads/side" in (work / ".git" / "packed-refs").read_text()
    present, broken = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is not None and present["refs/heads/side"] == c and broken == set(), broken
