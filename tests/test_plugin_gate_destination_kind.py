"""The kind of an open destination reason is decided at one place (DECISIONS.md D35, DESIGN_gegenstelle.md 7.2).

`_dest_resolution` gives every reason the destination check of R8-2 and R9-1 names together with its kind: the value
does not name the destination, this repository records a candidate, or the default case, a candidate whose presence on
the remote is not known here. Only the last may be handed over to Level 2. `resolve_push_targets` collects the targets
of a push whose every refspec ends in that default case, and only those; the push stays unresolved for Level 1, and the
answer's reason is the one it was.
"""
from __future__ import annotations

import os
import shutil
import time

import pytest

import test_plugin_gate_n2c_push_done as base

gate = base.gate
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _deadline() -> float:
    return time.monotonic() + 60


def test_each_reason_carries_its_kind(tmp_path):
    r = base.Repo(tmp_path)
    repo = str(r.path)
    kind, why, step = gate._dest_resolution(repo, "origin", "refs/heads/main", "refs/heads/main", _deadline())
    assert kind == gate.DEST_OPEN_AT_REMOTE and "is not known here" in why and step == "have a person review the push"
    assert gate._dest_resolution_problem(repo, "origin", "refs/heads/main", "refs/heads/main", _deadline()) == (why, step)
    kind, why, _step = gate._dest_resolution(repo, "origin", "refs/heads/other", "refs/heads/main", _deadline())
    assert kind == gate.DEST_NOT_NAMED and "does not name refs/heads/main" in why
    base._git(r.path, "update-ref", "refs/recorded/origin/refs/heads/main", base._rev(r.path, "HEAD"))
    kind, why, _step = gate._dest_resolution(repo, "origin", "refs/heads/main", "refs/heads/main", _deadline())
    assert kind == gate.DEST_RECORDED_CANDIDATE and "this repository records refs/refs/heads/main" in why


@pytest.mark.parametrize("args", [["origin", "main"], ["origin", "refs/heads/main:refs/heads/main"], ["origin"]])
def test_the_default_case_collects_the_targets_and_leaves_the_push_unresolved(tmp_path, args):
    r = base.Repo(tmp_path)
    plain: list = []
    assert gate.resolve_push_targets(str(r.path), args, _deadline(), plain) is None
    reasons, handover = [], {"targets": [], "remote": None}
    assert gate.resolve_push_targets(str(r.path), args, _deadline(), reasons, handover) is None
    assert reasons == plain, "the answer keeps the reason it had"
    assert handover["remote"] == "origin"
    assert [(t.source, t.dest) for t in handover["targets"]] == [(base._rev(r.path, "HEAD"), "refs/heads/main")]


@pytest.mark.parametrize("args", [["origin", "+main"], ["origin", ":refs/heads/main"], ["origin", "main:refs/heads/x"]])
def test_a_force_a_deletion_and_another_reason_collect_nothing(tmp_path, args):
    r = base.Repo(tmp_path)
    handover = {"targets": [], "remote": None}
    assert gate.resolve_push_targets(str(r.path), args, _deadline(), [], handover) is None
    assert handover["targets"] == []


def test_a_recorded_candidate_collects_nothing(tmp_path):
    r = base.Repo(tmp_path)
    base._git(r.path, "update-ref", "refs/recorded/origin/refs/heads/main", base._rev(r.path, "HEAD"))
    handover = {"targets": [], "remote": None}
    assert gate.resolve_push_targets(str(r.path), ["origin", "main"], _deadline(), [], handover) is None
    assert handover == {"targets": [], "remote": None}


def test_one_refspec_with_another_reason_drops_what_was_collected(tmp_path):
    r = base.Repo(tmp_path)
    base._git(r.path, "branch", "other")
    handover = {"targets": [], "remote": None}
    args = ["origin", "main", "other:refs/heads/nowhere"]
    assert gate.resolve_push_targets(str(r.path), args, _deadline(), [], handover) is None
    assert handover == {"targets": [], "remote": None}
