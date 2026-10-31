"""Review round 2 of 2026-10-09, R2-5: the blocker the hook names exists and shows the last state it measured.

Measured by the reviewer at 87dcbed8, with an order paths=['src/*'], max_blocks=1, no receipt and a new file
docs/a.txt: two stops wrote the blocker; after renaming the file to docs/b.txt the third stop named the old blocker
with docs/a.txt and the old tree; after deleting the blocker file it was not written again, and the message still
pointed to it. The blocker was written only at the first stop past the limit, because the open points kept their ids
and statuses. And after a valid unit receipt, a tracked source replaced by a FIFO gave the right open point
state_not_measured, but the check showed status null with detail "verified".

The class: a blocker that reports an earlier state, and a check that was not judged reported as verified. Now every
stop past the limit writes the blocker from the verdict it reached (the counter of blockers still counts it once), and
a check whose tree is not judged says so instead of "verified". Red against 87dcbed8.
"""
from __future__ import annotations

import json
import os
import pathlib

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment


def _read(repo: pathlib.Path) -> dict:
    return json.loads((repo / gate.DONE_BLOCKER).read_text(encoding="utf-8"))


@pytest.fixture
def ordered(tmp_path, keys) -> pathlib.Path:
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"], max_blocks=1)
    dc._commit(repo, "the order")
    return repo


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_blocker_follows_the_state_after_a_rename(env, ordered, host):
    dc._write(ordered / "docs" / "a.txt", "a\n")
    assert f6.stop(env, ordered, host)["decision"] == "block"
    first = f6.stop(env, ordered, host)
    assert set(first) == {"systemMessage"} and _read(ordered)["outside_paths"] == ["docs/a.txt"]
    tree_before = _read(ordered)["working_tree"]
    os.rename(ordered / "docs" / "a.txt", ordered / "docs" / "b.txt")
    third = f6.stop(env, ordered, host)
    assert set(third) == {"systemMessage"} and gate.DONE_BLOCKER in third["systemMessage"], third
    blocker = _read(ordered)
    assert blocker["outside_paths"] == ["docs/b.txt"], blocker["outside_paths"]
    outside = [p for p in blocker["open"] if p["status"] == "outside_paths"]
    assert outside and outside[0]["outside"] == ["docs/b.txt"]
    assert blocker["working_tree"] != tree_before


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_deleted_blocker_is_written_again_before_the_message_names_it(env, ordered, host):
    dc._write(ordered / "docs" / "a.txt", "a\n")
    f6.stop(env, ordered, host)
    f6.stop(env, ordered, host)
    (ordered / gate.DONE_BLOCKER).unlink()
    answer = f6.stop(env, ordered, host)
    assert set(answer) == {"systemMessage"} and gate.DONE_BLOCKER in answer["systemMessage"], answer
    assert (ordered / gate.DONE_BLOCKER).is_file()
    assert _read(ordered)["outside_paths"] == ["docs/a.txt"]


def test_the_blocker_counter_still_counts_one_blocker(env, ordered):
    dc._write(ordered / "docs" / "a.txt", "a\n")
    for _ in range(4):
        f6.stop(env, ordered)
    metrics = json.loads((ordered / gate.DONE_METRICS).read_text(encoding="utf-8"))
    assert metrics["blockers"] == 1, metrics


def test_a_check_whose_tree_was_not_judged_is_not_called_verified(env, tmp_path, keys):
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._commit(repo, "the order")
    dc._run(repo, keys.signer, UNIT)
    (repo / "src" / "module.py").unlink()
    os.mkfifo(repo / "src" / "module.py")
    blocker = f6.ends_in_the_blocker(env, repo, 1, "state_not_measured")
    (check,) = blocker["checks"]
    assert check["id"] == "unit" and check["status"] is None
    assert check["detail"] != "verified" and "not judged" in check["detail"], check


def test_control_a_green_check_is_still_called_verified(env, tmp_path, keys):
    """A check that verified and an open point elsewhere: the green check keeps the word verified."""
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"], max_blocks=1)
    dc._commit(repo, "the order")
    dc._run(repo, keys.signer, UNIT)
    blocker = f6.ends_in_the_blocker(env, repo, 1, "no_change")
    assert [(c["id"], c["status"], c["detail"]) for c in blocker["checks"]] == [("unit", "green", "verified")]
