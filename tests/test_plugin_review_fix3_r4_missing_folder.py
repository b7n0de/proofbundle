"""Review round 3 of 2026-10-09, R3-4: a refusal with a known repository is counted, or the failed count is visible.

Measured by the reviewer at 273763c3: a valid order and policy with max_blocks=1 committed, the working-tree folder
.proofbundle moved out of the repository, four stops with the same session_id and cwd: four times block/no_receipt,
no counter file, no blocker, and the answer named only the missing receipt. With an empty .proofbundle the second
stop wrote the blocker NOT DONE. The count depended silently on writing a file into a folder that was not there.

Now the hook makes the folder when nothing is at its path, so the count goes on and the session ends NOT DONE after
the order's limit; where the folder cannot be made or written (a file stands at its path) every block names that the
count could not be recorded and that the bounded end cannot take effect. Red against a5434981.
"""
from __future__ import annotations

import json
import pathlib
import shutil

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment


def _ordered(tmp_path: pathlib.Path, keys) -> pathlib.Path:
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._commit(repo, "the order")
    return repo


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_removed_evidence_folder_still_ends_in_the_blocker(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    shutil.move(str(repo / ".proofbundle"), str(tmp_path / "moved-away"))
    first = f6.stop(env, repo, host)
    assert first is not None and first.get("decision") == "block", first
    second = f6.stop(env, repo, host)
    assert second is not None and set(second) == {"systemMessage"}, second
    assert second["systemMessage"].startswith("proofbundle done check: NOT DONE. The same open points stayed open "
                                              "through 1 blocks"), second
    blocker = json.loads((repo / gate.DONE_BLOCKER).read_text(encoding="utf-8"))
    assert blocker["verdict"] == "NOT DONE"


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_folder_that_cannot_be_written_is_named_in_every_block(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    shutil.move(str(repo / ".proofbundle"), str(tmp_path / "moved-away"))
    (repo / ".proofbundle").write_text("a file where the folder belongs\n", encoding="utf-8")
    for _ in range(3):
        answer = f6.stop(env, repo, host)
        assert answer is not None and answer.get("decision") == "block", answer
        assert "The hook could not count this block" in answer["reason"], answer
        assert "cannot take effect" in answer["reason"]


def test_control_with_the_folder_in_place_the_blocker_comes_at_the_second_stop(env, tmp_path, keys):
    repo = _ordered(tmp_path, keys)
    first = f6.stop(env, repo)
    assert first is not None and first.get("decision") == "block"
    assert "could not count" not in first["reason"]
    second = f6.stop(env, repo)
    assert second is not None and set(second) == {"systemMessage"}, second
