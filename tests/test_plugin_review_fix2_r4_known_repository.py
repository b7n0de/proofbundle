"""Review round 2 of 2026-10-09, R2-4: every refusal with a known repository counts toward the repeat limit.

Measured by the reviewer at 87dcbed8: with a valid order, max_blocks=1 and remote.origin.promisor=true, show-toplevel
found the repository, the partial-clone guard refused the read of HEAD, and the failure carried a partial result with
repo null: five blocks, no counter file, no blocker. The result named the repository only after HEAD was read.

The class: every failure between show-toplevel and the point where the result named the repository. Now the result
names the repository the moment show-toplevel finds it, so a failure after that is counted like any other refusal:
after the default limit (the order is not read) the blocker is written and the session ends without a done verdict.
Red against 87dcbed8.
"""
from __future__ import annotations

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("key", ["remote.origin.promisor", "extensions.partialClone"])
def test_a_partial_clone_refused_before_head_ends_in_the_blocker(env, tmp_path, keys, host, key):
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._commit(repo, "the order")
    dc._run(repo, keys.signer, UNIT)
    dc._git(repo, "config", key, "origin" if key.startswith("extensions") else "true")
    blocker = f6.ends_in_the_blocker(env, repo, gate.DEFAULT_MAX_BLOCKS, "gate_error", host)
    assert blocker["open"][0]["id"] == "done-check"
    assert "promisor-related configuration" in blocker["open"][0]["detail"]


def test_removing_the_partial_clone_key_lets_the_check_go_on(env, tmp_path, keys):
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._commit(repo, "the order")
    dc._run(repo, keys.signer, UNIT)
    dc._git(repo, "config", "remote.origin.promisor", "true")
    f6.ends_in_the_blocker(env, repo, gate.DEFAULT_MAX_BLOCKS, "gate_error")
    dc._git(repo, "config", "--unset", "remote.origin.promisor")
    answer = f6.stop(env, repo)
    assert answer is not None and "done. 1 check (unit)" in answer["systemMessage"], answer
    assert not (repo / gate.DONE_BLOCKER).exists()
