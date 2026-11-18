"""D38, owner choice O3 of follow-up note 13: a local done order whose repository git no longer finds counts its blocks in the
gate directory.

Before, such an order blocked every end without a count; the review session measured a moved clone under Codex block six times with no
end. Now its blocks are counted beside the order, and after max_blocks the session ends without a done verdict, under
Claude Code and under Codex, as in D26. The order stays, and `done-order --list` names it.

RED at f6408b97 (no end); the control, an open order whose repository is there, blocks and ends as before at both.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as d
import test_plugin_done_local_order as lo
from _owner_state import owner_state_protected  # noqa: F401 - D128: a person's local done order is read

pytestmark = d.pytestmark
_clean_git_config = d._clean_git_config
env, repo, keys = d.env, d.repo, d.keys
gate = d.gate
LIMIT = gate.DEFAULT_MAX_BLOCKS


def _ends_without_a_done_verdict(answer: dict | None) -> str:
    assert answer is not None and "decision" not in answer, answer
    message = answer["systemMessage"]
    assert "NOT DONE" in message and "ends without a done verdict" in message, message
    return message


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_O3_a_moved_clone_ends_without_a_done_verdict_after_max_blocks(env, repo, keys, tmp_path, host):
    order = lo._local_order(env, repo, keys.public)
    repo.rename(repo.with_name("moved"))
    session = lo._session_dir(tmp_path)
    for _ in range(LIMIT):
        assert "git does not find the repository it names" in d.blocked(lo._stop(env, session, host))
    message = _ends_without_a_done_verdict(lo._stop(env, session, host))
    blocker = order.with_name(order.name.replace(".json", ".blocker.json"))
    assert str(blocker) in message and blocker.is_file(), message
    listed = subprocess.run([sys.executable, "-I", str(d.GATE), "done-order", "--list"], capture_output=True,
                            text=True, env=env, timeout=120, check=False)
    assert listed.returncode == 0 and "order_unbound" in listed.stdout and order.is_file(), listed


def test_O3_remove_takes_the_count_of_the_gate_directory_along(env, repo, keys, tmp_path):
    order = lo._local_order(env, repo, keys.public)
    repo.rename(repo.with_name("moved"))
    d.blocked(lo._stop(env, lo._session_dir(tmp_path)))
    state = order.with_name(order.name.replace(".json", ".state.json"))
    assert state.is_file()
    assert lo._done_order(env, "--remove", "--repo", str(repo)).returncode == 0
    assert not any(pathlib.Path(order.parent).glob(order.name.replace(".json", ".*")))


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_O3_control_an_open_order_whose_repository_is_there_blocks_and_ends_as_before(env, repo, keys, tmp_path, host):
    lo._local_order(env, repo, keys.public)
    session = lo._session_dir(tmp_path)
    for _ in range(LIMIT):
        assert "check tests is missing" in d.blocked(lo._stop(env, session, host))
    message = _ends_without_a_done_verdict(lo._stop(env, session, host))
    assert str(gate.DONE_BLOCKER) in message and (repo / gate.DONE_BLOCKER).is_file(), message


def _start(env: dict, cwd: pathlib.Path) -> dict | None:
    """The SessionStart hook of D127 as the plugin starts it; None where it prints nothing."""
    event = {"hook_event_name": "SessionStart", "session_id": "next", "cwd": str(cwd), "source": "startup",
             "transcript_path": str(cwd / "next.jsonl")}
    proc = subprocess.run([sys.executable, "-I", str(d.GATE), "session-start"], input=json.dumps(event),
                          capture_output=True, text=True, env=env, cwd=cwd, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def test_O3_the_next_session_start_names_the_blocker_and_hands_nothing_on(env, repo, keys, tmp_path):
    """D127, owner answer A on card OA-694b3f17d4 (reading of G-6, sol-pro, measured): a session that ended NOT DONE on
    an order whose repository git does not find leaves <key>.blocker.json beside the order. The next start names that
    blocker to the user and hands nothing on, since there is no repository to work in; done-order --list names the
    order and a person removes it. RED before: the start printed nothing. Control: without the protected channel of
    D128 the hook reads no order, and the start stays silent."""
    order = lo._local_order(env, repo, keys.public)
    repo.rename(repo.with_name("moved"))
    session = lo._session_dir(tmp_path)
    for _ in range(LIMIT + 1):
        lo._stop(env, session, "claude")
    blocker = order.with_name(order.name.replace(".json", ".blocker.json"))
    assert blocker.is_file()
    answer = _start({**env, "PROOFBUNDLE_OWNER_STATE": "protected"}, session)
    assert answer is not None and "hookSpecificOutput" not in answer, answer
    message = answer["systemMessage"]
    assert str(blocker) in message and "done-order --remove" in message and "(D127, O3)" in message, message
    without = {k: v for k, v in env.items() if k != "PROOFBUNDLE_OWNER_STATE"}
    assert _start(without, session) is None
