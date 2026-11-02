"""Review round 5 of 2026-10-09, R5-3: a present count record that does not serve as a running count is visible.

Measured by the reviewer at 9d333d1c: R4-3 bound the session by its sha256 (session_sha256) and kept the schema value
proofbundle-plugin/done-state/v0.1. A record an older gate (f0e25574) wrote names the session in clear (session="s"),
so the new gate read it, found no session_sha256 and counted blocks=1 again, without a word; a record of the right
schema whose blocks is "1" (a string) restarted the same way. The bounded end after max_blocks blocks without progress
then came one stop later, or never if every stop alternated.

Property: a present record that does not serve as a running count is made visible. The record the hook reads is now
checked field by field, not by its schema value alone; the older form (session in clear) is taken over by its sha256;
anything else that is present and unusable restarts the count with the reason named in the block. Red against 9d333d1c
for the old form and for every malformed field that restarted in silence. Both hosts.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6
import test_plugin_review_fix4_r3_counter_readable as r43

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment

SCHEMA = "proofbundle-plugin/done-state/v0.1"
OPEN = [["unit", "missing"]]
HASH_S = hashlib.sha256(b"s").hexdigest()
NOT_DONE = "proofbundle done check: NOT DONE. The same open points stayed open through 1 blocks"


def _ordered(tmp_path: pathlib.Path, keys) -> pathlib.Path:
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._commit(repo, "the order")
    return repo


def _record(repo: pathlib.Path, doc: dict) -> None:
    """The bytes the gate's writer produces, at f0e25574 and since (json.dumps(indent=1, sort_keys=True) + LF)."""
    (repo / ".proofbundle").mkdir(exist_ok=True)
    (repo / gate.DONE_STATE).write_bytes((json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8"))


def _ended(answer: dict | None) -> bool:
    return answer is not None and set(answer) == {"systemMessage"} and answer["systemMessage"].startswith(NOT_DONE)


def _named(answer: dict | None) -> bool:
    return (answer is not None and answer.get("decision") == "block" and "could not be read" in answer["reason"]
            and gate.DONE_STATE in answer["reason"])


def test_the_open_signature_of_the_order_is_the_one_used_here(env, tmp_path, keys):
    """Non-vacuous: the records below carry the open points the gate itself writes for this order."""
    repo = _ordered(tmp_path, keys)
    r43.stop(env, repo, "claude", "s")
    doc = json.loads((repo / gate.DONE_STATE).read_text(encoding="utf-8"))
    assert doc["open"] == OPEN and doc["blocks"] == 1 and doc["session_sha256"] == HASH_S, doc


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_record_of_the_older_gate_continues_the_count(env, tmp_path, keys, host):
    """The reviewer's case: f0e25574 counted one block for session "s"; the next stop of the same session with the
    same open points is the second block without progress, past max_blocks=1, so the session ends NOT DONE."""
    repo = _ordered(tmp_path, keys)
    _record(repo, {"schema": SCHEMA, "session": "s", "open": OPEN, "blocks": 1, "blocker": False})
    answer = r43.stop(env, repo, host, "s")
    assert _ended(answer), answer
    blocker = json.loads((repo / gate.DONE_BLOCKER).read_text(encoding="utf-8"))
    assert blocker["blocks_without_progress"] == 1, blocker


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_record_of_the_older_gate_for_another_session_starts_a_new_count(env, tmp_path, keys, host):
    """The control of the adoption: the session stays exact, an old record of session "t" is not session "s"."""
    repo = _ordered(tmp_path, keys)
    _record(repo, {"schema": SCHEMA, "session": "t", "open": OPEN, "blocks": 1, "blocker": False})
    answer = r43.stop(env, repo, host, "s")
    assert answer is not None and answer.get("decision") == "block" and not _named(answer), answer
    doc = json.loads((repo / gate.DONE_STATE).read_text(encoding="utf-8"))
    assert doc["blocks"] == 1 and doc["session_sha256"] == HASH_S and "session" not in doc, doc


VALID = {"schema": SCHEMA, "session_sha256": HASH_S, "open": OPEN, "blocks": 1, "blocker": False}
MALFORMED = {
    "blocks_string": {"blocks": "1"},
    "blocks_true": {"blocks": True},
    "blocks_negative": {"blocks": -1},
    "blocks_float": {"blocks": 1.0},
    "open_string": {"open": "x"},
    "open_short_pair": {"open": [["unit"]]},
    "open_number_status": {"open": [["unit", 1]]},
    "session_number": {"session_sha256": 5},
    "session_short": {"session_sha256": HASH_S[:63]},
    "session_upper": {"session_sha256": HASH_S.upper()},
    "blocker_string": {"blocker": "no"},
    "blocker_missing": {"blocker": None},
    "session_missing": {"session_sha256": None},
    "both_session_forms": {"session": "s"},
    "unknown_field": {"extra": 1},
}


def _malformed(change: dict) -> dict:
    doc = dict(VALID)
    for key, value in change.items():
        if value is None:
            doc.pop(key)
        else:
            doc[key] = value
    return doc


@pytest.mark.parametrize("case", list(MALFORMED))
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_record_that_is_no_running_count_is_named_not_restarted_in_silence(env, tmp_path, keys, host, case):
    """The schema value alone does not make a record usable: each field is checked. Where it does not serve as a
    count, the block names the record and why, and the hook writes its own record again."""
    repo = _ordered(tmp_path, keys)
    _record(repo, _malformed(MALFORMED[case]))
    answer = r43.stop(env, repo, host, "s")
    assert _named(answer), answer
    doc = gate._read_done_file(str(repo), gate.DONE_STATE, "state")
    assert doc == {"schema": SCHEMA, "session_sha256": HASH_S, "open": OPEN, "blocks": 1, "blocker": False}, doc
    assert _ended(r43.stop(env, repo, host, "s")), "after the named restart the next stop counts again"


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_a_valid_record_continues_the_count(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    _record(repo, VALID)
    assert _ended(r43.stop(env, repo, host, "s"))


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_a_valid_record_of_other_open_points_is_progress_not_a_problem(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    _record(repo, dict(VALID, open=[["integration", "missing"]]))
    answer = r43.stop(env, repo, host, "s")
    assert answer is not None and answer.get("decision") == "block" and not _named(answer), answer


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_a_valid_record_of_another_session_starts_a_new_count(env, tmp_path, keys, host):
    repo = _ordered(tmp_path, keys)
    _record(repo, dict(VALID, session_sha256=hashlib.sha256(b"t").hexdigest()))
    answer = r43.stop(env, repo, host, "s")
    assert answer is not None and answer.get("decision") == "block" and not _named(answer), answer


def test_control_no_record_is_a_first_block_without_a_notice(env, tmp_path, keys):
    repo = _ordered(tmp_path, keys)
    answer = r43.stop(env, repo, "claude", "s")
    assert answer is not None and answer.get("decision") == "block" and not _named(answer), answer
