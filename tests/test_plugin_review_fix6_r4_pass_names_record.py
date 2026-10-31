"""Review round 6 of 2026-10-10, R6-4: an unusable count record stays visible on a successful end too.

Measured by the reviewer at b513ff5a: a record with blocks "1" (a string) and a valid receipt; the Stop hook said only
"done" and wrote blocks 0 over the record. R5-3 had promised that a present record which does not serve as a running
count is named, and kept that promise for a refused end only (_account_pass read the record's problem and dropped it).

Property: a present record the hook cannot use is named wherever the hook replaces it, on a done end as on a refused
one; so is a record it cannot write. Red against the R6-3 commit. Both hosts.
"""
from __future__ import annotations

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
HASH_S = "043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89"   # sha256("s")


def _done_repo(tmp_path: pathlib.Path, keys) -> pathlib.Path:
    """An order with paths src/* and one check, the work inside the paths, a valid receipt for it: a done end."""
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(repo, "the order")
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    dc._run(repo, keys.signer, UNIT)
    return repo


def _record(repo: pathlib.Path, raw: bytes) -> None:
    (repo / ".proofbundle").mkdir(exist_ok=True)
    (repo / gate.DONE_STATE).write_bytes(raw)


def _doc(**fields) -> bytes:
    doc = {"schema": SCHEMA, "session_sha256": HASH_S, "open": [], "blocks": 0, "blocker": False, **fields}
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")


def _message(answer: dict | None) -> str:
    """The message of a done end. Since D53 a done end without a finding prints nothing, and its message is empty;
    a finding of the hook's own files stays a message, no block."""
    if answer is None:
        return ""
    assert set(answer) == {"systemMessage"}, answer
    return answer["systemMessage"]


def _rewritten(repo: pathlib.Path) -> dict:
    return json.loads((repo / gate.DONE_STATE).read_text(encoding="utf-8"))


def test_control_a_done_end_without_a_record_says_done_and_starts_the_count(env, tmp_path, keys):
    repo = _done_repo(tmp_path, keys)
    message = _message(r43.stop(env, repo, "claude", "s"))
    assert "could not" not in message, message
    assert _rewritten(repo)["blocks"] == 0


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_record_with_blocks_as_a_string_is_named_on_a_done_end(env, tmp_path, keys, host):
    """The reviewer's case."""
    repo = _done_repo(tmp_path, keys)
    _record(repo, _doc(blocks="1"))
    message = _message(r43.stop(env, repo, host, "s"))
    assert "could not be read" in message and gate.DONE_STATE in message, message
    assert "its block count is not a whole number" in message, message
    assert _rewritten(repo)["blocks"] == 0   # the hook's own record replaces it, as on a refused end


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("raw", [b"not json\n", b'{"schema": "proofbundle-plugin/done-state/v0.1"}\n'],
                         ids=["not_json", "fields_missing"])
def test_any_unusable_record_is_named_on_a_done_end(env, tmp_path, keys, host, raw):
    repo = _done_repo(tmp_path, keys)
    _record(repo, raw)
    message = _message(r43.stop(env, repo, host, "s"))
    assert "could not be read" in message and gate.DONE_STATE in message, message


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_record_the_hook_cannot_replace_is_named_on_a_done_end(env, tmp_path, keys, host):
    """A directory where the record belongs: the hook can neither read nor replace it, and says so."""
    repo = _done_repo(tmp_path, keys)
    (repo / gate.DONE_STATE).mkdir(parents=True)
    message = _message(r43.stop(env, repo, host, "s"))
    assert "could not" in message and gate.DONE_STATE in message, message


def test_control_the_older_form_is_taken_over_without_a_word(env, tmp_path, keys):
    """The record an older gate wrote (session in clear) is a running count (R5-3): nothing to name."""
    repo = _done_repo(tmp_path, keys)
    raw = (json.dumps({"schema": SCHEMA, "session": "s", "open": [], "blocks": 0, "blocker": False}, indent=1,
                      sort_keys=True) + "\n").encode("utf-8")
    _record(repo, raw)
    message = _message(r43.stop(env, repo, "claude", "s"))
    assert "could not" not in message, message
    assert _rewritten(repo)["session_sha256"] == HASH_S
