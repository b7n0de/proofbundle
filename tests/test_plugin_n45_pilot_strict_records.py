"""Follow-up note 45, point 1: the records of the pilot are read strictly, as main's strict decoding rule asks.

With main in the chain, tests/test_strict_decoding_guard.py reads plugins/ too, and found the readers of
pilot/pilot_records.py lax: json.loads kept the last of two members with one name. They read the decision and outcome
envelopes, the runs and the responses the observer kept, the closing rules and the key journal, which the
reconciliation judges; a strict verifier of the same bytes reads another envelope or response, or refuses it. Since
follow-up note 45 each refuses a member name that stands twice in one object, at any depth (ValueError), as a malformed file
was refused before; the key journal reads such a line as one that does not read (None), as it reads a broken line.

RED at cc6b0fc3 (before the fix): every case but the control.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "proofbundle" / "pilot"))
from _gate_answer import skip_where_the_gate_is_not_shipped  # noqa: E402
skip_where_the_gate_is_not_shipped(pathlib.Path(__file__).resolve().parent.parent / "plugins" / "proofbundle" / "pilot" / "pilot_records.py",
                                   pathlib.Path(__file__).resolve().parent.parent)
import pilot_records as pr  # noqa: E402

sys.path.pop(0)
TWICE = b'{"payload": "a", "payloadType": "t", "signatures": [], "payload": "b"}'
DEEP = b'{"outer": {"inner": 1, "inner": 2}}'


def test_N45_read_json_refuses_a_member_name_given_twice_at_the_top_and_at_depth(tmp_path):
    for name, raw in (("top.json", TWICE), ("deep.json", DEEP)):
        (tmp_path / name).write_bytes(raw)
        with pytest.raises(ValueError):
            pr.read_json(tmp_path / name)


def test_N45_control_a_file_without_a_repeated_name_reads_as_before(tmp_path):
    (tmp_path / "ok.json").write_text(json.dumps({"a": {"b": [1, {"c": 2}]}, "d": "e"}), encoding="utf-8")
    assert pr.read_json(tmp_path / "ok.json") == {"a": {"b": [1, {"c": 2}]}, "d": "e"}


def test_N45_a_kept_response_with_a_repeated_name_is_refused(tmp_path):
    folder = tmp_path / "run"
    folder.mkdir()
    (folder / "events-1.json").write_bytes(b'[{"type": "PushEvent", "type": "IssuesEvent"}]')
    run = {"folder": str(folder), "window": {"start": "2026-10-20T00:00:00.000000Z", "end": "2026-10-20T01:00:00.000000Z"},
           "requests": [{"kind": "events", "status": 200, "file": "events-1.json",
                         "requestedAt": "2026-10-20T00:30:00.000000Z"}]}
    with pytest.raises(ValueError):
        pr.effects_of_run(run, {})


def test_N45_the_hook_is_the_one_the_guard_runs():
    with pytest.raises(ValueError):
        pr._reject_duplicate_keys([("a", 1), ("b", 2), ("a", 3)])
    assert pr._reject_duplicate_keys([("a", 1), ("b", 2)]) == {"a": 1, "b": 2}
