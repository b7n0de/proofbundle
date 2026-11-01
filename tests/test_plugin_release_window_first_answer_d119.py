"""A copy of an owner's release with a later answer does not extend the window of its identity (D111, D119).

Order DELTA-FREIGABE-FENSTER-ERSTE-ANTWORT-01, after a finding of the cloud delivery for the draft
draft-gruszka-audit-decision-receipts-00 (delivery -3, at main 8bb289c8, paragraph 7 of its section 5): the window of a
release ran from the answer of the copy the gate was reading (_autonomy_release and _release_free, RELEASE_SKEW_SECONDS
before it to RELEASE_SECONDS after it). The identity of a release is its card, sha256 and session (_release_key), and
"once" holds per identity since D119; its window, though, moved with each copy. So for an identity not used yet, a copy
with a later answer opened a later window, which section 4 point 2 of the draft rules out: copies do not extend the
original validity. The signer service decides with the same code (signer_service.decide calls gate.tool_outcome).

The property: the window of an identity runs from the earliest answer the gate has seen for it, every copy that lies in
the folder freigaben now and every answer recorded in freigaben-erste.json of the plugin data directory, which the gate
writes for each identity it reads and never moves later. A record it cannot read or write releases nothing.

The limit, named: the gate sees only the copies that lie in the folder when it decides. A copy the gate never read,
written and taken away before any call reached the release, is unknown to it; only the writer of the releases at the
farmer, which reads every click of the decision board, knows each first answer for sure.

RED at 8bb289c8: the later copy lets the call run while the earlier copy lies beside it, after the earlier copy was taken
away, and past the end of the earlier window. CONTROL, green there and here: one copy within its window, and a release of
another card answered later.
"""
from __future__ import annotations

import json
import os
import pathlib
import time

import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's release is read

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n42_release_d111 as d111
import test_plugin_n49_release_once_d119 as d119

gate = d71.gate
pytestmark = d71.pytestmark
SESSION = d111.SESSION
COMMAND = d119.FREED[1]
OTHER = d119.FREED[0]


@pytest.fixture(autouse=True)
def _hook_environment(monkeypatch, tmp_path):
    d71._clean.__wrapped__(monkeypatch, tmp_path)


@pytest.fixture
def env(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(folder))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    (tmp_path / "gatedir").mkdir(exist_ok=True)
    return tmp_path


def _stamp(at: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))


def _copy(env: pathlib.Path, name: str, at: float, command: str = COMMAND, card: str = d111.CARD) -> pathlib.Path:
    """A release file as the writer at the farmer leaves it, answered at `at`."""
    folder = env / "gatedir" / "freigaben"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(json.dumps({"schema": d111.SCHEMA, "karte": card, "sitzung": SESSION,
                                "sha256": gate.command_sha256(command), "antwort": _stamp(at)}), encoding="utf-8")
    return path


def _passes(command: str, now: float, take: bool = True) -> bool:
    out = gate._autonomy_release(gate.Outcome("deny", "", []), command, d119._settle_env(), now, take=take)
    return out is not None and out.decision == "pass"


def test_a_later_copy_beside_an_earlier_one_does_not_reopen_a_window_that_has_ended(env):
    """RED at 8bb289c8: the copy answered ten minutes later let the call run 20 minutes after the first answer."""
    first = float(int(time.time())) - 20 * 60
    _copy(env, "a.json", first)
    _copy(env, "b.json", first + 10 * 60)
    assert not _passes(COMMAND, first + 20 * 60)


@pytest.mark.parametrize("past_the_end, runs", [(1, False), (0, True)],
                         ids=["one second past the first window", "control: the last second of the first window"])
def test_the_window_of_an_identity_ends_with_its_earliest_answer(env, past_the_end, runs):
    """Both copies lie in the folder. At the last second of the first window the release lets the call run, as before;
    one second later the copy answered ten minutes after the first does not. RED at 8bb289c8 one second past the end."""
    first = float(int(time.time())) - gate.RELEASE_SECONDS - 1
    _copy(env, "a.json", first)
    _copy(env, "b.json", first + 10 * 60)
    assert _passes(COMMAND, first + gate.RELEASE_SECONDS + past_the_end) is runs


def test_a_copy_the_gate_read_once_keeps_its_answer_after_it_was_taken_away(env):
    """The gate reads the folder for a call of another line while the first copy lies there; then the copy is taken
    away, and a copy answered ten minutes later appears. RED at 8bb289c8: the later copy let the call run after the end
    of the first window."""
    first = float(int(time.time())) - 20 * 60
    early = _copy(env, "a.json", first)
    assert not _passes(OTHER, first + 60), "the other line has no release"
    early.unlink()
    _copy(env, "b.json", first + 10 * 60)
    assert not _passes(COMMAND, first + 20 * 60)


def test_the_record_of_first_answers_never_moves_an_answer_later(env):
    first = float(int(time.time())) - 60
    _copy(env, "b.json", first + 30)
    assert not _passes(OTHER, first + 40)
    _copy(env, "a.json", first)
    assert not _passes(OTHER, first + 50)
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    record = json.loads((data / gate.RELEASES_FIRST).read_text(encoding="utf-8"))
    ident = gate._release_identity(f"{d111.CARD}:{gate.command_sha256(COMMAND)}:{SESSION}")
    assert record["erste"] == {ident: _stamp(first)}


@pytest.mark.parametrize("text", ["{", json.dumps({"schema": "x", "erste": {}}), json.dumps({"erste": []}),
                                  json.dumps({"schema": "proofbundle-plugin/freigaben-erste/v0.1",
                                              "erste": {"kein digest": "2026-11-01T00:00:00Z"}})],
                         ids=["not json", "another schema", "no mapping", "no digest"])
@pytest.mark.parametrize("take", [True, False], ids=["the use written before the pass", "the release held"])
def test_a_record_of_first_answers_that_does_not_read_whole_releases_nothing(env, text, take):
    """Also where the gate only holds the release (take=False): the hook in front of the pilot, and the signer service,
    which signs ALLOW for a held release and never writes the use itself."""
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    (data / "freigaben-erste.json").write_text(text, encoding="utf-8")
    _copy(env, "a.json", float(int(time.time())) - 30)
    assert not _passes(COMMAND, time.time(), take=take)


def test_the_use_is_not_written_for_a_copy_whose_identity_was_answered_earlier_beyond_the_window(env):
    """_release_take reads the record of first answers again under its lock: a later copy handed to it directly, with
    the window of its own answer still open, is not used where the identity was answered past that window."""
    first = float(int(time.time())) - 20 * 60
    early = _copy(env, "a.json", first)
    assert not _passes(OTHER, first + 60)
    early.unlink()
    later = {"karte": d111.CARD, "sitzung": SESSION, "sha256": gate.command_sha256(COMMAND),
             "antwort": _stamp(first + 10 * 60), "zeit": first + 10 * 60}
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    assert gate._release_take(later, {"CLAUDE_PLUGIN_DATA": str(data)}, first + 20 * 60) is False
    assert not (data / gate.RELEASES_USED).exists()


def test_control_one_copy_within_its_window_lets_the_call_run_once(env):
    now = float(int(time.time()))
    _copy(env, "a.json", now - 30)
    assert _passes(COMMAND, now) and not _passes(COMMAND, now + 1)


def test_control_a_release_of_another_card_answered_later_binds_on_its_own_answer(env):
    first = float(int(time.time())) - 20 * 60
    _copy(env, "a.json", first)
    _copy(env, "b.json", first + 10 * 60, card="OA-00000000ff")
    assert _passes(COMMAND, first + 20 * 60)


def test_the_signer_service_refuses_the_later_copy_with_a_data_directory_of_its_own(tmp_path):
    """End to end through the hook and the signer service (A2 of D119, a plugin data directory of its own): the service
    decides with the gate's code and refuses the later copy too. RED at 8bb289c8: the call ran and the service signed
    ALLOW."""
    world = d119.World(tmp_path)
    folder = world.variant("A2", True, own_data=True)
    world.release(ago=20 * 60, name="a.json")
    world.release(ago=10 * 60, name="b.json")
    decision, entry = world.hook()
    assert decision == "deny" and "released_by_owner" not in entry["reason_ids"], (decision, entry)
    assert world.used() == {} and "ALLOW" not in world.receipts()
    assert (folder / "data" / gate.RELEASES_FIRST).exists(), "the service records the first answer in its own data"
