"""The record of the releases used drops no use a release can still bind with; a full record takes no new use (D111, D119).

Owner choice of 2026-11-01, 16:0x Berlin ("Fix bei kraxo, Grenze im Draft", follow-up note 26 of KRAXO-MUSK-TEMPO-20261029-01),
after a finding of the cloud delivery for the draft draft-gruszka-audit-decision-receipts-00, read again at main ba8466d1:
the hook writes the use of an owner's release into its record, freigaben-genutzt.json in the plugin data directory
(_release_take, called by release_settle and by autonomous_outcome), and kept at most MAX_RELEASES_USED (1024) uses:
past that it dropped the oldest key, whatever its time. A release binds for RELEASE_SECONDS (15 minutes) from its
answer, and since D119 its use is keyed by card, sha256 and session. So after 1024 other uses within those 15 minutes
the record had dropped the key of a release that still binds, and the same release let its line run a second time.

The property: at MAX_RELEASES_USED uses the record first drops only the uses whose time lies more than RELEASE_SECONDS +
RELEASE_SKEW_SECONDS back (a release is used no earlier than RELEASE_SKEW_SECONDS before its answer and binds up to
RELEASE_SECONDS after it, so none of them binds any more with the answer it had). Where the record is still full after
that, the new release lets nothing run, its use is not written and the record stays as it is (fail closed). A use whose
time does not read is never dropped. Below the capacity no use is dropped. MAX_RELEASES_USED_BYTES stays the second
bound.

Since D124 the gate reads a release only where PROOFBUNDLE_OWNER_STATE is `protected` (tests/_owner_state.py).

RED at ba8466d1: 1025 releases in one window (the 1025th was used, and then each of the first ones a second time), the
expired uses at a full record (one dropped, the others kept), the full records in process (a use within the window
dropped for the new release), the step of the hook at a full record (release_settle let the call run) and the case
through the hook (the used release lets its line run a second time after 1024 other uses). CONTROL, green there and
here: below the capacity no use is dropped, and the longest record the hook writes stays below MAX_RELEASES_USED_BYTES.
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
#: The time past which no release binds any more with the answer it had, counted from its use.
PAST = gate.RELEASE_SECONDS + gate.RELEASE_SKEW_SECONDS


@pytest.fixture(autouse=True)
def _hook_environment(monkeypatch, tmp_path):
    d71._clean.__wrapped__(monkeypatch, tmp_path)


def _stamp(seconds_ago: float, now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - seconds_ago))


def _release(card: str, digit: str, now: float) -> dict:
    return {"karte": card, "sitzung": SESSION, "sha256": digit * 64, "antwort": _stamp(30, now), "zeit": now - 30}


def _seed(data, uses: dict) -> bytes:
    """A record of the uses as the hook writes it (_write_releases_used): the order of the keys is the order of the
    uses."""
    path = data / gate.RELEASES_USED
    path.write_text(json.dumps({"schema": gate.RELEASES_USED_SCHEMA, "genutzt": uses}), encoding="utf-8")
    return path.read_bytes()


def _others(count: int, seconds_ago: float, now: float, first: int = 0) -> dict:
    return {f"OA-1{i:09x}:{'b' * 64}:{SESSION}": _stamp(seconds_ago, now) for i in range(first, first + count)}


def _record(data) -> dict:
    return json.loads((data / gate.RELEASES_USED).read_text(encoding="utf-8"))["genutzt"]


@pytest.fixture
def data(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    return folder


def test_the_record_holds_1024_uses_and_a_release_binds_16_minutes_after_its_use_at_most():
    assert (gate.MAX_RELEASES_USED, gate.RELEASE_SECONDS, gate.RELEASE_SKEW_SECONDS, PAST) == (1024, 900, 60, 960)


def test_1025_releases_in_one_window_none_acts_twice_and_the_1025th_is_refused(data):
    """Follow-up note 26, the first test. RED at ba8466d1: the 1025th release was used, its use dropped the first one's,
    and then every one of the first 1024 was used a second time."""
    now = time.time()
    environ = {"CLAUDE_PLUGIN_DATA": str(data)}
    releases = [_release(f"OA-{i:010x}", "a", now) for i in range(gate.MAX_RELEASES_USED + 1)]
    first = [gate._release_take(r, environ, now) for r in releases[:gate.MAX_RELEASES_USED]]
    assert first == [True] * gate.MAX_RELEASES_USED
    full = (data / gate.RELEASES_USED).read_bytes()
    assert gate._release_take(releases[-1], environ, now) is False
    again = [i for i, r in enumerate(releases[:gate.MAX_RELEASES_USED]) if gate._release_take(r, environ, now)]
    assert again == [] and (data / gate.RELEASES_USED).read_bytes() == full, again[:5]
    assert list(_record(data)) == [gate._release_key(r) for r in releases[:gate.MAX_RELEASES_USED]]


def test_at_a_full_record_the_expired_uses_are_removed_and_a_new_release_passes(data):
    """Follow-up note 26, the second test. RED at ba8466d1: only the oldest use was dropped, the other expired ones
    stayed."""
    now = time.time()
    new = _release("OA-2000000000", "c", now)
    uses = {**_others(3, PAST + 1, now), **_others(500, 60, now, first=3),
            f"OA-3000000000:{'d' * 64}:{SESSION}": _stamp(PAST + 300, now),
            **_others(gate.MAX_RELEASES_USED - 504, 60, now, first=503)}
    assert len(uses) == gate.MAX_RELEASES_USED
    expired = [k for k, v in uses.items() if v != _stamp(60, now)]
    _seed(data, uses)
    assert gate._release_take(new, {"CLAUDE_PLUGIN_DATA": str(data)}, now) is True
    record = _record(data)
    assert not any(k in record for k in expired) and len(expired) == 4
    assert list(record) == [k for k in uses if k not in expired] + [gate._release_key(new)]


def test_at_a_full_record_a_later_expired_use_is_removed_while_the_oldest_still_binds(data):
    """The record's order is the order of the uses, not their times: where the clock went back, an expired use can stand
    after one that still binds. Only the expired one is removed. RED at ba8466d1: the oldest use was dropped."""
    now = time.time()
    target, new = _release("OA-0000000000", "a", now), _release("OA-2000000000", "c", now)
    later = f"OA-3000000000:{'d' * 64}:{SESSION}"
    _seed(data, {gate._release_key(target): _stamp(60, now), later: _stamp(PAST + 60, now),
                 **_others(gate.MAX_RELEASES_USED - 2, 60, now)})
    assert gate._release_take(new, {"CLAUDE_PLUGIN_DATA": str(data)}, now) is True
    record = _record(data)
    assert gate._release_used(target, record) and gate._release_used(new, record) and later not in record
    assert len(record) == gate.MAX_RELEASES_USED


def test_a_dropped_use_does_not_let_its_release_act_again_when_the_clock_goes_back(data):
    """A Codex pre-run of the reading: once the record dropped a use past its window, a clock set back into the window
    of that release found its key missing, and the release acted a second time. The record keeps the identity of a use
    it drops, as a digest it never drops, and refuses the release by it. RED at 2908b8e3: the release was taken a
    second time."""
    answered = float(int(time.time()))
    environ = {"CLAUDE_PLUGIN_DATA": str(data)}
    target = _release("OA-0000000000", "a", answered + 30)
    assert target["antwort"] == _stamp(0, answered)
    assert gate._release_take(target, environ, answered) is True
    _seed(data, {**_record(data), **_others(gate.MAX_RELEASES_USED - 1, 0, answered)})
    later = answered + PAST + 1
    assert gate._release_take(_release("OA-2000000000", "c", later + 30), environ, later) is True
    assert not gate._release_used(target, _record(data))
    before = (data / gate.RELEASES_USED).read_bytes()
    assert gate._release_take(target, environ, answered + 30) is False
    assert (data / gate.RELEASES_USED).read_bytes() == before
    # control: a release answered after that, at the later time, still passes
    assert gate._release_take(_release("OA-2100000000", "f", later + 30), environ, later) is True


@pytest.mark.parametrize("take", [True, False], ids=["the use written before the pass", "the use written by the step"])
def test_a_release_the_record_refuses_by_its_dropped_uses_does_not_hide_another_that_binds(env, take):
    """A Codex pre-run of the reading: with the clock set back, a release whose use the record dropped fits again and
    comes first; the gate chose it, the record refused it, and the other release of the same line, of another card, was
    never tried. RED at 32d7005a: nothing was released. The second answer is the present second, so the step of the
    hook writes the use within its window."""
    answered = int(time.time()) - 90
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    command = d119.FREED[1]
    folder = env / "gatedir" / "freigaben"
    folder.mkdir(parents=True)
    for name, card, at in (("a.json", "OA-00000000aa", answered), ("b.json", "OA-00000000bb", answered + 90)):
        (folder / name).write_text(json.dumps({"schema": d111.SCHEMA, "karte": card, "sitzung": SESSION,
                                               "sha256": gate.command_sha256(command), "antwort": _stamp(0, at)}))
    dropped = gate._release_identity(f"OA-00000000aa:{gate.command_sha256(command)}:{SESSION}")
    (data / gate.RELEASES_USED).write_text(json.dumps({"schema": gate.RELEASES_USED_SCHEMA, "genutzt": {},
                                                       "verbraucht": [dropped]}), encoding="utf-8")
    out = gate._autonomy_release(gate.Outcome("deny", "", []), command, d119._settle_env(), answered + 90, take=take)
    assert out is not None and out.decision == "pass" and out.release["freigabe"]["karte"] == "OA-00000000bb"
    if not take:
        answer, _asked = gate.release_settle({"tool_name": "Bash"}, out, d119._settle_env())
        assert answer.decision == "pass" and out.release["genutzt"] is True
    assert list(_record(data)) == [f"OA-00000000bb:{gate.command_sha256(command)}:{SESSION}"]
    assert gate._releases_record(str(data))[1] == {dropped}


@pytest.mark.parametrize("offset, taken", [(-gate.RELEASE_SKEW_SECONDS - 1, False), (gate.RELEASE_SECONDS + 1, False),
                                           (-gate.RELEASE_SKEW_SECONDS, True), (gate.RELEASE_SECONDS, True)],
                         ids=["before the window", "after the window", "control: its first second",
                              "control: its last second"])
def test_the_use_is_written_only_within_the_window_of_its_release(data, offset, taken):
    """A release binds from RELEASE_SKEW_SECONDS before its answer to RELEASE_SECONDS after it, and its use is written
    only then: _release_take checks it under the lock, with the clock that stamps the use. RED at a29a81b1 (before and
    after the window): the use was written."""
    answered = int(time.time())
    release = _release("OA-0000000000", "a", answered + 30)
    taken_now = gate._release_take(release, {"CLAUDE_PLUGIN_DATA": str(data)}, answered + offset)
    assert taken_now is taken and (data / gate.RELEASES_USED).exists() is taken


def test_a_clock_set_back_between_the_choice_and_the_step_of_the_hook_writes_no_use(env):
    """A Codex pre-run of the reading: the gate chose a release at its answer without writing the use (take=False);
    before release_settle wrote it, the clock stood 120 s before the answer. The use was stamped before the window of
    its release, so the record could later drop it while the release still bound. RED at a29a81b1: the use was written
    and the call ran."""
    answered = int(time.time()) + 120
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    command = d119.FREED[1]
    folder = env / "gatedir" / "freigaben"
    folder.mkdir(parents=True)
    (folder / "a.json").write_text(json.dumps({"schema": d111.SCHEMA, "karte": "OA-00000000aa", "sitzung": SESSION,
                                               "sha256": gate.command_sha256(command),
                                               "antwort": _stamp(0, answered)}))
    out = gate._autonomy_release(gate.Outcome("deny", "", []), command, d119._settle_env(), answered, take=False)
    assert out is not None and out.release["genutzt"] is False
    answer, _asked = gate.release_settle({"tool_name": "Bash"}, out, d119._settle_env())
    assert answer.decision == "deny" and "its use could not be written" in answer.text
    assert out.release["genutzt"] is False and not (data / gate.RELEASES_USED).exists()


def _copy(release: dict, at: float) -> dict:
    """The same release (card, sha256, session) issued again with a later answer."""
    return {**release, "antwort": _stamp(0, at), "zeit": at}


def test_a_copy_with_a_later_answer_of_a_release_whose_use_was_dropped_is_refused(data):
    """Follow-up note 28, the first test (external review of the draft, K9): the identity of a release (card, sha256,
    session) holds no answer time, its window does. Release X is used, its use is dropped once past its window, and a
    copy of X with a new answer time must be refused: a copy never extends the first use. RED at 7042a57d: the copy
    was taken."""
    answered = float(int(time.time()))
    environ = {"CLAUDE_PLUGIN_DATA": str(data)}
    x = _release("OA-0000000000", "a", answered + 30)
    assert gate._release_take(x, environ, answered) is True
    _seed(data, {**_record(data), **_others(gate.MAX_RELEASES_USED - 1, 0, answered)})
    later = answered + PAST + 1
    assert gate._release_take(_release("OA-2000000000", "c", later + 30), environ, later) is True
    assert not gate._release_used(x, _record(data))
    assert gate._release_take(_copy(x, later), environ, later) is False


def test_a_copy_is_refused_after_its_use_was_pushed_out_by_releases_spread_over_more_than_15_minutes(data):
    """Follow-up note 28, the second test: 1100 other releases, each used, one each second from the use of X on, so over
    more than RELEASE_SECONDS + RELEASE_SKEW_SECONDS; the record drops the use of X along the way. A copy of X answered
    at the end must be refused. RED at 7042a57d: the copy was taken."""
    answered = float(int(time.time())) - 1200
    environ = {"CLAUDE_PLUGIN_DATA": str(data)}
    x = _release("OA-0000000000", "a", answered + 30)
    assert gate._release_take(x, environ, answered) is True
    refused = [i for i in range(1, 1101)
               if not gate._release_take(_release(f"OA-3{i:09x}", "d", answered + i + 30), environ, answered + i)]
    assert refused == []
    end = answered + 1100
    assert end - answered > PAST and not gate._release_used(x, _record(data))
    assert gate._release_take(_copy(x, end), environ, end) is False


@pytest.mark.parametrize("full", [False, True], ids=["below the capacity", "at the capacity, the old use past"])
def test_a_copy_of_a_release_the_record_names_by_a_key_of_d111_is_refused_whatever_its_answer(data, full):
    """A Codex pre-run of the second reading: a key of D111 names the time of the answer as well, and the record found a
    copy with another answer only where the time was the same. Below the capacity the copy was taken beside the old
    use; at the capacity the old use was dropped and the copy taken in the same step. RED at b1e237d8: the copy was
    taken."""
    answered = float(int(time.time())) - 2000
    x = _release("OA-0000000000", "a", answered + 30)
    uses = {f"{gate._release_key(x)}:{x['antwort']}": _stamp(0, answered)}
    if full:
        uses.update(_others(gate.MAX_RELEASES_USED - 1, 0, answered))
    before = _seed(data, uses)
    now = answered + 1500
    assert gate._release_take(_copy(x, now), {"CLAUDE_PLUGIN_DATA": str(data)}, now) is False
    assert (data / gate.RELEASES_USED).read_bytes() == before


def test_a_use_that_would_carry_the_record_past_its_byte_bound_is_not_written(data):
    """The first reading (line 3, P2): a record below MAX_RELEASES_USED_BYTES with one long key took a new use, and the
    hook wrote a record past the bound, which it then could not read: every later release was refused. The record the
    hook writes stays readable, so where the new use would carry it past the bound, the use is not written. RED at
    7042a57d: the use was written and the record no longer read."""
    now = time.time()
    path = data / gate.RELEASES_USED
    body = {"schema": gate.RELEASES_USED_SCHEMA, "genutzt": {"x": _stamp(60, now)}}
    filler = gate.MAX_RELEASES_USED_BYTES - len(json.dumps(body)) - 40
    body["genutzt"] = {"x" * filler: _stamp(60, now)}
    path.write_text(json.dumps(body), encoding="utf-8")
    before = path.read_bytes()
    assert gate.MAX_RELEASES_USED_BYTES - 200 < len(before) <= gate.MAX_RELEASES_USED_BYTES
    assert gate._release_take(_release("OA-2000000000", "c", now), {"CLAUDE_PLUGIN_DATA": str(data)}, now) is False
    assert path.read_bytes() == before and len(gate._releases_record(str(data))[0]) == 1


@pytest.mark.parametrize("consumed", ["not a list", ["not a digest"], ["A" * 32], [5]])
def test_a_record_whose_digests_of_the_dropped_identities_do_not_read_takes_no_use(data, consumed):
    """RED at 2908b8e3: the record's other names were not read, and the release was taken."""
    now = time.time()
    (data / gate.RELEASES_USED).write_text(json.dumps({"schema": gate.RELEASES_USED_SCHEMA, "genutzt": {},
                                                       "verbraucht": consumed}), encoding="utf-8")
    assert gate._release_take(_release("OA-2000000000", "c", now), {"CLAUDE_PLUGIN_DATA": str(data)}, now) is False


@pytest.mark.parametrize("oldest", [60, "not a time", -120, PAST],
                         ids=["every use within the window", "the oldest use's time does not read",
                              "the oldest use's time lies ahead", "the oldest use exactly at the window's end"])
def test_a_full_record_takes_no_new_use_and_drops_no_use_within_the_window(data, oldest):
    """RED at ba8466d1: the oldest use was dropped for the new release, which was used. The use exactly at the window's
    end still counts: a release answered RELEASE_SKEW_SECONDS after it binds up to that second (now in whole seconds)."""
    now = float(int(time.time()))
    target, new = _release("OA-0000000000", "a", now), _release("OA-2000000000", "c", now)
    uses = {gate._release_key(target): _stamp(oldest, now) if isinstance(oldest, int) else oldest,
            **_others(gate.MAX_RELEASES_USED - 1, 60, now)}
    assert len(uses) == gate.MAX_RELEASES_USED
    before = _seed(data, uses)
    taken = gate._release_take(new, {"CLAUDE_PLUGIN_DATA": str(data)}, now)
    assert (taken, (data / gate.RELEASES_USED).read_bytes() == before) == (False, True)
    assert gate._release_used(target, _record(data)) and not gate._release_used(new, _record(data))


def test_a_used_release_does_not_free_its_line_again_after_1024_other_uses_within_the_window(tmp_path):
    """Through the hook as the host runs it (--autonomous, no pilot), each call a fresh gate process. RED at ba8466d1:
    the use of the other release dropped the first one's key, and its line ran a second time."""
    world = d119.World(tmp_path, pilot=False)
    world.release()
    assert world.hook()[0] == "pass" and len(world.used()) == 1
    now = time.time()
    _seed(world.data, {**world.used(), **_others(gate.MAX_RELEASES_USED - 1, 60, now)})
    other = d119.CREATE.replace("--title t", "--title u")
    world.release(other, card="OA-00000000ff")
    first, _entry = world.hook(other)
    kept = list(world.used())[0]
    again, entry = world.hook()
    assert (first, again, "released_by_owner" in entry["reason_ids"]) == ("deny", "deny", False), (first, again, entry)
    assert len(world.used()) == gate.MAX_RELEASES_USED and list(world.used())[0] == kept


@pytest.fixture
def env(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(folder))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    (tmp_path / "gatedir").mkdir(exist_ok=True)
    return tmp_path


def test_the_step_of_the_hook_keeps_its_answer_at_a_full_record(env):
    """release_settle: the use cannot be written, so the answer without the release stands and names why. RED at
    ba8466d1: the oldest use was dropped and the call ran."""
    out = d119._held(env, d119.FREED[1])
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    before = _seed(data, _others(gate.MAX_RELEASES_USED, 60, time.time()))
    answer, _asked = gate.release_settle({"tool_name": "Bash"}, out, d119._settle_env())
    assert answer.decision == "deny" and "released_by_owner" not in [v.reason_id for v in answer.verdicts]
    assert "its use could not be written" in answer.text and out.release["genutzt"] is False
    assert (data / gate.RELEASES_USED).read_bytes() == before


def test_no_use_judged_past_belongs_to_a_release_that_still_binds():
    """The window as an oracle of its own, not the gate's code: a release answered at a whole second A (the fetcher's
    stamp) is used at u with A - RELEASE_SKEW_SECONDS <= u <= A + RELEASE_SECONDS (_autonomy_release), the use is
    written in whole seconds (time.strftime), and at no later now where _release_use_past judges that use past does the
    release still bind. Fractions of a second in u and now, uses at both ends of the window."""
    answered = 1_793_000_000
    for step in range(0, 4 * (gate.RELEASE_SKEW_SECONDS + gate.RELEASE_SECONDS) + 1, 7):
        used = answered - gate.RELEASE_SKEW_SECONDS + step / 4 + 0.999 * (step % 2)
        if used > answered + gate.RELEASE_SECONDS:
            continue
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(used))
        for later in (0.0, 0.25, 0.5, 0.999, 1.0, 1.5):
            for now in (answered + gate.RELEASE_SECONDS + later - 1, answered + gate.RELEASE_SECONDS + later,
                        used + PAST + later - 1, used + PAST + later):
                binds = answered - gate.RELEASE_SKEW_SECONDS <= now <= answered + gate.RELEASE_SECONDS
                assert not (binds and gate._release_use_past(stamp, now)), (used, stamp, now)
    assert gate._release_use_past(_stamp(PAST + 1, float(answered)), float(answered))


def test_control_below_the_capacity_no_use_is_dropped(data):
    now = time.time()
    target, new = _release("OA-0000000000", "a", now), _release("OA-2000000000", "c", now)
    _seed(data, {gate._release_key(target): _stamp(PAST + 1, now), **_others(gate.MAX_RELEASES_USED - 2, 60, now)})
    assert gate._release_take(new, {"CLAUDE_PLUGIN_DATA": str(data)}, now) is True
    record = _record(data)
    assert len(record) == gate.MAX_RELEASES_USED and gate._release_used(target, record) and \
        gate._release_used(new, record)


def test_control_the_longest_record_the_hook_writes_stays_below_the_second_bound(data):
    """MAX_RELEASES_USED_BYTES stays the second bound: a full record of the longest keys (a session id of 128 signs, the
    key of D111 with the time of the answer) with a thousand digests of dropped identities is read whole, and one past
    the byte bound is not, so it takes no use."""
    now = time.time()
    session = "s" * 128
    assert gate._SESSION_ID.fullmatch(session)
    longest = {f"OA-{i:010x}:{'e' * 64}:{session}:{_stamp(30, now)}": _stamp(60, now)
               for i in range(gate.MAX_RELEASES_USED)}
    digests = [gate._release_identity(f"OA-{i:010x}:{'f' * 64}:{session}") for i in range(1000)]
    (data / gate.RELEASES_USED).write_text(json.dumps({"schema": gate.RELEASES_USED_SCHEMA, "genutzt": longest,
                                                       "verbraucht": digests}), encoding="utf-8")
    assert (data / gate.RELEASES_USED).stat().st_size < gate.MAX_RELEASES_USED_BYTES
    assert [len(part) for part in gate._releases_record(str(data))] == [gate.MAX_RELEASES_USED, 1000]
    _seed(data, {**_others(10, 60, now), "x" * gate.MAX_RELEASES_USED_BYTES: _stamp(60, now)})
    assert gate._release_take(_release("OA-2000000000", "c", now), {"CLAUDE_PLUGIN_DATA": str(data)}, now) is False
