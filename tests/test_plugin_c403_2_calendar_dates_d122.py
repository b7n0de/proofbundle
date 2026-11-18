"""D122 (Codex thread on pull request 403, pilot_records.py): a date the calendar does not have is no instant.

pilot_records.instant_key checked the month, the hours, the minutes and the seconds of an RFC 3339 instant by their
range and the day only up to 31, so 2026-04-31T00:00:00Z read as an instant, the same as 2026-05-01T00:00:00Z, and the
observer took it as the start or the end of its window. The two readers of decidedAt in the pilot, _instant_ns of the
key signer and of the signer service, handed the numbers to calendar.timegm, which normalises them: the key signer
signed a statement whose decidedAt named 2026-09-54 as if it named 2026-10-24. The profile github-write/1, which the
reconciliation applies, reads an instant with datetime and has none of them.

Now each of the three readers takes a date only where the proleptic Gregorian calendar has it: the day within its
month, 29 February in a leap year only, the year from 0001 on, as the profile reads it. The two readers of the gate
(_ts_seconds), whose time.strptime refused such a day already, take no second 60 or 61 either. Red at 2081257c.
"""
from __future__ import annotations

import base64
import datetime
import importlib.util
import itertools
import json

import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's release is read

import test_plugin_z405_key_signer as ks
import test_plugin_z405_observer as o

pr, gate = o.pr, ks.gate

PROFILE = o.ROOT / "tools" / "pilot" / "github_write_profile.py"


def profile():
    spec = importlib.util.spec_from_file_location("github_write_profile_d122", PROFILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def calendar_has(text: str) -> bool:
    """The oracle: whether datetime, which validates each field, reads the date and time of `text`."""
    try:
        datetime.datetime(int(text[0:4]), int(text[5:7]), int(text[8:10]), int(text[11:13]), int(text[14:16]),
                          int(text[17:19]))
    except ValueError:
        return False
    return True


IMPOSSIBLE = ["2026-04-31T00:00:00Z", "2026-02-29T12:00:00Z", "2100-02-29T00:00:00Z", "2026-06-31T23:59:59.5Z",
              "2026-09-31T00:00:00Z", "2026-11-31T00:00:00Z", "2026-02-30T00:00:00Z", "0000-01-01T00:00:00Z",
              "2026-01-00T00:00:00Z", "2026-00-10T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-32T00:00:00Z"]
POSSIBLE = ["2024-02-29T00:00:00Z", "2000-02-29T23:59:59.999Z", "2026-01-31T00:00:00Z", "2026-04-30T12:00:00Z",
            "2026-12-31T23:59:59Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59.000001Z"]


@pytest.mark.parametrize("text", IMPOSSIBLE)
def test_instant_key_reads_no_date_the_calendar_does_not_have(text):
    assert pr.instant_key(text) is None


@pytest.mark.parametrize("text", POSSIBLE)
def test_instant_key_reads_every_date_the_calendar_has(text):
    assert pr.instant_key(text) is not None


def _generated() -> list[str]:
    """Each month of a common year, a leap year, a century that is no leap year and one that is, the first year and the
    year 0000, each day from 00 to 32, at the edges of the clock."""
    texts = []
    for year, month, day in itertools.product((2026, 2024, 1900, 2000, 1, 0), range(0, 14), range(0, 33)):
        for clock in ("00:00:00", "23:59:59", "24:00:00", "12:60:00", "12:00:60"):
            texts.append(f"{year:04d}-{month:02d}-{day:02d}T{clock}Z")
    return texts


def test_instant_key_reads_what_the_profile_reads_and_orders_it_so():
    """The observer and the reconciliation read instants with instant_key, the profile with its own reader: both take
    the same texts, and two texts both take are ordered the same way."""
    reader = profile()
    texts = _generated()
    taken = [t for t in texts if pr.instant_key(t) is not None]
    assert [t for t in texts if (pr.instant_key(t) is None) != (reader.instant(t) is None)] == []
    assert [t for t in texts if (pr.instant_key(t) is None) == calendar_has(t)] == []
    ordered = sorted(taken, key=pr.instant_key)
    assert ordered == sorted(taken, key=reader.instant)


def test_the_observer_takes_no_window_with_a_date_the_calendar_does_not_have(env, tmp_path):
    records, sent, _decision = o.allowed_push(env, tmp_path)
    folder = o.recorded(tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))])
    for start, end in (("2026-04-31T00:00:00Z", "2026-05-02T00:00:00Z"), (o.now_plus(-60), "2099-02-29T00:00:00Z")):
        with pytest.raises(ValueError, match="RFC 3339"):
            o.observer.observe(pr.Records(records), "run-1", o.observer.RecordedTransport(folder), [o.REPO], start, end,
                               o.observer_key())
    assert not (records / "api" / "run-1").exists()


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    o.pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return o.pd.env.__wrapped__(tmp_path, monkeypatch)


def _six_digit(text: str) -> str:
    return text[:19] + ".000000Z"


@pytest.mark.parametrize("module", ["key_signer", "signer_service"])
def test_the_readers_of_decided_at_take_only_dates_the_calendar_has(module):
    reader = ks.k if module == "key_signer" else ks.service_module
    for text in _generated():
        six = _six_digit(text)
        if calendar_has(six):
            assert reader._instant_ns(six) == int(datetime.datetime.strptime(six, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=datetime.timezone.utc).timestamp()) * 10**9, six
        else:
            with pytest.raises(reader.Refused, match="statement_malformed"):
                reader._instant_ns(six)


@pytest.mark.parametrize("module", ["key_signer", "signer_service"])
def test_the_readers_of_decided_at_keep_the_microseconds(module):
    """Found by the lens on D122 (T6): the generated texts above carry six zeros, so a reader that dropped them passed."""
    reader = ks.k if module == "key_signer" else ks.service_module
    for text in ("2024-02-29T12:34:56.123456Z", "2026-10-24T23:59:59.999999Z", "0001-01-01T00:00:00.000001Z"):
        whole = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
        assert reader._instant_ns(text) == int(whole.replace(microsecond=0).timestamp()) * 10**9 + \
            whole.microsecond * 1000, text


def test_the_gate_reads_no_stamp_at_a_leap_second():
    """Found by the lens on D122 (T5): the gate's readers took the seconds 60 and 61 through time.strptime and read
    them, with calendar.timegm, as the next minute."""
    assert gate._ts_seconds("2026-10-24T23:59:59Z") == 1792886399
    for text in ("2026-10-24T23:59:60Z", "2026-10-24T23:59:61Z", "2026-04-31T00:00:00Z", "2026-02-29T00:00:00Z", None):
        assert gate._ts_seconds(text) is None, text


def test_a_release_answered_at_a_leap_second_is_not_read(tmp_path):
    folder = tmp_path / gate.RELEASES_DIR
    folder.mkdir()
    for n, answered in enumerate(("2026-10-24T12:00:59Z", "2026-10-24T12:00:60Z")):
        (folder / f"r{n}.json").write_text(json.dumps({"schema": gate.RELEASE_SCHEMA, "karte": f"OA-{n:010d}",
                                                       "sitzung": "s1", "sha256": "a" * 64, "antwort": answered}),
                                           encoding="utf-8")
    found = gate._releases({"PROOFBUNDLE_GATE_DIR": str(tmp_path), gate.OWNER_STATE_VARIABLE: gate.OWNER_STATE_PROTECTED})
    assert [r["antwort"] for r in found] == ["2026-10-24T12:00:59Z"], found


def test_records_with_a_window_that_is_no_instant_are_refused_by_the_run(env, tmp_path):
    """Records an observer of 2081257c kept with such a window: the runs are refused with the name of the run, before
    a new run writes a byte, instead of a TypeError where instant_key reads None."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    o.run_observer(records, o.recorded(tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))]), start,
                   o.now_plus(120))
    path = records / "api" / "run-1" / "run.json"
    run = json.loads(path.read_text(encoding="utf-8"))
    run["window"]["start"] = "2026-04-31T00:00:00Z"
    path.write_text(json.dumps(run), encoding="utf-8")
    with pytest.raises(pr.RecordsError, match="run-1"):
        pr.Records(records).runs()
    with pytest.raises(pr.RecordsError, match="run-1"):
        o.observer.observe(pr.Records(records), "run-2", o.observer.RecordedTransport(o.recorded(
            tmp_path, [], name="second")), [o.REPO], start, o.now_plus(120), o.observer_key())
    assert not (records / "api" / "run-2").exists()


def _impossible_now() -> str:
    """Now, written with the day counted on from the month before: 2026-10-24 as 2026-09-54. calendar.timegm reads it
    as now."""
    now = datetime.datetime.now(datetime.timezone.utc)
    year, month = (now.year, now.month - 1) if now.month > 1 else (now.year - 1, 12)
    days = (datetime.date(now.year, now.month, 1) - datetime.date(year, month, 1)).days
    return f"{year:04d}-{month:02d}-{now.day + days:02d}T{now:%H:%M:%S}.{now.microsecond:06d}Z"


def test_the_key_signer_signs_no_statement_whose_decided_at_the_calendar_does_not_have(env, tmp_path):
    """The exploit: at 2081257c the key signer signed a statement of its gate whose decidedAt names a day the month does
    not have, read as the day it normalises to, inside its window."""
    key = ks.Key(tmp_path)
    value = ks.statement(env)
    value["predicate"]["decidedAt"] = _impossible_now()
    body = ks._with_subject(value)
    proc = ks.run_key_signer(key.config, ks.request_of(body))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "statement_malformed"), proc
    (line,) = ks.key_lines(key.journal)
    assert (line["signed"], line["reason"]) == (False, "statement_malformed")
    control = ks.run_key_signer(key.config, ks.request_of(gate._pilot_canonical(ks.statement(env))))
    assert control.returncode == 0, control
    base64.b64decode(control.stdout.strip(), validate=True)
