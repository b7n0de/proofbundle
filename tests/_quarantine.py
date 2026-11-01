"""The quarantine of tests: a listed test keeps running and reports, but does not block, until its deadline.

THE LIST is `.github/test_quarantine.json`, part of the repository's configuration like the declaration of the
required contexts beside it. Each entry names a test, the reason, the deadline and the owner:

    {"test": "tests/test_x.py::test_y", "reason": "...", "deadline": "2026-11-08", "owner": "b7n0de"}

`test` is a pytest node id. Without a parameter id it covers every parameter of the test; with one
(`tests/test_x.py::test_y[renewal_work]`) only that parameter. Where both are listed, the parameter's own entry decides
for it, whatever the order of the list.

WHAT IT DOES. Through the end of its deadline day (UTC) a listed test runs as before and is marked as an expected
failure that is not strict: red, it reports `xfailed`; green, it reports `xpassed`; neither fails the run. From the
next day the entry no longer applies and the test blocks again. No test is skipped and none is deleted. The summary
of the run names every entry and what its test did, and every entry that has expired; on GitHub Actions each
quarantined failure and each expired entry is an annotation as well.

FAIL-CLOSED. A list that cannot be read, an entry without one of the four fields or with another field, a deadline
that is not a date (YYYY-MM-DD), a test that is not a node id under `tests/`, or the same test twice stops the run
with a usage error: a wrong list must not quietly quarantine more or less than it says. Without the file (outside a
checkout, where `.github/` is not shipped) nothing is quarantined.

LIMITS, named. `unittest discover` (the crypto-floor job) does not read the list, so there a listed test blocks as it
always did. The mutation gate counts an expected failure as no kill. A subtest that fails inside a listed test is
covered too: pytest 9.1.1 reports it as SUBXFAIL and the run passes (measured 2026-10-25 in a planted session).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LIST_FILE = REPO / ".github" / "test_quarantine.json"
FIELDS = ("test", "reason", "deadline", "owner")
_NODE_ID = re.compile(r"tests/[^:\s\[\]]+\.py(::[^:\s\[\]]+)+(\[[^\s]+\])?")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ListError(ValueError):
    """The list cannot be read as the list it claims to be."""


@dataclass(frozen=True)
class Entry:
    test: str
    reason: str
    deadline: dt.date
    owner: str

    def covers(self, nodeid: str) -> bool:
        """The entry's own node id, or a parameter of it when the entry names none."""
        return nodeid == self.test or ("[" not in self.test and nodeid.startswith(self.test + "["))

    def in_force(self, today: dt.date) -> bool:
        return today <= self.deadline


def load(path: Path = LIST_FILE) -> list[Entry] | None:
    """The entries of the list, or None when there is no list. Raises ListError on anything malformed."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ListError(f"{path}: not readable as JSON ({exc})") from exc
    raw = data.get("quarantine") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise ListError(f"{path}: no list under the key 'quarantine'")
    entries: list[Entry] = []
    for i, e in enumerate(raw):
        where = f"{path}: entry {i}"
        if not isinstance(e, dict):
            raise ListError(f"{where} is not an object")
        missing = [f for f in FIELDS if not isinstance(e.get(f), str) or not e[f].strip()]
        if missing:
            raise ListError(f"{where} lacks {', '.join(missing)}")
        extra = sorted(set(e) - set(FIELDS))
        if extra:
            raise ListError(f"{where} carries fields the list does not know: {extra}")
        if not _NODE_ID.fullmatch(e["test"]):
            raise ListError(f"{where}: {e['test']!r} is not a test node id under tests/")
        if not _DATE.fullmatch(e["deadline"]):
            raise ListError(f"{where}: deadline {e['deadline']!r} is not a date YYYY-MM-DD")
        try:
            deadline = dt.date.fromisoformat(e["deadline"])
        except ValueError as exc:
            raise ListError(f"{where}: deadline {e['deadline']!r} is not a date ({exc})") from exc
        if any(x.test == e["test"] for x in entries):
            raise ListError(f"{where}: {e['test']} is listed twice")
        entries.append(Entry(e["test"], e["reason"].strip(), deadline, e["owner"].strip()))
    return entries


class Quarantine:
    """The pytest plugin: it marks the listed tests whose deadline has not passed, and reports every entry."""

    def __init__(self, entries: list[Entry] | None, today: dt.date, source: Path):
        self.entries = entries or []
        self.has_list = entries is not None
        self.today = today
        self.source = source
        self.outcomes: dict[str, list[tuple[str, str]]] = {}

    def entry_for(self, nodeid: str) -> Entry | None:
        """The entry that names the node id itself, else the entry of its whole test: a parameter's own entry decides
        for it, whatever the order of the list."""
        covering = [e for e in self.entries if e.covers(nodeid)]
        return next((e for e in covering if e.test == nodeid), next(iter(covering), None))

    def pytest_collection_modifyitems(self, config, items):
        for item in items:
            e = self.entry_for(item.nodeid)
            if e is not None and e.in_force(self.today):
                item.add_marker(pytest.mark.xfail(
                    reason=f"quarantined until {e.deadline} (owner {e.owner}): {e.reason}", strict=False, run=True))

    def pytest_runtest_logreport(self, report):
        e = self.entry_for(report.nodeid)
        if e is None or not (report.when == "call" or report.outcome != "passed"):
            return
        if hasattr(report, "wasxfail"):
            outcome = "failed, quarantined" if report.skipped else "passed, quarantined"
        else:
            outcome = report.outcome
        self.outcomes.setdefault(e.test, []).append((report.nodeid, f"{outcome} ({report.when})"
                                                     if report.when != "call" else outcome))

    def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
        tr = terminalreporter
        tr.write_sep("-", "quarantine")
        if not self.has_list:
            tr.write_line(f"no quarantine list at {self.source}; nothing is quarantined")
            return
        if not self.entries:
            tr.write_line(f"{self.source}: the list is empty")
            return
        gha = os.environ.get("GITHUB_ACTIONS") == "true"
        for e in self.entries:
            state = (f"in force through {e.deadline}" if e.in_force(self.today)
                     else f"EXPIRED on {e.deadline}, the test blocks again")
            ran = self.outcomes.get(e.test, [])
            tr.write_line(f"{e.test} (owner {e.owner}, {state}): "
                          + ("; ".join(f"{n[len(e.test):] or 'run'}: {o}" for n, o in ran) if ran
                             else "not run in this session"))
            if gha and not e.in_force(self.today):
                tr.write_line(f"::error title=quarantine expired::{e.test}: the entry ran out on {e.deadline} "
                              f"(owner {e.owner}); the test blocks again")
            elif gha:
                for n, o in ran:
                    if o.startswith("failed, quarantined"):
                        tr.write_line(f"::warning title=quarantine::{n} failed and does not block until "
                                      f"{e.deadline} (owner {e.owner}): {e.reason}")


def register(config, path: Path = LIST_FILE, today: dt.date | None = None) -> None:
    """Read the list and register the plugin; a malformed list is a usage error that stops the run."""
    if config.pluginmanager.has_plugin("proofbundle-quarantine"):
        return
    try:
        entries = load(path)
    except ListError as exc:
        raise pytest.UsageError(f"quarantine list: {exc}") from exc
    today = today or dt.datetime.now(dt.timezone.utc).date()
    config.pluginmanager.register(Quarantine(entries, today, path), "proofbundle-quarantine")
