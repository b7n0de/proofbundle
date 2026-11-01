"""The quarantine of tests (tests/_quarantine.py, .github/test_quarantine.json) and the check of time caps
(scripts/quarantine_time_caps.py).

THE RED CASE FIRST. Without the quarantine, a test with a fixed time cap that a slower runner exceeds blocks every
merge until someone fixes it, and the fix may be on another branch for days. A listed test must keep running and
report, block nothing until its deadline, and block again after it. And the two caps the owner named on 2026-10-25
must be found where they stand: the 300 seconds of `test_c12_1` sit in a helper, `_lauf`, and the cost curve of
`renewal_work` asserts against a name bound from a constant in seconds.

The plugin is measured in pytest sessions of their own, in a planted tree, with a planted list and a fixed date.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "tests" / "_quarantine.py"
CHECKER = REPO / "scripts" / "quarantine_time_caps.py"
LIST = REPO / ".github" / "test_quarantine.json"
TODAY = "2026-10-25"

PLANTED = textwrap.dedent("""\
    import pathlib

    import pytest


    def test_red():
        pathlib.Path("ran_red").write_text("ran")
        assert False, "red on purpose"


    def test_green():
        pathlib.Path("ran_green").write_text("ran")


    def test_other_red():
        assert False, "red and not listed"


    @pytest.mark.parametrize("p", ["a", "b"])
    def test_param(p):
        assert p != "b"
    """)


def _entry(test: str, deadline: str = "2026-11-08", **kw) -> dict:
    return {"test": test, "reason": "a cap in seconds", "deadline": deadline, "owner": "o", **kw}


def _session(tmp_path: Path, quarantine, args: list[str], today: str = TODAY, env: dict | None = None):
    """One pytest session over the planted tests, with `quarantine` as the list (None: no file) and `today`."""
    root = tmp_path / "planted"
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "tests" / "test_planted.py").write_text(PLANTED, encoding="utf-8")
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    listed = root / "quarantine.json"
    if quarantine is None:
        listed.unlink(missing_ok=True)
    else:
        listed.write_text(quarantine if isinstance(quarantine, str) else json.dumps({"quarantine": quarantine}),
                          encoding="utf-8")
    (root / "conftest.py").write_text(textwrap.dedent(f"""\
        import datetime
        import sys
        from pathlib import Path

        sys.path.insert(0, {str(PLUGIN.parent)!r})
        import _quarantine


        def pytest_configure(config):
            _quarantine.register(config, path=Path(__file__).parent / "quarantine.json",
                                 today=datetime.date.fromisoformat({today!r}))
        """), encoding="utf-8")
    for f in ("ran_red", "ran_green"):
        (root / f).unlink(missing_ok=True)
    clean = {k: v for k, v in os.environ.items() if k not in ("GITHUB_ACTIONS", "PYTEST_ADDOPTS")}
    r = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rA", *args],
                       cwd=root, capture_output=True, text=True, timeout=300, env={**clean, **(env or {})})
    return r.returncode, r.stdout + r.stderr, root


RED = "tests/test_planted.py::test_red"


# ── the red cases: a listed test runs and reports and does not block until its deadline ────────────────────────────

def test_a_listed_red_test_runs_reports_and_does_not_block(tmp_path):
    rc, out, root = _session(tmp_path, [_entry(RED)], [RED])
    assert rc == 0, out
    assert (root / "ran_red").is_file(), "the listed test must run, not be skipped"
    assert "1 xfailed" in out, out
    assert "tests/test_planted.py::test_red (owner o, in force through 2026-11-08): run: failed, quarantined" in out, out


def test_on_its_deadline_day_the_entry_still_holds(tmp_path):
    rc, out, _ = _session(tmp_path, [_entry(RED, deadline=TODAY)], [RED])
    assert rc == 0, out


def test_a_listed_green_test_reports_that_it_passed(tmp_path):
    rc, out, root = _session(tmp_path, [_entry("tests/test_planted.py::test_green")], ["tests/test_planted.py::test_green"])
    assert rc == 0 and "1 xpassed" in out, out
    assert (root / "ran_green").is_file()
    assert "run: passed, quarantined" in out, out


def test_an_entry_without_a_parameter_covers_every_parameter(tmp_path):
    rc, out, _ = _session(tmp_path, [_entry("tests/test_planted.py::test_param")], ["tests/test_planted.py::test_param"])
    assert rc == 0, out
    assert "[b]: failed, quarantined" in out and "[a]: passed, quarantined" in out, out


def test_under_xdist_the_entry_holds_and_the_summary_sees_every_worker(tmp_path):
    pytest.importorskip("xdist")
    rc, out, _ = _session(tmp_path, [_entry(RED)], ["-n", "2", RED])
    assert rc == 0, out
    assert "run: failed, quarantined" in out, out


def test_on_github_actions_a_quarantined_failure_is_an_annotation(tmp_path):
    rc, out, _ = _session(tmp_path, [_entry(RED)], [RED], env={"GITHUB_ACTIONS": "true"})
    assert rc == 0, out
    assert "::warning title=quarantine::tests/test_planted.py::test_red failed and does not block until 2026-11-08" in out


# ── what blocks: after the deadline, an unlisted test, a parameter the entry does not name, no list ────────────────

def test_after_its_deadline_the_test_blocks_again(tmp_path):
    rc, out, root = _session(tmp_path, [_entry(RED, deadline="2026-10-24")], [RED], env={"GITHUB_ACTIONS": "true"})
    assert rc == 1, out
    assert (root / "ran_red").is_file()
    assert "EXPIRED on 2026-10-24, the test blocks again" in out, out
    assert "::error title=quarantine expired::tests/test_planted.py::test_red" in out, out


def test_an_unlisted_red_test_blocks(tmp_path):
    rc, out, _ = _session(tmp_path, [_entry(RED)], ["tests/test_planted.py::test_other_red"])
    assert rc == 1, out


def test_an_entry_with_a_parameter_covers_only_that_parameter(tmp_path):
    rc, out, _ = _session(tmp_path, [_entry("tests/test_planted.py::test_param[a]")], ["tests/test_planted.py::test_param"])
    assert rc == 1, out


def test_without_a_list_nothing_is_quarantined(tmp_path):
    rc, out, _ = _session(tmp_path, None, [RED])
    assert rc == 1, out
    assert "no quarantine list at" in out, out


@pytest.mark.parametrize("bad, why", [
    ("not json", "not readable as JSON"),
    (json.dumps({"other": []}), "no list under the key 'quarantine'"),
    ([{"test": RED, "reason": "r", "deadline": "2026-11-08"}], "lacks owner"),
    ([_entry(RED, reason="")], "lacks reason"),
    ([_entry(RED, extra="x")], "fields the list does not know"),
    ([_entry(RED, deadline="2026-13-01")], "is not a date"),
    ([_entry(RED, deadline="20261108")], "is not a date YYYY-MM-DD"),
    ([_entry("tests/test_planted.py")], "is not a test node id"),
    ([_entry("test_planted.py::test_red")], "is not a test node id"),
    ([_entry(RED), _entry(RED)], "listed twice"),
])
def test_a_malformed_list_stops_the_run(tmp_path, bad, why):
    rc, out, root = _session(tmp_path, bad, ["tests/test_planted.py::test_green"])
    assert rc == pytest.ExitCode.USAGE_ERROR, out
    assert why in out, out
    assert not (root / "ran_green").exists(), "a wrong list must stop the run before any test"


# ── the repository's own list and registration ──────────────────────────────────────────────────────────────────────

def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_this_repository_registers_the_quarantine(request):
    assert request.config.pluginmanager.has_plugin("proofbundle-quarantine")


def test_the_list_of_this_repository_is_well_formed_and_names_the_open_cap_of_nachtrag_7():
    """Of the two caps of Nachtrag 7, the one of renewal_work is open; the fix of test_c12_1 landed on main on
    2026-10-31 (68d3f020), and its entries left the list."""
    q = _load(PLUGIN, "_quarantine_under_test")
    entries = q.load(LIST)
    assert entries, "the list is missing or empty"
    names = {e.test for e in entries}
    assert not any(n.startswith("tests/test_c12_1_nicht_anwendbar_vor_dem_tag.py::") for n in names), names
    assert ("tests/test_budget_kostenkurve.py::TestObergrenzeAmGroesstenZugelassenenWert::"
            "test_kosten_am_limit_unter_der_obergrenze[renewal_work]") in names


# ── the check of time caps ──────────────────────────────────────────────────────────────────────────────────────────

CAPPED = textwrap.dedent("""\
    import signal
    import subprocess
    import time

    import pytest

    LIMIT_S = 2.0
    WAIT_S = 0.5


    def _run():
        return subprocess.run(["true"], timeout=300)


    def _outer():
        return _run()


    @pytest.fixture
    def slow():
        signal.alarm(30)


    def test_direct():
        subprocess.run(["true"], timeout=60)


    def test_through_a_helper():
        _outer()


    def test_through_a_fixture(slow):
        pass


    def test_a_clock_against_a_number():
        t0 = time.perf_counter()
        dauer = time.perf_counter() - t0
        assert dauer < 3.0


    def test_a_seconds_constant():
        latte = 3 * LIMIT_S
        assert 1.0 <= latte


    def test_a_clock_in_an_if_steers_and_is_no_cap():
        t0 = time.monotonic()
        if time.monotonic() - t0 >= WAIT_S:
            pass


    def test_no_cap():
        assert 1 + 1 == 2


    class TestK:
        def _helper(self):
            subprocess.run(["true"], timeout=120)

        def test_method(self):
            self._helper()

        @pytest.mark.timeout(45)
        def test_marked(self):
            pass
    """)


@pytest.fixture
def checker():
    return _load(CHECKER, "quarantine_time_caps_under_test")


def _planted_tree(tmp_path: Path, entries: list[dict] | None) -> Path:
    tree = tmp_path / "tree"
    (tree / "tests").mkdir(parents=True)
    (tree / ".github").mkdir()
    shutil.copy(PLUGIN, tree / "tests" / "_quarantine.py")
    (tree / "tests" / "test_capped.py").write_text(CAPPED, encoding="utf-8")
    if entries is not None:
        (tree / ".github" / "test_quarantine.json").write_text(json.dumps({"quarantine": entries}), encoding="utf-8")
    return tree


def _caps(report: dict) -> dict[str, list[str]]:
    return {r["test"].split("::", 1)[1]: [f"{c['kind']} {c['seconds']} in {c['where']}" for c in r["caps"]]
            for r in report["tests_with_a_cap"]}


def test_the_check_finds_a_cap_in_a_helper_and_an_asserted_bound(tmp_path, checker):
    tree = _planted_tree(tmp_path, [])
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == 0, report
    caps = _caps(report)
    assert caps["test_through_a_helper"] == ["timeout= 300 in _run"], caps
    assert caps["test_a_seconds_constant"] == ["seconds constant LIMIT_S = 2 in test_a_seconds_constant"], caps
    assert caps["test_a_clock_against_a_number"] == ["clock against a number 3 in test_a_clock_against_a_number"], caps
    assert caps["test_through_a_fixture"] == ["signal.alarm 30 in slow"], caps
    assert caps["TestK::test_method"] == ["timeout= 120 in TestK::_helper"], caps


def test_the_check_finds_the_direct_caps(tmp_path, checker):
    tree = _planted_tree(tmp_path, [])
    report, _ = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    caps = _caps(report)
    assert caps["test_direct"] == ["timeout= 60 in test_direct"], caps
    assert caps["TestK::test_marked"] == ["mark.timeout 45 in TestK::test_marked"], caps
    assert "test_no_cap" not in caps and "test_a_clock_in_an_if_steers_and_is_no_cap" not in caps, caps


def test_the_check_says_where_each_capped_test_stands_on_the_list(tmp_path, checker):
    tree = _planted_tree(tmp_path, [_entry("tests/test_capped.py::test_direct"),
                                    _entry("tests/test_capped.py::test_through_a_helper", deadline="2026-10-01")])
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == 1, report      # the expired entry, see test_an_expired_entry_turns_the_check_red_until_it_leaves_the_list
    place = {r["test"].split("::", 1)[1]: r["list"] for r in report["tests_with_a_cap"]}
    assert place["test_direct"] == ["in force through 2026-11-08 as tests/test_capped.py::test_direct (owner o)"]
    assert place["test_through_a_helper"][0].startswith("EXPIRED on 2026-10-01")
    assert place["TestK::test_method"] == ["NOT ON THE LIST"]


def test_an_entry_that_names_no_test_or_a_malformed_list_is_red(tmp_path, checker):
    tree = _planted_tree(tmp_path, [_entry("tests/test_capped.py::test_gone")])
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == 1 and report["entries_naming_no_test"] == ["tests/test_capped.py::test_gone"], report
    (tree / ".github" / "test_quarantine.json").write_text("{", encoding="utf-8")
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == 1 and "not readable as JSON" in report["error"], report


def test_in_this_tree_the_two_caps_of_nachtrag_7_are_found_and_the_open_one_listed(checker):
    report, rc = checker.check(REPO, LIST, dt.date(2026, 10, 25))
    assert rc == 0, report["entries_naming_no_test"]
    rows = {r["test"]: r for r in report["tests_with_a_cap"]}
    c12 = rows["tests/test_c12_1_nicht_anwendbar_vor_dem_tag.py::"
                "test_ausserhalb_eines_pull_request_haengt_c12_1_an_der_GUELTIGKEIT"]
    assert any(c["kind"] == "timeout=" and c["seconds"] == "900" and c["where"] == "_lauf" for c in c12["caps"]), c12
    assert c12["list"] == ["NOT ON THE LIST"], c12
    rw = rows["tests/test_budget_kostenkurve.py::TestObergrenzeAmGroesstenZugelassenenWert::"
               "test_kosten_am_limit_unter_der_obergrenze"]
    assert any(c["kind"] == "seconds constant" for c in rw["caps"]), rw
    assert rw["list"][0].endswith("test_kosten_am_limit_unter_der_obergrenze[renewal_work] (owner b7n0de)"), rw
    assert report["listed_without_a_cap"] == [], report["listed_without_a_cap"]


def _named_in(cap: dict, reason: str) -> bool:
    """Whether an entry's reason names this cap as the tree carries it: `timeout=<seconds>` for a timeout, the
    constant's name for an asserted bound on a seconds constant, the number otherwise."""
    if cap["kind"] == "timeout=":
        return f"timeout={cap['seconds']}" in reason
    if cap["kind"] == "seconds constant":
        return any(part.split(" = ")[0] in reason for part in cap["seconds"].split(", "))
    return cap["seconds"] in reason


def test_every_entry_names_the_cap_the_tree_carries(checker):
    """An entry stays while the fix of its cap is open, and its reason names that cap. When the cap changes, the
    fix has landed or the reason has gone stale; either way the entry no longer says what it quarantines. Measured
    on 2026-10-31: tests/test_c12_1_nicht_anwendbar_vor_dem_tag.py's `_lauf` was raised from timeout=300 to
    timeout=900 on main (68d3f020), and four entries still named the 300."""
    report, rc = checker.check(REPO, LIST, dt.date(2026, 10, 25))
    assert rc == 0, report["entries_naming_no_test"]
    q = _load(PLUGIN, "_quarantine_reasons_under_test")
    rows = {r["test"]: r for r in report["tests_with_a_cap"]}
    stale = []
    for e in q.load(LIST):
        caps = rows.get(e.test.split("[")[0], {}).get("caps", [])
        if not any(_named_in(c, e.reason) for c in caps):
            stale.append((e.test, [f"{c['kind']} {c['seconds']}" for c in caps]))
    assert stale == [], stale


# ── what the reading of 8ec67d5a found: an expired entry, and a parameter no collected case carries ────────────────

def test_an_expired_entry_turns_the_check_red_until_it_leaves_the_list(tmp_path, checker):
    """After its deadline an entry no longer marks its test, and a red test blocks again. A test that passes leaves the
    run green, though, and the entry could stand on the list for ever under an owner who has moved on. The check is
    red on an expired entry instead, so the job `test` stops until the entry leaves the list (the reading of the head
    8ec67d5a of this pull request, P1)."""
    tree = _planted_tree(tmp_path, [_entry("tests/test_capped.py::test_direct", deadline="2026-10-24")])
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == 1, report
    assert report["entries_expired"] == ["tests/test_capped.py::test_direct (expired on 2026-10-24, owner o)"], report


def test_on_its_deadline_day_the_entry_keeps_the_check_green(tmp_path, checker):
    tree = _planted_tree(tmp_path, [_entry("tests/test_capped.py::test_direct", deadline="2026-10-25")])
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == 0 and report["entries_expired"] == [], report


PARAMETRIZED = textwrap.dedent("""\
    import subprocess

    import pytest


    @pytest.mark.parametrize("value", [1], ids=["real"])
    def test_param(value):
        subprocess.run(["true"], timeout=10)
    """)


@pytest.mark.parametrize("listed, red", [("tests/test_param.py::test_param[missing]", True),
                                         ("tests/test_param.py::test_param[real]", False)])
def test_an_entry_whose_parameter_no_collected_case_carries_is_red(tmp_path, checker, listed, red):
    """An entry with a parameter id quarantines exactly that case. Compared by the function name alone, a typo in the
    id passed the check while the plugin covered no test (the reading of the head 8ec67d5a, P2). The ids are what
    pytest collects for the function, so they are read from a collection of it, not from the source."""
    tree = _planted_tree(tmp_path, [_entry(listed)])
    (tree / "tests" / "test_param.py").write_text(PARAMETRIZED, encoding="utf-8")
    report, rc = checker.check(tree, tree / ".github" / "test_quarantine.json", dt.date(2026, 10, 25))
    assert rc == (1 if red else 0), report
    assert report["entries_naming_no_collected_case"] == ([listed] if red else []), report
