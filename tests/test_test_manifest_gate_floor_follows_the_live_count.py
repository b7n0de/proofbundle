"""The floors of the test manifest stand two percent below the live counts of the last reviewed --update.

Owner decision of 2 November 2026 on card OA-9f9bd944a7, option A. Measured at 5a460680 before it: the lock held
1750 tests and 5 pytest-only modules while pytest collected 25875 tests in 514 pytest-only modules, so the gate
stayed green through a loss of 24125 tests. `--update` wrote the live counts themselves as floors, and the floors
had not been raised since.

What is measured here, with the real collector on small populations and on the committed lock:
  * `--update` writes each floor two percent below its live count, rounded down, and records the counts;
  * a drop within the two percent passes the gate, one test more fails it, for tests and for pytest-only modules;
  * the committed lock is what `--update` writes: each floor is the recorded live count less two percent.
"""
from __future__ import annotations

import json

import pytest

from test_test_manifest_gate_reads_its_lock_strictly import GATE


def _population(tmp_path, modules: int, tests_per_module: int):
    tests_dir = tmp_path / "population"
    tests_dir.mkdir()
    body = "".join(f"def test_{i}():\n    assert True\n\n" for i in range(tests_per_module))
    for m in range(modules):
        (tests_dir / f"test_m{m:03d}.py").write_text(body, encoding="utf-8")
    return tests_dir, tmp_path / "lock.json"


def _drop_tests(tests_dir, count: int) -> None:
    """Take `count` test functions out of the modules in name order; every module file stays."""
    for module in sorted(tests_dir.glob("test_*.py")):
        tests = [part for part in module.read_text(encoding="utf-8").split("\n\n") if part.strip()]
        taken = min(count, len(tests))
        module.write_text("\n\n".join(tests[taken:]) + "\n", encoding="utf-8")
        count -= taken
        if count == 0:
            return
    raise AssertionError("the population holds fewer tests than the case takes out")


def test_update_writes_each_floor_two_percent_below_its_live_count(tmp_path):
    tests_dir, lock = _population(tmp_path, modules=50, tests_per_module=2)
    written = GATE._write_lock(tests_dir, lock)
    assert written["recorded_live_counts"] == {"collected": 100, "pytest_only_modules": 50}, written
    assert (written["min_collected_tests"], written["min_pytest_only_modules"]) == (98, 49), written
    assert written["tolerance_percent"] == 2
    assert json.loads(lock.read_text(encoding="utf-8")) == written


@pytest.mark.parametrize("live, floor", [(0, 0), (1, 0), (49, 48), (50, 49), (100, 98), (25875, 25357), (514, 503)])
def test_the_floor_is_rounded_down_in_integers(live, floor):
    assert GATE.floor_below(live) == floor


def test_a_drop_of_two_percent_passes_and_one_test_more_fails(tmp_path):
    tests_dir, lock = _population(tmp_path, modules=50, tests_per_module=2)
    GATE._write_lock(tests_dir, lock)
    _drop_tests(tests_dir, 2)
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert (r["collected"], r["errors"]) == (98, 0), "precondition: the real collector ran"
    assert r["ok"] is True, r["problems"]
    _drop_tests(tests_dir, 1)
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert r["collected"] == 97 and r["ok"] is False, r
    assert any("collected 97 tests < locked floor 98" in p for p in r["problems"]), r["problems"]


def test_a_module_less_passes_and_two_modules_less_fail(tmp_path):
    tests_dir, lock = _population(tmp_path, modules=50, tests_per_module=1)
    GATE._write_lock(tests_dir, lock)
    data = json.loads(lock.read_text(encoding="utf-8"))
    data["min_collected_tests"] = 0   # this case is about the module floor alone
    lock.write_text(json.dumps(data), encoding="utf-8")
    (tests_dir / "test_m049.py").unlink()
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert (r["pytest_only_modules"], r["min_pytest_only_modules"]) == (49, 49) and r["ok"] is True, r
    (tests_dir / "test_m048.py").unlink()
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert r["pytest_only_modules"] == 48 and r["ok"] is False, r
    assert any("48 pytest-only module(s) < locked floor 49" in p for p in r["problems"]), r["problems"]


def test_the_committed_lock_is_what_update_writes():
    lock = GATE.load_lock()
    live = lock["recorded_live_counts"]
    assert lock["tolerance_percent"] == GATE.FLOOR_TOLERANCE_PERCENT == 2, lock
    assert lock["min_collected_tests"] == GATE.floor_below(live["collected"]), lock
    assert lock["min_pytest_only_modules"] == GATE.floor_below(live["pytest_only_modules"]), lock
