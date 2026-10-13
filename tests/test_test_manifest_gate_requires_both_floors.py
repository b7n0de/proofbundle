"""E2 of CODEX-KLASSENSUCHE-631-01 (class E, at f6ea5cc3): a missing population anchor is not two zero floors.

Measured at f6ea5cc3 with the setup of D4 (one temporary test module, collected for real): once the lock passed to
`evaluate` was missing, once it held ``{}``. `load_lock` gave ``{}`` for the missing file and `evaluate` set both
floors to 0 with ``.get(..., 0)``; both times collected=1, errors=0, both floors 0, problems=[], ok=True. The guard
against unnoticed test loss went away with its anchor. Controls: the complete lock 1/1 passes the same call, a floor
of 2 tests fails it, and a floor of 0 written out stays a floor.
"""
from __future__ import annotations

import json

import pytest

from test_test_manifest_gate_reads_its_lock_strictly import GATE, tree  # noqa: F401


def _evaluate(tests_dir, lock):
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert r["collected"] == 1 and r["errors"] == 0, "precondition: the real collector ran"
    return r


def test_a_missing_lock_gives_no_population_verdict(tree):  # noqa: F811
    tests_dir, lock = tree
    r = _evaluate(tests_dir, lock)
    assert r["ok"] is False and r["min_collected_tests"] is None and r["min_pytest_only_modules"] is None, r
    assert any("lock.json is missing" in p for p in r["problems"]), r["problems"]


@pytest.mark.parametrize("content, missing", [
    ({}, ["min_collected_tests", "min_pytest_only_modules"]),
    ({"min_pytest_only_modules": 1}, ["min_collected_tests"]),
    ({"min_collected_tests": 1}, ["min_pytest_only_modules"]),
    ({"min_collected_tests": "1", "min_pytest_only_modules": 1}, ["min_collected_tests"]),
    ({"min_collected_tests": True, "min_pytest_only_modules": 1}, ["min_collected_tests"]),
    ({"min_collected_tests": 1.5, "min_pytest_only_modules": 1}, ["min_collected_tests"]),
    ({"min_collected_tests": -1, "min_pytest_only_modules": 1}, ["min_collected_tests"]),
    ({"min_collected_tests": 1, "min_pytest_only_modules": None}, ["min_pytest_only_modules"]),
], ids=["empty object", "test floor absent", "pytest-only floor absent", "a string", "a boolean", "a fraction",
        "negative", "null"])
def test_each_floor_must_be_written_out_as_an_integer(tree, content, missing):  # noqa: F811
    tests_dir, lock = tree
    lock.write_text(json.dumps(content), encoding="utf-8")
    r = _evaluate(tests_dir, lock)
    assert r["ok"] is False, r
    for name in missing:
        assert r[name] is None and any(f"names no {name}" in p for p in r["problems"]), r["problems"]


def test_a_lock_that_is_no_object_gives_no_verdict(tree):  # noqa: F811
    tests_dir, lock = tree
    lock.write_text("[1, 1]", encoding="utf-8")
    r = _evaluate(tests_dir, lock)
    assert r["ok"] is False and any("no JSON object" in p for p in r["problems"]), r["problems"]


def test_control_the_complete_lock_passes_and_a_higher_floor_fails(tree):  # noqa: F811
    tests_dir, lock = tree
    lock.write_text('{"min_collected_tests":1,"min_pytest_only_modules":1}', encoding="utf-8")
    assert _evaluate(tests_dir, lock)["ok"] is True
    lock.write_text('{"min_collected_tests":2,"min_pytest_only_modules":1}', encoding="utf-8")
    assert _evaluate(tests_dir, lock)["ok"] is False


def test_control_a_floor_of_zero_written_out_stays_a_floor(tree):  # noqa: F811
    tests_dir, lock = tree
    lock.write_text('{"min_collected_tests":0,"min_pytest_only_modules":0}', encoding="utf-8")
    r = _evaluate(tests_dir, lock)
    assert r["ok"] is True and r["min_collected_tests"] == 0 and r["min_pytest_only_modules"] == 0, r
