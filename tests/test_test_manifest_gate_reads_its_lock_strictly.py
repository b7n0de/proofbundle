"""D4 of CODEX-KLASSENSUCHE-631-01 (class D, at f6ea5cc3): the test-manifest gate reads its lock strictly.

Measured at f6ea5cc3 with the setup of `tests/test_audit_candidate_360.py::TestTestManifestGate`: one temporary test
module ``def test_one(): assert True``, collected for real by pytest with no stand-in for the counter, and a lock
passed separately as ``{"min_collected_tests":2,"min_collected_tests":1,"min_pytest_only_modules":1}``. `evaluate`
gave collected=1, errors=0, min_collected_tests=1, ok=True: `json.loads` kept the last floor. Controls: the unique
lock 1/1 passes the same call; the unique floor of 2 tests fails it.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _gate():
    spec = importlib.util.spec_from_file_location("tmg_strict", REPO / "scripts" / "test_manifest_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = _gate()


@pytest.fixture()
def tree(tmp_path):
    tests_dir = tmp_path / "population"
    tests_dir.mkdir()
    (tests_dir / "test_one.py").write_text("def test_one():\n    assert True\n", encoding="utf-8")
    return tests_dir, tmp_path / "lock.json"


@pytest.mark.parametrize("text", [
    '{"min_collected_tests":2,"min_collected_tests":1,"min_pytest_only_modules":1}',
    '{"min_collected_tests":1,"min_collected_tests":2,"min_pytest_only_modules":1}',
    '{"min_collected_tests":1,"min_pytest_only_modules":2,"min_pytest_only_modules":1}',
], ids=["lower floor last", "lower floor first", "pytest-only floor twice"])
def test_a_floor_named_twice_is_no_floor(tree, text):
    tests_dir, lock = tree
    lock.write_text(text, encoding="utf-8")
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert r["collected"] == 1 and r["errors"] == 0, "precondition: the real collector ran"
    assert r["ok"] is False and r["min_collected_tests"] is None, r
    assert any("duplicate JSON key" in p and "no population verdict" in p for p in r["problems"]), r["problems"]


def test_control_the_unique_floor_of_one_passes(tree):
    tests_dir, lock = tree
    lock.write_text('{"min_collected_tests":1,"min_pytest_only_modules":1}', encoding="utf-8")
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert r["ok"] is True and r["min_collected_tests"] == 1, r


def test_control_the_unique_floor_of_two_fails(tree):
    tests_dir, lock = tree
    lock.write_text('{"min_collected_tests":2,"min_pytest_only_modules":1}', encoding="utf-8")
    r = GATE.evaluate(tests_dir=tests_dir, lock_path=lock)
    assert r["ok"] is False and any("< locked floor 2" in p for p in r["problems"]), r
