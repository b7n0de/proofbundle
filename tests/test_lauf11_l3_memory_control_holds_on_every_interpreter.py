"""631 part 2, P2 group 4 of CODEX-DEFEKTSUCHE-630-KANDIDAT-01 (at 98b168b9): the unshared-dict memory test holds its
property on every interpreter, not one interpreter's cost of breaking the key sharing.

`tests/test_lauf11_l3_testlast_ist_gedeckelt.py::TestKeineUngedeckelteTestlast::
test_die_tabelle_traegt_auch_ungeteilte_instanz_dicts` measured the bytes per chain element before and after an
instance of ArchiveTimeStamp lost its `time` attribute, in a fresh child process, and required the second reading to
be strictly larger as its control. The Codex search measured 320.9 B both times on CPython 3.12.14, a false red
whose table check (640 B) held. CPython 3.12.14 is not installed here (NOT MEASURED); on 3.11.17, 3.12.3 and 3.13.16
the two readings differ by 0.1 B. This file feeds the test the child output the Codex search measured and others:
equal readings pass, a reading above the table fails, and a child that did not run fails.
"""
from __future__ import annotations

import subprocess
import unittest

import test_lauf11_l3_testlast_ist_gedeckelt as L3

TEST = "test_die_tabelle_traegt_auch_ungeteilte_instanz_dicts"


def _run_with_child_output(stdout: str, returncode: int = 0) -> unittest.TestResult:
    original = subprocess.run

    def child(args, *a, **kw):
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr="the child failed")

    subprocess.run = child
    try:
        result = unittest.TestResult()
        L3.TestKeineUngedeckelteTestlast(TEST).run(result)
        return result
    finally:
        subprocess.run = original


def _verdict(result: unittest.TestResult) -> str:
    return "failed" if result.failures or result.errors else "passed"


def test_equal_readings_as_measured_on_cpython_3_12_14_pass():
    assert _verdict(_run_with_child_output("320.9 320.9\n")) == "passed"


def test_control_readings_as_measured_here_pass():
    assert _verdict(_run_with_child_output("328.8 328.9\n")) == "passed"


def test_control_a_shared_reading_above_the_table_fails():
    assert _verdict(_run_with_child_output("700.0 320.9\n")) == "failed"


def test_control_an_unshared_reading_above_the_table_fails():
    assert _verdict(_run_with_child_output("356.6 700.0\n")) == "failed"


def test_control_a_child_that_failed_fails():
    assert _verdict(_run_with_child_output("", returncode=1)) == "failed"


def test_control_a_child_that_measured_nothing_fails():
    assert _verdict(_run_with_child_output("0.0 0.0\n")) == "failed"
