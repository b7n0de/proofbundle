"""Review of 2026-10-09, F3: the CI job checks every check of an order, not exactly one receipt.

Measured by the reviewer at 91a52faa: the job's check step passed exactly one receipt with `--receipt`, so an order
with two checks ended in gate_error ("the done check declares 2 checks"). Now the test step names a folder,
`PROOFBUNDLE_RECEIPT_DIR`, where each check leaves `<id>.json`, points PROOFBUNDLE_OUT at `tests.json`, the receipt of
the one-check form, and the check step reads the folder with `--receipt-dir`.

The job's steps run as in tests/test_plugin_review_fix_f1_ci_commit.py. Counter-probes: an order with the checks unit
and integration passes when the test command leaves both receipts, through the folder the step names and through
`$RUNNER_TEMP/done` written out; it fails when one is missing, naming that check; the one-check form passes with the
plain test command. Red against 91a52faa and against the F1 fix, b7968b72.
"""
from __future__ import annotations

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f1_ci_commit as f1

UNIT = {"id": "unit", "args": ["tests/unit"], "receipt": ".proofbundle/receipts/unit.json"}
INTEGRATION = {"id": "integration", "args": ["tests/integration"],
               "receipt": ".proofbundle/receipts/integration.json"}

pytestmark = f1.pytestmark
keys = f1.keys
_clean_git_environment = f1._clean_git_environment


@pytest.fixture
def ordered(tmp_path, keys) -> f1.Job:
    """The job, with `checked` a repository whose HEAD declares an order with the checks unit and integration."""
    job = f1.Job(tmp_path, keys)
    path = job.checked
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "tests" / "unit" / "test_a.py", "def test_a():\n    assert True\n")
    dc._write(path / "tests" / "integration" / "test_b.py", "def test_b():\n    assert True\n")
    dc._declare_order(path, keys.public, checks=(UNIT, INTEGRATION))
    dc._commit(path, "the order: unit and integration")
    return job


@pytest.fixture
def one_check(tmp_path, keys) -> f1.Job:
    job = f1.Job(tmp_path, keys)
    path = job.checked
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "test_ok.py", "def test_ok():\n    assert True\n")
    dc._declare_done(path, keys.public)
    dc._commit(path, "the one-check form")
    return job


BOTH_THROUGH_THE_FOLDER = ('PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/unit.json" python "$EMIT" tests/unit && '
                           'PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/integration.json" python "$EMIT" tests/integration')
BOTH_WRITTEN_OUT = ('PROOFBUNDLE_OUT="$RUNNER_TEMP/done/unit.json" python "$EMIT" tests/unit && '
                    'PROOFBUNDLE_OUT="$RUNNER_TEMP/done/integration.json" python "$EMIT" tests/integration')


@pytest.mark.parametrize("command", [BOTH_THROUGH_THE_FOLDER, BOTH_WRITTEN_OUT], ids=["folder", "written out"])
def test_an_order_with_two_checks_passes_with_both_receipts(ordered, command):
    """Red at 91a52faa and at b7968b72: gate_error, the step passed one receipt for two checks."""
    check, report = ordered.run(command)
    assert (check.returncode, report["verdict"], report["reason_id"]) == (0, "pass", "done"), check.stderr
    assert "2 checks (unit, integration)" in report["message"]


def test_an_order_with_a_missing_receipt_fails_and_names_the_check(ordered):
    check, report = ordered.run('PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/unit.json" python "$EMIT" tests/unit')
    assert (check.returncode, report["verdict"], report["reason_id"]) == (1, "deny", "no_receipt"), check.stderr
    assert "check integration is missing" in report["message"]


def test_an_order_whose_receipt_names_another_selection_fails(ordered):
    command = ('PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/unit.json" python "$EMIT" tests && '
               'PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/integration.json" python "$EMIT" tests/integration')
    check, report = ordered.run(command)
    assert (check.returncode, report["reason_id"]) == (1, "other_selection"), check.stderr


def test_the_one_check_form_passes_with_the_plain_test_command(one_check):
    check, report = one_check.run('python "$EMIT"')
    assert (check.returncode, report["verdict"]) == (0, "pass"), check.stderr
    assert "1 check (tests)" in report["message"]


def test_the_steps_name_the_folder_and_the_one_check_receipt():
    tests = f1._step("Run the tests with a receipt")
    assert 'PROOFBUNDLE_RECEIPT_DIR="$RUNNER_TEMP/done"' in tests["run"]
    assert 'PROOFBUNDLE_OUT="$RUNNER_TEMP/done/tests.json"' in tests["run"]
    check = f1.done_steps()[-1]
    assert '--receipt-dir "$RUNNER_TEMP/done"' in check["run"] and "--receipt " not in check["run"]
