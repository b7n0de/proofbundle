"""D118, follow-up note 47: a completion message ends only with evidence that names a checked count above zero.

Measured in follow-up note 47 (messung/stop_f1_f5.jsonl): at 89d2e8b7, the gate of account A's look back, the Stop hook ran only
the declared done check and neither repository declares one, so F1 to F5 ended silently; since D80 the
head holds the five as D80 rebuilt them. What D80 still lets end, measured at db5ea274, is what this file holds: a
status of grün, hält or OK without a test word or a script word, a verdict word with a suffix (WITHSTANDS_DEEPGATE), a
run whose own exit code is 0 but that names no checked count above zero, and the evidence a repository declares in
.proofbundle/done-claims.json. The house rules behind it: who reports green names the checked set; zero checked items
are never green; exit codes without a pipe; claim nothing that was not measured.

RED at db5ea274: every case that must hold. The counter cases (evidence with a count, an honest status, a status that
claims nothing, a word in another sense) end at both.
"""
from __future__ import annotations

import json

import pytest

import test_plugin_done_check as dc
import test_plugin_n32_claims_d80 as d80

env = dc.env
repo = dc.repo
transcript = d80.transcript
remote = d80.remote
held = d80.held
ends = d80.ends
_stop = d80._stop

CLAIMS_FILE = ".proofbundle/done-claims.json"


def _declare(repo, evidence, commit=True):
    dc._write(repo / CLAIMS_FILE, {"schema": "proofbundle-plugin/done-claims/v0.1", "evidence": evidence})
    if commit:
        dc._commit(repo, "declare the evidence of a completion")


# --- F1 to F5 of account A, rebuilt in the forms D80 lets end ---------------------------------------------------------

def test_F1_a_check_script_reporting_OK_over_zero_rows_is_held(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh", out="rows 0 of 0, mismatches 0\nOK")
    reason = held(_stop(env, repo, transcript, "check_contract.sh OK: 0 von 0 Zeilen."))
    assert "names no checked count above 0" in reason, reason


def test_F2_a_verdict_word_with_a_suffix_is_a_verdict(env, repo, transcript):
    reason = held(_stop(env, repo, transcript, "Urteil: WITHSTANDS_DEEPGATE."))
    assert "the verdict names no digest" in reason, reason


def test_F3_a_receipt_reported_green_without_the_full_matrix_is_held(env, repo, transcript):
    transcript.edit().bash("python3.11 -m pytest -q", out="5 passed in 0.10s")
    reason = held(_stop(env, repo, transcript, "Quittung grün, volle Matrix Python 3.11 und 3.12."))
    assert "names Python 3.12" in reason, reason


def test_F4_green_from_tail_after_timeout_is_held(env, repo, transcript):
    transcript.edit().bash("timeout 600 python -m pytest -q 2>&1 | tail -5", out="")
    reason = held(_stop(env, repo, transcript, "Abnahme grün."))
    assert "is not its own" in reason, reason


def test_F5_green_over_an_empty_red_set_read_with_rs_is_held(env, repo, transcript):
    transcript.edit().bash("python -m pytest -q -rs", rc=1, out="2 failed, 3 passed")
    reason = held(_stop(env, repo, transcript, "Rotmenge leer, alles grün."))
    assert "did not exit 0" in reason, reason


# --- the words: grün, hält, OK as a status -------------------------------------------------------------------------

@pytest.mark.parametrize("message", ["Alles grün.", "Abnahme grün.", "All green.", "N46 hält.", "Die Lieferung hält.",
                                     "The gate holds.", "Alles OK.", "Lieferung OK."])
def test_D118_a_status_without_any_run_is_held(env, repo, transcript, message):
    held(_stop(env, repo, transcript, message))


@pytest.mark.parametrize("message", ["Alles grün.", "N46 hält.", "Alles OK."])
def test_D118_a_status_after_a_change_needs_a_run_after_it(env, repo, transcript, message):
    transcript.bash("python -m pytest -q", out="5 passed in 0.1s").edit()
    assert "follows the last change" in held(_stop(env, repo, transcript, message))


# --- the count: zero checked items are never green -------------------------------------------------------------------

@pytest.mark.parametrize("out", ["Ran 0 tests in 0.000s\n\nOK", "", "no tests ran in 0.01s", "5 tests collected"])
def test_D118_a_test_run_that_names_no_count_above_zero_is_no_evidence(env, repo, transcript, out):
    transcript.edit().bash("python -m pytest -q --co" if "collected" in out else "python -m pytest -q", out=out)
    assert "names no checked count above 0" in held(_stop(env, repo, transcript, "Tests grün."))


def test_D118_a_decimal_or_a_duration_is_no_count(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh", out="took 0.25s, ratio 1.0\nOK")
    assert "names no checked count above 0" in held(_stop(env, repo, transcript, "check_contract.sh OK."))


def test_D118_a_check_script_whose_exit_code_comes_through_a_pipe_is_held(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh | tail -2", out="rows 12 of 12\nOK")
    assert "is not its own" in held(_stop(env, repo, transcript, "check_contract.sh OK: 12 von 12 Zeilen."))


def test_D118_control_a_check_script_through_a_pipe_with_pipefail_ends(env, repo, transcript):
    transcript.bash("set -o pipefail; bash tools/check_contract.sh | tail -2", out="rows 12 of 12\nOK")
    ends(_stop(env, repo, transcript, "check_contract.sh OK: 12 von 12 Zeilen."))


def test_D118_a_status_whose_last_run_names_no_count_is_held(env, repo, transcript):
    transcript.edit().bash("python -m pytest -q", out="")
    assert "names no checked count above 0" in held(_stop(env, repo, transcript, "Alles grün."))


# --- the declared evidence of a repository (.proofbundle/done-claims.json) ------------------------------------------

def test_D118_a_declared_evidence_without_its_run_is_held(env, repo, transcript):
    _declare(repo, [{"id": "tests", "program": ["python", "-m", "pytest"]},
                    {"id": "contract", "program": ["bash", "tools/check_contract.sh"]}])
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s")
    reason = held(_stop(env, repo, transcript, "Tests grün."))
    assert "contract" in reason and "declared" in reason, reason


def test_D118_a_declared_run_before_the_last_change_is_no_evidence(env, repo, transcript):
    _declare(repo, [{"id": "tests", "program": ["python", "-m", "pytest"]}])
    transcript.bash("python -m pytest -q", out="5 passed in 0.1s").edit()
    transcript.bash("bash tools/check_contract.sh", out="rows 12 of 12\nOK")
    assert "declared evidence tests" in held(_stop(env, repo, transcript, "Alles grün."))


def test_D118_the_declaration_of_the_remote_counts_where_head_drops_an_entry(env, repo, remote, transcript):
    _declare(repo, [{"id": "contract", "program": ["bash", "tools/check_contract.sh"]}])
    dc._git(repo, "push", "-q")
    _declare(repo, [])
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s")
    assert "contract" in held(_stop(env, repo, transcript, "Fertig."))


def test_D118_a_declaration_only_in_the_work_tree_counts_too(env, repo, transcript):
    _declare(repo, [{"id": "contract", "program": ["bash", "tools/check_contract.sh"]}], commit=False)
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s")
    assert "contract" in held(_stop(env, repo, transcript, "Alles grün."))


@pytest.mark.parametrize("doc", [{"schema": "x", "evidence": []}, {"evidence": []},
                                 {"schema": "proofbundle-plugin/done-claims/v0.1", "evidence": [{"id": "t"}]},
                                 "not json"])
def test_D118_a_declaration_the_gate_cannot_read_holds_every_completion(env, repo, transcript, doc):
    path = repo / CLAIMS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    dc._commit(repo, "a declaration the gate cannot read")
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s")
    assert "done-claims.json" in held(_stop(env, repo, transcript, "Tests grün."))


# --- counter cases: evidence with a count, an honest status, no claim, another sense -------------------------------

@pytest.mark.parametrize("message", ["Alles grün: 5 passed.", "Abnahme grün.", "N46 hält.", "Alles OK.",
                                     "Tests grün."])
def test_D118_control_a_run_with_its_own_exit_code_and_a_count_ends(env, repo, transcript, message):
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s")
    ends(_stop(env, repo, transcript, message))


def test_D118_control_a_check_script_with_a_count_above_zero_ends(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh", out="rows 12 of 12, mismatches 0\nOK")
    ends(_stop(env, repo, transcript, "check_contract.sh OK: 12 von 12 Zeilen."))


def test_D118_control_unittest_with_tests_ends(env, repo, transcript):
    transcript.edit().bash("python -m unittest", out="Ran 4 tests in 0.010s\n\nOK")
    ends(_stop(env, repo, transcript, "Tests grün."))


def test_D118_control_the_declared_evidence_with_its_runs_ends(env, repo, transcript):
    _declare(repo, [{"id": "tests", "program": ["python", "-m", "pytest"]},
                    {"id": "contract", "program": ["bash", "tools/check_contract.sh"]}])
    transcript.edit().bash("bash tools/check_contract.sh", out="rows 12 of 12\nOK")
    transcript.bash("python -m pytest -q", out="5 passed in 0.1s")
    ends(_stop(env, repo, transcript, "Fertig, Tests grün."))


@pytest.mark.parametrize("message", ["Nicht grün: 2 Tests rot.", "Die Abnahme ist noch nicht grün.",
                                     "OK, ich lese als Nächstes die Datei.", "Das Tor hält die Meldung an.",
                                     "Ich halte das für richtig.", "The hook holds back the end.",
                                     "Ich habe die Datei gelesen.", "Grün wäre es erst nach dem Lauf."])
def test_D118_control_a_status_that_claims_nothing_ends(env, repo, transcript, message):
    transcript.edit()
    ends(_stop(env, repo, transcript, message))


def test_D118_control_without_a_declaration_nothing_more_is_needed(env, repo, transcript):
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s")
    ends(_stop(env, repo, transcript, "Fertig, Tests grün."))


@pytest.mark.parametrize("command", ["python -I -m pytest -q", ".venv/bin/python3.12 -X dev -m pytest -q",
                                     "timeout 600 python3 -m pytest -q"])
def test_D118_control_a_declared_python_program_matches_its_forms(env, repo, transcript, command):
    _declare(repo, [{"id": "tests", "program": ["python", "-m", "pytest"]}])
    transcript.edit().bash(command, out="5 passed in 0.1s")
    ends(_stop(env, repo, transcript, "Fertig, Tests grün."))


@pytest.mark.parametrize("command, why", [("python -m unittest", "declared evidence tests"),
                                          ("pytest -q", "declared evidence tests"),
                                          ("python -c 'import pytest'", "no test run follows the last change")])
def test_D118_another_program_is_not_the_declared_one(env, repo, transcript, command, why):
    _declare(repo, [{"id": "tests", "program": ["python", "-m", "pytest"]}])
    transcript.edit().bash(command, out="Ran 5 tests\n5 passed")
    assert why in held(_stop(env, repo, transcript, "Fertig."))
