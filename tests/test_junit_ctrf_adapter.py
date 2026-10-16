"""JUnit XML and CTRF JSON reports to a signed eval receipt (adapters/junit_ctrf.py).

Three layers, each against its own oracle:

* the readers against the vector manifest `tests/fixtures/test_reports/vectors.json`, whose counts
  were taken from the producers' own runs (pytest, jest-junit, jest-ctrf-json-reporter) and from the
  Surefire writer, never from this reader;
* the verdict and the score against exact fractions, over a grid of counts;
* the receipt through the process boundary: `emit-test-receipt`, then the existing `show-eval` and
  `verify`, then `check-test-receipt` against the report and against changed reports.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import pytest

from proofbundle.adapters.junit_ctrf import (
    NON_CLAIMS,
    REPORT_MAX_BYTES,
    VERDICT_RULE,
    XML_MAX_DEPTH,
    ReportRefused,
    from_ctrf_json,
    from_junit_xml,
    read_ctrf_json,
    read_junit_xml,
    verify_test_receipt,
)

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "tests" / "fixtures" / "test_reports"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
ENTRIES = MANIFEST["vectors"]
_FIELDS = ("tests", "passed", "failed", "errors", "skipped")


def _reader(rel: str):
    return read_junit_xml if rel.startswith("junit/") else read_ctrf_json


def _counts(c) -> list:
    return [c.tests, c.passed, c.failed, c.errors, c.skipped]


def _run(*args):
    return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args], capture_output=True, text=True,
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO / "src")})


# --- the manifest is complete and the vectors behave as recorded ------------------------------------

def test_every_vector_file_is_in_the_manifest():
    on_disk = {p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*")
               if p.is_file() and p.suffix in (".xml", ".json") and p.name != "vectors.json"}
    listed = [e["file"] for e in ENTRIES]
    assert len(listed) == len(set(listed)), "a vector is listed twice"
    assert on_disk == set(listed)


def test_the_manifest_states_the_same_rule_as_the_code():
    assert MANIFEST["verdict_rule"] == VERDICT_RULE
    assert MANIFEST["counts_order"] == list(_FIELDS)


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["file"] for e in ENTRIES])
def test_vector(entry):
    data = (VECTORS / entry["file"]).read_bytes()
    if entry["expect"] == "accept":
        counts = _reader(entry["file"])(data)
        assert _counts(counts) == entry["counts"]
        assert counts.verdict is entry["passed"]
    else:
        with pytest.raises(ReportRefused) as exc:
            _reader(entry["file"])(data)
        assert exc.value.code == entry["code"], str(exc.value)
        assert str(exc.value).strip(), "a refusal names its reason"


def test_both_formats_have_positive_and_negative_vectors_for_the_named_cases():
    by_code = {}
    for e in ENTRIES:
        fmt = e["file"].split("/")[0]
        by_code.setdefault((fmt, e["expect"]), set()).add(e.get("code"))
    for fmt in ("junit", "ctrf"):
        assert (fmt, "accept") in by_code
    assert {"doctype", "entity", "duplicate_attribute"} <= by_code[("junit", "refuse")]
    assert {"duplicate_key", "encoding", "unknown_field"} <= by_code[("ctrf", "refuse")]
    names = " ".join(e["file"] for e in ENTRIES)
    for case in ("xxe_external_entity", "entity_cascade", "only_skipped", "empty_suite", "empty_tests",
                 "duplicate_key"):
        assert case in names


# --- rules the vectors cannot carry as files ----------------------------------------------------------

def test_xml_nesting_beyond_the_limit_is_refused_and_at_the_limit_is_read():
    def nested(levels: int) -> bytes:
        return ("<testsuite name='s'>" * levels + "<testcase name='t'/>" + "</testsuite>" * levels).encode()
    assert read_junit_xml(nested(XML_MAX_DEPTH - 1)).passed == 1
    with pytest.raises(ReportRefused) as exc:
        read_junit_xml(nested(XML_MAX_DEPTH + 1))
    assert exc.value.code == "too_deep"


def test_ctrf_nesting_beyond_the_limit_is_refused():
    deep = {"x": None}
    for _ in range(80):
        deep = {"x": deep}
    doc = {"reportFormat": "CTRF", "specVersion": "0.2.0",
           "results": {"tool": {"name": "t"}, "summary": {"tests": 1, "passed": 1, "failed": 0, "pending": 0,
                                                         "skipped": 0, "other": 0, "start": 1, "stop": 2},
                       "tests": [{"name": "a", "status": "passed", "duration": 1, "extra": deep}]}}
    with pytest.raises(ReportRefused) as exc:
        read_ctrf_json(json.dumps(doc).encode())
    assert exc.value.code == "too_deep"


@pytest.mark.parametrize("reader,name", [(read_junit_xml, "junit/syn_testsuite_root_passed.xml"),
                                         (read_ctrf_json, "ctrf/syn_minimal_passed.json")])
def test_size_limit(reader, name):
    data = (VECTORS / name).read_bytes()
    assert reader(data, max_bytes=len(data)).verdict is True
    with pytest.raises(ReportRefused) as exc:
        reader(data, max_bytes=len(data) - 1)
    assert exc.value.code == "too_large"
    assert REPORT_MAX_BYTES >= 32 * 1024 * 1024


def test_an_external_entity_is_never_read(tmp_path):
    canary = tmp_path / "canary.txt"
    canary.write_text("CANARY-CONTENT", encoding="utf-8")
    data = (f'<?xml version="1.0"?><!DOCTYPE testsuite [<!ENTITY e SYSTEM "{canary.as_uri()}">]>'
            '<testsuite name="&e;" tests="1"><testcase name="t"/></testsuite>').encode()
    with pytest.raises(ReportRefused) as exc:
        read_junit_xml(data)
    assert exc.value.code == "doctype"
    assert "CANARY-CONTENT" not in str(exc.value)


def test_a_reader_takes_bytes_only():
    with pytest.raises(TypeError):
        read_junit_xml("<testsuite name='s'/>")
    with pytest.raises(TypeError):
        read_ctrf_json({"reportFormat": "CTRF"})


# --- the verdict and the score ------------------------------------------------------------------------

@pytest.mark.parametrize("passed,failed,errors,skipped,expected", [
    (1, 0, 0, 0, True), (5, 0, 0, 3, True), (0, 0, 0, 0, False), (0, 0, 0, 4, False),
    (3, 1, 0, 0, False), (3, 0, 1, 0, False), (0, 1, 0, 0, False), (0, 0, 1, 0, False)])
def test_verdict_rule(passed, failed, errors, skipped, expected):
    tests = passed + failed + errors + skipped
    cases = ("<testcase name='p'/>" * passed + "<testcase name='f'><failure/></testcase>" * failed
             + "<testcase name='e'><error/></testcase>" * errors + "<testcase name='s'><skipped/></testcase>" * skipped)
    counts = read_junit_xml(f"<testsuite name='s' tests='{tests}'>{cases}</testsuite>".encode())
    assert counts.verdict is expected


def _claim_for(passed: int, failed: int, errors: int):
    from proofbundle.adapters.junit_ctrf import ReportCounts, _claim_from_counts
    counts = ReportCounts(fmt="junit-xml", tests=passed + failed + errors, passed=passed, failed=failed,
                          errors=errors, skipped=0, name="s", tool_version=None, spec_version=None)
    claim, _ = _claim_from_counts(counts, "0" * 64, commit=None, suite=None, timestamp="2026-10-16T00:00:00Z",
                                  model_salt=b"m" * 16, dataset_salt=b"d" * 16)
    return claim


def test_the_signed_verdict_is_the_verdict_of_the_counts_on_a_grid():
    for passed in range(0, 12):
        for failed in range(0, 4):
            for errors in range(0, 3):
                claim = _claim_for(passed, failed, errors)
                assert claim["passed"] is (failed == 0 and errors == 0 and passed >= 1)
                assert claim["n"] == passed + failed + errors


@pytest.mark.parametrize("passed,executed", [(999_999, 1_000_000), (1_999_999, 2_000_000),
                                             (9_999_999, 10_000_000), (2, 3), (1, 3)])
def test_a_rate_just_below_one_never_rounds_to_passed(passed, executed):
    claim = _claim_for(passed, executed - passed, 0)
    assert claim["passed"] is False
    from decimal import Decimal
    score = Decimal(claim["provenance"]["pass_rate_floor"])
    assert score < 1
    assert Fraction(score) <= Fraction(passed, executed)


def test_with_the_doctype_refusal_planted_away_an_external_entity_is_still_refused(monkeypatch):
    """Gate meta test of the belt behind the doctype refusal: with that refusal removed, an external entity
    in content reaches the entity handler, which refuses it instead of letting the parser skip it in silence."""
    from proofbundle.adapters import junit_ctrf
    monkeypatch.setattr(junit_ctrf, "_refuse_doctype", lambda *_: None)
    data = (b'<?xml version="1.0"?><!DOCTYPE testsuite [<!ENTITY e SYSTEM "https://example.invalid/x">]>'
            b'<testsuite name="s" tests="1"><testcase name="t"><system-out>&e;</system-out></testcase></testsuite>')
    with pytest.raises(ReportRefused) as exc:
        read_junit_xml(data)
    assert exc.value.code == "external_reference"


def test_the_verdict_guard_refuses_a_score_that_disagrees_with_the_counts(monkeypatch):
    """Gate meta test of the guard between the score and the counts: a score that would sign passed for a run
    with a failure is refused, no claim is returned."""
    from proofbundle.adapters import junit_ctrf
    monkeypatch.setattr(junit_ctrf, "_pass_rate_floor", lambda passed, executed: "1")
    with pytest.raises(ReportRefused) as exc:
        _claim_for(3, 1, 0)
    assert exc.value.code == "verdict_mismatch"


# --- the receipt ---------------------------------------------------------------------------------------

def test_claim_shape_and_what_it_carries():
    path = VECTORS / "junit/pytest-9.1.1_mixed.xml"
    commit = "a" * 40
    claim, salts = from_junit_xml(path, commit=commit, timestamp="2026-10-16T00:00:00Z")
    prov = claim["provenance"]
    assert prov["report_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert prov["report_format"] == "junit-xml"
    assert prov["commit"] == commit
    assert [prov["tests_" + f] for f in _FIELDS[1:]] == [1, 3, 4, 2]
    assert prov["tests_total"] == 10
    assert prov["verdict_rule"] == VERDICT_RULE
    assert prov["non_claims"] == NON_CLAIMS
    assert "does not prove" in NON_CLAIMS and "real" in NON_CLAIMS
    assert (claim["metric"], claim["comparator"], claim["threshold"]) == ("pass_rate", ">=", "1")
    assert claim["passed"] is False and claim["n"] == 8
    assert set(salts) == {"model_salt", "dataset_salt"}


def test_ctrf_claim_records_the_spec_version_and_the_mapping():
    claim, _ = from_ctrf_json(VECTORS / "ctrf/jest-ctrf-json-reporter-0.2.0_mixed.json",
                              timestamp="2026-10-16T00:00:00Z")
    prov = claim["provenance"]
    assert prov["ctrf_spec_version"] == "0.2.0"
    assert prov["ctrf_status_other_counted_as_errors"] == 1
    assert prov["ctrf_status_pending_counted_as_skipped"] == 1
    assert prov["harness_version_status"] == "not_reported"
    assert "commit" not in prov


@pytest.mark.parametrize("bad", ["abc", "A" * 40, "a" * 39, "a" * 41, "g" * 40, " " + "a" * 40, ""])
def test_a_commit_is_a_full_lowercase_hex_object_name(bad):
    with pytest.raises(ValueError):
        from_junit_xml(VECTORS / "junit/pytest-9.1.1_all_passed.xml", commit=bad)
    for good in ("0" * 40, "f" * 64):
        claim, _ = from_junit_xml(VECTORS / "junit/pytest-9.1.1_all_passed.xml", commit=good)
        assert claim["provenance"]["commit"] == good


def test_a_path_that_is_not_a_regular_file_is_refused(tmp_path):
    with pytest.raises(ReportRefused) as exc:
        from_junit_xml(tmp_path)
    assert exc.value.code == "not_a_file"


def test_round_trip_through_the_cli(tmp_path):
    key = tmp_path / "k.key"
    cases = [("--junit", VECTORS / "junit/pytest-9.1.1_all_passed.xml", "True"),
             ("--junit", VECTORS / "junit/pytest-9.1.1_mixed.xml", "False"),
             ("--ctrf", VECTORS / "ctrf/jest-ctrf-json-reporter-0.2.0_all_passed.json", "True"),
             ("--ctrf", VECTORS / "ctrf/jest-ctrf-json-reporter-0.2.0_only_skipped.json", "False")]
    for i, (flag, report, shown) in enumerate(cases):
        out = tmp_path / f"r{i}.json"
        key_args = ("--new-key", str(key)) if i == 0 else ("--key", str(key))
        r = _run("emit-test-receipt", flag, str(report), "--out", str(out), "--commit", "b" * 40, *key_args)
        assert r.returncode == 0, r.stderr
        assert _run("verify", str(out)).returncode == 0
        show = _run("show-eval", str(out))
        assert show.returncode == 0, show.stderr
        assert f"passed     {shown}" in show.stdout
        assert "pass_rate >= 1" in show.stdout
        check = _run("check-test-receipt", str(out), "--report", str(report))
        assert check.returncode == 0, check.stdout + check.stderr
        issuer = verify_test_receipt(str(out), report)["claim"]["issuer"]
        pinned = _run("check-test-receipt", str(out), "--report", str(report), "--expect-issuer", issuer)
        assert pinned.returncode == 0


def test_check_fails_on_another_report_and_on_a_changed_receipt(tmp_path):
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    out = tmp_path / "r.json"
    assert _run("emit-test-receipt", "--junit", str(report), "--out", str(out),
                "--new-key", str(tmp_path / "k.key")).returncode == 0
    changed = tmp_path / "changed.xml"
    changed.write_bytes(report.read_bytes().replace(b'time="0.000"', b'time="0.001"', 1))
    assert changed.read_bytes() != report.read_bytes()
    r = _run("check-test-receipt", str(out), "--report", str(changed))
    assert r.returncode == 1 and "digest" in r.stdout + r.stderr
    other = VECTORS / "junit/pytest-9.1.1_mixed.xml"
    assert _run("check-test-receipt", str(out), "--report", str(other)).returncode == 1
    import base64
    bundle = json.loads(out.read_text(encoding="utf-8"))
    payload = base64.b64decode(bundle["payload_b64"])
    assert b'"passed":true' in payload
    bundle["payload_b64"] = base64.b64encode(payload.replace(b'"passed":true', b'"passed":false')).decode()
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(bundle), encoding="utf-8")
    assert _run("show-eval", str(bad)).returncode == 1
    assert _run("check-test-receipt", str(bad), "--report", str(report)).returncode == 1
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import issuer_fingerprint
    wrong = _run("check-test-receipt", str(out), "--report", str(report), "--expect-issuer",
                 issuer_fingerprint(generate_signer()))
    assert wrong.returncode == 1


def test_check_recomputes_the_counts_from_the_report(tmp_path):
    """A receipt whose signed counts differ from what the report reads as fails the check, even when the
    digest matches: a receipt signed by another reader is not taken on trust."""
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import emit_eval_receipt
    report = VECTORS / "junit/pytest-9.1.1_mixed.xml"
    claim, _ = from_junit_xml(report, timestamp="2026-10-16T00:00:00Z")
    claim["provenance"]["tests_failed"] = 0
    bundle = emit_eval_receipt(claim, generate_signer())
    result = verify_test_receipt(bundle, report)
    assert result["ok"] is False and "tests_failed" in result["reason"]


def test_check_refuses_a_receipt_that_is_not_a_test_report_receipt(tmp_path):
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
    claim, _ = build_eval_claim(suite="s", suite_version="v", metric="acc", comparator=">=", threshold="0.5",
                                score="0.9", n=10, model_id="m", dataset_id="d", issuer="",
                                timestamp="2026-10-16T00:00:00Z")
    result = verify_test_receipt(emit_eval_receipt(claim, generate_signer()),
                                 VECTORS / "junit/pytest-9.1.1_all_passed.xml")
    assert result["ok"] is False and "test-report" in result["reason"]


def test_emit_refusal_names_the_reason_and_writes_nothing(tmp_path):
    out = tmp_path / "r.json"
    r = _run("emit-test-receipt", "--junit", str(VECTORS / "junit/syn_xxe_external_entity.xml"),
             "--out", str(out), "--new-key", str(tmp_path / "k.key"))
    assert r.returncode == 2
    assert "doctype" in r.stderr and "ERROR" in r.stderr
    assert not out.exists()
    r = _run("emit-test-receipt", "--ctrf", str(VECTORS / "ctrf/syn_duplicate_key_status.json"),
             "--out", str(out), "--new-key", str(tmp_path / "k2.key"))
    assert r.returncode == 2 and "duplicate_key" in r.stderr
    assert not out.exists()


def test_emit_needs_exactly_one_report():
    r = _run("emit-test-receipt", "--out", "x.json", "--new-key", "k.key")
    assert r.returncode == 2
    r = _run("emit-test-receipt", "--junit", "a.xml", "--ctrf", "b.json", "--out", "x.json", "--new-key", "k.key")
    assert r.returncode == 2


def test_public_api_is_exported_with_english_names():
    import proofbundle.adapters as adapters
    for name in ("from_junit_xml", "from_ctrf_json", "read_junit_xml", "read_ctrf_json", "verify_test_receipt",
                 "ReportRefused"):
        assert name in adapters.__all__
        assert getattr(adapters, name) is not None


def _signed_with_provenance(change):
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import emit_eval_receipt
    claim, _ = from_junit_xml(VECTORS / "junit/pytest-9.1.1_mixed.xml", timestamp="2026-10-16T00:00:00Z")
    change(claim["provenance"])
    return emit_eval_receipt(claim, generate_signer())


@pytest.mark.parametrize("value", [["junit-xml"], {"a": 1}, 7, None, True])
def test_check_never_raises_on_a_report_format_of_another_type(value):
    bundle = _signed_with_provenance(lambda p: p.__setitem__("report_format", value))
    result = verify_test_receipt(bundle, VECTORS / "junit/pytest-9.1.1_mixed.xml")
    assert result["ok"] is False and "test-report" in result["reason"]


def test_check_compares_a_signed_count_by_type_not_only_by_value():
    """True == 1 in Python: a receipt signing tests_passed true for a report with one passed test is not about
    that report's counts."""
    bundle = _signed_with_provenance(lambda p: p.__setitem__("tests_passed", True))
    result = verify_test_receipt(bundle, VECTORS / "junit/pytest-9.1.1_mixed.xml")
    assert result["ok"] is False and "tests_passed" in result["reason"]


def test_emit_into_a_path_that_cannot_be_written_is_malformed_input(tmp_path):
    out = tmp_path / "missing-directory" / "r.json"
    r = _run("emit-test-receipt", "--junit", str(VECTORS / "junit/pytest-9.1.1_all_passed.xml"), "--out", str(out),
             "--new-key", str(tmp_path / "k.key"))
    assert r.returncode == 2 and "Traceback" not in r.stderr and "ERROR" in r.stderr


# --- lens run 1, iteration 1: each finding as a case, red at b4b393e6 ------------------------------------------------

def _receipt_with(report, change):
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import emit_eval_receipt
    reader = from_junit_xml if str(report).endswith(".xml") else from_ctrf_json
    claim, _ = reader(report, timestamp="2026-10-16T00:00:00Z")
    change(claim["provenance"])
    return emit_eval_receipt(claim, generate_signer())


@pytest.mark.parametrize("key,value", [("ctrf_status_other_counted_as_errors", 0),
                                       ("ctrf_status_pending_counted_as_skipped", 7),
                                       ("pass_rate_floor", "0.99"), ("ctrf_tool_name", "another tool"),
                                       ("verdict_rule", "passed = true"), ("non_claims", "proves everything"),
                                       ("harness_version_status", "reported")])
def test_check_compares_the_whole_provenance_not_only_the_five_counts(key, value):
    """F1 (P1): the check compared five counts and the verdict, and said ok for a receipt whose other signed
    provenance contradicted the report. It now rebuilds the provenance from the report and compares all of it."""
    report = VECTORS / "ctrf/jest-ctrf-json-reporter-0.2.0_mixed.json"
    result = verify_test_receipt(_receipt_with(report, lambda p: p.__setitem__(key, value)), report)
    assert result["ok"] is False and key in result["reason"]


def test_check_refuses_a_provenance_field_a_test_receipt_does_not_carry():
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    result = verify_test_receipt(_receipt_with(report, lambda p: p.__setitem__("audited_by", "someone")), report)
    assert result["ok"] is False and "audited_by" in result["reason"]


def test_check_requires_the_receipt_profile():
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    result = verify_test_receipt(_receipt_with(report, lambda p: p.pop("receipt_profile")), report)
    assert result["ok"] is False and "test-report receipt" in result["reason"]


@pytest.mark.parametrize("limit", [2 ** 40, 2 ** 63 - 1, 2 ** 63, 2 ** 80])
def test_a_large_limit_is_a_limit_not_an_allocation(limit, tmp_path):
    """F4 and F5: the file was read with one read of `max_bytes + 1`, so 2**40 ended in MemoryError and 2**63 in
    OverflowError, in the CLI and in verify_test_receipt."""
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    claim, _ = from_junit_xml(report, max_bytes=limit, timestamp="2026-10-16T00:00:00Z")
    assert claim["passed"] is True
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import emit_eval_receipt
    assert verify_test_receipt(emit_eval_receipt(claim, generate_signer()), report, max_bytes=limit)["ok"] is True
    out = tmp_path / "r.json"
    r = _run("emit-test-receipt", "--junit", str(report), "--out", str(out), "--new-key", str(tmp_path / "k.key"),
             "--max-report-bytes", str(limit))
    assert r.returncode == 0, r.stderr


def test_the_size_refusal_of_a_file_names_the_limit_not_a_wrong_size(tmp_path):
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    size = report.stat().st_size
    with pytest.raises(ReportRefused) as exc:
        from_junit_xml(report, max_bytes=size - 1)
    assert exc.value.code == "too_large"
    assert f"more than the limit of {size - 1} bytes" in str(exc.value) and str(size) not in str(exc.value)


def test_check_takes_the_report_limit_too(tmp_path):
    """F7: emit-test-receipt had --max-report-bytes and check-test-receipt had none, so a receipt made under a raised
    limit could never be checked."""
    report = VECTORS / "junit/pytest-9.1.1_mixed.xml"
    out = tmp_path / "r.json"
    assert _run("emit-test-receipt", "--junit", str(report), "--out", str(out),
                "--new-key", str(tmp_path / "k.key")).returncode == 0
    small = _run("check-test-receipt", str(out), "--report", str(report), "--max-report-bytes", "100")
    assert small.returncode == 1 and "more than the limit of 100 bytes" in small.stderr
    assert _run("check-test-receipt", str(out), "--report", str(report), "--max-report-bytes",
                str(report.stat().st_size)).returncode == 0


def _nfd_ctrf(tmp_path):
    import unicodedata
    doc = json.loads((VECTORS / "ctrf/syn_minimal_passed.json").read_text(encoding="utf-8"))
    doc["results"]["tool"]["name"] = unicodedata.normalize("NFD", "café")
    path = tmp_path / "nfd.json"
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return path


def test_a_report_string_that_is_not_nfc_is_refused_with_its_field(tmp_path):
    """F6: the canonicalizer refused it with "string is not NFC-normalized", naming no field, and --suite did not help
    for CTRF. Now the refusal names the field, and for JUnit a suite of one's own is the way past it."""
    import unicodedata
    with pytest.raises(ReportRefused) as exc:
        from_ctrf_json(_nfd_ctrf(tmp_path), suite="ok")
    assert exc.value.code == "not_nfc" and "results.tool.name" in str(exc.value)
    junit = tmp_path / "nfd.xml"
    junit.write_text(f'<testsuite name="{unicodedata.normalize("NFD", "café")}"><testcase name="a"/></testsuite>',
                     encoding="utf-8")
    with pytest.raises(ReportRefused) as exc:
        from_junit_xml(junit)
    assert exc.value.code == "not_nfc" and "suite=" in str(exc.value)
    claim, _ = from_junit_xml(junit, suite="cafe suite")
    assert claim["suite"] == "cafe suite"
    with pytest.raises(ReportRefused) as exc:
        from_junit_xml(junit, suite=unicodedata.normalize("NFD", "café"))
    assert exc.value.code == "not_nfc" and "suite argument" in str(exc.value)
    r = _run("emit-test-receipt", "--ctrf", str(_nfd_ctrf(tmp_path)), "--out", str(tmp_path / "o.json"),
             "--new-key", str(tmp_path / "k.key"))
    assert r.returncode == 2 and "results.tool.name" in r.stderr


def test_the_library_refuses_a_weak_issuer_pin_as_the_cli_does():
    """F8: verify_test_receipt compared a low-order pin as a string, where check-test-receipt refuses it (exit 2)."""
    import base64
    identity = "ed25519:" + base64.b64encode(bytes([1]) + bytes(31)).decode()
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    result = verify_test_receipt(_receipt_with(report, lambda p: None), report, expected_issuers=[identity])
    assert result["ok"] is False and "refused as a trusted key" in result["reason"]
    assert _run("check-test-receipt", "x.json", "--report", str(report), "--expect-issuer", identity).returncode == 2


def test_a_count_beyond_the_safe_range_is_named_as_such():
    """F10: 2**53 was refused as "must be a non-negative integer", which it is."""
    with pytest.raises(ReportRefused) as exc:
        read_ctrf_json((VECTORS / "ctrf/syn_count_above_the_safe_range.json").read_bytes())
    assert "at most 2**53-1" in str(exc.value)


def test_the_receipt_is_never_written_over_its_report(tmp_path):
    """F14: --out could name the report itself, and the receipt replaced the report it is about."""
    report = tmp_path / "report.xml"
    report.write_bytes((VECTORS / "junit/pytest-9.1.1_all_passed.xml").read_bytes())
    before = report.read_bytes()
    r = _run("emit-test-receipt", "--junit", str(report), "--out", str(report), "--new-key", str(tmp_path / "k.key"))
    assert r.returncode == 2 and "--out names the report" in r.stderr
    assert report.read_bytes() == before


def test_the_check_exit_codes_are_the_ones_its_help_names(tmp_path):
    """F15: the help said 2 for malformed input, while an unreadable receipt or report gives 1. The help now says
    what the command does: 1 for every way a receipt is not ok, 2 for a refused pin or a malformed option."""
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    assert _run("check-test-receipt", str(tmp_path / "absent.json"), "--report", str(report)).returncode == 1
    assert _run("check-test-receipt", "x.json", "--report", str(report), "--max-report-bytes", "x").returncode == 2
    help_text = " ".join(_run("check-test-receipt", "--help").stdout.split())
    assert "1 not ok" in help_text and "2 a refused --expect-issuer pin" in help_text


def test_check_compares_the_suite_version():
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import emit_eval_receipt
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    claim, _ = from_junit_xml(report, timestamp="2026-10-16T00:00:00Z")
    claim["suite_version"] = "ctrf-0.2.0"
    result = verify_test_receipt(emit_eval_receipt(claim, generate_signer()), report)
    assert result["ok"] is False and "ctrf-0.2.0" in result["reason"]


# --- lens run 1, iteration 2: each finding as a case, red at d05061a0 ------------------------------------------------

def _receipt_with_claim(report, change):
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import emit_eval_receipt
    claim, _ = from_junit_xml(report, timestamp="2026-10-16T00:00:00Z")
    change(claim)
    return emit_eval_receipt(claim, generate_signer())


@pytest.mark.parametrize("field,value", [("prereg_sha256", "ab" * 32), ("ci95", ["0.99", "1"]),
                                         ("context_binding", "ci"), ("multiple_testing", "none"),
                                         ("evaluation_card_sha256", "cd" * 32)])
def test_check_refuses_a_claim_field_a_test_receipt_does_not_carry(field, value):
    """N1: such a field is signed and shown by show-eval, but no report can confirm it."""
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    result = verify_test_receipt(_receipt_with_claim(report, lambda c: c.__setitem__(field, value)), report)
    assert result["ok"] is False and field in result["reason"]


def test_check_refuses_an_assurance_level_above_self_attested():
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    result = verify_test_receipt(_receipt_with_claim(report, lambda c: c.__setitem__("assurance_level", "reproduced")),
                                 report)
    assert result["ok"] is False and "self_attested" in result["reason"]


@pytest.mark.parametrize("value,accepted", [(1.0, True), (1e3, True), (-0.0, True), (1.5, False), (True, False),
                                            (float(2 ** 53), False)])
def test_a_ctrf_integer_is_read_as_the_schema_reads_it(value, accepted):
    """N2: JSON Schema draft 7, which CTRF's Appendix A is, takes 1.0 and 1e3 as integers."""
    doc = json.loads((VECTORS / "ctrf/syn_minimal_passed.json").read_text(encoding="utf-8"))
    doc["results"]["tests"][0]["duration"] = value
    doc["results"]["summary"]["start"] = value
    data = json.dumps(doc).encode()
    if accepted:
        assert read_ctrf_json(data).verdict is True
    else:
        with pytest.raises(ReportRefused) as exc:
            read_ctrf_json(data)
        assert exc.value.code == "bad_value"


def test_the_report_is_never_overwritten_through_a_hard_link_or_by_the_key(tmp_path):
    """N3 and N4: --out as a hard link of the report, and --new-key naming the report, overwrote it."""
    report = tmp_path / "report.xml"
    report.write_bytes((VECTORS / "junit/pytest-9.1.1_all_passed.xml").read_bytes())
    before = report.read_bytes()
    os.link(report, tmp_path / "hard.json")
    r = _run("emit-test-receipt", "--junit", str(report), "--out", str(tmp_path / "hard.json"),
             "--new-key", str(tmp_path / "k.key"))
    assert r.returncode == 2 and report.read_bytes() == before
    r = _run("emit-test-receipt", "--junit", str(report), "--out", str(tmp_path / "r.json"), "--new-key", str(report))
    assert r.returncode == 2 and report.read_bytes() == before
    r = _run("emit-test-receipt", "--junit", str(report), "--out", str(tmp_path / "same"), "--new-key",
             str(tmp_path / "same"))
    assert r.returncode == 2 and not (tmp_path / "same").exists()


def test_a_claim_the_emitter_refuses_writes_no_key(tmp_path):
    """N5: a report the reader accepts but whose claim the emitter refuses (a tool name past the verifier's string
    limit) left a new key file behind, against the command's own docstring."""
    doc = json.loads((VECTORS / "ctrf/syn_minimal_passed.json").read_text(encoding="utf-8"))
    doc["results"]["tool"]["name"] = "t" * 1_100_000
    report = tmp_path / "long.json"
    report.write_text(json.dumps(doc), encoding="utf-8")
    key = tmp_path / "k.key"
    r = _run("emit-test-receipt", "--ctrf", str(report), "--out", str(tmp_path / "r.json"), "--new-key", str(key))
    assert r.returncode == 2 and "limit" in r.stderr
    assert not key.exists() and not (tmp_path / "r.json").exists()


def test_a_timestamp_that_is_not_nfc_is_refused_with_its_field():
    """N6: the F6 message class at --timestamp."""
    import unicodedata
    with pytest.raises(ReportRefused) as exc:
        from_junit_xml(VECTORS / "junit/pytest-9.1.1_all_passed.xml",
                       timestamp=unicodedata.normalize("NFD", "2026-10-16T00:00:00Z é"))
    assert exc.value.code == "not_nfc" and "timestamp" in str(exc.value)


def test_check_refuses_a_size_limit_below_one_as_a_malformed_option():
    """N7: --max-report-bytes 0 gave exit 1, the help says 2 for a malformed option."""
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    assert _run("check-test-receipt", "x.json", "--report", str(report), "--max-report-bytes", "0").returncode == 2


@pytest.mark.parametrize("stamp,ok", [("0000-01-01T00:00:00Z", True), ("0000-02-29T00:00:00Z", True),
                                      ("2024-02-29T23:59:60Z", True), ("1900-02-29T00:00:00Z", False),
                                      ("2026-13-01T00:00:00Z", False), ("2026-04-31T00:00:00Z", False),
                                      ("2026-10-16T24:00:00Z", False), ("2026-10-16T10:00:00+24:00", False)])
def test_an_rfc3339_timestamp_is_read_by_its_own_calendar(stamp, ok):
    """N8: the year 0000 is a valid RFC 3339 year, which `datetime` cannot hold."""
    doc = json.loads((VECTORS / "ctrf/syn_minimal_passed.json").read_text(encoding="utf-8"))
    doc["timestamp"] = stamp
    data = json.dumps(doc).encode()
    if ok:
        assert read_ctrf_json(data).verdict is True
    else:
        with pytest.raises(ReportRefused) as exc:
            read_ctrf_json(data)
        assert exc.value.code == "bad_value"


class _ShouldNotBeAsked:
    def __fspath__(self):
        raise RuntimeError("the caller's __fspath__ ran")

    def __str__(self):
        raise RuntimeError("the caller's __str__ ran")


def test_a_report_path_whose_fspath_raises_gets_an_answer_not_an_exception():
    """N9: verify_test_receipt raised RuntimeError out of a never-raise surface."""
    report = VECTORS / "junit/pytest-9.1.1_all_passed.xml"
    result = verify_test_receipt(_receipt_with(report, lambda p: None), _ShouldNotBeAsked())
    assert result["ok"] is False and "path" in result["reason"]
    with pytest.raises(ReportRefused) as exc:
        from_junit_xml(_ShouldNotBeAsked())
    assert exc.value.code == "unreadable"


def test_check_says_that_ok_is_not_a_pass(tmp_path):
    """N11: exit 0 for the receipt of a failing run printed only "=> OK"."""
    report = VECTORS / "junit/pytest-9.1.1_mixed.xml"
    out = tmp_path / "r.json"
    assert _run("emit-test-receipt", "--junit", str(report), "--out", str(out),
                "--new-key", str(tmp_path / "k.key")).returncode == 0
    r = _run("check-test-receipt", str(out), "--report", str(report))
    # The verdict line itself: the reason line above it also holds "passed=False", so a test on the text alone
    # stayed green when the verdict line lost its value (mutant `cli: check does not print the signed verdict`).
    assert r.returncode == 0 and "verdict    passed=False (exit 0 says" in r.stdout


def test_written_files_are_exit_zero_under_a_stdout_that_cannot_encode_the_path(tmp_path):
    """N12: under an ASCII stdout the receipt and the key were written and the command still exited 2."""
    out = tmp_path / "quittung-é.json"
    p = subprocess.run([sys.executable, "-m", "proofbundle.cli", "emit-test-receipt", "--junit",
                        str(VECTORS / "junit/pytest-9.1.1_all_passed.xml"), "--out", str(out),
                        "--new-key", str(tmp_path / "k.key")], capture_output=True, cwd=REPO,
                       env={**os.environ, "PYTHONPATH": str(REPO / "src"), "PYTHONIOENCODING": "ascii"})
    assert p.returncode == 0, p.stderr
    assert out.exists() and b"\\xe9" in p.stdout
