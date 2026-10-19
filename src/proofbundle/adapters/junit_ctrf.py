"""Adapter: a JUnit XML or CTRF JSON test report to a signed eval receipt (file-based, no tool import).

A CI that already writes a JUnit XML report (pytest ``--junitxml``, Maven Surefire, jest-junit) or a
CTRF JSON report gets a receipt in the format this library writes for evaluations (``EVAL_CLAIM.md``),
which ``proofbundle show-eval`` verifies offline, and ``check-test-receipt`` checks against the report.

WHAT IS READ. Five counts: tests, passed, failed, errors and skipped. The verdict is ``VERDICT_RULE``:
no failure, no error, and at least one passed test. A report of skipped tests only, or of no test at
all, is therefore not passed. The claim carries the verdict as ``pass_rate >= 1`` over the tests that
ran (passed, failed and errors), and the counts, the report's SHA-256 and the rule itself in its
``provenance``.

STRICT READING. Both readers refuse rather than guess, and every refusal is a ``ReportRefused`` with a
stable ``code`` and a sentence naming the reason:

* XML with a document type declaration, an entity declaration, an external entity, a parameter entity
  or a processing instruction is refused when the parser meets it; nothing is resolved or fetched.
  Duplicate attributes, a second root element and anything that is not well-formed UTF-8 XML are
  refused by the parser. An element the JUnit XML formats above do not have at that place (a
  ``<testcase>`` inside ``<system-out>``, an unknown outcome inside a ``<testcase>``) is refused, so
  no second reader can count a test this one skipped.
* A count attribute (``tests``, ``failures``, ``errors``, ``skipped``) that is present has to equal
  the elements under it. A report that says two things is refused, neither number wins. Measured on
  real output: jest-junit 17.0.0 writes a ``test.todo`` as a ``<testcase>`` without a child and leaves
  it out of ``tests``, so such a report is refused.
* CTRF JSON is read by the strict helper (``_strict_json.loads_strict``): a duplicate key at any depth,
  a lone surrogate, bytes after the one value, a byte order mark, anything that is not UTF-8 and the
  literals ``NaN`` and ``Infinity`` are refused. Of the CTRF objects, the root, ``results``, ``tool``,
  ``summary`` and every test are checked for fields CTRF does not define outside ``extra``; the
  objects whose contents this adapter does not read (``environment``, ``insights``, ``baseline``, the
  retry attempts, attachments and steps of a test) are not validated here. The summary has to match
  the tests. Only CTRF ``specVersion`` 0.2.x is read, the version ``ctrf.io`` names on 2026-10-16.
* Both readers have a size limit (``REPORT_MAX_BYTES``) and a nesting limit.

CTRF HAS NO ERROR STATUS. ``other`` is an outcome that is neither a pass, a failure nor a skip (jest
writes a ``test.todo`` as ``other``), and it is counted as an error, so it never reads as passed.
``pending`` is counted as skipped. Both counts stand in the provenance beside the mapped ones.

WHAT THE RECEIPT DOES NOT PROVE stands in it (``NON_CLAIMS``): that a report with this digest was
signed by this key says nothing about whether the tests are meaningful, whether the report came from
the real run, or whether it lists every test. Measured on 2026-10-16: a jest test file that failed to
load was missing from both the jest-junit and the CTRF report of the same run.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Optional
from xml.parsers import expat

from .._membership import is_bool, is_member
from .._strict_json import loads_strict
from ..budget import DEFAULT_BUDGET, BudgetExceeded, render_safe
from ..canonical import _ein_stand
from ..errors import BundleFormatError
from ..evalclaim import build_eval_claim
from ._provenance import bind_reported_version

__all__ = [
    "FORMAT_JUNIT", "FORMAT_CTRF", "REPORT_MAX_BYTES", "XML_MAX_DEPTH", "CTRF_SPEC_VERSION", "VERDICT_RULE",
    "NON_CLAIMS", "RECEIPT_PROFILE", "ReportRefused", "ReportCounts", "read_junit_xml", "read_ctrf_json",
    "from_junit_xml", "from_ctrf_json", "verify_test_receipt",
]

FORMAT_JUNIT = "junit-xml"
FORMAT_CTRF = "ctrf"
#: Names the provenance this adapter writes. `verify_test_receipt` rebuilds that provenance from the report and
#: compares all of it, so a receipt of another profile is not read as one of this.
RECEIPT_PROFILE = "proofbundle/test-report-receipt/v1"
REPORT_MAX_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
XML_MAX_DEPTH = 64
JSON_MAX_NODES = 5_000_000
#: The CTRF specification version this reader follows: ctrf-io/ctrf spec/ctrf.md, version 0.2.0 dated
#: 2026-10-10, retrieved 2026-10-16. A report of another MAJOR.MINOR is refused.
CTRF_SPEC_VERSION = "0.2.0"
VERDICT_RULE = "passed = failed == 0 and errors == 0 and passed >= 1"
NON_CLAIMS = (
    "This receipt proves only that a test report with this SHA-256 was signed by this key, and how its counts "
    "read under the verdict rule. It does not prove that the tests are meaningful, that the report came from "
    "the real CI run, or that the report lists every test of the run: a test file that fails to load can be "
    "missing from a report without a trace.")

_UTF8_BOM = b"\xef\xbb\xbf"


class ReportRefused(ValueError):
    """A report this adapter does not read. ``code`` is stable (the vectors in
    ``tests/fixtures/test_reports/vectors.json`` name it), the message names the reason."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"report refused ({code}): {reason}")
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class ReportCounts:
    """The five counts of a report, plus what the receipt records about where they came from.

    ``tests == passed + failed + errors + skipped``. For CTRF, ``other`` (counted in ``errors``) and
    ``pending`` (counted in ``skipped``) are kept as read."""
    fmt: str
    tests: int
    passed: int
    failed: int
    errors: int
    skipped: int
    name: Optional[str]
    tool_version: Optional[str]
    spec_version: Optional[str]
    other: int = 0
    pending: int = 0

    @property
    def executed(self) -> int:
        """The tests that ran to an outcome: the denominator of the pass rate."""
        return self.passed + self.failed + self.errors

    @property
    def verdict(self) -> bool:
        """``VERDICT_RULE``."""
        return self.failed == 0 and self.errors == 0 and self.passed >= 1


def _the_bytes(data: Any) -> bytes:
    from ..signature import plain_bytes  # noqa: PLC0415
    raw = plain_bytes(data)
    if raw is None:
        raise TypeError(f"a report is read as bytes, got {type(data).__name__}")
    return raw


def _check_limit(max_bytes: Any) -> int:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError(f"max_bytes must be a positive int, got {render_safe(max_bytes)}")
    return max_bytes


def _refuse_size(raw: bytes, max_bytes: int) -> None:
    if len(raw) > max_bytes:
        raise ReportRefused("too_large", f"the report has {len(raw)} bytes, more than the limit of {max_bytes}")


def _refuse_nul(raw: bytes) -> None:
    """Neither XML nor JSON text holds a NUL character, and UTF-8 encodes one only as the byte 0. UTF-16 and UTF-32
    text without a byte order mark is full of zero bytes and decodes as valid UTF-8, so this is where the UTF-8
    promise holds for such a file: measured, expat read a UTF-16-LE report without a mark and counted it."""
    if b"\x00" in raw:
        raise ReportRefused("encoding", f"the report holds a NUL byte (at {raw.index(0)}), which UTF-8 XML and JSON "
                                        "text cannot hold; a UTF-16 or UTF-32 file without a byte order mark looks "
                                        "like this")


def _read_file(path: Any, max_bytes: int) -> bytes:
    """The report's bytes, read once. The file is opened without blocking and judged by the descriptor it
    opened, so a path swapped for a FIFO or a device between a check and the open is refused, not read."""
    # The path is read ONCE as the plain text or bytes it names: `os.open` would call the caller's own `__fspath__`, and
    # a never-raise check runs no code of the caller's that can raise out of it (lens run 1, iteration 2, N9).
    try:
        pfad = os.fspath(path)
    except Exception as exc:  # noqa: BLE001 - whatever the caller's __fspath__ raises, the answer is a refusal
        raise ReportRefused("unreadable", f"the report path cannot be read as a path ({type(exc).__name__})") from None
    if type(pfad) is not str and type(pfad) is not bytes:
        raise ReportRefused("unreadable", f"the report path must be text or bytes, got {type(pfad).__name__}")
    try:
        fd = os.open(pfad, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except (OSError, TypeError, ValueError) as exc:
        raise ReportRefused("unreadable", f"cannot open the report {render_safe(pfad)}: {exc}") from exc
    try:
        # The descriptor is judged before a file object is made of it: `os.fdopen` itself refuses a
        # directory with a raw IsADirectoryError.
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
        if regular:
            handle = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    if not regular:
        os.close(fd)
        raise ReportRefused("not_a_file", f"{render_safe(pfad)} is not a regular file")
    # Read in pieces, never more than the limit plus one byte: a single read of `max_bytes + 1` allocates that much
    # up front, and a large limit then ends in MemoryError or OverflowError instead of a reading.
    stuecke: list = []
    gelesen = 0
    try:
        with handle:
            while True:
                stueck = handle.read(min(_READ_CHUNK, max_bytes + 1 - gelesen))
                if not stueck:
                    break
                stuecke.append(stueck)
                gelesen += len(stueck)
                if gelesen > max_bytes:
                    raise ReportRefused("too_large", f"the report has more than the limit of {max_bytes} bytes")
    except OSError as exc:
        raise ReportRefused("unreadable", f"cannot read the report {render_safe(pfad)}: {exc}") from exc
    return b"".join(stuecke)


# ── JUnit XML ────────────────────────────────────────────────────────────────────────────────────────────

_FLAKY = frozenset({"flakyFailure", "flakyError"})
_RERUN = frozenset({"rerunFailure", "rerunError"})
#: Where each element of the JUnit XML formats this adapter reads may stand; None is the root. pytest,
#: jest-junit and Surefire 3.0.2 (surefire-test-report.xsd) write nothing outside this table.
_PARENTS = {
    "testsuites": frozenset({None}),
    "testsuite": frozenset({None, "testsuites", "testsuite"}),
    "testcase": frozenset({"testsuite"}),
    "properties": frozenset({"testsuites", "testsuite", "testcase"}),
    "property": frozenset({"properties"}),
    "failure": frozenset({"testcase"}),
    "error": frozenset({"testcase"}),
    "skipped": frozenset({"testcase"}),
    "flakyFailure": frozenset({"testcase"}),
    "flakyError": frozenset({"testcase"}),
    "rerunFailure": frozenset({"testcase"}),
    "rerunError": frozenset({"testcase"}),
    "stackTrace": _FLAKY | _RERUN,
    "system-out": frozenset({"testsuite", "testcase"}) | _FLAKY | _RERUN,
    "system-err": frozenset({"testsuite", "testcase"}) | _FLAKY | _RERUN,
}
#: A suite's count attribute and the element it counts. pytest counts elements (a setup error and a
#: teardown error of one test are two <error>), Surefire and jest-junit write at most one of each per
#: testcase, so for them elements and testcases are the same number.
_COUNT_ATTRIBUTES = (("tests", "testcase"), ("failures", "failure"), ("errors", "error"), ("skipped", "skipped"))
_COUNT_TEXT = re.compile(r"\A[0-9]{1,15}\Z")
_SUITES = frozenset({"testsuites", "testsuite"})
#: The outcome of one testcase, in the order of precedence the reader decides by is not this order.
_OUTCOMES = ("pass", "failure", "error", "skipped")


class _Frame:
    __slots__ = ("tag", "name", "declared", "counted")

    def __init__(self, tag: str, name: Optional[str] = None) -> None:
        self.tag = tag
        self.name = name
        self.declared: dict = {}
        self.counted = {"testcase": 0, "failure": 0, "error": 0, "skipped": 0, "flaky": 0, "rerun": 0}


class _JunitReading:
    def __init__(self) -> None:
        self.stack: list = []
        self.root_name: Optional[str] = None
        self.outcomes = dict.fromkeys(_OUTCOMES, 0)

    def xml_declaration(self, version: Any, encoding: Any, standalone: Any) -> None:
        if encoding is not None and encoding.lower() != "utf-8":
            raise ReportRefused("encoding", f"the XML declaration names the encoding {render_safe(encoding)}; "
                                            "only UTF-8 is read")

    def start(self, tag: str, attributes: dict) -> None:
        parent = self.stack[-1].tag if self.stack else None
        if len(self.stack) >= XML_MAX_DEPTH:
            raise ReportRefused("too_deep", f"the elements nest deeper than {XML_MAX_DEPTH} levels")
        allowed = _PARENTS.get(tag)
        if allowed is None or not is_member(parent, allowed):
            where = f"inside <{render_safe(parent, quote=False)}>" if parent else "as the root element"
            raise ReportRefused("structure", f"element <{render_safe(tag, quote=False)}> {where} is not part of "
                                             "the JUnit XML this adapter reads")
        frame = _Frame(tag, attributes.get("name") or None)
        if is_member(tag, _SUITES):
            frame.declared = _declared_counts(tag, attributes)
            if parent is None:
                self.root_name = frame.name
        elif tag in ("failure", "error", "skipped"):
            self.stack[-1].counted[tag] += 1
        elif is_member(tag, _FLAKY):
            self.stack[-1].counted["flaky"] += 1
        elif is_member(tag, _RERUN):
            self.stack[-1].counted["rerun"] += 1
        self.stack.append(frame)

    def end(self, tag: str) -> None:
        frame = self.stack.pop()
        if tag == "testcase":
            self._end_testcase(frame)
        elif is_member(tag, _SUITES):
            self._end_suite(frame)

    def _end_testcase(self, frame: _Frame) -> None:
        c = frame.counted
        final_failure = c["failure"] + c["error"]
        if c["rerun"] and not final_failure:
            raise ReportRefused("contradiction", f"testcase {render_safe(frame.name)} has a rerun record but no final "
                                                 "failure or error")
        if c["flaky"] and final_failure:
            raise ReportRefused("contradiction", f"testcase {render_safe(frame.name)} is marked flaky, which means it "
                                                 "passed on a rerun, and also has a final failure or error")
        # The precedence decides a testcase holding more than one outcome (pytest writes a teardown error
        # into the testcase of a skipped test): an error, then a failure, then a skip.
        if c["error"]:
            self.outcomes["error"] += 1
        elif c["failure"]:
            self.outcomes["failure"] += 1
        elif c["skipped"]:
            self.outcomes["skipped"] += 1
        else:
            self.outcomes["pass"] += 1
        suite = self.stack[-1].counted
        suite["testcase"] += 1
        for kind in ("failure", "error", "skipped"):
            suite[kind] += c[kind]

    def _end_suite(self, frame: _Frame) -> None:
        for attribute, element in _COUNT_ATTRIBUTES:
            if attribute in frame.declared and frame.declared[attribute] != frame.counted[element]:
                raise ReportRefused(
                    "count_mismatch",
                    f"<{frame.tag}>{' ' + render_safe(frame.name) if frame.name else ''} says "
                    f"{attribute}={frame.declared[attribute]}, but "
                    f"holds {frame.counted[element]} <{element}> element(s); the report contradicts itself")
        if self.stack:
            parent = self.stack[-1].counted
            for element in ("testcase", "failure", "error", "skipped"):
                parent[element] += frame.counted[element]

    def result(self) -> ReportCounts:
        n_pass, n_failure, n_error, n_skipped = (self.outcomes[k] for k in _OUTCOMES)
        return ReportCounts(fmt=FORMAT_JUNIT, tests=n_pass + n_failure + n_error + n_skipped, passed=n_pass,
                            failed=n_failure, errors=n_error, skipped=n_skipped, name=self.root_name,
                            tool_version=None, spec_version=None)


def _declared_counts(tag: str, attributes: dict) -> dict:
    declared = {}
    for attribute, _ in _COUNT_ATTRIBUTES:
        if attribute in attributes:
            text = attributes[attribute]
            if not _COUNT_TEXT.match(text):
                raise ReportRefused("bad_count", f"<{tag}> has {attribute}={render_safe(text)}, which is not a "
                                                 "non-negative integer")
            declared[attribute] = int(text)
    return declared


def _refuse_doctype(*_: Any) -> None:
    raise ReportRefused("doctype", "the report has a document type declaration; DTDs, entity declarations and "
                                   "external references are not read")


def _refuse_external_entity(context: str, base: Optional[str], system_id: Optional[str],
                            public_id: Optional[str]) -> int:
    # Unreachable while the document type declaration is refused: an external entity needs one. Kept so that
    # no reference is ever resolved or skipped in silence should that refusal be removed.
    raise ReportRefused("external_reference", "the report references an external entity; it is not read")


def _refuse_processing_instruction(target: str, _data: str) -> None:
    raise ReportRefused("processing_instruction",
                        f"the report has the processing instruction <?{render_safe(target, quote=False)} ...?>; "
                        "processing instructions can reference outside resources and are not read")


_EXPAT_CODES = {
    expat.errors.codes[expat.errors.XML_ERROR_DUPLICATE_ATTRIBUTE]: "duplicate_attribute",
    expat.errors.codes[expat.errors.XML_ERROR_UNDEFINED_ENTITY]: "entity",
    expat.errors.codes[expat.errors.XML_ERROR_JUNK_AFTER_DOC_ELEMENT]: "trailing_content",
    expat.errors.codes[expat.errors.XML_ERROR_INCORRECT_ENCODING]: "encoding",
    expat.errors.codes[expat.errors.XML_ERROR_UNKNOWN_ENCODING]: "encoding",
}


@_ein_stand
def read_junit_xml(data: bytes, *, max_bytes: int = REPORT_MAX_BYTES) -> ReportCounts:
    """The counts of a JUnit XML report given as bytes, or ``ReportRefused`` naming why it is not read."""
    raw = _the_bytes(data)
    _refuse_size(raw, _check_limit(max_bytes))
    try:
        (raw[len(_UTF8_BOM):] if raw.startswith(_UTF8_BOM) else raw).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportRefused("encoding", f"the report is not UTF-8 (byte {exc.start})") from None
    _refuse_nul(raw)
    reading = _JunitReading()
    # With namespace processing the parser itself refuses an unbound prefix and two attributes that name the same
    # expanded name; a namespaced element reaches the structure check as "uri name" and is refused there.
    parser = expat.ParserCreate("UTF-8", " ")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.XmlDeclHandler = reading.xml_declaration
    parser.StartDoctypeDeclHandler = _refuse_doctype
    parser.ExternalEntityRefHandler = _refuse_external_entity
    parser.ProcessingInstructionHandler = _refuse_processing_instruction
    parser.StartElementHandler = reading.start
    parser.EndElementHandler = reading.end
    try:
        parser.Parse(raw, True)
    except expat.ExpatError as exc:
        code = _EXPAT_CODES.get(exc.code, "malformed")
        raise ReportRefused(code, f"not well-formed XML at line {exc.lineno}, column {exc.offset}: "
                                  f"{expat.ErrorString(exc.code)}") from None
    return reading.result()


# ── CTRF JSON ────────────────────────────────────────────────────────────────────────────────────────────

# The fields CTRF 0.2.0 defines for the five objects this adapter reads (spec/ctrf.md sections 5 to 9, Appendix A),
# each with the kind of value the schema and the prose require. A POSITIVE LIST: a field not named here must sit
# inside an `extra` object, and a named field of another kind is refused. The objects named only as `obj` or `arr_obj`
# (environment, insights, baseline, labels' values aside, retry attempts, attachments, steps) are not read further.
_CTRF_ROOT = {"reportFormat": "ctrf", "specVersion": "semver", "reportId": "uuid", "runId": "str1",
              "timestamp": "datetime", "generatedBy": "str", "results": "obj", "insights": "obj", "baseline": "obj",
              "extra": "obj"}
_CTRF_RESULTS = {"tool": "obj", "summary": "obj", "tests": "arr_obj", "environment": "obj", "extra": "obj"}
_CTRF_TOOL = {"name": "str1", "version": "str", "extra": "obj"}
_CTRF_SUMMARY = {"tests": "uint", "passed": "uint", "failed": "uint", "pending": "uint", "skipped": "uint",
                 "other": "uint", "flaky": "uint", "suites": "uint", "start": "int", "stop": "int", "duration": "int",
                 "extra": "obj"}
_CTRF_TEST = {"id": "uuid", "testId": "str1", "executionId": "str1", "attemptId": "str1", "name": "str1",
              "status": "status", "duration": "int", "start": "int", "stop": "int", "suite": "arr_str1",
              "message": "str", "trace": "str", "snippet": "str", "ai": "str", "line": "int", "rawStatus": "str",
              "tags": "arr_str", "labels": "labels", "type": "str", "filePath": "str", "retries": "uint",
              "retryAttempts": "arr_obj1", "flaky": "bool", "stdout": "arr_str", "stderr": "arr_str",
              "threadId": "str", "browser": "str", "device": "str", "screenshot": "str", "attachments": "arr_obj",
              "parameters": "obj", "steps": "arr_obj", "insights": "obj", "extra": "obj"}
_CTRF_REQUIRED = {"the document": ("reportFormat", "specVersion", "results"),
                  "results": ("tool", "summary", "tests"),
                  "results.tool": ("name",),
                  "results.summary": ("tests", "passed", "failed", "pending", "skipped", "other", "start", "stop"),
                  "test": ("name", "status", "duration")}
_CTRF_STATUSES = ("passed", "failed", "skipped", "pending", "other")
_CTRF_SUMMARY_COUNTS = ("tests", "passed", "failed", "pending", "skipped", "other")
# SemVer 2.0.0 core without leading zeros, each part at most nine digits: a longer one is no version this reader
# needs, and it never reaches int() (more than 4300 digits raised a bare ValueError there).
_SEMVER = re.compile(r"\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
_SUPPORTED = tuple(int(x) for x in CTRF_SPEC_VERSION.split(".")[:2])
_MAX_COUNT = 2 ** 53 - 1
_UUID = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_RFC3339 = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?"
                      r"([Zz]|[+-]([0-9]{2}):([0-9]{2}))\Z")


_TAGE_IM_MONAT = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_rfc3339(text: str) -> bool:
    m = _RFC3339.match(text)
    if m is None:
        return False
    jahr, monat, tag, stunde, minute, sekunde = (int(m.group(i)) for i in range(1, 7))
    # The calendar by hand: RFC 3339 allows the year 0000, which `datetime` cannot hold (lens iteration 2, N8).
    if not 1 <= monat <= 12:
        return False
    schaltjahr = jahr % 4 == 0 and (jahr % 100 != 0 or jahr % 400 == 0)
    if not 1 <= tag <= (29 if monat == 2 and schaltjahr else _TAGE_IM_MONAT[monat - 1]):
        return False
    versatz_ok = m.group(9) is None or (int(m.group(9)) <= 23 and int(m.group(10)) <= 59)
    return stunde <= 23 and minute <= 59 and sekunde <= 60 and versatz_ok


def _is_label_value(value: Any) -> bool:
    def primitiv(v: Any) -> bool:
        return type(v) in (str, bool, int, float)
    if type(value) is list:
        return bool(value) and all(primitiv(v) for v in value)
    return primitiv(value)


def _integral(value: Any, lowest: int) -> bool:
    """A JSON integer as the CTRF schema (JSON Schema draft 7) reads one: an int, or a number with no fractional part
    such as 1.0 or 1e3, within 2**53-1. A bool is no integer (lens iteration 2, N2)."""
    if type(value) is int:
        return lowest <= value <= _MAX_COUNT
    return type(value) is float and value.is_integer() and lowest <= value <= _MAX_COUNT


def _kind_ok(kind: str, value: Any) -> bool:
    if kind == "str":
        return type(value) is str
    if kind == "str1":
        return type(value) is str and bool(value)
    if kind == "int":
        return _integral(value, -_MAX_COUNT)
    if kind == "uint":
        return _integral(value, 0)
    if kind == "bool":
        return type(value) is bool
    if kind == "obj":
        return type(value) is dict
    if kind == "arr_obj":
        return type(value) is list and all(type(v) is dict for v in value)
    if kind == "arr_obj1":
        return type(value) is list and bool(value) and all(type(v) is dict for v in value)
    if kind == "arr_str":
        return type(value) is list and all(type(v) is str for v in value)
    if kind == "arr_str1":
        return type(value) is list and bool(value) and all(type(v) is str for v in value)
    if kind == "uuid":
        return type(value) is str and _UUID.match(value) is not None
    if kind == "datetime":
        return type(value) is str and _is_rfc3339(value)
    if kind == "labels":
        return type(value) is dict and all(_is_label_value(v) for v in value.values())
    if kind == "status":
        return type(value) is str and is_member(value, _CTRF_STATUSES)
    raise AssertionError(f"unknown field kind {kind}")


_KIND_TEXT = {"str": "a string", "str1": "a non-empty string", "int": "an integer of magnitude at most 2**53-1",
              "uint": "a non-negative integer of at most 2**53-1", "bool": "a boolean", "obj": "an object",
              "arr_obj": "an array of objects", "arr_obj1": "a non-empty array of objects",
              "arr_str": "an array of strings", "arr_str1": "a non-empty array of strings",
              "uuid": "a UUID (RFC 4122)", "datetime": "an RFC 3339 date-time",
              "labels": "an object of strings, numbers, booleans or non-empty arrays of those",
              "status": f"one of {list(_CTRF_STATUSES)}"}


def _check_fields(obj: dict, fields: dict, where: str, required_key: str) -> None:
    """Every field of `obj` named in `fields` and of its kind, every required one present. The two fields with a
    reason code of their own (`reportFormat`, `specVersion`) are judged by the caller first."""
    for key in obj:
        if type(key) is not str or not is_member(key, fields):
            raise ReportRefused("unknown_field", f"{where} has the field {render_safe(key)}, which CTRF does not "
                                                 "define outside an extra object")
    for key in _CTRF_REQUIRED[required_key]:
        if key not in obj:
            raise ReportRefused("missing_field", f"{where} has no {key}, which CTRF requires")
    for key, value in obj.items():
        kind = fields[key]
        if kind in ("ctrf", "semver"):
            continue
        if not _kind_ok(kind, value):
            raise ReportRefused("bad_value", f"{where}.{key} must be {_KIND_TEXT[kind]}, got {render_safe(value)}")


def _check_retries(test: dict, where: str) -> None:
    """Section 9.20: retryAttempts present means retries present and equal to its length; retries above 0 needs
    retryAttempts, retries 0 forbids them."""
    if "retryAttempts" in test and test.get("retries") != len(test["retryAttempts"]):
        raise ReportRefused("contradiction", f"{where}.retries must be present and equal the "
                                             f"{len(test['retryAttempts'])} entries of retryAttempts")
    if test.get("retries", 0) > 0 and "retryAttempts" not in test:
        raise ReportRefused("contradiction", f"{where}.retries is {test['retries']} but there is no retryAttempts")


def _refuse_non_finite(doc: Any) -> None:
    """RFC 8259 has no NaN and no Infinity; Python's parser accepts both, and turns 1e999 into infinity."""
    stack = [doc]
    while stack:
        value = stack.pop()
        if type(value) is float and not math.isfinite(value):
            raise ReportRefused("malformed", "the report holds NaN or Infinity, which is not JSON (RFC 8259 "
                                             "section 6)")
        if type(value) is dict:
            stack.extend(value.values())
        elif type(value) is list:
            stack.extend(value)


def _parse_ctrf(raw: bytes, max_bytes: int) -> Any:
    if raw.startswith(_UTF8_BOM):
        raise ReportRefused("encoding", "the report starts with a byte order mark; CTRF requires UTF-8 without "
                                        "one (section 4.1)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportRefused("encoding", f"the report is not UTF-8 (byte {exc.start})") from None
    _refuse_nul(raw)
    budget = replace(DEFAULT_BUDGET, input_bytes=max_bytes, json_nodes=JSON_MAX_NODES, string_len=max_bytes)
    try:
        doc = loads_strict(text, budget=budget)
    except BudgetExceeded as exc:
        raise ReportRefused("too_large", f"the report exceeds the {exc.dimension} limit of {exc.limit}") from None
    except BundleFormatError as exc:
        message = str(exc)
        if message.startswith("duplicate JSON key"):
            raise ReportRefused("duplicate_key", message) from None
        if "nesting is too deep" in message:
            raise ReportRefused("too_deep", message) from None
        raise ReportRefused("malformed", message) from None
    except ValueError as exc:   # json.JSONDecodeError
        if getattr(exc, "msg", None) == "Extra data":
            raise ReportRefused("trailing_content", f"the report has bytes after its JSON value ({exc})") from None
        raise ReportRefused("malformed", f"the report is not JSON ({exc})") from None
    _refuse_non_finite(doc)
    return doc


@_ein_stand
def read_ctrf_json(data: bytes, *, max_bytes: int = REPORT_MAX_BYTES) -> ReportCounts:
    """The counts of a CTRF JSON report given as bytes, or ``ReportRefused`` naming why it is not read."""
    raw = _the_bytes(data)
    _refuse_size(raw, _check_limit(max_bytes))
    doc = _parse_ctrf(raw, max_bytes)
    if type(doc) is not dict:
        raise ReportRefused("not_ctrf", "a CTRF document is one JSON object")
    if doc.get("reportFormat") != "CTRF":
        raise ReportRefused("not_ctrf", f"reportFormat must be \"CTRF\", got {render_safe(doc.get('reportFormat'))}")
    version = doc.get("specVersion")
    match = _SEMVER.match(version) if type(version) is str else None
    if match is None or (int(match.group(1)), int(match.group(2))) != _SUPPORTED:
        raise ReportRefused("unsupported_version", f"specVersion {render_safe(version)} is not read; this adapter "
                                                   f"reads CTRF {_SUPPORTED[0]}.{_SUPPORTED[1]}.x")
    _check_fields(doc, _CTRF_ROOT, "the document", "the document")
    results = doc["results"]
    _check_fields(results, _CTRF_RESULTS, "results", "results")
    tool = results["tool"]
    _check_fields(tool, _CTRF_TOOL, "results.tool", "results.tool")
    summary = results["summary"]
    _check_fields(summary, _CTRF_SUMMARY, "results.summary", "results.summary")
    tests = results["tests"]
    by_status = dict.fromkeys(_CTRF_STATUSES, 0)
    for i, test in enumerate(tests):
        where = f"results.tests[{i}]"
        _check_fields(test, _CTRF_TEST, where, "test")
        _check_retries(test, where)
        by_status[test["status"]] += 1
    counted = {"tests": len(tests), **by_status}
    for k in _CTRF_SUMMARY_COUNTS:
        if summary[k] != counted[k]:
            raise ReportRefused("count_mismatch", f"results.summary.{k} is {summary[k]}, but the tests array holds "
                                                  f"{counted[k]}; the report contradicts itself")
    n_pass, n_failed, n_skipped, n_pending, n_other = (by_status[s] for s in _CTRF_STATUSES)
    return ReportCounts(fmt=FORMAT_CTRF, tests=len(tests), passed=n_pass, failed=n_failed, errors=n_other,
                        skipped=n_skipped + n_pending, name=tool["name"], tool_version=tool.get("version"),
                        spec_version=version, other=n_other, pending=n_pending)


# ── the claim ────────────────────────────────────────────────────────────────────────────────────────────

_COMMIT = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _pass_rate_floor(passed: int, executed: int) -> str:
    """The pass rate rounded DOWN to six places, as a decimal string. Rounded down, a rate just below one
    (1 999 999 of 2 000 000) stays below the threshold 1, so the score never decides the verdict the
    counts did not give."""
    if executed == 0:
        return "0"
    if passed == executed:
        return "1"
    six = passed * 1_000_000 // executed
    return ("0." + str(six).rjust(6, "0")).rstrip("0").rstrip(".")


def _require_nfc(text: Optional[str], where: str) -> None:
    """The eval claim signs NFC text only (EVAL_CLAIM.md section 4). A report string that is not NFC is refused here,
    with the field that holds it, rather than by the canonicalizer with a message that names none."""
    if text is not None and unicodedata.normalize("NFC", text) != text:
        raise ReportRefused("not_nfc", f"{where} is not NFC-normalized text, and the eval claim signs NFC text only")


def _provenance(counts: ReportCounts, digest_hex: str, commit: Optional[str]) -> dict:
    """THE ONE PROVENANCE of a test receipt. The producer signs what this returns and `verify_test_receipt` compares
    the signed provenance with what this returns for the report, all of it, so the check cannot cover less than the
    producer writes."""
    if commit is not None and (type(commit) is not str or not _COMMIT.match(commit)):
        raise ValueError("commit must be a full git object name: 40 or 64 lowercase hex characters, got "
                         f"{render_safe(commit)}")
    executed = counts.executed
    provenance: dict = {
        "receipt_profile": RECEIPT_PROFILE,
        "harness": counts.fmt, "report_format": counts.fmt, "report_sha256": digest_hex,
        "tests_total": counts.tests, "tests_passed": counts.passed, "tests_failed": counts.failed,
        "tests_errors": counts.errors, "tests_skipped": counts.skipped,
        "verdict_rule": VERDICT_RULE, "non_claims": NON_CLAIMS,
    }
    if executed:
        provenance["pass_rate_floor"] = _pass_rate_floor(counts.passed, executed)
    if commit is not None:
        provenance["commit"] = commit
    if counts.fmt == FORMAT_CTRF:
        provenance["ctrf_spec_version"] = counts.spec_version
        provenance["ctrf_tool_name"] = counts.name
        provenance["ctrf_status_other_counted_as_errors"] = counts.other
        provenance["ctrf_status_pending_counted_as_skipped"] = counts.pending
        bind_reported_version(provenance, "harness_version", counts.tool_version,
                              reason="the CTRF report carried no results.tool.version")
    else:
        bind_reported_version(provenance, "harness_version", None, bound=False,
                              reason="JUnit XML has no field for the version of the tool that wrote it")
    return provenance


def _suite_version(counts: ReportCounts) -> str:
    return FORMAT_JUNIT if counts.fmt == FORMAT_JUNIT else f"ctrf-{counts.spec_version}"


def _claim_from_counts(counts: ReportCounts, digest_hex: str, *, commit: Optional[str], suite: Optional[str],
                       timestamp: Optional[str], model_salt: Optional[bytes], dataset_salt: Optional[bytes]):
    provenance = _provenance(counts, digest_hex, commit)
    if suite is not None:
        if type(suite) is not str or not suite:
            raise ValueError(f"suite must be a non-empty string, got {render_safe(suite)}")
        _require_nfc(suite, "the suite argument")
    elif counts.fmt == FORMAT_JUNIT:
        _require_nfc(counts.name, "the name attribute of the report's root element (pass suite= to name the suite)")
    if counts.fmt == FORMAT_CTRF:
        _require_nfc(counts.name, "results.tool.name")
        _require_nfc(counts.tool_version, "results.tool.version")
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    elif type(timestamp) is not str or not timestamp:
        raise ValueError(f"timestamp must be a non-empty string, got {render_safe(timestamp)}")
    else:
        _require_nfc(timestamp, "the timestamp argument")
    executed = counts.executed
    claim, salts = build_eval_claim(
        suite=suite if suite is not None else (counts.name or counts.fmt), suite_version=_suite_version(counts),
        metric="pass_rate", comparator=">=", threshold="1", score=_pass_rate_floor(counts.passed, executed),
        n=executed, model_id=f"git:{commit}" if commit is not None else "git:not-given",
        dataset_id=f"sha256:{digest_hex}", issuer="", timestamp=timestamp, provenance=provenance,
        model_salt=model_salt, dataset_salt=dataset_salt)
    if claim["passed"] is not counts.verdict:
        # The builder computes `passed` from the score; the receipt signs only the counts' verdict.
        raise ReportRefused("verdict_mismatch", f"the claim's verdict {claim['passed']!r} is not the verdict of the "
                                                "counts; no receipt is built")
    return claim, salts


@_ein_stand(aussen={"path": "pfad"})
def from_junit_xml(path, *, commit: Optional[str] = None, suite: Optional[str] = None,
                   timestamp: Optional[str] = None, max_bytes: int = REPORT_MAX_BYTES,
                   model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Read a JUnit XML report and build an eval claim over it. Returns ``(claim, salts)`` for
    ``emit_eval_receipt``. ``commit`` is the full git object name the report is about, optional."""
    raw = _read_file(path, _check_limit(max_bytes))
    counts = read_junit_xml(raw, max_bytes=max_bytes)
    return _claim_from_counts(counts, hashlib.sha256(raw).hexdigest(), commit=commit, suite=suite,
                              timestamp=timestamp, model_salt=model_salt, dataset_salt=dataset_salt)


@_ein_stand(aussen={"path": "pfad"})
def from_ctrf_json(path, *, commit: Optional[str] = None, suite: Optional[str] = None,
                   timestamp: Optional[str] = None, max_bytes: int = REPORT_MAX_BYTES,
                   model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Read a CTRF JSON report and build an eval claim over it. Returns ``(claim, salts)``."""
    raw = _read_file(path, _check_limit(max_bytes))
    counts = read_ctrf_json(raw, max_bytes=max_bytes)
    return _claim_from_counts(counts, hashlib.sha256(raw).hexdigest(), commit=commit, suite=suite,
                              timestamp=timestamp, model_salt=model_salt, dataset_salt=dataset_salt)


_READERS = {FORMAT_JUNIT: read_junit_xml, FORMAT_CTRF: read_ctrf_json}
#: The claim fields a test receipt carries, exactly: what `build_eval_claim` writes for `_claim_from_counts` and
#: `emit_eval_receipt` adds. A field beyond these (ci95, prereg_sha256, samples, context_binding, ...) is signed but
#: never compared with the report, so a receipt that carries one is not a test receipt (lens iteration 2, N1).
_CLAIM_KEYS = frozenset({"schema", "suite", "suite_version", "metric", "comparator", "threshold", "passed", "n",
                         "model_id_commit", "dataset_id_commit", "commit_alg", "issuer", "timestamp",
                         "assurance_level", "provenance"})


def _as_json(value: Any) -> str:
    """One text per JSON value, by type: `true` and `1`, `1` and `1.0` are different texts, as they are different
    values in a signed claim."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _provenance_difference(signed: dict, expected: dict) -> Optional[str]:
    for key in sorted(set(signed) | set(expected), key=str):
        if key not in expected:
            return f"the receipt signs provenance.{render_safe(key, quote=False)}, which a test receipt does not carry"
        if key not in signed:
            return f"the receipt lacks provenance.{key}, which the report gives as {render_safe(expected[key])}"
        if _as_json(signed[key]) != _as_json(expected[key]):
            return (f"the receipt signs provenance.{key}={render_safe(signed[key])}, the report gives "
                    f"{render_safe(expected[key])}")
    return None


@_ein_stand(aussen={"report": "pfad"})
def verify_test_receipt(bundle, report, *, expected_issuers: Optional[list] = None,
                        max_bytes: int = REPORT_MAX_BYTES) -> dict:
    """Check a test receipt against the report it names, offline.

    Verifies the receipt (`decode_eval_claim`: signature, Merkle inclusion, issuer binding) and the pinned issuers,
    each pin judged by the trust-anchor rule `show-eval --expect-issuer` applies; then that the report's SHA-256 is the
    signed ``report_sha256``; then reads the report again with this adapter, rebuilds the provenance a receipt of
    ``RECEIPT_PROFILE`` carries for it (`_provenance`) and compares ALL of it, field by field and by type, and the
    claim's suite version, metric, comparator, threshold, ``n`` and verdict. A claim field a test receipt does not carry
    is refused, and the assurance level must be ``self_attested``. Not checked, because the report does not give them:
    the suite name, the timestamp and the two salted commitments.

    ``ok`` True says the receipt is about this report. It does not say that the run passed: that is the signed
    ``passed`` in the returned claim.

    Returns ``{"ok", "reason", "claim"}``; ``claim`` is None when the receipt itself does not verify. Never raises for
    a malformed receipt, report or pin."""
    from ..evalclaim import _issuer_key_weakness, decode_eval_claim  # noqa: PLC0415
    claim = decode_eval_claim(bundle)
    if claim is None:
        return {"ok": False, "reason": "not a valid, issuer-bound eval receipt", "claim": None}
    if expected_issuers is not None:
        if type(expected_issuers) not in (list, tuple) or not all(type(p) is str for p in expected_issuers):
            return {"ok": False, "reason": "expected_issuers must be a list of issuer strings", "claim": claim}
        for pin in expected_issuers:
            schwaeche = _issuer_key_weakness(pin)
            if schwaeche is not None:
                return {"ok": False, "reason": f"the pin {render_safe(pin)} names a {schwaeche} Ed25519 key, which is "
                                               "refused as a trusted key", "claim": claim}
        if claim["issuer"] not in expected_issuers:
            return {"ok": False, "reason": f"the receipt is signed by {claim['issuer']}, not by a pinned issuer",
                    "claim": claim}
    fremd = sorted(k for k in claim if not is_member(k, _CLAIM_KEYS))
    if fremd:
        return {"ok": False, "reason": f"the receipt signs claim fields a test receipt does not carry and the check "
                                       f"cannot compare with a report: {render_safe(fremd)}", "claim": claim}
    if claim.get("assurance_level") != "self_attested":
        return {"ok": False, "reason": f"the receipt signs the assurance level {render_safe(claim.get('assurance_level'))}"
                                       "; a test receipt is self_attested, and no report can show more", "claim": claim}
    provenance = claim.get("provenance") or {}
    fmt = provenance.get("report_format")
    if (type(fmt) is not str or not is_member(fmt, _READERS)
            or _as_json(provenance.get("receipt_profile")) != _as_json(RECEIPT_PROFILE)):
        return {"ok": False, "reason": "the receipt is not a test-report receipt (no report_format junit-xml or "
                                       f"ctrf of the profile {RECEIPT_PROFILE} in its provenance)", "claim": claim}
    try:
        raw = _read_file(report, _check_limit(max_bytes))
        digest = hashlib.sha256(raw).hexdigest()
        if digest != provenance.get("report_sha256"):
            return {"ok": False, "reason": f"the report's digest {digest} is not the signed report_sha256 "
                                           f"{render_safe(provenance.get('report_sha256'))}", "claim": claim}
        counts = _READERS[fmt](raw, max_bytes=max_bytes)
        expected = _provenance(counts, digest, provenance.get("commit"))
    except (ReportRefused, ValueError) as exc:
        return {"ok": False, "reason": str(exc), "claim": claim}
    unterschied = _provenance_difference(provenance, expected)
    if unterschied is not None:
        return {"ok": False, "reason": unterschied, "claim": claim}
    signed_verdict = claim["passed"]
    if not is_bool(signed_verdict):
        return {"ok": False, "reason": "the receipt's passed is not a boolean", "claim": claim}
    shape = (claim["suite_version"], claim["metric"], claim["comparator"], claim["threshold"], claim["n"],
             signed_verdict)
    if _as_json(list(shape)) != _as_json([_suite_version(counts), "pass_rate", ">=", "1", counts.executed,
                                          counts.verdict]):
        return {"ok": False, "reason": f"the receipt signs {render_safe(list(shape))}, the report gives "
                                       f"{_suite_version(counts)}, pass_rate >= 1 over n={counts.executed} with "
                                       f"passed={counts.verdict}", "claim": claim}
    return {"ok": True, "reason": f"the receipt is about this report: {counts.tests} tests, {counts.passed} passed, "
                                  f"{counts.failed} failed, {counts.errors} errors, {counts.skipped} skipped, "
                                  f"passed={counts.verdict}", "claim": claim}
