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
import math
import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Optional
from xml.parsers import expat

from .._strict_json import loads_strict
from ..budget import DEFAULT_BUDGET, BudgetExceeded, render_safe
from ..canonical import _ein_stand
from ..errors import BundleFormatError
from ..evalclaim import build_eval_claim
from ._provenance import bind_reported_version

__all__ = [
    "FORMAT_JUNIT", "FORMAT_CTRF", "REPORT_MAX_BYTES", "XML_MAX_DEPTH", "CTRF_SPEC_VERSION", "VERDICT_RULE",
    "NON_CLAIMS", "ReportRefused", "ReportCounts", "read_junit_xml", "read_ctrf_json", "from_junit_xml",
    "from_ctrf_json", "verify_test_receipt",
]

FORMAT_JUNIT = "junit-xml"
FORMAT_CTRF = "ctrf"
REPORT_MAX_BYTES = 64 * 1024 * 1024
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


def _read_file(path: Any, max_bytes: int) -> bytes:
    """The report's bytes, read once. The file is opened without blocking and judged by the descriptor it
    opened, so a path swapped for a FIFO or a device between a check and the open is refused, not read."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except (OSError, TypeError, ValueError) as exc:
        raise ReportRefused("unreadable", f"cannot open the report {render_safe(str(path))}: {exc}") from exc
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
        raise ReportRefused("not_a_file", f"{render_safe(str(path))} is not a regular file")
    try:
        with handle:
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ReportRefused("unreadable", f"cannot read the report {render_safe(str(path))}: {exc}") from exc
    _refuse_size(raw, max_bytes)
    return raw


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
        self.outcomes = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}

    def xml_declaration(self, version: Any, encoding: Any, standalone: Any) -> None:
        if encoding is not None and encoding.lower() != "utf-8":
            raise ReportRefused("encoding", f"the XML declaration names the encoding {render_safe(encoding)}; "
                                            "only UTF-8 is read")

    def start(self, tag: str, attributes: dict) -> None:
        parent = self.stack[-1].tag if self.stack else None
        if len(self.stack) >= XML_MAX_DEPTH:
            raise ReportRefused("too_deep", f"the elements nest deeper than {XML_MAX_DEPTH} levels")
        allowed = _PARENTS.get(tag)
        if allowed is None or parent not in allowed:
            where = f"inside <{render_safe(parent, quote=False)}>" if parent else "as the root element"
            raise ReportRefused("structure", f"element <{render_safe(tag, quote=False)}> {where} is not part of "
                                             "the JUnit XML this adapter reads")
        frame = _Frame(tag, attributes.get("name") or None)
        if tag in _SUITES:
            frame.declared = _declared_counts(tag, attributes)
            if parent is None:
                self.root_name = frame.name
        elif tag in ("failure", "error", "skipped"):
            self.stack[-1].counted[tag] += 1
        elif tag in _FLAKY:
            self.stack[-1].counted["flaky"] += 1
        elif tag in _RERUN:
            self.stack[-1].counted["rerun"] += 1
        self.stack.append(frame)

    def end(self, tag: str) -> None:
        frame = self.stack.pop()
        if tag == "testcase":
            self._end_testcase(frame)
        elif tag in _SUITES:
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
            self.outcomes["errors"] += 1
        elif c["failure"]:
            self.outcomes["failed"] += 1
        elif c["skipped"]:
            self.outcomes["skipped"] += 1
        else:
            self.outcomes["passed"] += 1
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
        o = self.outcomes
        return ReportCounts(fmt=FORMAT_JUNIT, tests=sum(o.values()), passed=o["passed"], failed=o["failed"],
                            errors=o["errors"], skipped=o["skipped"], name=self.root_name, tool_version=None,
                            spec_version=None)


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


def _refuse_external_entity(*_: Any) -> None:
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
    reading = _JunitReading()
    parser = expat.ParserCreate("UTF-8")
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

# The fields CTRF 0.2.0 defines (spec/ctrf.md, Appendix A); anything else must sit inside an `extra`.
_CTRF_ROOT = frozenset({"reportFormat", "specVersion", "reportId", "runId", "timestamp", "generatedBy", "results",
                        "insights", "baseline", "extra"})
_CTRF_RESULTS = frozenset({"tool", "summary", "tests", "environment", "extra"})
_CTRF_TOOL = frozenset({"name", "version", "extra"})
_CTRF_SUMMARY = frozenset({"tests", "passed", "failed", "pending", "skipped", "other", "flaky", "suites", "start",
                           "stop", "duration", "extra"})
_CTRF_TEST = frozenset({"id", "testId", "executionId", "attemptId", "name", "status", "duration", "start", "stop",
                        "suite", "message", "trace", "snippet", "ai", "line", "rawStatus", "tags", "labels", "type",
                        "filePath", "retries", "retryAttempts", "flaky", "stdout", "stderr", "threadId", "browser",
                        "device", "screenshot", "attachments", "parameters", "steps", "insights", "extra"})
_CTRF_STATUSES = ("passed", "failed", "skipped", "pending", "other")
_CTRF_SUMMARY_COUNTS = ("tests", "passed", "failed", "pending", "skipped", "other")
_SEMVER = re.compile(r"\A([0-9]+)\.([0-9]+)\.([0-9]+)\Z")
_SUPPORTED = tuple(int(x) for x in CTRF_SPEC_VERSION.split(".")[:2])
_MAX_COUNT = 2 ** 53 - 1


def _only_known(obj: dict, known: frozenset, where: str) -> None:
    for key in obj:
        if key not in known:
            raise ReportRefused("unknown_field", f"{where} has the field {render_safe(key)}, which CTRF does not "
                                                 "define outside an extra object")
    if "extra" in obj and type(obj["extra"]) is not dict:
        raise ReportRefused("bad_value", f"{where}.extra must be an object")


def _field(obj: dict, key: str, where: str) -> Any:
    if key not in obj:
        raise ReportRefused("missing_field", f"{where} has no {key}, which CTRF requires")
    return obj[key]


def _object(obj: dict, key: str, where: str) -> dict:
    value = _field(obj, key, where)
    if type(value) is not dict:
        raise ReportRefused("bad_value", f"{where}.{key} must be an object")
    return value


def _integer(value: Any, where: str, *, non_negative: bool) -> int:
    if type(value) is not int or abs(value) > _MAX_COUNT or (non_negative and value < 0):
        kind = "a non-negative integer" if non_negative else "an integer"
        raise ReportRefused("bad_value", f"{where} must be {kind}, got {render_safe(value)}")
    return value


def _text(value: Any, where: str) -> str:
    if type(value) is not str or not value:
        raise ReportRefused("bad_value", f"{where} must be a non-empty string, got {render_safe(value)}")
    return value


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
    _only_known(doc, _CTRF_ROOT, "the document")
    version = _field(doc, "specVersion", "the document")
    match = _SEMVER.match(version) if type(version) is str else None
    if match is None or (int(match.group(1)), int(match.group(2))) != _SUPPORTED:
        raise ReportRefused("unsupported_version", f"specVersion {render_safe(version)} is not read; this adapter "
                                                   f"reads CTRF {_SUPPORTED[0]}.{_SUPPORTED[1]}.x")
    results = _object(doc, "results", "the document")
    _only_known(results, _CTRF_RESULTS, "results")
    tool = _object(results, "tool", "results")
    _only_known(tool, _CTRF_TOOL, "results.tool")
    tool_name = _text(_field(tool, "name", "results.tool"), "results.tool.name")
    tool_version = tool.get("version")
    if tool_version is not None and type(tool_version) is not str:
        raise ReportRefused("bad_value", "results.tool.version must be a string")
    summary = _object(results, "summary", "results")
    _only_known(summary, _CTRF_SUMMARY, "results.summary")
    declared = {k: _integer(_field(summary, k, "results.summary"), f"results.summary.{k}", non_negative=True)
                for k in _CTRF_SUMMARY_COUNTS}
    for k in ("start", "stop"):
        _integer(_field(summary, k, "results.summary"), f"results.summary.{k}", non_negative=False)
    for k in ("flaky", "suites"):
        if k in summary:
            _integer(summary[k], f"results.summary.{k}", non_negative=True)
    if "duration" in summary:
        _integer(summary["duration"], "results.summary.duration", non_negative=False)
    tests = _field(results, "tests", "results")
    if type(tests) is not list:
        raise ReportRefused("bad_value", "results.tests must be an array")
    by_status = dict.fromkeys(_CTRF_STATUSES, 0)
    for i, test in enumerate(tests):
        where = f"results.tests[{i}]"
        if type(test) is not dict:
            raise ReportRefused("bad_value", f"{where} must be an object")
        _only_known(test, _CTRF_TEST, where)
        _text(_field(test, "name", where), f"{where}.name")
        status = _field(test, "status", where)
        if type(status) is not str or status not in by_status:
            raise ReportRefused("bad_value", f"{where}.status must be one of {list(_CTRF_STATUSES)}, got "
                                             f"{render_safe(status)}")
        _integer(_field(test, "duration", where), f"{where}.duration", non_negative=False)
        by_status[status] += 1
    counted = {"tests": len(tests), **by_status}
    for k in _CTRF_SUMMARY_COUNTS:
        if declared[k] != counted[k]:
            raise ReportRefused("count_mismatch", f"results.summary.{k} is {declared[k]}, but the tests array holds "
                                                  f"{counted[k]}; the report contradicts itself")
    return ReportCounts(fmt=FORMAT_CTRF, tests=len(tests), passed=by_status["passed"], failed=by_status["failed"],
                        errors=by_status["other"], skipped=by_status["skipped"] + by_status["pending"],
                        name=tool_name, tool_version=tool_version, spec_version=version,
                        other=by_status["other"], pending=by_status["pending"])


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


def _claim_from_counts(counts: ReportCounts, digest_hex: str, *, commit: Optional[str], suite: Optional[str],
                       timestamp: Optional[str], model_salt: Optional[bytes], dataset_salt: Optional[bytes]):
    if commit is not None and (type(commit) is not str or not _COMMIT.match(commit)):
        raise ValueError("commit must be a full git object name: 40 or 64 lowercase hex characters, got "
                         f"{render_safe(commit)}")
    executed = counts.executed
    score = _pass_rate_floor(counts.passed, executed)
    provenance: dict = {
        "harness": counts.fmt, "report_format": counts.fmt, "report_sha256": digest_hex,
        "tests_total": counts.tests, "tests_passed": counts.passed, "tests_failed": counts.failed,
        "tests_errors": counts.errors, "tests_skipped": counts.skipped,
        "verdict_rule": VERDICT_RULE, "non_claims": NON_CLAIMS,
    }
    if executed:
        provenance["pass_rate_floor"] = score
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
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    suite_version = FORMAT_JUNIT if counts.fmt == FORMAT_JUNIT else f"ctrf-{counts.spec_version}"
    claim, salts = build_eval_claim(
        suite=suite if suite is not None else (counts.name or counts.fmt), suite_version=suite_version,
        metric="pass_rate", comparator=">=", threshold="1", score=score, n=executed,
        model_id=f"git:{commit}" if commit is not None else "git:not-given", dataset_id=f"sha256:{digest_hex}",
        issuer="", timestamp=timestamp, provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
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


@_ein_stand(aussen={"report": "pfad"})
def verify_test_receipt(bundle, report, *, expected_issuers: Optional[list] = None,
                        max_bytes: int = REPORT_MAX_BYTES) -> dict:
    """Check a test receipt against the report it names, offline.

    Verifies the receipt (`decode_eval_claim`: signature, Merkle inclusion, issuer binding), then that
    the report's SHA-256 is the signed ``report_sha256``, then reads the report again with this adapter
    and compares every signed count and the verdict. Returns ``{"ok", "reason", "claim"}``; ``claim`` is
    None when the receipt itself does not verify. Never raises for a malformed receipt or report."""
    from ..evalclaim import decode_eval_claim  # noqa: PLC0415
    claim = decode_eval_claim(bundle)
    if claim is None:
        return {"ok": False, "reason": "not a valid, issuer-bound eval receipt", "claim": None}
    if expected_issuers is not None and claim["issuer"] not in list(expected_issuers):
        return {"ok": False, "reason": f"the receipt is signed by {claim['issuer']}, not by a pinned issuer",
                "claim": claim}
    provenance = claim.get("provenance") or {}
    fmt = provenance.get("report_format")
    if fmt not in _READERS:
        return {"ok": False, "reason": "the receipt is not a test-report receipt (no report_format junit-xml or "
                                       "ctrf in its provenance)", "claim": claim}
    try:
        raw = _read_file(report, _check_limit(max_bytes))
        digest = hashlib.sha256(raw).hexdigest()
        if digest != provenance.get("report_sha256"):
            return {"ok": False, "reason": f"the report's digest {digest} is not the signed report_sha256 "
                                           f"{render_safe(provenance.get('report_sha256'))}", "claim": claim}
        counts = _READERS[fmt](raw, max_bytes=max_bytes)
    except (ReportRefused, ValueError) as exc:
        return {"ok": False, "reason": str(exc), "claim": claim}
    expected = {"tests_total": counts.tests, "tests_passed": counts.passed, "tests_failed": counts.failed,
                "tests_errors": counts.errors, "tests_skipped": counts.skipped}
    for key, value in expected.items():
        if provenance.get(key) != value:
            return {"ok": False, "reason": f"the receipt signs {key}={render_safe(provenance.get(key))}, the report "
                                           f"reads as {value}", "claim": claim}
    shape = (claim["metric"], claim["comparator"], claim["threshold"], claim["n"], claim["passed"])
    if shape != ("pass_rate", ">=", "1", counts.executed, counts.verdict):
        return {"ok": False, "reason": f"the receipt signs {render_safe(list(shape))}, the report gives pass_rate >= 1 "
                                       f"over n={counts.executed} with passed={counts.verdict}", "claim": claim}
    return {"ok": True, "reason": f"the receipt is about this report: {counts.tests} tests, {counts.passed} passed, "
                                  f"{counts.failed} failed, {counts.errors} errors, {counts.skipped} skipped, "
                                  f"passed={counts.verdict}", "claim": claim}
