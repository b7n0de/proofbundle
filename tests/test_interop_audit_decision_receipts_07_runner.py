"""interop/audit-decision-receipts-07/run_cases.py reads a verifier's answer strictly and finishes every run.

The runner compares the first line of a verifier's output with the expected result of each starter case. The first
review of the folder (2026-11-09) measured three ways around that rule on the folder as built: an answer followed by
a vertical tab and text on the same line, an answer with bytes that are not UTF-8, and an answer that names a member
twice all matched every case; an answer nested 2000 levels deep and one whose step is a lone surrogate stopped the
whole run before its table; and --timeout nan or inf ended in a traceback. Each case below is a verifier command
that answers in one of these forms and must count as a mismatch, with the summary printed, or as a usage error.

The control verifier answers with the expected member of each case and must still match 37 of 37. The third review
(2026-11-09) found that an answer outside the form the README gives (a step for a pass, no step member, a step that is
no step of the draft) still matched, that the count was read as a substring, so "10 of 37" passed for "0 of 37", and
that an integer of more than 4300 digits in another member made a valid answer no answer.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

FOLDER = Path(__file__).resolve().parent.parent / "interop" / "audit-decision-receipts-07"
RUNNER = FOLDER / "run_cases.py"

#: A verifier that prints the expected answer of the case file it is given, then whatever TAIL adds.
_ECHO = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
         "sys.stdout.buffer.write(json.dumps(e).encode('utf-8') + {tail} + b'\\n')")


def _run(verifier_code: str, *runner_args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RUNNER), *runner_args, "--", sys.executable, "-c", verifier_code],
                          capture_output=True, timeout=600)


def _matches(p: subprocess.CompletedProcess, mode: tuple = ()) -> int:
    """The number of matching cases from the summary line, which must be there exactly once and name the mode."""
    name = b"accept/reject" if mode else b"result and step"
    found = re.findall(rb"^(\d+) of 37 cases match \((result and step|accept/reject)\)\r?$", p.stdout, re.M)
    if len(found) != 1 or found[0][1] != name:
        raise AssertionError("no single summary line for %r in: %r" % (name, p.stdout[-300:]))
    return int(found[0][0])


def _expected() -> list:
    return [json.loads(f.read_text(encoding="utf-8"))["expected"] for f in sorted((FOLDER / "cases").glob("*.json"))]


class AControlVerifierMatches(unittest.TestCase):
    def test_the_expected_answer_matches_every_case(self):
        p = _run(_ECHO.format(tail="b''"))
        self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-400:])
        self.assertEqual(_matches(p), 37)


class AMalformedAnswerIsAMismatch(unittest.TestCase):
    """Each answer is the expected one plus a defect; none may match, in either mode, and the run finishes."""

    CASES = {
        "text after a vertical tab on the first line": "b'\\x0bNOT_JSON'",
        "text after a form feed on the first line": "b'\\x0cNOT_JSON'",
        "text after a line separator on the first line": "'\\u2028NOT_JSON'.encode('utf-8')",
    }

    def test_trailing_text_on_the_first_line_is_no_answer(self):
        for name, tail in self.CASES.items():
            for mode in ((), ("--accept-reject",)):
                with self.subTest(defect=name, mode=mode):
                    p = _run(_ECHO.format(tail=tail), *mode)
                    self.assertEqual(p.returncode, 1)
                    self.assertEqual(_matches(p, mode), 0)

    def test_bytes_that_are_not_utf8_are_no_answer(self):
        code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "s = json.dumps(e); sys.stdout.buffer.write(s[:-1].encode() + b', \"x\": \"\\xff\"}\\n')")
        for mode in ((), ("--accept-reject",)):
            with self.subTest(mode=mode):
                p = _run(code, *mode)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(_matches(p, mode), 0)

    def test_a_member_named_twice_is_no_answer(self):
        code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "s = json.dumps(e); print('{\"result\": \"pass\", ' + s[1:])")
        for mode in ((), ("--accept-reject",)):
            with self.subTest(mode=mode):
                p = _run(code, *mode)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(_matches(p, mode), 0)


class AMalformedAnswerDoesNotStopTheRun(unittest.TestCase):
    def test_a_deeply_nested_answer_is_a_mismatch(self):
        p = _run("print('[' * 2000 + ']' * 2000)")
        self.assertEqual(p.returncode, 1, p.stderr.decode("utf-8", "replace")[-400:])
        self.assertEqual(_matches(p), 0)

    def test_a_lone_surrogate_in_the_step_is_no_answer(self):
        # The expected result with a step that is a lone surrogate: an answer that normalised the step instead of
        # refusing it would match every case under --accept-reject (review 2 of the folder).
        code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "print(json.dumps({'result': e['result'], 'step': '\\ud800'}))")
        for mode in ((), ("--accept-reject",)):
            with self.subTest(mode=mode):
                p = _run(code, *mode)
                self.assertEqual(p.returncode, 1, p.stderr.decode("utf-8", "replace")[-400:])
                self.assertEqual(_matches(p, mode), 0)
                self.assertNotIn(b"Traceback", p.stderr)


class TheJsonConstantsOfPythonAreNoJson(unittest.TestCase):
    def test_nan_and_infinity_in_a_member_are_no_answer(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                    "print(json.dumps(e)[:-1] + ', \"x\": " + token + "}')")
            for mode in ((), ("--accept-reject",)):
                with self.subTest(token=token, mode=mode):
                    p = _run(code, *mode)
                    self.assertEqual(p.returncode, 1)
                    self.assertEqual(_matches(p, mode), 0)


class OnlyTheFirstLineIsTheAnswer(unittest.TestCase):
    """Positive controls: what follows the first line feed does not decide, and the line may end otherwise."""

    def test_bytes_after_the_first_line_do_not_decide(self):
        for tail in ("b'\\nnot utf-8: \\xff'", "b'\\nany log line'"):
            for mode in ((), ("--accept-reject",)):
                with self.subTest(tail=tail, mode=mode):
                    p = _run(_ECHO.format(tail=tail), *mode)
                    self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-300:])
                    self.assertEqual(_matches(p, mode), 37)

    def test_a_crlf_line_and_an_unterminated_line_are_answers(self):
        crlf = _ECHO.format(tail="b'\\r'")
        ohne = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "sys.stdout.buffer.write(json.dumps(e).encode('utf-8'))")
        for name, code in (("crlf", crlf), ("unterminated", ohne)):
            for mode in ((), ("--accept-reject",)):
                with self.subTest(form=name, mode=mode):
                    p = _run(code, *mode)
                    self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-300:])
                    self.assertEqual(_matches(p, mode), 37)


class AnAnswerOutsideTheDocumentedFormIsNoAnswer(unittest.TestCase):
    """The README: result is one of four values, step is null for pass and otherwise one of the steps it names."""

    VERIFIERS = {
        "a step that is no step of the draft, for every case": "{'result': e['result'], 'step': 'NOT_A_STEP'}",
        "no step member": "{'result': e['result']}",
    }

    def test_every_case_answered_outside_the_form_matches_nothing(self):
        for name, answer in self.VERIFIERS.items():
            code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                    "print(json.dumps(" + answer + "))")
            for mode in ((), ("--accept-reject",)):
                with self.subTest(form=name, mode=mode):
                    p = _run(code, *mode)
                    self.assertEqual(p.returncode, 1)
                    self.assertEqual(_matches(p, mode), 0)

    def test_a_step_given_for_a_pass_is_no_answer(self):
        # Each pass is answered with a step of the draft, every other case exactly as expected.
        code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "s = '3.2 step 1' if e['result'] == 'pass' else e['step']; "
                "print(json.dumps({'result': e['result'], 'step': s}))")
        not_pass = sum(1 for e in _expected() if e["result"] != "pass")
        self.assertTrue(0 < not_pass < 37)
        for mode in ((), ("--accept-reject",)):
            with self.subTest(mode=mode):
                p = _run(code, *mode)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(_matches(p, mode), not_pass)


class TheStepsOfTheReadme(unittest.TestCase):
    """read_answer itself, on the steps the README names and on their nearest neighbours outside it."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("run_cases_07", RUNNER)
        cls.rc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.rc)

    def _read(self, result, step):
        return self.rc.read_answer(json.dumps({"result": result, "step": step}).encode("utf-8") + b"\n")[0]

    def test_each_named_step_is_read(self):
        steps = (["3.2 step %d" % n for n in range(1, 11)] + ["3.3 case %d" % n for n in range(1, 4)]
                 + ["3.4 step %d" % n for n in range(1, 8)] + ["3.5 third check", "4 item 1", "4 item 2", "4 item 12"])
        for step in steps:
            for result in ("fail", "refuse", "auditor-fail"):
                with self.subTest(step=step, result=result):
                    self.assertEqual(self._read(result, step), (result, step))
        self.assertEqual(self._read("pass", None), ("pass", None))

    def test_the_neighbours_of_the_named_steps_are_no_answer(self):
        for step in ("3.2 step 0", "3.2 step 11", "3.3 case 0", "3.3 case 4", "3.4 step 0", "3.4 step 8",
                     "3.5 first check", "4 item 0", "4 item 01", "4 item ", "3.2 step 1 ", " 3.2 step 1",
                     "3.2  step 1", "3.2 step ١", "3.2 step 1\n", ""):
            with self.subTest(step=step):
                self.assertIsNone(self._read("fail", step))
        self.assertIsNone(self._read("pass", "3.2 step 1"))
        self.assertIsNone(self._read("fail", None))

    def test_each_expected_step_of_the_cases_is_a_named_step(self):
        for e in _expected():
            with self.subTest(expected=e):
                self.assertEqual(self._read(e["result"], e["step"]), (e["result"], e["step"]))


class ANumberInAnotherMemberIsRead(unittest.TestCase):
    def test_an_integer_of_any_length_in_another_member_does_not_decide(self):
        for digits in (4300, 4301, 20000):
            code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                    "print(json.dumps(e)[:-1] + ', \"x\": ' + '1' * " + str(digits) + " + '}')")
            for mode in ((), ("--accept-reject",)):
                with self.subTest(digits=digits, mode=mode):
                    p = _run(code, *mode)
                    self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-300:])
                    self.assertEqual(_matches(p, mode), 37)


class ATimeoutMustBeAFiniteNumberOfSeconds(unittest.TestCase):
    def test_nan_inf_and_zero_are_usage_errors(self):
        for value in ("nan", "inf", "-inf", "0", "-1"):
            with self.subTest(timeout=value):
                p = _run("print('{}')", "--timeout", value)
                self.assertEqual(p.returncode, 2)
                self.assertNotIn(b"Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
