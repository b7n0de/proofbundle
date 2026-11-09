"""interop/audit-decision-receipts-07/run_cases.py reads a verifier's answer strictly and finishes every run.

The runner compares the first line of a verifier's output with the expected result of each starter case. The first
review of the folder (2026-11-09) measured three ways around that rule on the folder as built: an answer followed by
a vertical tab and text on the same line, an answer with bytes that are not UTF-8, and an answer that names a member
twice all matched every case; an answer nested 2000 levels deep and one whose step is a lone surrogate stopped the
whole run before its table; and --timeout nan or inf ended in a traceback. Each case below is a verifier command
that answers in one of these forms and must count as a mismatch, with the summary printed, or as a usage error.

The control verifier answers with the expected member of each case and must still match 37 of 37.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent.parent / "interop" / "audit-decision-receipts-07" / "run_cases.py"

#: A verifier that prints the expected answer of the case file it is given, then whatever TAIL adds.
_ECHO = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
         "sys.stdout.buffer.write(json.dumps(e).encode('utf-8') + {tail} + b'\\n')")


def _run(verifier_code: str, *runner_args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RUNNER), *runner_args, "--", sys.executable, "-c", verifier_code],
                          capture_output=True, timeout=600)


class AControlVerifierMatches(unittest.TestCase):
    def test_the_expected_answer_matches_every_case(self):
        p = _run(_ECHO.format(tail="b''"))
        self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-400:])
        self.assertIn(b"37 of 37 cases match (result and step)", p.stdout)


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
                    self.assertIn(b"0 of 37 cases match", p.stdout)

    def test_bytes_that_are_not_utf8_are_no_answer(self):
        code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "s = json.dumps(e); sys.stdout.buffer.write(s[:-1].encode() + b', \"x\": \"\\xff\"}\\n')")
        for mode in ((), ("--accept-reject",)):
            with self.subTest(mode=mode):
                p = _run(code, *mode)
                self.assertEqual(p.returncode, 1)
                self.assertIn(b"0 of 37 cases match", p.stdout)

    def test_a_member_named_twice_is_no_answer(self):
        code = ("import json, sys; e = json.load(open(sys.argv[-1], encoding='utf-8'))['expected']; "
                "s = json.dumps(e); print('{\"result\": \"pass\", ' + s[1:])")
        for mode in ((), ("--accept-reject",)):
            with self.subTest(mode=mode):
                p = _run(code, *mode)
                self.assertEqual(p.returncode, 1)
                self.assertIn(b"0 of 37 cases match", p.stdout)


class AMalformedAnswerDoesNotStopTheRun(unittest.TestCase):
    def test_a_deeply_nested_answer_is_a_mismatch(self):
        p = _run("print('[' * 2000 + ']' * 2000)")
        self.assertEqual(p.returncode, 1, p.stderr.decode("utf-8", "replace")[-400:])
        self.assertIn(b"0 of 37 cases match", p.stdout)

    def test_a_lone_surrogate_in_the_step_is_a_mismatch(self):
        p = _run("print('{\"result\": \"fail\", \"step\": \"\\\\ud800\"}')")
        self.assertEqual(p.returncode, 1, p.stderr.decode("utf-8", "replace")[-400:])
        self.assertIn(b"cases match", p.stdout)
        self.assertNotIn(b"Traceback", p.stderr)


class ATimeoutMustBeAFiniteNumberOfSeconds(unittest.TestCase):
    def test_nan_inf_and_zero_are_usage_errors(self):
        for value in ("nan", "inf", "-inf", "0", "-1"):
            with self.subTest(timeout=value):
                p = _run("print('{}')", "--timeout", value)
                self.assertEqual(p.returncode, 2)
                self.assertNotIn(b"Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
