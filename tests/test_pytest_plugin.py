"""pytest plugin (v1.0): opt-in safety + signed receipt of the test run from terminalreporter.stats."""
import json
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from proofbundle import verify_bundle
from proofbundle.evalclaim import decode_eval_claim
from proofbundle.pytest_plugin import pytest_terminal_summary


def _reporter(passed=3, failed=0, error=0):
    stats = {}
    if passed:
        stats["passed"] = [object()] * passed
    if failed:
        stats["failed"] = [object()] * failed
    if error:
        stats["error"] = [object()] * error
    return types.SimpleNamespace(stats=stats)


def _config(flag, rootpath="myproj"):
    return types.SimpleNamespace(getoption=lambda name, default=False: flag,
                                 rootpath=types.SimpleNamespace(name=rootpath, __str__=lambda self: rootpath))


class TestPytestPlugin(unittest.TestCase):
    def test_opt_in_off_no_receipt(self):
        with TemporaryDirectory() as d:
            import os
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            os.environ["PROOFBUNDLE_OUT"] = d
            pytest_terminal_summary(_reporter(), 0, _config(False))
            self.assertEqual([f for f in Path(d).iterdir()], [])

    def test_opt_in_flag_emits_receipt(self):
        with TemporaryDirectory() as d:
            import os
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ["PROOFBUNDLE_THRESHOLD"] = "0.5"
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            pytest_terminal_summary(_reporter(passed=3, failed=1), 1, _config(True))
            files = list(Path(d).glob("*.json"))
            self.assertEqual(len(files), 1)
            b = json.loads(files[0].read_text())
            self.assertTrue(verify_bundle(b).ok)
            d2 = decode_eval_claim(b)
            self.assertEqual(d2["suite"], "pytest")
            self.assertEqual(d2["metric"], "pass_rate")
            self.assertTrue(d2["passed"])                       # 3/4 = 0.75 >= 0.5
            self.assertEqual(d2["provenance"]["n_failed"], 1)

    def test_no_tests_no_receipt(self):
        with TemporaryDirectory() as d:
            import os
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            pytest_terminal_summary(_reporter(passed=0), 5, _config(False))
            self.assertEqual(list(Path(d).glob("*.json")), [])
            os.environ.pop("PROOFBUNDLE_EMIT", None)


class TestThresholdRequired(unittest.TestCase):
    def test_no_threshold_no_receipt(self):
        """No silent default of 0: pass_rate 0.0 >= 0 would assert passed=true for a run where
        every test failed (adversarial re-check 2026-08-22)."""
        with TemporaryDirectory() as d:
            import os
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ.pop("PROOFBUNDLE_THRESHOLD", None)
            pytest_terminal_summary(_reporter(passed=0, failed=4), 1, _config(False))
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            self.assertEqual(list(Path(d).glob("*.json")), [])


class TestTheMetricIsThePassRate(unittest.TestCase):
    """Codex thread 4217185750 on pull request 302: the plugin computes the pass rate and wrote it under any name
    PROOFBUNDLE_METRIC gave, so `accuracy` with one test passed and one failed signed an accuracy verdict of 0.5."""

    def _run(self, metric):
        import os
        from unittest import mock
        umgebung = {"PROOFBUNDLE_EMIT": "1", "PROOFBUNDLE_THRESHOLD": "0.9"}
        if metric is not None:
            umgebung["PROOFBUNDLE_METRIC"] = metric
        with TemporaryDirectory() as d, mock.patch.dict(os.environ, dict(umgebung, PROOFBUNDLE_OUT=d)):
            if metric is None:
                os.environ.pop("PROOFBUNDLE_METRIC", None)
            pytest_terminal_summary(_reporter(passed=1, failed=1), 1, _config(False))
            return [decode_eval_claim(json.loads(f.read_text())) for f in Path(d).glob("*.json")]

    def test_another_metric_name_writes_no_receipt(self):
        for name in ("accuracy", "", "pass_rate "):
            with self.subTest(metric=repr(name)):
                self.assertEqual(self._run(name), [])

    def test_the_pass_rate_is_written_as_pass_rate(self):
        for name in (None, "pass_rate"):
            with self.subTest(metric=repr(name)):
                claims = self._run(name)
                self.assertEqual(len(claims), 1)
                self.assertEqual(claims[0]["metric"], "pass_rate")
                self.assertFalse(claims[0]["passed"])          # 1/2 = 0.5 < 0.9


class TheVerdictIsTheCountsNotARoundedRate(unittest.TestCase):
    """K2 of the Codex defect search of the 6.3.0 candidate 98b168b9 (T2): the plugin rounded the pass rate to six
    places before `build_eval_claim` compared it, so two passed of three, 0.666666..., was signed passed=true against
    a threshold of 0.666667. The verdict now comes from the counts; the rounding is for the written number only."""

    def _claims(self, threshold, comparator=None, passed=2, failed=1):
        import os
        from unittest import mock
        stats = {"passed": [types.SimpleNamespace(nodeid=f"t{i}") for i in range(passed)],
                 "failed": [types.SimpleNamespace(nodeid=f"f{i}") for i in range(failed)]}
        with TemporaryDirectory() as d:
            key = Path(d) / "key.bin"
            key.write_bytes(bytes(range(32)))
            out = Path(d) / "out"
            out.mkdir()
            umgebung = {"PROOFBUNDLE_EMIT": "1", "PROOFBUNDLE_THRESHOLD": threshold,
                        "PROOFBUNDLE_KEY": str(key), "PROOFBUNDLE_OUT": str(out)}
            if comparator is not None:
                umgebung["PROOFBUNDLE_COMPARATOR"] = comparator
            with mock.patch.dict(os.environ, umgebung):
                os.environ.pop("PROOFBUNDLE_METRIC", None)
                if comparator is None:
                    os.environ.pop("PROOFBUNDLE_COMPARATOR", None)
                pytest_terminal_summary(types.SimpleNamespace(stats=stats), 1, _config(False))
            bundles = [json.loads(f.read_text()) for f in out.glob("*.json")]
        for b in bundles:
            self.assertTrue(verify_bundle(b).ok)
        return [decode_eval_claim(b) for b in bundles]

    def test_two_of_three_does_not_pass_a_threshold_of_0_666667(self):
        claims = self._claims("0.666667")
        self.assertEqual(len(claims), 1)
        self.assertIs(claims[0]["passed"], False)
        self.assertEqual((claims[0]["n"], claims[0]["provenance"]["tests_passed"]), (3, 2))

    def test_two_of_three_passes_a_threshold_of_0_666666(self):
        claims = self._claims("0.666666")
        self.assertEqual(len(claims), 1)
        self.assertIs(claims[0]["passed"], True)

    def test_the_other_comparators_follow_the_counts_too(self):
        # 2/3 against 0.666667: below it, so > is false and <= and < are true.
        for comparator, expected in ((">", False), ("<=", True), ("<", True)):
            with self.subTest(comparator=comparator):
                claims = self._claims("0.666667", comparator)
                self.assertEqual(len(claims), 1)
                self.assertIs(claims[0]["passed"], expected)

    def test_the_written_score_lies_on_the_side_of_the_exact_rate_for_every_comparator(self):
        """The oracle is the exact fraction against the decimal threshold, not the plugin's own helper: for every
        count up to twelve, thresholds on, beside and between the six-place roundings, and each comparator, the
        score the plugin hands on must earn in `evalclaim._passed_by` the verdict of the exact rate."""
        from fractions import Fraction
        from proofbundle.evalclaim import _passed_by
        from proofbundle.pytest_plugin import _score_beside_the_verdict
        ops = {">=": lambda a, b: a >= b, ">": lambda a, b: a > b, "<=": lambda a, b: a <= b, "<": lambda a, b: a < b}
        geprueft = 0
        for ran in range(1, 13):
            for passed in range(ran + 1):
                rate = Fraction(passed, ran)
                six = format(passed / ran, ".6f")
                schwellen = {six, "0", "1", "0.5", "-0.1", "1.0000001", "0.66666666", "0.6666667",
                             format(float(six) + 1e-6, ".6f"), format(max(float(six) - 1e-6, 0), ".6f"),
                             format(passed / ran, ".9f")}
                # More significant digits than a decimal context holds by default (28): the score must still
                # lie on the rate's side (lens 2 of the gate on this fix, `scaleb` rounded there).
                for stellen in (29, 41):
                    unten = passed * 10 ** stellen // ran
                    for k in (unten - 1, unten, unten + 1):
                        if k >= 0:
                            ziffern = str(k).rjust(stellen + 1, "0")
                            schwellen.add(ziffern[:-stellen] + "." + ziffern[-stellen:])
                for schwelle in schwellen:
                    score = _score_beside_the_verdict(passed, ran, schwelle)
                    for cmp, op in ops.items():
                        self.assertEqual(_passed_by(score, cmp, schwelle), op(rate, Fraction(schwelle)),
                                         (passed, ran, schwelle, cmp, score))
                        geprueft += 1
        self.assertGreater(geprueft, 5000)

    def test_a_rate_equal_to_a_threshold_with_more_than_six_places_keeps_its_verdict(self):
        """1 of 128 is exactly 0.0078125, seven places. Equal to the threshold, it passes >= and <= and fails > and <;
        a score rounded to six places would land beside the threshold (lens 3 of the gate on this fix), so at equality
        the score is the threshold's own digits. Through the plugin, with 128 distinct test ids."""
        from proofbundle.evalclaim import _passed_by
        from proofbundle.pytest_plugin import _score_beside_the_verdict
        for passed in (1, 3, 127):
            # passed/128 is passed * 5**7 / 10**7 exactly, written with its seven places
            schwelle = str(passed * 5 ** 7).rjust(8, "0")
            schwelle = schwelle[:-7] + "." + schwelle[-7:]
            score = _score_beside_the_verdict(passed, 128, schwelle)
            for cmp, erwartet in ((">=", True), ("<=", True), (">", False), ("<", False)):
                with self.subTest(passed=passed, threshold=schwelle, comparator=cmp):
                    self.assertIs(_passed_by(score, cmp, schwelle), erwartet, score)
        for cmp, erwartet in ((">=", True), ("<=", True), (">", False), ("<", False)):
            with self.subTest(through="the plugin", comparator=cmp):
                claims = self._claims("0.0078125", cmp, passed=1, failed=127)
                self.assertEqual(len(claims), 1)
                self.assertIs(claims[0]["passed"], erwartet)

    def test_a_threshold_longer_than_the_integer_string_limit_still_gets_its_receipt(self):
        """CPython converts at most 4300 digits between text and int. A threshold of 4400 zeros after the point and a
        `1`, one significant digit, made `Fraction(threshold)` raise, and the receipt was skipped where 98b168b9 wrote
        one (iteration 2 of the gate on this fix). Read through `Decimal`, it keeps its exact verdict. Both thresholds
        lie below 2/3: the first by far, the second by two thirds of a unit in its 4400th place."""
        from proofbundle.evalclaim import _passed_by
        from proofbundle.pytest_plugin import _score_beside_the_verdict, _verdict_from_the_counts
        winzig = "0." + "0" * 4400 + "1"
        sechsen = "0." + "6" * 4400          # just below 2/3
        for schwelle, cmp, erwartet in ((winzig, ">=", True), (winzig, "<", False), (sechsen, ">=", True),
                                        (sechsen, ">", True), (sechsen, "<=", False)):
            with self.subTest(threshold=schwelle[:12] + "...", comparator=cmp):
                self.assertIs(_verdict_from_the_counts(2, 3, cmp, schwelle), erwartet)
                self.assertIs(_passed_by(_score_beside_the_verdict(2, 3, schwelle), cmp, schwelle), erwartet)
                claims = self._claims(schwelle, cmp)
                self.assertEqual(len(claims), 1)
                self.assertIs(claims[0]["passed"], erwartet)

    def test_an_all_pass_and_an_all_fail_run_get_their_receipt(self):
        """A rate of 1 or 0 is written as `1` or `0`, not as `1.` or `0.`, which the builder's decimal rule refuses: a
        score that kept the trailing point would skip the receipt of every run whose tests all passed or all failed
        (iteration 3 of the gate on this fix, the mutant without `.rstrip(".")`)."""
        from proofbundle.evalclaim import _DECIMAL_RE
        from proofbundle.pytest_plugin import _score_beside_the_verdict
        for passed, ran, schwelle in ((3, 3, "0.9"), (0, 3, "0.5"), (3, 3, "1.5"), (0, 3, "-0.5")):
            with self.subTest(passed=passed, ran=ran, threshold=schwelle):
                self.assertRegex(_score_beside_the_verdict(passed, ran, schwelle), _DECIMAL_RE)
        for passed, failed, schwelle, erwartet in ((3, 0, "0.9", True), (0, 3, "0.5", False)):
            with self.subTest(through="the plugin", passed=passed, failed=failed):
                claims = self._claims(schwelle, passed=passed, failed=failed)
                self.assertEqual(len(claims), 1)
                self.assertIs(claims[0]["passed"], erwartet)

    def test_the_verdict_is_exact_where_a_float_is_not(self):
        """1/3 and 0.33333333333333331 are the same double, so a float comparison calls them equal; as fractions 1/3
        is larger. The verdict is the exact one (lens 3: computing it from floats survived every other test)."""
        from proofbundle.pytest_plugin import _verdict_from_the_counts
        self.assertEqual(1 / 3, float("0.33333333333333331"))
        self.assertIs(_verdict_from_the_counts(1, 3, ">", "0.33333333333333331"), True)
        self.assertIs(_verdict_from_the_counts(1, 3, "<=", "0.33333333333333331"), False)
        self.assertIs(_verdict_from_the_counts(1, 3, ">=", "0.3333333333333333333333333333334"), False)
        self.assertIsNone(_verdict_from_the_counts(1, 3, "==", "0.5"))
        self.assertIsNone(_verdict_from_the_counts(1, 3, ">=", "1e-1"))
        claims = self._claims("0.33333333333333331", ">", passed=1, failed=2)
        self.assertEqual(len(claims), 1)
        self.assertIs(claims[0]["passed"], True)

    def test_the_host_decimal_context_does_not_move_the_score(self):
        """A host that runs its tests under a narrow decimal context gets the same verdict: the score is written
        from integers, and `_passed_by` compares decimals built from strings, which no context rounds."""
        import decimal
        with decimal.localcontext() as ctx:
            ctx.prec, ctx.Emax, ctx.Emin = 3, 5, -5
            claims = self._claims("0.666667")
            self.assertEqual(len(claims), 1)
            self.assertIs(claims[0]["passed"], False)
            claims = self._claims("0." + "6" * 40)
            self.assertEqual(len(claims), 1)
            self.assertIs(claims[0]["passed"], True)

    def test_a_claim_whose_verdict_is_not_the_counts_is_not_signed(self):
        """The guard between the builder and the signature: a builder that answered another verdict than the counts
        gets no receipt. Here the builder is made to flip `passed`; the same run without the flip is the control."""
        from unittest import mock
        from proofbundle import evalclaim
        echt = evalclaim.build_eval_claim

        def gekippt(**kw):
            claim, salze = echt(**kw)
            return dict(claim, passed=not claim["passed"]), salze
        with mock.patch.object(evalclaim, "build_eval_claim", side_effect=gekippt):
            self.assertEqual(self._claims("0.666667"), [])
        self.assertEqual(len(self._claims("0.666667")), 1)

