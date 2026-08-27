"""inspect_ai hook (v1.0): opt-in safety + signed receipt from a real EvalLog (data.log)."""
import asyncio
import json
import os
import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

FX = Path(__file__).resolve().parent / "fixtures" / "inspect_logs" / "safety_refusal_demo.eval"


def _require_inspect(test):
    """makellose-500 I2 (Way B): a silently SKIPPED test must not read as coverage in a release-deciding
    run. In the hermetic default lane inspect_ai is absent and the skip stays (unchanged). Under the
    release marker PROOFBUNDLE_RELEASE_LANE=1 the SAME absence is a FAILURE — the release lane MUST install
    proofbundle[inspect,eval] and EXERCISE the shipped hook, never count a non-run as a pass. The
    enforcement lives in the test itself, so it cannot vanish through a CI-config regression."""
    try:
        from inspect_ai.log import read_eval_log  # noqa: F401,PLC0415
    except ImportError:
        if os.environ.get("PROOFBUNDLE_RELEASE_LANE") == "1":
            test.fail("inspect_ai is not installed but PROOFBUNDLE_RELEASE_LANE=1 — a release-deciding run "
                      "must EXERCISE the shipped inspect hook, not skip it. Install the extra: "
                      "pip install proofbundle[inspect,eval] (makellose-500 I2).")
        test.skipTest("inspect_ai not installed (pip install proofbundle[inspect])")


class TestInspectHook(unittest.TestCase):
    def setUp(self):
        _require_inspect(self)

    def _data(self):
        from inspect_ai.log import read_eval_log
        log = read_eval_log(str(FX), header_only=True)
        return types.SimpleNamespace(log=log, eval_id="demo", run_id="r", eval_set_id=None)

    def test_opt_in_off_no_receipt(self):
        from proofbundle.inspect_hook import ProofbundleHooks
        with TemporaryDirectory() as d:
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            os.environ["PROOFBUNDLE_OUT"] = d
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
            self.assertEqual(list(Path(d).glob("*.json")), [])

    def test_opt_in_emits_verifiable_receipt(self):
        from proofbundle import verify_bundle
        from proofbundle.evalclaim import decode_eval_claim
        from proofbundle.inspect_hook import ProofbundleHooks
        with TemporaryDirectory() as d:
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ["PROOFBUNDLE_THRESHOLD"] = "0"
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
            files = list(Path(d).glob("*.json"))
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            self.assertEqual(len(files), 1)
            b = json.loads(files[0].read_text())
            self.assertTrue(verify_bundle(b).ok)
            dec = decode_eval_claim(b)
            self.assertEqual(dec["suite"], "safety_refusal_demo")
            self.assertNotIn("mockllm", json.dumps(dec))        # model stays a salted commitment

    def test_enabled_reflects_env(self):
        from proofbundle.inspect_hook import ProofbundleHooks
        os.environ["PROOFBUNDLE_EMIT"] = "1"
        self.assertTrue(ProofbundleHooks().enabled())
        os.environ["PROOFBUNDLE_EMIT"] = "0"
        self.assertFalse(ProofbundleHooks().enabled())
        os.environ.pop("PROOFBUNDLE_EMIT", None)


class TestThresholdRequiredAndCapture(unittest.TestCase):
    """Adversarial re-check 2026-08-22: with the former default threshold "0" a run scoring
    mean 0.0 produced passed=true (vacuous), and a hook receipt was byte-indistinguishable
    from a later reader run. Both properties are bound here."""

    def setUp(self):
        _require_inspect(self)

    def _data(self):
        from inspect_ai.log import read_eval_log
        log = read_eval_log(str(FX), header_only=True)
        return types.SimpleNamespace(log=log, eval_id="demo", run_id="r", eval_set_id=None)

    def test_no_threshold_no_receipt(self):
        from proofbundle.inspect_hook import ProofbundleHooks
        with TemporaryDirectory() as d:
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ.pop("PROOFBUNDLE_THRESHOLD", None)
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            self.assertEqual(list(Path(d).glob("*.json")), [],
                             "without an explicit threshold no receipt may be emitted "
                             "(default 0 made passed vacuous)")

    def test_hook_receipt_carries_lifecycle_capture(self):
        from proofbundle.evalclaim import decode_eval_claim
        from proofbundle.inspect_hook import ProofbundleHooks
        with TemporaryDirectory() as d:
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ["PROOFBUNDLE_THRESHOLD"] = "0"
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            files = list(Path(d).glob("*.json"))
            self.assertEqual(len(files), 1)
            dec = decode_eval_claim(json.loads(files[0].read_text()))
            self.assertEqual(dec["provenance"]["capture_mechanism"], "lifecycle_hook")

    def test_reader_default_is_persisted_log_reader(self):
        from proofbundle.adapters.inspect_ai import from_inspect_ai_log
        claim, _ = from_inspect_ai_log(str(FX), "accuracy", comparator=">=", threshold="0",
                                       timestamp="2026-08-22T00:00:00+00:00")
        self.assertEqual((claim.get("provenance") or {}).get("capture_mechanism"),
                         "persisted_log_reader")


class TestReleaseLaneSkipVisibility(unittest.TestCase):
    """makellose-500 I2: proves the release-lane guard converts a would-be skip into a FAILURE (a non-run
    cannot masquerade as coverage). Hermetic — drives _require_inspect with inspect_ai forced absent, both
    marker states, so it runs and asserts REGARDLESS of whether inspect_ai is installed."""

    def test_release_marker_turns_absent_inspect_into_failure(self):
        from unittest import mock, SkipTest

        class _Failed(Exception):
            pass

        class FakeTest:  # faithful: real unittest .fail()/.skipTest() RAISE (so .fail() stops the flow)
            def fail(self, msg):
                raise _Failed(msg)

            def skipTest(self, msg):
                raise SkipTest(msg)

        with mock.patch.dict(sys.modules, {"inspect_ai": None, "inspect_ai.log": None}):
            os.environ.pop("PROOFBUNDLE_RELEASE_LANE", None)
            with self.assertRaises(SkipTest):  # default lane: absent inspect_ai -> SKIP
                _require_inspect(FakeTest())
            os.environ["PROOFBUNDLE_RELEASE_LANE"] = "1"
            try:
                with self.assertRaises(_Failed):  # release lane: absent inspect_ai -> FAIL, never skip
                    _require_inspect(FakeTest())
            finally:
                os.environ.pop("PROOFBUNDLE_RELEASE_LANE", None)


class TestFixtureProvenance(unittest.TestCase):
    """makellose-500 I3: the fixture carries its recording version, and (when inspect_ai is available) that
    recorded version matches the fixture's actual header — so a format/provenance drift is visible."""

    _SIDE = FX.parent / (FX.name + ".provenance.json")

    def test_provenance_sidecar_present_and_names_version(self):
        self.assertTrue(self._SIDE.is_file(), "fixture provenance sidecar missing (makellose-500 I3)")
        meta = json.loads(self._SIDE.read_text())
        self.assertTrue(meta.get("recorded_with_inspect_ai"), "sidecar must name the recording version")
        self.assertIsInstance(meta.get("eval_log_version"), int)

    def test_recorded_version_matches_fixture(self):
        _require_inspect(self)
        from inspect_ai.log import read_eval_log
        meta = json.loads(self._SIDE.read_text())
        log = read_eval_log(str(FX), header_only=True)
        pkgs = getattr(getattr(log, "eval", None), "packages", {}) or {}
        self.assertEqual(pkgs.get("inspect_ai"), meta["recorded_with_inspect_ai"],
                         "fixture header disagrees with the provenance sidecar")
        self.assertEqual(getattr(log, "version", None), meta["eval_log_version"])


if __name__ == "__main__":
    unittest.main()
