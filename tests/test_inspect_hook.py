"""inspect_ai hook (v1.0): opt-in safety + signed receipt from a real EvalLog (data.log)."""
import asyncio
import json
import os
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

FX = Path(__file__).resolve().parent / "fixtures" / "inspect_logs" / "safety_refusal_demo.eval"


class TestInspectHook(unittest.TestCase):
    def setUp(self):
        try:
            from inspect_ai.log import read_eval_log  # noqa: F401
        except ImportError:
            self.skipTest("inspect_ai not installed (pip install proofbundle[inspect])")

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
        try:
            from inspect_ai.log import read_eval_log  # noqa: F401
        except ImportError:
            self.skipTest("inspect_ai not installed (pip install proofbundle[inspect])")

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
