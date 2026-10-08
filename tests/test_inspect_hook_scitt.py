"""The Inspect hook's optional SCITT flag (6.4.0 producer, part 5).

Owner order of 2026-09-27: step 1 (sign a Signed Statement over the receipt) after the eval, step 2
(register it) only if a service URL is configured, no network by default. Registration is not built
yet, so with a service URL the hook says the statement was not submitted and still opens no
connection. Off unless ``PROOFBUNDLE_SCITT=1``, on top of the existing ``PROOFBUNDLE_EMIT=1``.
"""
import asyncio
import base64
import importlib.util
import json
import os
import socket
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

FX = Path(__file__).resolve().parent / "fixtures" / "inspect_logs" / "safety_refusal_demo.eval"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ENV = ("PROOFBUNDLE_EMIT", "PROOFBUNDLE_OUT", "PROOFBUNDLE_THRESHOLD", "PROOFBUNDLE_KEY", "PROOFBUNDLE_SCITT",
       "PROOFBUNDLE_SCITT_ISSUER", "PROOFBUNDLE_SCITT_SUBJECT", "PROOFBUNDLE_SCITT_SERVICE")


def _require(test):
    try:
        from inspect_ai.log import read_eval_log  # noqa: F401,PLC0415
    except ImportError:
        if os.environ.get("PROOFBUNDLE_RELEASE_LANE") == "1":
            test.fail("inspect_ai is not installed but PROOFBUNDLE_RELEASE_LANE=1 (makellose-500 I2)")
        test.skipTest("inspect_ai not installed (pip install proofbundle[inspect])")
    if importlib.util.find_spec("cbor2") is None or importlib.util.find_spec("rfc8785") is None:
        test.skipTest("the SCITT statement needs the [scitt] extra and the RFC 8785 canonicalizer")


class TestInspectHookScittFlag(unittest.TestCase):
    def setUp(self):
        _require(self)
        self._saved = {k: os.environ.get(k) for k in ENV}
        for k in ENV:
            os.environ.pop(k, None)
        self._dir = TemporaryDirectory()
        self.out = Path(self._dir.name)
        os.environ.update({"PROOFBUNDLE_EMIT": "1", "PROOFBUNDLE_OUT": str(self.out),
                           "PROOFBUNDLE_THRESHOLD": "0"})

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._dir.cleanup()

    def _data(self):
        from inspect_ai.log import read_eval_log  # noqa: PLC0415
        log = read_eval_log(str(FX), header_only=True)
        return types.SimpleNamespace(log=log, eval_id="demo", run_id="r", eval_set_id=None)

    def _run(self) -> str:
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        from proofbundle.inspect_hook import ProofbundleHooks  # noqa: PLC0415
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
        return out.getvalue()

    def _key(self) -> Path:
        path = self.out.parent / f"{self.out.name}.seed"
        path.write_bytes(bytes(range(32)))
        self.addCleanup(path.unlink)
        os.environ["PROOFBUNDLE_KEY"] = str(path)
        return path

    def _flag(self):
        os.environ.update({"PROOFBUNDLE_SCITT": "1", "PROOFBUNDLE_SCITT_ISSUER": "https://issuer.example",
                           "PROOFBUNDLE_SCITT_SUBJECT": "eval:demo"})

    def _check(self, statement: bytes, receipt: dict):
        from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
        from proofbundle.scitt_statement import check_signed_statement  # noqa: PLC0415
        spki = ED25519_SPKI_PREFIX + base64.b64decode(receipt["signature"]["public_key_b64"])
        root = receipt_canonical_root({k: v for k, v in receipt.items() if k != "anchors"})
        return check_signed_statement(statement, canonical_root=root, statement_keys=[spki])

    def test_off_by_default_no_statement(self):
        self._key()
        self._run()
        self.assertEqual(len(list(self.out.glob("*.json"))), 1)
        self.assertEqual(list(self.out.glob("*.cose")), [])

    def test_on_it_signs_a_statement_over_the_receipt_with_the_receipt_key(self):
        self._key()
        self._flag()
        printed = self._run()
        receipts = list(self.out.glob("*.json"))
        statements = list(self.out.glob("*.cose"))
        self.assertEqual((len(receipts), len(statements)), (1, 1), printed)
        self.assertEqual(statements[0].name, receipts[0].name[:-len(".json")] + ".scitt.cose")
        r = self._check(statements[0].read_bytes(), json.loads(receipts[0].read_text()))
        self.assertEqual((r.status, r.registration), ("confirmed", "not_registered"), r.detail)
        self.assertEqual((r.issuer, r.subject), ("https://issuer.example", "eval:demo"))
        self.assertIn("not registered", printed)

    def test_an_ephemeral_key_signs_both_with_the_same_key(self):
        self._flag()
        printed = self._run()
        receipt = json.loads(next(self.out.glob("*.json")).read_text())
        r = self._check(next(self.out.glob("*.cose")).read_bytes(), receipt)
        self.assertEqual(r.status, "confirmed", printed)

    def test_without_issuer_or_subject_the_statement_is_skipped_and_the_receipt_stays(self):
        self._key()
        self._flag()
        os.environ.pop("PROOFBUNDLE_SCITT_SUBJECT")
        printed = self._run()
        self.assertEqual(len(list(self.out.glob("*.json"))), 1)
        self.assertEqual(list(self.out.glob("*.cose")), [])
        self.assertIn("PROOFBUNDLE_SCITT_SUBJECT", printed)

    def test_no_network_by_default_and_none_with_a_service_url_either(self):
        self._key()
        self._flag()
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network")) as connect:
            printed = self._run()
            self.assertEqual(len(list(self.out.glob("*.cose"))), 1, printed)
            os.environ["PROOFBUNDLE_SCITT_SERVICE"] = "https://scitt.example"
            for f in self.out.iterdir():
                f.unlink()
            printed = self._run()
        self.assertEqual(connect.call_count, 0)
        self.assertEqual(len(list(self.out.glob("*.cose"))), 1, printed)
        self.assertIn("not submitted", printed)
        self.assertIn("https://scitt.example", printed)


if __name__ == "__main__":
    unittest.main()
