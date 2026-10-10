"""6.2.1 R6b-7: every accepted historical call is marked HISTORICAL, with or without ``--policy``.

The sibling surface ``verify-enclave --verification-time`` judges the EAT freshness as of the given instant as well,
and its output is marked the same way. Without the flag neither surface carries the mark.

Red at v6.2.0.
"""



from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_security_fix_620_zeit_n49b_cli as N49B  # noqa: E402
import test_security_fix_620_zeit_r6b6 as R6B6  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


class R6b7HistoricalAlwaysMarked(unittest.TestCase):
    def _run(self, with_policy: bool):
        env, pub, aud, nonce, _sk = R6B6._signed_receipt(with_expires="2021-01-01T00:00:00Z")
        with tempfile.TemporaryDirectory() as tmp:
            rp = R6B6._write(tmp, "r.json", env)
            extra = ["--policy", R6B6._write(tmp, "p.json", R6B6._policy(pub, "2099-01-01T00:00:00Z"))] \
                if with_policy else []
            rc, out = R6B6._cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                     "--nonce", nonce, *extra, "--verification-time", "2020-01-01T00:00:00Z",
                                     "--json"])
        return rc, json.loads(out)

    def test_a_historical_call_without_a_policy_is_marked_historical(self):
        rc, j = self._run(with_policy=False)
        self.assertEqual(rc, 0)
        self.assertEqual((j.get("verification_time") or {}).get("mode"), "HISTORICAL", j.keys())

    def test_control_with_a_policy_it_is_marked(self):
        rc, j = self._run(with_policy=True)
        self.assertEqual(rc, 0)
        self.assertEqual(j["verification_time"]["mode"], "HISTORICAL")

    def test_without_a_policy_the_policy_statuses_say_not_evaluated(self):
        _rc, j = self._run(with_policy=False)
        vt = j.get("verification_time") or {}
        self.assertEqual((vt.get("current_policy_status"), vt.get("historical_policy_status")),
                         ("NOT_EVALUATED", "NOT_EVALUATED"), vt)

    def test_control_present_mode_without_a_policy_carries_no_mark(self):
        env, pub, aud, nonce, _sk = R6B6._signed_receipt()
        with tempfile.TemporaryDirectory() as tmp:
            rp = R6B6._write(tmp, "r.json", env)
            rc, out = R6B6._cli_run(["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud,
                                     "--nonce", nonce, "--json"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("verification_time", json.loads(out))


class R6b7EnclaveHistoricalMarked(unittest.TestCase):
    """The sibling: `verify-enclave --verification-time` is marked HISTORICAL in JSON and in text."""

    def _run(self, *extra):
        from proofbundle.cli import main  # noqa: PLC0415
        case = N49B.Cx05VerifyEnclaveCliPinsTheEvaluationTime()
        with tempfile.TemporaryDirectory() as tmp:
            rcpt, eatp, vkey = case._setup(tmp)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = main(case._argv(rcpt, eatp, vkey, *extra))
        return rc, out.getvalue()

    def test_the_json_names_the_historical_instant(self):
        rc, out = self._run("--verification-time", "2020-09-14T00:00:00Z", "--json")
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(out).get("verification_time"),
                         {"mode": "HISTORICAL", "time": "2020-09-14T00:00:00Z"})

    def test_the_text_names_the_historical_instant(self):
        rc, out = self._run("--verification-time", "2020-09-14T00:00:00Z")
        self.assertEqual(rc, 0, out)
        self.assertIn("VERIFICATION_TIME: HISTORICAL (2020-09-14T00:00:00Z)", out)

    def test_control_without_the_flag_no_mark(self):
        rc, out = self._run("--json")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("verification_time", json.loads(out))
        rc, out = self._run()
        self.assertNotIn("VERIFICATION_TIME", out)


if __name__ == "__main__":
    unittest.main()
