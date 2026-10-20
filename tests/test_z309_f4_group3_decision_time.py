"""Z309 review round 6a, F4 group 3, at the merged head: a genuine and a foreign decision result, a valid and an
expired policy and receipt, in present and in historical mode, plus the four time counter-probes of R6a-4 to 7.

Part A drives verify_decision_receipt over receipt {no expiry, expires 2099, expires 2021} times policy
{valid until 2099, valid until 2021} times mode {present, historical 2020}. The verdict (ok) follows the one
evaluation time; safeForAutomation is present-tense (SPEC 399-410): it is positive only when the policy is valid
TODAY and the receipt is not expired TODAY, whatever the evaluation time.

Part B drives evaluate_decision_policy with the genuine result of the statement and with the result of a different
statement by the same signer, under a valid and an expired policy: only genuine plus valid is positive (N48).

The four time counter-probes (R6a-4 historical label and present-tense automation, R6a-5 malformed now, R6a-6 one
clock reading, R6a-7 no truncated fraction) are the cases of tests/test_security_fix_620_zeit_r6a.py; Part C
repeats each once at this head through the same helpers so all group-3 proofs sit on one commit.
"""
from __future__ import annotations

import base64
import itertools
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from proofbundle import decision as _decision
from proofbundle.decision import build_decision_statement, emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.policy import evaluate_decision_policy, load_policy

from test_decision_policy import _policy_trusting, _pred  # type: ignore
from test_security_fix_620_zeit_r6a import _Y2020, _Y2022, _cli_run, _policy, _signed_receipt, _write  # type: ignore

_TODAY = datetime.now(timezone.utc)
_FUTURE = "2099-01-01T00:00:00Z"
_PAST = "2021-01-01T00:00:00Z"


class PartAReceiptTimesPolicyTimesMode(unittest.TestCase):

    def test_every_cell(self):
        for expires, valid_until, now in itertools.product((None, _FUTURE, _PAST), (_FUTURE, _PAST), (None, _Y2020)):
            with self.subTest(expires=expires, policy_valid_until=valid_until, historical=now is not None):
                env, pub, aud, nonce, _sk = _signed_receipt(with_expires=expires)
                r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                            expected_nonce=nonce, policy=_policy(pub, valid_until), now=now)
                if now is None:
                    expected_ok = expires != _PAST and valid_until != _PAST
                else:
                    expected_ok = True   # in 2020 every receipt is fresh and every policy valid
                self.assertIs(r["ok"], expected_ok, r["errors"])
                valid_today = expires != _PAST and valid_until != _PAST
                self.assertIs(r["automation"]["safeForAutomation"], valid_today and expected_ok,
                              "safeForAutomation is present-tense: positive only when policy AND receipt are "
                              f"valid today; blockers {r['automation'].get('automationBlockers')}")
                if now is not None and expires == _PAST:
                    # R6b-6: in historical mode a receipt expired today blocks the present automation release
                    # with its own blocker, also under a policy valid today.
                    self.assertIn("RECEIPT_EXPIRED", r["automation"].get("automationBlockers") or [])


class PartBGenuineOrForeignResultTimesPolicyLifecycle(unittest.TestCase):

    def test_every_cell(self):
        signer = generate_signer()
        pub = base64.b64encode(signer.public_key().public_bytes_raw()).decode("ascii")
        stmt = build_decision_statement(_pred("deny"))
        genuine = verify_decision_receipt(emit_decision_receipt(_pred("deny"), signer),
                                          signer.public_key().public_bytes_raw(), strict=True)
        foreign = verify_decision_receipt(emit_decision_receipt(_pred("allow"), signer),
                                          signer.public_key().public_bytes_raw(), strict=True)
        for (name, result), valid_until in itertools.product((("genuine", genuine), ("foreign", foreign)),
                                                             (_FUTURE, _PAST)):
            with self.subTest(result=name, policy_valid_until=valid_until):
                pol = dict(_policy_trusting(pub), valid_until=valid_until)
                out = evaluate_decision_policy(stmt, result, load_policy(pol), signer_public_key_b64=pub, now=_TODAY)
                if name == "genuine" and valid_until == _FUTURE:
                    self.assertIs(out["policy_ok"], True, out["errors"])
                else:
                    self.assertIsNot(out["policy_ok"], True, out["errors"])


class PartCTheFourTimeCounterProbesAtThisHead(unittest.TestCase):

    def test_r6a_4_historical_mode_is_labelled_and_present_tense(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            env, pub, aud, nonce, _sk = _signed_receipt()
            rc, out = _cli_run(["decision", "verify", _write(tmp, "r.json", env), "--pub", pub, "--strict", "--aud",
                                aud, "--nonce", nonce, "--policy", _write(tmp, "p.json", _policy(pub, _PAST)), "--json",
                                "--verification-time", "2020-01-01T00:00:00Z"])
            rep = json.loads(out)
            self.assertEqual(rc, 0, out)
            self.assertIs(rep["automation"]["safeForAutomation"], False)
            self.assertEqual(rep["verification_time"]["mode"], "HISTORICAL")

    def test_r6a_5_a_malformed_now_fails_closed(self):
        env, pub, aud, nonce, _sk = _signed_receipt()
        for now in ("bad", True, 253402300800):
            with self.subTest(now=now):
                r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                            expected_nonce=nonce, policy=_policy(pub, _FUTURE), now=now)
                self.assertIs(r["ok"], False)

    def test_r6a_6_an_omitted_now_is_one_clock_reading(self):
        env, pub, aud, nonce, _sk = _signed_receipt()
        pol = dict(_policy(pub, _FUTURE), valid_from="2020-01-01T00:00:00Z")
        with mock.patch.object(_decision, "time", SimpleNamespace(time=lambda: float(_Y2020 - 86400))):
            r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                        expected_nonce=nonce, policy=pol, now=None)
        self.assertIs(r["policy_ok"], False)
        with mock.patch.object(_decision, "time", SimpleNamespace(time=lambda: float(_Y2022))):
            r = verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                        expected_nonce=nonce, policy=pol, now=None)
        self.assertIs(r["policy_ok"], True, "control inside the window")

    def test_r6a_7_a_fractional_verification_time_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            env, pub, aud, nonce, _sk = _signed_receipt(with_expires="2026-01-01T00:00:00.500000Z")
            rp = _write(tmp, "r.json", env)
            base = ["decision", "verify", rp, "--pub", pub, "--strict", "--aud", aud, "--nonce", nonce]
            self.assertEqual(_cli_run(base + ["--verification-time", "2026-01-01T00:00:00.750000Z"])[0], 2)
            self.assertEqual(_cli_run(base + ["--verification-time", "2026-01-01T00:00:00Z"])[0], 0, "control")


if __name__ == "__main__":
    unittest.main()
