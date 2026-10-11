"""6.2.1 R6b-4: one evaluation instant per verification: the policy lifetime is judged at the same clock reading as
the receipt, without truncating it to the whole second (``decision.py``). Both sides of a sub-second
``valid_from`` / ``valid_until`` boundary are judged correctly.

Red at v6.2.0.
"""



from __future__ import annotations

import base64
import sys
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_security_fix_620_zeit_r6a as R6A  # noqa: E402

from proofbundle import decision as _decision  # noqa: E402
from proofbundle.decision import verify_decision_receipt  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")


_T0 = 1767225600   # 2026-01-01T00:00:00Z


def _decision_at(clock: float, boundary: dict):
    env, pub, aud, nonce, _sk = R6A._signed_receipt()      # no expiresAt
    pol = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6b-4",
           "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub}]}, **boundary}
    with mock.patch.object(_decision, "time", SimpleNamespace(time=lambda: clock)):
        return verify_decision_receipt(env, base64.b64decode(pub), strict=True, expected_audience=aud,
                                       expected_nonce=nonce, policy=pol, now=None)


class R6b4OneUntruncatedInstant(unittest.TestCase):
    def test_a_policy_ended_half_a_second_ago_is_expired(self):
        r = _decision_at(_T0 + 0.75, {"valid_until": "2026-01-01T00:00:00.500000Z"})
        self.assertIsNot(r["policy_ok"], True)
        self.assertIsNot(r["ok"], True)
        self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True)

    def test_a_policy_begun_a_quarter_second_ago_is_valid(self):
        r = _decision_at(_T0 + 0.75, {"valid_from": "2026-01-01T00:00:00.500000Z"})
        self.assertIs(r["policy_ok"], True, "an honest positive must not flip at a sub-second valid_from")

    def test_control_before_the_sub_second_end_is_valid(self):
        self.assertIs(_decision_at(_T0 + 0.25, {"valid_until": "2026-01-01T00:00:00.500000Z"})["policy_ok"], True)

    def test_control_a_whole_second_after_the_end_is_expired(self):
        self.assertIs(_decision_at(_T0 + 1.0, {"valid_until": "2026-01-01T00:00:00.500000Z"})["policy_ok"], False)


if __name__ == "__main__":
    unittest.main()
