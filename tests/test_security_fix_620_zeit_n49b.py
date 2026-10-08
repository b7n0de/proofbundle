"""Nachtrag 49b (`KRAXO-CLOUD-N49B-ZEIT-AN-JEDEM-RAND-01`, Z309 / 6.2.0) — time at every edge.

Nachtrag 49 made expired/non-fresh material a negative verdict and gave the decision receipt ONE evaluation
time. N49b closes the edges N49 left open, each measured at the Codex base dbe2dc18 (red) and green after.

CX-01 decision.py: a declared validity.expiresAt whose VALUE is JSON null counted as a MISSING key
      (freshness_ok None, ok True). Value-presence, not key-presence. A present key with an unreadable value
      (null included) must fail closed; only an ABSENT key is not-applicable.
CX-03 policy.evaluate_decision_policy: it had no `now`, so policy_expired/policy_not_yet_valid read the wall
      clock themselves — a decision verified with a pinned evaluation time still judged the policy lifecycle at
      a different, independent instant. One evaluation time per call: verify_decision_receipt threads its `now`.
CX-04 verify_bundle / verify_sdjwt_vc: they had no `now`, so the KB-JWT iat freshness was never judged on the
      composed path (kbjwt.verify_key_binding was called without now). With `now` the stale presentation is no
      longer positive; without it the N49 behaviour is unchanged (fresh None).

CX-02 (decision verify CLI folds freshness into the exit) and CX-05 (verify-enclave CLI evaluation time) are in
test_security_fix_620_zeit_n49b_cli.py. Only fail-closed behaviour and the in-validity controls are tested,
each with a FIXED evaluation time (never the wall clock), so the gegenproben are deterministic.
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import unittest  # noqa: E402

from proofbundle.emit import generate_signer  # noqa: E402

_EXAMPLES = REPO / "examples"


def _raw(sk) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# A POSIX instant well beyond the year-2099 expiresAt the examples use, so the wall clock never reaches it and
# the red@base / green@head split is stable: at base the policy lifecycle is judged at the wall clock (2026,
# before 2099 → not expired); at head it is judged at this pinned instant (after 2099 → expired).
_NOW_AFTER_2099 = 4_200_000_000   # ~2103-01-xx UTC


class Cx01DecisionExpiresAtNullIsPresentNotMissing(unittest.TestCase):
    """A present validity.expiresAt whose value is JSON null fails closed (freshness_ok False, ok False); only
    an ABSENT key is not-applicable (freshness_ok None, ok True)."""

    def _base(self) -> dict:
        return json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))

    def _verify(self, *, expires=..., now=None):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        pred = self._base()
        if expires is ...:
            pred["validity"].pop("expiresAt", None)
        else:
            pred["validity"]["expiresAt"] = expires   # may be None → serialised as JSON null (key present)
        aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        return verify_decision_receipt(env, _raw(sk), strict=True, expected_audience=aud,
                                       expected_nonce=nonce, now=now)

    def test_a_null_expiresat_is_not_positive(self):
        # The key is present, the value is unreadable (null) → fail-closed, just like any other unreadable value.
        r = self._verify(expires=None, now=1_700_000_000)
        self.assertIs(r["ok"], False)
        self.assertIs(r["freshness_ok"], False)

    def test_control_an_absent_expiresat_is_unchanged(self):
        r = self._verify(expires=..., now=1_900_000_000)   # no key → not applicable
        self.assertIs(r["ok"], True)
        self.assertIsNone(r["freshness_ok"])

    def test_control_a_readable_expiresat_within_validity_stays_positive(self):
        r = self._verify(expires="2099-07-09T10:05:00Z", now=1_700_000_000)
        self.assertIs(r["ok"], True)
        self.assertIs(r["freshness_ok"], True)


class Cx03DecisionPolicyLifecycleUsesTheOneEvaluationTime(unittest.TestCase):
    """evaluate_decision_policy judges the policy lifecycle (valid_until/valid_from) at the evaluation time it is
    given, not an independent wall-clock read. verify_decision_receipt threads its `now` to that edge."""

    def _base(self) -> dict:
        return json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))

    def _verify(self, policy, *, now=None):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        pred = self._base()
        pred["validity"].pop("expiresAt", None)   # isolate the policy-lifecycle axis from CX-01
        aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        pub_b64 = _b64(_raw(sk))
        pol = {"decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub_b64}]}, **policy}
        r = verify_decision_receipt(env, _raw(sk), strict=True, expected_audience=aud,
                                    expected_nonce=nonce, policy=pol, now=now)
        return r

    def test_an_evaluation_time_after_valid_until_expires_the_policy(self):
        # valid_until 2099 is in the FUTURE at the wall clock (base: policy_ok True) and in the PAST at the
        # pinned instant (head: policy_ok False) — the one evaluation time reaches the policy lifecycle.
        r = self._verify({"valid_until": "2099-01-01T00:00:00Z"}, now=_NOW_AFTER_2099)
        self.assertIs(r["policy_ok"], False)

    def test_control_within_the_policy_window_stays_positive(self):
        r = self._verify({"valid_until": "2099-01-01T00:00:00Z"}, now=1_700_000_000)
        self.assertIs(r["policy_ok"], True)

    def test_control_without_now_reads_the_wall_clock_unchanged(self):
        # No evaluation time → the policy lifecycle is judged at the wall clock, the N49 behaviour (2099 future).
        r = self._verify({"valid_until": "2099-01-01T00:00:00Z"}, now=None)
        self.assertIs(r["policy_ok"], True)

    def test_direct_evaluate_decision_policy_honours_the_datetime_now(self):
        from proofbundle import dsse
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        from proofbundle.policy import evaluate_decision_policy
        pred = self._base()
        pred["validity"].pop("expiresAt", None)
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        r = verify_decision_receipt(env, _raw(sk), strict=True)
        self.assertIs(r["crypto_ok"], True)
        statement = json.loads(dsse.load_payload(env))   # load_payload returns bytes; the statement is its JSON
        pub_b64 = _b64(_raw(sk))
        pol = {"decision_receipt": {"trusted_decision_makers": [{"public_key_b64": pub_b64}]},
               "valid_until": "2099-01-01T00:00:00Z"}
        after = datetime(2103, 1, 1, tzinfo=timezone.utc)
        before = datetime(2026, 1, 1, tzinfo=timezone.utc)
        pe_after = evaluate_decision_policy(statement, r, pol, signer_public_key_b64=pub_b64, now=after)
        pe_before = evaluate_decision_policy(statement, r, pol, signer_public_key_b64=pub_b64, now=before)
        self.assertIs(pe_after["policy_ok"], False)
        self.assertIs(pe_before["policy_ok"], True)


class Cx04ComposedPathsJudgeTheKbJwtFreshness(unittest.TestCase):
    """verify_bundle / verify_sdjwt_vc thread `now` to kbjwt.verify_key_binding: a stale KB-JWT presentation is
    no longer a positive key binding; without `now` the freshness is not judged (N49 behaviour unchanged)."""

    _IAT = 1_780_000_000

    def _eval_bundle_with_kbjwt(self):
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
        signer, holder = generate_signer(), generate_signer()
        ev_claim, _ = build_eval_claim(
            suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
            score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
            timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
        plain = emit_eval_receipt(ev_claim, signer)
        real_root = (plain.get("merkle") or {}).get("root_b64")
        sd_claim = json.loads(base64.b64decode(plain["payload_b64"]))
        compact = issue_sd_jwt(sd_claim, signer, root_b64=real_root, exact_score="0.9",
                               holder_public_key=_raw(holder))
        presented = present_with_key_binding(compact, holder, aud="v.example", nonce="n", iat=self._IAT)
        vc = {"compact": presented, "issuer_public_key_b64": _b64(_raw(signer))}
        return emit_eval_receipt(ev_claim, signer, sd_jwt=vc)

    @staticmethod
    def _kb_check(result):
        return next((c for c in result.checks if c.name == "sd-jwt-key-binding"), None)

    def test_a_stale_presentation_is_no_longer_a_positive_key_binding(self):
        from proofbundle import verify_bundle
        bundle = self._eval_bundle_with_kbjwt()
        r = verify_bundle(bundle, expected_aud="v.example", expected_nonce="n",
                          now=self._IAT + 10 * 86400)   # 10 days after iat, default age 300 s
        kb = self._kb_check(r)
        self.assertIsNotNone(kb)
        self.assertIsNot(kb.ok, True)

    def test_control_a_fresh_presentation_is_a_positive_key_binding(self):
        from proofbundle import verify_bundle
        bundle = self._eval_bundle_with_kbjwt()
        r = verify_bundle(bundle, expected_aud="v.example", expected_nonce="n", now=self._IAT + 30)
        kb = self._kb_check(r)
        self.assertIsNotNone(kb)
        self.assertIs(kb.ok, True)

    def test_control_without_now_the_freshness_is_not_judged(self):
        from proofbundle import verify_bundle
        bundle = self._eval_bundle_with_kbjwt()
        r = verify_bundle(bundle, expected_aud="v.example", expected_nonce="n")
        kb = self._kb_check(r)
        self.assertIsNotNone(kb)
        self.assertIs(kb.ok, True)   # N49 behaviour: no now → kb fresh not judged, binding stays positive


if __name__ == "__main__":
    unittest.main()
