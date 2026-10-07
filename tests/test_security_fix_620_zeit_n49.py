"""Nachtrag 49 (`KRAXO-CLOUD-N49-ZEIT-UND-GUELTIGKEIT-01`, Z309 / 6.2.0) — time and validity.

Class: a declared validity/freshness field is allowed in the format but never part of the verdict, OR an
artifact time is treated as the evaluation time. One evaluation time per call: the `now` parameter when the
relying party supplies it, else (decision) the clock read once; an artifact time is never the evaluation time.

Owner choice A: K4-01..K4-04 before the tag; K4-05 (RFC 3161) after the tag, untouched here. Only fail-closed
behaviour and the in-validity controls are tested, each with a FIXED evaluation time (never the wall clock), so
the gegenproben are deterministic. Red at the Codex base e37e872b for each finding, green after.

K4-01 decision.py: a declared validity.expiresAt was never read; an expired, signed receipt verified ok=True.
K4-02 kbjwt.py: the KB-JWT iat had no freshness check; any numeric iat gave ok=True.
K4-03 statuslist.py: an expired snapshot stayed ok=True with status_label VALID (fresh=False only a report).
K4-04 experimental/enclave.py: an expired EAT stayed ok=True (fresh=False only a report).
"""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.emit import generate_signer  # noqa: E402


def _raw(sk) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class K4_01ADecisionReceiptExpiresAtIsPartOfTheVerdict(unittest.TestCase):
    """A declared validity.expiresAt is judged against one evaluation time; expired or unreadable fails closed,
    an absent expiresAt is unchanged (freshness_ok None)."""

    def _base(self):
        return json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))

    def _verify(self, *, expires=..., now=None):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        pred = self._base()
        if expires is ...:
            pred["validity"].pop("expiresAt", None)
        else:
            pred["validity"]["expiresAt"] = expires
        aud, nonce = pred["validity"]["audience"][0], pred["validity"]["nonce"]
        sk = generate_signer()
        env = emit_decision_receipt(pred, sk, strict=True)
        return verify_decision_receipt(env, _raw(sk), strict=True, expected_audience=aud,
                                       expected_nonce=nonce, now=now)

    def test_an_expired_receipt_is_not_positive(self):
        r = self._verify(expires="2026-07-09T10:05:00Z", now=1_900_000_000)   # now well after expiry
        self.assertIs(r["ok"], False)
        self.assertIs(r["freshness_ok"], False)

    def test_an_unreadable_expiresat_is_not_positive(self):
        r = self._verify(expires="not-a-timestamp", now=1_700_000_000)
        self.assertIs(r["ok"], False)
        self.assertIs(r["freshness_ok"], False)

    def test_control_a_receipt_within_validity_stays_positive(self):
        r = self._verify(expires="2026-07-09T10:05:00Z", now=1_700_000_000)   # now before expiry
        self.assertIs(r["ok"], True)
        self.assertIs(r["freshness_ok"], True)

    def test_control_a_receipt_without_expiresat_is_unchanged(self):
        r = self._verify(expires=..., now=1_900_000_000)   # no expiresAt → freshness not applicable
        self.assertIs(r["ok"], True)
        self.assertIsNone(r["freshness_ok"])


class K4_02TheKbJwtIatIsJudgedAgainstTheEvaluationTime(unittest.TestCase):
    """When the relying party supplies `now`, the KB-JWT iat is judged: too old or in the future fails closed;
    within the presentation age it stays positive. Without `now` the freshness is not judged (unchanged)."""

    def _presented(self, iat):
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
        claim, _ = build_eval_claim(suite="demo-suite", suite_version="1", metric="acc", comparator=">=",
                                    threshold="0.80", score="0.9", n=100, model_id="m", dataset_id="d",
                                    issuer="placeholder", timestamp="2026-07-09T10:00:00Z",
                                    assurance_level="reproduced")
        issuer, holder = generate_signer(), generate_signer()
        plain = emit_eval_receipt(claim, issuer)
        issuer_field = json.loads(base64.b64decode(plain["payload_b64"]))["issuer"]
        compact = issue_sd_jwt(dict(claim, issuer=issuer_field), issuer,
                               root_b64=plain["merkle"]["root_b64"], exact_score="0.92",
                               holder_public_key=_raw(holder))
        return present_with_key_binding(compact, holder, aud="verifier.example", nonce="n-1", iat=iat)

    def _verify(self, iat, **kw):
        from proofbundle.kbjwt import verify_key_binding
        return verify_key_binding(self._presented(iat), expected_aud="verifier.example",
                                  expected_nonce="n-1", **kw)

    def test_an_iat_older_than_the_default_age_is_not_positive(self):
        iat = 1_780_000_000
        r = self._verify(iat, now=iat + 10 * 86400)   # 10 days old, default age 5 min
        self.assertIs(r["ok"], False)
        self.assertIs(r["fresh"], False)

    def test_an_iat_in_the_future_is_not_positive(self):
        iat = 1_780_000_000
        r = self._verify(iat, now=iat - 10 * 86400)   # evaluated 10 days before it was issued
        self.assertIs(r["ok"], False)
        self.assertIs(r["fresh"], False)

    def test_control_a_fresh_presentation_stays_positive(self):
        iat = 1_780_000_000
        r = self._verify(iat, now=iat + 30)   # within the default 5-minute age
        self.assertIs(r["ok"], True)
        self.assertIs(r["fresh"], True)

    def test_control_an_explicit_age_admits_an_older_presentation(self):
        iat = 1_780_000_000
        r = self._verify(iat, now=iat + 10 * 86400, max_age_seconds=30 * 86400)
        self.assertIs(r["ok"], True)
        self.assertIs(r["fresh"], True)

    def test_control_without_now_freshness_is_not_judged(self):
        iat = 1_780_000_000
        r = self._verify(iat)   # no evaluation time → freshness not applicable, verdict unchanged
        self.assertIs(r["ok"], True)
        self.assertIsNone(r["fresh"])


class K4_03AnExpiredStatusSnapshotIsNotPositive(unittest.TestCase):
    """fresh False → ok not positive AND no status_label VALID; fresh None (no now, or neither exp nor ttl) is
    unchanged."""

    def _token(self, **kw):
        from proofbundle.statuslist import issue_status_list_token
        return issue_status_list_token([0], uri="https://example.org/status/1",
                                       signer=self._signer, iat=100, **kw)

    def setUp(self):
        self._signer = generate_signer()

    def _verify(self, token, now=None):
        from proofbundle.statuslist import verify_status_snapshot
        return verify_status_snapshot(token, expected_uri="https://example.org/status/1", index=0,
                                      issuer_pubkey=_raw(self._signer), now=now)

    def test_an_expired_snapshot_is_not_positive_and_not_labelled_valid(self):
        r = self._verify(self._token(exp=200), now=201)
        self.assertIs(r["ok"], False)
        self.assertIsNot(r["status_label"], "VALID")
        self.assertIs(r["fresh"], False)

    def test_control_a_fresh_snapshot_stays_positive_and_valid(self):
        r = self._verify(self._token(exp=200), now=150)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["status_label"], "VALID")
        self.assertIs(r["fresh"], True)

    def test_control_without_now_is_unchanged(self):
        r = self._verify(self._token(exp=200), now=None)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["status_label"], "VALID")

    def test_control_an_unbounded_snapshot_cannot_be_judged_stale(self):
        r = self._verify(self._token(), now=10_000)   # neither exp nor ttl → fresh None, ok as today
        self.assertIs(r["ok"], True)
        self.assertIsNone(r["fresh"])


class K4_04AnExpiredEnclaveAttestationIsNotPositive(unittest.TestCase):
    """fresh False → ok not positive; fresh None (no now or no exp) is unchanged."""

    def setUp(self):
        self._signer = generate_signer()
        self._binding = "a" * 64

    def _eat(self, **kw):
        from proofbundle.experimental.enclave import issue_enclave_attestation
        return issue_enclave_attestation(self._binding, self._signer, profile="p", tier="t", **kw)

    def _verify(self, eat, now=None):
        from proofbundle.experimental.enclave import verify_enclave_attestation
        return verify_enclave_attestation(eat, verifier_pubkey=_raw(self._signer),
                                          expected_binding=self._binding, expected_profile="p", now=now)

    def test_an_expired_attestation_is_not_positive(self):
        r = self._verify(self._eat(iat=100, exp=200), now=201)
        self.assertIs(r["ok"], False)
        self.assertIs(r["fresh"], False)

    def test_control_a_fresh_attestation_stays_positive(self):
        r = self._verify(self._eat(iat=100, exp=200), now=150)
        self.assertIs(r["ok"], True)
        self.assertIs(r["fresh"], True)

    def test_control_without_now_is_unchanged(self):
        r = self._verify(self._eat(iat=100, exp=200), now=None)
        self.assertIs(r["ok"], True)

    def test_control_an_unbounded_attestation_cannot_be_judged_stale(self):
        r = self._verify(self._eat(iat=100), now=10_000)   # no exp → fresh None, ok as today
        self.assertIs(r["ok"], True)
        self.assertIsNone(r["fresh"])


if __name__ == "__main__":
    unittest.main()
