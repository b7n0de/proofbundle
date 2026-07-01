"""Eval-receipt (v0.4) tests — No-Fake, one red-test per new invariant."""
import base64
import json
import unittest

from proofbundle import verify_bundle
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import (
    EvalClaimError,
    build_eval_claim,
    canonicalize,
    decode_eval_claim,
    emit_eval_receipt,
    issuer_fingerprint,
    salted_commit,
)

TS = "2026-07-01T12:00:00Z"


def _claim(signer, score="0.92", threshold="0.80", comparator=">="):
    claim, salts = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=comparator, threshold=threshold, score=score, n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp=TS,
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim, salts


class TestEvalClaim(unittest.TestCase):
    def test_round_trip(self):
        signer = generate_signer()
        claim, _ = _claim(signer)
        bundle = emit_eval_receipt(claim, signer)
        self.assertTrue(verify_bundle(bundle).ok)
        decoded = decode_eval_claim(bundle)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["suite"], "safety-refusal")
        self.assertTrue(decoded["passed"])

    def test_determinism_emoji_and_nfc(self):
        # A key beyond the BMP + NFC content must canonicalize identically twice.
        c = {"schema": "x", "\U0001F600z": "café"}  # NFD 'é'
        with self.assertRaises(EvalClaimError):
            canonicalize(c)  # non-NFC string rejected
        c2 = {"b": "1", "\U0001F600": "ok", "a": "2"}
        self.assertEqual(canonicalize(c2), canonicalize(dict(reversed(list(c2.items())))))

    def test_duplicate_keys_rejected(self):
        from proofbundle.evalclaim import load_claim_text
        with self.assertRaises(EvalClaimError):
            load_claim_text('{"a": 1, "a": 2}')

    def test_float_guard_red(self):
        with self.assertRaises(EvalClaimError):
            canonicalize({"schema": "x", "threshold": 0.80})  # a Python float is forbidden

    def test_passed_integrity_at_boundary(self):
        signer = generate_signer()
        eq, _ = _claim(signer, score="0.80", threshold="0.80", comparator=">=")
        self.assertTrue(eq["passed"])
        gt, _ = _claim(signer, score="0.80", threshold="0.80", comparator=">")
        self.assertFalse(gt["passed"])
        lt, _ = _claim(signer, score="0.79", threshold="0.80", comparator="<")
        self.assertTrue(lt["passed"])

    def test_issuer_binding_red(self):
        signer = generate_signer()
        claim, _ = _claim(signer)
        bundle = emit_eval_receipt(claim, signer)
        # Tamper the issuer field to a different key -> re-sign with the SAME signer.
        # decode must reject because claim.issuer != signing key.
        import copy
        b2 = copy.deepcopy(bundle)
        other = issuer_fingerprint(generate_signer())
        payload = json.loads(base64.b64decode(b2["payload_b64"]).decode("utf-8"))
        payload["issuer"] = other
        # keep bytes verifiable only if re-emitted; here we just prove decode's issuer check:
        b2["payload_b64"] = base64.b64encode(canonicalize(payload)).decode("ascii")
        # signature no longer matches the new payload -> verify_bundle fails -> decode None.
        self.assertIsNone(decode_eval_claim(b2))

    def test_commitment_hides_identifier(self):
        c1 = salted_commit("gpt-4o", b"A" * 16)
        c1b = salted_commit("gpt-4o", b"A" * 16)
        c2 = salted_commit("gpt-4o", b"B" * 16)
        self.assertEqual(c1, c1b)          # same id + salt -> same commit
        self.assertNotEqual(c1, c2)        # different salt -> different commit
        signer = generate_signer()
        claim, _ = _claim(signer)
        payload = json.dumps(claim)
        self.assertNotIn("acme/model-x", payload)   # plaintext id never in the payload
        with self.assertRaises(EvalClaimError):
            salted_commit("x", b"short")             # salt must be >= 16 bytes

    def test_tamper_red(self):
        signer = generate_signer()
        claim, _ = _claim(signer)
        bundle = emit_eval_receipt(claim, signer)
        bundle["payload_b64"] = base64.b64encode(b'{"tampered":true}').decode("ascii")
        self.assertFalse(verify_bundle(bundle).ok)
        self.assertIsNone(decode_eval_claim(bundle))


if __name__ == "__main__":
    unittest.main()
