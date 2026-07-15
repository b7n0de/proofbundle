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

    def test_issuer_must_be_the_signing_key(self):
        # the core binding: the claim's `issuer` fingerprint MUST be the key that signed the bundle. A
        # hand-signed claim declaring key B as issuer but signed by key A keeps a VALID signature, yet must
        # NOT decode (the issuer-binding rejection branch was untested).
        from proofbundle.emit import emit_bundle
        signer_a, signer_b = generate_signer(), generate_signer()
        claim, _ = _claim(signer_a)
        good = decode_eval_claim(emit_eval_receipt(claim, signer_a))
        c = dict(good)
        c["issuer"] = issuer_fingerprint(signer_b)          # declare B ...
        bundle = emit_bundle(canonicalize(c), signer_a)     # ... but sign with A
        self.assertTrue(verify_bundle(bundle).ok, "signature must still verify")
        self.assertIsNone(decode_eval_claim(bundle),
                          "a claim whose issuer is not the signing key must not decode")

    def test_decode_rejects_bad_comparator_and_threshold(self):
        # release-review CRITICAL: emit_eval_receipt signs a hand-built claim WITHOUT build_eval_claim's checks,
        # so decode_eval_claim must enforce comparator-enum + decimal-threshold at the verify boundary — else a
        # downstream value-consistency check silently no-ops on comparator "==" / non-finite threshold "inf".
        signer = generate_signer()
        for key, bad in (("comparator", "=="), ("comparator", "~="),
                         ("threshold", "inf"), ("threshold", "nan"), ("threshold", "1e5")):
            claim, _ = _claim(signer)
            claim[key] = bad
            bundle = emit_eval_receipt(claim, signer)
            self.assertTrue(verify_bundle(bundle).ok, f"{key}={bad}: bundle still signs/verifies")
            self.assertIsNone(decode_eval_claim(bundle), f"{key}={bad}: claim must NOT decode")

    def test_decode_enforces_required_and_unknown_fields(self):
        # F3 (v1.9.2): the exact key set is a VERIFY-path invariant, not only an emit-side one.
        # emit_eval_receipt enforces _REQUIRED/_OPTIONAL, but a hand-signed claim (emit_bundle over a
        # canonicalized dict) bypasses that path — previously such a claim decoded fine (the emit-vs-
        # verify asymmetry class the project documents). The signature stays valid; only decode rejects.
        from proofbundle.emit import emit_bundle
        signer = generate_signer()
        claim, _ = _claim(signer)
        good = decode_eval_claim(emit_eval_receipt(claim, signer))
        self.assertIsNotNone(good)
        # (a) a claim missing a required field must NOT decode (issuer is checked separately, exclude it)
        for drop in ("timestamp", "suite", "assurance_level", "n", "comparator"):
            c = {k: v for k, v in good.items() if k != drop}
            bundle = emit_bundle(canonicalize(c), signer)
            self.assertTrue(verify_bundle(bundle).ok, f"drop {drop}: signature must still verify")
            self.assertIsNone(decode_eval_claim(bundle), f"missing {drop}: claim must NOT decode")
        # (b) a claim carrying an unknown field must NOT decode
        c = dict(good)
        c["totally_unknown_field"] = "x"
        bundle = emit_bundle(canonicalize(c), signer)
        self.assertTrue(verify_bundle(bundle).ok, "unknown field: signature must still verify")
        self.assertIsNone(decode_eval_claim(bundle), "unknown field: claim must NOT decode")

    def test_decode_reads_path_once_no_toctou(self):
        # CRITICAL (release review): decode_eval_claim(path) must resolve the path to a dict EXACTLY ONCE and
        # verify + parse the SAME object. A second re-read is a TOCTOU (CWE-367) file-race window that could return
        # content whose signature was never checked. Pin the read count so the double-read cannot silently return.
        import os
        import tempfile
        from unittest import mock

        import proofbundle.evalclaim as ec
        signer = generate_signer()
        claim, _ = _claim(signer)
        bundle = emit_eval_receipt(claim, signer)
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh)
        try:
            real = ec.load_bundle
            calls = {"n": 0}

            def _counting(p):
                calls["n"] += 1
                return real(p)
            with mock.patch.object(ec, "load_bundle", _counting):
                decoded = ec.decode_eval_claim(path)
            self.assertIsNotNone(decoded)
            self.assertEqual(calls["n"], 1, "decode_eval_claim must read the path exactly once (no TOCTOU re-read)")
        finally:
            os.unlink(path)

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

    def test_deep_nesting_no_raw_recursion_crash(self):
        # WP-H4 (6-lens review): a pathologically deep-nested claim payload must NEVER surface an
        # uncaught RecursionError (CWE-674) — the crash was reachable from decode_eval_claim /
        # hf_evals.verify_eval_results_entry / policy.evaluate_policy / CLI emit-eval. The contract is
        # "no raw RecursionError": either the input is cleanly mapped to EvalClaimError (via the shared
        # loads_strict) or a given interpreter parses it without hitting its limit — both are fine; a
        # raw RecursionError is the regression. (Version-robust: 3.12+ changed recursion handling, so a
        # fixed depth may or may not hit the limit — the security property is invariant.)
        from proofbundle.evalclaim import load_claim_text
        deep = "[" * 100000 + "]" * 100000
        try:
            load_claim_text(deep)
        except EvalClaimError:
            pass
        except RecursionError:
            self.fail("uncaught RecursionError — H4 regression (must be mapped to EvalClaimError)")

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

    def test_evaluation_card_sha256_round_trips_through_decode(self):
        # Finding 18 (additive): the new optional evaluation_card_sha256 field survives the full
        # emit->verify->decode path unchanged, and its ABSENCE from a claim (the common case) is
        # unaffected — decode still succeeds and the key is simply not present.
        signer = generate_signer()
        digest = "ab" * 32
        claim, _ = _claim(signer)
        claim["evaluation_card_sha256"] = digest
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["evaluation_card_sha256"], digest)

        claim_without, _ = _claim(signer)
        bundle2 = emit_eval_receipt(claim_without, signer)
        decoded2 = decode_eval_claim(bundle2)
        self.assertIsNotNone(decoded2)
        self.assertNotIn("evaluation_card_sha256", decoded2)

    def test_tamper_red(self):
        signer = generate_signer()
        claim, _ = _claim(signer)
        bundle = emit_eval_receipt(claim, signer)
        bundle["payload_b64"] = base64.b64encode(b'{"tampered":true}').decode("ascii")
        self.assertFalse(verify_bundle(bundle).ok)
        self.assertIsNone(decode_eval_claim(bundle))


if __name__ == "__main__":
    unittest.main()
