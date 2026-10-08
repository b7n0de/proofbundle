"""Nachtrag 48 + 48b (`KRAXO-CLOUD-N48-ERGEBNIS-AN-DIE-GEPRUEFTEN-DATEN-01`,
`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`), Z309 / 6.2.0 security fix.

Same class as Nachtrag 44 F2 / Nachtrag 46: a policy or property takes a verify RESULT and the judged data as
separate arguments and does not bind the two — nor does it check that the result came from this process's real
verifier. Owner choice A: F1-F3 before the tag (F4/F5 are delegated-verifier surfaces, after the tag, untouched).
Measured by this session at the bind-branch base (decision/relation/intoto unchanged from Nachtrag 46's head
40a6a09c and from the Codex base e37e872b).

F1 (decision.py / policy.py): evaluate_decision_policy took verify_result and never read it, so signer_trusted
    and policy_ok came from the caller-supplied signer_public_key_b64 (the pin) alone — an empty, hand-built or
    cross-receipt result with a merely-named signer was trusted. Fix: verify_decision_receipt additively records
    the verified signer and the digest of the exact signed statement bytes, and an origin token, only on a passing
    DSSE signature; evaluate_decision_policy evaluates a decision only when crypto_ok is EXACTLY True (not a total
    `ok` that itself depends on the policy) AND the result's recorded digest equals sha256 of this statement's
    RFC-8785 canonicalization AND the recorded signer equals signer_public_key_b64 AND the origin token is authentic.

Only fail-closed behaviour and its controls are tested here (the test keys come from the WP5 decision helpers).
Red at the bind-branch base for each finding, green after. Catch proof in scratchpad/n48.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

from proofbundle.decision import (_rfc8785_bytes, build_decision_statement, emit_decision_receipt,
                                   verify_decision_receipt)
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import (build_eval_claim, decode_eval_claim, emit_eval_receipt,
                                    issuer_fingerprint)
from proofbundle.intoto import export_svr_dsse, svr_properties
from proofbundle.policy import evaluate_decision_policy, load_policy
from proofbundle.relation import LINEAGE_VERIFIED, evaluate_relations_policy

# The WP5 decision-policy fixtures (test keys only) and the Nachtrag 48 bound-result/lineage/svr helpers.
from _decision_result_binding import bound_decision_result  # type: ignore
from _lineage_binding import bound_lineage, bound_lineage_copy  # type: ignore
from _svr_binding import bound_svr_result  # type: ignore
from test_decision_policy import _pred, _policy_trusting  # type: ignore

_FIXED_SALT = b"\x11" * 16


def _b64pub(signer) -> str:
    return base64.b64encode(signer.public_key().public_bytes_raw()).decode("ascii")


def _keypair():
    s = generate_signer()
    return s, base64.b64encode(s.public_key().public_bytes_raw()).decode("ascii")


class F1ADecisionPolicyResultMustBeBoundToTheStatementAndSigner(unittest.TestCase):
    """F1 counter-probes + controls: evaluate_decision_policy confers signer_trusted / policy_ok only for a
    result this process's verify_decision_receipt produced for exactly this statement and signer."""

    def _statement_and_policy(self):
        signer, pub = _keypair()
        pred = _pred("deny")
        stmt = build_decision_statement(pred)
        return signer, pub, stmt, load_policy(_policy_trusting(pub))

    def test_an_empty_result_confers_no_trust(self):
        _s, pub, stmt, pol = self._statement_and_policy()
        out = evaluate_decision_policy(stmt, {}, pol, signer_public_key_b64=pub)
        self.assertIsNot(out["policy_ok"], True)
        self.assertIsNot(out["signer_trusted"], True)

    def test_a_merely_named_signer_that_never_signed_confers_no_trust(self):
        signer, pub, stmt, _pol = self._statement_and_policy()
        real = verify_decision_receipt(emit_decision_receipt(_pred("deny"), signer),
                                       signer.public_key().public_bytes_raw(), strict=True)
        # a different key, pinned by the policy, but which never signed this statement
        _att, pub_att = _keypair()
        out = evaluate_decision_policy(stmt, real, load_policy(_policy_trusting(pub_att)),
                                       signer_public_key_b64=pub_att)
        self.assertIsNot(out["policy_ok"], True)
        self.assertIsNot(out["signer_trusted"], True)

    def test_a_hand_built_result_with_matching_fields_but_no_origin_is_refused(self):
        _s, pub, stmt, pol = self._statement_and_policy()
        hand = {"crypto_ok": True, "verified_signer_pub_b64": pub,
                "verified_payload_digest": hashlib.sha256(_rfc8785_bytes(stmt)).hexdigest()}
        out = evaluate_decision_policy(stmt, hand, pol, signer_public_key_b64=pub)
        self.assertIsNot(out["policy_ok"], True)
        self.assertIsNot(out["signer_trusted"], True)

    def test_a_result_of_one_statement_does_not_judge_a_different_statement(self):
        signer, pub = _keypair()
        env = emit_decision_receipt(_pred("deny"), signer)
        real = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), strict=True,
                                       policy=load_policy(_policy_trusting(pub)))
        other_stmt = build_decision_statement(_pred("allow"))
        out = evaluate_decision_policy(other_stmt, real, load_policy(_policy_trusting(pub)),
                                       signer_public_key_b64=pub)
        self.assertIsNot(out["policy_ok"], True)

    def test_control_the_bound_result_of_this_statement_is_trusted(self):
        _s, pub, stmt, pol = self._statement_and_policy()
        out = evaluate_decision_policy(stmt, bound_decision_result(stmt, pub), pol, signer_public_key_b64=pub)
        self.assertIs(out["policy_ok"], True)
        self.assertIs(out["signer_trusted"], True)

    def test_control_a_full_verify_stays_positive(self):
        signer, pub = _keypair()
        env = emit_decision_receipt(_pred("deny"), signer)
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), strict=True,
                                    policy=load_policy(_policy_trusting(pub)))
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["policy_ok"], True)
        self.assertIs(r["signer_trusted"], True)
        self.assertIsInstance(r.get("verified_origin"), str)


class F2ARelationSignerMustBeBoundToTheVerifiedSuccessorReceipt(unittest.TestCase):
    """F2 counter-probes + controls: evaluate_relations_policy satisfies relation_signer only for a lineage
    result bound to the verified successor receipt for exactly this key and its relation data. The review's
    required gegenproben: a genuinely verified receipt with foreign relation data under the same signer key,
    and a result of one receipt judged with another key."""

    def _lineage(self, verified_under):
        return {"lineage": LINEAGE_VERIFIED,
                "edges": [{"relation": "supersedes", "targetDigest": "a" * 64, "resolution": LINEAGE_VERIFIED,
                           "verified_under": verified_under}]}

    def _pinned(self, key):
        return {"relation_signer": {"supersedes": {"mode": "pinned", "keys": [key]}}}

    def _codes(self, out):
        return [v["code"] for v in out]

    def test_a_merely_named_key_does_not_satisfy_a_pinned_rule(self):
        key = _b64pub(generate_signer())
        target = _b64pub(generate_signer())
        # a hand-built (unstamped) lineage + the caller-supplied key == the pinned key
        out = evaluate_relations_policy(self._pinned(key), self._lineage(target), successor_key_b64=key)
        self.assertIn("RELATION_SIGNER_UNAUTHORIZED", self._codes(out))

    def test_control_a_bound_lineage_with_a_pinned_member_is_satisfied(self):
        key = _b64pub(generate_signer())
        target = _b64pub(generate_signer())
        lineage = bound_lineage(self._lineage(target), key)
        out = evaluate_relations_policy(self._pinned(key), lineage, successor_key_b64=key)
        self.assertNotIn("RELATION_SIGNER_UNAUTHORIZED", self._codes(out))

    def test_a_verified_receipt_with_foreign_relation_data_under_the_same_key_is_refused(self):
        key = _b64pub(generate_signer())
        target = _b64pub(generate_signer())
        lineage = bound_lineage(self._lineage(target), key)
        # swap in foreign relation data AFTER stamping, keeping the same successor key
        lineage["edges"] = [{"relation": "supersedes", "targetDigest": "b" * 64, "resolution": LINEAGE_VERIFIED,
                             "verified_under": target}]
        out = evaluate_relations_policy(self._pinned(key), lineage, successor_key_b64=key)
        self.assertIn("RELATION_SIGNER_UNAUTHORIZED", self._codes(out))

    def test_a_result_bound_to_one_key_does_not_satisfy_another_key(self):
        key = _b64pub(generate_signer())
        other = _b64pub(generate_signer())
        lineage = bound_lineage_copy(self._lineage(other), key)   # bound to key
        out = evaluate_relations_policy(self._pinned(other), lineage, successor_key_b64=other)
        self.assertIn("RELATION_SIGNER_UNAUTHORIZED", self._codes(out))

    def test_control_a_full_verify_with_a_relation_signer_policy_binds_the_successor(self):
        # the in-verify path stamps the lineage; a bundle without relationship edges has nothing to violate, so
        # a relation_signer policy over it is vacuously satisfied (no RELATION_SIGNER_UNAUTHORIZED).
        signer = generate_signer()
        env = emit_decision_receipt(_pred("deny"), signer)
        r = verify_decision_receipt(
            env, signer.public_key().public_bytes_raw(), strict=True,
            policy=load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t",
                                "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": _b64pub(signer)}]},
                                "relations": {"relation_signer": {"supersedes": {"mode": "pinned",
                                                                                "keys": [_b64pub(signer)]}}}}))
        self.assertIs(r["crypto_ok"], True)
        self.assertNotIn("RELATION_SIGNER_UNAUTHORIZED", r.get("relations_policy_codes") or [])


class F3SvrPropertiesMustBeBoundToTheVerifiedClaim(unittest.TestCase):
    """F3 counter-probes + controls: svr_properties derives a property only for a VerificationResult this
    process's verify_bundle produced (an authentic origin token) whose recorded payload digest equals the
    passed claim's digest under the same fixed JCS encoding verify_bundle recorded over the signed payload.
    A result of one claim combined with a different or mutated claim earns nothing; a hand-built result with
    a matching digest but no origin earns nothing (the review's svr reproducer). export_svr_dsse passes the
    result and the claim of one verified bundle, so its internally-bound positive path stays positive."""

    def _claim(self, signer, *, score="0.99", threshold="0.98", n=500):
        # the decoded eval claim carries the verdict and commitments, not the raw score, so two passing
        # claims differ only by a STORED field (here n, the sample count) — enough for a distinct JCS digest.
        claim, _ = build_eval_claim(
            suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=",
            threshold=threshold, score=score, n=n, model_id="acme/secret-model",
            dataset_id="acme/secret-set", issuer=issuer_fingerprint(signer),
            timestamp="2026-07-05T12:00:00Z", model_salt=_FIXED_SALT, dataset_salt=_FIXED_SALT)
        return claim

    def test_control_a_result_earns_its_properties_for_its_own_verified_claim(self):
        s = generate_signer()
        result, claim = bound_svr_result(self._claim(s), s)
        props = svr_properties(result, claim)
        self.assertIn("PROOFBUNDLE_SIGNATURE_VALID", props)
        self.assertIn("PROOFBUNDLE_RECEIPT_UNCHANGED", props)
        self.assertIn("PROOFBUNDLE_THRESHOLD_MET", props)

    def test_a_result_of_one_claim_earns_nothing_for_a_different_claim(self):
        # the base gap: a good result of receipt A + a different passing claim B emitted B's THRESHOLD_MET
        # under A's crypto. Different claim content -> different JCS digest -> the result does not bind it.
        s = generate_signer()
        result_a, _claim_a = bound_svr_result(self._claim(s, n=500), s)
        _result_b, claim_b = bound_svr_result(self._claim(s, n=250), s)
        self.assertEqual(svr_properties(result_a, claim_b), [])

    def test_a_mutated_claim_with_a_reused_result_earns_nothing(self):
        s = generate_signer()
        result, claim = bound_svr_result(self._claim(s, n=500), s)
        mutated = dict(claim, n=250)   # a stored field changed -> different JCS digest, result still bound to 500
        self.assertEqual(svr_properties(result, mutated), [])

    def test_a_hand_built_result_with_a_matching_digest_but_no_origin_earns_nothing(self):
        # a VerificationResult with passing checks and the exact payload digest, but NOT stamped by this
        # process's verifier (no authentic origin token) earns nothing. Hand-built, not emitted by verify.
        from proofbundle.errors import Check, VerificationResult
        s = generate_signer()
        claim = decode_eval_claim(emit_eval_receipt(self._claim(s), s))
        hand = VerificationResult([Check("ed25519-signature", True), Check("merkle-inclusion", True)])
        hand.verified_payload_digest = hashlib.sha256(_rfc8785_bytes(claim)).hexdigest()
        # deliberately NO stamp_origin()
        self.assertEqual(svr_properties(hand, claim), [])

    def test_control_export_svr_dsse_stays_positive(self):
        s = generate_signer()
        env = export_svr_dsse(emit_eval_receipt(self._claim(s), s), s)
        props = json.loads(base64.b64decode(env["payload"]))["predicate"]["properties"]
        self.assertIn("PROOFBUNDLE_SIGNATURE_VALID", props)
        self.assertIn("PROOFBUNDLE_RECEIPT_UNCHANGED", props)
        self.assertIn("PROOFBUNDLE_THRESHOLD_MET", props)


if __name__ == "__main__":
    unittest.main()
