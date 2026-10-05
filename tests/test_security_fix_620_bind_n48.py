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
import unittest

from proofbundle.decision import (_rfc8785_bytes, build_decision_statement, emit_decision_receipt,
                                   verify_decision_receipt)
from proofbundle.emit import generate_signer
from proofbundle.policy import evaluate_decision_policy, load_policy

# The WP5 decision-policy fixtures (test keys only) and the Nachtrag 48 bound-result helper.
from _decision_result_binding import bound_decision_result  # type: ignore
from test_decision_policy import _pred, _policy_trusting  # type: ignore


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


if __name__ == "__main__":
    unittest.main()
