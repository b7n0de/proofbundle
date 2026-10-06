"""Nachtrag 46b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`), Z309 / 6.2.0 security fix.

External contract review of Nachtrag 46/48 (owner choice A, adopt all points). The findings were measured by
this session at the Nachtrag 46 head 40a6a09c518b6ba1099cc1478ea1719788daa689.

Review point 1 (binding the state OUTSIDE the signed payload). The Nachtrag 46 result binding covers the
payload digest and the signer, which pin the SIGNED bytes only. The stated Merkle root is not signed, so a
bundle re-anchoring the SAME payload under a DIFFERENT root (same signer, same payload digest, which the
Nachtrag 46 binding alone accepts) inherited a prior positive root-authenticity verdict. evaluate_policy now
adopts a positive root-authenticity check only for the exact root the result verified.
    - counter-probe (red at 40a6a09c, green after): same payload and signer, a different stated Merkle root
      -> policy:authenticated_root not positive, the policy not positive.
    - gegenprobe (already fail-closed at 40a6a09c by Nachtrag 44 + 46, measured): same payload and signer,
      the sd_jwt_vc swapped in from a different bundle -> no SD-JWT rule positive. The sd_jwt_vc block needs
      no new captured field: a judge's SD-JWT rules bind to this bundle through the verified signer (the
      SD-JWT issuer MUST be the bundle signer, Nachtrag 44), which Nachtrag 46 takes from the result.

Review point 2 (the result's provenance). Matching binding fields are no proof of a verification run: a
hand-built or post-stamp-mutated VerificationResult carrying a matching signer and payload digest passed.
evaluate_policy now requires the result to carry an authentic per-process ORIGIN token that this process's
verify_bundle stamped over exactly the fields the result now holds.
    - counter-probe (red at 40a6a09c, green after): a hand-built result with a matching signer and digest,
      and a real result whose captured fields were changed after stamping -> policy:result_origin not
      positive.
    - control: the real result verify_bundle returned for this bundle stays positive.

Review point 3 adapts the Nachtrag 46 F1 gegenprobe, which lives in test_security_fix_620_bind_n46.py.

Only fail-closed behaviour and its controls are tested; the attack inputs come from the Nachtrag 44 test
helpers with their test keys. Red at 40a6a09c518b6ba1099cc1478ea1719788daa689 for the origin and Merkle
classes, green after; the SD-JWT swap is a gegenprobe already fail-closed at that commit. Catch proof in
scratchpad/n46b.
"""
from __future__ import annotations

import base64
import copy
import unittest

from proofbundle import verify_bundle
from proofbundle.errors import VerificationResult
from proofbundle.policy import evaluate_policy

# The Nachtrag 44 fixtures (test keys only): an honest eval receipt whose one key signs both the bundle and
# the SD-JWT, plus the KB-JWT audience/nonce.
from test_security_fix_620_bind_n44 import _AUD, _NONCE, _control_bundle  # type: ignore

_SD_POLICY = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n46b",
              "sd_jwt": {"require_key_binding_when_cnf_present": True, "require_nonce": True,
                         "expected_aud": _AUD}}
_MERKLE_POLICY = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n46b",
                  "merkle": {"require_authenticated_root": True}}


def _named_check(out: dict, name: str):
    return next((c for c in out.get("checks", []) if c["name"] == name), None)


class TheResultMustComeFromThisVerifier(unittest.TestCase):
    """Review point 2: a result that merely carries matching binding fields is not a verification. A
    hand-built or post-stamp-mutated VerificationResult is refused at the origin gate; the real result the
    verifier returned stays positive."""

    def test_a_hand_built_result_with_matching_fields_is_refused(self):
        bundle = _control_bundle()
        good = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertIs(good.ok, True)
        # a hand-built result copying the checks and the Nachtrag 46 binding fields, but with no origin token
        hand = VerificationResult(checks=list(good.checks))
        hand.verified_signer_pub = good.verified_signer_pub
        hand.verified_payload_digest = good.verified_payload_digest
        out = evaluate_policy(bundle, hand, copy.deepcopy(_SD_POLICY))
        self.assertIsNot(out["policy_ok"], True)
        origin = _named_check(out, "policy:result_origin")
        self.assertIsNotNone(origin)
        self.assertIs(origin["ok"], False)
        self.assertIn("origin", out.get("reason", ""))

    def test_a_result_mutated_after_stamping_is_refused(self):
        bundle = _control_bundle()
        good = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)
        # change a captured field the Nachtrag 46 signer+digest gate does NOT check, so only the origin token
        # catches the tampering (the signer and payload digest still match this bundle).
        good.verified_merkle_root = b"\x22" * 32
        self.assertIs(good.origin_authentic(), False)
        out = evaluate_policy(bundle, good, copy.deepcopy(_SD_POLICY))
        self.assertIsNot(out["policy_ok"], True)
        origin = _named_check(out, "policy:result_origin")
        self.assertIsNotNone(origin)
        self.assertIs(origin["ok"], False)

    def test_control_the_real_result_is_positive(self):
        bundle = _control_bundle()
        good = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertIs(good.origin_authentic(), True)
        out = evaluate_policy(bundle, good, copy.deepcopy(_SD_POLICY))
        self.assertIs(out["policy_ok"], True)
        # the origin gate adds no failing check on a real result (absent == not gated closed)
        self.assertIsNone(_named_check(out, "policy:result_origin"))


class AnOutOfPayloadMerkleRootIsNotCarriedOver(unittest.TestCase):
    """Review point 1 (Merkle): the stated Merkle root is not in the signed payload, so payload + signer
    equality does not pin it. A positive root-authenticity verdict is adopted only for the root the result
    verified; a bundle re-anchoring the same payload under a different root inherits nothing."""

    def test_a_good_result_does_not_authenticate_a_rewrapped_root(self):
        bundle = _control_bundle()
        root_b64 = bundle["merkle"]["root_b64"]
        good = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE, expected_root_b64=root_b64)
        self.assertIs(next(c.ok for c in good.checks if c.name == "root-authenticity"), True)
        rewrapped = copy.deepcopy(bundle)
        rewrapped["merkle"]["root_b64"] = base64.b64encode(b"\x11" * 32).decode("ascii")
        # same signed payload, same signer, a different (unsigned) stated root: the Nachtrag 46 binding alone
        # would accept it.
        self.assertEqual(rewrapped["payload_b64"], bundle["payload_b64"])
        self.assertEqual(rewrapped["signature"]["public_key_b64"], bundle["signature"]["public_key_b64"])
        self.assertNotEqual(rewrapped["merkle"]["root_b64"], root_b64)
        out = evaluate_policy(rewrapped, good, copy.deepcopy(_MERKLE_POLICY))
        self.assertIsNot(out["policy_ok"], True)
        authroot = _named_check(out, "policy:authenticated_root")
        self.assertIsNotNone(authroot)
        self.assertIsNot(authroot["ok"], True)

    def test_control_the_matching_root_is_authenticated(self):
        bundle = _control_bundle()
        root_b64 = bundle["merkle"]["root_b64"]
        good = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE, expected_root_b64=root_b64)
        out = evaluate_policy(bundle, good, copy.deepcopy(_MERKLE_POLICY))
        authroot = _named_check(out, "policy:authenticated_root")
        self.assertIsNotNone(authroot)
        self.assertIs(authroot["ok"], True)


class AnOutOfPayloadSdJwtConfersNothing(unittest.TestCase):
    """Review point 1 (SD-JWT): sd_jwt_vc lives outside the signed payload. Swapping it leaves the payload and
    the bundle signer unchanged, yet it confers no positive SD-JWT rule. Already fail-closed at 40a6a09c
    (Nachtrag 44 + 46: the SD-JWT issuer must be the bundle signer, taken from the result), so this is the
    review's required gegenprobe, not a new fix; measured both at 40a6a09c and after."""

    def test_a_swapped_sd_jwt_confers_no_positive_rule(self):
        bundle = _control_bundle()
        other = _control_bundle()
        swapped = copy.deepcopy(bundle)
        swapped["sd_jwt_vc"] = copy.deepcopy(other["sd_jwt_vc"])
        self.assertNotEqual(swapped["sd_jwt_vc"], bundle["sd_jwt_vc"])
        self.assertEqual(swapped["payload_b64"], bundle["payload_b64"])
        self.assertEqual(swapped["signature"]["public_key_b64"], bundle["signature"]["public_key_b64"])
        good = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)
        out = evaluate_policy(swapped, good, copy.deepcopy(_SD_POLICY))
        self.assertIsNot(out["policy_ok"], True)
        names = {c["name"]: c["ok"] for c in out.get("checks", [])}
        for name in ("policy:key_binding_present", "policy:nonce_present", "policy:expected_aud"):
            self.assertIn(name, names)
            self.assertIsNot(names[name], True, f"{name} must not be positive on a swapped sd_jwt")


if __name__ == "__main__":
    unittest.main()
