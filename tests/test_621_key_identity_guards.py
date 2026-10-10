"""6.2.1 guards: the coverage gaps named by the key-identity class search, as contracts.

These hold at the tag candidate; no defect is claimed here. Each pins one property that so far no test
measured, so that a later change cannot lose it silently:

1. ``allowed_issuers``: a matching ``kid`` with a different key never matches; only the key material does.
2. ``sd_jwt.issuer_key_pin``: the same key bytes under a different algorithm prefix never trust the issuer.
3. Outcome receivers: a hybrid receiver entry whose classical half equals the resolver answer never makes
   ``receiver_role_trusted`` or ``receiver_key_bound`` True (today held by the N47 rule).
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle import emit_bundle, verify_bundle  # noqa: E402
from proofbundle.emit import generate_signer  # noqa: E402
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: E402
from proofbundle.policy import evaluate_policy  # noqa: E402
from test_security_fix_620_bind_n44 import _AUD, _NONCE, _attack_bundle, _check, _trust_ok  # noqa: E402
from test_security_fix_620_trustpack_n45b_receiver import (  # noqa: E402
    _content_root,
    _genesis_pack,
    _outcome_pred_with_receiver,
)


def _b64_pub(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


class AllowedIssuersMatchOnKeyMaterial(unittest.TestCase):
    def _judge(self, pinned_pub_b64: str):
        sk = generate_signer()
        bundle = emit_bundle(b"guard allowed_issuers", sk)
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "guard-kid",
                  "allowed_issuers": [{"kid": "kid-1", "public_key_b64": pinned_pub_b64(sk)}]}
        return evaluate_policy(bundle, verify_bundle(bundle), policy)

    def test_the_same_kid_with_another_key_does_not_match(self):
        other = generate_signer()
        out = self._judge(lambda _sk: _b64_pub(other))
        self.assertIsNot(out.get("policy_ok"), True, out)

    def test_control_the_signing_key_matches(self):
        out = self._judge(_b64_pub)
        self.assertIs(out.get("policy_ok"), True, out)


class IssuerKeyPinBindsTheAlgorithm(unittest.TestCase):
    def test_the_same_key_bytes_under_another_algorithm_prefix_do_not_trust(self):
        bundle, pin = _attack_bundle()
        foreign = "es256:" + pin.split(":", 1)[1]
        r = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE, sd_jwt_issuer_key_pin=foreign)
        self.assertEqual(_check(r), (False, False))
        self.assertIs(_trust_ok(r), False)

    def test_control_the_ed25519_prefix_trusts(self):
        bundle, pin = _attack_bundle()
        r = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE, sd_jwt_issuer_key_pin=pin)
        self.assertEqual(_check(r), (True, True))


class HybridReceiverNotReducedToItsClassicalHalf(unittest.TestCase):
    def test_a_hybrid_receiver_entry_is_not_trusted_from_its_classical_half(self):
        recv_pub = generate_signer().public_key().public_bytes_raw()
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred_with_receiver(), out_sk)
        pred, _ = _genesis_pack(out_pub, recv_pub)
        pred["keys"]["kid-recv"] = {"alg": "hybrid-ed25519-mldsa65",
                                    "publicKey": base64.b64encode(recv_pub).decode("ascii"),
                                    "publicKeyPq": base64.b64encode(b"\x02" * 1952).decode("ascii")}
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: recv_pub)
        self.assertIsNot(r["receiver_role_trusted"], True)
        self.assertIsNot(r["receiver_key_bound"], True)


if __name__ == "__main__":
    unittest.main()
