"""Z309 review round 6a, F4 group 4, at the merged head: a content-bound trust pack under anchor B (verified
envelope plus pinned root keys) with the full key identity of R6a-3, combined with the receiver path of N47.

Matrix: pin {matching, hybrid pin over an Ed25519-only root, foreign key} times receiver resolver {returns the
pack key of the receiver, returns a different key, no resolver}. In every cell the receiver role is never
positive and the receiver evidence never reaches INDEPENDENTLY_ATTESTED. The executor role is positive only
under the matching pin.
"""
from __future__ import annotations

import base64
import hashlib
import unittest

from proofbundle.assurance import EvidenceLevel
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import sign_trust_pack

from test_security_fix_620_trustpack_n45b_receiver import (  # type: ignore
    _genesis_pack, _outcome_pred_with_receiver, _pinned_root_keys,
)

_HYB = "hybrid-ed25519-mldsa65"
_PQ = hashlib.shake_256(b"z309-f4-g4/pq-leg").digest(1952)


def _case():
    out_sk = generate_signer()
    out_pub = out_sk.public_key().public_bytes_raw()
    recv_pub = generate_signer().public_key().public_bytes_raw()
    pred, root_sks = _genesis_pack(out_pub, recv_pub)
    return {"out_env": emit_outcome_receipt(_outcome_pred_with_receiver(), out_sk), "out_pub": out_pub,
            "recv_pub": recv_pub, "pred": pred, "tp_env": sign_trust_pack(pred, root_sks)}


def _pins(pred: dict) -> dict:
    matching = _pinned_root_keys(pred)
    hybrid = {kid: dict(v, alg=_HYB, publicKeyPq=base64.b64encode(_PQ).decode("ascii"))
              for kid, v in matching.items()}
    foreign = {kid: {"publicKey": base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode("ascii")}
               for kid in matching}
    return {"matching": matching, "hybrid_over_ed25519": hybrid, "foreign": foreign}


def _resolvers(case: dict) -> dict:
    wrong = generate_signer().public_key().public_bytes_raw()
    return {"pack_key": {"evidence_resolver": lambda d: True,
                         "receiver_attestation_resolver": lambda d: case["recv_pub"]},
            "other_key": {"evidence_resolver": lambda d: True,
                          "receiver_attestation_resolver": lambda d: wrong},
            "none": {}}


class TrustPackAnchorBTimesReceiverResolver(unittest.TestCase):

    def test_every_cell(self):
        case = _case()
        for pin_name, pin in _pins(case["pred"]).items():
            for res_name, res in _resolvers(case).items():
                with self.subTest(pin=pin_name, resolver=res_name):
                    r = verify_outcome_receipt(case["out_env"], case["out_pub"], trust_pack=case["pred"],
                                               trust_pack_envelope=case["tp_env"],
                                               trust_pack_expected_root_keys=pin, **res)
                    self.assertIsNot(r["receiver_role_trusted"], True,
                                     "a resolver answer never makes the receiver role positive")
                    self.assertIsNot(r["receiver_key_bound"], True)
                    level = (r.get("evidence_levels") or {}).get("receiverRefs", {}).get("level")
                    self.assertNotEqual(level, EvidenceLevel.INDEPENDENTLY_ATTESTED)
                    if pin_name == "matching":
                        self.assertIs(r["executor_role_trusted"], True, "control: anchor B with the matching pin")
                        self.assertIs(r["ok"], True)
                    else:
                        self.assertIsNot(r["executor_role_trusted"], True,
                                         "a pin that does not match the full key identity anchors nothing")
                        self.assertIsNot(r["ok"], True)
                        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_the_named_receiver_outcomes_under_the_matching_pin(self):
        case = _case()
        pin = _pins(case["pred"])["matching"]
        res = _resolvers(case)
        by_pack_key = verify_outcome_receipt(case["out_env"], case["out_pub"], trust_pack=case["pred"],
                                             trust_pack_envelope=case["tp_env"],
                                             trust_pack_expected_root_keys=pin, **res["pack_key"])
        self.assertIsNone(by_pack_key["receiver_role_trusted"])
        self.assertTrue(any("RECEIVER_STATEMENT_NOT_VERIFIED" in e for e in by_pack_key["errors"]))
        by_other_key = verify_outcome_receipt(case["out_env"], case["out_pub"], trust_pack=case["pred"],
                                              trust_pack_envelope=case["tp_env"],
                                              trust_pack_expected_root_keys=pin, **res["other_key"])
        self.assertIs(by_other_key["receiver_role_trusted"], False)


if __name__ == "__main__":
    unittest.main()
