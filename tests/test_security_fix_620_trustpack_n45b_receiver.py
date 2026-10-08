"""Addendum 45b (`KRAXO-CLOUD-N45B-EMPFAENGER-NUR-MIT-GEBUNDENEM-SCHLUESSEL-01`), addition to N45, Z309 / 6.2.0.
Implements point 3 from Addendum 44b (the receiver path the N44 report did not cover).

FINDING (read on the code at ae4a4c1d): with a pinned pack, verify_outcome_receipt set receiver_role_trusted to
True when receiverKeyId is a member of outcomeReceivers and NO signing key was resolved — only with a warning
"by LABEL only" (outcome.py). A positive trust field with no binding to the key that carries the statement.

CONTRACT N45B: receiver_role_trusted was positive only when the pack is anchored bound to the content per N45, a
signing key of the receiver statement was resolved, and it binds exactly to the pack key of that receiverKeyId
(receiver_key_bound True). Label alone -> receiver_role_trusted None, receiver_key_bound None, with reason and
warning. A resolved, non-binding key stays False. ok is unaffected (receiverRefs never gate ok).

N47 (`KRAXO-CLOUD-N47-EMPFAENGER-NICHT-AUS-RESOLVER-ANTWORT-01`) supersedes the positive end: a caller resolver
answer can no longer confer receiver trust, because the library does not itself verify the referenced receiver
statement. A member whose resolved signer key byte-matches the pack key is now receiver_role_trusted None and
receiver_key_bound None, with an error containing "RECEIVER_STATEMENT_NOT_VERIFIED" — no longer True/True. The
counter-probes (label-only None, resolved-but-non-binding False) are unchanged, and ok stays unaffected.

Red at ae4a4c1d, green afterwards. Only fail-closed checked, no further attack probes.
"""
from __future__ import annotations

import base64
import hashlib
import unittest

from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import _rfc8785_bytes, sign_trust_pack


def _pub_b64(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _content_root(pred: dict) -> str:
    return hashlib.sha256(_rfc8785_bytes(pred)).hexdigest()


def _outcome_pred_with_receiver() -> dict:
    return {"schemaVersion": "0.1.0", "outcomeId": "outcome-n45b", "decisionRef": {"sha256": "a" * 64},
            "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
            "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
            "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
            "receiverRefs": [{"relation": "observed", "digest": {"sha256": "d" * 64},
                              "receiverKeyId": "kid-recv"}]}


def _genesis_pack(exec_pub: bytes, recv_pub: "bytes | None"):
    """Genesis (v1) pack: 2 root keys (threshold 2), outcomeExecutors[kid-exec]->exec_pub, and
    outcomeReceivers[kid-recv] whose key material is recv_pub when supplied (so a resolved signer can BIND),
    or absent (label only) when recv_pub is None. Returns (predicate, {rootKeyId: signer})."""
    root_sks = {f"root-{i}": generate_signer() for i in range(2)}
    keys = {kid: {"publicKey": _pub_b64(sk)} for kid, sk in root_sks.items()}
    keys["kid-exec"] = {"publicKey": base64.b64encode(exec_pub).decode("ascii")}
    roles = {"root": {"keyIds": list(root_sks), "threshold": 2},
             "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1},
             "outcomeReceivers": {"keyIds": ["kid-recv"], "threshold": 1}}
    if recv_pub is not None:
        keys["kid-recv"] = {"publicKey": base64.b64encode(recv_pub).decode("ascii")}
    pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-n45b", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": roles, "keys": keys,
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    return pred, root_sks


def _pinned_root_keys(pred: dict) -> dict:
    return {kid: {"publicKey": pred["keys"][kid]["publicKey"]} for kid in pred["roles"]["root"]["keyIds"]}


class TestReceiverRoleNeedsBoundKey(unittest.TestCase):
    """Under N45B a resolved AND bound signer key was the only positive case; N47 caps even that at None
    (RECEIVER_STATEMENT_NOT_VERIFIED) — a caller resolver answer can no longer confer receiver trust."""

    def _fixtures(self, recv_pub):
        out_sk = generate_signer()
        out_pub = out_sk.public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred_with_receiver(), out_sk)
        pred, root_sks = _genesis_pack(out_pub, recv_pub)
        return env, out_pub, pred, root_sks

    def test_label_only_member_is_not_positive(self):
        # COUNTER-PROBE (red@ae4a4c1d: receiver_role_trusted True by LABEL only). A member with NO resolved
        # signer key is None now, not True. The pack IS content-anchored (digest), so this isolates the label.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred, _ = self._fixtures(recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred))
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertIs(r["ok"], True)   # receiverRefs never gate ok; the executor is anchored+bound
        self.assertTrue(any("RECEIVER_ROLE_NOT_BOUND" in e for e in r["errors"]))

    def test_resolved_key_that_does_not_bind_is_false(self):
        # COUNTER-PROBE: a resolved signer key that does NOT match the pack key for the receiverKeyId stays False.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred, _ = self._fixtures(recv_pub)
        wrong_key = generate_signer().public_key().public_bytes_raw()
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: wrong_key)
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertIs(r["receiver_key_bound"], False)
        self.assertIs(r["ok"], True)

    def test_resolved_and_bound_key_is_not_positive_statement_not_verified(self):
        # CONTROL (was positive under N45B): a resolved signer key that byte-matches the pack key under a
        # content-bound anchor. N47: a caller resolver answer can no longer confer receiver trust — the library
        # does not itself verify the referenced receiver statement (it never fetches the statement for the digest
        # or checks a signature under the returned key), so this is receiver_role_trusted None, receiver_key_bound
        # None with RECEIVER_STATEMENT_NOT_VERIFIED, not True/True. ok is unaffected (receiverRefs never gate ok).
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred, _ = self._fixtures(recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: recv_pub)
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertTrue(any("RECEIVER_STATEMENT_NOT_VERIFIED" in e for e in r["errors"]))
        self.assertIs(r["ok"], True)

    def test_label_only_without_anchor_stays_not_anchored(self):
        # Sibling: without a content-bound anchor the receiver path is TRUST_PACK_NOT_ANCHORED (N45), not the
        # label-only None — the anchor gate comes first.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred, _ = self._fixtures(recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred))  # root-key only, no envelope
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertTrue(any("TRUST_PACK_NOT_ANCHORED" in e and "receiverRefs" in e for e in r["errors"]))


class TestN45EnvelopeReviewCounterProbes(unittest.TestCase):
    """Two counter-probes from the N45 review (owner N45B): the envelope anchor must fail closed."""

    def _env_and_signer(self):
        out_sk = generate_signer()
        return emit_outcome_receipt(_outcome_pred_with_receiver(), out_sk), out_sk.public_key().public_bytes_raw()

    def test_correct_root_pin_but_invalid_envelope_is_not_trusted(self):
        # The pinned root keys are correct, but the envelope was signed by OTHER keys (threshold of the declared
        # root not met) -> verify_trust_pack ok False -> the envelope anchor does not bind -> not positive.
        env, out_pub = self._env_and_signer()
        pred, _root_sks = _genesis_pack(out_pub, generate_signer().public_key().public_bytes_raw())
        wrong = {kid: generate_signer() for kid in pred["roles"]["root"]["keyIds"]}   # not the declared root keys
        bad_env = sign_trust_pack(pred, wrong)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_envelope=bad_env,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred))
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["ok"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])

    def test_real_pack_verdict_with_swapped_predicate_is_not_trusted(self):
        # A genuinely verifying envelope for predicate A, but a DIFFERENT predicate B is passed to outcome ->
        # the content binding (envelope content == this predicate) fails -> not positive.
        env, out_pub = self._env_and_signer()
        pred_a, root_sks = _genesis_pack(out_pub, generate_signer().public_key().public_bytes_raw())
        good_env = sign_trust_pack(pred_a, root_sks)          # verifies for pred_a
        pred_b = dict(pred_a)
        pred_b["trustPackId"] = "tp-n45b-swapped"            # a different predicate content
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred_b,
                                   trust_pack_envelope=good_env,
                                   trust_pack_expected_root_keys=_pinned_root_keys(pred_a))
        self.assertIs(r["executor_role_trusted"], False)
        self.assertIs(r["ok"], False)
        self.assertIn("TRUST_PACK_NOT_ANCHORED", r["automation"]["automationBlockers"])


if __name__ == "__main__":
    unittest.main()
