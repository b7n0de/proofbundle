"""Addendum 47 (`KRAXO-CLOUD-N47-EMPFAENGER-NICHT-AUS-RESOLVER-ANTWORT-01`), follow-up to N45b, Z309 / 6.2.0.

FINDING (measured at 215754bb): the receiver path treated a caller resolver answer as content-and-signature
verification. A receiverRefs entry on a digest with NO statement, with evidence_resolver returning True and a
receiver_attestation_resolver that merely returns the pack public key, yielded receiver_role_trusted True,
receiver_key_bound True, evidence level INDEPENDENTLY_ATTESTED and ok True. The sibling is
assurance.classify_receiver_corroboration, where a bare True or 32 bytes from the resolver reached
INDEPENDENTLY_ATTESTED.

CONTRACT N47: a resolver answer never makes receiver_role_trusted or receiver_key_bound True. As long as the
library does not itself verify the referenced receiver statement, they are at most None in 6.2.0, with a named
reason (RECEIVER_STATEMENT_NOT_VERIFIED). A resolved key that does not bind stays False; a label alone stays
None; ok is unaffected (receiverRefs never gate ok). INDEPENDENTLY_ATTESTED is not produced from a resolver
answer, neither in classify_receiver_corroboration nor in the outcome receiver path, neither from a bare True
nor from 32 bytes; the level stays in the enum but is honestly unreachable, like EFFECT_OBSERVED, with a named
reason in the detail.

Red at 215754bb51e79189ee8d3e52f6d7a8daf96e94c1, green afterwards. Only fail-closed checked, no further attack
probes; the attack inputs are built here with test keys.
"""
from __future__ import annotations

import unittest

from proofbundle.assurance import EvidenceLevel, classify_receiver_corroboration
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt

from test_security_fix_620_trustpack_n45b_receiver import (  # type: ignore
    _content_root, _genesis_pack, _outcome_pred_with_receiver,
)

_CAP = "INDEPENDENTLY_ATTESTED is not reachable"


def _fixtures(recv_pub):
    out_sk = generate_signer()
    out_pub = out_sk.public_key().public_bytes_raw()
    env = emit_outcome_receipt(_outcome_pred_with_receiver(), out_sk)
    pred, _ = _genesis_pack(out_pub, recv_pub)
    return env, out_pub, pred


class TestReceiverTrustNotFromResolverAnswer(unittest.TestCase):
    """The outcome receiver path: a resolver answer confers no receiver trust and no INDEPENDENTLY_ATTESTED."""

    def test_resolver_returning_the_pack_key_is_not_positive(self):
        # COUNTER-PROBE (the Codex shape): a receiverRefs entry on a digest with no statement, evidence_resolver
        # True, and a resolver that returns the pack key -> not True, not INDEPENDENTLY_ATTESTED; ok unchanged.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: recv_pub)
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertNotEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertTrue(any("RECEIVER_STATEMENT_NOT_VERIFIED" in e for e in r["errors"]))
        self.assertIs(r["ok"], True)   # receiverRefs never gate ok; the executor is anchored

    def test_resolved_non_binding_key_stays_false(self):
        # CONTROL: a resolved signer key that does NOT match the pack key for the receiverKeyId stays False
        # (a measurable negative, unchanged by N47).
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        wrong = generate_signer().public_key().public_bytes_raw()
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred),
                                   evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: wrong)
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertIs(r["receiver_key_bound"], False)
        self.assertIs(r["ok"], True)

    def test_label_only_stays_none(self):
        # CONTROL: a role member seen by LABEL only (no resolved signer key) stays None (unchanged by N47).
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred))
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertTrue(any("RECEIVER_ROLE_NOT_BOUND" in e for e in r["errors"]))
        self.assertIs(r["ok"], True)

    def test_executor_path_under_content_anchor_stays_positive(self):
        # CONTROL: the executor path is NOT affected by N47 — its key comes from the DSSE verification, so an
        # executor under a content-bound anchor is still positive.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        r = verify_outcome_receipt(env, out_pub, trust_pack=pred,
                                   trust_pack_expected_genesis_digest=_content_root(pred))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["executor_key_bound"], True)
        self.assertIs(r["ok"], True)


class TestClassifyReceiverCorroborationCappedAtContentResolved(unittest.TestCase):
    """classify_receiver_corroboration never reaches INDEPENDENTLY_ATTESTED from a resolver answer."""

    _DIG = {"sha256": "d" * 64}

    def test_bare_true_does_not_attest(self):
        r = classify_receiver_corroboration(self._DIG, evidence_resolver=lambda d: True,
                                            independent_attestation_resolver=lambda d: True,
                                            executor_key_id="kid-exec", receiver_key_id="kid-recv",
                                            expected_receiver_public_key=None)
        self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertIn(_CAP, r["detail"])

    def test_thirty_two_bytes_do_not_attest(self):
        recv_pub = generate_signer().public_key().public_bytes_raw()
        r = classify_receiver_corroboration(self._DIG, evidence_resolver=lambda d: True,
                                            independent_attestation_resolver=lambda d: recv_pub,
                                            executor_key_id="kid-exec", receiver_key_id="kid-recv",
                                            expected_receiver_public_key=recv_pub)
        self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertIn(_CAP, r["detail"])


if __name__ == "__main__":
    unittest.main()
