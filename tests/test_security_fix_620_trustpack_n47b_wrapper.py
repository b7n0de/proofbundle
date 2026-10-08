"""Addendum 47b (`KRAXO-CLOUD-N47B-DOKU-UND-WRAPPER-TEST-01`), follow-up to N47, Z309 / 6.2.0.

COVERAGE GAP (Codex defect search at f51aabc2): the N47 file
(`test_security_fix_620_trustpack_n47_receiver.py`) pins the N47 contract on `verify_outcome_receipt` and on
`assurance.classify_receiver_corroboration`, but NOT on the explicit-exception wrapper
`verify_outcome_receipt_or_raise`. The three ``verify_outcome_receipt`` exclusions in
`test_a_verdict_is_that_of_a_state_the_inputs_held.py` therefore leave the wrapper without its own ratchet: a
later positive special-case in the wrapper alone could pass unnoticed. At the measured commit the wrapper is a
pure delegation (`outcome.verify_outcome_receipt_or_raise` just forwards to `verify_outcome_receipt` with
`_raise_on_malformed=True`), so the gap is a test-coverage gap, not a measured positive verdict — this file
closes it by running the SAME counter-probes as the N47 file through the wrapper.

CONTRACT (unchanged from N47, now pinned on the wrapper): a resolver answer never makes
`receiver_role_trusted` or `receiver_key_bound` True. As long as the library does not itself verify the
referenced receiver statement they are at most None, with a named reason (RECEIVER_STATEMENT_NOT_VERIFIED). A
resolved key that does not bind stays False; a label alone stays None; `ok` is unaffected (receiverRefs never
gate ok). INDEPENDENTLY_ATTESTED is not produced from a resolver answer; the receiverRefs level stays at
CONTENT_RESOLVED.

Red at 215754bb51e79189ee8d3e52f6d7a8daf96e94c1 (before N47), green afterwards. Only fail-closed checked, no
further attack probes; the attack inputs are built here with test keys. For a well-formed envelope the wrapper
returns a verdict (it does not raise), so the receiver fields are asserted on its returned result exactly as in
the N47 file.
"""
from __future__ import annotations

import unittest

from proofbundle.assurance import EvidenceLevel
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt_or_raise

from test_security_fix_620_trustpack_n45b_receiver import (  # type: ignore
    _content_root, _genesis_pack, _outcome_pred_with_receiver,
)


def _fixtures(recv_pub):
    out_sk = generate_signer()
    out_pub = out_sk.public_key().public_bytes_raw()
    env = emit_outcome_receipt(_outcome_pred_with_receiver(), out_sk)
    pred, _ = _genesis_pack(out_pub, recv_pub)
    return env, out_pub, pred


class TestReceiverTrustNotFromResolverAnswerViaWrapper(unittest.TestCase):
    """verify_outcome_receipt_or_raise confers no receiver trust and no INDEPENDENTLY_ATTESTED from a resolver
    answer — the same contract the N47 file pins on verify_outcome_receipt, now on the wrapper."""

    def test_resolver_returning_the_pack_key_is_not_positive(self):
        # COUNTER-PROBE (the Codex shape): a receiverRefs entry on a digest with no statement, evidence_resolver
        # True, and a resolver that returns the pack key -> not True, not INDEPENDENTLY_ATTESTED; ok unchanged.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        r = verify_outcome_receipt_or_raise(env, out_pub, trust_pack=pred,
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
        # CONTROL: a resolved signer key that does NOT match the pack key for the receiverKeyId stays False.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        wrong = generate_signer().public_key().public_bytes_raw()
        r = verify_outcome_receipt_or_raise(env, out_pub, trust_pack=pred,
                                            trust_pack_expected_genesis_digest=_content_root(pred),
                                            evidence_resolver=lambda d: True,
                                            receiver_attestation_resolver=lambda d: wrong)
        self.assertIs(r["receiver_role_trusted"], False)
        self.assertIs(r["receiver_key_bound"], False)
        self.assertIs(r["ok"], True)

    def test_label_only_stays_none(self):
        # CONTROL: a role member seen by LABEL only (no resolved signer key) stays None.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        r = verify_outcome_receipt_or_raise(env, out_pub, trust_pack=pred,
                                            trust_pack_expected_genesis_digest=_content_root(pred))
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["receiver_key_bound"])
        self.assertTrue(any("RECEIVER_ROLE_NOT_BOUND" in e for e in r["errors"]))
        self.assertIs(r["ok"], True)

    def test_executor_path_under_content_anchor_stays_positive(self):
        # CONTROL: the executor path is NOT affected — its key comes from the DSSE verification, so an executor
        # under a content-bound anchor is still positive through the wrapper.
        recv_pub = generate_signer().public_key().public_bytes_raw()
        env, out_pub, pred = _fixtures(recv_pub)
        r = verify_outcome_receipt_or_raise(env, out_pub, trust_pack=pred,
                                            trust_pack_expected_genesis_digest=_content_root(pred))
        self.assertIs(r["executor_role_trusted"], True)
        self.assertIs(r["executor_key_bound"], True)
        self.assertIs(r["ok"], True)


if __name__ == "__main__":
    unittest.main()
