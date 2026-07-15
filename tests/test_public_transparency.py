"""3.2.0 O3 Public Transparency profile — policy layer over the C2SP checkpoint primitives.

Named statuses, fail-closed on missing material for REQUIRED checks, NOT_EVALUATED (visible) for optional
ones. unittest-style.
"""
from __future__ import annotations

import os
import unittest

from proofbundle.checkpoint import cosign_checkpoint, cosign_vkey, sign_checkpoint, vkey
from proofbundle.emit import generate_signer
from proofbundle.public_transparency import (
    ConsistencyVerificationResult,
    PublicTransparencyError,
    evaluate_public_transparency,
    validate_public_transparency_policy,
)

_ORIGIN = "example.transparency.log"
_ROOT = os.urandom(32)
_SIZE = 42


def _pub(sk) -> bytes:
    return sk.public_key().public_bytes_raw()


def _signed_note():
    sk = generate_signer()
    note = sign_checkpoint(_ORIGIN, _SIZE, _ROOT, sk, "logkey")
    return note, vkey("logkey", _pub(sk))


def _witnessed(note):
    w = generate_signer()
    note2 = cosign_checkpoint(note, w, "witness1", 1_700_000_000)
    return note2, cosign_vkey("witness1", _pub(w))


class TestPolicyValidate(unittest.TestCase):
    def test_valid_policy(self):
        self.assertEqual(validate_public_transparency_policy(
            {"requireSignedCheckpoint": True, "trustedLogOrigins": [_ORIGIN]}), [])

    def test_unknown_key_rejected(self):
        self.assertTrue(validate_public_transparency_policy({"nope": 1}))

    def test_bad_witness_threshold_rejected(self):
        self.assertTrue(validate_public_transparency_policy({"witnessQuorum": {"threshold": 0}}))

    def test_bad_policy_raises_in_evaluate(self):
        note, _ = _signed_note()
        with self.assertRaises(PublicTransparencyError):
            evaluate_public_transparency(note, {"nope": 1})


class TestEvaluate(unittest.TestCase):
    def test_signed_and_origin_pass(self):
        note, lv = _signed_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "trustedLogOrigins": [_ORIGIN], "trustedLogKeys": [lv]},
            log_vkey=lv)
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "PASS", r)
        self.assertEqual(r["statuses"]["CHECKPOINT_SIGNATURE"], "PASS")
        self.assertEqual(r["statuses"]["LOG_ORIGIN"], "PASS")

    def test_untrusted_origin_fails(self):
        note, lv = _signed_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "trustedLogOrigins": ["other.log"]}, log_vkey=lv)
        self.assertEqual(r["statuses"]["LOG_ORIGIN"], "FAIL")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")

    def test_require_signature_without_vkey_fails_closed(self):
        note, _ = _signed_note()
        r = evaluate_public_transparency(note, {"requireSignedCheckpoint": True})
        self.assertEqual(r["statuses"]["CHECKPOINT_SIGNATURE"], "FAIL")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")

    def test_vkey_not_on_allowlist_fails(self):
        note, lv = _signed_note()
        _, other = _signed_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "trustedLogKeys": [other]}, log_vkey=lv)
        self.assertEqual(r["statuses"]["CHECKPOINT_SIGNATURE"], "FAIL")

    def test_root_authenticity_not_evaluated_when_no_reference(self):
        note, lv = _signed_note()
        r = evaluate_public_transparency(note, {"requireSignedCheckpoint": True}, log_vkey=lv)
        self.assertEqual(r["statuses"]["ROOT_BYTES_AUTHENTICITY"], "NOT_EVALUATED")

    def test_root_authenticity_pass_and_fail(self):
        import base64
        note, lv = _signed_note()
        good = base64.b64encode(_ROOT).decode()
        r_ok = evaluate_public_transparency(note, {"requireSignedCheckpoint": True}, log_vkey=lv,
                                            expected_root_b64=good)
        self.assertEqual(r_ok["statuses"]["ROOT_BYTES_AUTHENTICITY"], "PASS")
        r_bad = evaluate_public_transparency(note, {"requireSignedCheckpoint": True}, log_vkey=lv,
                                             expected_root_b64=base64.b64encode(b"z" * 32).decode())
        self.assertEqual(r_bad["statuses"]["ROOT_BYTES_AUTHENTICITY"], "FAIL")

    def test_tree_context_mismatch_fails(self):
        note, lv = _signed_note()
        r = evaluate_public_transparency(note, {"requireSignedCheckpoint": True}, log_vkey=lv,
                                         expected_tree_size=999)
        self.assertEqual(r["statuses"]["TREE_CONTEXT_AUTHENTICITY"], "FAIL")

    def test_consistency_required_without_proof_fails_closed(self):
        note, lv = _signed_note()
        r = evaluate_public_transparency(note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
                                         log_vkey=lv)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "FAIL")
        r2 = evaluate_public_transparency(note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
                                          log_vkey=lv, consistency_confirmed=True)
        self.assertEqual(r2["statuses"]["CONSISTENCY"], "PASS")

    def test_witness_quorum_pass(self):
        note, lv = _signed_note()
        note2, wv = _witnessed(note)
        r = evaluate_public_transparency(
            note2, {"requireSignedCheckpoint": True, "witnessQuorum": {"threshold": 1}},
            log_vkey=lv, witness_vkeys=[wv])
        self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "PASS", r)

    def test_witness_quorum_required_without_witnesses_fails_closed(self):
        note, lv = _signed_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "witnessQuorum": {"threshold": 1}}, log_vkey=lv)
        self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "FAIL")

    def test_witness_quorum_count_not_met_fails(self):
        # threshold 2 but only ONE valid witness cosignature → quorum not met (distinct from zero-witnesses)
        note, lv = _signed_note()
        note2, wv = _witnessed(note)
        r = evaluate_public_transparency(
            note2, {"requireSignedCheckpoint": True, "witnessQuorum": {"threshold": 2}},
            log_vkey=lv, witness_vkeys=[wv])
        self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "FAIL")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")

    def test_malformed_note_checkpoint_signature_fails_not_crash(self):
        # a note that is not a well-formed signed checkpoint → CHECKPOINT_SIGNATURE FAIL, never a crash
        _note, lv = _signed_note()
        r = evaluate_public_transparency("not\na\ncheckpoint", {"requireSignedCheckpoint": True},
                                         log_vkey=lv)
        self.assertEqual(r["statuses"]["CHECKPOINT_SIGNATURE"], "FAIL")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")

    def test_empty_policy_evaluates_nothing_is_fail(self):
        note, _ = _signed_note()
        r = evaluate_public_transparency(note, {})
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")
        self.assertTrue(all(v == "NOT_EVALUATED" for v in r["statuses"].values()))

    def test_plaintext_only_without_crypto_anchor_is_fail(self):
        # release-review #5: origin/root/tree-size are PLAINTEXT claims from the note. Without a verified
        # CHECKPOINT_SIGNATURE or WITNESS_QUORUM the aggregate must NOT be PASS, even though no status FAILs —
        # an attacker could author any origin/root/tree-size on an unsigned note.
        import base64
        note, _lv = _signed_note()  # a real note, but the policy does NOT require/verify the signature
        r = evaluate_public_transparency(
            note, {"trustedLogOrigins": [_ORIGIN]},
            expected_root_b64=base64.b64encode(_ROOT).decode(),
            expected_tree_size=_SIZE)
        self.assertEqual(r["statuses"]["LOG_ORIGIN"], "PASS")
        self.assertEqual(r["statuses"]["CHECKPOINT_SIGNATURE"], "NOT_EVALUATED")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL", r)
        self.assertTrue(any("not cryptographically anchored" in e for e in r["errors"]), r["errors"])

    def test_signed_anchor_lets_plaintext_checks_pass(self):
        # with the signature required + verified (a crypto anchor), the same plaintext checks aggregate to PASS.
        import base64
        note, lv = _signed_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "trustedLogOrigins": [_ORIGIN]},
            log_vkey=lv, expected_root_b64=base64.b64encode(_ROOT).decode(), expected_tree_size=_SIZE)
        self.assertEqual(r["statuses"]["CHECKPOINT_SIGNATURE"], "PASS")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "PASS", r)

    def test_witness_quorum_alone_is_a_valid_crypto_anchor(self):
        # WITNESS_QUORUM==PASS also anchors the aggregate (no separate log-signature requirement needed).
        note, _lv = _signed_note()
        note2, wv = _witnessed(note)
        r = evaluate_public_transparency(
            note2, {"trustedLogOrigins": [_ORIGIN], "witnessQuorum": {"threshold": 1}},
            witness_vkeys=[wv])
        self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "PASS")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "PASS", r)


# --- finding 10: an unbound consistency_confirmed boolean was replayable onto any checkpoint --------
#
# evaluate_public_transparency previously took `consistency_confirmed: bool | None` with NO binding to
# WHICH (old, new) checkpoint pair was actually checked — a True computed for one pair verified equally
# well for a completely unrelated `new` checkpoint. ConsistencyVerificationResult carries the checkpoint
# identities so evaluate_public_transparency can bind new_origin/new_tree_size/new_root_b64 to the exact
# note being evaluated BEFORE `confirmed` is ever accepted, and its own .validate() independently rejects
# a structurally impossible pair (a same-size-different-root "split view") regardless of `confirmed`.


def _good_consistency_result(**overrides) -> ConsistencyVerificationResult:
    import base64
    fields = dict(
        old_origin=_ORIGIN, old_tree_size=10, old_root_b64=base64.b64encode(b"o" * 32).decode(),
        new_origin=_ORIGIN, new_tree_size=_SIZE, new_root_b64=base64.b64encode(_ROOT).decode(),
        proof_digest="proof-digest-abc", verifier_version="monitor-v1", policy_digest="policy-abc",
        confirmed=True)
    fields.update(overrides)
    return ConsistencyVerificationResult(**fields)


class TestConsistencyVerificationResult(unittest.TestCase):
    """Unit-level: .validate() is a structural, No-Fake floor independent of `confirmed`."""

    def test_valid_result_validates_clean(self):
        self.assertEqual(_good_consistency_result().validate(), [])

    def test_empty_proof_digest_rejected(self):
        # a confirmed=True with no record of what was actually checked is not evidence (omission floor)
        self.assertTrue(_good_consistency_result(proof_digest="").validate())

    def test_old_larger_than_new_rejected(self):
        errs = _good_consistency_result(old_tree_size=100, new_tree_size=10).validate()
        self.assertTrue(errs)
        self.assertTrue(any("old_tree_size exceeds new_tree_size" in e for e in errs), errs)

    def test_mismatched_origins_rejected(self):
        errs = _good_consistency_result(new_origin="other.log").validate()
        self.assertTrue(any("old_origin and new_origin differ" in e for e in errs), errs)

    def test_equal_size_different_roots_is_a_split_view(self):
        import base64
        errs = _good_consistency_result(
            old_tree_size=_SIZE, old_root_b64=base64.b64encode(b"F" * 32).decode()).validate()
        self.assertTrue(any("split view" in e for e in errs), errs)

    def test_malformed_types_do_not_crash(self):
        # never raise on a caller-constructed/deserialized result with wrong field types
        bad = ConsistencyVerificationResult(
            old_origin=None, old_tree_size="10", old_root_b64=1,  # type: ignore[arg-type]
            new_origin=_ORIGIN, new_tree_size=_SIZE, new_root_b64="x",
            proof_digest="p", verifier_version="v", policy_digest="q", confirmed="yes")  # type: ignore[arg-type]
        errs = bad.validate()
        self.assertTrue(errs)


class TestConsistencyResultBinding(unittest.TestCase):
    """Integration: evaluate_public_transparency binds/rejects consistency_result and strict_consistency."""

    def test_consistency_result_correct_pair_passes(self):
        note, lv = _signed_note()
        cr = _good_consistency_result()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_result=cr)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "PASS", r)
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "PASS", r)

    def test_consistency_result_wrong_checkpoint_pair_fails(self):
        # confirmed=True, but new_root_b64 does NOT match the checkpoint actually being evaluated —
        # the classic "confirmed for a different pair, replayed here" attack finding 10 closes.
        import base64
        note, lv = _signed_note()
        cr = _good_consistency_result(new_root_b64=base64.b64encode(b"Z" * 32).decode())
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_result=cr)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "FAIL", r)
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL", r)
        self.assertTrue(any("wrong checkpoint pair" in e for e in r["errors"]), r["errors"])

    def test_consistency_result_not_confirmed_fails(self):
        note, lv = _signed_note()
        cr = _good_consistency_result(confirmed=False)
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_result=cr)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "FAIL", r)

    def test_bare_boolean_rejected_in_strong_profile(self):
        # strict_consistency=True refuses the unbound bare-boolean path entirely.
        note, lv = _signed_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_confirmed=True, strict_consistency=True)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "FAIL", r)
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL", r)
        self.assertTrue(any("strict_consistency" in e for e in r["errors"]), r["errors"])
        # additive / backward-compat: WITHOUT strict_consistency the bare boolean still works as before
        r2 = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_confirmed=True)
        self.assertEqual(r2["statuses"]["CONSISTENCY"], "PASS", r2)
        self.assertEqual(r2["PUBLIC_TRANSPARENCY"], "PASS", r2)

    def test_monitor_split_view_fails(self):
        # an independent monitor's own report: the SAME tree size was seen under TWO different roots —
        # the textbook log split view / fork. No genuine consistency proof can ever confirm this (RFC
        # 9162: identical size implies identical root), so .validate() rejects it structurally and
        # evaluate_public_transparency must FAIL the check regardless of confirmed=True — even though
        # new_root_b64 correctly matches the checkpoint under evaluation (isolating the split-view
        # rejection from the ordinary wrong-checkpoint-pair binding failure above).
        import base64
        note, lv = _signed_note()
        cr = _good_consistency_result(
            old_tree_size=_SIZE, old_root_b64=base64.b64encode(b"F" * 32).decode())
        self.assertTrue(cr.validate())  # structurally invalid standalone, independent of evaluate()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_result=cr)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "FAIL", r)
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL", r)
        self.assertTrue(any("split view" in e for e in r["errors"]), r["errors"])

    def test_consistency_result_takes_precedence_over_bare_boolean(self):
        # when both are supplied, the typed (bound) result wins even if the bare boolean disagrees.
        import base64
        note, lv = _signed_note()
        cr = _good_consistency_result(new_root_b64=base64.b64encode(b"Z" * 32).decode())  # wrong pair
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "requireConsistencyProof": True},
            log_vkey=lv, consistency_confirmed=True, consistency_result=cr)
        self.assertEqual(r["statuses"]["CONSISTENCY"], "FAIL", r)  # the bound result's mismatch wins


if __name__ == "__main__":
    unittest.main()
