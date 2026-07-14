"""B3↔B5 wiring: an ArchiveTimeStamp carries a real time-authority signature (the RFC-4998 TimeStampToken
role), and renewal MIGRATES the signature algorithm toward PQ (ed25519 → hybrid → mldsa65). verify_sequence
checks the newest ATS's signature against the relying party's trusted authority keys (WP-A1).

Closes the audit MEDIUM (default anchor trusted an unauthenticated field): with authority_keys the anchor
is a real cryptographic signature, not the bare anchor_status string.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.pqsig import generate_mldsa
from proofbundle.renewal import (
    ArchiveTimeStamp,
    build_initial_sequence,
    last_ats,
    renew_hashtree,
    renew_timestamp,
    verify_sequence,
)

DATA = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]


def _authority():
    ed = Ed25519PrivateKey.generate()
    ed_pub = ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    m = generate_mldsa("mldsa65")
    m_pub = m.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signers = {"ed25519": ed, "mldsa65": m}
    keys = {"ed25519": ed_pub, "mldsa65": m_pub}
    return signers, keys


class TestSignedRenewal(unittest.TestCase):
    def test_ed25519_signed_sequence_verifies(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers=signers)
        self.assertEqual(last_ats(seq).sig_alg, "ed25519")
        self.assertTrue(verify_sequence(seq, DATA, authority_keys=keys).ok)

    def test_signature_algorithm_migrates_to_pq(self):
        # the B5 point: renewal upgrades the signature ed25519 -> hybrid -> mldsa65 (PQ), still verifying
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers=signers)
        seq = renew_timestamp(seq, time=2000, sig_alg="hybrid-ed25519-mldsa65", signers=signers)
        seq = renew_timestamp(seq, time=3000, sig_alg="mldsa65", signers=signers)
        res = verify_sequence(seq, DATA, authority_keys=keys)
        self.assertTrue(res.ok, [str(c) for c in res.checks if not c.ok])
        self.assertEqual(last_ats(seq).sig_alg, "mldsa65")   # newest is post-quantum

    def test_hashtree_renewal_keeps_signature_authenticated(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="hybrid-ed25519-mldsa65", signers=signers)
        seq = renew_hashtree(seq, DATA, new_hash_alg="sha512", time=2000,
                             sig_alg="hybrid-ed25519-mldsa65", signers=signers)
        self.assertTrue(verify_sequence(seq, DATA, authority_keys=keys).ok)

    def test_forged_signature_is_rejected(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="mldsa65", signers=signers)
        forged = dataclasses.replace(
            seq[0][0], signatures=(("mldsa65", base64.b64encode(b"\x00" * 3309).decode()),))
        self.assertFalse(verify_sequence([[forged]], DATA, authority_keys=keys).ok)

    def test_wrong_authority_key_is_rejected(self):
        signers, _keys = _authority()
        _other_signers, other_keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers=signers)
        self.assertFalse(verify_sequence(seq, DATA, authority_keys=other_keys).ok)

    def test_hybrid_requires_both_legs_present(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="hybrid-ed25519-mldsa65", signers=signers)
        # only the ed25519 authority key supplied → the PQ leg cannot verify → fail closed
        self.assertFalse(verify_sequence(seq, DATA, authority_keys={"ed25519": keys["ed25519"]}).ok)

    def test_unsigned_ats_fails_when_authority_keys_required(self):
        _signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)  # unsigned
        # a caller that supplies authority_keys demands a real signature; an unsigned ATS has none
        self.assertFalse(verify_sequence(seq, DATA, authority_keys=keys).ok)

    def test_tampered_data_still_fails_under_signed_anchor(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers=signers)
        tampered = [DATA[0], hashlib.sha256(b"evil").hexdigest()]
        self.assertFalse(verify_sequence(seq, tampered, authority_keys=keys).ok)

    def test_unknown_sig_alg_rejected_at_build(self):
        signers, _keys = _authority()
        with self.assertRaises(Exception):
            build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                   sig_alg="rsa-pkcs1", signers=signers)

    def test_missing_signer_rejected_at_build(self):
        with self.assertRaises(Exception):
            build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                   sig_alg="mldsa65", signers={})  # no mldsa65 signer

    def test_unsigned_default_fails_closed_but_opt_in_structural_works(self):
        # API-safety audit fix: an unsigned sequence with NO anchor mode supplied fails closed (no silent
        # structural pass); a caller who only wants the covering check opts in explicitly.
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
        self.assertFalse(verify_sequence(seq, DATA).ok)
        self.assertTrue(verify_sequence(seq, DATA, allow_unauthenticated_anchor=True).ok)


class TestSigAlgDowngradeCritical(unittest.TestCase):
    """The CRITICAL finding: sig_alg is bound into _ats_content, so a hybrid/mldsa65 ATS cannot be
    relabeled down to its (post-quantum-forgeable) ed25519 leg without breaking the signature."""

    def test_downgrade_hybrid_to_ed25519_is_rejected(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="hybrid-ed25519-mldsa65", signers=signers)
        legit = seq[0][0]
        ed_sig = dict(legit.signatures)["ed25519"]
        # relabel to ed25519-only, keeping the ed25519 leg that was valid under the hybrid label
        downgraded = dataclasses.replace(legit, sig_alg="ed25519",
                                         signatures=(("ed25519", ed_sig),))
        self.assertFalse(verify_sequence([[downgraded]], DATA, authority_keys=keys).ok)

    def test_downgrade_hybrid_to_mldsa65_is_rejected(self):
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="hybrid-ed25519-mldsa65", signers=signers)
        legit = seq[0][0]
        m_sig = dict(legit.signatures)["mldsa65"]
        downgraded = dataclasses.replace(legit, sig_alg="mldsa65",
                                         signatures=(("mldsa65", m_sig),))
        self.assertFalse(verify_sequence([[downgraded]], DATA, authority_keys=keys).ok)

    def test_require_pq_rejects_ed25519_only_newest(self):
        # a PQ-strict relying party (still holding the ed25519 key for legacy) rejects an ed25519-only newest
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers=signers)
        self.assertTrue(verify_sequence(seq, DATA, authority_keys=keys).ok)   # ok without the floor
        self.assertFalse(verify_sequence(seq, DATA, authority_keys=keys, require_pq=True).ok)
        # a migrated (mldsa65) newest satisfies the PQ floor
        seq2 = renew_timestamp(seq, time=2000, sig_alg="mldsa65", signers=signers)
        self.assertTrue(verify_sequence(seq2, DATA, authority_keys=keys, require_pq=True).ok)

    def test_signature_replayed_onto_different_ats_is_rejected(self):
        # domain separation: a signature valid for one ATS's content must not verify on a different ATS
        signers, keys = _authority()
        seq_a = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                       sig_alg="ed25519", signers=signers)
        stolen_sig = dict(seq_a[0][0].signatures)["ed25519"]
        other = dataclasses.replace(seq_a[0][0], time=9999, signatures=(("ed25519", stolen_sig),))
        self.assertFalse(verify_sequence([[other]], DATA, authority_keys=keys).ok)

    def test_tampering_prior_ats_signature_breaks_next_covering(self):
        # token() folds the signature in, so tampering an EARLIER ATS's signature breaks the later ATS's
        # covering digest (structural), independent of the anchor
        signers, keys = _authority()
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000,
                                     sig_alg="ed25519", signers=signers)
        seq = renew_timestamp(seq, time=2000, sig_alg="ed25519", signers=signers)
        bad_first = dataclasses.replace(
            seq[0][0], signatures=(("ed25519", base64.b64encode(b"\x00" * 64).decode()),))
        broken = [[bad_first, seq[0][1]]]
        self.assertFalse(verify_sequence(broken, DATA, authority_keys=keys).ok)


class TestSignedRobustness(unittest.TestCase):
    """Malformed signed input must return ok=False, never raise (the 'never raise' contract)."""

    def test_signatures_none_does_not_crash(self):
        _signers, keys = _authority()
        ats = ArchiveTimeStamp("sha256", DATA[0], 1000, "confirmed", "ed25519", None)  # type: ignore[arg-type]
        # must not raise; anchor fails closed
        self.assertFalse(verify_sequence([[ats]], [DATA[0]], authority_keys=keys).ok)

    def test_malformed_signature_tuple_does_not_crash(self):
        _signers, keys = _authority()
        ats = ArchiveTimeStamp("sha256", DATA[0], 1000, "confirmed", "ed25519",
                               (("ed25519", "x", "extra"),))  # 3-tuple
        self.assertFalse(verify_sequence([[ats]], [DATA[0]], authority_keys=keys).ok)

    def test_non_int_time_fails_closed_not_raise(self):
        _signers, keys = _authority()
        a0 = ArchiveTimeStamp("sha256", DATA[0], "1000", "confirmed")  # type: ignore[arg-type]
        res = verify_sequence([[a0]], [DATA[0]], authority_keys=keys)  # must not raise
        self.assertFalse(res.ok)


if __name__ == "__main__":
    unittest.main()
