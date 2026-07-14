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

    def test_backward_compat_unsigned_default_path(self):
        # no sig_alg, no authority_keys → the legacy structural anchor path still verifies
        seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
        self.assertTrue(verify_sequence(seq, DATA).ok)


if __name__ == "__main__":
    unittest.main()
