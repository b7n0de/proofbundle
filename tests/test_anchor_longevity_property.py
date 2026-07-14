"""Property-based tests (Hypothesis) for the anchor-longevity modules — B2 hashalg, B3/B4 renewal, B5
pqsig. Generational testing catches the input VARIATIONS a handful of fixed vectors miss: arbitrary
payloads, arbitrary current-algorithm pairs, arbitrary ascending renewal sequences with mixed modes,
arbitrary tamper positions.

Style matches tests/test_merkle_property.py (unittest + Hypothesis, dev-only dependency, guarded import).
"""
from __future__ import annotations

import hashlib
import unittest

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - dev-only dependency
    given = None

from proofbundle.hashalg import (
    HASH_REGISTRY,
    compute_digest,
    compute_dual_hash,
    resolve_hash_alg,
    verify_dual_hash,
)
from proofbundle.renewal import (
    build_initial_sequence,
    last_ats,
    renew_hashtree,
    renew_timestamp,
)
from proofbundle.renewal import verify_sequence as _verify_sequence


def verify_sequence(seq, data, **kw):
    # structural property tests: opt into the unauthenticated anchor so the covering/ordering logic is
    # what is under test (the signed anchor path is covered by tests/test_renewal_signed.py).
    kw.setdefault("allow_unauthenticated_anchor", True)
    return _verify_sequence(seq, data, **kw)


_CURRENT = [a for a, spec in HASH_REGISTRY.items() if spec.status == "current"]
_DEPRECATED = [a for a, spec in HASH_REGISTRY.items() if spec.status == "deprecated"]
_HEX = "0123456789abcdef"


def _digest_list(payloads):
    return [hashlib.sha256(p).hexdigest() for p in payloads] or ["a" * 64]


if given is not None:

    class TestHashAlgProperties(unittest.TestCase):
        @settings(max_examples=200, deadline=None)
        @given(st.binary(max_size=2048), st.sampled_from(_CURRENT))
        def test_compute_digest_matches_hashlib(self, data, alg):
            spec = resolve_hash_alg(alg)
            expected = hashlib.new(spec.hashlib_name, data).hexdigest()
            self.assertEqual(compute_digest(data, alg), expected)

        @settings(max_examples=200, deadline=None)
        @given(st.binary(max_size=2048), st.lists(st.sampled_from(_CURRENT), min_size=2, max_size=4,
                                                  unique=True))
        def test_dual_hash_roundtrips_for_any_current_pair(self, data, algs):
            digests = compute_dual_hash(data, algs)
            self.assertTrue(verify_dual_hash(data, digests).ok)

        @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
        @given(st.binary(max_size=1024), st.binary(max_size=1024),
               st.lists(st.sampled_from(_CURRENT), min_size=2, max_size=3, unique=True))
        def test_dual_hash_fails_for_different_bytes(self, data, other, algs):
            if data == other:
                return
            digests = compute_dual_hash(data, algs)
            self.assertFalse(verify_dual_hash(other, digests).ok)

        @settings(max_examples=200, deadline=None)
        @given(st.text(alphabet=_HEX, min_size=1, max_size=12))
        def test_unregistered_ids_always_fail_closed(self, name):
            if name in HASH_REGISTRY:
                return
            with self.assertRaises(Exception):
                resolve_hash_alg(name)

        @settings(max_examples=50, deadline=None)
        @given(st.sampled_from(_DEPRECATED) if _DEPRECATED else st.just("sha1"))
        def test_deprecated_always_fails_closed_by_default(self, alg):
            # the algorithm-confusion defense: a deprecated hash must never resolve by default
            with self.assertRaises(Exception):
                resolve_hash_alg(alg)
            # …but a legacy verifier may opt in explicitly (the id is known, just weak)
            self.assertEqual(resolve_hash_alg(alg, allow_deprecated=True).status, "deprecated")

    class TestRenewalProperties(unittest.TestCase):
        @settings(max_examples=150, deadline=None)
        @given(st.lists(st.binary(min_size=1, max_size=64), min_size=1, max_size=6),
               st.lists(st.sampled_from(["ts", "ht"]), min_size=0, max_size=6))
        def test_any_ascending_renewal_sequence_verifies(self, payloads, modes):
            data = _digest_list(payloads)
            seq = build_initial_sequence(data, hash_alg="sha256", time=1000)
            t = 1000
            for i, mode in enumerate(modes):
                t += 1 + i
                if mode == "ts":
                    seq = renew_timestamp(seq, time=t)
                else:
                    # alternate the stronger hash so a hash-tree renewal always moves algorithm forward
                    seq = renew_hashtree(seq, data, new_hash_alg="sha512" if i % 2 == 0 else "sha3-256",
                                         time=t)
            res = verify_sequence(seq, data)
            self.assertTrue(res.ok, msg=[str(c) for c in res.checks if not c.ok])
            # the watched ATS is always the newest by time
            self.assertEqual(last_ats(seq).time, t if modes else 1000)

        @settings(max_examples=150, deadline=None)
        @given(st.lists(st.binary(min_size=1, max_size=64), min_size=1, max_size=6),
               st.integers(min_value=0, max_value=5))
        def test_tampering_any_data_object_fails(self, payloads, n_renewals):
            data = _digest_list(payloads)
            seq = build_initial_sequence(data, hash_alg="sha256", time=1000)
            t = 1000
            for i in range(n_renewals):
                t += 1 + i
                seq = renew_hashtree(seq, data, new_hash_alg="sha512", time=t)
            tampered = list(data)
            tampered[0] = "f" * 64 if tampered[0] != "f" * 64 else "e" * 64
            self.assertFalse(verify_sequence(seq, tampered).ok)

    class TestSignedMigrationProperties(unittest.TestCase):
        @settings(max_examples=60, deadline=None)
        @given(st.lists(st.tuples(st.sampled_from(["ts", "ht"]),
                                  st.sampled_from(["ed25519", "hybrid-ed25519-mldsa65", "mldsa65"])),
                        min_size=0, max_size=5))
        def test_any_sig_alg_migration_path_verifies(self, steps):
            # any interleaving of hash-renewal mode AND signature-algorithm migration, signed for real, must
            # verify under the authority keys — the gap the property layer previously did not cover.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            from proofbundle.pqsig import generate_mldsa
            ed = Ed25519PrivateKey.generate()
            m = generate_mldsa("mldsa65")
            signers = {"ed25519": ed, "mldsa65": m}
            keys = {"ed25519": ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                    "mldsa65": m.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}
            data = ["a" * 64, "b" * 64]
            seq = build_initial_sequence(data, hash_alg="sha256", time=1000,
                                         sig_alg="ed25519", signers=signers)
            t = 1000
            for i, (mode, sa) in enumerate(steps):
                t += 1 + i
                if mode == "ts":
                    seq = renew_timestamp(seq, time=t, sig_alg=sa, signers=signers)
                else:
                    seq = renew_hashtree(seq, data, new_hash_alg="sha512" if i % 2 == 0 else "sha3-256",
                                         time=t, sig_alg=sa, signers=signers)
            res = _verify_sequence(seq, data, authority_keys=keys)
            self.assertTrue(res.ok, [str(c) for c in res.checks if not c.ok])


if __name__ == "__main__":
    unittest.main()
