"""Property-based generalization of the witness-quorum key-material dedup (split-view resistance).

test_cosignature.py fixes the 2-name case (test_red_one_key_under_two_names_not_a_quorum). This
generalizes the invariant generatively:
  * ONE key under ANY number of names counts as ONE witness — a threshold >= 2 is never met by relabeling;
  * the DISTINCT-key count equals the number of distinct KEYS, independent of how many names each wears
    (a quorum is met at threshold == #distinct-keys and not at #distinct-keys + 1).

This is the C2SP requirement that operators use distinct keys per cosigner; the count must follow key
MATERIAL, never names.
"""
from __future__ import annotations

import hashlib
import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - dev-only dependency
    given = None

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import checkpoint as cp
from proofbundle import generate_signer

TS = 1_780_000_000
ROOT = hashlib.sha256(b"leaf").digest()
ORIGIN = "example.com/log"


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _fresh_note():
    log_key = generate_signer()
    note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
    return note, cp.vkey(ORIGIN, _raw_pub(log_key))


if given is not None:

    class TestWitnessQuorumDedupProperties(unittest.TestCase):
        @settings(max_examples=60, deadline=None)
        @given(st.integers(min_value=2, max_value=6), st.integers(min_value=2, max_value=6))
        def test_one_key_any_number_of_names_never_reaches_quorum(self, n_names, threshold):
            # one physical key registered under n_names names → exactly ONE distinct witness
            note, log_vkey = _fresh_note()
            sole = generate_signer()
            vkeys = []
            for i in range(n_names):
                name = f"witness{i}.example.com/w"
                note = cp.cosign_checkpoint(note, sole, name, TS + i)
                vkeys.append(cp.cosign_vkey(name, _raw_pub(sole)))
            res = cp.verify_witnessed_checkpoint(note, log_vkey, vkeys,
                                                 threshold=min(threshold, n_names))
            # distinct key material = 1, so any threshold >= 2 is unmet
            self.assertFalse(res["witnesses_ok"])
            self.assertFalse(res["ok"])

        @settings(max_examples=50, deadline=None)
        @given(st.integers(min_value=1, max_value=4), st.integers(min_value=0, max_value=2))
        def test_distinct_key_count_is_independent_of_names(self, m_keys, extra_names_each):
            # m distinct keys, each optionally relabeled under extra names → count == m
            note, log_vkey = _fresh_note()
            vkeys = []
            ts = TS
            for k in range(m_keys):
                key = generate_signer()
                for j in range(1 + extra_names_each):
                    name = f"w{k}n{j}.example.com/w"
                    note = cp.cosign_checkpoint(note, key, name, ts)
                    vkeys.append(cp.cosign_vkey(name, _raw_pub(key)))
                    ts += 1
            # quorum is met exactly at the distinct-key count, not the name count
            met = cp.verify_witnessed_checkpoint(note, log_vkey, vkeys, threshold=m_keys)
            self.assertTrue(met["witnesses_ok"])
            over = cp.verify_witnessed_checkpoint(note, log_vkey, vkeys, threshold=m_keys + 1)
            self.assertFalse(over["witnesses_ok"])


if __name__ == "__main__":
    unittest.main()
