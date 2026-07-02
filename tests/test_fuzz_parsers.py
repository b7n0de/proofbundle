"""Property-based fuzzing of the text/JWT parsers (v1.8).

The invariant for every attacker-controlled parser: on ANY input it returns a value or raises a
proofbundle error (BundleFormatError / ProofBundleError / ValueError) — NEVER an uncaught crash
(AttributeError, IndexError, KeyError, TypeError, UnicodeError, recursion, …) and never a hang.
This is the "never a raw traceback" contract, checked adversarially with Hypothesis rather than
by hand-picked cases. Hypothesis is the lowest-friction sound fuzzer for pure-Python parsers
(no native toolchain); an Atheris coverage-guided driver over the same bodies can be added under
fuzz/ for Linux CI if deeper coverage is ever wanted. hypothesis is a dev dependency only — this
module no-ops when it is absent (same pattern as test_merkle_property.py)."""
from __future__ import annotations

import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - dev-only dependency
    given = None

from proofbundle.errors import ProofBundleError
from proofbundle.tlogproof import parse_tlog_proof, verify_tlog_proof
from proofbundle.checkpoint import verify_checkpoint, verify_cosignature
from proofbundle.statuslist import verify_status_snapshot
from proofbundle.kbjwt import split_key_binding, verify_key_binding
from proofbundle.sdjwt import verify_sd_jwt

_ALLOWED = (ProofBundleError, ValueError)   # the documented "malformed input" surface


def _must_not_crash(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except _ALLOWED:
        pass   # documented malformed-input path — fine
    # any other exception propagates and fails the test (the contract violation we hunt)


if given is not None:
    _texts = st.text(alphabet=st.characters(min_codepoint=1, max_codepoint=0x2FFF), max_size=400)

    class TestParserRobustness(unittest.TestCase):
        @settings(max_examples=300, deadline=None)
        @given(_texts)
        def test_parse_tlog_proof_never_crashes(self, s):
            _must_not_crash(parse_tlog_proof, s)

        @settings(max_examples=200, deadline=None)
        @given(_texts, _texts)
        def test_verify_tlog_proof_never_crashes(self, proof, leaf):
            _must_not_crash(verify_tlog_proof, proof, leaf.encode("utf-8", "surrogatepass"),
                            "log+00000000+" + "A" * 44)

        @settings(max_examples=300, deadline=None)
        @given(_texts, _texts)
        def test_verify_checkpoint_never_crashes(self, note, vkey):
            _must_not_crash(verify_checkpoint, note, vkey)

        @settings(max_examples=300, deadline=None)
        @given(_texts, _texts)
        def test_verify_cosignature_never_crashes(self, note, vkey):
            _must_not_crash(verify_cosignature, note, vkey)

        @settings(max_examples=300, deadline=None)
        @given(_texts)
        def test_split_key_binding_never_crashes(self, compact):
            sd, kb = split_key_binding(compact)          # total by contract → returns a tuple
            self.assertIsInstance(sd, str)

        @settings(max_examples=300, deadline=None)
        @given(_texts)
        def test_verify_key_binding_never_crashes(self, compact):
            _must_not_crash(verify_key_binding, compact)

        @settings(max_examples=300, deadline=None)
        @given(_texts)
        def test_verify_sd_jwt_never_crashes(self, compact):
            _must_not_crash(verify_sd_jwt, compact)

        @settings(max_examples=200, deadline=None)
        @given(_texts)
        def test_verify_status_snapshot_never_crashes(self, token):
            _must_not_crash(verify_status_snapshot, token, expected_uri="u", index=0,
                            issuer_pubkey=b"\x00" * 32)

        @settings(max_examples=200, deadline=None)
        @given(_texts, st.one_of(st.text(min_size=32, max_size=32), st.integers(),
                                 st.lists(st.integers()), st.none(), st.binary(max_size=64)))
        def test_verify_status_snapshot_never_crashes_on_malformed_receipt_key(self, token, rk):
            # v1.9.1 self_issued: receipt_issuer_pubkey darf JEDEN Typ tragen ohne die 'never crashes'-Zusage
            # zu brechen (der symmetrische Typ-Guard fängt non-bytes → self_issued=False statt TypeError).
            _must_not_crash(verify_status_snapshot, token, expected_uri="u", index=0,
                            issuer_pubkey=b"\x00" * 32, receipt_issuer_pubkey=rk)


if __name__ == "__main__":
    unittest.main()
