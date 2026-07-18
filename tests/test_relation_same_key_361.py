"""3.6.1 — same-key relation_signer requires a matching verified_under (PB-2026-0717-04).

Before 3.6.1 the same-key rule only produced a violation when ``verified_under`` was PRESENT and
unequal. A VERIFIED edge with a MISSING/None ``verified_under`` produced no violation (fail-open
footgun in the direct related-API path; the CLI loader always sets it). The fix: once an edge is
VERIFIED, same-key REQUIRES a present ``verified_under`` that byte-matches the successor key, else
``RELATION_SIGNER_UNAUTHORIZED``. A declared-only (unresolved) edge is unaffected (no false
unauthorized) — that is the resolution pin's job.
"""
import base64
import unittest

from proofbundle.emit import generate_signer
from proofbundle.relation import (
    CODE_RELATION_SIGNER_UNAUTHORIZED,
    LINEAGE_DECLARED_UNRESOLVED,
    LINEAGE_VERIFIED,
    evaluate_relations_policy,
)

_SAME_KEY = {"relation_signer": {"supersedes": {"mode": "same-key"}}}


def _pub_b64(signer):
    return base64.b64encode(signer.public_key().public_bytes_raw()).decode()


def _lineage(resolution, verified_under=..., relation="supersedes"):
    edge = {"relation": relation, "resolution": resolution, "targetDigest": "a" * 64}
    if verified_under is not ...:   # allow explicitly omitting the key vs. setting it to None
        edge["verified_under"] = verified_under
    return {"edges": [edge]}


def _codes(section, lineage, succ_key):
    return [v["code"] for v in evaluate_relations_policy(section, lineage, successor_key_b64=succ_key)]


class SameKeyVerifiedUnder(unittest.TestCase):
    def setUp(self):
        self.succ = generate_signer()
        self.succ_key = _pub_b64(self.succ)

    def test_same_key_verified_without_verified_under_fails(self):
        # VERIFIED edge, verified_under key entirely absent -> unauthorized (was a silent pass).
        codes = _codes(_SAME_KEY, _lineage(LINEAGE_VERIFIED), self.succ_key)
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, codes)

    def test_same_key_verified_under_null_fails(self):
        codes = _codes(_SAME_KEY, _lineage(LINEAGE_VERIFIED, verified_under=None), self.succ_key)
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, codes)

    def test_same_key_verified_under_differing_key_fails(self):
        other = _pub_b64(generate_signer())
        codes = _codes(_SAME_KEY, _lineage(LINEAGE_VERIFIED, verified_under=other), self.succ_key)
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, codes)

    def test_same_key_verified_under_matching_passes(self):
        # the only accept path: VERIFIED and verified_under byte-matches the successor key.
        codes = _codes(_SAME_KEY, _lineage(LINEAGE_VERIFIED, verified_under=self.succ_key), self.succ_key)
        self.assertNotIn(CODE_RELATION_SIGNER_UNAUTHORIZED, codes)

    def test_declared_only_edge_is_not_unauthorized(self):
        # an unresolved (declared-only) edge must NOT be flagged unauthorized — resolution is a
        # separate pin, and same-key can only be judged once the target verified.
        codes = _codes(_SAME_KEY, _lineage(LINEAGE_DECLARED_UNRESOLVED, verified_under=None), self.succ_key)
        self.assertNotIn(CODE_RELATION_SIGNER_UNAUTHORIZED, codes)

    def test_related_result_cannot_claim_verified_without_verification_key(self):
        # behavioural form of "make inconsistent states unrepresentable": a result that claims
        # VERIFIED but carries no verification key is rejected, so a consumer can never read a
        # satisfied same-key edge without a bound key.
        codes = _codes(_SAME_KEY, _lineage(LINEAGE_VERIFIED, verified_under=None), self.succ_key)
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, codes)


class RustParity(unittest.TestCase):
    def test_python_rust_same_key_missing_key_parity(self):
        self.skipTest("BLOCKED-rust-fix-open: the Rust same-key verified_under fix is a separate open "
                      "item (PB-2026-0717-04 Rust half); parity is NOT-RUN, not a PASS.")


if __name__ == "__main__":
    unittest.main()
