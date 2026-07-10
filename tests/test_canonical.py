"""Universal content-root primitive (ADR 0002) — No-Fake, one invariant per test.

Covers: canonical-idempotence + key-order independence, producer/verifier agreement (the two-part rule),
signature bytes never in the preimage, full-Statement scope (not predicate-only), and fail-closed behaviour
when the RFC 8785 canonicalizer extra is absent.
"""
import hashlib
import json
import sys
import unittest
from unittest import mock

from proofbundle.canonical import (
    CONTENT_ROOT_ALG,
    CanonicalizerUnavailable,
    canonicalize_statement,
    statement_content_root,
)
from proofbundle.errors import ProofBundleError


def _statement():
    """A representative in-toto Statement (full: _type + subject + predicateType + predicate)."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "decision:abc", "digest": {"sha256": "a" * 64}}],
        "predicateType": "https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1",
        "predicate": {"schemaVersion": "0.1.0", "decisionId": "abc", "z": 1, "a": 2},
    }


class TestCanonicalizeStatement(unittest.TestCase):
    def test_key_order_independent(self):
        # RFC 8785 sorts object keys, so insertion order cannot change the canonical bytes.
        a = {"_type": "S", "b": 1, "a": {"y": 2, "x": 3}}
        b = {"a": {"x": 3, "y": 2}, "b": 1, "_type": "S"}
        self.assertEqual(canonicalize_statement(a), canonicalize_statement(b))

    def test_idempotent_over_reparse(self):
        # Canonicalizing a re-parsed canonical form yields byte-identical output (stable content root).
        stmt = _statement()
        once = canonicalize_statement(stmt)
        twice = canonicalize_statement(json.loads(once.decode("utf-8")))
        self.assertEqual(once, twice)

    def test_returns_bytes(self):
        self.assertIsInstance(canonicalize_statement(_statement()), (bytes, bytearray))


class TestStatementContentRoot(unittest.TestCase):
    def test_root_is_sha256_over_canonical_bytes(self):
        stmt = _statement()
        self.assertEqual(
            statement_content_root(stmt),
            hashlib.sha256(canonicalize_statement(stmt)).digest())
        self.assertEqual(len(statement_content_root(stmt)), 32)

    def test_producer_and_verifier_agree(self):
        # The two-part rule: the object path (canonicalize+hash) equals the bytes path over the SAME
        # canonical bytes a producer would sign. This agreement is the whole point of a content root.
        stmt = _statement()
        canonical = canonicalize_statement(stmt)
        self.assertEqual(statement_content_root(stmt), statement_content_root(canonical))

    def test_verifier_hashes_exact_bytes_never_recanonicalizes(self):
        # A verifier passes the EXACT transmitted payload bytes; the primitive must hash those bytes as-is
        # and MUST NOT re-canonicalize. Non-canonical bytes therefore root differently from the object.
        stmt = {"b": 1, "a": 2}
        noncanonical = b'{"b": 1, "a": 2}'   # original order + spaces: valid JSON, not RFC-8785 canonical
        self.assertNotEqual(canonicalize_statement(stmt), noncanonical)   # guard: bytes really are non-canon
        self.assertEqual(statement_content_root(noncanonical), hashlib.sha256(noncanonical).digest())
        self.assertNotEqual(statement_content_root(noncanonical), statement_content_root(stmt))

    def test_signature_bytes_never_in_preimage(self):
        # The content root is over the STATEMENT (pre-signature). Wrapping the exact same statement in DSSE
        # envelopes with DIFFERENT signatures leaves the statement's own root unchanged — it survives
        # counter-signing / key rotation / multi-sig.
        stmt = _statement()
        body = canonicalize_statement(stmt)
        root = statement_content_root(body)
        env_a = {"payloadType": "application/vnd.in-toto+json", "payload": body,
                 "signatures": [{"keyid": "k1", "sig": "AAAA"}]}
        env_b = {"payloadType": "application/vnd.in-toto+json", "payload": body,
                 "signatures": [{"keyid": "k1", "sig": "AAAA"}, {"keyid": "k2", "sig": "BBBB"}]}
        self.assertEqual(statement_content_root(env_a["payload"]), root)
        self.assertEqual(statement_content_root(env_b["payload"]), root)

    def test_full_statement_scope_not_predicate_only(self):
        # The root binds the FULL statement: changing subject OR predicateType (not just predicate) changes
        # it. Binding only the predicate would allow a subject / predicateType confusion attack.
        base = _statement()
        base_root = statement_content_root(base)

        diff_subject = json.loads(json.dumps(base))
        diff_subject["subject"][0]["digest"]["sha256"] = "b" * 64
        self.assertNotEqual(statement_content_root(diff_subject), base_root)

        diff_ptype = json.loads(json.dumps(base))
        diff_ptype["predicateType"] = "https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.2"
        self.assertNotEqual(statement_content_root(diff_ptype), base_root)

    def test_bad_input_type_fail_closed(self):
        for bad in (123, 1.5, None, "a-json-string"):
            with self.assertRaises(ProofBundleError):
                statement_content_root(bad)  # type: ignore[arg-type]


class TestFailClosedWithoutExtra(unittest.TestCase):
    def test_missing_rfc8785_raises_canonicalizer_unavailable(self):
        # Simulate the base install (no [eval] extra): `import rfc8785` fails → fail-closed, not a raw
        # ImportError and never a silent pass over non-canonical bytes.
        with mock.patch.dict(sys.modules, {"rfc8785": None}):
            with self.assertRaises(CanonicalizerUnavailable):
                canonicalize_statement(_statement())
            with self.assertRaises(CanonicalizerUnavailable):
                statement_content_root(_statement())   # producer path needs the canonicalizer too

    def test_verifier_bytes_path_needs_no_extra(self):
        # The verifier byte path is a plain SHA-256: it must keep working with no canonicalizer installed.
        with mock.patch.dict(sys.modules, {"rfc8785": None}):
            self.assertEqual(statement_content_root(b"exact-bytes"),
                             hashlib.sha256(b"exact-bytes").digest())


class TestModuleContract(unittest.TestCase):
    def test_declared_alg_id(self):
        self.assertEqual(CONTENT_ROOT_ALG, "jcs-sha256-v1")

    def test_public_top_level_exports(self):
        import proofbundle
        self.assertIs(proofbundle.canonicalize_statement, canonicalize_statement)
        self.assertIs(proofbundle.statement_content_root, statement_content_root)


if __name__ == "__main__":
    unittest.main()
