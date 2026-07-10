"""WP2 activation (ADR 0002): eval-result / test-result / SVR DSSE exports migrate off
`json.dumps(sort_keys=True)` to the versioned universal content root `jcs-sha256-v1`, with an explicit
`legacy-sortkeys-json-v0` mode so ALREADY-SIGNED released 2.0.0 receipts keep verifying byte-for-byte.

No-Fake, one invariant per test. Three load-bearing proofs (addendum §3.4 P0 + the non-breaking guarantee):

  A. a genuine released 2.0.0-format receipt (json.dumps root, NO `contentRootAlg`) still verifies (legacy);
  B. a new default receipt is `jcs-sha256-v1` and verifies against the shared RFC-8785 canonicalizer;
  C. a `json.dumps(sort_keys=True)` body OFFERED AS `jcs-sha256-v1` is REJECTED (fail-closed) unless legacy
     is explicitly declared/absent — proven in BOTH directions, with no silent fallback between algorithms.
"""
import base64
import json
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import canonical, dsse, generate_signer
from proofbundle.errors import ProofBundleError
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.intoto import (
    CONTENT_ROOT_ALG,
    EVAL_RESULT_PREDICATE_TYPE,
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    LEGACY_CONTENT_ROOT_ALG,
    STATEMENT_TYPE,
    TEST_RESULT_PAYLOAD_TYPE,
    _canonical_body,
    export_eval_result_dsse,
    export_intoto_dsse,
    export_svr_dsse,
    resolve_subject,
    to_eval_result_predicate,
    to_eval_result_statement,
    to_test_result_statement,
    verify_eval_result_dsse,
    verify_intoto_dsse,
    verify_svr_dsse,
)

TS = "2026-07-05T12:00:00Z"
CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True, "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32, "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1", "issuer": "ed25519:AAAA", "timestamp": TS,
    "assurance_level": "self_attested",
}


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _stmt(env) -> dict:
    return json.loads(base64.b64decode(env["payload"]))


def _legacy_json(obj) -> bytes:
    """The released 2.0.0 serializer, spelled out with stdlib json (independent of the module helper)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _receipt(signer, *, score="0.99", threshold="0.98"):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=",
        threshold=threshold, score=score, n=500, model_id="acme/secret-model", dataset_id="acme/secret-set",
        issuer=issuer_fingerprint(signer), timestamp=TS, model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
    return emit_eval_receipt(claim, signer)


# ─────────────────────────────────────────────────────────────────────────────
# Proof A — released 2.0.0 receipts (no contentRootAlg, json.dumps root) still verify. NON-BREAKING.
# ─────────────────────────────────────────────────────────────────────────────
class TestProofA_LegacyReceiptsStillVerify(unittest.TestCase):
    def _released_2_0_0_eval_result_envelope(self, signer):
        # Built the way released 2.0.0 built it: real statement, NO contentRootAlg, json.dumps(sort_keys)
        # root — NO dependency on the new producer. This is a genuine pre-migration artifact.
        statement = {
            "_type": STATEMENT_TYPE,
            "subject": resolve_subject("receipt", CLAIM, root_b64="cm9vdA=="),
            "predicateType": EVAL_RESULT_PREDICATE_TYPE,
            "predicate": to_eval_result_predicate(CLAIM, root_b64="cm9vdA=="),
        }
        body = _legacy_json(statement)
        return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE), body

    def test_A1_genuine_2_0_0_eval_result_receipt_verifies_as_legacy(self):
        signer = generate_signer()
        env, _ = self._released_2_0_0_eval_result_envelope(signer)
        self.assertNotIn("contentRootAlg", _stmt(env))          # the 2.0.0 wire carries no field
        res = verify_eval_result_dsse(env, _raw_pub(signer))
        self.assertTrue(res["ok"], res)                          # the CORE non-breaking guarantee
        self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)  # absent ⇒ legacy
        self.assertTrue(res["content_root_ok"])

    def test_A1_genuine_2_0_0_test_result_receipt_verifies_as_legacy(self):
        signer = generate_signer()
        statement = {
            "_type": STATEMENT_TYPE,
            "subject": [{"name": "eval-receipt", "digest": {"sha256": "c" * 64}}],
            "predicateType": "https://in-toto.io/attestation/test-result/v0.1",
            "predicate": {"result": "PASSED", "configuration": [{"name": "m", "digest": {"x": "y"}}]},
        }
        env = dsse.sign_envelope(_legacy_json(statement), signer, payload_type=TEST_RESULT_PAYLOAD_TYPE)
        res = verify_intoto_dsse(env, _raw_pub(signer))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)

    def test_A2_legacy_re_emission_is_byte_identical_to_the_2_0_0_wire(self):
        # The named legacy producer path reproduces the released wire byte-for-byte (retained, not deleted).
        signer = generate_signer()
        _, released_body = self._released_2_0_0_eval_result_envelope(signer)
        env_legacy = export_eval_result_dsse(CLAIM, signer, root_b64="cm9vdA==",
                                             content_root_alg=LEGACY_CONTENT_ROOT_ALG)
        self.assertEqual(base64.b64decode(env_legacy["payload"]), released_body)  # byte-identical
        self.assertNotIn("contentRootAlg", _stmt(env_legacy))
        self.assertTrue(verify_eval_result_dsse(env_legacy, _raw_pub(signer))["ok"])

    def test_A3_legacy_svr_wire_is_the_json_dumps_form_and_verifies(self):
        signer = generate_signer()
        env = export_svr_dsse(_receipt(signer), signer, time_created=TS,
                              content_root_alg=LEGACY_CONTENT_ROOT_ALG)
        stmt = _stmt(env)
        self.assertNotIn("contentRootAlg", stmt)
        # bytes are exactly the stdlib json.dumps(sort_keys) form (the released 2.0.0 SVR wire)
        self.assertEqual(base64.b64decode(env["payload"]), _legacy_json(stmt))
        res = verify_svr_dsse(env, _raw_pub(signer))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)


# ─────────────────────────────────────────────────────────────────────────────
# Proof B — new receipts default to jcs-sha256-v1 and verify against the shared RFC-8785 canonicalizer.
# ─────────────────────────────────────────────────────────────────────────────
class TestProofB_NewReceiptsUseJcs(unittest.TestCase):
    def test_B1_default_eval_result_is_jcs_and_verifies(self):
        signer = generate_signer()
        env = export_eval_result_dsse(CLAIM, signer, root_b64="cm9vdA==")   # default (no alg passed)
        stmt = _stmt(env)
        self.assertEqual(stmt["contentRootAlg"], CONTENT_ROOT_ALG)
        # the signed bytes ARE the RFC-8785 canonicalization of the statement (real JCS, not json.dumps)
        self.assertEqual(base64.b64decode(env["payload"]), canonical.canonicalize_statement(stmt))
        res = verify_eval_result_dsse(env, _raw_pub(signer))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], CONTENT_ROOT_ALG)
        self.assertTrue(res["content_root_ok"])

    def test_B2_default_test_result_and_svr_are_jcs_and_verify(self):
        signer = generate_signer()
        env_tr = export_intoto_dsse(CLAIM, signer, root_b64="AAAA")
        self.assertEqual(_stmt(env_tr)["contentRootAlg"], CONTENT_ROOT_ALG)
        self.assertEqual(base64.b64decode(env_tr["payload"]), canonical.canonicalize_statement(_stmt(env_tr)))
        self.assertTrue(verify_intoto_dsse(env_tr, _raw_pub(signer))["ok"])

        env_svr = export_svr_dsse(_receipt(signer), signer, time_created=TS)
        self.assertEqual(_stmt(env_svr)["contentRootAlg"], CONTENT_ROOT_ALG)
        self.assertEqual(base64.b64decode(env_svr["payload"]),
                         canonical.canonicalize_statement(_stmt(env_svr)))
        self.assertTrue(verify_svr_dsse(env_svr, _raw_pub(signer))["ok"])

    def test_B3_migration_is_a_real_wire_change(self):
        # Honest: the signed bytes DO change for new receipts (default jcs) vs the legacy re-emission.
        signer = generate_signer()
        jcs_body = base64.b64decode(export_eval_result_dsse(CLAIM, signer, root_b64="cm9vdA==")["payload"])
        legacy_body = base64.b64decode(export_eval_result_dsse(
            CLAIM, signer, root_b64="cm9vdA==", content_root_alg=LEGACY_CONTENT_ROOT_ALG)["payload"])
        self.assertNotEqual(jcs_body, legacy_body)


# ─────────────────────────────────────────────────────────────────────────────
# Proof C — the P0 guard (addendum §3.4): a json.dumps(sort_keys) root offered as jcs is REJECTED.
# ─────────────────────────────────────────────────────────────────────────────
def _attack_statement(alg):
    # A float forces json.dumps(sort_keys) ("1.0") to DIFFER from RFC-8785/JCS ("1"), so a legacy body
    # offered as jcs is provably non-canonical. Predicate shape is irrelevant to the binding check.
    stmt = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
        "predicateType": EVAL_RESULT_PREDICATE_TYPE,
        "predicate": {"threshold": 1.0},
    }
    if alg is not None:
        stmt["contentRootAlg"] = alg
    return stmt


class TestProofC_P0Reject(unittest.TestCase):
    def test_C0_the_divergence_is_real_not_tautological(self):
        s = _attack_statement(CONTENT_ROOT_ALG)
        self.assertNotEqual(_canonical_body(s), canonical.canonicalize_statement(s))  # 1.0 vs 1

    def _signed(self, signer, statement, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE):
        # Sign the json.dumps(sort_keys) bytes (a valid signature) so the ONLY reason a verify can fail is
        # the content-root binding — isolating the P0 guard from the signature check.
        body = _legacy_json(statement)
        return dsse.sign_envelope(body, signer, payload_type=payload_type)

    def test_C1_sortkeys_root_declared_jcs_is_rejected(self):
        signer = generate_signer()
        env = self._signed(signer, _attack_statement(CONTENT_ROOT_ALG))
        res = verify_eval_result_dsse(env, _raw_pub(signer))
        self.assertFalse(res["ok"], res)                 # P0: rejected
        self.assertFalse(res["content_root_ok"])         # rejected BY the binding, not the signature
        self.assertIn("canonical", res["content_root_detail"].lower())

    def test_C2_same_bytes_declared_legacy_or_absent_are_accepted(self):
        signer = generate_signer()
        for alg in (LEGACY_CONTENT_ROOT_ALG, None):      # explicit legacy, and absent ⇒ legacy
            env = self._signed(signer, _attack_statement(alg))
            res = verify_eval_result_dsse(env, _raw_pub(signer))
            self.assertTrue(res["ok"], (alg, res))       # the SAME bytes verify as legacy
            self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)

    def test_C3_jcs_bytes_declared_legacy_are_rejected_no_reverse_fallback(self):
        # The other direction: genuine JCS bytes declared as legacy must ALSO fail-closed. 1e-6 diverges
        # ROBUSTLY and SURVIVES a reparse: JCS writes "0.000001", Python json.dumps writes "1e-06". So JCS
        # bytes declared legacy → the verifier re-serializes with json.dumps → "1e-06" ≠ transmitted
        # "0.000001" → reject. No silent fallback in either direction.
        signer = generate_signer()
        stmt = {
            "_type": STATEMENT_TYPE,
            "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
            "predicateType": EVAL_RESULT_PREDICATE_TYPE,
            "predicate": {"n": 1e-6},
            "contentRootAlg": LEGACY_CONTENT_ROOT_ALG,   # declares legacy, but the bytes below are real JCS
        }
        body = canonical.canonicalize_statement(stmt)    # real JCS bytes ("0.000001")
        self.assertNotEqual(body, _legacy_json(json.loads(body)))  # guard: divergence survives reparse
        env = dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        res = verify_eval_result_dsse(env, _raw_pub(signer))
        self.assertFalse(res["ok"], res)
        self.assertFalse(res["content_root_ok"])

    def test_C4_unknown_alg_is_rejected_no_silent_default(self):
        signer = generate_signer()
        env = self._signed(signer, _attack_statement("totally-made-up-v9"))
        res = verify_eval_result_dsse(env, _raw_pub(signer))
        self.assertFalse(res["ok"], res)
        self.assertIn("unknown contentRootAlg", res["content_root_detail"])

    def test_C5_p0_guard_holds_on_all_three_released_paths(self):
        signer = generate_signer()
        cases = [
            (verify_eval_result_dsse, INTOTO_STATEMENT_PAYLOAD_TYPE),
            (verify_intoto_dsse, TEST_RESULT_PAYLOAD_TYPE),
            (verify_svr_dsse, INTOTO_STATEMENT_PAYLOAD_TYPE),
        ]
        for verify_fn, ptype in cases:
            env = self._signed(signer, _attack_statement(CONTENT_ROOT_ALG), payload_type=ptype)
            res = verify_fn(env, _raw_pub(signer))
            self.assertFalse(res["ok"], (verify_fn.__name__, res))
            self.assertFalse(res["content_root_ok"], verify_fn.__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Shape check (WP2-foundation-review Should-Fix #1): opt-in guard against a bare predicate. NON-BREAKING.
# ─────────────────────────────────────────────────────────────────────────────
class TestShapeCheckOptIn(unittest.TestCase):
    FULL = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
        "predicateType": EVAL_RESULT_PREDICATE_TYPE,
        "predicate": {"a": 1},
    }
    BARE_PREDICATE = {"a": 1, "b": 2}   # a predicate has none of the 4 Statement keys

    def test_full_statement_passes_the_opt_in_shape_check(self):
        self.assertIsInstance(
            canonical.canonicalize_statement(self.FULL, require_statement_shape=True), (bytes, bytearray))
        self.assertEqual(
            len(canonical.statement_content_root(self.FULL, require_statement_shape=True)), 32)

    def test_bare_predicate_fails_closed_when_shape_required(self):
        with self.assertRaises(ProofBundleError):
            canonical.canonicalize_statement(self.BARE_PREDICATE, require_statement_shape=True)
        with self.assertRaises(ProofBundleError):
            canonical.statement_content_root(self.BARE_PREDICATE, require_statement_shape=True)

    def test_default_off_stays_non_breaking_for_bare_predicate_callers(self):
        # decision.build_decision_statement canonicalizes a BARE predicate for its subject digest — the
        # default MUST NOT break that. Off by default: a bare predicate canonicalizes fine.
        self.assertIsInstance(canonical.canonicalize_statement(self.BARE_PREDICATE), (bytes, bytearray))
        self.assertEqual(len(canonical.statement_content_root(self.BARE_PREDICATE)), 32)

    def test_bytes_verifier_path_ignores_the_flag(self):
        # Opaque transmitted bytes cannot be shape-checked; the flag is a documented no-op on that path.
        import hashlib
        self.assertEqual(canonical.statement_content_root(b"exact", require_statement_shape=True),
                         hashlib.sha256(b"exact").digest())


# ─────────────────────────────────────────────────────────────────────────────
# Builder self-description: to_*_statement declare the alg; legacy omits the field.
# ─────────────────────────────────────────────────────────────────────────────
class TestBuilderDeclaration(unittest.TestCase):
    def test_builders_default_declare_jcs(self):
        s1 = to_eval_result_statement(CLAIM, subject=resolve_subject("receipt", CLAIM))
        self.assertEqual(s1["contentRootAlg"], CONTENT_ROOT_ALG)
        s2 = to_test_result_statement(CLAIM, subject_digest={"sha256": "a" * 64})
        self.assertEqual(s2["contentRootAlg"], CONTENT_ROOT_ALG)

    def test_builders_legacy_omit_the_field(self):
        s = to_eval_result_statement(CLAIM, subject=resolve_subject("receipt", CLAIM),
                                     content_root_alg=LEGACY_CONTENT_ROOT_ALG)
        self.assertNotIn("contentRootAlg", s)


if __name__ == "__main__":
    unittest.main()
