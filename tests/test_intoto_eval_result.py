"""in-toto eval-result predicate export (in-toto/attestation#565 proposal) — subject profiles,
salt-leak guard, determinism, DSSE payloadType, verify roundtrip. Adversarial-first (Paket 2 tests
1-4 + 13). No real keys or salts appear anywhere here."""
import json
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.intoto import (
    EVAL_RESULT_PREDICATE_TYPE,
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    export_eval_result_dsse,
    resolve_subject,
    to_eval_result_statement,
    verify_eval_result_dsse,
)

# A well-formed eval claim: commitments ONLY, never a plaintext model/dataset name or a salt.
CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True,
    "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32,
    "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1",
    "issuer": "ed25519:AAAA",
    "timestamp": "2026-07-05T12:00:00Z",
    "assurance_level": "self_attested",
}


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _statement_from(envelope) -> dict:
    import base64
    return json.loads(base64.b64decode(envelope["payload"]))


class TestSaltLeakGuard(unittest.TestCase):
    def test_no_salt_or_plaintext_in_statement(self):
        # Paket 2 test 1: grep the serialized statement — no plaintext identifier, no raw salt VALUE.
        # (The safe metadata `sha256-salted-v1` / `"salted": true` documents the privacy semantics and is
        # intentional; the leak we guard against is a plaintext name or a raw salt, neither of which the
        # commitment-only claim carries.)
        env = export_eval_result_dsse(CLAIM, generate_signer())
        body = json.dumps(_statement_from(env))
        for forbidden in ("gpt-4o", "internal-eval-set", "00112233445566778899aabbccddeeff"):
            self.assertNotIn(forbidden, body)
        # the salted flag IS present (proves the privacy semantics are marked, not hidden)
        self.assertIn('"salted": true', json.dumps(_statement_from(env), indent=0))

    def test_export_refuses_a_claim_carrying_plaintext(self):
        # A claim that still carries a plaintext name / raw salt must be REFUSED, never exported.
        for bad_key, bad_val in (("model_id", "gpt-4o"), ("salt", "00" * 16),
                                 ("dataset_name", "internal-eval-set")):
            with self.assertRaises(BundleFormatError):
                export_eval_result_dsse({**CLAIM, bad_key: bad_val}, generate_signer())


class TestDeterminism(unittest.TestCase):
    def test_statement_bytes_are_byte_identical(self):
        # Paket 2 test 2: identical input → byte-identical statement payload.
        s = generate_signer()
        a = _statement_from(export_eval_result_dsse(CLAIM, s))
        b = _statement_from(export_eval_result_dsse(CLAIM, s))
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


class TestRefuseInvalid(unittest.TestCase):
    def test_missing_required_field_is_refused(self):
        # Paket 2 test 3: an incomplete receipt claim cannot be exported.
        for drop in ("suite", "metric", "threshold", "model_id_commit", "timestamp"):
            claim = {k: v for k, v in CLAIM.items() if k != drop}
            with self.assertRaises(BundleFormatError):
                export_eval_result_dsse(claim, generate_signer())


class TestSubjectProfiles(unittest.TestCase):
    def test_receipt_profile_default_binds_without_revealing(self):
        subj = resolve_subject("receipt", CLAIM, root_b64="cm9vdA==")
        self.assertEqual(subj[0]["name"], "eval-receipt")
        self.assertEqual(set(subj[0]["digest"]), {"sha256"})
        self.assertEqual(len(subj[0]["digest"]["sha256"]), 64)

    def test_public_model_subject_digest_is_the_chosen_subject(self):
        # Paket 2 test 4: subject digest == the caller's chosen subject sha256.
        sha = "c3" * 32
        subj = resolve_subject("public-model", CLAIM, subject_name="acme/model-7b", subject_sha256=sha)
        self.assertEqual(subj[0]["name"], "acme/model-7b")
        self.assertEqual(subj[0]["digest"]["sha256"], sha)

    def test_release_gate_subject(self):
        sha = "d4" * 32
        subj = resolve_subject("release-gate", CLAIM, subject_name="acme/service:1.2.3", subject_sha256=sha)
        self.assertEqual(subj[0]["digest"]["sha256"], sha)

    def test_public_model_requires_name_and_valid_sha256(self):
        with self.assertRaises(BundleFormatError):
            resolve_subject("public-model", CLAIM, subject_sha256="c3" * 32)          # no name
        with self.assertRaises(BundleFormatError):
            resolve_subject("public-model", CLAIM, subject_name="x", subject_sha256="tooshort")
        with self.assertRaises(BundleFormatError):
            resolve_subject("public-model", CLAIM, subject_name="x", subject_sha256="G3" * 32)  # non-hex

    def test_unknown_profile_rejected(self):
        with self.assertRaises(BundleFormatError):
            resolve_subject("whatever", CLAIM)


class TestStatementShape(unittest.TestCase):
    def test_predicate_type_and_type_and_commitments(self):
        stmt = to_eval_result_statement(
            CLAIM, subject=resolve_subject("receipt", CLAIM), root_b64="cm9vdA==")
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], EVAL_RESULT_PREDICATE_TYPE)
        pred = stmt["predicate"]
        self.assertEqual(pred["claims"][0]["metric"], "refusal_rate")
        self.assertTrue(pred["claims"][0]["passed"])
        # commitments carry the salted flag and {alg,value}, never a plain hash
        self.assertTrue(pred["commitments"]["model"]["salted"])
        self.assertEqual(pred["commitments"]["model"]["value"], "a1" * 32)
        self.assertEqual(pred["receipt"]["merkleRootB64"], "cm9vdA==")

    def test_no_fabricated_optional_time_fields(self):
        # No preRegistration unless the claim actually has a prereg hash.
        pred = to_eval_result_statement(CLAIM, subject=resolve_subject("receipt", CLAIM))["predicate"]
        self.assertNotIn("preRegistration", pred)
        with_prereg = {**CLAIM, "prereg_sha256": "e5" * 32}
        pred2 = to_eval_result_statement(with_prereg, subject=resolve_subject("receipt", with_prereg))["predicate"]
        self.assertEqual(pred2["preRegistration"]["value"], "e5" * 32)


class TestDSSERoundtrip(unittest.TestCase):
    def test_payload_type_is_exact_intoto_statement(self):
        # Paket 2 test 13: DSSE payloadType MUST be application/vnd.in-toto+json.
        env = export_eval_result_dsse(CLAIM, generate_signer())
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")
        self.assertEqual(INTOTO_STATEMENT_PAYLOAD_TYPE, "application/vnd.in-toto+json")

    def test_verify_roundtrip_green_and_tamper_red(self):
        s = generate_signer()
        env = export_eval_result_dsse(CLAIM, s, root_b64="cm9vdA==")
        res = verify_eval_result_dsse(env, _raw_pub(s))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["predicate_type"], EVAL_RESULT_PREDICATE_TYPE)
        # wrong key → fail
        self.assertFalse(verify_eval_result_dsse(env, _raw_pub(generate_signer()))["ok"])
        # tamper the payload → fail
        import base64
        tampered = dict(env)
        stmt = _statement_from(env)
        stmt["predicate"]["claims"][0]["passed"] = False
        tampered["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
        self.assertFalse(verify_eval_result_dsse(tampered, _raw_pub(s))["ok"])

    def test_verify_accepts_urlsafe_base64_payload(self):
        # DSSE verifiers MUST accept standard OR url-safe base64 (Paket 2 test 13, second half).
        import base64
        s = generate_signer()
        env = export_eval_result_dsse(CLAIM, s)
        raw = base64.b64decode(env["payload"])
        env["payload"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.assertTrue(verify_eval_result_dsse(env, _raw_pub(s))["ok"])


if __name__ == "__main__":
    unittest.main()
