"""A verifier reads `public_model` and `release_gate` as `public-model` and `release-gate`; proofbundle writes hyphens.

in-toto/attestation pull request 575 spells the values of `subjectProfile` in snake_case, as those of
`assuranceLevel` are spelled: `receipt`, `public_model`, `release_gate`. proofbundle wrote and read the hyphen
forms only (`SUBJECT_PROFILES`), so a statement written after that draft failed at 6.6.1: the v0.1 member check
and the v0.2 predicate check both refused `public_model` and `release_gate`, and `proofbundle intoto --verify`
answered FAIL with exit 1.

Both checks now read the value through `_subject_profile_read`, the one table that equates the two spellings.
`receipt` has one spelling. Any other value is refused as before, with the same exit code. What proofbundle writes
does not change: the CLI choice, the exporters and the statements they sign keep the hyphen form, and the bytes the
exporters write here are pinned to the bytes the tree before this change wrote.
"""
from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse
from proofbundle import intoto as I

REPO = Path(__file__).resolve().parents[1]
_G2_JCS = REPO / "tests/fixtures/eval_result_v0_1/envelope_jcs.json"
# A fixed test seed, so the exporters' bytes are reproducible and can be pinned; it signs nothing outside this module.
_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

#: (spelling in the statement, the profile it is read as)
BOTH_SPELLINGS = (
    ("receipt", "receipt"),
    ("public-model", "public-model"), ("public_model", "public-model"),
    ("release-gate", "release-gate"), ("release_gate", "release-gate"),
)
#: Values that name no profile and stay refused.
OTHER_VALUES = ("public model", "publicModel", "Public-Model", "PUBLIC_MODEL", "release-gate ", "release__gate",
                "public-model_", "receipt_", "public", "model", "bogus_profile", "", 7, None, ["public_model"])

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
ROOT = "cmVjZWlwdC1tZXJrbGUtcm9vdA=="
EVALUATOR = "https://example.com/evaluator"
_DISCLOSED = {"subject_name": "acme/open-model-7b", "subject_sha256": "e4" * 32}


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(statement: dict) -> dict:
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    body = I._serialize_statement(statement, alg)
    return dsse.sign_envelope(body, _SIGNER, payload_type=I.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _v01_statement(profile) -> dict:
    """The statement a released version wrote (tests/fixtures/eval_result_v0_1), with `subjectProfile` set."""
    env = json.loads(_G2_JCS.read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(env["payload"]))
    statement["predicate"]["subjectProfile"] = profile
    return statement


def _v02_statement(profile) -> dict:
    """The draft's private-model example, written by hand, with `subjectProfile` set."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "eval-receipt", "digest": {"sha256": "c0" * 32}}],
        "predicateType": I.EVAL_RESULT_V02_PREDICATE_TYPE,
        "predicate": {
            "evaluator": {"id": EVALUATOR},
            "evaluatedAt": "2026-07-05T12:00:00Z",
            "suite": {"name": "safety-refusals", "version": "1.2.0"},
            "claims": [{"metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True}],
            "sampleSize": 500,
            "commitments": {
                "model": {"alg": "sha256-salted-v1", "value": "a1" * 32, "salted": True},
                "dataset": {"alg": "sha256-salted-v1", "value": "b2" * 32, "salted": True},
            },
            "assuranceLevel": "self_attested",
            "subjectProfile": profile,
            "evidence": [{"name": "eval-receipt", "digest": {"sha256": "d3" * 32}}],
        },
    }


def _cli(*argv: str) -> tuple[int, str]:
    from proofbundle.cli import main
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = main(list(argv))
        except SystemExit as exc:          # argparse refuses a choice with SystemExit(2)
            rc = exc.code
    return rc, out.getvalue() + err.getvalue()


def _cli_verify(envelope: dict) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "env.json"
        path.write_text(json.dumps(envelope), encoding="utf-8")
        return _cli("intoto", "--verify", "--pub", base64.b64encode(_pub()).decode(), str(path))


class TheTableIsTheOnePlace(unittest.TestCase):
    def test_each_spelling_is_read_as_its_profile(self):
        for spelling, profile in BOTH_SPELLINGS:
            with self.subTest(spelling=spelling):
                self.assertEqual(I._subject_profile_read(spelling), profile)

    def test_every_profile_it_reads_as_is_one_proofbundle_writes(self):
        self.assertEqual(sorted(set(I._SUBJECT_PROFILE_SPELLINGS.values())), sorted(I.SUBJECT_PROFILES))
        self.assertEqual(I.SUBJECT_PROFILES, ("receipt", "public-model", "release-gate"))

    def test_any_other_value_names_no_profile(self):
        for value in OTHER_VALUES:
            with self.subTest(value=value):
                self.assertIsNone(I._subject_profile_read(value))


class V01ReadsBothSpellings(unittest.TestCase):
    def test_public_model_with_an_underscore_verifies(self):
        self._verifies("public_model")

    def test_release_gate_with_an_underscore_verifies(self):
        self._verifies("release_gate")

    def test_public_model_with_a_hyphen_verifies(self):
        self._verifies("public-model")

    def test_release_gate_with_a_hyphen_verifies(self):
        self._verifies("release-gate")

    def test_receipt_verifies(self):
        self._verifies("receipt")

    def test_another_value_is_refused_with_exit_1(self):
        for value in OTHER_VALUES:
            with self.subTest(value=value):
                res = I.verify_eval_result_dsse(_sign(_v01_statement(value)), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn("subjectProfile", res["content_root_detail"])
        for value in ("public model", "PUBLIC_MODEL", "release__gate"):
            with self.subTest(cli=value):
                rc, text = _cli_verify(_sign(_v01_statement(value)))
                self.assertEqual(rc, 1, text)
                self.assertIn("[FAIL] eval-result attestation", text)

    def _verifies(self, spelling: str) -> None:
        env = _sign(_v01_statement(spelling))
        res = I.verify_eval_result_dsse(env, _pub())
        self.assertIs(res["ok"], True, res)
        rc, text = _cli_verify(env)
        self.assertEqual(rc, 0, text)
        self.assertIn("[PASS] eval-result attestation", text)


class V02ReadsBothSpellings(unittest.TestCase):
    def test_public_model_with_an_underscore_verifies(self):
        self._verifies("public_model")

    def test_release_gate_with_an_underscore_verifies(self):
        self._verifies("release_gate")

    def test_public_model_with_a_hyphen_verifies(self):
        self._verifies("public-model")

    def test_release_gate_with_a_hyphen_verifies(self):
        self._verifies("release-gate")

    def test_receipt_verifies(self):
        self._verifies("receipt")

    def test_another_value_is_refused_with_exit_1(self):
        for value in OTHER_VALUES:
            with self.subTest(value=value):
                statement = _v02_statement(value)
                ok, detail = I.classify_eval_result_v02_predicate(statement)
                self.assertIs(ok, False)
                self.assertIn("subjectProfile", detail)
                res = I.verify_eval_result_dsse(_sign(statement), _pub(),
                                                expected_predicate_type=I.EVAL_RESULT_V02_PREDICATE_TYPE)
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, res)
        for value in ("public model", "PUBLIC_MODEL", "release__gate"):
            with self.subTest(cli=value):
                rc, text = _cli_verify(_sign(_v02_statement(value)))
                self.assertEqual(rc, 1, text)
                self.assertIn("subjectProfile", text)

    def _verifies(self, spelling: str) -> None:
        statement = _v02_statement(spelling)
        self.assertEqual(I.classify_eval_result_v02_predicate(statement), (True, ""))
        env = _sign(statement)
        res = I.verify_eval_result_dsse(env, _pub(), expected_predicate_type=I.EVAL_RESULT_V02_PREDICATE_TYPE)
        self.assertIs(res["ok"], True, res)
        rc, text = _cli_verify(env)
        self.assertEqual(rc, 0, text)


if __name__ == "__main__":
    unittest.main()
