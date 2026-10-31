"""The strings svr v0.1, eval-result v0.1 and test-result v0.1 type as URIs or timestamps verify only in that form.

The predicates give these members a form, not only the JSON type string: svr v0.1 types `verifier.id` as TypeURI
and `timeCreated` as Timestamp (in-toto spec/predicates/svr.md v0.1), docs/IN_TOTO_PROFILE.md types the
`verifier.id` of eval-result v0.1 as TypeURI and its `evaluatedAt` as the RFC 3339 time of the receipt, and the
test-result predicate types `url` as ResourceURI. eval-result v0.2 already reads its own two with `_URI_RE` and
`_is_rfc3339`.

Measured on main b55d736d, two runs each: a validly signed statement verified with "not a uri" in each URI member
and with "yesterday" in each timestamp member, and `proofbundle svr --verify` and `proofbundle intoto --verify`
answered PASS with exit 0. By the owner's choice of 2026-10-31 these members are read in their form, with the
readers of v0.2; `url` in URI form only, never fetched.

A producer writes no statement its own verifier refuses: `export_svr_dsse` refuses a `time_created`,
`to_test_result_statement` a `url` and `to_eval_result_predicate` a claim timestamp that is not in that form.
Every statement a released version wrote has these forms, so it keeps verifying.
"""
from __future__ import annotations

import base64
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse, generate_signer
from proofbundle import intoto as I
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint

REPO = Path(__file__).resolve().parents[1]
_G2_JCS = REPO / "tests/fixtures/eval_result_v0_1/envelope_jcs.json"
_G2_CORPUS = REPO / "tests/fixtures/eval_result_v0_1/corpus.json"
# A key made for this module alone; it signs only the statements below.
_SIGNER = Ed25519PrivateKey.generate()
_ROOT = "0191e2d1d171c8a2effd253b3d6dbd250cc6d4dfa28ffc18e0a7bf2ad1c95242"
_SALT = b"\x11" * 16
NOT_A_URI = ("not a uri", "", "proofbundle", "https://b7n0de.com/a b")
NOT_A_TIME = ("yesterday", "", "2026-10-31", "2026-10-31T09:00:00", "2026-13-01T00:00:00Z")
CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True, "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32, "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1", "issuer": "ed25519:AAAA", "timestamp": "2026-07-05T12:00:00Z",
    "assurance_level": "self_attested",
}


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(statement: dict, payload_type: str = I.INTOTO_STATEMENT_PAYLOAD_TYPE) -> dict:
    """A valid signature over the bytes of `statement` under the content root it declares."""
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    return dsse.sign_envelope(I._serialize_statement(statement, alg), _SIGNER, payload_type=payload_type)


def _svr() -> dict:
    """An SVR v0.1 statement in the form `export_svr_dsse` writes."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"verifier": {"id": I.VERIFIER_ID}, "timeCreated": "2026-10-31T09:00:00Z",
                          "properties": ["PROOFBUNDLE_SIGNATURE_VALID"]},
            "predicateType": I.SVR_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _ROOT}, "name": "eval-receipt"}]}


def _released_eval_result() -> dict:
    env = json.loads(_G2_JCS.read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(env["payload"]))


def _test_result() -> dict:
    """A generic test result with both required members and a `url`."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"result": "PASSED",
                          "configuration": [{"name": "suite.yaml", "digest": {"sha256": _ROOT}}],
                          "url": "https://ci.example/run/1", "passedTests": ["a"]},
            "predicateType": I.TEST_RESULT_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _ROOT}, "name": "artifact"}]}


def _cli(verb: str, env: dict) -> tuple[int, str]:
    from proofbundle.cli import main
    with tempfile.TemporaryDirectory() as td:
        pfad = Path(td) / "env.json"
        pfad.write_text(json.dumps(env), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main([verb, "--verify", "--pub", base64.b64encode(_pub()).decode(), str(pfad)])
    return rc, out.getvalue() + err.getvalue()


def _receipt(signer):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=",
        threshold="0.98", score="0.99", n=500, model_id="acme/secret-model", dataset_id="acme/secret-set",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-05T12:00:00Z", model_salt=_SALT, dataset_salt=_SALT)
    return emit_eval_receipt(claim, signer)


class AnSvrString(unittest.TestCase):
    def test_a_verifier_id_that_is_no_uri_does_not_verify(self):
        for wert in NOT_A_URI:
            with self.subTest(wert=wert):
                statement = _svr()
                statement["predicate"]["verifier"]["id"] = wert
                res = I.verify_svr_dsse(_sign(statement), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["predicate_shape_ok"], False)
                self.assertIn("verifier.id must be a URI", res["content_root_detail"])

    def test_a_time_created_that_is_no_rfc3339_time_does_not_verify(self):
        for wert in NOT_A_TIME:
            with self.subTest(wert=wert):
                statement = _svr()
                statement["predicate"]["timeCreated"] = wert
                res = I.verify_svr_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["predicate_shape_ok"], False)
                self.assertIn("timeCreated must be an RFC 3339", res["content_root_detail"])

    def test_the_cli_does_not_answer_pass(self):
        for pfad, wert in ((("verifier", "id"), "not a uri"), (("timeCreated",), "yesterday")):
            with self.subTest(pfad=pfad):
                statement = _svr()
                ziel = statement["predicate"]
                for teil in pfad[:-1]:
                    ziel = ziel[teil]
                ziel[pfad[-1]] = wert
                rc, text = _cli("svr", _sign(statement))
                self.assertEqual(rc, 2, text)
                self.assertNotIn("[PASS]", text)

    def test_the_exporter_refuses_a_time_created_that_is_no_rfc3339_time(self):
        s = generate_signer()
        for wert in ("yesterday", "2026-10-31", "2026-10-31T09:00:00"):
            with self.subTest(wert=wert):
                with self.assertRaises(BundleFormatError) as ctx:
                    I.export_svr_dsse(_receipt(s), s, time_created=wert)
                self.assertIn("time_created must be an RFC 3339", str(ctx.exception))


class AnEvalResultV01String(unittest.TestCase):
    def test_a_verifier_id_that_is_no_uri_does_not_verify(self):
        for wert in NOT_A_URI:
            with self.subTest(wert=wert):
                statement = _released_eval_result()
                statement["predicate"]["verifier"]["id"] = wert
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn("verifier.id: must be a URI", res["content_root_detail"])

    def test_an_evaluated_at_that_is_no_rfc3339_time_does_not_verify(self):
        for wert in NOT_A_TIME:
            with self.subTest(wert=wert):
                statement = _released_eval_result()
                statement["predicate"]["evaluatedAt"] = wert
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn("evaluatedAt", res["content_root_detail"])

    def test_the_cli_answers_fail_with_exit_1(self):
        for pfad, wert in ((("verifier", "id"), "not a uri"), (("evaluatedAt",), "yesterday")):
            with self.subTest(pfad=pfad):
                statement = _released_eval_result()
                ziel = statement["predicate"]
                for teil in pfad[:-1]:
                    ziel = ziel[teil]
                ziel[pfad[-1]] = wert
                rc, text = _cli("intoto", _sign(statement))
                self.assertEqual(rc, 1, text)
                self.assertIn("[FAIL] eval-result attestation", text)

    def test_the_producer_refuses_a_claim_timestamp_that_is_no_rfc3339_time(self):
        for wert in ("yesterday", "2026-07-05", "2026-07-05T12:00:00"):
            with self.subTest(wert=wert):
                with self.assertRaises(BundleFormatError) as ctx:
                    I.to_eval_result_predicate({**CLAIM, "timestamp": wert})
                self.assertIn("timestamp must be an RFC 3339", str(ctx.exception))


class ATestResultUrl(unittest.TestCase):
    def test_a_url_that_is_no_uri_does_not_verify(self):
        for wert in NOT_A_URI:
            with self.subTest(wert=wert):
                statement = _test_result()
                statement["predicate"]["url"] = wert
                res = I.verify_intoto_dsse(_sign(statement, I.TEST_RESULT_PAYLOAD_TYPE), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn("predicate url: must be a URI", res["content_root_detail"])

    def test_the_producer_refuses_a_url_that_is_no_uri(self):
        for wert in ("not a uri", "ci.example/run/1"):
            with self.subTest(wert=wert):
                with self.assertRaises(BundleFormatError) as ctx:
                    I.to_test_result_statement(CLAIM, subject_digest={"sha256": _ROOT}, url=wert)
                self.assertIn("url must be a URI", str(ctx.exception))


class Controls(unittest.TestCase):
    def test_the_well_formed_statements_verify(self):
        self.assertIs(I.verify_svr_dsse(_sign(_svr()), _pub())["ok"], True)
        self.assertIs(I.verify_eval_result_dsse(_sign(_released_eval_result()), _pub())["ok"], True)
        self.assertIs(I.verify_intoto_dsse(_sign(_test_result(), I.TEST_RESULT_PAYLOAD_TYPE), _pub())["ok"], True)

    def test_an_offset_and_fractional_seconds_are_rfc3339_times(self):
        for wert in ("2026-10-31T10:00:00+01:00", "2026-10-31T09:00:00.123456Z", "2026-10-31t09:00:00z"):
            with self.subTest(wert=wert):
                statement = _svr()
                statement["predicate"]["timeCreated"] = wert
                self.assertIs(I.verify_svr_dsse(_sign(statement), _pub())["ok"], True)

    def test_the_svr_exporter_signs_what_its_verifier_accepts(self):
        s = generate_signer()
        pub = s.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        for kw in ({}, {"time_created": "2026-07-05T12:34:56Z"}, {"time_created": ""}):
            with self.subTest(kw=kw):
                res = I.verify_svr_dsse(I.export_svr_dsse(_receipt(s), s, **kw), pub)
                self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_the_test_result_exporter_with_a_uri_url_signs_what_its_verifier_accepts(self):
        env = I.export_intoto_dsse(CLAIM, _SIGNER, url="https://ci.example/run/1")
        res = I.verify_intoto_dsse(env, _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_every_statement_a_released_version_wrote_still_verifies(self):
        corpus = json.loads(_G2_CORPUS.read_text(encoding="utf-8"))
        public = base64.b64decode(corpus["public_key_b64"])
        self.assertEqual(len(corpus["entries"]), 14)
        for entry in corpus["entries"]:
            with self.subTest(entry=entry["id"]):
                res = I.verify_eval_result_dsse(copy.deepcopy(entry["envelope"]), public)
                self.assertIs(res["ok"], True, res)


if __name__ == "__main__":
    unittest.main()
