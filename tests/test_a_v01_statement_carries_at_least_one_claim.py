"""An eval-result v0.1 statement verifies only when `claims` carries at least one claim.

docs/IN_TOTO_PROFILE.md lists `claims[]` without a minimum, and the v0.2 draft requires one or more
(docs/upstream/eval-result.md). By the owner's choice of 2026-10-31 a v0.1 statement claims something as well: an
eval-result without a claim attests nothing.

Measured on main b55d736d and with the three patches of the predicate sweep: a validly signed v0.1 statement whose
`claims` was [] verified ok=True, and `proofbundle intoto --verify` printed `[PASS] eval-result attestation` with
exit 0.

Every statement a released version wrote carries exactly one claim (the 14 entries of
tests/fixtures/eval_result_v0_1/corpus.json), so they keep verifying, and so does every statement
`to_eval_result_predicate` writes.
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

from proofbundle import dsse
from proofbundle import intoto as I

REPO = Path(__file__).resolve().parents[1]
_G2_JCS = REPO / "tests/fixtures/eval_result_v0_1/envelope_jcs.json"
_G2_CORPUS = REPO / "tests/fixtures/eval_result_v0_1/corpus.json"
# A key made for this module alone; it re-signs the released statement below.
_SIGNER = Ed25519PrivateKey.generate()


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(statement: dict) -> dict:
    """A valid signature over the bytes of `statement` under the content root it declares."""
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    body = I._serialize_statement(statement, alg)
    return dsse.sign_envelope(body, _SIGNER, payload_type=I.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _released_statement() -> dict:
    env = json.loads(_G2_JCS.read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(env["payload"]))


def _with_claims(claims: list) -> dict:
    statement = _released_statement()
    statement["predicate"]["claims"] = claims
    return statement


def _cli(env: dict) -> tuple[int, str]:
    from proofbundle.cli import main
    with tempfile.TemporaryDirectory() as td:
        pfad = Path(td) / "env.json"
        pfad.write_text(json.dumps(env), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["intoto", "--verify", "--pub", base64.b64encode(_pub()).decode(), str(pfad)])
    return rc, out.getvalue() + err.getvalue()


class AnEmptyClaimsArray(unittest.TestCase):
    def test_a_released_statement_with_it_does_not_verify(self):
        res = I.verify_eval_result_dsse(_sign(_with_claims([])), _pub())
        self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
        self.assertIs(res["ok"], False, res)
        self.assertIs(res["predicate_claim_ok"], False)
        self.assertIn("predicate claims", res["content_root_detail"])
        self.assertIn("at least one claim", res["content_root_detail"])

    def test_the_cli_answers_fail_with_exit_1(self):
        rc, text = _cli(_sign(_with_claims([])))
        self.assertEqual(rc, 1, text)
        self.assertIn("[FAIL] eval-result attestation", text)


class Controls(unittest.TestCase):
    def test_the_released_statement_re_signed_unchanged_verifies(self):
        statement = _released_statement()
        self.assertEqual(len(statement["predicate"]["claims"]), 1, "precondition: one claim")
        res = I.verify_eval_result_dsse(_sign(statement), _pub())
        self.assertIs(res["ok"], True, res)
        rc, text = _cli(_sign(statement))
        self.assertEqual(rc, 0, text)

    def test_two_claims_verify(self):
        claims = _released_statement()["predicate"]["claims"]
        res = I.verify_eval_result_dsse(_sign(_with_claims(claims + copy.deepcopy(claims))), _pub())
        self.assertIs(res["ok"], True, res)

    def test_claims_that_is_no_array_stays_the_claim_rule_reason(self):
        res = I.verify_eval_result_dsse(_sign(_with_claims({})), _pub())
        self.assertIs(res["ok"], False, res)
        self.assertIn("must be an array of claim objects", res["content_root_detail"])
        self.assertNotIn("at least one claim", res["content_root_detail"])

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
