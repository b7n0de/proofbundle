"""An eval-result v0.1 statement verifies only when `verifier`, `suite` and `subjectProfile` have the form v0.1 gives.

docs/IN_TOTO_PROFILE.md lists the v0.1 predicate: `verifier.id`, the emitter TypeURI; `suite` as `{name, version}`;
`subjectProfile`, which of the subject profiles `receipt`, `public-model` and `release-gate` produced the subject.
None of these is marked optional. Pull request 445 made the eight top-level members required and left the value of
a present member to the claim rule, which judges `suite` only through the parts it carries and never reads
`verifier` or `subjectProfile`.

Measured on main b55d736d: a validly signed v0.1 statement verified ok=True, and `proofbundle intoto --verify`
printed `[PASS] eval-result attestation` with exit 0, with `verifier` {} or a string, with `verifier.id` 5, with
`suite` lacking `name` or `version`, and with `subjectProfile` 7 or "bogus_profile".

Every statement a released version wrote has these forms (the 14 entries of
tests/fixtures/eval_result_v0_1/corpus.json), so they keep verifying.
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
WRONG = (
    (("verifier",), {}), (("verifier",), "https://b7n0de.com/proofbundle"), (("verifier", "id"), 5),
    (("subjectProfile",), 7), (("subjectProfile",), "bogus_profile"),
)
MISSING = (("verifier", "id"), ("suite", "name"), ("suite", "version"))


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


def _set(statement: dict, pfad: tuple, wert) -> dict:
    ziel = statement["predicate"]
    for teil in pfad[:-1]:
        ziel = ziel[teil]
    ziel[pfad[-1]] = wert
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


class APartOfAMemberThatIsAbsent(unittest.TestCase):
    def test_a_released_statement_without_it_does_not_verify(self):
        for pfad in MISSING:
            with self.subTest(pfad=pfad):
                statement = _released_statement()
                del statement["predicate"][pfad[0]][pfad[1]]
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, (pfad, res))
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn(".".join(pfad), res["content_root_detail"])


class AMemberOfTheWrongForm(unittest.TestCase):
    def test_a_released_statement_with_it_does_not_verify(self):
        for pfad, wert in WRONG:
            with self.subTest(pfad=pfad, wert=wert):
                statement = _set(_released_statement(), pfad, wert)
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, (pfad, res))
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn(pfad[0], res["content_root_detail"])

    def test_the_cli_answers_fail_with_exit_1(self):
        for pfad, wert in ((("verifier", "id"), 5), (("subjectProfile",), "bogus_profile")):
            with self.subTest(pfad=pfad):
                rc, text = _cli(_sign(_set(_released_statement(), pfad, wert)))
                self.assertEqual(rc, 1, text)
                self.assertIn("[FAIL] eval-result attestation", text)


class Controls(unittest.TestCase):
    def test_each_subject_profile_verifies(self):
        for profil in I.SUBJECT_PROFILES:
            with self.subTest(profil=profil):
                res = I.verify_eval_result_dsse(_sign(_set(_released_statement(), ("subjectProfile",), profil)),
                                                _pub())
                self.assertIs(res["ok"], True, res)

    def test_the_released_statement_re_signed_unchanged_verifies(self):
        res = I.verify_eval_result_dsse(_sign(_released_statement()), _pub())
        self.assertIs(res["ok"], True, res)
        rc, text = _cli(_sign(_released_statement()))
        self.assertEqual(rc, 0, text)

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
