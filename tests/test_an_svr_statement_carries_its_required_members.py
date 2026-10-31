"""An SVR v0.1 statement verifies only when its predicate carries `verifier`, `verifier.id`, `timeCreated` and
`properties`.

The in-toto Simple Verification Result predicate in its v0.1 version (spec/predicates/svr.md at in-toto/attestation
1fa33327, the version before the bump to v0.2) marks `verifier` (object), `verifier.id` (string, TypeURI),
`timeCreated` (string, Timestamp) and `properties` (array of string) as required.

Measured on main b55d736d: a validly signed statement of type `svr/v0.1` whose predicate lacked `verifier`, lacked
`verifier.id`, lacked `timeCreated`, or carried `verifier.id` as a number verified ok=True through `verify_svr_dsse`,
and `proofbundle svr --verify` printed `[PASS] SVR attestation` and exited 0. `classify_svr_predicate_shape`
judged `verifier` and `timeCreated` only when present and never looked at `verifier.id`.

Every statement `export_svr_dsse` writes carries all four, so an exported attestation keeps verifying; the v0.1
extension field `verifier.policy` stays optional and an unknown member stays unread.
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

# A key made for this module alone; it signs only the statements below.
_SIGNER = Ed25519PrivateKey.generate()
_ROOT = "0191e2d1d171c8a2effd253b3d6dbd250cc6d4dfa28ffc18e0a7bf2ad1c95242"
REQUIRED = ("verifier", "timeCreated", "properties")


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(statement: dict) -> dict:
    """A valid signature over the bytes of `statement` under the content root it declares."""
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    body = I._serialize_statement(statement, alg)
    return dsse.sign_envelope(body, _SIGNER, payload_type=I.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _svr() -> dict:
    """An SVR v0.1 statement with every required member, in the form `export_svr_dsse` writes."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"verifier": {"id": I.VERIFIER_ID}, "timeCreated": "2026-10-31T09:00:00Z",
                          "properties": ["PROOFBUNDLE_SIGNATURE_VALID"]},
            "predicateType": I.SVR_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _ROOT}, "name": "eval-receipt"}]}


def _cli(env: dict) -> tuple[int, str]:
    from proofbundle.cli import main
    with tempfile.TemporaryDirectory() as td:
        pfad = Path(td) / "svr.json"
        pfad.write_text(json.dumps(env), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["svr", "--verify", "--pub", base64.b64encode(_pub()).decode(), str(pfad)])
    return rc, out.getvalue() + err.getvalue()


class EachRequiredMember(unittest.TestCase):
    def test_a_statement_without_it_does_not_verify(self):
        for member in REQUIRED:
            with self.subTest(member=member):
                statement = _svr()
                del statement["predicate"][member]
                res = I.verify_svr_dsse(_sign(statement), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, (member, res))
                self.assertIs(res["predicate_shape_ok"], False)
                self.assertIn(member, res["content_root_detail"])

    def test_verifier_needs_its_id(self):
        statement = _svr()
        del statement["predicate"]["verifier"]["id"]
        res = I.verify_svr_dsse(_sign(statement), _pub())
        self.assertIs(res["ok"], False, res)
        self.assertIn("verifier.id", res["content_root_detail"])

    def test_the_cli_does_not_answer_pass(self):
        for member in ("verifier", "timeCreated"):
            with self.subTest(member=member):
                statement = _svr()
                del statement["predicate"][member]
                rc, text = _cli(_sign(statement))
                self.assertEqual(rc, 2, text)
                self.assertNotIn("[PASS]", text)
                self.assertIn(member, text)


class ARequiredMemberOfTheWrongType(unittest.TestCase):
    def test_does_not_verify(self):
        for pfad, wert in ((("verifier",), "https://b7n0de.com/proofbundle"), (("verifier", "id"), 5),
                           (("timeCreated",), 1793437049), (("properties",), "PROOFBUNDLE_SIGNATURE_VALID")):
            with self.subTest(pfad=pfad, wert=wert):
                statement = _svr()
                ziel = statement["predicate"]
                for teil in pfad[:-1]:
                    ziel = ziel[teil]
                ziel[pfad[-1]] = wert
                res = I.verify_svr_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, (pfad, res))
                self.assertIs(res["predicate_shape_ok"], False)


class Controls(unittest.TestCase):
    def test_a_statement_with_every_required_member_verifies(self):
        res = I.verify_svr_dsse(_sign(_svr()), _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])
        rc, text = _cli(_sign(_svr()))
        self.assertEqual(rc, 0, text)

    def test_the_policy_extension_and_an_unknown_member_stay_optional(self):
        statement = _svr()
        statement["predicate"]["verifier"]["policy"] = {"uri": "https://policy.example/p",
                                                        "digest": {"sha256": _ROOT}}
        statement["predicate"]["x-unknown"] = {"anything": [1, 2]}
        res = I.verify_svr_dsse(_sign(statement), _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_the_classifier_names_a_complete_predicate_good(self):
        self.assertEqual(I.classify_svr_predicate_shape(_svr()), (True, ""))


if __name__ == "__main__":
    unittest.main()
