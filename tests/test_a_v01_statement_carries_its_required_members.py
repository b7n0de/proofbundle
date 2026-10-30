"""An eval-result v0.1 statement verifies only when its predicate carries the members v0.1 requires.

docs/IN_TOTO_PROFILE.md lists the v0.1 predicate: `verifier`, `evaluatedAt`, `suite`, `claims`,
`sampleSize`, `commitments` (with `model` and `dataset`, "both required" in the migration table),
`assuranceLevel` and `subjectProfile`; `preRegistration`, `receipt` and `harness` are the optional ones. The
same page applies the Monotonic Principle: a verifier denies unless a valid attestation exists.

Measured on main 647ed0a2: a validly signed statement of type `eval-result/v0.1` whose predicate carries
none of those members verified ok=True, and `proofbundle intoto --verify` printed
`[PASS] eval-result attestation` and exited 0.

Every statement a released version wrote carries all eight (the 14 entries of
tests/fixtures/eval_result_v0_1/corpus.json), so they keep verifying; the optional members stay optional.
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
# The throwaway example key: it signs only examples and vectors, and it signed the corpus.
_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
REQUIRED = ("verifier", "evaluatedAt", "suite", "claims", "sampleSize", "commitments", "assuranceLevel",
            "subjectProfile")
OPTIONAL = ("preRegistration", "receipt", "harness")


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


def _foreign() -> dict:
    """The v0.1 type over a predicate that is not an eval result."""
    root = "0191e2d1d171c8a2effd253b3d6dbd250cc6d4dfa28ffc18e0a7bf2ad1c95242"
    return {"_type": "https://in-toto.io/Statement/v1", "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"count": 3, "root": root},
            "predicateType": I.EVAL_RESULT_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": root}, "name": "artifact"}]}


def _cli(env: dict) -> tuple[int, str]:
    from proofbundle.cli import main
    with tempfile.TemporaryDirectory() as td:
        pfad = Path(td) / "env.json"
        pfad.write_text(json.dumps(env), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["intoto", "--verify", "--pub", base64.b64encode(_pub()).decode(), str(pfad)])
    return rc, out.getvalue() + err.getvalue()


class AForeignPredicateUnderTheV01Type(unittest.TestCase):
    def test_does_not_verify(self):
        res = I.verify_eval_result_dsse(_sign(_foreign()), _pub())
        self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
        self.assertIs(res["ok"], False, res)

    def test_the_cli_answers_fail_with_exit_1(self):
        rc, text = _cli(_sign(_foreign()))
        self.assertEqual(rc, 1, text)
        self.assertIn("[FAIL] eval-result attestation", text)


class EachRequiredMember(unittest.TestCase):
    def test_a_released_statement_without_it_does_not_verify(self):
        for member in REQUIRED:
            with self.subTest(member=member):
                statement = _released_statement()
                del statement["predicate"][member]
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, (member, res))
                self.assertIn(member, res["content_root_detail"])

    def test_commitments_need_model_and_dataset(self):
        for part in ("model", "dataset"):
            with self.subTest(part=part):
                statement = _released_statement()
                del statement["predicate"]["commitments"][part]
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, (part, res))
                self.assertIn(f"commitments.{part}", res["content_root_detail"])


class Controls(unittest.TestCase):
    def test_the_released_statement_re_signed_unchanged_verifies(self):
        res = I.verify_eval_result_dsse(_sign(_released_statement()), _pub())
        self.assertIs(res["ok"], True, res)

    def test_the_optional_members_stay_optional(self):
        for member in OPTIONAL:
            with self.subTest(member=member):
                statement = _released_statement()
                statement["predicate"].pop(member, None)
                res = I.verify_eval_result_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], True, (member, res))

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
