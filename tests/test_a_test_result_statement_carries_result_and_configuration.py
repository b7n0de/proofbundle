"""A test-result v0.1 statement verifies only when its predicate carries `result` and `configuration`.

The in-toto test-result predicate (spec/predicates/test-result.md) marks `result` and `configuration` as
required and `url`, `passedTests`, `warnedTests` and `failedTests` as optional. SPEC.md section 7b says the
same of the mapping this package writes: `configuration` is a required list of ResourceDescriptors.

Measured on main 647ed0a2: a validly signed statement of type `test-result/v0.1` whose predicate carries
neither member verified ok=True through `verify_intoto_dsse`.

Every statement `to_test_result_statement` writes carries both, so an exported attestation keeps verifying,
and a generic statement that carries both keeps verifying although none of its descriptors is ours.
"""
from __future__ import annotations

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse
from proofbundle import intoto as I

# The throwaway example key: it signs only examples and vectors.
_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
REQUIRED = ("result", "configuration")
OPTIONAL = ("url", "passedTests", "warnedTests", "failedTests")
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


def _sign(statement: dict) -> dict:
    """A valid signature over the bytes of `statement` under the content root it declares."""
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    body = I._serialize_statement(statement, alg)
    return dsse.sign_envelope(body, _SIGNER, payload_type=I.TEST_RESULT_PAYLOAD_TYPE)


def _root() -> str:
    return "0191e2d1d171c8a2effd253b3d6dbd250cc6d4dfa28ffc18e0a7bf2ad1c95242"


def _foreign() -> dict:
    """The test-result type over a predicate that is not a test result."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"count": 3, "root": _root()},
            "predicateType": I.TEST_RESULT_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _root()}, "name": "artifact"}]}


def _generic() -> dict:
    """A generic test result: both required members, no descriptor of ours, every optional member."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"result": "PASSED",
                          "configuration": [{"name": "suite.yaml", "digest": {"sha256": _root()}}],
                          "url": "https://ci.example/run/1", "passedTests": ["a"], "warnedTests": [],
                          "failedTests": []},
            "predicateType": I.TEST_RESULT_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _root()}, "name": "artifact"}]}


def _exported() -> dict:
    return I.to_test_result_statement(CLAIM, subject_digest={"sha256": _root()})


class AForeignPredicateUnderTheTestResultType(unittest.TestCase):
    def test_does_not_verify(self):
        res = I.verify_intoto_dsse(_sign(_foreign()), _pub())
        self.assertIs(res["signature_ok"], True)
        self.assertIs(res["ok"], False)
        self.assertIs(res["predicate_claim_ok"], False)
        self.assertIn("predicate result: is required by test-result v0.1 and absent", res["content_root_detail"])


class EachRequiredMember(unittest.TestCase):
    def test_a_generic_statement_without_it_does_not_verify(self):
        for member in REQUIRED:
            with self.subTest(member=member):
                statement = _generic()
                del statement["predicate"][member]
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False)
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn(f"predicate {member}: is required by test-result v0.1 and absent",
                              res["content_root_detail"])

    def test_an_exported_statement_without_it_does_not_verify(self):
        for member in REQUIRED:
            with self.subTest(member=member):
                statement = _exported()
                del statement["predicate"][member]
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False)
                self.assertIs(res["predicate_claim_ok"], False)


class Controls(unittest.TestCase):
    def test_an_exported_statement_verifies(self):
        res = I.verify_intoto_dsse(_sign(_exported()), _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_the_exporter_signs_a_statement_that_verifies(self):
        env = I.export_intoto_dsse(CLAIM, _SIGNER)
        res = I.verify_intoto_dsse(env, _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_a_generic_statement_with_both_verifies(self):
        res = I.verify_intoto_dsse(_sign(_generic()), _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_the_optional_members_stay_optional(self):
        for member in OPTIONAL:
            with self.subTest(member=member):
                statement = copy.deepcopy(_generic())
                del statement["predicate"][member]
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], True, res["content_root_detail"])


if __name__ == "__main__":
    unittest.main()
