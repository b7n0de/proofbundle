"""A test-result v0.1 statement verifies only when the members it carries have the types the predicate gives them.

The in-toto test-result predicate (spec/predicates/test-result.md) types its members: `result` is an enum, one of
`PASSED`, `WARNED` or `FAILED`; `configuration` is a list of ResourceDescriptors, and a ResourceDescriptor MUST
specify one of `uri`, `digest` or `content` (spec/v1/resource_descriptor.md); `url` is a ResourceURI, a string;
`passedTests`, `warnedTests` and `failedTests` are lists of strings. SPEC.md section 7b says the same of the
descriptors: a bare `name`-only descriptor is invalid per the ResourceDescriptor rule.

Measured on main b55d736d: a validly signed generic statement of type `test-result/v0.1`, one whose descriptors carry
no proofbundle commitment, verified ok=True through `verify_intoto_dsse` with `result` 1, "BOGUS" or "passed", with a
configuration entry `{}` or `{"name": "only-a-name"}`, with `url` 5, with `passedTests` "a", with `warnedTests` 3 and
with `failedTests` [1, 2]. The types were judged only when a descriptor of ours annotated a verdict.

Every statement `to_test_result_statement` writes has these types, so an exported attestation keeps verifying, and a
generic statement whose members have them keeps verifying although none of its descriptors is ours.
"""
from __future__ import annotations

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse
from proofbundle import intoto as I

# A key made for this module alone; it signs only the statements below.
_SIGNER = Ed25519PrivateKey.generate()
_ROOT = "0191e2d1d171c8a2effd253b3d6dbd250cc6d4dfa28ffc18e0a7bf2ad1c95242"
CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True, "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32, "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1", "issuer": "ed25519:AAAA", "timestamp": "2026-07-05T12:00:00Z",
    "assurance_level": "self_attested",
}
WRONG = (
    ("result", 1), ("result", "BOGUS"), ("result", "passed"),
    ("configuration", [{}]), ("configuration", [{"name": "only-a-name"}]),
    ("url", 5), ("passedTests", "a"), ("warnedTests", 3), ("failedTests", [1, 2]),
)


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(statement: dict) -> dict:
    """A valid signature over the bytes of `statement` under the content root it declares."""
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    body = I._serialize_statement(statement, alg)
    return dsse.sign_envelope(body, _SIGNER, payload_type=I.TEST_RESULT_PAYLOAD_TYPE)


def _generic() -> dict:
    """A generic test result: both required members, no descriptor of ours, every optional member."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"result": "PASSED",
                          "configuration": [{"name": "suite.yaml", "digest": {"sha256": _ROOT}}],
                          "url": "https://ci.example/run/1", "passedTests": ["a"], "warnedTests": [],
                          "failedTests": []},
            "predicateType": I.TEST_RESULT_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _ROOT}, "name": "artifact"}]}


class AMemberOfTheWrongType(unittest.TestCase):
    def test_a_generic_statement_with_it_does_not_verify(self):
        for member, wert in WRONG:
            with self.subTest(member=member, wert=wert):
                statement = _generic()
                statement["predicate"][member] = wert
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["signature_ok"], True, "precondition: a valid signature")
                self.assertIs(res["ok"], False, (member, wert, res))
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn(f"predicate {member}", res["content_root_detail"])

    def test_an_exported_statement_with_it_does_not_verify(self):
        for member, wert in (("result", "BOGUS"), ("url", 5)):
            with self.subTest(member=member, wert=wert):
                statement = I.to_test_result_statement(CLAIM, subject_digest={"sha256": _ROOT})
                statement["predicate"][member] = wert
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], False, (member, res))


class Controls(unittest.TestCase):
    def test_every_result_value_of_the_enum_verifies_in_a_generic_statement(self):
        for wert, listen in (("PASSED", {"passedTests": ["a"]}), ("WARNED", {"warnedTests": ["a"]}),
                             ("FAILED", {"failedTests": ["a"]})):
            with self.subTest(result=wert):
                statement = _generic()
                for name in ("passedTests", "warnedTests", "failedTests"):
                    statement["predicate"].pop(name)
                statement["predicate"].update(result=wert, **listen)
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_a_descriptor_with_uri_or_content_alone_verifies(self):
        for entry in ({"uri": "https://ci.example/suite.yaml"}, {"content": "c3VpdGU="}):
            with self.subTest(entry=entry):
                statement = _generic()
                statement["predicate"]["configuration"] = [entry]
                res = I.verify_intoto_dsse(_sign(statement), _pub())
                self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_the_generic_statement_and_an_exported_one_verify(self):
        for statement in (_generic(), I.to_test_result_statement(CLAIM, subject_digest={"sha256": _ROOT})):
            with self.subTest(statement=statement["predicate"].get("result")):
                res = I.verify_intoto_dsse(_sign(copy.deepcopy(statement)), _pub())
                self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_the_exporter_signs_a_statement_that_verifies(self):
        res = I.verify_intoto_dsse(I.export_intoto_dsse(CLAIM, _SIGNER), _pub())
        self.assertIs(res["ok"], True, res["content_root_detail"])


if __name__ == "__main__":
    unittest.main()
