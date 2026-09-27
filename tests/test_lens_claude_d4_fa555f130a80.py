"""Lens run (Claude family) on fix/the-commit-pattern-holds-at-the-verify-boundary at fa555f13.

Every case below states the property it holds and was RED at fa555f130a80cdfedd5965715bc7f8451c974bbe
and at main 31816e08 when it was written (python -m pytest on this file, Python 3.11.15). None of
them changes production code; each one is the reproduction of one row of
REVIEW_lens_claude_d4_fa555f130a80.md. Oracles: the package's own signed bytes (L1 to L6), the
package's own documented rule (L7, L9 to L12), and for L8 the regular-expression dialect JSON Schema
names for "pattern" (ECMA-262), measured off-test with node v22.22.2.
"""
from __future__ import annotations

import base64
import copy
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import evalclaim as ec
from proofbundle import intoto
from proofbundle.canonical import canonicalize_statement
from proofbundle.emit import emit_bundle
from proofbundle.errors import Check, ProofBundleError, VerificationResult

_SIGNER = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
_PUB = _SIGNER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _claim(threshold: str) -> dict:
    claim, _ = ec.build_eval_claim(
        suite="real-suite", suite_version="1", metric="acc", comparator=">=", threshold=threshold,
        score="0.5", n=100, model_id="m", dataset_id="d", issuer="x",
        timestamp="2026-07-09T10:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class _SwapAfter(dict):
    """A dict whose stored `field` is the signed value, and whose own `__getitem__` answers with
    `forged` from read number `after + 1` on. The stored contents never change."""

    def __init__(self, source: dict, field: str, forged: str, after: int) -> None:
        super().__init__(source)
        self.field, self.forged, self.after, self.reads = field, forged, after, 0

    def __getitem__(self, key):
        if key == self.field:
            self.reads += 1
            if self.reads > self.after:
                return self.forged
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        if key == self.field and dict.__contains__(self, key):
            return self[key]
        return dict.get(self, key, default)


class _EncodesTwice(str):
    """A str that holds the signed base64 and whose own `encode` returns `forged` after the first call."""

    def __new__(cls, text: str, forged: str) -> "_EncodesTwice":
        obj = super().__new__(cls, text)
        obj.forged, obj.calls = forged, 0
        return obj

    def encode(self, *args, **kwargs):  # type: ignore[override]
        self.calls += 1
        return (str.__str__(self) if self.calls == 1 else self.forged).encode(*args, **kwargs)


class L1to3VerifiedBytesAreTheParsedBytes(unittest.TestCase):
    """PROPERTY: a verify surface returns only what the signature covers. decode_eval_claim and
    classify_eval_claim read `payload_b64` once for verify_bundle and again to parse it, both times
    through the caller's object. P0. Reachable only with a caller-built object (a dict subclass, or
    a str subclass in the field), never from bytes, the CLI or the Rust verifier."""

    def setUp(self) -> None:
        self.bundle = ec.emit_eval_receipt(_claim("0.80"), _SIGNER)
        self.signed = ec.decode_eval_claim(self.bundle)
        forged = dict(self.signed, passed=True, suite="forged-suite")
        self.forged_b64 = base64.b64encode(ec.canonicalize(forged)).decode("ascii")

    def _assert_signed_or_refused(self, out) -> None:
        if out is not None:
            self.assertEqual(out, self.signed, "returned a claim the signature does not cover")

    def test_l1_decode_dict_subclass(self) -> None:
        for after in range(4):
            with self.subTest(after=after):
                bundle = _SwapAfter(copy.deepcopy(self.bundle), "payload_b64", self.forged_b64, after)
                self._assert_signed_or_refused(ec.decode_eval_claim(bundle))

    def test_l2_decode_str_subclass_in_a_plain_dict(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["payload_b64"] = _EncodesTwice(self.bundle["payload_b64"], self.forged_b64)
        self._assert_signed_or_refused(ec.decode_eval_claim(bundle))

    def test_l3_classify_dict_subclass(self) -> None:
        for after in range(5):
            with self.subTest(after=after):
                bundle = _SwapAfter(copy.deepcopy(self.bundle), "payload_b64", self.forged_b64, after)
                outcome, out = ec.classify_eval_claim(bundle)
                if outcome == ec.CLAIM_VALID:
                    self.assertEqual(out, self.signed, "CLAIM_VALID for a claim the signature does not cover")


class L4to6DsseVerifiersJudgeTheSignedStatement(unittest.TestCase):
    """PROPERTY: `ok` True means the returned statement is the one the signature covers.
    dsse.verify_envelope and dsse.load_payload read `payload` from the caller's envelope twice. P0,
    same precondition as L1 to L3."""

    def _check(self, envelope: dict, verify, mutate) -> None:
        signed = verify(envelope, _PUB)
        self.assertTrue(signed["ok"])
        forged = copy.deepcopy(signed["statement"])
        mutate(forged)
        forged_b64 = base64.b64encode(canonicalize_statement(forged)).decode("ascii")
        self.assertFalse(verify(dict(envelope, payload=forged_b64), _PUB)["ok"])
        for after in range(3):
            with self.subTest(after=after):
                res = verify(_SwapAfter(copy.deepcopy(envelope), "payload", forged_b64, after), _PUB)
                if res["ok"]:
                    self.assertEqual(res["statement"], signed["statement"],
                                     "ok=True over a statement the signature does not cover")

    def test_l4_verify_intoto_dsse(self) -> None:
        def mutate(st: dict) -> None:
            st["predicate"]["result"] = "PASSED"
            for entry in st["predicate"].get("configuration", []):
                if "passed" in entry.get("annotations", {}):
                    entry["annotations"]["passed"] = True
            if "failedTests" in st["predicate"]:
                st["predicate"]["passedTests"] = st["predicate"].pop("failedTests")
        self._check(intoto.export_intoto_dsse(_claim("0.80"), _SIGNER), intoto.verify_intoto_dsse,
                    mutate)

    def test_l5_verify_eval_result_dsse(self) -> None:
        def mutate(st: dict) -> None:
            st["predicate"]["claims"][0]["passed"] = True
        self._check(intoto.export_eval_result_dsse(_claim("0.80"), _SIGNER),
                    intoto.verify_eval_result_dsse, mutate)

    def test_l6_verify_svr_dsse(self) -> None:
        def mutate(st: dict) -> None:
            st["predicate"]["properties"] = sorted(set(st["predicate"]["properties"])
                                                   | {"PROOFBUNDLE_ANCHOR_VALID"})
        bundle = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)
        self._check(intoto.export_svr_dsse(bundle, _SIGNER), intoto.verify_svr_dsse, mutate)


class L7ABoolKeywordIsABool(unittest.TestCase):
    """PROPERTY (round 10, `canonical._flagge`, R-B4): a boolean keyword is True or False, and any
    other value is refused, never read by its truth. hashalg's `allow_deprecated` opens the
    deprecated-hash gate for the string "false". P1: the gate opens only on a caller value that is
    no bool."""

    def test_l7_allow_deprecated_string_false(self) -> None:
        from proofbundle import hashalg  # noqa: PLC0415
        for value in ("false", "no", 1, [0]):
            with self.subTest(value=value):
                with self.assertRaises(ProofBundleError):
                    hashalg.compute_digest(b"x", "sha1", allow_deprecated=value)


class L8TrustPackPatternsHoldTheSchemaDialect(unittest.TestCase):
    """PROPERTY: the validator accepts nothing schemas/trust-pack-v0.1.schema.json refuses. The
    schema's patterns are ECMA-262, where `$` is the end of the input and `\\d` is [0-9];
    trust_pack.py compiles them for Python `re` with `^...$` and `\\d`, where `$` also matches before
    a final newline and `\\d` matches every Unicode decimal digit. The sibling modules carry the
    `\\A..\\Z` fix (decision, outcome, run_ledger, relation, verification_summary, agent_review);
    trust_pack.py does not. P1: the validator's verdict is "valid" for a value the schema refuses."""

    def test_l8_values_the_schema_refuses(self) -> None:
        from proofbundle.trust_pack import validate_trust_pack_predicate  # noqa: PLC0415

        def _fixture(version: int) -> dict:
            # The genesis or version-2 pack of tests/test_trust_pack.py `_fixture`, with fixed keys.
            # Literal seeds: tests/test_sdist_ohne_signierwerkzeug.py allows `from_private_bytes` in a
            # shipped test only over a seed written out in the source.
            seeds = (Ed25519PrivateKey.from_private_bytes(b"\x01" * 32),
                     Ed25519PrivateKey.from_private_bytes(b"\x02" * 32),
                     Ed25519PrivateKey.from_private_bytes(b"\x03" * 32))
            keys = {f"root-{i}": {"publicKey": base64.b64encode(sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
                "scheme": "ed25519"} for i, sk in enumerate(seeds)}
            return {
                "schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": version,
                "expires": "2027-01-01T00:00:00Z",
                "prevVersionDigest": None if version == 1 else {"sha256": "b" * 64},
                "roles": {"root": {"keyIds": list(keys), "threshold": 2},
                          "outcomeExecutors": {"keyIds": ["root-0"], "threshold": 1}},
                "keys": keys,
                "nonClaims": ["names which keys hold which role, not that the holders are honest"],
            }

        self.assertEqual(validate_trust_pack_predicate(_fixture(1)), [])
        self.assertEqual(validate_trust_pack_predicate(_fixture(2)), [])
        for field, value, version in (
                ("prevVersionDigest", {"sha256": "b" * 64 + "\n"}, 2),
                ("expires", "2027-01-01T00:00:00Z\n", 1),
                ("expires", "\u0662\u0660\u0662\u0667-01-01T00:00:00Z", 1),
                ("schemaVersion", "0.1.0\n", 1),
                ("schemaVersion", "0.1.\u0663", 1)):
            with self.subTest(field=field, value=value):
                predicate = _fixture(version)
                predicate[field] = value
                self.assertNotEqual(validate_trust_pack_predicate(predicate), [])


class L9ThePairFormRefusesADuplicateKey(unittest.TestCase):
    """PROPERTY (`canonical._plain_for_jcs`): two keys whose characters are equal are refused,
    because JSON has one key for both. emit_eval_receipt reads a list of [key, value] pairs through
    `dict()` on the copy, which keeps the last of two: `passed` False then True is signed as True.
    P1: a boundary the copy holds for objects does not hold for the documented pair form."""

    def test_l9_passed_twice(self) -> None:
        pairs = [[k, v] for k, v in _claim("0.80").items()] + [["passed", True]]
        with self.assertRaises(ec.EvalClaimError):
            ec.emit_eval_receipt(pairs, _SIGNER)


class L10OneFailedCheckWithholdsItsProperty(unittest.TestCase):
    """PROPERTY (round 10, `svr_properties`): a property is earned only by a check whose `ok` is
    True. With two checks named ed25519-signature, one False and one True, the answer depends on
    their order: False then True earns PROOFBUNDLE_SIGNATURE_VALID, True then False does not. P1:
    reachable through a caller-built result only; verify_bundle names each check once."""

    def test_l10_failed_then_passed(self) -> None:
        claim = _claim("0.10")
        result = VerificationResult([Check("ed25519-signature", False), Check("ed25519-signature", True)])
        try:
            props = intoto.svr_properties(result, claim)
        except ProofBundleError:
            return
        self.assertNotIn("PROOFBUNDLE_SIGNATURE_VALID", props)


class L11ARefusalNeedsADeclaration(unittest.TestCase):
    """PROPERTY (classify_eval_claim's own rule for the envelope): only a present, non-empty string
    that is not ours declares a foreign format; an absent value or one that is no usable identifier
    declares nothing and stays `invalid`. At the payload the function refuses them all as an unknown
    schema. P1: fail-closed, but the outcome class is wrong. Same class as branch 234."""

    def test_l11_payload_schema_without_a_declaration(self) -> None:
        signed = ec.decode_eval_claim(ec.emit_eval_receipt(_claim("0.80"), _SIGNER))
        for label, value in (("absent", None), ("null", "null"), ("empty", ""), ("int", 1),
                             ("list", [ec.EVAL_CLAIM_SCHEMA])):
            with self.subTest(schema=label):
                claim = dict(signed)
                if value is None:
                    del claim["schema"]
                else:
                    claim["schema"] = None if value == "null" else value
                bundle = emit_bundle(ec.canonicalize(claim), _SIGNER)
                self.assertEqual(ec.classify_eval_claim(bundle)[0], ec.CLAIM_INVALID)


class L12TheEmitterRefusesWithItsOwnError(unittest.TestCase):
    """PROPERTY: the emitter refuses an input with EvalClaimError, never a raw exception. An
    identifier holding a lone surrogate raises a raw UnicodeEncodeError from salted_commit. P2:
    fail-closed, wrong error. KNOWN: commit fa555f13 names this as not changed."""

    def test_l12_lone_surrogate_identifier(self) -> None:
        with self.assertRaises(ec.EvalClaimError):
            ec.build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.10",
                score="0.5", n=1, model_id="\ud800", dataset_id="d", issuer="x", timestamp="t",
                model_salt=b"0" * 16, dataset_salt=b"1" * 16)


if __name__ == "__main__":
    unittest.main()
