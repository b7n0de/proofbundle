"""One reading at the verify boundary, and the P1 findings of lens run 10 (D4 round 11).

SOURCE. The lens's cases in this file (its L1 to L10) are taken unchanged, with their docstrings, from
tests/test_lens_claude_d4_fa555f130a80.py at e664c010 (branch claude/lens-620-d4-fa555f130a80,
review REVIEW_lens_claude_d4_fa555f130a80.md at 78455de3), by the owner's leave. The lens's
module docstring said: every case was RED at fa555f130a80cdfedd5965715bc7f8451c974bbe and at main
31816e08 when it was written (Python 3.11.15); oracles are the package's own signed bytes (L1 to
L6), the package's own documented rule (L7, L9, L10), and for L8 the regular-expression dialect
JSON Schema names for "pattern" (ECMA-262), measured off-test with node v22.22.2. L11 goes to
branch 234 and L12 to the residual-risk list; neither is here.

The classes after the lens's L10 are this round's own cases, each written where the fix needed
more than the lens's case showed. Every case in this file was measured RED at fa555f13 and GREEN at
the head that adds it, on Python 3.10 to 3.14.
"""
from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

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
            keys = {f"root-{i}": {"publicKey": base64.b64encode(
                Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32).public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
                "scheme": "ed25519"} for i in range(3)}
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


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# This round's own cases. Each was measured RED at fa555f13 and GREEN at the head that adds it.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

_AUFRUFE: list = []


class _RecordingDict(dict):
    """A dict that records every call of a method a reader could use instead of its stored contents."""

    def __getitem__(self, key):
        _AUFRUFE.append("dict.__getitem__")
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        _AUFRUFE.append("dict.get")
        return dict.get(self, key, default)

    def __contains__(self, key):
        _AUFRUFE.append("dict.__contains__")
        return dict.__contains__(self, key)

    def __iter__(self):
        _AUFRUFE.append("dict.__iter__")
        return dict.__iter__(self)

    def __len__(self):
        _AUFRUFE.append("dict.__len__")
        return dict.__len__(self)

    def keys(self):
        _AUFRUFE.append("dict.keys")
        return dict.keys(self)

    def items(self):
        _AUFRUFE.append("dict.items")
        return dict.items(self)

    def values(self):
        _AUFRUFE.append("dict.values")
        return dict.values(self)


class _RecordingList(list):
    def __iter__(self):
        _AUFRUFE.append("list.__iter__")
        return list.__iter__(self)

    def __getitem__(self, index):
        _AUFRUFE.append("list.__getitem__")
        return list.__getitem__(self, index)

    def __len__(self):
        _AUFRUFE.append("list.__len__")
        return list.__len__(self)


class _RecordingStr(str):
    def encode(self, *args, **kwargs):  # type: ignore[override]
        _AUFRUFE.append("str.encode")
        return str.encode(self, *args, **kwargs)

    def __str__(self):
        _AUFRUFE.append("str.__str__")
        return str.__str__(self)

    def __eq__(self, other):
        _AUFRUFE.append("str.__eq__")
        return str.__eq__(self, other)

    def __ne__(self, other):
        _AUFRUFE.append("str.__ne__")
        return str.__ne__(self, other)

    def __hash__(self):
        _AUFRUFE.append("str.__hash__")
        return str.__hash__(self)

    def __len__(self):
        _AUFRUFE.append("str.__len__")
        return str.__len__(self)


def _recording(value):
    """`value` rebuilt from recording subclasses, every dict, list, key and string of it."""
    if type(value) is dict:
        return _RecordingDict({_recording(k): _recording(v) for k, v in value.items()})
    if type(value) is list:
        return _RecordingList(_recording(v) for v in value)
    if type(value) is str:
        return _RecordingStr(value)
    return value


class OneReadingRunsNoMethodOfTheCallersObject(unittest.TestCase):
    """PROPERTY (round 11, the owner's wording of class A): the caller's object is turned into bytes
    once and none of its own methods run: no `__getitem__`, `get` or `__contains__` of a dict
    subclass, no `encode` of a str subclass. L1 to L6 measure one swapped field each; this measures
    the property over every dict, list, key and string of the object, at the five surfaces. RED at
    fa555f13: verify_bundle and dsse.verify_envelope read the object through `get` and `[]`."""

    def _gemessen(self, aufruf):
        _AUFRUFE.clear()
        ergebnis = aufruf()
        return ergebnis, list(_AUFRUFE)

    def test_decode_and_classify_read_what_the_bundle_stores(self) -> None:
        bundle = ec.emit_eval_receipt(_claim("0.80"), _SIGNER)
        signed = ec.decode_eval_claim(bundle)
        for name, aufruf in (("decode_eval_claim", ec.decode_eval_claim),
                             ("classify_eval_claim", ec.classify_eval_claim)):
            with self.subTest(surface=name):
                eingabe = _recording(copy.deepcopy(bundle))
                out, aufrufe = self._gemessen(lambda: aufruf(eingabe))
                self.assertEqual(aufrufe, [], f"{name} ran methods of the caller's object")
                self.assertEqual(out if name == "decode_eval_claim" else out[1], signed)

    def test_the_dsse_verifiers_read_what_the_envelope_stores(self) -> None:
        bundle = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)
        for name, envelope, verify in (
                ("verify_intoto_dsse", intoto.export_intoto_dsse(_claim("0.80"), _SIGNER),
                 intoto.verify_intoto_dsse),
                ("verify_eval_result_dsse", intoto.export_eval_result_dsse(_claim("0.80"), _SIGNER),
                 intoto.verify_eval_result_dsse),
                ("verify_svr_dsse", intoto.export_svr_dsse(bundle, _SIGNER), intoto.verify_svr_dsse)):
            with self.subTest(surface=name):
                signed = verify(envelope, _PUB)
                self.assertTrue(signed["ok"])
                eingabe = _recording(copy.deepcopy(envelope))
                res, aufrufe = self._gemessen(lambda: verify(eingabe, _PUB))
                self.assertEqual(aufrufe, [], f"{name} ran methods of the caller's envelope")
                self.assertTrue(res["ok"])
                self.assertEqual(res["statement"], signed["statement"])


class TheIssuerBindingReadsTheKeyTheSignatureWasCheckedUnder(unittest.TestCase):
    """PROPERTY: decode_eval_claim binds the claim's `issuer` to the key that signed the bundle. The
    key was read twice at fa555f13, once by verify_bundle and once for the binding, both through the
    caller's `signature` object. A claim signed by one key and naming another as its issuer was
    returned when the second read answered with the named key. Same class A, another field."""

    def test_a_claim_naming_another_issuer_is_refused(self) -> None:
        opfer = Ed25519PrivateKey.from_private_bytes(b"\x08" * 32)
        opfer_b64 = base64.b64encode(opfer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        claim = dict(_claim("0.80"), issuer="ed25519:" + opfer_b64)
        bundle = emit_bundle(ec.canonicalize(claim), _SIGNER)   # signed by _SIGNER, names the victim
        self.assertIsNone(ec.decode_eval_claim(bundle))
        for after in range(3):
            with self.subTest(after=after):
                gefaelscht = copy.deepcopy(bundle)
                gefaelscht["signature"] = _SwapAfter(gefaelscht["signature"], "public_key_b64",
                                                     opfer_b64, after)
                self.assertIsNone(ec.decode_eval_claim(gefaelscht),
                                  "returned a claim whose issuer is not the key that signed it")


class AValueThatIsNoJsonValueIsRefused(unittest.TestCase):
    """PROPERTY (the one reader's refusal, round 11): the verify boundary reads the caller's object
    as the JSON it stands for, and an object holding a value that is no JSON value stands for none.
    It is refused fail-closed (None, ok=False), where fa555f13 ignored a field the verifier does not
    read and returned the claim or ok=True."""

    def test_decode_and_classify(self) -> None:
        bundle = ec.emit_eval_receipt(_claim("0.80"), _SIGNER)
        bundle["anchors"] = [{"target": "receipt", "proof": b"not json"}]
        self.assertIsNone(ec.decode_eval_claim(bundle))
        self.assertEqual(ec.classify_eval_claim(bundle), (ec.CLAIM_INVALID, None))

    def test_the_dsse_verifiers(self) -> None:
        bundle = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)
        for name, envelope, verify in (
                ("verify_intoto_dsse", intoto.export_intoto_dsse(_claim("0.80"), _SIGNER),
                 intoto.verify_intoto_dsse),
                ("verify_eval_result_dsse", intoto.export_eval_result_dsse(_claim("0.80"), _SIGNER),
                 intoto.verify_eval_result_dsse),
                ("verify_svr_dsse", intoto.export_svr_dsse(bundle, _SIGNER), intoto.verify_svr_dsse)):
            for wert in (b"not json", {"a", "b"}):
                with self.subTest(surface=name, value=type(wert).__name__):
                    self.assertIs(verify(dict(envelope, extra=wert), _PUB)["ok"], False)


class L9ThePairFormRefusesADuplicateKeyInEitherOrder(unittest.TestCase):
    """PROPERTY (L9, the other order): the refusal does not depend on which of the two pairs comes
    last. At fa555f13 `passed` True then False was signed as False, silently, as the lens's order was
    signed as True."""

    def test_passed_true_then_false(self) -> None:
        claim = _claim("0.10")
        self.assertIs(claim["passed"], True)
        pairs = [[k, v] for k, v in claim.items()] + [["passed", False]]
        with self.assertRaises(ec.EvalClaimError):
            ec.emit_eval_receipt(pairs, _SIGNER)


class L8TheTimestampParserHoldsTheSameDialect(unittest.TestCase):
    """PROPERTY (L8, the second pattern the lens named, trust_pack.py:98): `_parse_rfc3339_z` parses
    only what `_RFC3339_Z` accepts, in the schema's ECMA-262 meaning. At fa555f13 its own `^...$`
    and `\\d` parsed a timestamp with a trailing newline and one with Arabic-Indic digits."""

    def test_the_parser_refuses_what_the_schema_refuses(self) -> None:
        from proofbundle.trust_pack import _parse_rfc3339_z  # noqa: PLC0415
        arabisch = "".join(chr(0x0660 + d) for d in (2, 0, 2, 7))
        self.assertEqual(_parse_rfc3339_z("2027-01-01T00:00:00Z").year, 2027)
        for wert in ("2027-01-01T00:00:00Z\n", arabisch + "-01-01T00:00:00Z"):
            with self.subTest(value=wert):
                with self.assertRaises(ValueError):
                    _parse_rfc3339_z(wert)


_KEIN_BOOL = ("false", "no", 1, [0])


class L7SiblingsAPermissiveFlagIsABool(unittest.TestCase):
    """PROPERTY (class B, the sweep of L7): a keyword that OPENS a gate when True is True or False,
    and any other value is refused, never read by its truth. Each flag below opened its gate for the
    string "false" at fa555f13, measured by the round's sweep; the lens named leaf_witnessed, the
    other four are the same shape found by the sweep. A surface that returns a verdict gives a
    fail-closed verdict naming the flag; the others raise ProofBundleError."""

    def test_resolve_hash_alg_refuses_before_the_id_is_read(self) -> None:
        from proofbundle import hashalg  # noqa: PLC0415
        for wert in _KEIN_BOOL:
            with self.subTest(value=wert):
                with self.assertRaises(ProofBundleError):
                    hashalg.resolve_hash_alg("sha256", allow_deprecated=wert)

    def test_allow_pending(self) -> None:
        from proofbundle import anchors  # noqa: PLC0415
        gespeichert = dict(anchors._VERIFIERS)
        self.addCleanup(lambda: (anchors._VERIFIERS.clear(), anchors._VERIFIERS.update(gespeichert)))
        anchors.register_anchor_type("pending-anchor", lambda proof, root, *, frozen, now: {
            "ok": False, "warn": True, "status": "pending", "detail": "pending"})
        wurzel = b"\xaa" * 32
        anker = {"type": "pending-anchor", "target": "receipt",
                 "canonicalRoot": base64.b64encode(wurzel).decode("ascii"),
                 "proof": base64.b64encode(b"w").decode("ascii"), "anchoredAt": "2026-07-05T12:00:00Z"}
        self.assertEqual(anchors.verify_anchors([anker], target_roots={"receipt": wurzel}, require="any",
                                                allow_pending=False)["status"], "FAIL")
        for wert in _KEIN_BOOL:
            with self.subTest(value=wert):
                with self.assertRaises(ProofBundleError):
                    anchors.verify_anchors([anker], target_roots={"receipt": wurzel}, require="any",
                                           allow_pending=wert)

    def test_allow_unauthenticated_anchor(self) -> None:
        from proofbundle import renewal  # noqa: PLC0415
        daten = ["a" * 64, "b" * 64, "c" * 64]
        folge = renewal.build_initial_sequence(daten, hash_alg="sha256", time=1000)
        self.assertIs(renewal.verify_sequence(folge, daten, allow_unauthenticated_anchor=True).ok, True)
        for wert in _KEIN_BOOL:
            with self.subTest(value=wert):
                res = renewal.verify_sequence(folge, daten, allow_unauthenticated_anchor=wert)
                self.assertIs(res.ok, False)
                self.assertTrue(any(c.name == "renewal:anchor_mode" and not c.ok for c in res.checks))

    def test_allow_value_mismatch(self) -> None:
        from proofbundle import hf_evals  # noqa: PLC0415
        bundle = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)   # passed: 0.5 >= 0.10
        for wert in _KEIN_BOOL:
            with self.subTest(value=wert):
                with self.assertRaises(ProofBundleError) as fang:
                    hf_evals.to_eval_results_entry(bundle, dataset_id="d", task_id="t", value=0.05,
                                                   allow_value_mismatch=wert)
                self.assertIn("allow_value_mismatch", str(fang.exception))

    def test_allow_unverified_rotation(self) -> None:
        from datetime import datetime, timezone  # noqa: PLC0415
        from proofbundle import trust_pack  # noqa: PLC0415
        schluessel = {f"root-{i}": Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
                      for i in range(3)}
        keys = {k: {"publicKey": base64.b64encode(sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
            "scheme": "ed25519"} for k, sk in schluessel.items()}
        praedikat = {"schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": 2,
                     "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": {"sha256": "b" * 64},
                     "roles": {"root": {"keyIds": list(keys), "threshold": 2},
                               "outcomeExecutors": {"keyIds": ["root-0"], "threshold": 1}},
                     "keys": keys,
                     "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
        umschlag = trust_pack.sign_trust_pack(praedikat, schluessel)
        jetzt = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
        self.assertIs(trust_pack.verify_trust_pack(umschlag, now=jetzt,
                                                   allow_unverified_rotation=True)["ok"], True)
        for wert in _KEIN_BOOL:
            with self.subTest(value=wert):
                res = trust_pack.verify_trust_pack(umschlag, now=jetzt, allow_unverified_rotation=wert)
                self.assertIs(res["ok"], False)
                self.assertTrue(any("allow_unverified_rotation" in e for e in res["errors"]))

    def test_leaf_witnessed(self) -> None:
        from proofbundle import agent_review as ar  # noqa: PLC0415
        fall = (Path(__file__).resolve().parents[1] / "conformance" / "agent_review"
                / "agent-review-v02-positive-control-current-v02-is-marked-current" / "envelope.json")
        umschlag = json.loads(fall.read_text(encoding="utf-8"))
        praedikat = json.loads(base64.b64decode(umschlag["payload"], validate=True))["predicate"]
        zeile = ar.render_disclosure_line(praedikat, receipt_digest="0" * 64, receipt_url="https://x/r",
                                          leaf_url="https://x/leaf", leaf_witnessed=False)
        self.assertIn("not yet in a witnessed checkpoint", zeile)
        for wert in _KEIN_BOOL:
            with self.subTest(value=wert):
                with self.assertRaises(ProofBundleError):
                    ar.render_disclosure_line(praedikat, receipt_digest="0" * 64,
                                              receipt_url="https://x/r", leaf_url="https://x/leaf",
                                              leaf_witnessed=wert)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# Class A at the nine sibling sites (owner decision, option A) and on the native-bundle side.
# Each case was measured RED at fa555f13 and GREEN at the head that adds it.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

_K2 = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)   # signs S2; the verifying key _SIGNER never does
_STATEMENT_TYPE = "application/vnd.in-toto+json"


def _statement_of(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))


def _b64_statement(statement: dict) -> str:
    return base64.b64encode(canonicalize_statement(statement)).decode("ascii")


def _other_type(statement: dict) -> None:
    statement["predicateType"] = "https://example.invalid/not-this-predicate/v0"


def _unknown_field(statement: dict) -> None:
    statement["predicate"]["xUnsignedProbe"] = 1


def _agent_review_predicate(case: str) -> dict:
    fall = Path(__file__).resolve().parents[1] / "conformance" / "agent_review" / case / "envelope.json"
    umschlag = json.loads(fall.read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(umschlag["payload"], validate=True))["predicate"]


def _subject_hex(envelope: dict) -> str:
    return _statement_of(envelope)["subject"][0]["digest"]["sha256"]


class ClassAAtTheNineSiblingSites(unittest.TestCase):
    """PROPERTY (class A, owner decision option A): `ok` True means the statement judged is one the
    verifying key signed. Each site below paired `dsse.verify_envelope` with `dsse.load_payload`, two
    readings of the caller's envelope (the lens estimated them by grep; this round measured them).

    Construction, per site: S2 is a valid statement signed by another key; S1 is S2 made invalid in
    a way the verifier checks, signed by the verifying key. The envelope stores S1, and the lens's
    `_SwapAfter` answers S2 from read `after + 1` on. Controls: the envelope and the envelope carrying
    S2 are both ok=False. Measured at fa555f13: ok=True at after=1 (after=2 for the version switch),
    a verdict over a statement the verifying key never signed."""

    def _held(self, verify, genuine_other_key: dict, mutate=_other_type) -> None:
        s2 = _statement_of(genuine_other_key)
        s1 = copy.deepcopy(s2)
        mutate(s1)
        from proofbundle import dsse  # noqa: PLC0415
        e1 = dsse.sign_envelope(canonicalize_statement(s1), _SIGNER, payload_type=_STATEMENT_TYPE)
        positiv = dsse.sign_envelope(canonicalize_statement(s2), _SIGNER, payload_type=_STATEMENT_TYPE)
        self.assertIs(verify(positiv)["ok"], True, "positive control: S2 signed by the verifying key")
        self.assertIs(verify(e1)["ok"], False, "control: S1 is refused")
        self.assertIs(verify(dict(e1, payload=_b64_statement(s2)))["ok"], False, "control: S2 is unsigned")
        for after in range(4):
            with self.subTest(after=after):
                res = verify(_SwapAfter(copy.deepcopy(e1), "payload", _b64_statement(s2), after))
                self.assertIsNot(res["ok"], True, "ok=True over a statement the key never signed")

    def test_decision_py_567_verify_decision_receipt(self) -> None:
        from proofbundle import decision  # noqa: PLC0415
        praedikat = json.loads((Path(__file__).resolve().parents[1] / "examples"
                                / "decision_receipt_allow.json").read_text(encoding="utf-8"))
        self._held(lambda e: decision.verify_decision_receipt(e, _PUB),
                   decision.emit_decision_receipt(praedikat, _K2, strict=True))

    def test_verification_summary_py_223_verify_verification_summary(self) -> None:
        from proofbundle import verification_summary as vs  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "summaryId": "summary-0001",
                     "producedAt": "2026-07-14T10:00:00Z",
                     "producer": {"id": "verifier://example/summarizer"},
                     "levels": [{"kind": "eval", "receiptRef": {"sha256": "a" * 64}, "status": "VERIFIED",
                                 "evidenceClass": "authorship_integrity", "checks": ["crypto", "merkle"]}],
                     "nonClaims": ["does not prove the eval number is true"]}
        self._held(lambda e: vs.verify_verification_summary(e, _PUB),
                   vs.emit_verification_summary(praedikat, _K2))

    def test_run_ledger_py_275_verify_run_ledger(self) -> None:
        from proofbundle import run_ledger as rl  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "studyId": "study-0001", "runBudget": 5,
                     "runs": rl.link_runs(["1" * 64, "2" * 64, "3" * 64],
                                          ["completed", "aborted", "completed"]),
                     "selectedSeq": 3, "nonClaims": ["does not prove the selected run is representative"]}
        self._held(lambda e: rl.verify_run_ledger(e, _PUB), rl.emit_run_ledger(praedikat, _K2))

    def test_outcome_py_599_verify_outcome_receipt(self) -> None:
        from proofbundle import outcome  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001",
                     "decisionRef": {"sha256": "a" * 64},
                     "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
                     "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
                     "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
        self._held(lambda e: outcome.verify_outcome_receipt(e, _PUB),
                   outcome.emit_outcome_receipt(praedikat, _K2))

    def test_relation_statement_py_215_verify_relation_statement(self) -> None:
        from proofbundle import relation_statement as rs  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
                     "relationships": [{"relation": "retracts", "targetReceiptDigest": {
                         "digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64}}]}
        self._held(lambda e: rs.verify_relation_statement(e, _PUB),
                   rs.emit_relation_statement(praedikat, _K2))

    def test_agent_review_py_2300_verify_agent_review_v01(self) -> None:
        from proofbundle import agent_review as ar  # noqa: PLC0415
        umschlag = ar.emit_agent_review(
            _agent_review_predicate("agent-review-v02-positive-control-legacy-v01-is-marked-legacy"),
            _K2, legacy_v01=True)
        subjekt = _subject_hex(umschlag)
        self._held(lambda e: ar.verify_agent_review(e, _PUB, expected_subject_digest=subjekt), umschlag)

    def test_agent_review_py_2626_verify_agent_review_v02(self) -> None:
        from proofbundle import agent_review as ar  # noqa: PLC0415
        umschlag = ar.emit_agent_review(
            _agent_review_predicate("agent-review-v02-positive-control-current-v02-is-marked-current"), _K2)
        subjekt = _subject_hex(umschlag)
        self._held(lambda e: ar.verify_agent_review_v02(e, _PUB, expected_subject_digest=subjekt),
                   umschlag)

    def test_agent_review_py_3044_verify_agent_review_any(self) -> None:
        """The version switch read `payload` for the type and handed the caller's envelope on, so the
        verifier behind it read it twice more; S1 keeps the type and carries an unknown field."""
        from proofbundle import agent_review as ar  # noqa: PLC0415
        umschlag = ar.emit_agent_review(
            _agent_review_predicate("agent-review-v02-positive-control-current-v02-is-marked-current"), _K2)
        subjekt = _subject_hex(umschlag)
        self._held(lambda e: ar.verify_agent_review_any(e, _PUB, expected_subject_digest=subjekt),
                   umschlag, _unknown_field)

    def test_trust_pack_py_463_verify_trust_pack(self) -> None:
        """verify_trust_pack read `payload` once but `signatures` twice through the caller's envelope:
        once for the signatures cap and once for the threshold loop. Measured at fa555f13 with a dict
        subclass storing the three signatures and answering 600 entries from the second read on: the
        cap judged three and the loop checked 600 signatures (budget.signatures is 512), 20 000
        entries took 2.0 s. The one reading checks the stored three and the pack verifies."""
        from unittest import mock  # noqa: PLC0415
        from datetime import datetime, timezone  # noqa: PLC0415
        from proofbundle import trust_pack  # noqa: PLC0415
        from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415
        schluessel = {f"root-{i}": Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
                      for i in range(3)}
        keys = {k: {"publicKey": base64.b64encode(sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
            "scheme": "ed25519"} for k, sk in schluessel.items()}
        praedikat = {"schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": 1,
                     "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": None,
                     "roles": {"root": {"keyIds": list(keys), "threshold": 2},
                               "outcomeExecutors": {"keyIds": ["root-0"], "threshold": 1}},
                     "keys": keys,
                     "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
        umschlag = trust_pack.sign_trust_pack(praedikat, schluessel)
        jetzt = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
        viele = [{"keyid": "root-0", "sig": base64.b64encode(bytes(64)).decode("ascii")}] * 600
        self.assertGreater(len(viele), DEFAULT_BUDGET.signatures)
        echt = trust_pack._verify_signature_for_alg
        with mock.patch.object(trust_pack, "_verify_signature_for_alg", wraps=echt) as zaehler:
            res = trust_pack.verify_trust_pack(_SwapAfter(umschlag, "signatures", viele, 1), now=jetzt)
        self.assertLessEqual(zaehler.call_count, DEFAULT_BUDGET.signatures,
                             "the loop checked more signatures than the cap it passed")
        self.assertIs(res["ok"], True)


class NoFunctionReadsAnEnvelopeTwice(unittest.TestCase):
    """PROPERTY (the class, statically): no function under src/proofbundle hands the same envelope to
    both `verify_envelope` and `load_payload`, the pairing behind L4 to L6 and the nine sites above.
    `dsse._verify_and_load` is the one-line replacement. RED at fa555f13: eleven functions paired
    them (the three in-toto verifiers, the seven sites of `ClassAAtTheNineSiblingSites` that call
    `verify_envelope`, and the `--with-related` reader of the CLI, which reads a parsed file)."""

    def test_no_pairing(self) -> None:
        import ast  # noqa: PLC0415
        paket = Path(__file__).resolve().parents[1] / "src" / "proofbundle"
        funde = []
        for datei in sorted(paket.rglob("*.py")):
            if datei.name == "dsse.py":
                continue
            baum = ast.parse(datei.read_text(encoding="utf-8"))
            for knoten in ast.walk(baum):
                if not isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                gelesen: dict = {}
                for aufruf in ast.walk(knoten):
                    if (isinstance(aufruf, ast.Call) and isinstance(aufruf.func, ast.Attribute)
                            and aufruf.func.attr in ("verify_envelope", "load_payload") and aufruf.args):
                        gelesen.setdefault(ast.unparse(aufruf.args[0]), set()).add(aufruf.func.attr)
                for argument, namen in gelesen.items():
                    if len(namen) == 2:
                        funde.append(f"{datei.relative_to(paket)}::{knoten.name}({argument})")
        self.assertEqual(funde, [], "verify_envelope and load_payload read one envelope twice")


class ClassAOnTheNativeBundleSide(unittest.TestCase):
    """PROPERTY (class A, the native bundle): a verdict and the content it is about come from one
    reading of the caller's bundle. Measured at fa555f13 and at the head before this change with a
    dict subclass whose own `__getitem__`/`get` answer other fields from a later read on."""

    def test_verify_bundle_binds_the_sd_jwt_to_the_payload_it_verified(self) -> None:
        """verify_bundle read `payload_b64` and `merkle` a second time for the SD-JWT binding. An
        SD-JWT issued for receipt B (passed True) grafted onto receipt A (passed False) is refused;
        with the second reads answering B's fields, it verified ok=True (after=1)."""
        from proofbundle.bundle import verify_bundle  # noqa: PLC0415
        from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding  # noqa: PLC0415
        halter = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
        a = ec.emit_eval_receipt(_claim("0.80"), _SIGNER)                  # passed False
        schlicht = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)           # passed True
        kompakt = issue_sd_jwt(json.loads(base64.b64decode(schlicht["payload_b64"])), _SIGNER,
                               root_b64=schlicht["merkle"]["root_b64"],
                               holder_public_key=halter.public_key().public_bytes(
                                   serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        vc = {"compact": present_with_key_binding(kompakt, halter, aud="v", nonce="n", iat=1_780_000_000),
              "issuer_public_key_b64": base64.b64encode(_PUB).decode("ascii")}
        b = ec.emit_eval_receipt(_claim("0.10"), _SIGNER, sd_jwt=vc)
        self.assertIs(verify_bundle(b).ok, True)
        pfropf = dict(a, sd_jwt_vc=b["sd_jwt_vc"])
        self.assertIs(verify_bundle(pfropf).ok, False)
        for after in range(3):
            with self.subTest(after=after):
                gefaelscht = _SwapTwo(pfropf, {"payload_b64": b["payload_b64"], "merkle": b["merkle"]},
                                      after)
                self.assertIs(verify_bundle(gefaelscht).ok, False,
                              "verified an SD-JWT bound to another receipt")

    def test_verify_bundle_reads_the_type_the_object_has(self) -> None:
        """The copy reads an object by its own type, so an object whose `__class__` claims dict and
        which holds a list is a list to it, and verify_bundle refuses it with its documented
        BundleFormatError. At fa555f13 `isinstance` believed `__class__` and a raw AttributeError
        escaped from `bundle.get`."""
        from proofbundle.bundle import verify_bundle  # noqa: PLC0415
        from proofbundle.errors import BundleFormatError  # noqa: PLC0415

        class _KlasseLuegt(list):
            @property
            def __class__(self):  # type: ignore[override]
                return dict

        with self.assertRaises(BundleFormatError):
            verify_bundle(_KlasseLuegt([1]))

    def test_export_svr_dsse_signs_about_one_receipt(self) -> None:
        """export_svr_dsse read the bundle three times (decode_eval_claim, verify_bundle,
        recompute_merkle_root_b64). With `merkle` answering another receipt's from a later read, it
        signed an SVR whose subject binds that other receipt's root (after=2 at fa555f13)."""
        x = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)
        y = ec.emit_eval_receipt(dict(_claim("0.20"), suite="other-suite"), _SIGNER)
        echt = _statement_of(intoto.export_svr_dsse(x, _SIGNER))["subject"]
        for after in range(4):
            with self.subTest(after=after):
                try:
                    umschlag = intoto.export_svr_dsse(_SwapTwo(x, {"merkle": y["merkle"]}, after), _SIGNER)
                except ProofBundleError:
                    continue
                self.assertEqual(_statement_of(umschlag)["subject"], echt,
                                 "signed an SVR about a root the verified receipt does not carry")

    def test_to_eval_results_entry_checks_the_verdict_of_the_bundle_it_verified(self) -> None:
        """to_eval_results_entry verified the bundle, then read it again in decode_eval_claim and
        again for `payload_b64`. With `payload_b64` answering a non-claim payload from the second read,
        it built an entry whose value contradicts the signed verdict (after=1 and 2 at fa555f13).
        decode_eval_claim's one reading closes it."""
        from proofbundle import hf_evals  # noqa: PLC0415
        x = ec.emit_eval_receipt(_claim("0.10"), _SIGNER)                  # passed True
        fremd = base64.b64encode(b'{"x": 1}').decode("ascii")
        for after in range(4):
            with self.subTest(after=after):
                with self.assertRaises(ProofBundleError):
                    hf_evals.to_eval_results_entry(_SwapTwo(x, {"payload_b64": fremd}, after),
                                                   dataset_id="d", task_id="t", value=0.05)


class _SwapTwo(dict):
    """`_SwapAfter` for several fields: stores `source`; its own `__getitem__` and `get` answer
    `forged[field]` from read `after + 1` of that field on."""

    def __init__(self, source: dict, forged: dict, after: int) -> None:
        super().__init__(source)
        self.forged, self.after, self.reads = forged, after, {k: 0 for k in forged}

    def __getitem__(self, key):
        if key in self.forged:
            self.reads[key] += 1
            if self.reads[key] > self.after:
                return self.forged[key]
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        if key in self.forged and dict.__contains__(self, key):
            return self[key]
        return dict.get(self, key, default)


if __name__ == "__main__":
    unittest.main()
