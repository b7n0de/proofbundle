"""Lens run (Claude family) on fix/the-commit-pattern-holds-at-the-verify-boundary at fa555f13.

Every case below states the property it holds and was RED at fa555f130a80cdfedd5965715bc7f8451c974bbe
when it was written (python -m pytest on this file, Python 3.11.15); L1 to L12 also at main 31816e08.
L13 to L25 were added under the owner order of 2026-09-27, 19:3x Berlin (L13 to L19: class A, the
nine load_payload sites; L20 to L25: class B, the flag sweep); their result at main 0ace3039 is in
the review. None of them changes production
code; each one is the reproduction of one row of REVIEW_lens_claude_d4_fa555f130a80.md. Oracles: the
package's own signed bytes (L1 to L6, L13 to L19), the package's own documented rule (L7, L9 to
L12, L20 to L25), and for L8 the regular-expression dialect JSON Schema names for "pattern" (ECMA-262), measured
off-test with node v22.22.2.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
import unittest

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import dsse
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


class _EncodesAfter(str):
    """A str that holds the signed base64 and whose own `encode` returns `forged` from call
    `after + 1` on (the verify_agent_review_any route reads the payload three times)."""

    def __new__(cls, text: str, forged: str, after: int) -> "_EncodesAfter":
        obj = super().__new__(cls, text)
        obj.forged, obj.after, obj.calls = forged, after, 0
        return obj

    def encode(self, *args, **kwargs):  # type: ignore[override]
        self.calls += 1
        return (str.__str__(self) if self.calls <= self.after else self.forged).encode(*args, **kwargs)


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


_INTOTO = "application/vnd.in-toto+json"
_EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _sign_statement(statement: dict) -> dict:
    return dsse.sign_envelope(canonicalize_statement(statement), _SIGNER, payload_type=_INTOTO)


def _with_predicate(statement: dict, predicate: dict) -> dict:
    """The builder's statement for a valid predicate, carrying `predicate` instead, with its own
    subject digest. The builders refuse the predicate a producer may still sign by other means."""
    statement = copy.deepcopy(statement)
    statement["predicate"] = predicate
    statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(rfc8785.dumps(predicate)).hexdigest()
    return statement


def _review_statement(predicate: dict, predicate_type: str) -> dict:
    return {"_type": AR.STATEMENT_TYPE,
            "subject": [{"name": AR._subject_name(predicate),
                         "digest": {"sha256": AR._subject_digest(predicate)}}],
            "predicateType": predicate_type, "predicate": predicate}


def _review_predicate(v02: bool) -> dict:
    # The v0.1 and v0.2 predicates of tests/test_agent_review_zeitsemantik.py (`_pred`, `_pred_v02`).
    predicate = {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                           "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        "times": {"declaredAt": "2026-08-31T20:00:00Z", "observedAt": None},
        "limitations": ["l"],
    }
    if v02:
        predicate["subjectContext"]["disclosureCoreDigest"] = "e" * 64
        predicate["limitationCodes"] = ["CURRENTNESS_UNKNOWN", "IDENTITY_UNBOUND",
                                        "NOT_QUALITY_ATTESTATION", "TIME_SELF_DECLARED"]
        predicate["times"]["signedAt"] = "2026-08-31T20:00:00Z"
    return predicate


class L13to19DsseReceiptVerifiersJudgeTheSignedStatement(unittest.TestCase):
    """PROPERTY: `ok` True means the statement that was judged is the one the signature covers
    (the class of L4 to L6, at the nine load_payload sites of decision, verification_summary,
    trust_pack, run_ledger, outcome, relation_statement and agent_review). Each verifier calls
    dsse.verify_envelope and then dsse.load_payload, and both read `payload` from the caller's
    envelope. Each case signs a statement S that the verifier refuses on one signed field, and
    offers F, the same statement with that field changed, from a later read: a dict subclass whose
    `__getitem__` and `get` answer F, or a str subclass in the field whose `encode` answers F.
    Controls in every case: S is refused, F in S's envelope is refused, F signed by the same key
    passes. P0, same precondition as L1 to L6: a caller-built object, never bytes, the CLI or the
    Rust verifier. trust_pack reads the payload once and holds; the dispatch read of
    verify_agent_review_any refuses when it alone differs (the report has both)."""

    def _check(self, signed: dict, forged: dict, verify, reads: int = 2) -> None:
        envelope = _sign_statement(signed)
        forged_b64 = base64.b64encode(canonicalize_statement(forged)).decode("ascii")
        self.assertFalse(verify(copy.deepcopy(envelope))["ok"], "control: S is refused")
        self.assertFalse(verify(dict(envelope, payload=forged_b64))["ok"], "control: F is unsigned")
        self.assertTrue(verify(_sign_statement(forged))["ok"], "control: F passes when signed")
        for after in range(reads + 1):
            with self.subTest(form="dict subclass", after=after):
                res = verify(_SwapAfter(copy.deepcopy(envelope), "payload", forged_b64, after))
                self.assertFalse(res["ok"], "ok=True over a statement the signature does not cover")
            with self.subTest(form="str subclass", after=after):
                env = copy.deepcopy(envelope)
                env["payload"] = _EncodesAfter(envelope["payload"], forged_b64, after)
                self.assertFalse(verify(env)["ok"], "ok=True over a statement the signature does not cover")

    def test_l13_verify_decision_receipt(self) -> None:
        from proofbundle.decision import build_decision_statement, verify_decision_receipt  # noqa: PLC0415
        signed = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        forged = copy.deepcopy(signed)
        forged["validity"]["nonce"] = "the-verifier-s-nonce"
        self._check(build_decision_statement(signed), build_decision_statement(forged),
                    lambda e: verify_decision_receipt(e, _PUB, expected_nonce="the-verifier-s-nonce"))

    def test_l14_verify_verification_summary(self) -> None:
        from proofbundle.verification_summary import (  # noqa: PLC0415
            build_summary_statement, verify_verification_summary)
        signed = {"schemaVersion": "0.1.0", "summaryId": "summary-0001", "producedAt": "2026-07-14T10:00:00Z",
                  "producer": {"id": "verifier://example/summarizer"},
                  "levels": [{"kind": "eval", "status": "VERIFIED", "evidenceClass": "authorship_integrity"}],
                  "nonClaims": ["does not prove the eval number is true"]}
        forged = copy.deepcopy(signed)
        forged["levels"][0]["receiptRef"] = {"sha256": "a" * 64}
        self._check(_with_predicate(build_summary_statement(forged), signed), build_summary_statement(forged),
                    lambda e: verify_verification_summary(e, _PUB))

    def test_l15_verify_run_ledger(self) -> None:
        from proofbundle.run_ledger import build_run_ledger_statement, link_runs, verify_run_ledger  # noqa: PLC0415
        signed = {"schemaVersion": "0.1.0", "studyId": "study-0001", "runBudget": 2,
                  "runs": link_runs(["1" * 64, "2" * 64, "3" * 64], ["completed", "aborted", "completed"]),
                  "selectedSeq": 3, "nonClaims": ["does not prove the selected run is representative"]}
        forged = dict(signed, runBudget=5)
        self._check(_with_predicate(build_run_ledger_statement(forged), signed),
                    build_run_ledger_statement(forged), lambda e: verify_run_ledger(e, _PUB))

    def test_l16_verify_outcome_receipt(self) -> None:
        from proofbundle.outcome import build_outcome_statement, verify_outcome_receipt  # noqa: PLC0415
        signed = {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
                  "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
                  "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
                  "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
        forged = dict(signed, decisionRef={"sha256": "b" * 64})
        self._check(build_outcome_statement(signed), build_outcome_statement(forged),
                    lambda e: verify_outcome_receipt(e, _PUB, expected_decision_ref="b" * 64))

    def test_l17_verify_relation_statement(self) -> None:
        from proofbundle.relation_statement import (  # noqa: PLC0415
            build_relation_statement, verify_relation_statement)
        forged = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
                  "relationships": [{"relation": "retracts", "targetReceiptDigest": {
                      "digestAlgorithm": "jcs-sha256-v1", "digest": "f" * 64}}]}
        signed = dict(forged, schemaVersion="0.2.0")
        self._check(_with_predicate(build_relation_statement(forged), signed), build_relation_statement(forged),
                    lambda e: verify_relation_statement(e, _PUB))

    def test_l18_verify_agent_review_v01(self) -> None:
        signed = _review_predicate(v02=False)
        forged = copy.deepcopy(signed)
        forged["subjectContext"]["headSha"] = "f" * 40
        expected = AR._subject_digest(forged)
        t = AR.AGENT_REVIEW_PREDICATE_TYPE
        for name, verify, reads in (
                ("verify_agent_review", AR.verify_agent_review, 2),
                ("verify_agent_review_any", AR.verify_agent_review_any, 3)):
            with self.subTest(surface=name):
                self._check(_review_statement(signed, t), _review_statement(forged, t),
                            lambda e, v=verify: v(e, _PUB, strict=True, expected_subject_digest=expected),
                            reads)

    def test_l19_verify_agent_review_v02_and_v03(self) -> None:
        signed = _review_predicate(v02=True)
        forged = copy.deepcopy(signed)
        forged["subjectContext"]["headSha"] = "f" * 40
        expected = AR._subject_digest(forged)
        for name, verify, t, reads in (
                ("verify_agent_review_v02", AR.verify_agent_review_v02, AR.AGENT_REVIEW_PREDICATE_TYPE_V02, 2),
                ("verify_agent_review_v03", AR.verify_agent_review_v03, AR.AGENT_REVIEW_PREDICATE_TYPE_V03, 2),
                ("verify_agent_review_any", AR.verify_agent_review_any, AR.AGENT_REVIEW_PREDICATE_TYPE_V02, 3)):
            with self.subTest(surface=name):
                self._check(_review_statement(signed, t), _review_statement(forged, t),
                            lambda e, v=verify: v(e, _PUB, strict=True, expected_subject_digest=expected),
                            reads)


_NON_BOOL_TRUTHY = ("false", "no", 1, [0])
_NON_BOOL_FALSY = (None, 0, "")


class L20to25AFlagCountsOnlyAsABool(unittest.TestCase):
    """PROPERTY (class B; round 10, `canonical._flagge`, R-B4; L7 holds it for allow_deprecated): a
    boolean keyword is True or False, and any other value is refused, never read by its truth.
    Measured at fa555f13 with the lens-3 flag sweep (73 keywords, six non-bool values): these six
    keywords relax on a non-bool and change a verdict or a signed field. Truthy non-bools include
    "false" and "no". L22 to L24 hold at this head what N3, N2 and N1 of the lens run on branch 291
    (3a8074fc) hold there."""

    def test_l20_allow_pending_opens_the_anchor_requirement(self) -> None:
        # P1: verify_anchors(require="any") answers FAIL for a pending anchor, and allow_pending="false"
        # makes the pending anchor meet the requirement.
        from proofbundle import anchors  # noqa: PLC0415
        root = b"\xaa" * 32
        pending = [{"type": "lens-pending/v1", "target": "receipt", "canonicalRoot": base64.b64encode(root).decode(),
                    "proof": base64.b64encode(b"p").decode(), "anchoredAt": "2026-07-05T12:00:00Z"}]
        saved = dict(anchors._VERIFIERS)
        anchors.register_anchor_type(
            "lens-pending/v1",
            lambda proof, r, *, frozen, now: {"ok": False, "warn": True, "status": "pending", "detail": "pending"})
        try:
            def run(value):
                return anchors.verify_anchors(pending, target_roots={"receipt": root}, require="any",
                                              allow_pending=value)
            self.assertEqual(run(False)["status"], "FAIL")
            self.assertEqual(run(True)["status"], "WARN")
            for value in _NON_BOOL_TRUTHY:
                with self.subTest(allow_pending=value):
                    try:
                        res = run(value)
                    except ProofBundleError:
                        continue
                    self.assertEqual(res["status"], "FAIL")
        finally:
            anchors._VERIFIERS.clear()
            anchors._VERIFIERS.update(saved)

    def test_l21_allow_value_mismatch_publishes_a_contradiction(self) -> None:
        # P1: the signed claim says passed=False (score 0.5 against >= 0.80); a published value of 0.95
        # contradicts it and is refused, and allow_value_mismatch="false" publishes it.
        from proofbundle import hf_evals  # noqa: PLC0415
        bundle = ec.emit_eval_receipt(_claim("0.80"), _SIGNER)

        def run(value):
            return hf_evals.to_eval_results_entry(bundle, dataset_id="d", task_id="t", value=0.95,
                                                  allow_value_mismatch=value)
        with self.assertRaises(ProofBundleError):
            run(False)
        self.assertEqual(run(True)["value"], 0.95)
        for value in _NON_BOOL_TRUTHY:
            with self.subTest(allow_value_mismatch=value):
                with self.assertRaises(ProofBundleError):
                    run(value)

    def test_l22_legacy_v01_signs_under_the_old_rules(self) -> None:
        # P1: `return not legacy_v01`; "false" and "no" judge a v0.1 predicate under the legacy v0.1
        # rules that False refuses under the v0.2 rules, and emit_agent_review signs it.
        body = "# T\n\nText.\n"
        findings = [{"id": "F1", "severity": "low", "title": "t", "disposition": "dismissed", "reason": "r"}]
        predicate = {
            "schemaVersion": "0.1.0", "reviewId": "r",
            "subjectContext": {"kind": "githubPullRequest", "forge": "github.com", "repositoryId": "R",
                               "pullRequestNodeId": "PR", "headSha": "a" * 40, "baseSha": "b" * 40,
                               "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": AR.body_core_digest(body)},
            "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}], "reviewRuns": [],
                            "findings": findings, "findingsTotal": 1,
                            "findingsRoot": AR.findings_root(findings), "nonClaims": ["n"]},
            "coverage": {"status": "UNKNOWN"}, "times": {"declaredAt": "2026-08-31T17:00:00Z"},
            "limitations": ["l"],
        }
        sites = (
            ("emit_agent_review", lambda v: AR.emit_agent_review(predicate, _SIGNER, legacy_v01=v)),
            ("require_valid_agent_review_predicate_any",
             lambda v: AR.require_valid_agent_review_predicate_any(predicate, legacy_v01=v)),
            ("render_disclosure_block", lambda v: AR.render_disclosure_block(predicate, legacy_v01=v)),
        )
        for name, call in sites:
            with self.assertRaises(ProofBundleError):
                call(False)
            for value in ("false", "no"):
                with self.subTest(site=name, legacy_v01=value):
                    with self.assertRaises(ProofBundleError):
                        call(value)

    def test_l23_bound_writes_the_version_as_reported(self) -> None:
        # P1: `if bound and ...`; bound="false" writes status `reported` into the provenance block that
        # is signed into the receipt, where False writes `not_bound` with its reason.
        from proofbundle.adapters._provenance import bind_reported_version  # noqa: PLC0415
        block: dict = {}
        bind_reported_version(block, "harness_version", "0.3.1", reason="r", bound=False)
        self.assertNotEqual(block.get("harness_version_status"), "reported")
        for value in _NON_BOOL_TRUTHY:
            with self.subTest(bound=value):
                block = {}
                try:
                    bind_reported_version(block, "harness_version", "0.3.1", reason="r", bound=value)
                except (ValueError, ProofBundleError):
                    continue
                self.assertNotEqual(block.get("harness_version_status"), "reported")

    def test_l24_applicable_drops_the_weakest_link(self) -> None:
        # P1: `if not applicable`; a falsy non-bool makes a weak field not applicable, and the ladder
        # summary of a CLAIMED and a CONTENT_RESOLVED field rises to CONTENT_RESOLVED.
        from proofbundle import assurance  # noqa: PLC0415
        strong = assurance.classify_digest_evidence({"sha256": "a" * 64}, applicable=True,
                                                    evidence_resolver=lambda _d: True)
        weak = assurance.classify_digest_evidence({"sha256": "not-hex"}, applicable=True)
        self.assertEqual(assurance.evidence_ladder_summary(weak, strong)["level_name"], "CLAIMED")
        for value in _NON_BOOL_FALSY + ([],):
            with self.subTest(applicable=value):
                try:
                    field = assurance.classify_digest_evidence({"sha256": "not-hex"}, applicable=value)
                except ProofBundleError:
                    continue
                self.assertEqual(assurance.evidence_ladder_summary(field, strong)["level_name"], "CLAIMED")

    def test_l25_strict_none_signs_what_the_default_refuses(self) -> None:
        # P2: emit_decision_receipt defaults to strict=True and reads it by its truth
        # (`_REQUIRED_STRICT if strict else _REQUIRED_ALWAYS`); None, 0 and "" sign a predicate the
        # default refuses. None is what `strict=config.get("strict")` passes when the key is absent.
        from proofbundle.decision import emit_decision_receipt  # noqa: PLC0415
        predicate = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        del predicate["notChecked"]
        with self.assertRaises(ProofBundleError):
            emit_decision_receipt(predicate, _SIGNER)
        emit_decision_receipt(predicate, _SIGNER, strict=False)
        for value in _NON_BOOL_FALSY:
            with self.subTest(strict=value):
                with self.assertRaises(ProofBundleError):
                    emit_decision_receipt(predicate, _SIGNER, strict=value)


if __name__ == "__main__":
    unittest.main()
