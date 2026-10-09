"""eval-result v0.2: the revised shape of the in-toto/attestation#575 draft (its second revision) under its own
vendor type.

The draft changed the predicate in three places, and each is a property here:

1. `evaluator.id` names the party that ran the evaluation. It is required and the emitter has no default
   for it: the tool that records a result is not the party that produced it.
   The same party MAY hold more than one role, so an evaluator that is also the signer is not refused.
2. The model and the dataset are each identified exactly once: `commitments.<x>` for a private identity,
   or a predicate-level ResourceDescriptor with a `digest` for a public one. Both or neither is refused,
   each present representation must satisfy its own field rules (a commitment MUST set `salted` to
   `true`, a descriptor MUST carry `digest`), and Statement `subject` entries and `evidence` references
   never count.
3. `evidence[]` of ResourceDescriptors replaces the `receipt` block, and an entry without `digest` is
   refused. The digest identifies the referenced artifact itself (the decoded bytes when `content` is
   present); an internal Merkle root is not a substitute. The SHOULD fields (`mediaType`, `uri` or
   `downloadLocation`) are not refusals.

Unknown fields are ignored at every level, as the in-toto parsing rules require, which is why the old
`receipt` block and an `anchors` array in a v0.2 predicate are ignored rather than refused.

G2, the old contract: `https://b7n0de.com/attestation/eval-result/v0.1` was emitted and signed by
released versions. Its statements keep verifying under the v0.1 contract, the default verify call keeps
expecting v0.1, and the v0.1 emitter keeps writing the same bytes. A valid signature alone does not show
that, so `tests/fixtures/eval_result_v0_1/corpus.json` carries v0.1 envelopes with a named origin each
(fixtures from the published 6.1.0 wheel, own reconstructions from the source at the release tags
v2.0.0 to v6.0.0) and the verdicts the released 6.1.0 verifier gives on them and on negative variants;
this head must give the same verdicts, and must dispatch on `predicateType` to the old or the revised
rules.

The verifier vectors below are built by hand from the draft text, not from the emitter, so the verifier
and the emitter are checked against the text independently. Every vector is signed with a valid key, so
a refusal comes from the predicate shape and nothing else.
"""
from __future__ import annotations

import base64
import copy
import hashlib
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
from proofbundle.errors import BundleFormatError

REPO = Path(__file__).resolve().parents[1]
_G2_JCS = REPO / "tests/fixtures/eval_result_v0_1/envelope_jcs.json"
_G2_LEGACY = REPO / "tests/fixtures/eval_result_v0_1/envelope_legacy.json"
_G2_CORPUS = REPO / "tests/fixtures/eval_result_v0_1/corpus.json"

V01 = "https://b7n0de.com/attestation/eval-result/v0.1"
V02 = "https://b7n0de.com/attestation/eval-result/v0.2"
EVALUATOR = "https://example.com/evaluator"
ROOT = "cmVjZWlwdC1tZXJrbGUtcm9vdA=="
# The throwaway example key: it signs only examples and vectors.
_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True,
    "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32,
    "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1",
    "issuer": "ed25519:AAAA",
    "timestamp": "2026-07-05T12:00:00Z",
    "assurance_level": "self_attested",
}


def _pub(signer=_SIGNER) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _base_statement() -> dict:
    """The draft's own private-model example, with real hex where the draft writes an ellipsis."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "eval-receipt", "digest": {"sha256": "c0" * 32}}],
        "predicateType": V02,
        "predicate": {
            "evaluator": {"id": "https://example.com/evaluator"},
            "evaluatedAt": "2026-07-05T12:00:00Z",
            "suite": {"name": "safety-refusals", "version": "1.2.0"},
            "claims": [{"metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True}],
            "sampleSize": 500,
            "commitments": {
                "model": {"alg": "sha256-salted-v1", "value": "a1" * 32, "salted": True},
                "dataset": {"alg": "sha256-salted-v1", "value": "b2" * 32, "salted": True},
            },
            "assuranceLevel": "self_attested",
            "subjectProfile": "receipt",
            "evidence": [{"name": "eval-receipt", "digest": {"sha256": "d3" * 32},
                          "mediaType": "application/json"}],
        },
    }


def _sign(statement: dict, signer=_SIGNER) -> dict:
    """A valid signature over the canonical bytes of `statement`, whatever its predicate says."""
    body = I._serialize_statement(statement, I.LEGACY_CONTENT_ROOT_ALG)
    return dsse.sign_envelope(body, signer, payload_type=I.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _verify_v02(statement: dict) -> dict:
    return I.verify_eval_result_dsse(_sign(statement), _pub(),
                                     expected_predicate_type=I.EVAL_RESULT_V02_PREDICATE_TYPE)


def _mutated(change) -> dict:
    statement = _base_statement()
    change(statement, statement["predicate"])
    return statement


def _public_model(pred: dict) -> None:
    del pred["commitments"]["model"]
    pred["model"] = {"name": "acme/open-model-7b", "digest": {"sha256": "e4" * 32},
                     "uri": "https://example.com/acme/open-model-7b"}


def _set(key, value):
    def change(_statement, pred):
        pred[key] = value
    return change


def _drop(*path):
    def change(_statement, pred):
        node = pred
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    return change


# (case, change, a word the refusal must name)
REFUSED = [
    ("evaluator absent", _drop("evaluator"), "evaluator"),
    ("evaluator.id absent", _set("evaluator", {}), "evaluator"),
    ("evaluator.id empty", _set("evaluator", {"id": ""}), "evaluator"),
    ("evaluator.id not a string", _set("evaluator", {"id": 7}), "evaluator"),
    ("evaluator.id without a scheme", _set("evaluator", {"id": "example.com/evaluator"}), "evaluator"),
    ("evaluator a bare string", _set("evaluator", "https://example.com/evaluator"), "evaluator"),
    ("the v0.1 role name in place of evaluator",
     lambda s, p: p.__setitem__("verifier", p.pop("evaluator")), "evaluator"),
    ("model identified twice",
     lambda s, p: p.__setitem__("model", {"name": "m", "digest": {"sha256": "e4" * 32}}), "model"),
    ("model identified not at all", _drop("commitments", "model"), "model"),
    ("dataset identified twice",
     lambda s, p: p.__setitem__("dataset", {"name": "d", "digest": {"sha256": "f5" * 32}}), "dataset"),
    ("dataset identified not at all", _drop("commitments", "dataset"), "dataset"),
    ("neither identified, commitments absent", _drop("commitments"), "model"),
    ("model descriptor without digest",
     lambda s, p: (_public_model(p), p["model"].pop("digest")), "model"),
    ("model descriptor with an empty digest",
     lambda s, p: (_public_model(p), p["model"].__setitem__("digest", {})), "model"),
    ("model descriptor with the draft's placeholder as digest",
     lambda s, p: (_public_model(p), p["model"].__setitem__("digest", {"sha256": "…"})), "model"),
    ("model descriptor sha256 in upper case",
     lambda s, p: (_public_model(p), p["model"].__setitem__("digest", {"sha256": "E4" * 32})), "model"),
    ("model descriptor sha256 one character short",
     lambda s, p: (_public_model(p), p["model"].__setitem__("digest", {"sha256": "e" * 63})), "model"),
    ("model descriptor digest value not a string",
     lambda s, p: (_public_model(p), p["model"].__setitem__("digest", {"gitCommit": 7})), "model"),
    ("model descriptor not an object",
     lambda s, p: (_public_model(p), p.__setitem__("model", "sha256:" + "e4" * 32)), "model"),
    ("model descriptor uri not a string",
     lambda s, p: (_public_model(p), p["model"].__setitem__("uri", ["https://example.com"])), "model"),
    ("commitments.model null beside nothing else",
     lambda s, p: p["commitments"].__setitem__("model", None), "model"),
    ("commitments.model null beside a descriptor",
     lambda s, p: (_public_model(p), p["commitments"].__setitem__("model", None)), "model"),
    ("commitment value not hex",
     lambda s, p: p["commitments"]["model"].__setitem__("value", "zz"), "model"),
    ("commitment value empty",
     lambda s, p: p["commitments"]["model"].__setitem__("value", ""), "model"),
    ("commitment salted false (revision 2: MUST be true)",
     lambda s, p: p["commitments"]["model"].__setitem__("salted", False), "salted"),
    ("dataset commitment salted false",
     lambda s, p: p["commitments"]["dataset"].__setitem__("salted", False), "salted"),
    ("commitment salted not a boolean",
     lambda s, p: p["commitments"]["model"].__setitem__("salted", "true"), "salted"),
    ("commitment without salted", _drop("commitments", "model", "salted"), "salted"),
    ("commitment without alg", _drop("commitments", "dataset", "alg"), "dataset"),
    ("commitments not an object", _set("commitments", []), "commitments"),
    ("evidence entry without digest",
     _set("evidence", [{"name": "r", "mediaType": "application/json", "uri": "https://example.com/r"}]),
     "evidence"),
    ("evidence entry with an empty digest", _set("evidence", [{"name": "r", "digest": {}}]), "evidence"),
    ("second evidence entry without digest",
     _set("evidence", [{"digest": {"sha256": "d3" * 32}}, {"uri": "https://example.com/log"}]), "evidence[1]"),
    ("evidence an object, not an array", _set("evidence", {"digest": {"sha256": "d3" * 32}}), "evidence"),
    ("evidence entry a bare URI", _set("evidence", ["https://example.com/r"]), "evidence"),
    ("evidence null", _set("evidence", None), "evidence"),
    ("evidence content that is not its digest's bytes",
     _set("evidence", [{"digest": {"sha256": hashlib.sha256(b"other bytes").hexdigest()},
                        "content": base64.b64encode(b"receipt bytes").decode()}]), "evidence[0]"),
    ("evidence content that is not base64",
     _set("evidence", [{"digest": {"sha256": "d3" * 32}, "content": "not base64!"}]), "evidence[0]"),
    ("claims empty", _set("claims", []), "claims"),
    ("claims absent", _drop("claims"), "claims"),
    ("passed a string", lambda s, p: p["claims"][0].__setitem__("passed", "true"), "passed"),
    ("passed an integer", lambda s, p: p["claims"][0].__setitem__("passed", 1), "passed"),
    ("comparator outside the four", lambda s, p: p["claims"][0].__setitem__("comparator", "=="), "comparator"),
    ("comparator a list", lambda s, p: p["claims"][0].__setitem__("comparator", [">="]), "comparator"),
    ("threshold a JSON number", lambda s, p: p["claims"][0].__setitem__("threshold", 0.98), "threshold"),
    ("threshold not a number at all", lambda s, p: p["claims"][0].__setitem__("threshold", "abc"), "threshold"),
    ("metric empty", lambda s, p: p["claims"][0].__setitem__("metric", ""), "metric"),
    ("sampleSize a boolean", _set("sampleSize", True), "sampleSize"),
    ("sampleSize negative", _set("sampleSize", -1), "sampleSize"),
    ("sampleSize a string", _set("sampleSize", "500"), "sampleSize"),
    ("assuranceLevel outside the enum", _set("assuranceLevel", "certified"), "assuranceLevel"),
    ("subjectProfile outside the enum", _set("subjectProfile", "model"), "subjectProfile"),
    ("evaluatedAt not RFC 3339", _set("evaluatedAt", "05.07.2026 12:00"), "evaluatedAt"),
    ("evaluatedAt without an offset", _set("evaluatedAt", "2026-07-05T12:00:00"), "evaluatedAt"),
    ("evaluatedAt month 13", _set("evaluatedAt", "2026-13-05T12:00:00Z"), "evaluatedAt"),
    ("suite.version absent", _drop("suite", "version"), "suite"),
    ("suite absent", _drop("suite"), "suite"),
    ("harness without version", _set("harness", {"name": "inspect_ai"}), "harness"),
    ("harness digest empty", _set("harness", {"name": "inspect_ai", "version": "0.3.244", "digest": {}}),
     "harness"),
    ("preRegistration value not hex", _set("preRegistration", {"alg": "sha256", "value": "not hex"}),
     "preRegistration"),
    ("predicate an array", lambda s, p: s.__setitem__("predicate", [p]), "predicate"),
    ("subject empty", lambda s, p: s.__setitem__("subject", []), "subject"),
    ("subject entry without digest", lambda s, p: s.__setitem__("subject", [{"name": "eval-receipt"}]),
     "subject"),
    ("_type not Statement v1", lambda s, p: s.__setitem__("_type", "https://in-toto.io/Statement/v0.1"),
     "_type"),
]

# (case, change): each must verify. Unknown fields are ignored; SHOULDs are not refusals.
ACCEPTED = [
    ("the draft's example as written", lambda s, p: None),
    ("an unknown predicate field", _set("futureField", {"any": ["shape"]})),
    ("an unknown field in evaluator", lambda s, p: p["evaluator"].__setitem__("name", "Example Evals")),
    ("an unknown field in a claim", lambda s, p: p["claims"][0].__setitem__("stderr", "0.004")),
    ("an unknown field in commitments", lambda s, p: p["commitments"].__setitem__("tokenizer", 1)),
    ("an unknown field in a commitment", lambda s, p: p["commitments"]["model"].__setitem__("note", "x")),
    ("the v0.1 receipt block beside evidence",
     _set("receipt", {"schema": "proofbundle/v0.1", "merkleRootB64": ROOT})),
    ("an anchors array", _set("anchors", [{"type": "rfc3161", "token": "AAAA"}])),
    ("a subjectDigestNote", _set("subjectDigestNote", "subject.digest is a binder, not an artifact hash")),
    ("a public model by descriptor", lambda s, p: _public_model(p)),
    ("a public model and a public dataset, no commitments",
     lambda s, p: (_public_model(p), p.pop("commitments"),
                   p.__setitem__("dataset", {"name": "ds", "digest": {"sha256": "f5" * 32},
                                             "downloadLocation": "https://example.com/ds.tar"}))),
    ("an unknown field in a descriptor",
     lambda s, p: (_public_model(p), p["model"].__setitem__("vendorExtension", {"k": 1}))),
    ("a descriptor digest under an algorithm the verifier does not know",
     lambda s, p: (_public_model(p), p["model"].__setitem__("digest", {"proofbundleOther": "x1"}))),
    ("an evidence entry with digest only", _set("evidence", [{"digest": {"sha256": "d3" * 32}}])),
    ("an evidence entry with an unknown field",
     lambda s, p: p["evidence"][0].__setitem__("vendorNote", "kept, not read")),
    ("evidence absent", _drop("evidence")),
    ("evidence empty", _set("evidence", [])),
    ("harness with name and version only", _set("harness", {"name": "inspect_ai", "version": "0.3.244"})),
    ("harness with a digest",
     _set("harness", {"name": "inspect_ai", "version": "0.3.244", "digest": {"sha256": "ab" * 32}})),
    ("preRegistration", _set("preRegistration", {"alg": "sha256", "value": "e5" * 32})),
    ("evaluatedAt with an offset and fractions", _set("evaluatedAt", "2026-07-05T14:00:00.250+02:00")),
    ("sampleSize zero", _set("sampleSize", 0)),
    ("each comparator and a negative threshold",
     _set("claims", [{"metric": m, "comparator": c, "threshold": "-0.5", "passed": False}
                     for m, c in (("a", ">="), ("b", ">"), ("c", "<="), ("d", "<"))])),
    ("an evidence entry whose content is its digest's bytes",
     _set("evidence", [{"digest": {"sha256": hashlib.sha256(b"receipt bytes").hexdigest()},
                        "content": base64.b64encode(b"receipt bytes").decode()}])),
    ("an evidence entry with content under a digest algorithm the verifier cannot compute",
     _set("evidence", [{"digest": {"gitBlob": "ab" * 20}, "content": base64.b64encode(b"x").decode()}])),
    # Revision 2 of the draft: the same party MAY hold more than one role. proofbundle's own URI as evaluator, in a
    # statement proofbundle's key signs, is the self-attested case and is not refused.
    ("the evaluator is the signing party", lambda s, p: p.__setitem__("evaluator", {"id": I.VERIFIER_ID})),
]


class TheV02VerifierRefusesWhatTheTextRefuses(unittest.TestCase):
    def test_the_type_is_its_own_version(self):
        self.assertEqual(I.EVAL_RESULT_V02_PREDICATE_TYPE, V02)
        self.assertEqual(I.EVAL_RESULT_PREDICATE_TYPE, V01)

    def test_every_refused_case_is_refused_on_its_shape_alone(self):
        for case, change, word in REFUSED:
            with self.subTest(case=case):
                res = _verify_v02(_mutated(change))
                self.assertIs(res["ok"], False, res)
                self.assertIs(res["content_root_ok"], True, "the refusal must come from the shape")
                self.assertIs(res["predicate_type_ok"], True)
                self.assertIs(res["predicate_shape_ok"], False)
                self.assertIn(word, res["predicate_shape_detail"])
                self.assertIn(res["predicate_shape_detail"], res["content_root_detail"])

    def test_every_accepted_case_verifies(self):
        for case, change in ACCEPTED:
            with self.subTest(case=case):
                res = _verify_v02(_mutated(change))
                self.assertIs(res["ok"], True, res.get("predicate_shape_detail"))
                self.assertIs(res["predicate_shape_ok"], True)
                self.assertEqual(res["predicate_shape_detail"], "")

    def test_a_refusal_needs_a_valid_signature_first(self):
        env = _sign(_base_statement())
        res = I.verify_eval_result_dsse(env, _pub(Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)),
                                        expected_predicate_type=I.EVAL_RESULT_V02_PREDICATE_TYPE)
        self.assertIs(res["ok"], False)

    def test_the_shape_check_judges_and_never_raises(self):
        hostile = [None, 1, "x", [], {}, {"predicate": None}, {"predicate": {"evaluator": []}},
                   {"predicate": {"claims": [None, 1, "x"]}}, {"predicate": {"commitments": {"model": []}}},
                   {"predicate": {"evidence": [{"digest": []}]}}, {"subject": {"a": 1}, "predicate": {}},
                   {"predicate": {"claims": [{"comparator": {}}]}}, {"predicate": {"sampleSize": 10 ** 400}}]
        for value in hostile:
            with self.subTest(value=repr(value)[:60]):
                ok, detail = I.classify_eval_result_v02_predicate(value)
                self.assertIs(ok, False)
                self.assertIsInstance(detail, str)
                self.assertTrue(detail)

    def test_the_shape_check_accepts_the_base_case_directly(self):
        self.assertEqual(I.classify_eval_result_v02_predicate(_base_statement()), (True, ""))


class TheV01ContractStands(unittest.TestCase):
    """G2: old evidence stays verifiable under its old contract."""

    def _released(self):
        return [json.loads(p.read_text(encoding="utf-8")) for p in (_G2_JCS, _G2_LEGACY)]

    def test_envelopes_written_by_the_released_version_verify_with_the_default_call(self):
        for env in self._released():
            res = I.verify_eval_result_dsse(env, _pub())
            self.assertIs(res["ok"], True, res)
            self.assertEqual(res["predicate_type"], V01)

    def test_the_v01_emitter_still_writes_those_bytes(self):
        from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
        claim, _ = build_eval_claim(
            suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
            comparator=">=", threshold="0.98", score="0.994", n=500,
            model_id="acme/secret-model-7b", dataset_id="acme/internal-redteam-set",
            issuer=issuer_fingerprint(_SIGNER), timestamp="2026-07-05T12:00:00Z",
            model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
        for alg, path in ((I.CONTENT_ROOT_ALG, _G2_JCS), (I.LEGACY_CONTENT_ROOT_ALG, _G2_LEGACY)):
            env = I.export_eval_result_dsse(claim, _SIGNER, root_b64=ROOT, content_root_alg=alg,
                                            harness={"name": "inspect_ai", "version": "0.3.244"})
            self.assertEqual(json.dumps(env, indent=2) + "\n", path.read_text(encoding="utf-8"), alg)

    def test_a_v01_statement_is_not_read_under_the_v02_contract(self):
        for env in self._released():
            res = I.verify_eval_result_dsse(env, _pub(), expected_predicate_type=None)
            self.assertIs(res["ok"], True)
            self.assertIn("predicate_shape_ok", res)
            self.assertIsNone(res["predicate_shape_ok"], "no v0.2 shape contract applies to a v0.1 type")

    def test_a_v01_statement_relabelled_v02_is_refused(self):
        for env in self._released():
            statement = json.loads(base64.b64decode(env["payload"]))
            statement["predicateType"] = V02
            statement.pop("contentRootAlg", None)
            res = _verify_v02(statement)
            self.assertIs(res["ok"], False)
            self.assertIn("evaluator", res["predicate_shape_detail"])

    def test_the_default_call_still_expects_v01(self):
        res = I.verify_eval_result_dsse(_sign(_base_statement()), _pub())
        self.assertIs(res["ok"], False)
        self.assertIs(res["predicate_type_ok"], False)
        self.assertEqual(res["predicate_type"], V02)


def _statement_v02(claim=CLAIM, **kw) -> dict:
    kw.setdefault("evaluator_id", EVALUATOR)
    profile = kw.get("subject_profile", "receipt")
    if profile == "receipt":
        subject = I.resolve_subject("receipt", claim, root_b64=ROOT)
    else:
        subject = I.resolve_subject(profile, claim, subject_name="acme/open-model-7b", subject_sha256="e4" * 32)
    return I.to_eval_result_v02_statement(claim, subject=subject, **kw)


_MODEL_RD = {"name": "acme/open-model-7b", "digest": {"sha256": "e4" * 32},
             "uri": "https://example.com/acme/open-model-7b"}
_DATASET_RD = {"name": "acme/open-set", "digest": {"sha256": "f5" * 32}}


class TheV02EmitterWritesTheRevisedShape(unittest.TestCase):
    def test_the_revised_fields_and_none_of_the_old(self):
        receipt = b'{"payload_b64": "e30="}\n'
        pred = _statement_v02(evidence=[I.receipt_evidence(receipt)])["predicate"]
        self.assertEqual(pred["evaluator"], {"id": EVALUATOR})
        for old in ("verifier", "receipt", "anchors"):
            self.assertNotIn(old, pred)
        self.assertEqual(set(pred["commitments"]), {"model", "dataset"})
        self.assertTrue(pred["commitments"]["model"]["salted"])
        self.assertNotIn("model", pred)
        self.assertNotIn("dataset", pred)
        self.assertEqual(pred["evidence"][0]["digest"], {"sha256": hashlib.sha256(receipt).hexdigest()})
        self.assertEqual(pred["suite"], {"name": "safety-refusals", "version": "1.2.0"})
        self.assertIn("subjectDigestNote", pred)

    def test_the_statement_carries_the_v02_type(self):
        st = _statement_v02()
        self.assertEqual(st["predicateType"], V02)
        self.assertEqual(I.classify_eval_result_v02_predicate(st), (True, ""))

    def test_the_evaluator_has_no_default(self):
        for bad in (None, "", "example.com/evaluator", 7, "https://ex ample.com"):
            with self.subTest(evaluator=bad):
                with self.assertRaises(BundleFormatError):
                    _statement_v02(evaluator_id=bad)

    def test_a_public_model_is_identified_once_by_its_descriptor(self):
        pred = _statement_v02(model=_MODEL_RD, subject_profile="public-model")["predicate"]
        self.assertEqual(pred["model"], _MODEL_RD)
        self.assertEqual(set(pred["commitments"]), {"dataset"})
        self.assertNotIn("subjectDigestNote", pred)

    def test_public_model_and_dataset_leave_no_commitments(self):
        pred = _statement_v02(model=_MODEL_RD, dataset=_DATASET_RD)["predicate"]
        self.assertNotIn("commitments", pred)
        self.assertEqual(pred["dataset"], _DATASET_RD)

    def test_the_emitter_refuses_what_its_verifier_refuses(self):
        cases = {
            "model descriptor without digest": {"model": {"name": "m", "uri": "https://example.com/m"}},
            "dataset descriptor with a placeholder digest": {"dataset": {"digest": {"sha256": "…"}}},
            "evidence entry without digest": {"evidence": [{"uri": "https://example.com/log"}]},
            "evidence not a list": {"evidence": {"digest": {"sha256": "d3" * 32}}},
            "harness without version": {"harness": {"name": "inspect_ai"}},
        }
        for case, kw in cases.items():
            with self.subTest(case=case):
                with self.assertRaises(BundleFormatError):
                    _statement_v02(**kw)

    def test_a_claim_without_a_suite_version_is_refused(self):
        claim = {k: v for k, v in CLAIM.items() if k != "suite_version"}
        with self.assertRaises(BundleFormatError):
            _statement_v02(claim)

    def test_the_receipt_evidence_names_the_bytes(self):
        receipt = b'{"a": 1}\r\n'
        rd = I.receipt_evidence(receipt, uri="https://example.com/r.json")
        self.assertEqual(rd, {"name": "eval-receipt", "digest": {"sha256": hashlib.sha256(receipt).hexdigest()},
                              "mediaType": "application/json", "uri": "https://example.com/r.json"})
        self.assertEqual(set(I.receipt_evidence(receipt)), {"name", "digest", "mediaType"})
        with self.assertRaises(BundleFormatError):
            I.receipt_evidence("not bytes")

    def test_the_receipt_evidence_digest_covers_the_signature_and_is_no_merkle_root(self):
        # Revision 2 of the draft: for a signed receipt the artifact includes the signature when it is part of the
        # supplied receipt, and an internal Merkle root is not a substitute. A proofbundle receipt file
        # carries its signature and its Merkle root inside the same JSON object, so the digest over the
        # file's bytes covers both, and the root appears nowhere in the entry.
        from proofbundle.bundle import recompute_merkle_root_b64
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
        claim, _ = build_eval_claim(
            suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
            comparator=">=", threshold="0.98", score="0.994", n=500,
            model_id="acme/secret-model-7b", dataset_id="acme/internal-redteam-set",
            issuer=issuer_fingerprint(_SIGNER), timestamp="2026-07-05T12:00:00Z",
            model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
        bundle = emit_eval_receipt(claim, _SIGNER)
        self.assertIn("signature", bundle)
        raw = (json.dumps(bundle, indent=2) + "\n").encode("utf-8")
        entry = I.receipt_evidence(raw)
        self.assertEqual(entry["digest"], {"sha256": hashlib.sha256(raw).hexdigest()})
        other_sig = json.loads(raw)
        other_sig["signature"] = dict(other_sig["signature"], **{k: "AAAA" for k in other_sig["signature"]
                                                                if isinstance(other_sig["signature"][k], str)})
        raw2 = (json.dumps(other_sig, indent=2) + "\n").encode("utf-8")
        self.assertNotEqual(I.receipt_evidence(raw2)["digest"], entry["digest"],
                            "the signature is part of the artifact the digest names")
        root = recompute_merkle_root_b64(bundle)["stated_b64"]
        root_hex = base64.b64decode(root).hex()
        flat = json.dumps(entry)
        self.assertNotIn(root, flat)
        self.assertNotIn(root_hex, flat)

    def test_no_secret_and_no_plaintext(self):
        with self.assertRaises(BundleFormatError):
            _statement_v02({**CLAIM, "model_id": "acme/secret-model-7b"})
        body = json.dumps(_statement_v02())
        self.assertNotIn("acme/secret", body)

    def test_roundtrip_through_dsse(self):
        env = I.export_eval_result_v02_dsse(CLAIM, _SIGNER, evaluator_id=EVALUATOR, root_b64=ROOT,
                                            evidence=[I.receipt_evidence(b"{}\n")])
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")
        res = I.verify_eval_result_dsse(env, _pub(), expected_predicate_type=I.EVAL_RESULT_V02_PREDICATE_TYPE)
        self.assertIs(res["ok"], True, res)
        self.assertIs(res["predicate_shape_ok"], True)
        tampered = dict(env)
        statement = json.loads(base64.b64decode(env["payload"]))
        statement["predicate"]["claims"][0]["passed"] = False
        tampered["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
        self.assertIs(I.verify_eval_result_dsse(
            tampered, _pub(), expected_predicate_type=I.EVAL_RESULT_V02_PREDICATE_TYPE)["ok"], False)

    def test_every_profile_and_identification_the_emitter_writes_verifies(self):
        for profile in I.SUBJECT_PROFILES:
            for model, dataset in ((None, None), (_MODEL_RD, None), (None, _DATASET_RD), (_MODEL_RD, _DATASET_RD)):
                with self.subTest(profile=profile, model=bool(model), dataset=bool(dataset)):
                    st = _statement_v02(subject_profile=profile, model=model, dataset=dataset)
                    self.assertEqual(I.classify_eval_result_v02_predicate(st), (True, ""))


def _identity_case(identity: str, case: str):
    """The exactly-once table of revision 2 for one identity. Returns (statement, expected ok)."""
    statement = _base_statement()
    pred = statement["predicate"]
    digest = {"model": "e4" * 32, "dataset": "f5" * 32}[identity]
    descriptor = {"name": f"public-{identity}", "digest": {"sha256": digest}}
    commitment = pred["commitments"].pop(identity)
    if case == "neither":
        return statement, False
    if case == "commitment only":
        pred["commitments"][identity] = commitment
        return statement, True
    if case == "descriptor only":
        pred[identity] = descriptor
        return statement, True
    if case == "both":
        pred["commitments"][identity] = commitment
        pred[identity] = descriptor
        return statement, False
    if case == "descriptor without digest":
        pred[identity] = {"name": f"public-{identity}", "uri": f"https://example.com/{identity}"}
        return statement, False
    if case == "descriptor without digest beside a commitment":
        pred["commitments"][identity] = commitment
        pred[identity] = {"name": f"public-{identity}", "uri": f"https://example.com/{identity}"}
        return statement, False
    if case == "also the Statement subject, identified once in the predicate":
        statement["subject"] = [dict(descriptor)]
        pred[identity] = descriptor
        return statement, True
    if case == "only the Statement subject, not in the predicate":
        statement["subject"] = [dict(descriptor)]
        return statement, False
    if case == "only an evidence reference, not in the predicate":
        pred["evidence"] = [dict(descriptor)]
        return statement, False
    if case == "commitment and an evidence reference to the same artifact":
        pred["commitments"][identity] = commitment
        pred["evidence"] = [dict(descriptor)]
        return statement, True
    raise AssertionError(case)


IDENTITY_CASES = ("neither", "commitment only", "descriptor only", "both", "descriptor without digest",
                  "descriptor without digest beside a commitment",
                  "also the Statement subject, identified once in the predicate",
                  "only the Statement subject, not in the predicate",
                  "only an evidence reference, not in the predicate",
                  "commitment and an evidence reference to the same artifact")


class TheExactlyOnceRuleForEachIdentity(unittest.TestCase):
    """Revision 2 of the draft, the conformance check: both locations are inspected, both or neither is refused, a
    present representation must satisfy its own field rules, and subject and evidence never count.
    One generated test per identity and case, so each row of the table has its own red and green."""


def _make_identity_test(identity: str, case: str):
    def test(self):
        statement, expected = _identity_case(identity, case)
        res = _verify_v02(statement)
        self.assertIs(res["content_root_ok"], True)
        self.assertIs(res["ok"], expected, res.get("predicate_shape_detail"))
        if not expected:
            self.assertIn(identity, res["predicate_shape_detail"])
    return test


for _identity in ("model", "dataset"):
    for _i, _case in enumerate(IDENTITY_CASES):
        setattr(TheExactlyOnceRuleForEachIdentity, f"test_{_identity}_{_i:02d}_" + "_".join(
            _case.replace(",", "").split()), _make_identity_test(_identity, _case))


class TheReleasedV01Statements(unittest.TestCase):
    """G2 with regression evidence: v0.1 envelopes as released versions emitted them, each with its
    origin, verified under the old rules. The expected verdicts are the released 6.1.0 verifier's, not
    this head's, so a change of the old contract shows as a difference here."""

    ORIGIN_WORDING = {"release-artifact": "fixture from release ",
                      "tag-reconstruction": "own reconstruction from the source at tag "}

    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(_G2_CORPUS.read_text(encoding="utf-8"))
        cls.own = base64.b64decode(cls.corpus["public_key_b64"])
        cls.other = base64.b64decode(cls.corpus["other_public_key_b64"])
        cls.keys = cls.corpus["verdict_keys"]

    def _verdict(self, envelope, key):
        res = I.verify_eval_result_dsse(envelope, key)
        return res, {k: res[k] for k in self.keys}

    def test_every_statement_names_an_origin_that_matches_its_kind(self):
        kinds = set()
        for entry in self.corpus["entries"]:
            with self.subTest(entry=entry["id"]):
                wording = self.ORIGIN_WORDING[entry["origin_kind"]]
                self.assertTrue(entry["origin"].startswith(wording), entry["origin"])
                self.assertTrue(entry["id"].startswith(
                    {"release-artifact": "release-", "tag-reconstruction": "reconstruction-"}[entry["origin_kind"]]))
                statement = json.loads(base64.b64decode(entry["envelope"]["payload"]))
                self.assertEqual(statement["predicateType"], V01)
                kinds.add(entry["origin_kind"])
        self.assertEqual(kinds, set(self.ORIGIN_WORDING))
        self.assertGreaterEqual(len(self.corpus["entries"]), 14)

    def test_each_statement_gets_the_released_verifiers_verdict(self):
        for entry in self.corpus["entries"]:
            with self.subTest(entry=entry["id"]):
                res, verdict = self._verdict(entry["envelope"], self.own)
                self.assertEqual(verdict, entry["release_6_1_0_verdict"])
                self.assertIs(res["ok"], True)
                self.assertIs(entry["own_verdict"]["ok"], True, "the emitting version accepted its own statement")
                self.assertIsNone(res["predicate_shape_ok"], "a v0.1 statement is judged under the v0.1 rules")
                self.assertEqual(res["statement"], json.loads(base64.b64decode(entry["envelope"]["payload"])))

    def test_each_statement_under_another_key_gets_the_released_verdict(self):
        for entry in self.corpus["entries"]:
            with self.subTest(entry=entry["id"]):
                _, verdict = self._verdict(entry["envelope"], self.other)
                self.assertEqual(verdict, entry["release_6_1_0_verdict_other_key"])
                self.assertIs(verdict["ok"], False)

    def test_the_negative_variants_get_the_released_verdict(self):
        seen = 0
        for entry in self.corpus["entries"]:
            for negative in entry["negatives"]:
                with self.subTest(entry=entry["id"], case=negative["case"]):
                    _, verdict = self._verdict(negative["envelope"], self.own)
                    self.assertEqual(verdict, negative["release_6_1_0_verdict"])
                    self.assertIs(verdict["ok"], False)
                    seen += 1
        self.assertEqual(seen, 6)

    def test_the_v01_emitter_writes_the_release_fixtures_byte_for_byte(self):
        from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
        claim, _ = build_eval_claim(
            suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
            comparator=">=", threshold="0.98", score="0.994", n=500,
            model_id="acme/secret-model-7b", dataset_id="acme/internal-redteam-set",
            issuer=issuer_fingerprint(_SIGNER), timestamp="2026-07-05T12:00:00Z",
            model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
        receipt = {"subject_profile": "receipt", "root_b64": ROOT,
                   "harness": {"name": "inspect_ai", "version": "0.3.244"}}
        calls = {
            "receipt, jcs-sha256-v1": (claim, dict(receipt, content_root_alg=I.CONTENT_ROOT_ALG)),
            "receipt, legacy-sortkeys-json-v0": (claim, dict(receipt, content_root_alg=I.LEGACY_CONTENT_ROOT_ALG)),
            "public-model": (claim, {"subject_profile": "public-model", "subject_name": "acme/open-model-7b",
                                     "subject_sha256": "a" * 64, "root_b64": ROOT}),
            "release-gate": (claim, {"subject_profile": "release-gate",
                                     "subject_name": "acme/inference-service:1.4.2",
                                     "subject_sha256": "b" * 64, "root_b64": ROOT}),
            "receipt with preRegistration and anchors": (
                dict(claim, prereg_sha256="e5" * 32),
                dict(receipt, anchors=[{"kind": "example-anchor", "digest": {"sha256": "cc" * 32}}])),
        }
        released = {e["variant"]: e["envelope"] for e in self.corpus["entries"]
                    if e["origin_kind"] == "release-artifact"}
        self.assertEqual(set(released), set(calls))
        for variant, (c, kw) in calls.items():
            with self.subTest(variant=variant):
                self.assertEqual(I.export_eval_result_dsse(c, _SIGNER, **kw), released[variant])

    def test_dispatch_the_same_predicate_under_v02_gets_the_revised_rules(self):
        for entry in self.corpus["entries"]:
            with self.subTest(entry=entry["id"]):
                statement = json.loads(base64.b64decode(entry["envelope"]["payload"]))
                statement["predicateType"] = V02
                statement.pop("contentRootAlg", None)
                res = I.verify_eval_result_dsse(_sign(statement), _pub(), expected_predicate_type=None)
                self.assertIs(res["ok"], False)
                self.assertIs(res["predicate_shape_ok"], False)
                self.assertIn("evaluator", res["predicate_shape_detail"])

    def test_dispatch_a_revised_predicate_under_v01_gets_the_old_rules(self):
        # The v0.1 contract never checked the predicate's shape, and it still does not: dispatch is by
        # the declared type, not by what the predicate looks like.
        statement = _base_statement()
        statement["predicateType"] = V01
        res = I.verify_eval_result_dsse(_sign(statement), _pub())
        self.assertIs(res["ok"], True)
        self.assertIsNone(res["predicate_shape_ok"])
        del statement["predicate"]["evaluator"]
        res = I.verify_eval_result_dsse(_sign(statement), _pub())
        self.assertIs(res["ok"], True, "no v0.2 rule reaches a v0.1 statement")


class TheV02PathHoldsTheRulesOfV01(unittest.TestCase):
    """Measured after the merge of main c335c6ee into this branch (8e655e28): three rules every v0.1 path of main holds
    did not reach the v0.2 path. Each case below fails at 8e655e28 and passes after it; each has its v0.1 control."""

    def test_no_v02_envelope_over_a_receipt_a_low_order_key_signed(self):
        claim = dict(CLAIM, issuer="ed25519:" + base64.b64encode(b"\x01" + b"\x00" * 31).decode())
        with self.assertRaises(BundleFormatError) as ctx:
            I.export_eval_result_v02_dsse(claim, _SIGNER, evaluator_id=EVALUATOR, root_b64=ROOT)
        self.assertIn("low-order", str(ctx.exception))
        with self.assertRaises(BundleFormatError):   # control: the v0.1 exporter refuses the same claim
            I.export_eval_result_dsse(claim, _SIGNER, root_b64=ROOT)

    def test_a_value_the_serializer_cannot_write_is_the_exporters_refusal(self):
        for wert in (float("nan"), float("inf"), 2 ** 64):
            with self.subTest(value=repr(wert)):
                with self.assertRaises(BundleFormatError):
                    I.export_eval_result_v02_dsse(CLAIM, _SIGNER, evaluator_id=EVALUATOR, root_b64=ROOT,
                                                  harness={"name": "h", "version": "1", "x": wert})

    def test_the_claim_rule_judges_a_signed_v02_statement(self):
        """The v0.2 shape asks a commitment for lower-case hex and a non-empty alg; the claim rule of main asks for
        64 hex characters under sha256-salted-v1, as for v0.1, so a commitment under another algorithm is refused."""
        cases = {
            "model commitment of two hex characters": lambda p: p["commitments"]["model"].__setitem__("value", "ab"),
            "dataset commitment under another algorithm":
                lambda p: p["commitments"]["dataset"].__setitem__("alg", "md5-plain"),
        }
        for case, change in cases.items():
            with self.subTest(case=case):
                statement = _base_statement()
                change(statement["predicate"])
                res = _verify_v02(statement)
                self.assertIs(res["predicate_shape_ok"], True, "the shape alone accepts it")
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIs(res["ok"], False)
        res = _verify_v02(_base_statement())
        self.assertIs(res["predicate_claim_ok"], True, "control: the draft's example passes the claim rule")
        self.assertIs(res["ok"], True)

    def test_the_ownership_rule_reaches_every_place_v02_adds_for_a_descriptor(self):
        """Codex thread 4218003341: the claim rule walked the predicate's scalar fields and the subject, so a model
        descriptor of ours at the top level, annotated with `passed` "false", verified ok=True although the same
        descriptor in the subject is refused. The dataset, an evidence entry and the harness are the siblings."""
        ours = {"digest": {I.MODEL_COMMIT_DIGEST_KEY: "aa" * 32}, "annotations": {"passed": "false"}}
        ours_ds = {"digest": {I.DATASET_COMMIT_DIGEST_KEY: "aa" * 32}, "annotations": {"passed": "false"}}

        def model(p):
            del p["commitments"]["model"]
            p["model"] = copy.deepcopy(ours)

        def dataset(p):
            del p["commitments"]["dataset"]
            p["dataset"] = copy.deepcopy(ours_ds)
        cases = {
            "model": model,
            "dataset": dataset,
            "an evidence entry": lambda p: p["evidence"].append(copy.deepcopy(ours)),
            "the harness": lambda p: p.__setitem__("harness", dict(copy.deepcopy(ours), name="h", version="1")),
        }
        for case, change in cases.items():
            with self.subTest(case=case):
                statement = _base_statement()
                change(statement["predicate"])
                res = _verify_v02(statement)
                self.assertIs(res["predicate_shape_ok"], True, "the shape alone accepts it")
                self.assertIs(res["predicate_claim_ok"], False, res["content_root_detail"])
                self.assertIs(res["ok"], False)
            with self.subTest(case=case, control="a boolean passed"):
                statement = _base_statement()
                change(statement["predicate"])
                for wo in ("model", "dataset", "harness"):
                    if wo in statement["predicate"]:
                        statement["predicate"][wo]["annotations"]["passed"] = False
                for eintrag in statement["predicate"].get("evidence", []):
                    if "annotations" in eintrag:
                        eintrag["annotations"]["passed"] = False
                self.assertIs(_verify_v02(statement)["ok"], True)
        with self.subTest(case="the same descriptor in the subject, the rule this extends"):
            statement = _base_statement()
            statement["subject"].append(dict(copy.deepcopy(ours), name="m"))
            self.assertIs(_verify_v02(statement)["predicate_claim_ok"], False)

    def test_a_v01_statement_does_not_read_the_places_v02_adds(self):
        """G2, the other direction: v0.1 defines no top-level model, dataset or evidence, so such a field is unknown
        there and stays unread, as the released verifier leaves it; its harness keeps the v0.1 walk too."""
        ours = {"digest": {I.MODEL_COMMIT_DIGEST_KEY: "aa" * 32}, "annotations": {"passed": "false"}}
        env = json.loads(_G2_LEGACY.read_text(encoding="utf-8"))
        statement = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(statement["predicateType"], V01)
        for wo in ("model", "dataset", "evidence"):
            with self.subTest(field=wo):
                kopie = copy.deepcopy(statement)
                kopie["predicate"][wo] = [copy.deepcopy(ours)] if wo == "evidence" else copy.deepcopy(ours)
                res = I.verify_eval_result_dsse(_sign(kopie), _pub())
                self.assertEqual(res["predicate_type"], V01)
                self.assertIs(res["predicate_claim_ok"], True, res["content_root_detail"])
                self.assertIs(res["ok"], True)


class TheCommandLine(unittest.TestCase):
    def setUp(self) -> None:
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        claim, _ = build_eval_claim(
            suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
            comparator=">=", threshold="0.98", score="0.994", n=500,
            model_id="acme/secret-model-7b", dataset_id="acme/internal-redteam-set",
            issuer=issuer_fingerprint(_SIGNER), timestamp="2026-07-05T12:00:00Z",
            model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
        self.receipt = self.dir / "receipt.json"
        self.receipt.write_text(json.dumps(emit_eval_receipt(claim, _SIGNER), indent=2) + "\n", encoding="utf-8")
        self.key = self.dir / "key.bin"
        self.key.write_bytes(bytes(range(32)))
        self.pub = base64.b64encode(_pub()).decode()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *argv) -> tuple[int, str]:
        from proofbundle.cli import main
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def _emit(self, *extra) -> tuple[int, str, Path]:
        out = self.dir / "att.json"
        code, text = self._run("intoto", str(self.receipt), "--out", str(out), "--key", str(self.key), *extra)
        return code, text, out

    def test_v02_is_written_on_request_and_verifies(self):
        code, text, out = self._emit("--predicate-version", "v0.2", "--evaluator", EVALUATOR)
        self.assertEqual(code, 0, text)
        env = json.loads(out.read_text(encoding="utf-8"))
        statement = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(statement["predicateType"], V02)
        self.assertEqual(statement["predicate"]["evaluator"], {"id": EVALUATOR})
        entry = statement["predicate"]["evidence"][0]
        self.assertEqual(entry, {"name": "eval-receipt", "mediaType": "application/json",
                                 "digest": {"sha256": hashlib.sha256(self.receipt.read_bytes()).hexdigest()}},
                         "the digest of the receipt file's bytes, and no Merkle root beside it")
        code, text = self._run("intoto", str(out), "--verify", "--pub", self.pub)
        self.assertEqual(code, 0, text)
        self.assertIn(V02, text)

    def test_the_default_stays_v01(self):
        code, text, out = self._emit()
        self.assertEqual(code, 0, text)
        statement = json.loads(base64.b64decode(json.loads(out.read_text(encoding="utf-8"))["payload"]))
        self.assertEqual(statement["predicateType"], V01)
        code, text = self._run("intoto", str(out), "--verify", "--pub", self.pub)
        self.assertEqual(code, 0, text)

    def test_v02_without_an_evaluator_is_refused(self):
        code, text, out = self._emit("--predicate-version", "v0.2")
        self.assertEqual(code, 2, text)
        self.assertFalse(out.exists())

    def test_v02_only_flags_are_refused_under_v01(self):
        for extra in (("--evaluator", EVALUATOR), ("--receipt-uri", "https://example.com/r.json")):
            with self.subTest(flag=extra[0]):
                code, text, out = self._emit(*extra)
                self.assertEqual(code, 2, text)

    def test_a_public_model_is_written_as_a_descriptor(self):
        code, text, out = self._emit("--predicate-version", "v0.2", "--evaluator", EVALUATOR,
                                     "--subject-profile", "public-model", "--subject-name", "acme/open-model-7b",
                                     "--subject-sha256", "e4" * 32, "--receipt-uri", "https://example.com/r.json")
        self.assertEqual(code, 0, text)
        pred = json.loads(base64.b64decode(json.loads(out.read_text(encoding="utf-8"))["payload"]))["predicate"]
        self.assertEqual(pred["model"], {"name": "acme/open-model-7b", "digest": {"sha256": "e4" * 32}})
        self.assertEqual(set(pred["commitments"]), {"dataset"})
        self.assertEqual(pred["evidence"][0]["uri"], "https://example.com/r.json")

    def test_verify_refuses_a_signed_v02_statement_with_a_bad_shape(self):
        bad = _mutated(_drop("evaluator"))
        path = self.dir / "bad.json"
        path.write_text(json.dumps(_sign(bad)), encoding="utf-8")
        code, text = self._run("intoto", str(path), "--verify", "--pub", self.pub)
        self.assertEqual(code, 1, text)
        self.assertIn("evaluator", text)

    def test_verify_accepts_the_released_v01_envelopes(self):
        for path in (_G2_JCS, _G2_LEGACY):
            code, text = self._run("intoto", str(path), "--verify", "--pub", self.pub)
            self.assertEqual(code, 0, text)

    def test_verify_refuses_another_predicate_type(self):
        other = copy.deepcopy(_base_statement())
        other["predicateType"] = "https://in-toto.io/attestation/svr/v0.1"
        path = self.dir / "other.json"
        path.write_text(json.dumps(_sign(other)), encoding="utf-8")
        code, text = self._run("intoto", str(path), "--verify", "--pub", self.pub)
        self.assertEqual(code, 1, text)


if __name__ == "__main__":
    unittest.main()
