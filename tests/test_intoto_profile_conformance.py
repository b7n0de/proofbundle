"""in-toto Statement v1 profile conformance on the DSSE VERIFY path (L5-03) and the contentRootAlg
allowlist (L2-03).

WHAT WAS BROKEN (both live in shipped 3.7.0).

L5-03 — the three ``verify_*_dsse`` surfaces checked the signature, the payloadType, the content-root
binding and the predicateType, but never whether the signed payload was a CONFORMANT in-toto Statement.
A payload with no ``subject`` at all (absent / null / empty array / a descriptor with no digest) or with a
missing or wrong ``_type`` returned ``ok=True``. The documented release-gate profile ("deploy only if the
eval passed") keys on the exit code of ``proofbundle intoto --verify`` / ``proofbundle svr --verify``, so an
attestation that binds to NO artifact printed ``[PASS] ... => OK`` and exited 0.

L2-03 — ``_declared_content_root_alg`` decided on the declaration's TYPE, not on whether the algorithm is
KNOWN. The string ``"sha256-v0-attacker"`` was correctly rejected, but a present-but-unrecognised NON-STRING
(``0``, ``[]``, ``{}``, ``true``, ``""``, ``null``, ``["jcs-sha256-v1"]``) fell through the ``isinstance``
test and was silently read as LEGACY — an algorithm-confusion hole one JSON type away from the guarded one.

WHY THE FIX IS A CLASS FIX. Both defences live in the ONE place all three verify surfaces already funnel
through (``_intoto_verify_result`` / ``_content_root_binding``), not in three edited call sites. The scope of
this test is DISCOVERED from the module (``SURFACES`` is asserted equal to every ``verify_*_dsse`` attribute
of ``proofbundle.intoto``), so a fourth verify surface added later fails this file instead of being silently
unchecked.

Each negative case is built so that the signature, the payloadType, the content-root binding and the
predicateType all still PASS — the only thing that can produce the rejection is the defence being named.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import canonical, dsse, generate_signer, intoto
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.intoto import (
    CONTENT_ROOT_ALG,
    EVAL_RESULT_PREDICATE_TYPE,
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    LEGACY_CONTENT_ROOT_ALG,
    STATEMENT_TYPE,
    SVR_PREDICATE_TYPE,
    TEST_RESULT_PAYLOAD_TYPE,
    TEST_RESULT_PREDICATE_TYPE,
    export_eval_result_dsse,
    export_intoto_dsse,
    export_svr_dsse,
    verify_eval_result_dsse,
    verify_intoto_dsse,
    verify_svr_dsse,
)

try:
    import jsonschema
except ImportError:                                     # pragma: no cover - optional test-only extra
    jsonschema = None

TS = "2026-07-05T12:00:00Z"
CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True, "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32, "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1", "issuer": "ed25519:AAAA", "timestamp": TS,
    "assurance_level": "self_attested",
}

# The verify surfaces, each with the payloadType it pins and the predicateType it expects. The set of KEYS is
# asserted against what the module actually exposes (test_surface_scope_is_discovered_not_enumerated), so this
# mapping cannot silently fall behind the code.
SURFACES = {
    "verify_intoto_dsse": (verify_intoto_dsse, TEST_RESULT_PAYLOAD_TYPE, TEST_RESULT_PREDICATE_TYPE),
    "verify_eval_result_dsse": (verify_eval_result_dsse, INTOTO_STATEMENT_PAYLOAD_TYPE,
                                EVAL_RESULT_PREDICATE_TYPE),
    "verify_svr_dsse": (verify_svr_dsse, INTOTO_STATEMENT_PAYLOAD_TYPE, SVR_PREDICATE_TYPE),
}


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _legacy_json(obj) -> bytes:
    """The released 2.0.0 serializer, spelled out with stdlib json (independent of the module helper)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_legacy(statement, signer, payload_type):
    """Sign a hand-built Statement as LEGACY bytes: no contentRootAlg field, json.dumps(sort_keys) body.

    That makes the signature valid AND the content-root binding valid, so a rejection can only come from the
    conformance check under test — never from an earlier guard on a different axis.
    """
    return dsse.sign_envelope(_legacy_json(statement), signer, payload_type=payload_type)


def _sign_jcs(statement, signer, payload_type):
    """The same, in the DEFAULT `jcs-sha256-v1` mode: the hole was open in both serialization modes, because
    `_serialize_statement` calls `canonicalize_statement` WITHOUT `require_statement_shape`."""
    declared = {**statement, "contentRootAlg": CONTENT_ROOT_ALG}
    return dsse.sign_envelope(canonical.canonicalize_statement(declared), signer, payload_type=payload_type)


def _conformant(predicate_type):
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "artifact", "digest": {"sha256": "a" * 64}}],
        "predicateType": predicate_type,
        "predicate": {},
    }


def _without(statement, key):
    return {k: v for k, v in statement.items() if k != key}


# Every mutation keeps signature + payloadType + content-root binding + predicateType intact. `ept=None`
# opts out of the predicateType check for the cases that attack predicateType itself, so that even there the
# ONLY possible source of the rejection is the conformance check.
#   name -> (mutate(statement) -> statement, expected_predicate_type_override_is_none)
NON_CONFORMANT = {
    "subject_absent": (lambda s: _without(s, "subject"), False),
    "subject_null": (lambda s: {**s, "subject": None}, False),
    "subject_empty_array": (lambda s: {**s, "subject": []}, False),
    "subject_not_an_array": (lambda s: {**s, "subject": {"name": "x", "digest": {"sha256": "a" * 64}}}, False),
    "subject_entry_not_an_object": (lambda s: {**s, "subject": ["artifact"]}, False),
    "subject_digest_absent": (lambda s: {**s, "subject": [{"name": "artifact"}]}, False),
    "subject_digest_empty": (lambda s: {**s, "subject": [{"name": "artifact", "digest": {}}]}, False),
    "subject_digest_not_an_object": (lambda s: {**s, "subject": [{"name": "a", "digest": "a" * 64}]}, False),
    "subject_digest_value_not_a_string": (
        lambda s: {**s, "subject": [{"name": "a", "digest": {"sha256": 1234}}]}, False),
    "subject_digest_value_empty": (
        lambda s: {**s, "subject": [{"name": "a", "digest": {"sha256": ""}}]}, False),
    "subject_name_not_a_string": (
        lambda s: {**s, "subject": [{"name": 7, "digest": {"sha256": "a" * 64}}]}, False),
    # multiplicity: a good FIRST entry must not license a digest-less SECOND one (a verifier over a SET
    # must not attribute the first match to the whole set).
    "subject_second_entry_digestless": (
        lambda s: {**s, "subject": [{"name": "a", "digest": {"sha256": "a" * 64}}, {"name": "b"}]}, False),
    "type_absent": (lambda s: _without(s, "_type"), False),
    "type_wrong": (lambda s: {**s, "_type": "https://in-toto.io/Statement/v0.1"}, False),
    "type_not_a_string": (lambda s: {**s, "_type": 1}, False),
    "predicate_not_an_object": (lambda s: {**s, "predicate": []}, False),
    "predicate_type_absent": (lambda s: _without(s, "predicateType"), True),
    "predicate_type_empty": (lambda s: {**s, "predicateType": ""}, True),
    "predicate_type_not_a_string": (lambda s: {**s, "predicateType": 42}, True),
}

# The ONE axis on which this verifier profile is deliberately STRICTER than the shipped JSON Schema: a
# subject must resolve to an artifact. The schema's `anyOf` admits a name-only / uri-only descriptor and its
# digest values carry no `minLength`, so an empty digest value passes it too — but in-toto matching happens
# on the DIGEST, and a release gate must not see ok=True for a statement that binds to nothing. The three
# corpus members where the two oracles therefore disagree are pinned here as an ENUMERATED, honest gap: a
# fourth divergence breaks test_profile_agrees_with_shipped_schema instead of slipping in unnoticed.
SCHEMA_VALID_BUT_PROFILE_REJECTED = (
    "subject_digest_absent", "subject_digest_value_empty", "subject_second_entry_digestless")

# Present-but-unrecognised contentRootAlg declarations (L2-03). None is JSON `null`; every one of these was
# silently read as LEGACY before the fix.
HOSTILE_ALGS = (0, [], {}, True, "", None, ["jcs-sha256-v1"], 1.5, "sha256-v0-attacker")


class TestSurfaceScope(unittest.TestCase):
    """The scope of this file is DISCOVERED from the module, never enumerated by hand."""

    def test_surface_scope_is_discovered_not_enumerated(self):
        discovered = {
            name for name in dir(intoto)
            if name.startswith("verify_") and name.endswith("_dsse") and callable(getattr(intoto, name))
        }
        self.assertEqual(discovered, set(SURFACES),
                         "a verify_*_dsse surface exists that this conformance sweep does not cover")


class TestStatementConformanceOnVerify(unittest.TestCase):
    """L5-03: a non-conformant in-toto Statement is never ok=True, on EVERY verify surface."""

    def setUp(self):
        self.signer = generate_signer()
        self.pub = _raw_pub(self.signer)

    def _verify(self, surface_name, statement, *, ept_none):
        fn, payload_type, predicate_type = SURFACES[surface_name]
        env = _sign_legacy(statement, self.signer, payload_type)
        kwargs = {"expected_predicate_type": None} if ept_none else {}
        return fn(env, self.pub, **kwargs)

    def test_conformant_statement_still_verifies_on_every_surface(self):
        """True-positive floor: the check must not reject what it is supposed to accept."""
        for name, (_fn, _pt, predicate_type) in SURFACES.items():
            with self.subTest(surface=name):
                res = self._verify(name, _conformant(predicate_type), ept_none=False)
                self.assertTrue(res["ok"], res)
                self.assertTrue(res["statement_ok"], res)
                self.assertEqual(res["statement_detail"], "")

    def test_non_conformant_statements_are_rejected_on_every_surface(self):
        for surface in SURFACES:
            predicate_type = SURFACES[surface][2]
            for case, (mutate, ept_none) in NON_CONFORMANT.items():
                with self.subTest(surface=surface, case=case):
                    res = self._verify(surface, mutate(_conformant(predicate_type)), ept_none=ept_none)
                    self.assertFalse(res["ok"], (case, res))
                    self.assertFalse(res["statement_ok"], (case, res))
                    self.assertNotEqual(res["statement_detail"], "", case)

    def test_rejection_comes_from_the_named_defence_not_from_an_earlier_guard(self):
        """Non-vacuity: for every case the OTHER three axes are green, so only conformance can reject."""
        for surface in SURFACES:
            predicate_type = SURFACES[surface][2]
            for case, (mutate, ept_none) in NON_CONFORMANT.items():
                with self.subTest(surface=surface, case=case):
                    res = self._verify(surface, mutate(_conformant(predicate_type)), ept_none=ept_none)
                    self.assertTrue(res["content_root_ok"], (case, res))       # binding green
                    self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG, case)
                    expected_type_ok = None if ept_none else True
                    self.assertIs(res["predicate_type_ok"], expected_type_ok, (case, res))

    def test_non_conformant_statements_are_rejected_in_jcs_mode_too(self):
        """Both content-root modes: `canonicalize_statement` is called without `require_statement_shape`,
        so the default jcs path was exactly as blind as the legacy one."""
        for case, (mutate, ept_none) in NON_CONFORMANT.items():
            with self.subTest(case=case):
                statement = mutate(_conformant(EVAL_RESULT_PREDICATE_TYPE))
                env = _sign_jcs(statement, self.signer, INTOTO_STATEMENT_PAYLOAD_TYPE)
                kwargs = {"expected_predicate_type": None} if ept_none else {}
                res = verify_eval_result_dsse(env, self.pub, **kwargs)
                self.assertFalse(res["ok"], (case, res))
                self.assertFalse(res["statement_ok"], (case, res))
                self.assertTrue(res["content_root_ok"], (case, res))     # binding green: only conformance rejects
                self.assertEqual(res["content_root_alg"], CONTENT_ROOT_ALG)

    def test_verdict_key_set_is_identical_happy_and_fail_closed(self):
        """Shape parity: a consumer must never infer the verdict from a key-set difference."""
        happy = self._verify("verify_svr_dsse", _conformant(SVR_PREDICATE_TYPE), ept_none=False)
        broken = self._verify("verify_svr_dsse",
                              _without(_conformant(SVR_PREDICATE_TYPE), "subject"), ept_none=False)
        garbage = verify_svr_dsse({"payload": "!!not-base64!!", "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
                                   "signatures": []}, self.pub)
        self.assertEqual(set(happy), set(broken))
        self.assertEqual(set(happy), set(garbage))
        for key in ("ok", "statement_ok"):
            for verdict in (happy, broken, garbage):
                self.assertIsInstance(verdict[key], bool, key)
        for verdict in (happy, broken, garbage):
            self.assertIsInstance(verdict["statement_detail"], str)

    def test_real_exports_are_conformant_in_both_content_root_modes(self):
        """Backward compatibility: everything the shipped exporters emit keeps verifying."""
        bundle = _receipt(self.signer)
        for alg in (CONTENT_ROOT_ALG, LEGACY_CONTENT_ROOT_ALG):
            with self.subTest(alg=alg):
                env = export_eval_result_dsse(CLAIM, self.signer, root_b64="cm9vdA==", content_root_alg=alg)
                res = verify_eval_result_dsse(env, self.pub)
                self.assertTrue(res["ok"] and res["statement_ok"], res)

                env = export_intoto_dsse(CLAIM, self.signer, root_b64="cm9vdA==", content_root_alg=alg)
                res = verify_intoto_dsse(env, self.pub)
                self.assertTrue(res["ok"] and res["statement_ok"], res)

                env = export_svr_dsse(bundle, self.signer, content_root_alg=alg)
                res = verify_svr_dsse(env, self.pub)
                self.assertTrue(res["ok"] and res["statement_ok"], res)

    def test_released_2_0_0_wire_shape_still_verifies(self):
        """A statement in the released 2.0.0 shape (no contentRootAlg, json.dumps root) is untouched."""
        res = self._verify("verify_eval_result_dsse", _conformant(EVAL_RESULT_PREDICATE_TYPE), ept_none=False)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)

    def test_cli_release_gate_exit_code_is_not_zero_for_a_subjectless_attestation(self):
        """The documented harm: a release gate keys on the exit code, not on the verdict dict."""
        from proofbundle.cli import main  # noqa: PLC0415

        env = _sign_legacy(_without(_conformant(EVAL_RESULT_PREDICATE_TYPE), "subject"),
                           self.signer, INTOTO_STATEMENT_PAYLOAD_TYPE)
        handle, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(env, fh)
            rc = main(["intoto", path, "--verify", "--pub", base64.b64encode(self.pub).decode()])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)


class TestStatementConformanceOracle(unittest.TestCase):
    """The conformance function itself: total, never raising, and in agreement with the shipped schema."""

    def test_problems_function_never_raises_on_hostile_input(self):
        for value in (None, 0, "", [], (), {"subject": 1}, {"_type": object()}, float("nan"),
                      {"subject": [{"digest": {"k": object()}}]}):
            with self.subTest(value=repr(value)[:40]):
                problems = intoto.statement_conformance_problems(value)
                self.assertIsInstance(problems, list)
                self.assertTrue(all(isinstance(p, str) for p in problems))

    def test_problem_messages_are_bounded(self):
        """Never-raise message hygiene: a huge/recursive value must not be interpolated unbounded."""
        recursive: dict = {"_type": STATEMENT_TYPE, "predicateType": "x"}
        recursive["subject"] = [recursive]
        problems = intoto.statement_conformance_problems(recursive)
        self.assertTrue(problems)
        for problem in problems:
            self.assertLess(len(problem), 2000, problem)
        huge = {"_type": "z" * 100000, "subject": [{"digest": {"sha256": "a" * 64}}], "predicateType": "x"}
        for problem in intoto.statement_conformance_problems(huge):
            self.assertLess(len(problem), 2000)

    def test_every_shipped_statement_artifact_is_conformant(self):
        """Backward compatibility, measured rather than asserted: every in-toto Statement artifact COMMITTED
        in this repo (the published examples and the cross-implementation conformance fixtures) must satisfy
        the profile, so the stricter verify path cannot reject bytes a legitimate producer already emitted.
        The corpus is GLOBBED, not listed — a new example is covered automatically."""
        from pathlib import Path  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        paths = sorted(root.glob("examples/intoto/*.json")) + \
            sorted(root.glob("examples/*.intoto.json")) + \
            sorted(root.glob("conformance/**/*eval_result*.json"))
        self.assertTrue(paths, "no shipped statement artifacts found — the glob has gone stale")
        for path in paths:
            with self.subTest(path=str(path.relative_to(root))):
                document = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(document, dict) and "payload" in document:
                    document = json.loads(base64.b64decode(document["payload"]))
                self.assertEqual(intoto.statement_conformance_problems(document), [])

    @unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install proofbundle[test])")
    def test_profile_agrees_with_shipped_schema(self):
        """Cross-oracle: the stdlib profile check and schemas/in_toto_statement_v1.schema.json agree,
        except on the ONE enumerated, documented strengthening."""
        from pathlib import Path  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        schema = json.loads(
            (root / "schemas" / "in_toto_statement_v1.schema.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)

        base = _conformant(EVAL_RESULT_PREDICATE_TYPE)
        self.assertEqual(intoto.statement_conformance_problems(base), [])
        self.assertTrue(validator.is_valid(base), "the conformant fixture must satisfy the shipped schema")

        divergences = []
        for case, (mutate, _ept) in NON_CONFORMANT.items():
            statement = mutate(_conformant(EVAL_RESULT_PREDICATE_TYPE))
            profile_rejects = bool(intoto.statement_conformance_problems(statement))
            schema_rejects = not validator.is_valid(statement)
            self.assertTrue(profile_rejects, f"{case}: the profile must reject every corpus member")
            if not schema_rejects:
                divergences.append(case)
        self.assertEqual(sorted(divergences), sorted(SCHEMA_VALID_BUT_PROFILE_REJECTED),
                         "the set of cases where the profile is stricter than the schema is pinned; "
                         "a new divergence must be documented, not silently added")


class TestContentRootAlgAllowlist(unittest.TestCase):
    """L2-03: contentRootAlg is decided by KNOWN-id allowlist, not by the declaration's Python type."""

    def setUp(self):
        self.signer = generate_signer()
        self.pub = _raw_pub(self.signer)

    def test_present_but_unrecognised_alg_is_rejected_on_every_surface(self):
        for surface, (fn, payload_type, predicate_type) in SURFACES.items():
            for alg in HOSTILE_ALGS:
                with self.subTest(surface=surface, alg=repr(alg)):
                    statement = {**_conformant(predicate_type), "contentRootAlg": alg}
                    res = fn(_sign_legacy(statement, self.signer, payload_type), self.pub)
                    self.assertFalse(res["ok"], (alg, res))
                    self.assertFalse(res["content_root_ok"], (alg, res))
                    self.assertIn("unknown contentRootAlg", res["content_root_detail"])

    def test_absent_means_legacy_and_still_verifies(self):
        statement = _conformant(EVAL_RESULT_PREDICATE_TYPE)
        self.assertNotIn("contentRootAlg", statement)
        res = verify_eval_result_dsse(
            _sign_legacy(statement, self.signer, INTOTO_STATEMENT_PAYLOAD_TYPE), self.pub)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)

    def test_both_known_ids_still_verify(self):
        legacy = {**_conformant(EVAL_RESULT_PREDICATE_TYPE), "contentRootAlg": LEGACY_CONTENT_ROOT_ALG}
        res = verify_eval_result_dsse(
            _sign_legacy(legacy, self.signer, INTOTO_STATEMENT_PAYLOAD_TYPE), self.pub)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], LEGACY_CONTENT_ROOT_ALG)

        jcs = {**_conformant(EVAL_RESULT_PREDICATE_TYPE), "contentRootAlg": CONTENT_ROOT_ALG}
        body = canonical.canonicalize_statement(jcs)
        env = dsse.sign_envelope(body, self.signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        res = verify_eval_result_dsse(env, self.pub)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["content_root_alg"], CONTENT_ROOT_ALG)

    def test_declared_alg_reader_unit(self):
        self.assertEqual(intoto._declared_content_root_alg({}), LEGACY_CONTENT_ROOT_ALG)
        self.assertEqual(intoto._declared_content_root_alg("not-a-dict"), LEGACY_CONTENT_ROOT_ALG)
        self.assertEqual(
            intoto._declared_content_root_alg({"contentRootAlg": LEGACY_CONTENT_ROOT_ALG}),
            LEGACY_CONTENT_ROOT_ALG)
        self.assertEqual(
            intoto._declared_content_root_alg({"contentRootAlg": CONTENT_ROOT_ALG}), CONTENT_ROOT_ALG)
        for alg in HOSTILE_ALGS:
            with self.subTest(alg=repr(alg)):
                with self.assertRaises(BundleFormatError):
                    intoto._declared_content_root_alg({"contentRootAlg": alg})


class TestAntiTautology(unittest.TestCase):
    """Blind each detector and show the planted violation walks straight back in.

    Both twins vary the SAME axis the rule decides on: the conformance verdict and the declared-algorithm
    verdict respectively. A guard that cannot be made to go green again is a guard that was never deciding.
    """

    def setUp(self):
        self.signer = generate_signer()
        self.pub = _raw_pub(self.signer)

    def test_gutting_the_conformance_detector_lets_the_subjectless_statement_pass(self):
        planted = _without(_conformant(EVAL_RESULT_PREDICATE_TYPE), "subject")
        env = _sign_legacy(planted, self.signer, INTOTO_STATEMENT_PAYLOAD_TYPE)
        self.assertFalse(verify_eval_result_dsse(env, self.pub)["ok"])   # caught while the detector is live

        original = intoto.statement_conformance_problems
        intoto.statement_conformance_problems = lambda statement: []     # blinded
        try:
            self.assertTrue(verify_eval_result_dsse(env, self.pub)["ok"],
                            "with the conformance detector blinded the violation must return, otherwise "
                            "this test was passing for some other reason")
        finally:
            intoto.statement_conformance_problems = original
        self.assertFalse(verify_eval_result_dsse(env, self.pub)["ok"])   # detector restored

    def test_restoring_the_type_based_alg_reader_lets_the_hostile_declaration_pass(self):
        def pre_fix_declared_content_root_alg(statement):
            """The shipped 3.7.0 implementation: decides on TYPE, not on membership."""
            if isinstance(statement, dict):
                alg = statement.get("contentRootAlg")
                if isinstance(alg, str) and alg:
                    return alg
            return LEGACY_CONTENT_ROOT_ALG

        planted = {**_conformant(EVAL_RESULT_PREDICATE_TYPE), "contentRootAlg": []}
        env = _sign_legacy(planted, self.signer, INTOTO_STATEMENT_PAYLOAD_TYPE)
        self.assertFalse(verify_eval_result_dsse(env, self.pub)["ok"])   # caught with the allowlist live

        original = intoto._declared_content_root_alg
        intoto._declared_content_root_alg = pre_fix_declared_content_root_alg
        try:
            self.assertTrue(verify_eval_result_dsse(env, self.pub)["ok"],
                            "with the type-based reader back the hostile declaration must be accepted "
                            "again, otherwise the allowlist is not what this test measures")
        finally:
            intoto._declared_content_root_alg = original
        self.assertFalse(verify_eval_result_dsse(env, self.pub)["ok"])   # allowlist restored


def _receipt(signer, *, score="0.99", threshold="0.98"):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=",
        threshold=threshold, score=score, n=500, model_id="acme/secret-model", dataset_id="acme/secret-set",
        issuer=issuer_fingerprint(signer), timestamp=TS, model_salt=b"\x11" * 16, dataset_salt=b"\x11" * 16)
    return emit_eval_receipt(claim, signer)


if __name__ == "__main__":
    unittest.main()
