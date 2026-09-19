"""The verify boundary types what it decodes, and a `-> dict` loader returns a dict.

Two audit findings of 2026-09-19, measured at head 79f66a2, share one shape: a promise made in a
signature or a docstring that nothing enforced, and a consumer downstream that COERCES instead of
checking — so a wrong type became a wrong VERDICT rather than an error.

A-16: `load_claim_text` is annotated `-> dict` and its docstring promises "never a raw traceback",
but valid JSON is also `[]`, `"x"` and `1`. `decode_eval_claim` then did `claim.get(...)` and raised
AttributeError out of a documented never-raise surface, on a bundle whose signature and Merkle root
were INTACT. Its sibling `classify_eval_claim` carried an `isinstance` guard; this one did not.

A-15: `passed`, `n` and `metric` were not typed at the verify boundary. 10 of 11 wrong-typed
hand-signed claims were accepted, and `intoto.to_test_result_statement` turns them into a verdict
via `_RESULT_ENUM[bool(claim["passed"])]` — where `bool("false")` is True, so a claim that says the
string "false" exported to in-toto as PASSED. `hf_evals.verify_eval_results_entry` coerces the same
field the same way, so a Hub entry whose published value sat on the passing side verified as
CONSISTENT with a signed failure; both consumers are measured below.

Every case below is a case that FAILED before its fix and passes after it; the control arm at the
top of each class is the proof that the harness can still say yes.
"""
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.bundle import load_bundle, verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import (
    EvalClaimError,
    build_eval_claim,
    decode_eval_claim,
    emit_eval_receipt,
    issuer_fingerprint,
    load_claim_text,
)
from proofbundle.hf_evals import receipt_token, verify_eval_results_entry
from proofbundle.intoto import to_test_result_statement

TS = "2026-09-19T12:00:00Z"

# Valid JSON that is not a JSON object. `{}` is deliberately ABSENT: it was already handled before
# the fix, so it is a SEPARATE case, not a catch-proof, and counting it as one would inflate the
# number of things this file actually proves.
NON_OBJECT_JSON = ([], ["a"], "x", "", 1, 0, 1.5, True, False, None)


def _valid_claim(signer):
    """A claim built by the blessed emitter — the control arm, so a rejection below means something."""
    claim, _salts = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=">=", threshold="0.80", score="0.92", n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp=TS,
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class TestADictLoaderReturnsADict(unittest.TestCase):
    """A-16 — the annotation is a promise to every caller, including the ones not written yet."""

    def test_control_a_real_receipt_still_decodes(self):
        signer = generate_signer()
        bundle = emit_eval_receipt(_valid_claim(signer), signer)
        self.assertIsInstance(decode_eval_claim(bundle), dict)

    def test_load_claim_text_refuses_json_that_is_not_an_object(self):
        for value in NON_OBJECT_JSON:
            with self.subTest(value=value):
                with self.assertRaises(EvalClaimError):
                    load_claim_text(json.dumps(value))

    def test_decode_returns_none_for_a_signed_bundle_whose_payload_is_not_an_object(self):
        # The bundle is CORRECTLY signed: verify_bundle says ok, and the failure is only in the
        # payload's shape. That is what made this reachable without forging anything.
        signer = Ed25519PrivateKey.generate()
        for value in NON_OBJECT_JSON:
            with self.subTest(value=value):
                bundle = emit_bundle(json.dumps(value).encode(), signer)
                self.assertTrue(verify_bundle(bundle).ok)
                self.assertIsNone(decode_eval_claim(bundle))

    def test_load_bundle_refuses_a_file_that_is_not_a_json_object(self):
        # 11 call sites read this loader's result as a dict; the annotation says they may.
        directory = pathlib.Path(tempfile.mkdtemp())
        for value in NON_OBJECT_JSON:
            with self.subTest(value=value):
                path = directory / "bundle.json"
                path.write_text(json.dumps(value))
                with self.assertRaises(BundleFormatError):
                    load_bundle(str(path))


class TestTheVerifyBoundaryTypesWhatItDecodes(unittest.TestCase):
    """A-15 — `passed`, `n` and `metric` are the three fields every consumer reads."""

    def _signed_with(self, field, value):
        signer = Ed25519PrivateKey.generate()
        claim = dict(_valid_claim(signer))
        claim[field] = value
        return emit_eval_receipt(claim, signer)

    def test_control_the_unmodified_claim_is_accepted(self):
        signer = generate_signer()
        decoded = decode_eval_claim(emit_eval_receipt(_valid_claim(signer), signer))
        self.assertIsInstance(decoded, dict)
        self.assertIsInstance(decoded["passed"], bool)

    def test_passed_must_be_a_bool(self):
        # "false" is the one that mattered: it is TRUTHY, so every `bool(claim["passed"])` downstream
        # read a signed failure as a pass.
        # A FLOAT IS NOT SEPARATE, and the first version of this comment said it was. It claimed
        # canonicalization forbids floats, so `passed: 1.0` "never reaches this boundary" -- which
        # is a statement about the BOUNDARY derived from measuring ONE of its callers. A review
        # lens took the technique this very file already uses for A-16, signing the payload with
        # `emit_bundle` instead of the emitter, and `canonicalize` is then never called at all.
        # The float arrives, correctly signed, and the old code accepted it. The cases now live in
        # `test_a_float_reaches_this_boundary_because_the_emitter_is_not_the_boundary` and count.
        for value in ("false", "true", "", 1, 0, [], {}, None):
            with self.subTest(value=value):
                self.assertIsNone(decode_eval_claim(self._signed_with("passed", value)))

    def test_n_must_be_an_int_and_a_bool_is_not_one(self):
        # This was checked ONLY inside `if samples is not None`, so a claim that omits the optional
        # samples block skipped it entirely. A presence-conditional check is an option.
        for value in ("x", "500", True, False, None, [500]):
            with self.subTest(value=value):
                self.assertIsNone(decode_eval_claim(self._signed_with("n", value)))

    def _handsigniert(self, field, value):
        """A correctly signed bundle whose payload never went through `canonicalize`.

        `emit_eval_receipt` canonicalizes and refuses floats, so a test that only uses the emitter
        measures the emitter. This is the same shape the A-16 cases above already use, and it is
        the honest way to ask what the VERIFY boundary does: a third party's bundle was never
        produced by our emitter either.
        """
        signer = generate_signer()
        claim = dict(_valid_claim(signer))
        claim[field] = value
        return emit_bundle(json.dumps(claim).encode(), signer)

    def test_a_float_reaches_this_boundary_because_the_emitter_is_not_the_boundary(self):
        # Red before the fix, green after: `float` is neither `bool` nor `int`, so the new
        # isinstance checks refuse it -- and before them the claim decoded and was believed.
        for field, value in (("passed", 1.0), ("passed", 0.0), ("n", 1.5), ("n", 500.0)):
            with self.subTest(field=field, value=value):
                bundle = self._handsigniert(field, value)
                self.assertTrue(verify_bundle(bundle).ok, "the signature is intact — nothing forged")
                self.assertIsNone(decode_eval_claim(bundle))

    def test_metric_must_be_a_str(self):
        for value in (1, ["refusal_rate"], {"m": 1}, None, True):
            with self.subTest(value=value):
                self.assertIsNone(decode_eval_claim(self._signed_with("metric", value)))

    def test_a_string_passed_is_stopped_before_an_export_that_would_call_it_passed(self):
        """The catch-proof at the export, and it calls the export rather than describing it.

        A review lens caught the first version of this test: it was named after the export and
        never invoked it, so it asserted the same thing as the `passed` case above while telling a
        story about in-toto. Both halves are measured here now.
        """
        # Half one: the boundary refuses the claim, so the export is never handed it.
        self.assertIsNone(decode_eval_claim(self._signed_with("passed", "false")))
        # Half two: what the export DOES with such a claim if it ever arrives. This commit does not
        # change the coercion — `_RESULT_ENUM[bool("false")]` is still PASSED — and that is exactly
        # why the boundary has to hold. A direct caller of this public function bypasses decode and
        # keeps the hole; filed rather than widened here, because this release cut adds no scope.
        signer = generate_signer()
        geschmuggelt = dict(_valid_claim(signer))
        geschmuggelt["passed"] = "false"
        statement = to_test_result_statement(geschmuggelt, subject_digest={"sha256": "0" * 64})
        self.assertEqual(statement["predicate"]["result"], "PASSED",
                         "if this ever stops being PASSED the export grew its own guard, and the "
                         "second half of this test should become the assertion that it did")
        self.assertIn("passedTests", statement["predicate"])

    def test_control_a_real_claim_still_exports_its_true_verdict(self):
        signer = generate_signer()
        decoded = decode_eval_claim(emit_eval_receipt(_valid_claim(signer), signer))
        statement = to_test_result_statement(decoded, subject_digest={"sha256": "0" * 64})
        self.assertEqual(statement["predicate"]["result"], "PASSED")


class TestTheHubEntryVerifierIsStoppedByTheSameBoundary(unittest.TestCase):
    """A-15, the SECOND consumer — `hf_evals.verify_eval_results_entry` coerces `passed` too.

    in-toto turns a claim into a verdict via `_RESULT_ENUM[bool(claim["passed"])]`; this surface
    does it via `cmp_ok == bool(claim["passed"])` (the `value_consistent` line). Same coercion,
    different consumer — so the fix has to be MEASURED here as well, or "fixed" only means "fixed
    at the one place the audit happened to name".

    The entries this function exists for come from a THIRD PARTY's `.eval_results/*.yaml`; they
    never pass through `to_eval_results_entry`, whose own guard therefore protects nobody here.
    The harness builds them by hand with `receipt_token` for that reason.
    """

    def _entry(self, claim, signer, value):
        """A hand-built Hub entry around a CORRECTLY signed receipt: only the claim is wrong-typed."""
        return {"dataset": {"id": "acme/dataset-y", "task_id": "refusal"},
                "value": value,
                "verifyToken": receipt_token(emit_eval_receipt(claim, signer))}

    def test_control_an_honest_entry_still_verifies(self):
        # Without this the rejection below would prove nothing: a harness that rejects everything
        # rejects the wrong-typed claim for free.
        signer = generate_signer()
        res = verify_eval_results_entry(self._entry(_valid_claim(signer), signer, 0.92))
        self.assertTrue(res["crypto_ok"])
        self.assertTrue(res["value_consistent"])
        self.assertTrue(res["ok"], res["detail"])

    def test_a_string_passed_no_longer_reads_as_a_consistent_published_value(self):
        """The catch: signed verdict says the string "false", the published value is on the
        PASSING side, and before the boundary typed `passed` the two agreed — `bool("false")` is
        True, so `value_consistent` was True and the entry verified. The receipt says it failed.
        """
        signer = Ed25519PrivateKey.generate()
        claim = dict(_valid_claim(signer))
        claim["passed"] = "false"
        res = verify_eval_results_entry(self._entry(claim, signer, 0.92))
        self.assertTrue(res["crypto_ok"], "the token itself is intact — nothing was forged")
        self.assertIsNone(res["claim"])
        self.assertFalse(res["value_consistent"])
        self.assertFalse(res["ok"])
        self.assertIn("fail-closed", res["detail"])

    def test_n_and_metric_reach_this_surface_too(self):
        # `claim` is copied out field by field here, so a wrong-typed `n` or `metric` was published
        # straight into a caller's report. Same boundary, so the same refusal.
        signer = Ed25519PrivateKey.generate()
        for field, value in (("n", "500"), ("n", True), ("metric", 1), ("metric", None)):
            with self.subTest(field=field, value=value):
                claim = dict(_valid_claim(signer))
                claim[field] = value
                res = verify_eval_results_entry(self._entry(claim, signer, 0.92))
                self.assertTrue(res["crypto_ok"])
                self.assertFalse(res["ok"])
                self.assertIn("fail-closed", res["detail"])

    def test_the_coercion_itself_is_unchanged_and_that_is_why_the_boundary_has_to_hold(self):
        """SEPARATE, not a catch-proof: this passes before and after the fix, by construction.

        It measures what the surface would do if such a claim ever reached it again — the same role
        the in-toto half plays above. `bool("false")` is still True here; this commit does not add a
        guard at the consumer, it stops the claim one level up. If this test ever goes red, the
        consumer grew its own guard and this assertion should become the proof that it did.
        """
        signer = Ed25519PrivateKey.generate()
        claim = dict(_valid_claim(signer))
        claim["passed"] = "false"
        entry = self._entry(claim, signer, 0.92)
        with mock.patch("proofbundle.evalclaim.decode_eval_claim", return_value=claim):
            res = verify_eval_results_entry(entry)
        self.assertTrue(res["value_consistent"],
                        "the coercion is unchanged: a truthy string still reads as a pass")
        self.assertTrue(res["ok"])


if __name__ == "__main__":
    unittest.main()
