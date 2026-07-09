"""Malformed-input robustness of verify_bundle + build_eval_claim (holistic-review findings, 0.7.1).

The verifier's contract is OK/FAILED/malformed — never a raw traceback. build_eval_claim must not emit a
receipt that fails its own published schema. One red-test per finding."""
import copy
import unittest

from proofbundle import recompute_merkle_root_b64, verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError, UnsupportedError
from proofbundle.evalclaim import EvalClaimError, build_eval_claim


def _bundle():
    return emit_bundle(b"payload", generate_signer())


def _mut(mut):
    b = copy.deepcopy(_bundle())
    mut(b)
    return b


class TestBundleRobustness(unittest.TestCase):
    def test_leaf_index_non_numeric_raises_format_error(self):   # D1
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b["merkle"].__setitem__("leaf_index", "abc")))

    def test_signature_non_object_raises_format_error(self):     # D2
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b.__setitem__("signature", "notadict")))
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b.__setitem__("merkle", ["x"])))

    def test_tree_size_float_rejected(self):                     # D3 (SPEC §2: integers only)
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b["merkle"].__setitem__("tree_size", 1.5)))

    def test_missing_inclusion_proof_rejected(self):             # D4 (SPEC §5: required)
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b["merkle"].pop("inclusion_proof_b64")))

    def test_unknown_fields_rejected(self):                      # SPEC §3: additionalProperties false
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b.__setitem__("evil", "x")))
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b["signature"].__setitem__("evil", "x")))
        with self.assertRaises(BundleFormatError):
            verify_bundle(_mut(lambda b: b["merkle"].__setitem__("evil", "x")))

    def test_well_formed_still_ok(self):                         # no false positive
        self.assertTrue(verify_bundle(_bundle()).ok)

    def test_missing_hash_alg_rejected_with_migration_hint(self):   # WP-B1, closes #28
        # SPEC.md §5 makes merkle.hash_alg REQUIRED (the verifier already enforced this since
        # v1.6; SPEC.md was the drift). The error must name the missing field AND the fix, since
        # the realistic cause is a pre-v1.6 hand-authored or archived bundle, not a bug.
        with self.assertRaises(BundleFormatError) as ctx:
            verify_bundle(_mut(lambda b: b["merkle"].pop("hash_alg")))
        msg = str(ctx.exception)
        self.assertIn("merkle.hash_alg", msg)
        self.assertIn("sha256-rfc6962", msg)          # migration hint names the concrete fix
        self.assertIn("REQUIRED", msg)

    def test_missing_hash_alg_rejected_same_way_in_recompute(self):   # WP-B1
        # recompute_merkle_root_b64 validates hash_alg the SAME way verify_bundle does (bundle.py
        # comment) — pin both call sites to the shared helper so they cannot drift apart again.
        with self.assertRaises(BundleFormatError) as ctx:
            recompute_merkle_root_b64(_mut(lambda b: b["merkle"].pop("hash_alg")))
        self.assertIn("merkle.hash_alg", str(ctx.exception))

    def test_unsupported_hash_alg_value_rejected(self):           # WP-B1
        with self.assertRaises(UnsupportedError):
            verify_bundle(_mut(lambda b: b["merkle"].__setitem__("hash_alg", "sha512-not-a-thing")))


class TestEvalClaimSchemaConformance(unittest.TestCase):
    def _build(self, **kw):
        base = dict(suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.8",
                    score="0.9", n=1, model_id="m", dataset_id="d", issuer="",
                    timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        base.update(kw)
        return build_eval_claim(**base)

    def test_negative_n_rejected(self):                          # schema minimum 0
        with self.assertRaises(EvalClaimError):
            self._build(n=-5)

    def test_exponent_and_sign_threshold_rejected(self):         # schema decimal pattern
        for bad in ("1e2", "Infinity", "+5", " 0.9 "):
            with self.assertRaises(EvalClaimError):
                self._build(threshold=bad)

    def test_plain_decimal_accepted(self):
        claim, _ = self._build(threshold="0.80", score="0.92")
        self.assertTrue(claim["passed"])
