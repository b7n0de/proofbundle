"""6.2.1 local red tests: R6b-1 and R6b-2 (bind), the neighbours of R6a-2 left open at 6.2.0.

R6b-1 -- a checkpoint-only policy adopts an inclusion that was never proven. The result of bundle A is
reused for a copy of A whose ``merkle.root_b64`` was replaced by the root of another bundle B; the policy
pins only a genuinely signed checkpoint for B's root at tree size 1. The checkpoint match sets the policy
check (and the derived trust fields) positive although the result never proved inclusion under that root.

R6b-2 -- an equal root does not bind the rest of the inclusion context. The result of a two-leaf bundle at
index 1 is reused for a copy whose ``leaf_index`` was set to 0, or whose ``inclusion_proof_b64`` was
emptied; root and tree size stay equal, the checkpoint for them is genuine, ``require_authenticated_root``
is on. The old positive inclusion verdict is still adopted for a context that does not verify.

Property: a policy verdict and its trust fields are positive only for the inclusion context the
authentic result itself proved; a fresh ``verify_bundle`` of every altered copy fails, and the policy
must not be more lenient than that.
"""
from __future__ import annotations

import base64
import copy
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle import emit_bundle, verify_bundle  # noqa: E402
from proofbundle.policy import evaluate_policy, load_policy  # noqa: E402
from test_tree_context_authenticity import _checkpoint_entry, _two_leaf_bundle  # noqa: E402


def _policy(entry: dict, *, require_root: bool) -> dict:
    merkle = {"trusted_checkpoints": [entry]}
    if require_root:
        merkle["require_authenticated_root"] = True
    return load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "r6b-bind",
                        "merkle": merkle})


def _not_positive(test: unittest.TestCase, out: dict, what: str) -> None:
    test.assertIsNot(out.get("policy_ok"), True, f"{what}: policy_ok must not be True (got {out!r})")
    test.assertIsNot(out.get("root_authenticated"), True, f"{what}: root_authenticated must not be True")
    test.assertIsNot(out.get("tree_context_authenticated"), True,
                     f"{what}: tree_context_authenticated must not be True for an unproven inclusion")
    test.assertNotEqual(out.get("checkpoint_authenticity"), "PASS",
                        f"{what}: checkpoint_authenticity must not be PASS for an unproven inclusion")


class R6b1CheckpointOnlyPolicy(unittest.TestCase):
    def _setup(self):
        a = emit_bundle(b"r6b-1 bundle A", Ed25519PrivateKey.generate())
        b = emit_bundle(b"r6b-1 bundle B", Ed25519PrivateKey.generate())
        result_a = verify_bundle(a)
        swapped = copy.deepcopy(a)
        swapped["merkle"]["root_b64"] = b["merkle"]["root_b64"]
        return a, b, result_a, swapped

    def test_a_swapped_root_under_a_checkpoint_only_policy_is_not_positive(self):
        _a, b, result_a, swapped = self._setup()
        entry = _checkpoint_entry(base64.b64decode(b["merkle"]["root_b64"]), 1)
        _not_positive(self, evaluate_policy(swapped, result_a, _policy(entry, require_root=False)),
                      "checkpoint-only policy, swapped root")

    def test_the_trust_fields_stay_negative_also_with_require_authenticated_root(self):
        _a, b, result_a, swapped = self._setup()
        entry = _checkpoint_entry(base64.b64decode(b["merkle"]["root_b64"]), 1)
        _not_positive(self, evaluate_policy(swapped, result_a, _policy(entry, require_root=True)),
                      "require_authenticated_root, swapped root")

    def test_control_a_fresh_verify_of_the_swapped_copy_fails(self):
        _a, _b, _r, swapped = self._setup()
        self.assertFalse(verify_bundle(swapped).ok)

    def test_control_the_unchanged_bundle_under_its_own_checkpoint_passes(self):
        a, _b, result_a, _s = self._setup()
        entry = _checkpoint_entry(base64.b64decode(a["merkle"]["root_b64"]), 1)
        out = evaluate_policy(a, result_a, _policy(entry, require_root=False))
        self.assertIs(out.get("policy_ok"), True)
        self.assertIs(out.get("root_authenticated"), True)
        self.assertIs(out.get("tree_context_authenticated"), True)
        self.assertEqual(out.get("checkpoint_authenticity"), "PASS")


class R6b2InclusionContextBound(unittest.TestCase):
    def _setup(self):
        bundle, _relabel, root = _two_leaf_bundle()
        result = verify_bundle(bundle)
        policy = _policy(_checkpoint_entry(root, 2), require_root=True)
        return bundle, result, policy

    def _altered(self, bundle: dict, field: str) -> dict:
        copy_ = copy.deepcopy(bundle)
        if field == "leaf_index":
            copy_["merkle"]["leaf_index"] = 0
        else:
            copy_["merkle"]["inclusion_proof_b64"] = []
        return copy_

    def test_a_changed_leaf_index_is_not_adopted_from_the_old_result(self):
        bundle, result, policy = self._setup()
        _not_positive(self, evaluate_policy(self._altered(bundle, "leaf_index"), result, policy),
                      "leaf_index 1 -> 0, same root and size")

    def test_an_emptied_inclusion_proof_is_not_adopted_from_the_old_result(self):
        bundle, result, policy = self._setup()
        _not_positive(self, evaluate_policy(self._altered(bundle, "proof"), result, policy),
                      "inclusion proof emptied, same root and size")

    def test_control_a_fresh_verify_of_each_altered_copy_fails(self):
        bundle, _result, _policy_ = self._setup()
        self.assertFalse(verify_bundle(self._altered(bundle, "leaf_index")).ok)
        self.assertFalse(verify_bundle(self._altered(bundle, "proof")).ok)

    def test_control_the_unchanged_bundle_with_its_own_result_passes(self):
        bundle, result, policy = self._setup()
        out = evaluate_policy(bundle, result, policy)
        self.assertIs(out.get("policy_ok"), True)
        self.assertIs(out.get("root_authenticated"), True)
        self.assertIs(out.get("tree_context_authenticated"), True)


if __name__ == "__main__":
    unittest.main()
