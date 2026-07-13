"""A-P0-1 (3.1.3) — root and tree size authenticated ATOMICALLY from one source.

The sharp vector (audit 2026-07-13): RFC 6962 inclusion constrains (leaf_index, tree_size)
only up to path-shape equivalence — a REAL 2-leaf receipt for the payload at index 1
relabelled as (index 2 of a 3-leaf tree) verifies with the SAME payload, signature, root
and proof. A naked root-bytes pin cannot tell the two labelings apart (both share the
root), so `rootAuthenticity: PASS` + `safeForAutomation: true` was reachable for a forged
tree context. The fix: `tree_size` and `root` MUST come atomically from ONE authenticated
source — a signed C2SP checkpoint (policy `merkle.trusted_checkpoints` or CLI
`--trusted-checkpoint`/`--checkpoint-vkey`) or an RP-supplied (root, size) PAIR — and a
naked root pin reaches at most ROOT_BYTES_AUTHENTICITY, never TREE_CONTEXT_AUTHENTICITY,
never `safeForAutomation: true` (rootTrustLevel: ROOT_BYTES_ONLY).
"""
import base64
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest

from proofbundle import checkpoint as cp
from proofbundle import merkle
from proofbundle.bundle import root_authenticity_summary, verify_bundle
from proofbundle.cli import main
from proofbundle.emit import _raw_pub, emit_bundle, generate_signer
from proofbundle.policy import evaluate_policy, load_policy

ORIGIN = "proofbundle.example/log"


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _two_leaf_bundle():
    """A REAL 2-leaf receipt for the signed payload at index 1, plus its (index=2, tree_size=3)
    relabel: same payload, same signature, same root, same proof. RFC 6962 inclusion holds for
    BOTH labelings, so only an atomically authenticated (root, tree_size) pair separates them."""
    signer = generate_signer()
    single = emit_bundle(b"A-P0-1 atomic tree context payload", signer)
    payload = base64.b64decode(single["payload_b64"])
    leaves = [b"first leaf, not ours", payload]
    root = merkle.merkle_tree_hash(leaves)
    proof = merkle.inclusion_proof(leaves, 1)
    bundle = copy.deepcopy(single)
    bundle["merkle"] = {"hash_alg": "sha256-rfc6962", "leaf_index": 1, "tree_size": 2,
                        "inclusion_proof_b64": [_b64(p) for p in proof], "root_b64": _b64(root)}
    relabel = copy.deepcopy(bundle)
    relabel["merkle"]["leaf_index"] = 2
    relabel["merkle"]["tree_size"] = 3
    return bundle, relabel, root


def _checkpoint_entry(root: bytes, tree_size: int, *, origin=ORIGIN, hash_alg="sha256-rfc6962",
                      valid_until=None, signer=None, vkey_of=None):
    """A policy `merkle.trusted_checkpoints` entry: a real C2SP-signed (origin, size, root)
    triple. ``vkey_of`` lets a test pin a DIFFERENT signer's vkey (signer mismatch)."""
    signer = signer or generate_signer()
    signed = cp.sign_checkpoint(origin, tree_size, root, signer, origin)
    sig_b64 = signed.split("\n\n", 1)[1].strip().split(" ")[2]
    entry = {"origin": origin, "root": _b64(root), "treeSize": tree_size, "hashAlg": hash_alg,
             "checkpointSigner": cp.vkey(origin, _raw_pub(vkey_of or signer)),
             "signature": sig_b64}
    if valid_until is not None:
        entry["validUntil"] = valid_until
    return entry


def _cp_policy(entry) -> dict:
    return load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "cp-test",
                        "merkle": {"trusted_checkpoints": [entry]}})


class TestRelabelReproduction(unittest.TestCase):
    def test_two_leaf_relabel_verifies_inclusion_and_matches_naked_root_pin(self):
        # The reproduced hole: inclusion holds for BOTH labelings AND the root BYTES match the
        # naked pin for both — bytes alone are not tree context.
        bundle, relabel, root = _two_leaf_bundle()
        self.assertTrue(verify_bundle(bundle).ok)
        self.assertTrue(verify_bundle(relabel).ok)
        self.assertTrue(verify_bundle(relabel, expected_root_b64=_b64(root)).ok)


class TestTrustedCheckpointPolicy(unittest.TestCase):
    """merkle.trusted_checkpoints — the policy pins a SIGNED (origin, size, root) triple."""

    def test_two_leaf_proof_relabelled_as_three_leaf_tree_fails(self):
        bundle, relabel, root = _two_leaf_bundle()
        pol = _cp_policy(_checkpoint_entry(root, 2))
        good = evaluate_policy(bundle, verify_bundle(bundle), pol)
        self.assertTrue(good["policy_ok"])
        self.assertTrue(good["tree_context_authenticated"])
        self.assertEqual(good["checkpoint_authenticity"], "PASS")
        bad = evaluate_policy(relabel, verify_bundle(relabel), pol)
        self.assertFalse(bad["policy_ok"], "the relabelled tree context must FAIL the checkpoint pin")
        self.assertFalse(bad["tree_context_authenticated"])

    def test_root_match_tree_size_mismatch_fails(self):
        # the checkpoint's root matches the bundle's root BIT-EXACT, but its size does not —
        # a root-bytes-only comparison would pass; the atomic pair must fail.
        bundle, _relabel, root = _two_leaf_bundle()
        pol = _cp_policy(_checkpoint_entry(root, 3))
        res = evaluate_policy(bundle, verify_bundle(bundle), pol)
        self.assertFalse(res["policy_ok"])
        self.assertFalse(res["tree_context_authenticated"])

    def test_leaf_index_relabel_fails(self):
        # the audit relabel moves BOTH leaf_index and tree_size; under the pinned checkpoint the
        # relabelled context is rejected while the honest one passes (discriminating vector).
        bundle, relabel, root = _two_leaf_bundle()
        pol = _cp_policy(_checkpoint_entry(root, 2))
        self.assertTrue(evaluate_policy(bundle, verify_bundle(bundle), pol)["policy_ok"])
        self.assertFalse(evaluate_policy(relabel, verify_bundle(relabel), pol)["policy_ok"])

    def test_checkpoint_origin_mismatch_fails(self):
        # tampering the pinned origin invalidates the signature (the origin is INSIDE the signed
        # note) — the checkpoint must not authenticate.
        bundle, _relabel, root = _two_leaf_bundle()
        entry = _checkpoint_entry(root, 2)
        entry["origin"] = "evil.example/other-log"
        res = evaluate_policy(bundle, verify_bundle(bundle), _cp_policy(entry))
        self.assertFalse(res["policy_ok"])
        self.assertEqual(res["checkpoint_authenticity"], "FAIL")

    def test_checkpoint_signer_mismatch_fails(self):
        bundle, _relabel, root = _two_leaf_bundle()
        entry = _checkpoint_entry(root, 2, vkey_of=generate_signer())   # vkey of a DIFFERENT key
        res = evaluate_policy(bundle, verify_bundle(bundle), _cp_policy(entry))
        self.assertFalse(res["policy_ok"])
        self.assertEqual(res["checkpoint_authenticity"], "FAIL")

    def test_checkpoint_expired_fails(self):
        bundle, _relabel, root = _two_leaf_bundle()
        entry = _checkpoint_entry(root, 2, valid_until="2020-01-01T00:00:00Z")
        res = evaluate_policy(bundle, verify_bundle(bundle), _cp_policy(entry))
        self.assertFalse(res["policy_ok"])
        self.assertEqual(res["checkpoint_authenticity"], "FAIL")

    def test_checkpoint_hash_alg_mismatch_fails(self):
        bundle, _relabel, root = _two_leaf_bundle()
        entry = _checkpoint_entry(root, 2, hash_alg="sha3-256-unknown")
        res = evaluate_policy(bundle, verify_bundle(bundle), _cp_policy(entry))
        self.assertFalse(res["policy_ok"])
        self.assertEqual(res["checkpoint_authenticity"], "FAIL")

    def test_legacy_root_pin_never_sets_tree_context_pass(self):
        # a naked trusted_roots pin stays verifiable but reaches at most ROOT_BYTES_AUTHENTICITY:
        # tree context NOT authenticated, rootTrustLevel ROOT_BYTES_ONLY, safeForAutomation false.
        bundle, _relabel, root = _two_leaf_bundle()
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "naked",
                           "merkle": {"trusted_roots": [_b64(root)]}})
        res = evaluate_policy(bundle, verify_bundle(bundle), pol)
        self.assertTrue(res["policy_ok"])                       # still verifiable (legacy kept)
        self.assertTrue(res["root_authenticated"])              # bytes ARE authenticated
        self.assertNotEqual(res.get("tree_context_authenticated"), True)
        s = root_authenticity_summary(verify_bundle(bundle), policy_authenticated_root=True,
                                      policy_ok=True, signer_trusted=True)
        self.assertNotEqual(s["treeContextAuthenticity"], "PASS")
        self.assertEqual(s["rootTrustLevel"], "ROOT_BYTES_ONLY")
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("TREE_CONTEXT_NOT_AUTHENTICATED", s["automationBlockers"])


class TestSummaryTreeContext(unittest.TestCase):
    def _authenticated(self, bundle, root):
        return verify_bundle(bundle, expected_root_b64=_b64(root), expected_tree_size=2)

    def test_checkpoint_level_sets_safe_with_policy(self):
        bundle, _relabel, root = _two_leaf_bundle()
        s = root_authenticity_summary(self._authenticated(bundle, root), policy_ok=True,
                                      signer_trusted=True, tree_context_authenticated=True,
                                      checkpoint_authenticity="PASS")
        self.assertTrue(s["safeForAutomation"], s)
        self.assertEqual(s["rootTrustLevel"], "CHECKPOINT")
        self.assertEqual(s["treeContextAuthenticity"], "PASS")
        self.assertEqual(s["checkpointAuthenticity"], "PASS")

    def test_root_and_size_pair_level(self):
        bundle, _relabel, root = _two_leaf_bundle()
        s = root_authenticity_summary(self._authenticated(bundle, root), policy_ok=True,
                                      signer_trusted=True, tree_context_authenticated=True)
        self.assertTrue(s["safeForAutomation"], s)
        self.assertEqual(s["rootTrustLevel"], "ROOT_AND_TREE_SIZE_PINNED")
        self.assertEqual(s["checkpointAuthenticity"], "NOT_EVALUATED")

    def test_bytes_only_and_none_levels(self):
        bundle, _relabel, root = _two_leaf_bundle()
        s = root_authenticity_summary(verify_bundle(bundle, expected_root_b64=_b64(root)))
        self.assertEqual(s["rootTrustLevel"], "ROOT_BYTES_ONLY")
        self.assertIn("TREE_CONTEXT_NOT_AUTHENTICATED", s["automationBlockers"])
        s = root_authenticity_summary(verify_bundle(bundle))
        self.assertEqual(s["rootTrustLevel"], "NONE")

    def test_legacy_root_authenticity_key_is_bytes_alias(self):
        # wire-compat: the legacy rootAuthenticity key stays present and equals the
        # differentiated rootBytesAuthenticity (documented alias, never a broader claim).
        bundle, _relabel, root = _two_leaf_bundle()
        s = root_authenticity_summary(verify_bundle(bundle, expected_root_b64=_b64(root)))
        self.assertEqual(s["rootAuthenticity"], s["rootBytesAuthenticity"])
        self.assertEqual(s["rootBytesAuthenticity"], "PASS")

    def test_failed_tree_context_reports_fail(self):
        bundle, relabel, root = _two_leaf_bundle()
        r = verify_bundle(relabel, expected_root_b64=_b64(root), expected_tree_size=2)
        self.assertFalse(r.ok)   # tree-size check fails
        s = root_authenticity_summary(r, tree_context_authenticated=False)
        self.assertEqual(s["treeContextAuthenticity"], "FAIL")
        self.assertFalse(s["safeForAutomation"])


class TestCLITrustedCheckpoint(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _files(self, bundle, root, tree_size, signer=None):
        signer = signer or generate_signer()
        note = cp.sign_checkpoint(ORIGIN, tree_size, root, signer, ORIGIN)
        vk = cp.vkey(ORIGIN, _raw_pub(signer))
        bfd, bpath = tempfile.mkstemp(suffix=".json")
        with os.fdopen(bfd, "w") as f:
            json.dump(bundle, f)
        nfd, npath = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(nfd, "w") as f:
            f.write(note)
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, npath)
        return bpath, npath, vk

    def test_checkpoint_match_passes_and_reports_levels(self):
        bundle, _relabel, root = _two_leaf_bundle()
        bpath, npath, vk = self._files(bundle, root, 2)
        rc, out, _ = self._run(["verify", "--json", bpath,
                                "--trusted-checkpoint", npath, "--checkpoint-vkey", vk])
        self.assertEqual(rc, 0, out)
        ra = json.loads(out)["root_authenticity"]
        self.assertEqual(ra["treeContextAuthenticity"], "PASS")
        self.assertEqual(ra["checkpointAuthenticity"], "PASS")
        self.assertEqual(ra["rootTrustLevel"], "CHECKPOINT")
        # no policy supplied → still not automation-safe (honest global verdict)
        self.assertFalse(ra["safeForAutomation"])

    def test_relabelled_bundle_fails_under_checkpoint(self):
        bundle, relabel, root = _two_leaf_bundle()
        bpath, npath, vk = self._files(relabel, root, 2)
        rc, out, _ = self._run(["verify", bpath,
                                "--trusted-checkpoint", npath, "--checkpoint-vkey", vk])
        self.assertEqual(rc, 1, out)   # tree_size 3 != checkpoint size 2 → crypto verdict FAIL

    def test_wrong_vkey_fails_closed(self):
        bundle, _relabel, root = _two_leaf_bundle()
        bpath, npath, _vk = self._files(bundle, root, 2)
        wrong_vk = cp.vkey(ORIGIN, _raw_pub(generate_signer()))
        rc, out, _ = self._run(["verify", "--json", bpath,
                                "--trusted-checkpoint", npath, "--checkpoint-vkey", wrong_vk])
        self.assertEqual(rc, 1, out)
        ra = json.loads(out)["root_authenticity"]
        self.assertEqual(ra["checkpointAuthenticity"], "FAIL")
        self.assertNotEqual(ra["treeContextAuthenticity"], "PASS")

    def test_lone_checkpoint_flag_is_usage_error(self):
        bundle, _relabel, root = _two_leaf_bundle()
        bpath, npath, vk = self._files(bundle, root, 2)
        self.assertEqual(self._run(["verify", bpath, "--trusted-checkpoint", npath])[0], 2)
        self.assertEqual(self._run(["verify", bpath, "--checkpoint-vkey", vk])[0], 2)

    def test_conflicting_expected_root_is_ambiguity_error(self):
        bundle, _relabel, root = _two_leaf_bundle()
        bpath, npath, vk = self._files(bundle, root, 2)
        other = _b64(b"\x07" * 32)
        rc, _out, _err = self._run(["verify", bpath, "--trusted-checkpoint", npath,
                                    "--checkpoint-vkey", vk, "--expected-root", other])
        self.assertEqual(rc, 2)
        rc, _out, _err = self._run(["verify", bpath, "--trusted-checkpoint", npath,
                                    "--checkpoint-vkey", vk, "--expected-tree-size", "9"])
        self.assertEqual(rc, 2)

    def test_agreeing_explicit_flags_are_not_a_conflict(self):
        bundle, _relabel, root = _two_leaf_bundle()
        bpath, npath, vk = self._files(bundle, root, 2)
        rc, _out, _err = self._run(["verify", bpath, "--trusted-checkpoint", npath,
                                    "--checkpoint-vkey", vk,
                                    "--expected-root", _b64(root), "--expected-tree-size", "2"])
        self.assertEqual(rc, 0)

    def test_root_and_size_pair_without_checkpoint(self):
        bundle, _relabel, root = _two_leaf_bundle()
        bfd, bpath = tempfile.mkstemp(suffix=".json")
        with os.fdopen(bfd, "w") as f:
            json.dump(bundle, f)
        self.addCleanup(os.unlink, bpath)
        rc, out, _ = self._run(["verify", "--json", bpath,
                                "--expected-root", _b64(root), "--expected-tree-size", "2"])
        self.assertEqual(rc, 0)
        ra = json.loads(out)["root_authenticity"]
        self.assertEqual(ra["treeContextAuthenticity"], "PASS")
        self.assertEqual(ra["rootTrustLevel"], "ROOT_AND_TREE_SIZE_PINNED")
        self.assertEqual(ra["checkpointAuthenticity"], "NOT_EVALUATED")


if __name__ == "__main__":
    unittest.main()
