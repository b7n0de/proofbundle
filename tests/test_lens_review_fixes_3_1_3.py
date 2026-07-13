"""Regressions for the 3.1.3 six-lens adversarial review findings (folded back before release).

Each test names the lens and the defect it pins closed. The one release-blocker was the historical
fail-open: safeForAutomation is a PRESENT-tense verdict, so a not-yet-valid policy or an expired-today
checkpoint must never read automation-safe just because a past instant was supplied.
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
from proofbundle.cli import main
from proofbundle.emit import _raw_pub, emit_bundle, generate_signer
from proofbundle.policy import evaluate_policy, explain_policy, lint_policy, load_policy

ORIGIN = "proofbundle.example/log"


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _two_leaf_bundle():
    signer = generate_signer()
    single = emit_bundle(b"lens review payload", signer)
    payload = base64.b64decode(single["payload_b64"])
    leaves = [b"foreign", payload]
    root = merkle.merkle_tree_hash(leaves)
    proof = merkle.inclusion_proof(leaves, 1)
    b = copy.deepcopy(single)
    b["merkle"] = {"hash_alg": "sha256-rfc6962", "leaf_index": 1, "tree_size": 2,
                   "inclusion_proof_b64": [_b64(p) for p in proof], "root_b64": _b64(root)}
    return b, root


def _checkpoint_entry(root, tree_size, *, valid_until=None, signer=None):
    signer = signer or generate_signer()
    signed = cp.sign_checkpoint(ORIGIN, tree_size, root, signer, ORIGIN)
    sig_b64 = signed.split("\n\n", 1)[1].strip().split(" ")[2]
    entry = {"origin": ORIGIN, "root": _b64(root), "treeSize": tree_size, "hashAlg": "sha256-rfc6962",
             "checkpointSigner": cp.vkey(ORIGIN, _raw_pub(signer)), "signature": sig_b64}
    if valid_until is not None:
        entry["validUntil"] = valid_until
    return entry


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _write(obj, suffix=".json"):
    fd, p = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return p


class TestHistoricalFailOpen(unittest.TestCase):
    """Lens 2/3/4/6 CONVERGENT — safeForAutomation must reflect CURRENT lifecycle validity."""

    def _pub(self, signer):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return base64.b64encode(signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    def test_future_verification_time_rejected(self):
        # --verification-time is HISTORICAL: a future instant is a usage error (exit 2), not a
        # forward-dating into force.
        b, root = _two_leaf_bundle()
        bpath = _write(b)
        ppath = _write({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "policyPurpose": "eval",
                        "merkle": {"required_hash_alg": "sha256-rfc6962"}})
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, ppath)
        rc, _out, err = _run(["verify", bpath, "--policy", ppath,
                              "--verification-time", "2099-01-01T00:00:00Z"])
        self.assertEqual(rc, 2)
        self.assertIn("must be in the past", err)

    def test_not_yet_valid_policy_never_automation_safe_historically(self):
        # a policy whose valid_from is in the FUTURE is not in force; any PAST --verification-time is
        # before valid_from too, so the historical verification also fails (exit 3), and even if it did
        # not, the POLICY_NOT_YET_VALID current-time backstop keeps safeForAutomation false.
        b, root = _two_leaf_bundle()
        signer = generate_signer()  # not the bundle signer; purpose is the lifecycle gate
        pub = self._pub(signer)
        bpath = _write(b)
        ppath = _write({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "future",
                        "policyPurpose": "eval", "valid_from": "2099-01-01T00:00:00Z",
                        "allowed_issuers": [{"public_key_b64": pub}],
                        "signature": {"require_expected_signer": True}})
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, ppath)
        rc, out, _ = _run(["verify", "--json", bpath, "--policy", ppath,
                           "--expected-root", _b64(root), "--expected-tree-size", "2",
                           "--verification-time", "2020-06-01T00:00:00Z"])
        data = json.loads(out)
        self.assertFalse(data["root_authenticity"]["safeForAutomation"])
        self.assertEqual(rc, 3)   # not-yet-valid at the historical instant too

    def test_not_yet_valid_current_time_backstop_blocker(self):
        # unit: the summary forces safe false with POLICY_NOT_YET_VALID when the policy is not-yet-valid now
        from proofbundle.bundle import root_authenticity_summary, verify_bundle
        b, root = _two_leaf_bundle()
        r = verify_bundle(b, expected_root_b64=_b64(root), expected_tree_size=2)
        s = root_authenticity_summary(r, policy_ok=True, signer_trusted=True,
                                      tree_context_authenticated=True, policy_not_yet_valid=True)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_NOT_YET_VALID", s["automationBlockers"])

    def test_expired_today_checkpoint_not_safe_in_historical_mode(self):
        # Lens-4 F2-2b: a checkpoint expired TODAY but valid at the (past) verification instant must not
        # yield safeForAutomation true — the safety verdict authenticates the checkpoint at CURRENT time.
        b, root = _two_leaf_bundle()
        signer = generate_signer()
        pub = self._pub(signer)
        entry = _checkpoint_entry(root, 2, valid_until="2026-01-01T00:00:00Z")  # expired at real-now
        bpath = _write(b)
        ppath = _write({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "cpexp",
                        "policyPurpose": "eval",
                        "allowed_issuers": [{"public_key_b64": pub}],
                        "signature": {"require_expected_signer": True},
                        "merkle": {"trusted_checkpoints": [entry]}})
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, ppath)
        rc, out, _ = _run(["verify", "--json", bpath, "--policy", ppath,
                           "--verification-time", "2025-06-01T00:00:00Z"])
        ra = json.loads(out)["root_authenticity"]
        self.assertFalse(ra["safeForAutomation"])
        self.assertIn("TREE_CONTEXT_NOT_AUTHENTICATED", ra["automationBlockers"])

    def test_current_policy_status_surfaces_not_yet_valid(self):
        b, root = _two_leaf_bundle()
        bpath = _write(b)
        ppath = _write({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "nyv",
                        "policyPurpose": "eval", "valid_from": "2099-01-01T00:00:00Z",
                        "merkle": {"required_hash_alg": "sha256-rfc6962"}})
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, ppath)
        _rc, out, _ = _run(["verify", "--json", bpath, "--policy", ppath,
                            "--verification-time", "2020-01-01T00:00:00Z"])
        self.assertEqual(json.loads(out)["verification_time"]["current_policy_status"], "NOT_YET_VALID")


class TestCheckpointRootTrustLabel(unittest.TestCase):
    """Lens 3 F2 / Lens 4 F3 — no CHECKPOINT / checkpointAuthenticity overclaim without a real match."""

    def test_non_matching_policy_checkpoint_plus_passing_pair_is_not_checkpoint_level(self):
        b, root = _two_leaf_bundle()
        entry = _checkpoint_entry(root, 3)   # authentic checkpoint of a DIFFERENT tree (size 3)
        bpath = _write(b)
        ppath = _write({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "cpother",
                        "merkle": {"trusted_checkpoints": [entry]}})
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, ppath)
        rc, out, _ = _run(["verify", "--json", bpath, "--policy", ppath,
                           "--expected-root", _b64(root), "--expected-tree-size", "2"])
        ra = json.loads(out)["root_authenticity"]
        self.assertNotEqual(ra["rootTrustLevel"], "CHECKPOINT")
        self.assertEqual(ra["checkpointAuthenticity"], "FAIL")   # authentic but did not match this bundle
        self.assertEqual(ra["treeContextAuthenticity"], "FAIL")
        self.assertEqual(rc, 3)


class TestTreeSizeExpectationCheckpoint(unittest.TestCase):
    """Lens 3 F3 — a failed checkpoint is a requested-but-unauthenticated tree-size, not NOT_REQUESTED."""

    def test_badsig_checkpoint_treesizeexpectation_is_fail(self):
        b, root = _two_leaf_bundle()
        signer = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 2, root, signer, ORIGIN)
        wrong_vk = cp.vkey(ORIGIN, _raw_pub(generate_signer()))
        bpath = _write(b)
        nfd, npath = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(nfd, "w") as f:
            f.write(note)
        self.addCleanup(os.unlink, bpath)
        self.addCleanup(os.unlink, npath)
        rc, out, _ = _run(["verify", "--json", bpath, "--trusted-checkpoint", npath,
                           "--checkpoint-vkey", wrong_vk])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["treeSizeExpectation"]["status"], "FAIL")


class TestRequireAuthRootByCheckpoint(unittest.TestCase):
    """Lens 6 #2 — a matching checkpoint satisfies require_authenticated_root (it authenticates the root)."""

    def test_require_authenticated_root_satisfied_by_matching_checkpoint(self):
        from proofbundle.bundle import verify_bundle
        b, root = _two_leaf_bundle()
        entry = _checkpoint_entry(root, 2)
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "beltsusp",
                           "merkle": {"require_authenticated_root": True,
                                      "trusted_checkpoints": [entry]}})
        res = evaluate_policy(b, verify_bundle(b), pol)
        self.assertTrue(res["policy_ok"], res["reason"])
        self.assertTrue(res["root_authenticated"])
        self.assertTrue(res["tree_context_authenticated"])


class TestLibRobustness(unittest.TestCase):
    """Lens 6 #3 — a raw dict bypassing load_policy must not crash evaluate_policy."""

    def test_non_string_checkpoint_signer_fails_closed(self):
        from proofbundle.bundle import verify_bundle
        b, root = _two_leaf_bundle()
        raw = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "raw",
               "merkle": {"trusted_checkpoints": [
                   {"origin": ORIGIN, "root": _b64(root), "treeSize": 2, "hashAlg": "sha256-rfc6962",
                    "checkpointSigner": None, "signature": "AAAA"}]}}
        res = evaluate_policy(b, verify_bundle(b), raw)   # must not raise
        self.assertFalse(res["policy_ok"])
        self.assertIs(res["tree_context_authenticated"], False)


class TestExplainEnforceParity(unittest.TestCase):
    """Lens 2 — a minimal raw template pins policy:not_template, so explain must list it (not 'vacuous')."""

    def test_minimal_template_is_not_reported_vacuous(self):
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "tmpl",
                           "requiresIdentityOverlay": True})
        pins = explain_policy(pol)
        self.assertTrue(any("template" in p for p in pins))
        res = lint_policy(pol)
        self.assertFalse(any("pins nothing" in e or "vacuous" in e for e in res["errors"]))


class TestPolicyPurposeNull(unittest.TestCase):
    """Lens 4 F1 — schema allows policyPurpose:null; the parser must treat it exactly like absent."""

    def test_null_purpose_loads_and_is_treated_as_absent(self):
        from proofbundle.bundle import verify_bundle
        b, _root = _two_leaf_bundle()
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "np",
                           "policyPurpose": None, "merkle": {"required_hash_alg": "sha256-rfc6962"}})
        res = evaluate_policy(b, verify_bundle(b), pol)   # no purpose check added, passes
        self.assertTrue(res["policy_ok"])
        self.assertFalse(any(c["name"] == "policy:purpose" for c in res["checks"]))
        # strict lint still requires a real purpose (null == missing)
        self.assertFalse(lint_policy(pol, strict=True)["ok"])


if __name__ == "__main__":
    unittest.main()
