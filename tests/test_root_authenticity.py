"""P0-A (Hardening 3.0.1 §6) — native root authenticity.

The native Merkle root is NOT in the signature input (SPEC §5), so the SAME signed payload verifies under
DIFFERENT roots: a *coherent one-leaf rewrap* re-anchors the payload at index 0 of a 2-leaf tree with a
foreign sibling, and inclusion still holds. These tests pin (a) the reproduced status quo — both verify
without policy, merkle inclusion proves CONSISTENCY not authenticity — and (b) that a relying party can
now close it, via --expected-root/expected_tree_size or a policy require_authenticated_root/trusted_roots."""
import base64
import copy
import hashlib
import unittest
from pathlib import Path

from proofbundle.bundle import root_authenticity_summary, verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.policy import evaluate_policy, explain_policy, load_policy

REPO = Path(__file__).resolve().parents[1]


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _make_orig_and_coherent_rewrap():
    """A real single-leaf receipt and a COHERENT 2-leaf rewrap of the SAME signed payload."""
    signer = generate_signer()
    orig = emit_bundle(b"P0-A root authenticity payload", signer)
    assert orig["merkle"]["tree_size"] == 1
    payload = base64.b64decode(orig["payload_b64"])
    leaf = hashlib.sha256(b"\x00" + payload).digest()          # RFC 6962 leaf hash
    sibling = hashlib.sha256(b"\x00" + b"attacker foreign sibling").digest()
    rewrap_root = hashlib.sha256(b"\x01" + leaf + sibling).digest()   # node(leaf, sibling)
    rewrap = copy.deepcopy(orig)                               # SAME payload + SAME signature
    rewrap["merkle"] = {"hash_alg": "sha256-rfc6962", "leaf_index": 0, "tree_size": 2,
                        "inclusion_proof_b64": [_b64(sibling)], "root_b64": _b64(rewrap_root)}
    return orig, rewrap


class TestReproducedStatusQuo(unittest.TestCase):
    def test_coherent_single_leaf_rewrap_verifies_without_policy(self):
        # The finding, reproduced: WITHOUT any root authentication, the SAME payload verifies under TWO
        # different roots. Merkle inclusion proves consistency under the STATED root, not its authenticity.
        orig, rewrap = _make_orig_and_coherent_rewrap()
        self.assertTrue(verify_bundle(orig).ok)
        self.assertTrue(verify_bundle(rewrap).ok)
        self.assertNotEqual(orig["merkle"]["root_b64"], rewrap["merkle"]["root_b64"])


class TestExpectedRootGate(unittest.TestCase):
    def test_expected_root_matches_passes(self):
        orig, _ = _make_orig_and_coherent_rewrap()
        r = verify_bundle(orig, expected_root_b64=orig["merkle"]["root_b64"])
        self.assertTrue(r.ok)
        self.assertTrue(any(c.name == "root-authenticity" and c.ok for c in r.checks))

    def test_coherent_rewrap_fails_when_root_authentication_required(self):
        # The fix: the coherent rewrap does NOT match the authenticated (original) root → verification FAILS,
        # while signature + merkle-consistency still PASS (the honest separation).
        orig, rewrap = _make_orig_and_coherent_rewrap()
        r = verify_bundle(rewrap, expected_root_b64=orig["merkle"]["root_b64"])
        self.assertFalse(r.ok)
        by = {c.name: c.ok for c in r.checks}
        self.assertTrue(by["ed25519-signature"])
        self.assertTrue(by["merkle-inclusion"])
        self.assertFalse(by["root-authenticity"])

    def test_tree_size_substitution_is_caught(self):
        orig, rewrap = _make_orig_and_coherent_rewrap()
        # the rewrap claims tree_size 2; pinning the original size 1 catches it
        r = verify_bundle(rewrap, expected_tree_size=1)
        self.assertFalse(r.ok)
        self.assertFalse({c.name: c.ok for c in r.checks}["tree-size"])
        self.assertTrue(verify_bundle(orig, expected_tree_size=1).ok)

    def test_expected_tree_size_rejects_bool_and_float(self):
        orig, _ = _make_orig_and_coherent_rewrap()  # tree_size 1; True==1 and 1.0==1 must NOT satisfy it
        self.assertFalse({c.name: c.ok for c in verify_bundle(orig, expected_tree_size=True).checks}["tree-size"])
        self.assertFalse({c.name: c.ok for c in verify_bundle(orig, expected_tree_size=1.0).checks}["tree-size"])
        self.assertTrue({c.name: c.ok for c in verify_bundle(orig, expected_tree_size=1).checks}["tree-size"])


class TestCLIRootAuthenticity(unittest.TestCase):
    """Audit 2026-07-13 (§16 CLI + exit-code tests): exercise --expected-root through the real
    argparse/CLI path and the JSON contract, not only verify_bundle() directly."""

    def _emit_single_leaf(self, d):
        import subprocess
        import sys
        payload = Path(d) / "payload.json"
        payload.write_text('{"claim":"cli root-auth test"}', encoding="utf-8")
        out = Path(d) / "b.json"
        key = Path(d) / "k.seed"
        env = {"PYTHONPATH": str(REPO / "src")}
        subprocess.run([sys.executable, "-m", "proofbundle.cli", "emit", "--payload-file", str(payload),
                        "--out", str(out), "--new-key", str(key)], check=True, cwd=REPO, env=env,
                       capture_output=True)
        import json as _json
        return out, _json.loads(out.read_text())["merkle"]["root_b64"]

    def _run(self, *args):
        import subprocess
        import sys
        return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args], cwd=REPO,
                              env={"PYTHONPATH": str(REPO / "src")}, capture_output=True, text=True)

    def test_cli_expected_root_exit_codes_and_json(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bundle, root = self._emit_single_leaf(d)
            # match → exit 0, ROOT-AUTHENTICITY: PASS; P0-B: safe-for-automation FALSE without a policy
            ok = self._run("verify", str(bundle), "--expected-root", root)
            self.assertEqual(ok.returncode, 0)
            self.assertIn("ROOT-AUTHENTICITY: PASS", ok.stdout)
            self.assertIn("safe-for-automation false", ok.stdout)
            # mismatch → exit 1, FAIL
            bad = self._run("verify", str(bundle), "--expected-root", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            self.assertEqual(bad.returncode, 1)
            self.assertIn("ROOT-AUTHENTICITY: FAIL", bad.stdout)
            # JSON contract: root_authenticity present with the five verdict keys
            js = self._run("verify", str(bundle), "--expected-root", root, "--json")
            obj = _json.loads(js.stdout)
            self.assertEqual(obj["root_authenticity"]["rootAuthenticity"], "PASS")
            # P0-B: root authenticated but no policy → NOT safe, with an explicit blocker
            self.assertFalse(obj["root_authenticity"]["safeForAutomation"])
            self.assertIn("POLICY_NOT_EVALUATED", obj["root_authenticity"]["automationBlockers"])
            for k in ("payloadSignature", "merkleConsistency", "rootAuthenticity",
                      "publicTransparency", "safeForAutomation", "automationBlockers"):
                self.assertIn(k, obj["root_authenticity"])

    def test_p0a_expected_tree_size_without_root_is_enforced_and_surfaced(self):
        # P0-A (audit 2026-07-13): --expected-tree-size must be enforced ON ITS OWN, never a silent no-op
        # gated on --expected-root, and surfaced as a machine-readable treeSizeExpectation object.
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bundle, _root = self._emit_single_leaf(d)   # single leaf → tree_size 1
            # (a) MATCH without --expected-root → exit 0, treeSizeExpectation PASS
            js = self._run("verify", str(bundle), "--expected-tree-size", "1", "--json")
            self.assertEqual(js.returncode, 0)
            obj = _json.loads(js.stdout)
            self.assertEqual(obj["treeSizeExpectation"]["status"], "PASS")
            self.assertEqual(obj["treeSizeExpectation"]["expected"], 1)
            self.assertEqual(obj["treeSizeExpectation"]["actual"], 1)
            # (b) MISMATCH without --expected-root → exit 1 (ENFORCED, not silently ignored)
            bad = self._run("verify", str(bundle), "--expected-tree-size", "999")
            self.assertEqual(bad.returncode, 1)
            self.assertIn("tree_size 1 != expected 999", bad.stdout)
            jbad = _json.loads(self._run("verify", str(bundle), "--expected-tree-size", "999", "--json").stdout)
            self.assertEqual(jbad["treeSizeExpectation"]["status"], "FAIL")
            # (c) flag absent → NOT_REQUESTED, actual still surfaced
            none = _json.loads(self._run("verify", str(bundle), "--json").stdout)
            self.assertEqual(none["treeSizeExpectation"]["status"], "NOT_REQUESTED")
            self.assertIsNone(none["treeSizeExpectation"]["expected"])
            self.assertEqual(none["treeSizeExpectation"]["actual"], 1)
            # (d) bool/float rejected at the CLI (argparse type=int rejects non-ints → exit 2)
            fl = self._run("verify", str(bundle), "--expected-tree-size", "1.0")
            self.assertEqual(fl.returncode, 2)

    def test_cli_malformed_json_error_path_carries_root_authenticity_key(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{ not valid json", encoding="utf-8")
            r = self._run("verify", str(bad), "--json")
            self.assertEqual(r.returncode, 2)
            obj = _json.loads(r.stdout)
            # audit L1: the error path must carry the key (None), never omit it (KeyError for integrators)
            self.assertIn("root_authenticity", obj)
            self.assertIsNone(obj["root_authenticity"])


class TestSummary(unittest.TestCase):
    def test_summary_three_states(self):
        orig, rewrap = _make_orig_and_coherent_rewrap()
        # not evaluated → NOT_EVALUATED, not safe
        s = root_authenticity_summary(verify_bundle(orig))
        self.assertEqual(s["rootAuthenticity"], "NOT_EVALUATED")
        self.assertFalse(s["safeForAutomation"])
        self.assertEqual(s["publicTransparency"], "NOT_EVALUATED")
        # authenticated → PASS + safe
        s = root_authenticity_summary(verify_bundle(orig, expected_root_b64=orig["merkle"]["root_b64"]))
        self.assertEqual(s["rootAuthenticity"], "PASS")
        # P0-B (audit 2026-07-13): root PASS alone is NOT automation-safe without a passing trust policy.
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_NOT_EVALUATED", s["automationBlockers"])
        # mismatched → FAIL, not safe, but signature + consistency still PASS
        s = root_authenticity_summary(verify_bundle(rewrap, expected_root_b64=orig["merkle"]["root_b64"]))
        self.assertEqual(s["rootAuthenticity"], "FAIL")
        self.assertEqual(s["payloadSignature"], "PASS")
        self.assertEqual(s["merkleConsistency"], "PASS")
        self.assertFalse(s["safeForAutomation"])

    def test_summary_folds_policy_trusted_root(self):
        orig, _ = _make_orig_and_coherent_rewrap()
        # AP-1 §5: root BYTES authenticated by the policy's trusted_roots → rootAuthenticity PASS.
        # A-P0-1 (3.1.3): bytes alone are NOT tree context — a naked root pin is ROOT_BYTES_ONLY and
        # never automation-safe (the 2→3-leaf relabel shares the root). Automation needs the atomic
        # (root, tree_size) authentication (trusted_checkpoints / --trusted-checkpoint / root+size pair).
        s = root_authenticity_summary(verify_bundle(orig), policy_authenticated_root=True,
                                      policy_ok=True, signer_trusted=True)
        self.assertEqual(s["rootAuthenticity"], "PASS")
        self.assertEqual(s["rootTrustLevel"], "ROOT_BYTES_ONLY")
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("TREE_CONTEXT_NOT_AUTHENTICATED", s["automationBlockers"])
        # with the atomic tree context authenticated, the same gates DO reach safe (positive control)
        s = root_authenticity_summary(verify_bundle(orig), policy_authenticated_root=True,
                                      policy_ok=True, signer_trusted=True,
                                      tree_context_authenticated=True)
        self.assertTrue(s["safeForAutomation"])

    def test_p0b_safe_for_automation_requires_passing_policy(self):
        # P0-B (audit 2026-07-13): safeForAutomation is a GLOBAL trust verdict. A crypto-valid, root-
        # authenticated receipt is NOT automation-safe unless a supplied trust policy PASSED with a real
        # signer pin. The former `policy_ok is not False` let policy_ok=None (no policy) through — the bug.
        orig, rewrap = _make_orig_and_coherent_rewrap()
        r = verify_bundle(orig, expected_root_b64=orig["merkle"]["root_b64"])  # crypto OK, root authenticated
        # (1) expected_root without any policy → NOT safe (POLICY_NOT_EVALUATED; since 3.1.3 a
        # root-bytes-only pin additionally reports TREE_CONTEXT_NOT_AUTHENTICATED, A-P0-1)
        s = root_authenticity_summary(r)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_NOT_EVALUATED", s["automationBlockers"])
        self.assertIn("TREE_CONTEXT_NOT_AUTHENTICATED", s["automationBlockers"])
        # (2) an explicitly FAILED policy → NOT safe (POLICY_FAILED)
        s = root_authenticity_summary(r, policy_ok=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_FAILED", s["automationBlockers"])
        # (3) AP-1 §5: a PASSING policy that pins no trusted signer → NOT safe (SIGNER_NOT_PINNED).
        # test_policy_without_signer_pin_never_sets_safe_true / test_untrusted_signer_forces_safe_false
        s = root_authenticity_summary(r, policy_ok=True, signer_trusted=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("SIGNER_NOT_PINNED", s["automationBlockers"])
        # (3b) test_policy_warning_forces_safe_false — signer pinned but a residual policy warning present
        s = root_authenticity_summary(r, policy_ok=True, signer_trusted=True, policy_warnings=["residual"])
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_WARNINGS_PRESENT", s["automationBlockers"])
        # (4) test_missing_required_anchor_forces_safe_false — a FAILED anchor gate blocks even a good policy
        s = root_authenticity_summary(r, policy_ok=True, signer_trusted=True, anchor_ok=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("ANCHOR_REQUIRED_FAILED", s["automationBlockers"])
        # (4b) required public-transparency / replay gates (forward-compat blockers)
        self.assertIn("PUBLIC_TRANSPARENCY_REQUIRED_FAILED",
                      root_authenticity_summary(r, policy_ok=True, signer_trusted=True,
                                                public_transparency_ok=False)["automationBlockers"])
        self.assertIn("REPLAY_BINDING_REQUIRED_FAILED",
                      root_authenticity_summary(r, policy_ok=True, signer_trusted=True,
                                                replay_ok=False)["automationBlockers"])
        # (5) test_all_required_gates_pass_sets_safe_true — passing policy + pinned signer + root +
        # anchor + ATOMIC tree context (A-P0-1: without it, bytes-only is never automation-safe)
        s = root_authenticity_summary(r, policy_ok=True, signer_trusted=True, anchor_ok=True,
                                      tree_context_authenticated=True)
        self.assertTrue(s["safeForAutomation"])
        self.assertEqual(s["automationBlockers"], [])
        # (6) crypto FAIL dominates → NOT safe (CRYPTO_FAILED), even with a passing policy
        rf = verify_bundle(rewrap, expected_root_b64=orig["merkle"]["root_b64"])   # root mismatch → crypto FAIL
        self.assertFalse(rf.ok)
        s = root_authenticity_summary(rf, policy_ok=True, signer_trusted=True)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("CRYPTO_FAILED", s["automationBlockers"])

    def test_ap1_automation_blockers_enumerate_every_false_reason(self):
        # §5.4 test_automation_blockers_enumerate_every_false_reason: a fully-failing state lists ALL reasons.
        orig, rewrap = _make_orig_and_coherent_rewrap()
        rf = verify_bundle(rewrap, expected_root_b64=orig["merkle"]["root_b64"])  # crypto FAIL + root FAIL
        s = root_authenticity_summary(rf, policy_ok=False, anchor_ok=False,
                                      public_transparency_ok=False, replay_ok=False)
        for b in ("CRYPTO_FAILED", "ROOT_NOT_AUTHENTICATED", "POLICY_FAILED",
                  "ANCHOR_REQUIRED_FAILED", "PUBLIC_TRANSPARENCY_REQUIRED_FAILED",
                  "REPLAY_BINDING_REQUIRED_FAILED"):
            self.assertIn(b, s["automationBlockers"])
        self.assertFalse(s["safeForAutomation"])


class TestPolicyAuthenticatedRoot(unittest.TestCase):
    def _policy(self, trusted):
        return load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
                            "merkle": {"require_authenticated_root": True, "trusted_roots": trusted}})

    def test_trusted_root_matches_passes_mismatch_fails(self):
        orig, rewrap = _make_orig_and_coherent_rewrap()
        pol = self._policy([orig["merkle"]["root_b64"]])
        good = evaluate_policy(orig, verify_bundle(orig), pol)
        self.assertTrue(good["policy_ok"])
        self.assertTrue(good["root_authenticated"])
        bad = evaluate_policy(rewrap, verify_bundle(rewrap), pol)
        self.assertFalse(bad["policy_ok"])
        self.assertFalse(bad["root_authenticated"])
        self.assertIn("coherent-rewrap", bad["reason"])

    def test_trusted_roots_without_require_flag_still_enforces(self):
        # A non-empty trusted_roots enforces on its own — a policy that pins roots but forgets the
        # boolean must NOT fail-open on a foreign root (6-lens review 2026-07-12).
        orig, rewrap = _make_orig_and_coherent_rewrap()
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
                          "merkle": {"trusted_roots": [orig["merkle"]["root_b64"]]}})
        self.assertTrue(evaluate_policy(orig, verify_bundle(orig), pol)["policy_ok"])
        bad = evaluate_policy(rewrap, verify_bundle(rewrap), pol)
        self.assertFalse(bad["policy_ok"], "trusted_roots alone must reject a foreign root (no fail-open)")

    def test_require_authenticated_root_without_any_source_fails(self):
        orig, _ = _make_orig_and_coherent_rewrap()
        pol = self._policy([])   # no trusted roots and no --expected-root supplied → cannot authenticate
        res = evaluate_policy(orig, verify_bundle(orig), pol)
        self.assertFalse(res["policy_ok"])

    def test_malformed_trusted_root_never_matches(self):
        from proofbundle.policy import PolicyError
        orig, _ = _make_orig_and_coherent_rewrap()
        # A-P0-5 §9.1 (3.1.3): a malformed pin is its OWN loud load error now, never a silent
        # never-matches — load_policy refuses it outright.
        with self.assertRaises(PolicyError):
            self._policy(["!!!not base64!!!"])
        # defense-in-depth: a raw dict that BYPASSED load_policy still never authenticates on the
        # evaluate layer (the silent-skip stays as the second net).
        raw = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
               "merkle": {"require_authenticated_root": True, "trusted_roots": ["!!!not base64!!!"]}}
        res = evaluate_policy(orig, verify_bundle(orig), raw)
        self.assertFalse(res["policy_ok"], "a malformed trusted_root must never authenticate (fail-closed)")

    def test_shipped_authenticated_root_profile_activates_protection(self):
        # Audit 2026-07-13 (§18a): a SHIPPED profile must actually activate the rewrap protection —
        # not only a bespoke inline test policy. strict-eval-authenticated-root-template-v1 sets
        # require_authenticated_root, so a relying party who loads it (and supplies the authenticated
        # root) is protected against the coherent rewrap.
        from proofbundle.policy_profiles import profile_path
        prof = load_policy(profile_path("strict-eval-authenticated-root-template-v1"))
        self.assertTrue(prof["merkle"]["require_authenticated_root"])
        orig, rewrap = _make_orig_and_coherent_rewrap()
        # with the authentic root trusted, orig's root authenticates; the rewrap's does not
        prof_trusted = dict(prof)
        prof_trusted["merkle"] = {**prof["merkle"], "trusted_roots": [orig["merkle"]["root_b64"]]}
        self.assertTrue(evaluate_policy(orig, verify_bundle(orig), prof_trusted)["root_authenticated"])
        self.assertFalse(evaluate_policy(rewrap, verify_bundle(rewrap), prof_trusted)["root_authenticated"])
        # and with NO root source at all, the profile fails closed (demands an authenticated root)
        res = evaluate_policy(orig, verify_bundle(orig), prof)
        self.assertFalse(res["root_authenticated"])

    def test_explain_lists_the_new_pins(self):
        root32 = base64.b64encode(b"\x0a" * 32).decode("ascii")   # A-P0-5: pins must be 32-byte roots
        lines = explain_policy(self._policy([root32]))
        joined = " ".join(lines).lower()
        self.assertIn("authenticated", joined)
        self.assertIn("trusted_roots", joined)


class TestAP3TreeSizeExpectation(unittest.TestCase):
    """AP-3 §7.2 — the expected-tree-size rest package: additive regressions for negative/zero/huge
    values, the non-integer CLI usage error, and the NOT_REQUESTED JSON status when the flag is absent.
    The core (tree-size checked INDEPENDENTLY of the root) is already proven in TestExpectedRootGate."""

    @staticmethod
    def _bundle_path():
        import json
        import os
        import tempfile
        b = emit_bundle(b"AP-3 tree-size", generate_signer())   # a real single-leaf receipt (tree_size 1)
        fd, p = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(b, f)
        return p

    def _verify(self, *extra):
        import contextlib
        import io
        import json
        from proofbundle.cli import main
        p = self._bundle_path()
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    rc = main(["verify", "--json", p, *extra])
                except SystemExit as exc:   # argparse usage errors sys.exit() instead of returning
                    rc = exc.code if isinstance(exc.code, int) else 2
        finally:
            import os
            os.unlink(p)
        data = None
        try:
            data = json.loads(out.getvalue())
        except ValueError:
            pass
        return rc, data, err.getvalue()

    def test_expected_tree_size_negative_fails(self):
        rc, data, err = self._verify("--expected-tree-size", "-1")
        self.assertEqual(rc, 1)                                  # crypto verdict FAIL, not a crash
        self.assertNotIn("Traceback", err)
        self.assertEqual(data["treeSizeExpectation"]["status"], "FAIL")
        self.assertEqual(data["treeSizeExpectation"]["expected"], -1)

    def test_expected_tree_size_zero_fails_or_matches_only_empty_tree(self):
        # a real 1-leaf receipt has tree_size 1, so an expectation of 0 must FAIL (0 could only match an
        # empty tree, which is not a producible receipt here).
        rc, data, _ = self._verify("--expected-tree-size", "0")
        self.assertEqual(rc, 1)
        self.assertEqual(data["treeSizeExpectation"]["status"], "FAIL")

    def test_expected_tree_size_huge_value_fails_cleanly(self):
        rc, data, err = self._verify("--expected-tree-size", "1" + "0" * 40)   # 10**40, absurdly large
        self.assertIn(rc, (1, 2))                                # a clean FAIL/usage exit, never a crash
        self.assertNotIn("Traceback", err)
        if data is not None:
            self.assertEqual(data["treeSizeExpectation"]["status"], "FAIL")

    def test_cli_expected_tree_size_non_integer_rejected_with_usage_error(self):
        rc, _, err = self._verify("--expected-tree-size", "1.5")
        self.assertEqual(rc, 2)                                  # argparse usage error
        self.assertIn("invalid int value", err)

    def test_json_tree_size_expectation_not_requested_when_flag_absent(self):
        rc, data, _ = self._verify()
        self.assertEqual(rc, 0)
        tse = data["treeSizeExpectation"]
        self.assertEqual(tse["status"], "NOT_REQUESTED")
        self.assertIsNone(tse["expected"])
        self.assertEqual(tse["actual"], 1)


class TestAP1PreLandReviewRegressions(unittest.TestCase):
    """Regressions for the pre-land L2 review findings on the safeForAutomation signer gate."""

    def test_decision_maker_only_policy_does_not_fake_a_trusted_signer_on_verify_path(self):
        # L2-F1 (HIGH, fail-open): a v0.2 policy that pins ONLY decision_receipt.trusted_decision_makers
        # (a DIFFERENT key than the bundle signer) must NOT yield safeForAutomation:true on the verify
        # (bundle) path — evaluate_policy never matches the bundle signer against trusted_decision_makers
        # (that is the verify-decision path), so the signer was authorised by nobody. Before the fix, the
        # absence of the 'attributes to nobody' warning (which counts trusted_decision_makers as a pin)
        # made signer_trusted=True → SAFE_FOR_AUTOMATION: YES against an unpinned signer.
        import contextlib
        import io
        import json
        import os
        import tempfile

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        from proofbundle.cli import main
        from proofbundle.emit import emit_bundle, generate_signer

        signer_a = generate_signer()                     # the bundle's actual signer
        key_b = _b64(generate_signer().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        bundle = emit_bundle(b"L2-F1 decision-maker-only policy", signer_a)
        policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/dm-only",
                  "allowed_schema_versions": ["proofbundle/v0.1"],
                  "signature": {"allowed_algs": ["ed25519"]},
                  "merkle": {"trusted_roots": [bundle["merkle"]["root_b64"]]},   # root authenticates legitimately
                  "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": key_b}]}}
        bfd, bpath = tempfile.mkstemp(suffix=".json")
        pfd, ppath = tempfile.mkstemp(suffix=".policy.json")
        try:
            with os.fdopen(bfd, "w") as f:
                json.dump(bundle, f)
            with os.fdopen(pfd, "w") as f:
                json.dump(policy, f)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main(["verify", "--json", bpath, "--policy", ppath])
            data = json.loads(out.getvalue())
        finally:
            os.unlink(bpath)
            os.unlink(ppath)
        ra = data["root_authenticity"]
        self.assertFalse(ra["safeForAutomation"],
                         "a decision-maker-only policy must not fake a trusted signer on the verify path")
        self.assertIn("SIGNER_NOT_PINNED", ra["automationBlockers"])

    def test_allowed_issuers_matching_signer_still_sets_safe_true(self):
        # regression-guard the other direction: a real eval policy that pins the matching signer + an
        # atomically authenticated (root, tree_size) STILL yields safeForAutomation:true (the fix must
        # not over-tighten). Since A-P0-1 the atomic pair (--expected-root AND --expected-tree-size,
        # or a trusted checkpoint) is required — a policy trusted_roots pin alone is bytes-only.
        import contextlib
        import io
        import json
        import os
        import tempfile

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        from proofbundle.cli import main
        from proofbundle.emit import emit_bundle, generate_signer

        signer = generate_signer()
        pub = _b64(signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        bundle = emit_bundle(b"L2-F1 positive control", signer)
        root = bundle["merkle"]["root_b64"]
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "org/pinned",
                  "allowed_schema_versions": ["proofbundle/v0.1"],
                  "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
                  "allowed_issuers": [{"public_key_b64": pub}],
                  "merkle": {"trusted_roots": [root]}}
        bfd, bpath = tempfile.mkstemp(suffix=".json")
        pfd, ppath = tempfile.mkstemp(suffix=".policy.json")
        try:
            with os.fdopen(bfd, "w") as f:
                json.dump(bundle, f)
            with os.fdopen(pfd, "w") as f:
                json.dump(policy, f)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main(["verify", "--json", bpath, "--policy", ppath,
                      "--expected-root", root, "--expected-tree-size", "1"])
            data = json.loads(out.getvalue())
        finally:
            os.unlink(bpath)
            os.unlink(ppath)
        ra = data["root_authenticity"]
        self.assertTrue(ra["safeForAutomation"], f"a pinned matching signer must stay safe: {ra}")
        self.assertEqual(ra["automationBlockers"], [])
        self.assertEqual(ra["rootTrustLevel"], "ROOT_AND_TREE_SIZE_PINNED")

    def test_pinned_signer_but_requires_overlay_is_template_not_instantiated(self):
        # L2 pre-land audit F1: a policy that DOES pin+match the signer but still carries
        # requiresIdentityOverlay:true (an un-cleared template-lifecycle flag) must be safeForAutomation:false
        # with the HONEST blocker TEMPLATE_NOT_INSTANTIATED — never the factually-wrong SIGNER_NOT_PINNED (a
        # signer IS pinned here). Fail-closed direction; the point is honest attribution.
        import contextlib
        import io
        import json
        import os
        import tempfile

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        from proofbundle.cli import main
        from proofbundle.emit import emit_bundle, generate_signer

        signer = generate_signer()
        pub = _b64(signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        bundle = emit_bundle(b"L2-F1 template flag with real pin", signer)
        root = bundle["merkle"]["root_b64"]
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "org/half-baked",
                  "requiresIdentityOverlay": True,   # left set — the un-cleared template flag
                  "allowed_schema_versions": ["proofbundle/v0.1"],
                  "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
                  "allowed_issuers": [{"public_key_b64": pub}],   # a REAL signer IS pinned + matches
                  "merkle": {"trusted_roots": [root]}}
        bfd, bpath = tempfile.mkstemp(suffix=".json")
        pfd, ppath = tempfile.mkstemp(suffix=".policy.json")
        try:
            with os.fdopen(bfd, "w") as f:
                json.dump(bundle, f)
            with os.fdopen(pfd, "w") as f:
                json.dump(policy, f)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main(["verify", "--json", bpath, "--policy", ppath])
            data = json.loads(out.getvalue())
        finally:
            os.unlink(bpath)
            os.unlink(ppath)
        ra = data["root_authenticity"]
        self.assertFalse(ra["safeForAutomation"])
        self.assertIn("TEMPLATE_NOT_INSTANTIATED", ra["automationBlockers"])
        self.assertNotIn("SIGNER_NOT_PINNED", ra["automationBlockers"])


class TestAP1S54NamedRegressions(unittest.TestCase):
    """AP-1 §5.4 — the mandatory safeForAutomation regressions as individually-named tests. The unit
    matrix is also covered inside TestP0BSafeForAutomation; these give each §5.4 name a discrete home
    and add the two end-to-end cases (expiry, human⟷JSON parity) that only the CLI path exercises."""

    def _authenticated_result(self):
        orig, _ = _make_orig_and_coherent_rewrap()
        return verify_bundle(orig, expected_root_b64=orig["merkle"]["root_b64"])

    def test_expected_root_without_policy_never_sets_safe_true(self):
        s = root_authenticity_summary(self._authenticated_result())
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_NOT_EVALUATED", s["automationBlockers"])
        # A-P0-1 (3.1.3): the root-only expectation additionally lacks the atomic tree context
        self.assertIn("TREE_CONTEXT_NOT_AUTHENTICATED", s["automationBlockers"])

    def test_policy_none_never_sets_safe_true(self):
        self.assertFalse(root_authenticity_summary(self._authenticated_result(),
                                                   policy_ok=None)["safeForAutomation"])

    def test_policy_without_signer_pin_never_sets_safe_true(self):
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True, signer_trusted=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("SIGNER_NOT_PINNED", s["automationBlockers"])

    def test_policy_warning_forces_safe_false(self):
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True,
                                      signer_trusted=True, policy_warnings=["residual"])
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_WARNINGS_PRESENT", s["automationBlockers"])

    def test_expired_policy_forces_safe_false(self):
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True,
                                      signer_trusted=True, policy_expired=True)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_EXPIRED", s["automationBlockers"])

    def test_untrusted_signer_forces_safe_false(self):
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True, signer_trusted=False)
        self.assertFalse(s["safeForAutomation"])

    def test_missing_required_anchor_forces_safe_false(self):
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True,
                                      signer_trusted=True, anchor_ok=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("ANCHOR_REQUIRED_FAILED", s["automationBlockers"])

    def test_missing_required_public_transparency_forces_safe_false(self):
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True,
                                      signer_trusted=True, public_transparency_ok=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("PUBLIC_TRANSPARENCY_REQUIRED_FAILED", s["automationBlockers"])

    def test_missing_required_nonce_forces_safe_false(self):
        # a required replay/nonce binding gate that FAILED forces safe false (forward-compat blocker)
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True,
                                      signer_trusted=True, replay_ok=False)
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("REPLAY_BINDING_REQUIRED_FAILED", s["automationBlockers"])

    def test_all_required_gates_pass_sets_safe_true(self):
        # mutation-gated (§15): the ONE true-path — passing policy + pinned signer + authenticated root +
        # ATOMIC tree context (A-P0-1) + a satisfied anchor gate, no warnings, not expired. Flip any
        # single input and safe must go false.
        s = root_authenticity_summary(self._authenticated_result(), policy_ok=True, signer_trusted=True,
                                      anchor_ok=True, policy_expired=False,
                                      tree_context_authenticated=True)
        self.assertTrue(s["safeForAutomation"])
        self.assertEqual(s["automationBlockers"], [])

    def test_automation_blockers_enumerate_every_false_reason(self):
        orig, rewrap = _make_orig_and_coherent_rewrap()
        rf = verify_bundle(rewrap, expected_root_b64=orig["merkle"]["root_b64"])   # crypto + root FAIL
        s = root_authenticity_summary(rf, policy_ok=False, anchor_ok=False,
                                      public_transparency_ok=False, replay_ok=False)
        for b in ("CRYPTO_FAILED", "ROOT_NOT_AUTHENTICATED", "POLICY_FAILED",
                  "ANCHOR_REQUIRED_FAILED", "PUBLIC_TRANSPARENCY_REQUIRED_FAILED",
                  "REPLAY_BINDING_REQUIRED_FAILED"):
            self.assertIn(b, s["automationBlockers"])

    def test_human_and_json_safe_flag_never_disagree(self):
        # AP-1 §5.3 / Iteration F: the human SAFE_FOR_AUTOMATION line and the JSON flag are derived from
        # the same summary, so across a range of scenarios they must always agree. Exercised via the real
        # CLI on a signed eval receipt, with and without a pinning policy + matching --expected-root.
        import contextlib
        import io
        import json
        import os
        import tempfile

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        from proofbundle.cli import main
        from proofbundle.emit import generate_signer as _gen
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.policy_profiles import instantiate_template

        def _run(argv):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main(argv)
            return out.getvalue()

        signer = _gen()
        pub = base64.b64encode(
            signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        claim, _ = build_eval_claim(
            suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
            score="0.9", n=10, model_id="m", dataset_id="d", issuer="placeholder",
            timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
        bundle = emit_eval_receipt(claim, signer)
        root_b64 = bundle["merkle"]["root_b64"]

        pinned = instantiate_template("strict-eval-template-v1", issuer_keys=[pub], policy_id="org/e2e-v1")
        expired = instantiate_template("strict-eval-template-v1", issuer_keys=[pub], policy_id="org/e2e-exp-v1",
                                       valid_until="2020-01-01T00:00:00Z")

        tmp = []
        try:
            def _w(obj, suffix):
                fd, p = tempfile.mkstemp(suffix=suffix)
                with os.fdopen(fd, "w") as f:
                    json.dump(obj, f)
                tmp.append(p)
                return p
            bpath = _w(bundle, ".json")
            ppath = _w(pinned, ".policy.json")
            xpath = _w(expired, ".policy.json")

            scenarios = [
                ["verify", bpath],                                                       # no policy → NO
                ["verify", bpath, "--policy", ppath],                                    # pinned but no root → NO
                ["verify", bpath, "--policy", ppath, "--expected-root", root_b64],       # all gates pass → YES
                ["verify", bpath, "--policy", xpath, "--expected-root", root_b64],       # expired → NO
            ]
            for argv in scenarios:
                human = _run(argv + [])
                data = json.loads(_run(argv + ["--json"]))
                json_safe = data["root_authenticity"]["safeForAutomation"]
                human_yes = "SAFE_FOR_AUTOMATION: YES" in human
                human_no = "SAFE_FOR_AUTOMATION: NO" in human
                self.assertTrue(human_yes ^ human_no, f"exactly one verdict line expected for {argv}")
                self.assertEqual(json_safe, human_yes, f"human/JSON safe flag disagree for {argv}")
        finally:
            for p in tmp:
                os.unlink(p)


if __name__ == "__main__":
    unittest.main()
