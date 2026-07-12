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
            # match → exit 0, ROOT-AUTHENTICITY: PASS, safe-for-automation true
            ok = self._run("verify", str(bundle), "--expected-root", root)
            self.assertEqual(ok.returncode, 0)
            self.assertIn("ROOT-AUTHENTICITY: PASS", ok.stdout)
            self.assertIn("safe-for-automation true", ok.stdout)
            # mismatch → exit 1, FAIL
            bad = self._run("verify", str(bundle), "--expected-root", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            self.assertEqual(bad.returncode, 1)
            self.assertIn("ROOT-AUTHENTICITY: FAIL", bad.stdout)
            # JSON contract: root_authenticity present with the five verdict keys
            js = self._run("verify", str(bundle), "--expected-root", root, "--json")
            obj = _json.loads(js.stdout)
            self.assertEqual(obj["root_authenticity"]["rootAuthenticity"], "PASS")
            self.assertTrue(obj["root_authenticity"]["safeForAutomation"])
            for k in ("payloadSignature", "merkleConsistency", "rootAuthenticity",
                      "publicTransparency", "safeForAutomation"):
                self.assertIn(k, obj["root_authenticity"])

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
        self.assertTrue(s["safeForAutomation"])
        # mismatched → FAIL, not safe, but signature + consistency still PASS
        s = root_authenticity_summary(verify_bundle(rewrap, expected_root_b64=orig["merkle"]["root_b64"]))
        self.assertEqual(s["rootAuthenticity"], "FAIL")
        self.assertEqual(s["payloadSignature"], "PASS")
        self.assertEqual(s["merkleConsistency"], "PASS")
        self.assertFalse(s["safeForAutomation"])

    def test_summary_folds_policy_trusted_root(self):
        orig, _ = _make_orig_and_coherent_rewrap()
        s = root_authenticity_summary(verify_bundle(orig), policy_authenticated_root=True)
        self.assertEqual(s["rootAuthenticity"], "PASS")
        self.assertTrue(s["safeForAutomation"])

    def test_safe_for_automation_false_when_policy_or_anchor_fails(self):
        # §6.3: safeForAutomation requires root authenticity AND policy. A failing policy/anchor gate
        # makes it false even when the root itself authenticated (6-lens review 2026-07-12).
        orig, _ = _make_orig_and_coherent_rewrap()
        r = verify_bundle(orig, expected_root_b64=orig["merkle"]["root_b64"])  # root authenticated
        self.assertTrue(root_authenticity_summary(r)["safeForAutomation"])
        self.assertFalse(root_authenticity_summary(r, policy_ok=False)["safeForAutomation"])
        self.assertFalse(root_authenticity_summary(r, anchor_ok=False)["safeForAutomation"])
        self.assertTrue(root_authenticity_summary(r, policy_ok=True)["safeForAutomation"])


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
        orig, _ = _make_orig_and_coherent_rewrap()
        pol = self._policy(["!!!not base64!!!"])
        res = evaluate_policy(orig, verify_bundle(orig), pol)
        self.assertFalse(res["policy_ok"], "a malformed trusted_root must never authenticate (fail-closed)")

    def test_shipped_authenticated_root_profile_activates_protection(self):
        # Audit 2026-07-13 (§18a): a SHIPPED profile must actually activate the rewrap protection —
        # not only a bespoke inline test policy. strict-eval-authenticated-root-v1 sets
        # require_authenticated_root, so a relying party who loads it (and supplies the authenticated
        # root) is protected against the coherent rewrap.
        from proofbundle.policy_profiles import profile_path
        prof = load_policy(profile_path("strict-eval-authenticated-root-v1"))
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
        lines = explain_policy(self._policy(["AAAA"]))
        joined = " ".join(lines).lower()
        self.assertIn("authenticated", joined)
        self.assertIn("trusted_roots", joined)


if __name__ == "__main__":
    unittest.main()
