"""A-P0-2 / A-P0-4 / A-P0-5 (3.1.3) — policy lifecycle on the EVAL path, policyPurpose,
and hardened policy metadata.

A-P0-2: the decision path already rejected an expired policy (exit 3); the EVAL path did not —
an expired eval policy still produced `POLICY: OK` / exit 0 while only `safeForAutomation`
went false. Lifecycle (template / not-before / expiry / purpose) is now part of the policy
EVALUATION itself on both paths: `POLICY: FAIL`, exit 3. Historical verification never happens
silently — only via an explicit `--verification-time`, labelled HISTORICAL in the output.

A-P0-4: `policyPurpose` binds a policy to ONE verifier path (eval / decision / outcome /
trust-pack / public-transparency); the wrong purpose is exit 3.

A-P0-5: trusted_roots entries are hard-validated (base64, 32 bytes) with their OWN error;
reserved template metadata cannot be overridden by an instantiate overlay; deploymentReady
is derived, never asserted.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import (
    PolicyError, evaluate_policy, lint_policy, load_policy,
)
from proofbundle.policy_profiles import instantiate_template

POLICY_SCHEMA = "proofbundle/trust-policy/v0.1"


def _pub_b64(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _receipt():
    """A signed eval receipt on disk; returns (path, bundle, signer_public_key_b64)."""
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
    bundle = emit_eval_receipt(claim, signer)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path, bundle, bundle["signature"]["public_key_b64"]


def _policy_file(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


def _base_policy(**over) -> dict:
    p = {"schema": POLICY_SCHEMA, "policy_id": "lifecycle-test"}
    p.update(over)
    return p


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestExpiredEvalPolicy(unittest.TestCase):
    """§6 — the eval path takes over the SAME lifecycle checks as the decision path."""

    def test_expired_eval_policy_fails(self):
        path, _bundle, _pub = _receipt()
        pol = _policy_file(_base_policy(valid_until="2020-01-01T00:00:00Z",
                                        merkle={"required_hash_alg": "sha256-rfc6962"}))
        try:
            rc, out, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3, out)
        self.assertIn("POLICY: FAIL", out)

    def test_current_mode_rejects_expired_policy(self):
        from proofbundle.bundle import verify_bundle
        path, bundle, _pub = _receipt()
        os.unlink(path)
        pol = load_policy(_base_policy(valid_until="2020-01-01T00:00:00Z",
                                       merkle={"required_hash_alg": "sha256-rfc6962"}))
        res = evaluate_policy(bundle, verify_bundle(bundle), pol)
        self.assertFalse(res["policy_ok"])
        self.assertTrue(any(c["name"] == "policy:not_expired" and not c["ok"] for c in res["checks"]))

    def test_not_yet_valid_eval_policy_fails(self):
        path, _bundle, _pub = _receipt()
        pol = _policy_file(_base_policy(valid_from="2099-01-01T00:00:00Z",
                                        merkle={"required_hash_alg": "sha256-rfc6962"}))
        try:
            rc, out, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3, out)
        self.assertIn("POLICY: FAIL", out)

    def test_raw_template_fails_eval_policy(self):
        # policy:not_template on the eval path (parity with the decision-path AP-2 sibling gate)
        from proofbundle.bundle import verify_bundle
        path, bundle, _pub = _receipt()
        os.unlink(path)
        pol = load_policy(_base_policy(requiresIdentityOverlay=True,
                                       merkle={"required_hash_alg": "sha256-rfc6962"}))
        res = evaluate_policy(bundle, verify_bundle(bundle), pol)
        self.assertFalse(res["policy_ok"])
        self.assertTrue(any(c["name"] == "policy:not_template" and not c["ok"] for c in res["checks"]))

    def test_exit_code_3_on_policy_lifecycle_failure(self):
        # exit-code contract: a lifecycle failure is exit 3 (policy), never 1 (crypto) or 0.
        path, _bundle, _pub = _receipt()
        pol = _policy_file(_base_policy(valid_until="2020-01-01T00:00:00Z"))
        try:
            rc, out, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3)
        self.assertIn("CRYPTO: OK", out)

    def test_expired_decision_policy_fails(self):
        signer = generate_signer()
        env = _decision_env(signer)
        pol = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "dec-exp",
               "valid_until": "2020-01-01T00:00:00Z",
               "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": _pub_b64(signer)}]}}
        res = verify_decision_receipt(env, base64.b64decode(_pub_b64(signer)),
                                      policy=load_policy(pol))
        self.assertFalse(res["policy_ok"])


class TestHistoricalVerification(unittest.TestCase):
    """§6.3 — historical verification only via an explicit --verification-time, labelled output."""

    def _expired_policy_file(self):
        return _policy_file(_base_policy(valid_until="2026-01-01T00:00:00Z",
                                         merkle={"required_hash_alg": "sha256-rfc6962"}))

    def test_historical_verification_requires_explicit_time(self):
        # WITHOUT the flag, the same expired policy is exit 3 — no silent backdating.
        path, _bundle, _pub = _receipt()
        pol = self._expired_policy_file()
        try:
            rc, _out, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3)

    def test_historical_mode_labels_and_passes(self):
        path, _bundle, _pub = _receipt()
        pol = self._expired_policy_file()
        try:
            rc, out, _ = _run(["verify", path, "--policy", pol,
                               "--verification-time", "2025-06-01T00:00:00Z"])
            rcj, outj, _ = _run(["verify", "--json", path, "--policy", pol,
                                 "--verification-time", "2025-06-01T00:00:00Z"])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 0, out)
        self.assertIn("VERIFICATION_TIME: HISTORICAL", out)
        self.assertIn("CURRENT_POLICY_STATUS: EXPIRED", out)
        self.assertIn("HISTORICAL_POLICY_STATUS: PASS", out)
        data = json.loads(outj)
        self.assertEqual(rcj, 0)
        vt = data["verification_time"]
        self.assertEqual(vt["mode"], "HISTORICAL")
        self.assertEqual(vt["current_policy_status"], "EXPIRED")
        self.assertEqual(vt["historical_policy_status"], "PASS")
        # an expired-today policy is NEVER automation-safe, even when historically valid
        self.assertFalse(data["root_authenticity"]["safeForAutomation"])
        self.assertIn("POLICY_EXPIRED", data["root_authenticity"]["automationBlockers"])

    def test_verification_time_without_policy_is_usage_error(self):
        path, _bundle, _pub = _receipt()
        try:
            rc, _out, _ = _run(["verify", path, "--verification-time", "2025-06-01T00:00:00Z"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)

    def test_verification_time_malformed_is_usage_error(self):
        path, _bundle, _pub = _receipt()
        pol = self._expired_policy_file()
        try:
            rc, _out, _ = _run(["verify", path, "--policy", pol,
                                "--verification-time", "not-a-time"])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 2)


def _decision_env(signer):
    """A minimal valid decision receipt DSSE envelope signed by ``signer``."""
    predicate = {
        "schemaVersion": "0.1.0",
        "decisionId": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "decisionType": "preActionAuthorization",
        "decidedAt": "2026-07-13T00:00:00Z",
        "decisionMaker": {"id": "https://example.org/gate/v1"},
        "agent": {"id": "agent://example/agent"},
        "principal": {"id": "workload://example/principal"},
        "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
        "inputSnapshot": [{"name": "input", "digest": {"sha256": "0" * 64}}],
        "policyBoundary": {"policyEngine": "opa", "policyId": "https://example.org/policy/v1",
                           "policyDigest": {"sha256": "0" * 64}, "decisionPath": "data.example.allow"},
        "evidenceRefs": [],
        "decision": {"verdict": "DENY", "reasonCodes": ["example.reason"]},
    }
    return emit_decision_receipt(predicate, signer, strict=False)


class TestPolicyPurpose(unittest.TestCase):
    """§8 — a policy is bound to ONE verifier path; the wrong purpose is a policy failure."""

    def test_eval_rejects_decision_policy(self):
        path, _bundle, _pub = _receipt()
        pol = _policy_file({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "dec-purpose",
                            "policyPurpose": "decision",
                            "merkle": {"required_hash_alg": "sha256-rfc6962"}})
        try:
            rc, out, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3, out)
        self.assertIn("POLICY: FAIL", out)

    def test_eval_rejects_every_foreign_purpose(self):
        from proofbundle.bundle import verify_bundle
        path, bundle, _pub = _receipt()
        os.unlink(path)
        for purpose in ("decision", "outcome", "trust-pack", "public-transparency"):
            with self.subTest(purpose=purpose):
                pol = load_policy(_base_policy(policyPurpose=purpose))
                res = evaluate_policy(bundle, verify_bundle(bundle), pol)
                self.assertFalse(res["policy_ok"])
                self.assertTrue(any(c["name"] == "policy:purpose" and not c["ok"]
                                    for c in res["checks"]))

    def test_eval_purpose_matching_passes(self):
        from proofbundle.bundle import verify_bundle
        path, bundle, _pub = _receipt()
        os.unlink(path)
        pol = load_policy(_base_policy(policyPurpose="eval",
                                       merkle={"required_hash_alg": "sha256-rfc6962"}))
        res = evaluate_policy(bundle, verify_bundle(bundle), pol)
        self.assertTrue(res["policy_ok"])
        self.assertTrue(any(c["name"] == "policy:purpose" and c["ok"] for c in res["checks"]))

    def test_decision_rejects_eval_policy(self):
        signer = generate_signer()
        env = _decision_env(signer)
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "eval-on-dec",
                           "policyPurpose": "eval",
                           "decision_receipt": {"trusted_decision_makers":
                                                [{"public_key_b64": _pub_b64(signer)}]}})
        res = verify_decision_receipt(env, base64.b64decode(_pub_b64(signer)), policy=pol)
        self.assertFalse(res["policy_ok"])

    def test_decision_purpose_matching_passes(self):
        signer = generate_signer()
        env = _decision_env(signer)
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "dec-on-dec",
                           "policyPurpose": "decision",
                           "decision_receipt": {"trusted_decision_makers":
                                                [{"public_key_b64": _pub_b64(signer)}]}})
        res = verify_decision_receipt(env, base64.b64decode(_pub_b64(signer)), policy=pol)
        self.assertTrue(res["policy_ok"], res["errors"])

    def test_purpose_unknown_fails(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(policyPurpose="benchmark"))
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(policyPurpose=True))

    def test_purpose_missing_fails_in_strict_mode(self):
        pol = load_policy(_base_policy(allowed_issuers=[
            {"public_key_b64": _pub_b64(generate_signer())}]))
        res = lint_policy(pol, strict=True)
        self.assertFalse(res["ok"])
        self.assertTrue(any("policyPurpose" in e for e in res["errors"]))
        # and WITH a purpose the same policy passes strict lint
        pol2 = load_policy(_base_policy(policyPurpose="eval", allowed_issuers=[
            {"public_key_b64": _pub_b64(generate_signer())}]))
        self.assertTrue(lint_policy(pol2, strict=True)["ok"], lint_policy(pol2, strict=True))


class TestPolicyMetadataHardening(unittest.TestCase):
    """§9 — hard root validation, reserved metadata, derived deploymentReady."""

    def setUp(self):
        self.pub = _pub_b64(generate_signer())

    def test_invalid_base64_root_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            load_policy(_base_policy(merkle={"trusted_roots": ["!!!not base64!!!"]}))
        self.assertIn("trusted_roots", str(ctx.exception))

    def test_wrong_length_root_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            load_policy(_base_policy(merkle={"trusted_roots": ["QQ=="]}))   # 1 byte, not 32
        self.assertIn("32", str(ctx.exception))

    def test_checkpoint_entry_unknown_field_fails(self):
        entry = {"origin": "log.example", "root": base64.b64encode(b"\x01" * 32).decode(),
                 "treeSize": 1, "hashAlg": "sha256-rfc6962", "checkpointSigner": "x+00000000+QQ==",
                 "signature": "QQ==", "surprise": 1}
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                         "merkle": {"trusted_checkpoints": [entry]}})

    def test_checkpoint_entry_missing_required_field_fails(self):
        entry = {"origin": "log.example", "treeSize": 1}
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                         "merkle": {"trusted_checkpoints": [entry]}})

    def test_contradictory_metadata_fails(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(deploymentReady=True, requiresIdentityOverlay=True))

    def test_overlay_cannot_set_deployment_ready(self):
        with self.assertRaises(PolicyError):
            instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                 policy_id="org/x", overlay={"deploymentReady": True})

    def test_overlay_cannot_clear_requires_identity_overlay(self):
        with self.assertRaises(PolicyError):
            instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                 policy_id="org/x", overlay={"requiresIdentityOverlay": False})

    def test_overlay_cannot_touch_other_reserved_metadata(self):
        for key, val in (("policyPurpose", "decision"), ("generatedFromTemplate", "spoof"),
                         ("schema", "proofbundle/trust-policy/v0.2")):
            with self.subTest(reserved=key):
                with self.assertRaises(PolicyError):
                    instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                         policy_id="org/x", overlay={key: val})

    def test_derived_deployment_ready_only(self):
        # deploymentReady is DERIVED from the final instance: an expired lifecycle can never be
        # deployment-ready, and the instance records its template provenance.
        inst = instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                    policy_id="org/exp", valid_until="2020-01-01T00:00:00Z")
        self.assertIs(inst["deploymentReady"], False)
        fresh = instantiate_template("strict-eval-template-v1", issuer_keys=[self.pub],
                                     policy_id="org/ok")
        self.assertIs(fresh["deploymentReady"], True)
        self.assertEqual(fresh["generatedFromTemplate"], "strict-eval-template-v1")
        self.assertEqual(fresh["policyPurpose"], "eval")

    def test_templates_carry_purpose(self):
        from proofbundle.policy_profiles import list_profiles, profile_path
        expected = {"decision-receipt-template-v1": "decision"}
        for name in list_profiles():
            pol = load_policy(profile_path(name))
            self.assertEqual(pol.get("policyPurpose"), expected.get(name, "eval"),
                             f"{name} must declare its policyPurpose")


class TestDecisionAudNonceRegression(unittest.TestCase):
    """§7 — A-P0-3 closed in 3.1.2; these pin the named fail-closed vectors permanently."""

    def setUp(self):
        self.signer = generate_signer()
        self.pub = base64.b64decode(_pub_b64(self.signer))

    def _env(self, validity=None):
        predicate = {
            "schemaVersion": "0.1.0",
            "decisionId": "urn:uuid:00000000-0000-0000-0000-000000000002",
            "decisionType": "preActionAuthorization",
            "decidedAt": "2026-07-13T00:00:00Z",
            "decisionMaker": {"id": "https://example.org/gate/v1"},
            "agent": {"id": "agent://example/agent"},
            "principal": {"id": "workload://example/principal"},
            "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
            "inputSnapshot": [{"name": "input", "digest": {"sha256": "0" * 64}}],
            "policyBoundary": {"policyEngine": "opa", "policyId": "https://example.org/policy/v1",
                               "policyDigest": {"sha256": "0" * 64},
                               "decisionPath": "data.example.allow"},
            "evidenceRefs": [],
            "decision": {"verdict": "ALLOW", "reasonCodes": ["example.reason"]},
        }
        if validity is not None:
            predicate["validity"] = validity
        return emit_decision_receipt(predicate, self.signer, strict=False)

    def test_required_audience_without_validity_fails(self):
        res = verify_decision_receipt(self._env(), self.pub, expected_audience="rp.example")
        self.assertIs(res["audience_ok"], False)
        self.assertFalse(res["ok"])

    def test_required_nonce_without_validity_fails(self):
        res = verify_decision_receipt(self._env(), self.pub, expected_nonce="n-1")
        self.assertIs(res["nonce_ok"], False)
        self.assertFalse(res["ok"])

    def test_audience_mismatch_fails(self):
        res = verify_decision_receipt(self._env({"audience": ["other.example"], "nonce": "n-1"}),
                                      self.pub, expected_audience="rp.example")
        self.assertIs(res["audience_ok"], False)

    def test_nonce_mismatch_fails(self):
        res = verify_decision_receipt(self._env({"audience": ["rp.example"], "nonce": "other"}),
                                      self.pub, expected_nonce="n-1")
        self.assertIs(res["nonce_ok"], False)

    def test_audience_and_nonce_match_pass(self):
        res = verify_decision_receipt(self._env({"audience": ["rp.example"], "nonce": "n-1"}),
                                      self.pub, expected_audience="rp.example", expected_nonce="n-1")
        self.assertIs(res["audience_ok"], True)
        self.assertIs(res["nonce_ok"], True)
        self.assertTrue(res["ok"])

    def test_empty_audience_fails(self):
        res = verify_decision_receipt(self._env({"audience": [], "nonce": "n-1"}),
                                      self.pub, expected_audience="rp.example")
        self.assertIs(res["audience_ok"], False)

    def test_empty_nonce_fails(self):
        res = verify_decision_receipt(self._env({"audience": ["rp.example"], "nonce": ""}),
                                      self.pub, expected_nonce="n-1")
        self.assertIs(res["nonce_ok"], False)

    def test_wrong_type_audience_fails(self):
        res = verify_decision_receipt(self._env({"audience": "rp.example", "nonce": "n-1"}),
                                      self.pub, expected_audience="rp.example")
        self.assertIs(res["audience_ok"], False)

    def test_wrong_type_nonce_fails(self):
        res = verify_decision_receipt(self._env({"audience": ["rp.example"], "nonce": 42}),
                                      self.pub, expected_nonce="42")
        self.assertIs(res["nonce_ok"], False)

    # NOTE (§7.3 expired_validity / future_not_before): decision-receipt/v0.1 `validity` carries
    # ONLY audience+nonce (schemas/decision-receipt-v0.1.schema.json) — there is no time window
    # inside the predicate to expire. Lifecycle time-windowing lives on the POLICY
    # (valid_from/valid_until, enforced fail-closed on both paths since 3.1.3, see
    # TestExpiredEvalPolicy). A predicate-level validity window would be a format change
    # (next breaking version, §17.3 ADR package).


if __name__ == "__main__":
    unittest.main()
