"""WP-B3 — trust policy v0.1 + `verify --policy`.

A relying party's trust decision is first-class, machine-readable, fail-closed and offline. Without a
policy `verify` makes NO trust decision (POLICY: NOT_EVALUATED); with one, a policy failure is exit 3,
distinct from a crypto failure (exit 1). A malformed policy or an aud/policy ambiguity is exit 2.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import PolicyError, evaluate_policy, load_policy

POLICY_SCHEMA = "proofbundle/trust-policy/v0.1"


def _receipt(*, assurance_level="reproduced", prereg=None, timestamp="2026-07-09T10:00:00Z"):
    """A signed eval receipt; returns (path, signer_public_key_b64)."""
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp=timestamp, assurance_level=assurance_level,
        prereg_sha256=prereg)
    bundle = emit_eval_receipt(claim, signer)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path, bundle["signature"]["public_key_b64"]


def _policy_file(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


def _base_policy(**over) -> dict:
    p = {"schema": POLICY_SCHEMA, "policy_id": "test-policy"}
    p.update(over)
    return p


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


class TestLoadPolicyFailClosed(unittest.TestCase):
    def test_unknown_top_level_field_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(surprise=True))

    def test_unknown_nested_field_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(sd_jwt={"require_nonce": True, "typo_field": 1}))

    def test_wrong_schema_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v9.9", "policy_id": "x"})

    def test_missing_policy_id_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy({"schema": POLICY_SCHEMA})

    def test_bad_minimum_level_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(assurance={"minimum_level": "super_duper"}))

    def test_negative_max_iat_age_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(sd_jwt={"max_iat_age_seconds": -5}))

    def test_field_order_does_not_change_parse(self):
        a = load_policy({"schema": POLICY_SCHEMA, "policy_id": "p", "assurance": {"minimum_level": "reproduced"}})
        b = load_policy({"assurance": {"minimum_level": "reproduced"}, "policy_id": "p", "schema": POLICY_SCHEMA})
        self.assertEqual(a, b)


class TestEvaluatePolicyUnits(unittest.TestCase):
    def _bundle(self, path):
        with open(path) as f:
            return json.load(f)

    def _verify(self, bundle, **kw):
        from proofbundle.bundle import verify_bundle
        return verify_bundle(bundle, **kw)

    def test_signer_mismatch_fails(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(
            allowed_issuers=[{"issuer": "Other", "public_key_b64": base64.b64encode(b"\x01" * 32).decode()}],
            signature={"require_expected_signer": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])
        self.assertTrue(any(not c["ok"] and "signer" in c["name"] for c in res["checks"]))

    def test_require_signer_with_empty_issuers_fails_closed(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(signature={"require_expected_signer": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])

    def test_hash_alg_mismatch_fails(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(merkle={"required_hash_alg": "sha512-something"}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])

    def test_status_requirement_fails_closed_no_snapshot(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(status={"reject_self_issued": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])   # no status snapshot input in v0.1 → fail-closed
        self.assertTrue(any("status" in c["name"] for c in res["checks"]))

    def test_self_attested_without_prereg_rejected(self):
        path, _pub = _receipt(assurance_level="self_attested", prereg=None)
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(assurance={"reject_self_attested_without_prereg": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])

    def test_self_attested_with_prereg_accepted(self):
        path, _pub = _receipt(assurance_level="self_attested", prereg="a" * 64)
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(assurance={"reject_self_attested_without_prereg": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertTrue(res["policy_ok"])

    def test_freshness_stale_fails(self):
        path, _pub = _receipt(timestamp="2020-01-01T00:00:00Z")
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(sd_jwt={"max_iat_age_seconds": 10}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])   # a 2020 receipt is far older than 10s

    def test_field_order_does_not_change_verdict(self):
        path, pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        p1 = load_policy(_base_policy(allowed_issuers=[{"public_key_b64": pub}],
                                      merkle={"required_hash_alg": "sha256-rfc6962"}))
        p2 = load_policy({"merkle": {"required_hash_alg": "sha256-rfc6962"},
                          "allowed_issuers": [{"public_key_b64": pub}],
                          "policy_id": "test-policy", "schema": POLICY_SCHEMA})
        r1 = evaluate_policy(bundle, self._verify(bundle), p1)
        r2 = evaluate_policy(bundle, self._verify(bundle), p2)
        self.assertEqual(r1["policy_ok"], r2["policy_ok"])
        self.assertTrue(r1["policy_ok"])


class TestVerifyPolicyCli(unittest.TestCase):
    def test_policy_pass_exit_zero(self):
        path, pub = _receipt(assurance_level="reproduced")
        pol = _policy_file(_base_policy(
            allowed_issuers=[{"issuer": "Lab", "public_key_b64": pub}],
            signature={"require_expected_signer": True},
            merkle={"required_hash_alg": "sha256-rfc6962"},
            assurance={"minimum_level": "reproduced"}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: OK", out)

    def test_policy_fail_exit_three(self):
        path, pub = _receipt(assurance_level="reproduced")
        pol = _policy_file(_base_policy(assurance={"minimum_level": "enclave_attested"}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3)                # crypto OK but policy NOT satisfied → the new exit 3
        self.assertIn("CRYPTO: OK", out)
        self.assertIn("POLICY: FAIL", out)

    def test_policy_json_fields(self):
        path, pub = _receipt()
        pol = _policy_file(_base_policy(allowed_issuers=[{"public_key_b64": pub}]))
        try:
            _, out = _run(["verify", "--json", path, "--policy", pol])
            data = json.loads(out)
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertTrue(data["crypto_ok"])
        self.assertTrue(data["policy_ok"])          # real result, not the WP-B2 null default
        self.assertEqual(data["policy_id"], "test-policy")
        self.assertIn("policy_checks", data)

    def test_missing_policy_is_not_evaluated(self):
        path, _pub = _receipt()
        try:
            rc, out = _run(["verify", path])
            _, jout = _run(["verify", "--json", path])
            data = json.loads(jout)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: NOT_EVALUATED", out)
        self.assertIsNone(data["policy_ok"])         # crypto passes, policy not evaluated

    def test_malformed_policy_exit_two(self):
        path, _pub = _receipt()
        pol = _policy_file({"schema": POLICY_SCHEMA, "policy_id": "p", "bogus_field": 1})
        try:
            rc, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 2)                       # malformed policy → exit 2 (not 1 or 3)

    def test_aud_flag_policy_conflict_exit_two(self):
        path, _pub = _receipt()
        pol = _policy_file(_base_policy(sd_jwt={"expected_aud": "policy.example"}))
        try:
            rc, _out = _run(["verify", path, "--aud", "flag.example", "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 2)                       # ambiguous aud → exit 2, never a silent override

    def test_crypto_fail_policy_not_checked(self):
        path, pub = _receipt()
        with open(path) as f:
            b = json.load(f)
        b["payload_b64"] = "AAAA"                     # tamper: crypto fails
        with open(path, "w") as f:
            json.dump(b, f)
        pol = _policy_file(_base_policy(allowed_issuers=[{"public_key_b64": pub}]))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
            _, jout = _run(["verify", "--json", path, "--policy", pol])
            data = json.loads(jout)
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 1)                        # crypto failure dominates
        self.assertIn("POLICY: NOT_EVALUATED (crypto failed", out)
        self.assertIsNone(data["policy_ok"])           # a policy is never evaluated on unverified bytes


if __name__ == "__main__":
    unittest.main()
