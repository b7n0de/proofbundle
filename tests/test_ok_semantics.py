"""WP-B2 — CRYPTO/POLICY/ASSURANCE separation, the stable machine-readable single-field contract,
and the verify exit-code contract (0/1/2/3).

A crypto success must never read as a policy pass or a truth verdict, and every machine-readable
field for a check that did NOT run in the offline core verify path must be ``null`` (not applicable)
— never silently ``true``.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import _derive_verify_fields, _policy_line, _verify_exit_code, main
from proofbundle.errors import VerificationResult

# The full documented single-field contract (WP-B2.3). Pinned here so a silent removal/rename of any
# field breaks a test — the JSON contract is a stability promise to integrators.
CONTRACT_FIELDS = {
    "schema_ok", "signature_ok", "merkle_ok", "sd_jwt_ok", "key_binding_ok", "audience_ok",
    "nonce_ok", "freshness_ok", "anchor_ok", "witness_ok", "status_ok", "assurance_policy_ok",
    "crypto_ok", "policy_ok", "assurance", "warnings", "limitations",
}
# Fields that are NOT applicable in the offline core verify path → MUST be null, never true.
NOT_APPLICABLE_IN_CORE = {
    "freshness_ok", "anchor_ok", "witness_ok", "status_ok", "assurance_policy_ok", "policy_ok",
}


def _bundle_file(payload=b'{"suite": "safety", "passed": true}') -> str:
    bundle = emit_bundle(payload, generate_signer())
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _eval_receipt_file(assurance_level: str = "self_attested") -> str:
    from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
    claim, _salts = build_eval_claim(
        suite="safety-bench", suite_version="1.0", metric="accuracy", comparator=">=",
        threshold="0.8", score="0.9", n=100, model_id="m", dataset_id="d",
        issuer="Example Lab", timestamp="2026-07-09T10:00:00Z", assurance_level=assurance_level)
    receipt = emit_eval_receipt(claim, generate_signer())
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(receipt, f)
    return path


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


class TestExitCodeContract(unittest.TestCase):
    """The pure exit-code function encodes all four codes (§1.4). Code 2 (malformed) is returned by
    the CLI before this is reached; WP-B3 wires the real policy_ok=False → 3 trigger via --policy,
    but the contract itself is proven here independent of that wiring."""

    def test_pure_exit_code_matrix(self):
        self.assertEqual(_verify_exit_code(True, None), 0)    # crypto ok, no policy supplied
        self.assertEqual(_verify_exit_code(True, True), 0)    # crypto ok, policy satisfied
        self.assertEqual(_verify_exit_code(True, False), 3)   # crypto ok, policy NOT satisfied
        self.assertEqual(_verify_exit_code(False, None), 1)   # crypto failure
        self.assertEqual(_verify_exit_code(False, False), 1)  # crypto failure dominates policy
        self.assertEqual(_verify_exit_code(False, True), 1)

    def test_cli_valid_bundle_exits_zero(self):
        path = _bundle_file()
        try:
            rc, _ = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)

    def test_cli_tampered_exits_one(self):
        path = _bundle_file()
        with open(path) as f:
            b = json.load(f)
        b["payload_b64"] = "AAAA"   # tamper: payload no longer signed/anchored
        with open(path, "w") as f:
            json.dump(b, f)
        try:
            rc, out = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        self.assertIn("CRYPTO: FAILED", out)

    def test_cli_malformed_exits_two(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("{ not json")
        try:
            rc, _ = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)


class TestLabelledOutput(unittest.TestCase):
    def test_no_bare_ok_every_line_is_context_labelled(self):
        path = _bundle_file()
        try:
            rc, out = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertNotIn("=> OK", out)                # the bare marker is gone
        self.assertIn("CRYPTO: OK", out)              # crypto success is explicitly a CRYPTO result
        self.assertIn("POLICY: NOT_EVALUATED", out)   # no policy → said so, never a bare pass
        self.assertIn("ASSURANCE:", out)
        self.assertIn("LIMITATIONS:", out)

    def test_policy_line_branches(self):
        self.assertIn("NOT_EVALUATED", _policy_line(None))
        self.assertEqual(_policy_line(True), "OK")
        self.assertTrue(_policy_line(False, "signer not allowed").startswith("FAIL ("))
        self.assertEqual(_policy_line(False), "FAIL")

    def test_plain_bundle_assurance_is_na(self):
        path = _bundle_file()
        try:
            _, out = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertIn("ASSURANCE: n/a", out)   # a plain emit bundle is not an eval receipt

    def test_eval_receipt_assurance_is_verbatim(self):
        # WP-B2.2: the ASSURANCE line is the issuer's signed level, shown verbatim, not interpreted.
        path = _eval_receipt_file(assurance_level="reproduced")
        try:
            rc, out = _run(["verify", path])
            _, jout = _run(["verify", "--json", path])
            data = json.loads(jout)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertIn("ASSURANCE: reproduced", out)
        self.assertEqual(data["assurance"], "reproduced")   # verbatim, not "trusted"/"OK"/interpreted


class TestJsonFieldContract(unittest.TestCase):
    def test_all_contract_fields_present_and_backward_compatible(self):
        path = _bundle_file()
        try:
            rc, out = _run(["verify", "--json", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        for field in CONTRACT_FIELDS:
            self.assertIn(field, data, f"missing stable field {field!r}")
        # existing contract keys stay present (additive change)
        self.assertIn("ok", data)
        self.assertIn("checks", data)
        self.assertIn("meaning", data)

    def test_not_applicable_fields_are_null_never_true(self):
        path = _bundle_file()
        try:
            _, out = _run(["verify", "--json", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        for field in NOT_APPLICABLE_IN_CORE:
            self.assertIsNone(data[field], f"{field} must be null (not applicable), got {data[field]!r}")

    def test_crypto_fields_true_on_valid_bundle(self):
        path = _bundle_file()
        try:
            _, out = _run(["verify", "--json", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertTrue(data["schema_ok"])
        self.assertTrue(data["signature_ok"])
        self.assertTrue(data["merkle_ok"])
        self.assertTrue(data["crypto_ok"])
        self.assertIsNone(data["sd_jwt_ok"])       # no SD-JWT in a plain bundle → not applicable
        self.assertIsNone(data["assurance"])       # not an eval receipt
        self.assertEqual(data["warnings"], [])
        self.assertTrue(data["limitations"])       # non-empty

    def test_derive_fields_marks_failed_checks_as_warnings(self):
        result = VerificationResult()
        result.add("ed25519-signature", False, "invalid signature")
        result.add("merkle-inclusion", True, "anchored")
        fields = _derive_verify_fields(result, aud_requested=False, nonce_requested=False,
                                       assurance=None, policy_ok=None)
        self.assertFalse(fields["signature_ok"])
        self.assertTrue(fields["merkle_ok"])
        self.assertFalse(fields["crypto_ok"])
        self.assertTrue(any("ed25519-signature" in w for w in fields["warnings"]))

    def test_audience_nonce_fields_null_unless_requested(self):
        # A bundle with no SD-JWT: audience_ok/nonce_ok are null when the RP did not request binding.
        result = VerificationResult()
        result.add("ed25519-signature", True, "ok")
        result.add("merkle-inclusion", True, "ok")
        not_req = _derive_verify_fields(result, aud_requested=False, nonce_requested=False,
                                        assurance=None, policy_ok=None)
        self.assertIsNone(not_req["audience_ok"])
        self.assertIsNone(not_req["nonce_ok"])
        self.assertIsNone(not_req["key_binding_ok"])


if __name__ == "__main__":
    unittest.main()
