"""WP-B2 — CRYPTO/POLICY/ASSURANCE separation, the stable machine-readable single-field contract,
and the verify exit-code contract (0/1/2/3).

A crypto success must never read as a policy pass or a truth verdict, and every machine-readable
field for a check that did NOT run in the offline core verify path must be ``null`` (not applicable)
— never silently ``true``.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import _derive_verify_fields, _policy_line, _safe_line, _verify_exit_code, main
from proofbundle.errors import VerificationResult
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

# The full documented single-field contract (WP-B2.3). Pinned here so a silent removal/rename of any
# field breaks a test — the JSON contract is a stability promise to integrators.
CONTRACT_FIELDS = {
    "schema_ok", "signature_ok", "merkle_ok", "sd_jwt_ok", "sd_jwt_issuer_verified", "key_binding_ok",
    "audience_ok", "nonce_ok", "freshness_ok", "anchor_ok", "witness_ok", "status_ok",
    "assurance_policy_ok", "crypto_ok", "policy_ok", "assurance", "assurance_declared_by",
    "warnings", "limitations",
}

_IAT = 1_780_000_000


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sd_jwt_bundle_file(*, with_issuer_key: bool = True, aud: str = "verifier.example",
                        nonce: str = "n-1") -> str:
    """A bundle carrying a real, key-bound SD-JWT presentation (built like tests/test_kbjwt.py).
    ``with_issuer_key`` controls whether sd_jwt_vc.issuer_public_key_b64 is present — its absence is
    exactly the case where the issuer signature is never checked (Fund A)."""
    issuer = generate_signer()
    holder = generate_signer()
    claim = {"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "demo-suite",
             "issuer": "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")}
    compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score="0.92",
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud=aud, nonce=nonce, iat=_IAT)
    sd_jwt_vc = {"compact": presented}
    if with_issuer_key:
        sd_jwt_vc["issuer_public_key_b64"] = base64.b64encode(_raw_pub(issuer)).decode("ascii")
    bundle = emit_bundle(b'{"x":1}', issuer, sd_jwt_vc=sd_jwt_vc)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path
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


def _write_bundle(bundle) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


class TestExitCodeContract(unittest.TestCase):
    """The pure exit-code function encodes all four codes (see ``proofbundle verify --help``). Code 2
    (malformed) is returned by the CLI before this is reached; WP-B3 wires the real policy_ok=False →
    3 trigger via --policy, but the contract itself is proven here independent of that wiring."""

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

    def test_assurance_line_names_the_issuer_as_source(self):
        # WP-N2: the level is the issuer's own declaration, not an appraisal — the line says so, and
        # the JSON attributes it machine-readably. Pinned so the suffix cannot silently disappear.
        path = _eval_receipt_file(assurance_level="reproduced")
        try:
            rc, out = _run(["verify", path])
            _, jout = _run(["verify", "--json", path])
            data = json.loads(jout)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertIn("ASSURANCE: reproduced (issuer-declared)", out)
        self.assertEqual(data["assurance_declared_by"], "issuer")

    def test_assurance_declared_by_null_when_not_an_eval_receipt(self):
        # No assurance level → nothing to attribute: the field must be null, never a fake "issuer",
        # and the n/a display line carries no issuer-declared suffix.
        path = _bundle_file()
        try:
            _, jout = _run(["verify", "--json", path])
            data = json.loads(jout)
            _, out = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertIsNone(data["assurance"])
        self.assertIsNone(data["assurance_declared_by"])
        self.assertIn("ASSURANCE: n/a (not an eval receipt)", out)
        self.assertNotIn("(issuer-declared)", out)


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


class TestSdJwtFields(unittest.TestCase):
    """The SD-JWT single-fields must reflect REAL verification, and must be null (never silently
    true) when the issuer signature was not checked (verify-lens L1/L2, 2026-07-09)."""

    def test_true_on_real_key_bound_presentation(self):   # Fund B (green)
        path = _sd_jwt_bundle_file(aud="verifier.example", nonce="n-1")
        try:
            rc, out = _run(["verify", "--json", "--aud", "verifier.example", "--nonce", "n-1", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertTrue(data["crypto_ok"])
        self.assertTrue(data["sd_jwt_ok"])
        self.assertTrue(data["sd_jwt_issuer_verified"])
        self.assertTrue(data["key_binding_ok"])
        self.assertTrue(data["audience_ok"])
        self.assertTrue(data["nonce_ok"])

    def test_audience_mismatch_fails(self):   # Fund B (red counter-test)
        path = _sd_jwt_bundle_file(aud="verifier.example", nonce="n-1")
        try:
            rc, out = _run(["verify", "--json", "--aud", "OTHER.example", "--nonce", "n-1", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)                     # crypto fails: KB-JWT aud does not match
        self.assertFalse(data["key_binding_ok"])
        self.assertFalse(data["audience_ok"])

    def test_null_and_warns_without_issuer_key(self):   # Fund A — the core fix
        path = _sd_jwt_bundle_file(with_issuer_key=False)
        try:
            _, out = _run(["verify", "--json", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        # structure is well-formed, but the issuer signature was NEVER checked → NOT silently true
        self.assertIsNone(data["sd_jwt_ok"])
        self.assertIsNone(data["sd_jwt_issuer_verified"])
        self.assertTrue(any("issuer" in w.lower() and "unverified" in w.lower()
                            for w in data["warnings"]))


class TestAssuranceInjection(unittest.TestCase):
    def test_out_of_enum_level_rejected_on_verify_path(self):   # Fund D — core
        from proofbundle.evalclaim import build_eval_claim, canonicalize, issuer_fingerprint
        signer = generate_signer()
        claim, _ = build_eval_claim(suite="s", suite_version="1", metric="acc", comparator=">=",
                                    threshold="0.5", score="0.9", n=1, model_id="m", dataset_id="d",
                                    issuer="placeholder", timestamp="2026-01-01T00:00:00Z")
        claim["issuer"] = issuer_fingerprint(signer)   # bind to the signing key (issuer-check passes)
        # inject: out-of-enum level with embedded newlines forging fake CRYPTO:/POLICY: lines
        claim["assurance_level"] = "self_attested\nCRYPTO: OK\nPOLICY: OK (independently audited)"
        path = _write_bundle(emit_bundle(canonicalize(claim), signer))
        try:
            rc, out = _run(["verify", path])
            _, jout = _run(["verify", "--json", path])
            data = json.loads(jout)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)                                      # the bytes ARE signed — crypto is fine
        self.assertNotIn("POLICY: OK (independently audited)", out)  # forged line must NOT appear
        self.assertIn("ASSURANCE: n/a", out)                         # out-of-enum level → decode rejects it
        self.assertIsNone(data["assurance"])

    def test_safe_line_neutralises_control_chars(self):   # Fund D — defense-in-depth
        self.assertEqual(_safe_line("a\nb\rc\td"), "a b c d")
        self.assertEqual(_safe_line("self_attested"), "self_attested")   # printable unchanged


class TestErrorPathAndRobustness(unittest.TestCase):
    def test_error_json_carries_field_contract(self):   # Fund C
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("{ not json")
        try:
            rc, out = _run(["verify", "--json", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)
        self.assertIn("error", data)
        self.assertFalse(data["crypto_ok"])    # readable without a KeyError on the error path
        self.assertIsNone(data["signature_ok"])
        # Six-lens review (2026-07-11): the exit-2 path must carry the FULL single-field contract —
        # this is the test the cli.py "a test pins the union" comment promises.
        for field in CONTRACT_FIELDS:
            self.assertIn(field, data, f"error path missing stable field {field!r}")
        self.assertIsNone(data["assurance_declared_by"])

    def test_crypto_fail_assurance_reason_is_distinct(self):   # Fund E
        path = _eval_receipt_file(assurance_level="reproduced")
        with open(path) as f:
            b = json.load(f)
        b["merkle"]["root_b64"] = base64.b64encode(b"\x00" * 32).decode()   # tamper merkle only
        with open(path, "w") as f:
            json.dump(b, f)
        try:
            rc, out = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        self.assertIn("CRYPTO: FAILED", out)
        self.assertIn("crypto verification failed", out)   # a real receipt whose crypto broke
        self.assertNotIn("not an eval receipt", out)

    def test_deeply_nested_json_exits_two_no_traceback(self):   # Fund F
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("[" * 6000 + "]" * 6000)
        try:
            rc, out = _run(["verify", "--json", path])
            data = json.loads(out)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)               # malformed, NOT a raw RecursionError (which was exit 1)
        self.assertFalse(data["crypto_ok"])


if __name__ == "__main__":
    unittest.main()
