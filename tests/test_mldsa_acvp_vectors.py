"""proofbundle.pqsig.verify_mldsa against the NIST ACVP ML-DSA sigVer (FIPS 204) Known-Answer Tests.

These vectors do not come from proofbundle itself — they are vendored from the official NIST
Automated Cryptographic Validation Protocol (ACVP) test-vector generator (usnistgov/ACVP-Server,
`ML-DSA-sigVer-FIPS204/internalProjection.json`, see tests/fixtures/mldsa_acvp/PROVENANCE.json).
Passing them proves ML-DSA verification is FIPS-204-conformant against an independent, government
reference implementation — not merely self-consistent with proofbundle's own `generate_mldsa` /
`sign_mldsa` round-trip (already covered by tests/test_pqsig.py).

Honest scope limitation (No-Fake — this is NOT a full ACVP conformance suite):
`proofbundle.pqsig.verify_mldsa(public_key, signature, message, level=...)` wraps the
`cryptography` library's pure-external ML-DSA verify with an IMPLICIT EMPTY context and does not
accept a `context` argument. The full ACVP sigVer vector set for one parameter set covers four
axes proofbundle's API cannot exercise:
  - `signatureInterface=internal` (6 of 12 test groups) — no public API for the raw internal
    Verify(pk, M', sigma); not reachable through verify_mldsa at all.
  - `preHash=preHash` (HashML-DSA, half of the `external` groups) — `cryptography`'s verify()
    implements only the pure (non-prehashed) external interface (domain separator byte 0, not 1);
    prehashing the message ourselves would not reproduce the FIPS 204 HashML-DSA encoding.
  - any test vector whose `context` field is non-empty — verify_mldsa has no way to pass it.
So the ONLY vectors this test can honestly exercise are `signatureInterface=external`,
`preHash=pure`, `context==""`. In the vendored 12-group / 180-test source file that combination
occurs exactly ONCE per parameter set (ML-DSA-44/65/87) — 3 vectors total (1 valid, 2 invalid,
cross-validated against the independent expectedResults.json answer key; see PROVENANCE.json).
That is a real, honest constraint of the source data, not an artificially small sample.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path

from proofbundle.pqsig import verify_mldsa

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    _HAS_MLDSA = True
except ImportError:
    _HAS_MLDSA = False

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "mldsa_acvp"
SLICE_PATH = FIXTURE_DIR / "mldsa_sigver_slice.json"
PROVENANCE_PATH = FIXTURE_DIR / "PROVENANCE.json"


def _load_slice() -> dict:
    return json.loads(SLICE_PATH.read_text(encoding="utf-8"))


def _load_provenance() -> dict:
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


@unittest.skipUnless(SLICE_PATH.exists() and PROVENANCE_PATH.exists(),
                     "mldsa_acvp fixtures not vendored (tests/fixtures/mldsa_acvp/)")
class TestMldsaAcvpFixtureIntegrity(unittest.TestCase):
    """Pin the vendored fixture's content SHA-256 against PROVENANCE.json — a tamper on the fixture
    (e.g. flipping a byte in a 'valid' vector's signature so a broken verifier would still pass)
    must be a RED test, not a silent pass."""

    def test_provenance_pins_every_vendored_file(self) -> None:
        prov = _load_provenance()
        entries = {e["filename"]: e for e in prov["files"]}
        vendored = {p.name for p in FIXTURE_DIR.iterdir()
                   if p.is_file() and p.name != "PROVENANCE.json"}
        self.assertTrue(vendored, "no vendored files found — vacuous provenance check")
        self.assertEqual(vendored, set(entries),
                         "every file in tests/fixtures/mldsa_acvp/ must have a PROVENANCE.json entry "
                         "(and vice versa)")

    def test_fixture_sha256_matches_provenance(self) -> None:
        prov = _load_provenance()
        for entry in prov["files"]:
            path = FIXTURE_DIR / entry["filename"]
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(actual, entry["sha256"],
                             f"{entry['filename']} content does not match its PROVENANCE.json pin "
                             "(fixture was modified/tampered after vendoring)")

    def test_tampered_fixture_is_detected(self) -> None:
        # Anti-vacuity: prove the pin actually catches a tamper, not just that it currently matches.
        real = SLICE_PATH.read_bytes()
        tampered = bytearray(real)
        tampered[100] ^= 0xFF
        prov = _load_provenance()
        pin = next(e["sha256"] for e in prov["files"] if e["filename"] == "mldsa_sigver_slice.json")
        self.assertNotEqual(hashlib.sha256(bytes(tampered)).hexdigest(), pin,
                            "a single-byte tamper must change the SHA-256 (pin is not vacuous)")


@unittest.skipUnless(_HAS_MLDSA, "needs cryptography with FIPS 204 (ML-DSA) support")
@unittest.skipUnless(SLICE_PATH.exists(), "mldsa_acvp fixture not vendored")
class TestMldsaAcvpVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = _load_slice()["vectors"]

    def test_slice_is_the_expected_empty_context_pure_external_subset(self) -> None:
        self.assertEqual(len(self.vectors), 3, "expected exactly the 3 real empty-context vectors")
        param_sets = {v["parameterSet"] for v in self.vectors}
        self.assertEqual(param_sets, {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
        for v in self.vectors:
            self.assertEqual(v["signatureInterface"], "external")
            self.assertEqual(v["preHash"], "pure")
            self.assertEqual(v["context"], "", f"vector tc{v['tcId']} must have an empty context")
        passed = [v["testPassed"] for v in self.vectors]
        self.assertIn(True, passed, "expected at least one valid (testPassed=True) vector")
        self.assertIn(False, passed, "expected at least one invalid (testPassed=False) vector")

    def test_acvp_sigver_vectors_match_nist_verdict(self) -> None:
        level_by_param = {"ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65", "ML-DSA-87": "mldsa87"}
        checked = 0
        for v in self.vectors:
            pk = bytes.fromhex(v["pk"])
            sig = bytes.fromhex(v["signature"])
            msg = bytes.fromhex(v["message"])
            level = level_by_param[v["parameterSet"]]
            got = verify_mldsa(pk, sig, msg, level=level)
            self.assertEqual(got, v["testPassed"],
                             f"tgId={v['tgId']} tcId={v['tcId']} {v['parameterSet']} "
                             f"({v['reason']!r}): proofbundle said {got}, NIST ACVP says {v['testPassed']}")
            checked += 1
        self.assertEqual(checked, 3, "must not vacuously pass over an empty vector list")

    def test_valid_vector_signature_tamper_is_rejected(self) -> None:
        # Derived coverage on top of the one real valid ACVP vector (ML-DSA-65 tc35): flipping a
        # signature byte of a KNOWN-VALID external ACVP vector must flip the verdict to False.
        valid = next(v for v in self.vectors if v["testPassed"] is True)
        pk = bytes.fromhex(valid["pk"])
        sig = bytearray(bytes.fromhex(valid["signature"]))
        msg = bytes.fromhex(valid["message"])
        level = {"ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65",
                 "ML-DSA-87": "mldsa87"}[valid["parameterSet"]]
        self.assertTrue(verify_mldsa(pk, bytes(sig), msg, level=level))
        sig[0] ^= 0xFF
        self.assertFalse(verify_mldsa(pk, bytes(sig), msg, level=level))

    def test_valid_vector_wrong_message_is_rejected(self) -> None:
        valid = next(v for v in self.vectors if v["testPassed"] is True)
        pk = bytes.fromhex(valid["pk"])
        sig = bytes.fromhex(valid["signature"])
        level = {"ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65",
                 "ML-DSA-87": "mldsa87"}[valid["parameterSet"]]
        self.assertFalse(verify_mldsa(pk, sig, b"not the ACVP message" + base64.b64encode(sig)[:8],
                                      level=level))


if __name__ == "__main__":
    unittest.main()
