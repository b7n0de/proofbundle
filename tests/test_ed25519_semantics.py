"""WP-C2 — the Ed25519 verify semantics are DECIDED and PINNED, not incidental.

Ed25519 implementations disagree on edge-case signatures ("Taming the Many EdDSAs",
eprint 2020/1244): cofactored vs cofactorless verification, the RFC 8032 S-bound, non-canonical
point encodings, small-order components. proofbundle delegates verification to `cryptography`
(OpenSSL). That backing behavior is now a DOCUMENTED, versioned property (SPEC.md §4a) instead of
an undocumented accident — and this test pins the full 12-vector edge-case envelope so a change in
the backing library turns into a RED TEST in THIS repository's CI (which exercises the declared
cryptography support range, ==42.* through the latest, in the `crypto-floor` + matrix jobs). It is
a deliberate, documented decision, never a silent drift of what CI accepts as "verified".

Vectors: tests/fixtures/ed25519_speccheck_cases.json — vendored verbatim (byte-identical) from
novifinancial/ed25519-speccheck cases.json, upstream commit
5e4bfc4542293286e9ad3cb2b805badee00503de (2020-10-12), git blob SHA
8686dcb7eef8b6abe36ca8fa9bb10de112e63774, Apache-2.0 (see the sibling .LICENSE / .README.md).
The bytes are pinned by SHA-256 below, so a fixture tamper is a red test, not a silent pass.

The pinned profile (cryptography/OpenSSL): observed identical from cryptography 42.0.8 (the declared
floor) through the current release. It matches the **BoringSSL / Dalek (non-strict)** row of the
upstream table EXACTLY: ACCEPT {0,1,2,3,11}, REJECT {4,5,6,7,8,9,10}. Concretely: cofactorless;
the RFC 8032 S-bound enforced (6, 7 REJECT); non-canonical R rejected (8, 9); non-canonical A
partially accepted (10 REJECT / 11 ACCEPT — the "not reduced for hash" variant slips through);
small-/mixed-order components accepted (0–3). It is NEITHER Dalek-strict (which rejects {0,1,2,11}
and accepts only 3 — rejecting 3, the mixed-order vector, needs a full-order check no surveyed
library performs) NOR ZIP-215 (Zebra, which additionally accepts {4,5,9,10}). The divergence from
Dalek-strict is exactly {0,1,2,11}; from ZIP-215 exactly {4,5,9,10}. Honest signers producing
RFC 8032 signatures over canonical keys are accepted by all of these profiles — the divergence
envelope exists only for adversarially crafted signatures; the cross-verifier consequence is
documented in SPEC.md §4a and THREAT_MODEL.md.
"""
import hashlib
import json
import unittest
from pathlib import Path

from proofbundle.signature import verify_ed25519

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ed25519_speccheck_cases.json"
# Pin the exact vendored bytes: a tamper on a REJECT-pinned vector would otherwise stay silently
# green (the verdict is still REJECT), defeating the pin. Content SHA-256 of the verbatim upstream
# cases.json (git blob 8686dcb7…).
FIXTURE_SHA256 = "08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450"

# The pinned edge-case envelope of the backing verifier (== BoringSSL / Dalek non-strict).
#           case:  0     1     2     3     4      5      6      7      8      9      10     11
EXPECTED = (True, True, True, True, False, False, False, False, False, False, False, True)

_CASE_NOTES = (
    "0: S=0, small-order A and R",
    "1: small-order A, mixed-order R",
    "2: mixed-order A, small-order R",
    "3: mixed-order A and R (accepted unless full-order is checked)",
    "4: cofactorless-invalid, cofactored-valid",
    "5: fails cofactored iff (8h) pre-reduced",
    "6: S just above L (RFC 8032 bound)",
    "7: S far above L",
    "8: non-canonical R, reduced for hashing",
    "9: non-canonical R, not reduced for hashing",
    "10: non-canonical A, reduced for hashing",
    "11: non-canonical A, not reduced for hashing (accepted!)",
)


class TestEd25519EdgeCaseEnvelope(unittest.TestCase):
    def test_fixture_bytes_are_pinned(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(), FIXTURE_SHA256,
            "vendored ed25519-speccheck fixture changed — a tamper (or an intentional refresh) must "
            "be a deliberate, reviewed edit: update FIXTURE_SHA256 + EXPECTED together, never silently.")

    def test_speccheck_vectors_pin_the_backing_semantics(self):
        cases = json.loads(FIXTURE.read_bytes())
        self.assertEqual(len(cases), len(EXPECTED), "vector count drifted from the pin")
        for i, (case, expected) in enumerate(zip(cases, EXPECTED)):
            got = verify_ed25519(bytes.fromhex(case["pub_key"]),
                                 bytes.fromhex(case["signature"]),
                                 bytes.fromhex(case["message"]))
            self.assertEqual(
                got, expected,
                f"speccheck case {i} ({_CASE_NOTES[i]}): expected "
                f"{'ACCEPT' if expected else 'REJECT'}, got {'ACCEPT' if got else 'REJECT'} — "
                "the backing Ed25519 semantics CHANGED (library update?). This must be a "
                "deliberate, documented decision: update SPEC.md §4a + THREAT_MODEL.md and this "
                "pin together, never silently.")

    def test_honest_rfc8032_signature_still_verifies(self):
        # The envelope pin must never be mistaken for strictness against honest signers: a normal
        # RFC 8032 signature over a canonical key verifies, and a wrong-message check fails.
        from proofbundle import generate_signer
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        sig = signer.sign(b"hello")
        self.assertTrue(verify_ed25519(pub, sig, b"hello"))
        self.assertFalse(verify_ed25519(pub, sig, b"goodbye"))


if __name__ == "__main__":
    unittest.main()
