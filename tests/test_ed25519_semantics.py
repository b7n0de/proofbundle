"""WP-C2 — the Ed25519 verify semantics are DECIDED and PINNED, not incidental.

Ed25519 implementations disagree on edge-case signatures ("Taming the Many EdDSAs",
eprint 2020/1244): cofactored vs cofactorless verification, the RFC 8032 S-bound, non-canonical
point encodings, small-order components. proofbundle delegates verification to `cryptography`
(OpenSSL). That backing behavior is now a DOCUMENTED, versioned property (SPEC.md §4a) instead of
an undocumented accident — and this test pins the full 12-vector edge-case envelope so a change in
the backing library turns into a RED TEST (a deliberate decision), never a silent drift of what
"verified" means across proofbundle installs.

Vectors: tests/fixtures/ed25519_speccheck_cases.json — vendored verbatim from
novifinancial/ed25519-speccheck (Apache-2.0), the artifact of eprint 2020/1244.

The pinned profile (OpenSSL): **cofactorless**, RFC 8032 **S-bound enforced** (cases 6, 7 REJECT),
**non-canonical R rejected** (8, 9), **non-canonical A partially accepted** (10 REJECT / 11 ACCEPT
— the "not reduced for hash" variant slips through), **small/mixed-order components accepted**
(0–3). This is NEITHER the paper's "strict" profile (which rejects 0–3 and 11) NOR ZIP-215 (which
accepts 0–5). Honest signers producing RFC 8032 signatures over canonical keys are unaffected —
the divergence envelope exists only for adversarially crafted signatures; the cross-verifier
consequence is documented in SPEC.md §4a and THREAT_MODEL.md.
"""
import json
import unittest
from pathlib import Path

from proofbundle.signature import verify_ed25519

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ed25519_speccheck_cases.json"

# The pinned edge-case envelope of the backing verifier (observed on cryptography/OpenSSL,
# 2026-07-11; see the module docstring for what each case means).
#           case:  0     1     2     3     4      5      6      7      8      9      10     11
EXPECTED = (True, True, True, True, False, False, False, False, False, False, False, True)

_CASE_NOTES = (
    "0: S=0, small-order A and R",
    "1: small-order A, mixed-order R",
    "2: mixed-order A, small-order R",
    "3: mixed-order A and R (cofactorless-valid)",
    "4: valid only under cofactored verification",
    "5: fails cofactored iff (8h) pre-reduced",
    "6: S just above L (RFC 8032 bound)",
    "7: S far above L",
    "8: non-canonical R, reduced for hashing",
    "9: non-canonical R, not reduced for hashing",
    "10: non-canonical A, reduced for hashing",
    "11: non-canonical A, not reduced for hashing (accepted!)",
)


class TestEd25519EdgeCaseEnvelope(unittest.TestCase):
    def test_speccheck_vectors_pin_the_backing_semantics(self):
        cases = json.loads(FIXTURE.read_text(encoding="utf-8"))
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
