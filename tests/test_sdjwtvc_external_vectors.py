"""proofbundle.sdjwt.verify_sd_jwt / proofbundle.sdjwt_vc.check_vc_profile against REAL SD-JWT VC
examples from the OAuth WG editor's copy of the SD-JWT-based Verifiable Credentials draft.

These are not proofbundle-generated credentials — they are vendored verbatim from
oauth-wg/oauth-sd-jwt-vc's own worked examples (see tests/fixtures/sdjwtvc/PROVENANCE.json).

Honest scope limitation (No-Fake): all 5 examples use an ES256 (ECDSA P-256) issuer signature.
`proofbundle.sdjwt.verify_sd_jwt` only implements EdDSA (Ed25519) issuer-signature verification
(documented module scope) — so `sig_checked`/`sig_ok` are never exercised by these vectors, and
this suite does NOT claim to test issuer-signature cryptography. What IS real external conformance
coverage here: the STRUCTURAL verify path (every disclosure's digest is actually committed in the
issuer-signed payload, including the RECURSIVE disclosure fixpoint resolution RFC 9901 requires),
and `check_vc_profile`'s `typ`/`vct` relying-party checks — both algorithm-independent.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_vc import check_vc_profile

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "sdjwtvc"
PROVENANCE_PATH = FIXTURE_DIR / "PROVENANCE.json"
EXAMPLES_PATH = FIXTURE_DIR / "sdjwtvc_examples.txt"

_IDENTITY_VCT = "https://credentials.example.com/identity_credential"
_PID_VCT = "urn:example:eudi:pid:aendgard:1"


def _load_provenance() -> dict:
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


def _load_examples() -> list[str]:
    return [ln.strip() for ln in EXAMPLES_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]


@unittest.skipUnless(PROVENANCE_PATH.exists() and EXAMPLES_PATH.exists(),
                     "sdjwtvc fixtures not vendored (tests/fixtures/sdjwtvc/)")
class TestSdjwtVcFixtureIntegrity(unittest.TestCase):
    def test_provenance_pins_every_vendored_file(self) -> None:
        prov = _load_provenance()
        entries = {e["filename"] for e in prov["files"]}
        vendored = {p.name for p in FIXTURE_DIR.iterdir()
                   if p.is_file() and p.name != "PROVENANCE.json"}
        self.assertTrue(vendored)
        self.assertEqual(vendored, entries,
                         "every vendored file must have a PROVENANCE.json entry (and vice versa)")

    def test_fixture_sha256_matches_provenance(self) -> None:
        prov = _load_provenance()
        for entry in prov["files"]:
            actual = hashlib.sha256((FIXTURE_DIR / entry["filename"]).read_bytes()).hexdigest()
            self.assertEqual(actual, entry["sha256"],
                             f"{entry['filename']} does not match its PROVENANCE.json pin (tampered)")

    def test_tampered_fixture_is_detected(self) -> None:
        real = EXAMPLES_PATH.read_bytes()
        tampered = bytearray(real)
        tampered[0] ^= 0xFF
        prov = _load_provenance()
        pin = next(e["sha256"] for e in prov["files"] if e["filename"] == "sdjwtvc_examples.txt")
        self.assertNotEqual(hashlib.sha256(bytes(tampered)).hexdigest(), pin,
                            "a single-byte tamper must change the SHA-256 (pin is not vacuous)")

    def test_exactly_five_examples_vendored(self) -> None:
        self.assertEqual(len(_load_examples()), 5, "must not vacuously pass over zero/wrong count")


@unittest.skipUnless(EXAMPLES_PATH.exists(), "sdjwtvc examples fixture not vendored")
class TestSdjwtVcStructuralExternalVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.examples = _load_examples()

    def test_all_examples_have_es256_issuer_alg_by_design_not_checked_here(self) -> None:
        # documents the honest scope boundary rather than silently ignoring it
        import base64
        for i, compact in enumerate(self.examples):
            header_b64 = compact.split("~", 1)[0].split(".")[0]
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
            self.assertEqual(header.get("alg"), "ES256",
                             f"example {i}: fixture assumption changed, re-check the scope docstring")
            self.assertEqual(header.get("typ"), "dc+sd-jwt")

    def test_all_examples_structure_ok(self) -> None:
        checked = 0
        for i, compact in enumerate(self.examples):
            res = verify_sd_jwt(compact)
            self.assertTrue(res["structure_ok"], f"example {i}: {res['detail']}")
            checked += 1
        self.assertEqual(checked, 5, "must not vacuously pass over zero vectors")

    def test_recursive_disclosures_resolve_to_fixpoint(self) -> None:
        # examples 3 and 4 (0-indexed) are the recursive-disclosure PID credential; a broken
        # fixpoint resolver would reject these even though every disclosure IS transitively rooted.
        for i in (3, 4):
            res = verify_sd_jwt(self.examples[i])
            self.assertTrue(res["structure_ok"], f"recursive example {i}: {res['detail']}")

    def test_tampered_disclosure_is_rejected(self) -> None:
        compact = self.examples[0]
        parts = compact.split("~")
        self.assertGreaterEqual(len(parts), 2, "expected at least one disclosure")
        d = parts[1]
        # flip a character deep enough to survive base64url padding edge cases
        bad_char = "A" if d[-4] != "A" else "B"
        parts[1] = d[:-4] + bad_char + d[-3:]
        tampered = "~".join(parts)
        res = verify_sd_jwt(tampered)
        self.assertFalse(res["structure_ok"], "a tampered disclosure must not verify as committed")

    def test_dropping_a_disclosure_still_verifies_selective_disclosure(self) -> None:
        # SD-JWT's whole point: presenting FEWER disclosures than were issued is still valid,
        # as long as every PRESENTED disclosure is committed.
        compact = self.examples[0]
        parts = compact.split("~")
        disclosures = [p for p in parts[1:] if p]
        self.assertGreater(len(disclosures), 1, "need at least 2 disclosures for this test")
        reduced = parts[0] + "~" + disclosures[0] + "~"
        res = verify_sd_jwt(reduced)
        self.assertTrue(res["structure_ok"], res["detail"])


@unittest.skipUnless(EXAMPLES_PATH.exists(), "sdjwtvc examples fixture not vendored")
class TestSdjwtVcProfileExternalVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.examples = _load_examples()

    def test_identity_credential_examples_pass_profile_with_correct_allowlist(self) -> None:
        policy = {"vctAllowlist": [_IDENTITY_VCT]}
        for i in (0, 1, 2):
            r = check_vc_profile(self.examples[i], policy)
            self.assertTrue(r["ok"], f"example {i}: {r['errors']}")
            self.assertTrue(r["typ_ok"])
            self.assertTrue(r["vct_ok"])
            self.assertEqual(r["vct"], _IDENTITY_VCT)

    def test_pid_credential_examples_pass_profile_with_correct_allowlist(self) -> None:
        policy = {"vctAllowlist": [_PID_VCT]}
        for i in (3, 4):
            r = check_vc_profile(self.examples[i], policy)
            self.assertTrue(r["ok"], f"example {i}: {r['errors']}")
            self.assertEqual(r["vct"], _PID_VCT)

    def test_unknown_vct_is_fail_closed(self) -> None:
        policy = {"vctAllowlist": ["urn:example:not-the-real-type"]}
        r = check_vc_profile(self.examples[0], policy)
        self.assertFalse(r["ok"])
        self.assertFalse(r["vct_ok"])
        self.assertTrue(any("not on the relying party's vctAllowlist" in e for e in r["errors"]))

    def test_cross_credential_type_is_fail_closed(self) -> None:
        # the identity-credential vct must not satisfy a PID-only allowlist and vice versa
        self.assertFalse(check_vc_profile(self.examples[0], {"vctAllowlist": [_PID_VCT]})["ok"])
        self.assertFalse(check_vc_profile(self.examples[3], {"vctAllowlist": [_IDENTITY_VCT]})["ok"])


if __name__ == "__main__":
    unittest.main()
