"""proofbundle.sdjwt.verify_sd_jwt / proofbundle.sdjwt_vc.check_vc_profile against REAL SD-JWT VC
examples from the OAuth WG editor's copy of the SD-JWT-based Verifiable Credentials draft.

These are not proofbundle-generated credentials — they are vendored verbatim from
oauth-wg/oauth-sd-jwt-vc's own worked examples (see tests/fixtures/sdjwtvc/PROVENANCE.json).

Finding 20 / issue #27 (2026-07-15): all 5 examples use an ES256 (ECDSA P-256) issuer signature,
and `proofbundle.sdjwt.verify_sd_jwt` now implements ES256 issuer-signature verification alongside
EdDSA — so this suite verifies the issuer signature CRYPTOGRAPHICALLY, not just structurally. The
issuer public key (`sdjwtvc_issuer_pubkey.json`) is extracted from the SAME pinned commit's
`examples/settings.yml` and was independently re-verified (every example's signature actually
verifies under it) before vendoring — see PROVENANCE.json. External conformance coverage here is
therefore now real end-to-end: the STRUCTURAL verify path (every disclosure's digest is actually
committed in the issuer-signed payload, including the RECURSIVE disclosure fixpoint resolution RFC
9901 requires), the issuer signature itself, AND `check_vc_profile`'s `typ`/`vct` relying-party
checks.

No official NEGATIVE (tampered/invalid) SD-JWT VC vectors were found upstream: neither
oauth-wg/oauth-sd-jwt-vc nor the base oauth-wg/oauth-selective-disclosure-jwt repo nor the
openwallet-foundation-labs/sd-jwt-python reference implementation's `tests/testcases/` publish
adversarial vectors — every worked example in all three is a POSITIVE structural variant (checked
2026-07-15). The negative tests below therefore adversarially mutate the vendored POSITIVE vectors
in code (the established pattern this file already used for `test_tampered_disclosure_is_rejected`),
rather than fabricating a fictitious "official" source.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path

from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_vc import check_vc_profile

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "sdjwtvc"
PROVENANCE_PATH = FIXTURE_DIR / "PROVENANCE.json"
EXAMPLES_PATH = FIXTURE_DIR / "sdjwtvc_examples.txt"
ISSUER_PUBKEY_PATH = FIXTURE_DIR / "sdjwtvc_issuer_pubkey.json"

_IDENTITY_VCT = "https://credentials.example.com/identity_credential"
_PID_VCT = "urn:example:eudi:pid:aendgard:1"


def _load_provenance() -> dict:
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


def _load_examples() -> list[str]:
    return [ln.strip() for ln in EXAMPLES_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load_issuer_pubkey_raw() -> bytes:
    """The vendored EC JWK (x, y) as the 65-byte SEC1 uncompressed point 0x04||X||Y
    ``sdjwt.verify_sd_jwt`` expects for an ES256 issuer key."""
    jwk = json.loads(ISSUER_PUBKEY_PATH.read_text(encoding="utf-8"))
    x, y = _b64url_decode(jwk["x"]), _b64url_decode(jwk["y"])
    assert len(x) == 32 and len(y) == 32, "P-256 coordinates must each be 32 bytes"
    return b"\x04" + x + y


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

    def test_all_examples_have_es256_issuer_alg(self) -> None:
        for i, compact in enumerate(self.examples):
            header_b64 = compact.split("~", 1)[0].split(".")[0]
            header = json.loads(_b64url_decode(header_b64))
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


@unittest.skipUnless(EXAMPLES_PATH.exists() and ISSUER_PUBKEY_PATH.exists(),
                     "sdjwtvc examples/issuer-key fixtures not vendored")
class TestSdjwtVcIssuerSignatureExternalVectors(unittest.TestCase):
    """Finding 20 / issue #27 (2026-07-15): the issuer signature is now REAL cryptography, not
    merely a documented out-of-scope boundary. Positive: all 5 examples verify under the vendored,
    independently re-verified issuer key. Negative: adversarial mutations of those same vectors (no
    official negative vectors exist upstream — see the module docstring)."""

    def setUp(self) -> None:
        self.examples = _load_examples()
        self.issuer_pubkey = _load_issuer_pubkey_raw()

    def test_all_examples_issuer_signature_verifies(self) -> None:
        checked = 0
        for i, compact in enumerate(self.examples):
            res = verify_sd_jwt(compact, self.issuer_pubkey)
            self.assertEqual(res["alg"], "ES256", f"example {i}")
            self.assertTrue(res["sig_checked"], f"example {i}: sig_checked must be True when a key is supplied")
            self.assertTrue(res["sig_ok"], f"example {i}: {res['detail']}")
            self.assertTrue(res["structure_ok"], f"example {i}: {res['detail']}")
            checked += 1
        self.assertEqual(checked, 5, "must not vacuously pass over zero vectors")

    def test_tampered_signature_is_rejected(self) -> None:
        compact = self.examples[0]
        jwt, rest = compact.split("~", 1)
        header_b64, payload_b64, sig_b64 = jwt.split(".")
        raw_sig = bytearray(_b64url_decode(sig_b64))
        raw_sig[-1] ^= 0xFF
        tampered_sig_b64 = base64.urlsafe_b64encode(bytes(raw_sig)).rstrip(b"=").decode("ascii")
        tampered = f"{header_b64}.{payload_b64}.{tampered_sig_b64}~{rest}"
        res = verify_sd_jwt(tampered, self.issuer_pubkey)
        self.assertTrue(res["sig_checked"])
        self.assertFalse(res["sig_ok"], "a bit-flipped ES256 signature must not verify")

    def test_signature_does_not_transfer_across_payloads(self) -> None:
        # cross-splice example 0's (identity_credential) signature onto example 3's (a DIFFERENT
        # credential, the recursive PID/aendgard example — examples 0/1/2 are three PRESENTATIONS of
        # the SAME issuer JWT, so they'd share an identical payload_b64 and defeat this test) payload.
        # Both are real, well-formed vendored JSON — no risk of an incidental JSON-parse failure
        # masking what this is actually testing, unlike a raw byte-flip. The signature covers
        # header_b64 + payload_b64 verbatim (RFC 7515 JWS), so it must NOT verify over a different
        # payload — proving it actually covers the issuer-signed CLAIMS, not just the disclosure
        # commitments.
        header0_b64, payload0_b64, sig0_b64 = self.examples[0].split("~", 1)[0].split(".")
        _header3_b64, payload3_b64, _sig3_b64 = self.examples[3].split("~", 1)[0].split(".")
        self.assertNotEqual(payload0_b64, payload3_b64, "examples must actually differ for this test to mean anything")
        spliced = f"{header0_b64}.{payload3_b64}.{sig0_b64}~"
        res = verify_sd_jwt(spliced, self.issuer_pubkey)
        self.assertTrue(res["sig_checked"])
        self.assertFalse(res["sig_ok"], "example 0's signature must not verify over example 3's payload")

    def test_wrong_issuer_key_is_rejected(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        attacker_pub = attacker_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        res = verify_sd_jwt(self.examples[0], attacker_pub)
        self.assertTrue(res["sig_checked"])
        self.assertFalse(res["sig_ok"], "a different (attacker-generated) ES256 key must not verify")

    def test_wrong_key_length_does_not_crash(self) -> None:
        # a 32-byte Ed25519-shaped key handed to an ES256-signed JWT must fail closed, never crash —
        # verify_sd_jwt's "never a crash, always a boolean" contract holds across algorithms.
        res = verify_sd_jwt(self.examples[0], b"\x00" * 32)
        self.assertTrue(res["sig_checked"])
        self.assertFalse(res["sig_ok"])

    def test_examples_kid_matches_vendored_issuer_key_when_present(self) -> None:
        jwk = json.loads(ISSUER_PUBKEY_PATH.read_text(encoding="utf-8"))
        found_with_kid = 0
        for compact in self.examples:
            header_b64 = compact.split("~", 1)[0].split(".")[0]
            header = json.loads(_b64url_decode(header_b64))
            if "kid" in header:
                self.assertEqual(header["kid"], jwk["kid"])
                found_with_kid += 1
        self.assertGreater(found_with_kid, 0, "must not vacuously pass with no kid-bearing example")


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
