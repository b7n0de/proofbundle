"""proofbundle.anchors_ots.verify_opentimestamps against REAL OpenTimestamps example proofs.

These vectors do not come from proofbundle itself — they are vendored verbatim from the official
opentimestamps/javascript-opentimestamps repo's `examples/` directory (see
tests/fixtures/ots/PROVENANCE.json), which is the canonical set of example `.ots` proofs used
across the OpenTimestamps ecosystem to exercise the pending/upgraded/confirmed lifecycle.

Two paths, matching the honest lifecycle documented in proofbundle.anchors_ots:

  * PENDING path (incomplete.txt, merkle2.txt, two-calendars.txt, known-and-unknown-notary.txt):
    these proofs carry only calendar PendingAttestations, no Bitcoin attestation. Deserializing
    them does NOT need ripemd160 (empirically confirmed — see module-level probe below), so these
    tests run unconditionally.

  * CONFIRMED path (hello-world.txt.ots): this proof is upgraded with a real Bitcoin block-header
    attestation at height 358391. The op DAG that `opentimestamps` walks while deserializing it
    uses RIPEMD160 (the classic Bitcoin OP_HASH160-style commitment), which needs OpenSSL's
    "legacy" provider — NOT available by default on OpenSSL 3.x (`hashlib.new("ripemd160")`
    raises `unsupported hash type`). This test is `@skipUnless` that probe passes. The block
    header's `merkle_root` (tests/fixtures/ots/block358391.json, sourced from the Blockstream
    Esplora API) is documented in Bitcoin's human-readable BIG-ENDIAN display order and had to be
    BYTE-REVERSED to the internal little-endian wire order proofbundle compares against — this
    was empirically confirmed out-of-band (OPENSSL_CONF pointing at a legacy-provider-enabled
    config, outside the normal test env) to make verify_opentimestamps() return
    status="confirmed"/ok=True; the reversed value is what test_confirmed_path_with_correct_rp_header
    below uses. Without that env, this whole class is honestly SKIPPED, never faked green.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

try:
    hashlib.new("ripemd160")
    _HAS_RIPEMD160 = True
except ValueError:
    _HAS_RIPEMD160 = False

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "ots"
PROVENANCE_PATH = FIXTURE_DIR / "PROVENANCE.json"

_PENDING_NAMES = ["incomplete.txt", "merkle2.txt", "two-calendars.txt", "known-and-unknown-notary.txt"]


def _load_provenance() -> dict:
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


def _root_of(name: str) -> bytes:
    return hashlib.sha256((FIXTURE_DIR / name).read_bytes()).digest()


def _proof(name: str) -> bytes:
    return (FIXTURE_DIR / (name + ".ots")).read_bytes()


@unittest.skipUnless(PROVENANCE_PATH.exists(), "ots fixtures not vendored (tests/fixtures/ots/)")
class TestOtsFixtureIntegrity(unittest.TestCase):
    def test_provenance_pins_every_vendored_file(self) -> None:
        prov = _load_provenance()
        entries = {e["filename"] for e in prov["files"]}
        vendored = {p.name for p in FIXTURE_DIR.iterdir()
                   if p.is_file() and p.name != "PROVENANCE.json"}
        self.assertTrue(vendored, "no vendored files found — vacuous provenance check")
        self.assertEqual(vendored, entries,
                         "every vendored file must have a PROVENANCE.json entry (and vice versa)")

    def test_fixture_sha256_matches_provenance(self) -> None:
        prov = _load_provenance()
        for entry in prov["files"]:
            actual = hashlib.sha256((FIXTURE_DIR / entry["filename"]).read_bytes()).hexdigest()
            self.assertEqual(actual, entry["sha256"],
                             f"{entry['filename']} does not match its PROVENANCE.json pin (tampered)")

    def test_tampered_fixture_is_detected(self) -> None:
        real = (FIXTURE_DIR / "hello-world.txt.ots").read_bytes()
        tampered = bytearray(real)
        tampered[0] ^= 0xFF
        prov = _load_provenance()
        pin = next(e["sha256"] for e in prov["files"] if e["filename"] == "hello-world.txt.ots")
        self.assertNotEqual(hashlib.sha256(bytes(tampered)).hexdigest(), pin,
                            "a single-byte tamper must change the SHA-256 (pin is not vacuous)")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestOtsPendingPathExternalVectors(unittest.TestCase):
    """4 real calendar-only (not yet Bitcoin-anchored) example proofs — every one must be reported
    as an honest WARN, never a silent pass and never a hard fail."""

    def test_all_four_pending_examples_are_warn_never_pass(self) -> None:
        from proofbundle.anchors_ots import verify_opentimestamps
        checked = 0
        for name in _PENDING_NAMES:
            res = verify_opentimestamps(_proof(name), _root_of(name), frozen={})
            self.assertFalse(res["ok"], f"{name}: a pending proof must never be ok=True")
            self.assertTrue(res["warn"], f"{name}: a pending proof must be warn=True")
            self.assertEqual(res["status"], "pending", f"{name}: expected status=pending")
            checked += 1
        self.assertEqual(checked, len(_PENDING_NAMES), "must not vacuously pass over zero vectors")

    def test_pending_examples_reject_wrong_root(self) -> None:
        from proofbundle.anchors_ots import verify_opentimestamps
        for name in _PENDING_NAMES:
            wrong_root = hashlib.sha256(b"not the real file content: " + name.encode()).digest()
            res = verify_opentimestamps(_proof(name), wrong_root, frozen={})
            self.assertFalse(res["ok"])
            self.assertEqual(res["status"], "unbound",
                             f"{name}: a proof bound to a different root must be status=unbound")

    def test_known_and_unknown_notary_example_is_pending(self) -> None:
        # Paket 1 test 7 style: this specific example mixes a known + an unknown calendar notary —
        # both are still just PendingAttestations, so the verdict must be identical to the others.
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(_proof("known-and-unknown-notary.txt"),
                                    _root_of("known-and-unknown-notary.txt"), frozen={})
        self.assertEqual(res["status"], "pending")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
@unittest.skipUnless(_HAS_RIPEMD160,
                     "hello-world.txt.ots's op DAG needs ripemd160 (OpenSSL legacy provider not "
                     "active in this interpreter — hashlib.new('ripemd160') raises)")
class TestOtsConfirmedPathExternalVector(unittest.TestCase):
    """The real hello-world.txt.ots example, upgraded with a genuine Bitcoin block-358391
    attestation. WP-A1: the block header must come from the RELYING PARTY, never trusted from the
    proof's own `frozen` block."""

    def setUp(self) -> None:
        self.proof = _proof("hello-world.txt")
        self.root = _root_of("hello-world.txt")
        block = json.loads((FIXTURE_DIR / "block358391.json").read_text(encoding="utf-8"))
        self.height = block["height"]
        # Bitcoin block explorers report merkle_root in human BIG-ENDIAN display order; the OTS
        # BitcoinBlockHeaderAttestation commits to the internal LITTLE-ENDIAN wire order.
        self.merkle_root_le_hex = bytes.fromhex(block["merkle_root"])[::-1].hex()

    def test_confirmed_path_with_correct_rp_header(self) -> None:
        from proofbundle.anchors_ots import verify_opentimestamps
        rp = {"bitcoin_block_headers": {str(self.height): self.merkle_root_le_hex}}
        res = verify_opentimestamps(self.proof, self.root, frozen={}, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")
        self.assertTrue(res["rp_trusted"])
        self.assertEqual(res["trustedTime"], {"source": "bitcoin_block", "height": self.height})

    def test_no_rp_header_is_honest_not_pass(self) -> None:
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(self.proof, self.root, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "needs_rp_trust")

    def test_wrong_rp_header_is_block_mismatch(self) -> None:
        from proofbundle.anchors_ots import verify_opentimestamps
        bad = bytearray(bytes.fromhex(self.merkle_root_le_hex))
        bad[0] ^= 0xFF
        rp = {"bitcoin_block_headers": {str(self.height): bytes(bad).hex()}}
        res = verify_opentimestamps(self.proof, self.root, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "block_mismatch")

    def test_big_endian_display_root_does_not_confirm(self) -> None:
        # Regression-shape check on the byte-order claim itself: feeding the UN-reversed
        # (display/big-endian) merkle root must NOT confirm — proves the little-endian reversal
        # above is load-bearing, not decorative.
        from proofbundle.anchors_ots import verify_opentimestamps
        block = json.loads((FIXTURE_DIR / "block358391.json").read_text(encoding="utf-8"))
        rp = {"bitcoin_block_headers": {str(self.height): block["merkle_root"]}}
        res = verify_opentimestamps(self.proof, self.root, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "block_mismatch")


if __name__ == "__main__":
    unittest.main()
