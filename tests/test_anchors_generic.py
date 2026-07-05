"""Generic anchor-layer contract (no network, no TSA/OTS lib): missing→SKIP, present→fail-closed,
cross-target safety, unknown-type→FAIL, --require-anchor. Paket 1 tests 5, 6, 9, 10 (+ unknown type)."""
import base64
import unittest

from proofbundle import anchors
from proofbundle.errors import BundleFormatError

_RECEIPT_ROOT = b"\xaa" * 32
_PREREG_ROOT = b"\xbb" * 32
_ROOTS = {"receipt": _RECEIPT_ROOT, "preRegistration": _PREREG_ROOT}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _anchor(*, atype="test-anchor", target="receipt", root=_RECEIPT_ROOT, proof=b"proof"):
    return {"type": atype, "target": target, "canonicalRoot": _b64(root),
            "proof": _b64(proof), "anchoredAt": "2026-07-05T12:00:00Z"}


class AnchorRegistryFixture(unittest.TestCase):
    """Registers a deterministic dummy verifier for the tests; unregisters after."""

    def setUp(self):
        self._saved = dict(anchors._VERIFIERS)
        # dummy verifier: ok iff the proof is exactly b"good"
        anchors.register_anchor_type(
            "test-anchor",
            lambda proof, root, *, frozen, now: {"ok": proof == b"good", "detail": "dummy"})

    def tearDown(self):
        anchors._VERIFIERS.clear()
        anchors._VERIFIERS.update(self._saved)


class TestMissingAnchorsSkip(AnchorRegistryFixture):
    def test_no_anchors_is_skip_not_fail(self):
        # Paket 1 test 5: anchors missing → SKIP, verify still passes.
        res = anchors.verify_anchors([], target_roots=_ROOTS)
        self.assertEqual(res["status"], "SKIP")
        self.assertEqual(anchors.verify_anchors(None, target_roots=_ROOTS)["status"], "SKIP")

    def test_require_anchor_missing_is_fail(self):
        # Paket 1 test 9: --require-anchor with no anchors present → FAIL.
        self.assertEqual(anchors.verify_anchors([], target_roots=_ROOTS, require="any")["status"], "FAIL")
        self.assertEqual(
            anchors.verify_anchors([], target_roots=_ROOTS, require="rfc3161-tsa")["status"], "FAIL")


class TestPresentAnchorsFailClosed(AnchorRegistryFixture):
    def test_good_anchor_passes(self):
        res = anchors.verify_anchors([_anchor(proof=b"good")], target_roots=_ROOTS)
        self.assertEqual(res["status"], "PASS")

    def test_bad_proof_fails(self):
        res = anchors.verify_anchors([_anchor(proof=b"bad")], target_roots=_ROOTS)
        self.assertEqual(res["status"], "FAIL")

    def test_root_mismatch_fails(self):
        # Paket 1 test 6: canonicalRoot ≠ target root → FAIL, never silent.
        res = anchors.verify_anchors([_anchor(proof=b"good", root=b"\x00" * 32)], target_roots=_ROOTS)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("canonicalRoot", res["results"][0]["detail"])

    def test_unknown_type_fails_not_skips(self):
        res = anchors.verify_anchors([_anchor(atype="mystery/v9", proof=b"good")], target_roots=_ROOTS)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("no verifier", res["results"][0]["detail"])


class TestCrossTargetSafety(AnchorRegistryFixture):
    def test_prereg_anchor_never_validates_a_receipt_target(self):
        # Paket 1 test 10: a preRegistration anchor carries the prereg root; against a receipt with only a
        # receipt root it fails (no preRegistration target), and if it claims target=receipt its root
        # (prereg) will not equal the receipt root.
        prereg_anchor = _anchor(target="preRegistration", root=_PREREG_ROOT, proof=b"good")
        # receipt has ONLY a receipt target
        res = anchors.verify_anchors([prereg_anchor], target_roots={"receipt": _RECEIPT_ROOT})
        self.assertEqual(res["status"], "FAIL")
        # a preRegistration proof relabelled as target=receipt: its root won't match the receipt root
        mislabelled = _anchor(target="receipt", root=_PREREG_ROOT, proof=b"good")
        res2 = anchors.verify_anchors([mislabelled], target_roots=_ROOTS)
        self.assertEqual(res2["status"], "FAIL")

    def test_receipt_anchor_validates_only_the_receipt_target(self):
        res = anchors.verify_anchors([_anchor(target="receipt", root=_RECEIPT_ROOT, proof=b"good")],
                                     target_roots=_ROOTS)
        self.assertEqual(res["status"], "PASS")


class TestSchemaValidation(AnchorRegistryFixture):
    def test_unknown_field_rejected(self):
        bad = _anchor(proof=b"good")
        bad["evil"] = "x"
        with self.assertRaises(BundleFormatError):
            anchors.verify_anchor(bad, target_roots=_ROOTS)

    def test_bad_target_fails(self):
        res = anchors.verify_anchor(_anchor(target="nonsense", proof=b"good"), target_roots=_ROOTS)
        self.assertFalse(res["ok"])

    def test_prereg_canonical_root_helper(self):
        self.assertEqual(anchors.prereg_canonical_root("ab" * 32), bytes.fromhex("ab" * 32))
        with self.assertRaises(BundleFormatError):
            anchors.prereg_canonical_root("tooshort")


if __name__ == "__main__":
    unittest.main()
