"""OpenTimestamps anchor — honest lifecycle: PENDING is a WARN (never a full anchor), an upgraded proof
without a Bitcoin block header is an honest not-pass (never silent), structural binding is enforced.
Paket 1 test 7. Skipped without the [anchors] extra (opentimestamps); a CI job exercises it."""
import hashlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle import anchors

_ROOT = hashlib.sha256(b"ots-canonical-root").digest()


def _serialize(dtf) -> bytes:
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _pending_proof(msg=_ROOT) -> bytes:
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _upgraded_proof(msg=_ROOT, height=800000) -> bytes:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestOpenTimestampsVerifier(unittest.TestCase):
    def test_pending_is_warn_never_pass(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(_pending_proof(), _ROOT, frozen={})
        self.assertFalse(res["ok"])       # a pending proof is NOT a verified anchor
        self.assertTrue(res["warn"])      # but it is a WARN, not a hard fail
        self.assertEqual(res["status"], "pending")

    def test_upgraded_without_header_is_honest_not_pass(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(_upgraded_proof(), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "upgraded_unverified")
        self.assertIn("Bitcoin node", res["detail"])

    def test_pending_and_upgraded_are_distinguished(self):
        # Paket 1 test 7: the two states must be told apart, never collapsed.
        from proofbundle.anchors_ots import verify_opentimestamps
        p = verify_opentimestamps(_pending_proof(), _ROOT, frozen={})
        u = verify_opentimestamps(_upgraded_proof(), _ROOT, frozen={})
        self.assertNotEqual(p["status"], u["status"])

    def test_unbound_proof_fails(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        # a proof over a DIFFERENT message must not verify against our root
        res = verify_opentimestamps(_pending_proof(msg=hashlib.sha256(b"other").digest()), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "unbound")

    def test_malformed_proof_fails_closed(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(b"not an ots proof", _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestOtsThroughGenericLayer(unittest.TestCase):
    def _anchor(self, proof: bytes) -> dict:
        import base64
        return {"type": "opentimestamps", "target": "receipt",
                "canonicalRoot": base64.b64encode(_ROOT).decode(),
                "proof": base64.b64encode(proof).decode(),
                "anchoredAt": "2026-07-05T00:00:00Z"}

    def test_pending_anchor_makes_the_aggregate_warn(self):
        res = anchors.verify_anchors([self._anchor(_pending_proof())], target_roots={"receipt": _ROOT})
        self.assertEqual(res["status"], "WARN")

    def test_pending_does_not_satisfy_require_anchor(self):
        res = anchors.verify_anchors([self._anchor(_pending_proof())], target_roots={"receipt": _ROOT},
                                     require="opentimestamps")
        self.assertEqual(res["status"], "FAIL")   # a pending proof is not a verifying anchor

    def test_root_mismatch_still_hard_fails(self):
        res = anchors.verify_anchors([self._anchor(_pending_proof())], target_roots={"receipt": b"\x00" * 32})
        self.assertEqual(res["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
