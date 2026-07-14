"""B6 evidence-pack hardening for offline long-term verification. The four regressions from the
anchor-longevity enabler prompt, at the MECHANISM level (synthetic upgraded OTS proofs, the same way
test_anchors_ots.py builds them — no real Bitcoin confirmation, which is an Owner-gated calendar
submission).

  * ots_upgraded_proof_is_self_contained   — an upgraded proof (Bitcoin attestation, no pending) is
                                             self-contained; a pending proof is not.
  * offline_verify_from_bundled_bitcoin_headers — a pack + a relying-party trusted headers set confirms
                                             the anchor with no network.
  * multi_calendar_redundancy_verifies      — a pack records >=2 calendars (redundancy) and still verifies.
  * verify_without_network_succeeds         — verify_evidence_pack performs NO socket I/O (proven by
                                             blocking the socket module during the call).

WP-A1 boundary (kept, never crossed): the header the pack BUNDLES is producer-controlled EVIDENCE, never
trust; confirmation needs a relying-party header (which may be an OFFLINE trusted checkpoint, so still no
network). A pack with a bundled header but NO relying-party trust is honestly needs_rp_trust, not a pass.
"""
import base64
import hashlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

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
class TestSelfContained(unittest.TestCase):
    def test_ots_upgraded_proof_is_self_contained(self):
        from proofbundle.evidence_pack import ots_upgraded_proof_is_self_contained
        self.assertTrue(ots_upgraded_proof_is_self_contained(_upgraded_proof()))

    def test_pending_proof_is_not_self_contained(self):
        from proofbundle.evidence_pack import ots_upgraded_proof_is_self_contained
        self.assertFalse(ots_upgraded_proof_is_self_contained(_pending_proof()))

    def test_malformed_proof_is_not_self_contained(self):
        from proofbundle.evidence_pack import ots_upgraded_proof_is_self_contained
        self.assertFalse(ots_upgraded_proof_is_self_contained(b"not an ots proof"))


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestBuildAndVerifyPack(unittest.TestCase):
    def _pack(self, proof: bytes, calendars=None, bundled_headers=None):
        from proofbundle.evidence_pack import build_evidence_pack
        return build_evidence_pack(
            _ROOT, proof,
            calendars=calendars or ["https://alice.btc.calendar.opentimestamps.org",
                                    "https://bob.btc.calendar.opentimestamps.org"],
            bundled_headers=bundled_headers)

    def test_pack_records_self_contained_and_calendars(self):
        pack = self._pack(_upgraded_proof())
        self.assertTrue(pack["selfContained"])
        self.assertEqual(pack["canonicalRoot"], base64.b64encode(_ROOT).decode())
        self.assertGreaterEqual(len(pack["calendars"]), 2)   # multi-calendar redundancy recorded

    def test_multi_calendar_redundancy_verifies(self):
        from proofbundle.evidence_pack import verify_evidence_pack
        pack = self._pack(_upgraded_proof(),
                          calendars=["https://alice.btc.calendar.opentimestamps.org",
                                     "https://bob.btc.calendar.opentimestamps.org",
                                     "https://finney.calendar.opentimestamps.org"])
        self.assertGreaterEqual(pack["calendarRedundancy"], 2)
        rp = {"bitcoin_block_headers": {"800000": _ROOT.hex()}}
        res = verify_evidence_pack(pack, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")

    def test_offline_verify_from_bundled_bitcoin_headers(self):
        # the pack BUNDLES the header as evidence; confirmation still needs a relying-party header (which
        # here is an offline trusted checkpoint). Together, offline, it confirms.
        from proofbundle.evidence_pack import verify_evidence_pack
        pack = self._pack(_upgraded_proof(), bundled_headers={"800000": _ROOT.hex()})
        self.assertTrue(pack["bundledHeaderEvidence"])   # bundled as EVIDENCE, labelled
        rp = {"bitcoin_block_headers": {"800000": _ROOT.hex()}}
        res = verify_evidence_pack(pack, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")

    def test_bundled_header_alone_is_not_trust_wp_a1(self):
        # WP-A1: a pack's own bundled header, without relying-party trust, must NOT confirm.
        from proofbundle.evidence_pack import verify_evidence_pack
        pack = self._pack(_upgraded_proof(), bundled_headers={"800000": _ROOT.hex()})
        res = verify_evidence_pack(pack)   # no rp_trust
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "needs_rp_trust")

    def test_pending_pack_is_warn_not_pass(self):
        from proofbundle.evidence_pack import verify_evidence_pack
        pack = self._pack(_pending_proof())
        self.assertFalse(pack["selfContained"])
        res = verify_evidence_pack(pack)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "pending")

    def test_verify_without_network_succeeds(self):
        # PROVE no network: replace socket.socket with a bomb for the duration of the verify.
        import socket
        from proofbundle.evidence_pack import verify_evidence_pack
        pack = self._pack(_upgraded_proof())
        rp = {"bitcoin_block_headers": {"800000": _ROOT.hex()}}
        real_socket = socket.socket

        def _no_network(*a, **k):
            raise AssertionError("verify_evidence_pack must not open a socket")

        socket.socket = _no_network  # type: ignore[assignment]
        try:
            res = verify_evidence_pack(pack, rp_trust=rp)
        finally:
            socket.socket = real_socket  # type: ignore[assignment]
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
