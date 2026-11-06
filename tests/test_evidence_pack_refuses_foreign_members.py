"""An evidence pack is judged as the object `build_evidence_pack` writes, not as any dict with a proof.

DELTA2 N3 (2026-11-06). `verify_evidence_pack` read `proof` and `canonicalRoot` and handed them to
the OpenTimestamps verifier. `type` and `packVersion` were never compared, and a member the builder
never writes was carried along unread, so a pack of another type or version, or with a foreign
member, came back with the verdict of its proof. A container check names its members and refuses
foreign ones, each by repr.
"""
import base64
import hashlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _OTS = True
except ImportError:  # pragma: no cover
    _OTS = False

_ROOT = hashlib.sha256(b"delta2-n3-pack-root").digest()


def _pack():
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    from proofbundle.evidence_pack import build_evidence_pack
    ts = Timestamp(_ROOT)
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
    return build_evidence_pack(_ROOT, ctx.getbytes(), declared_calendars=["https://x.example"],
                               bundled_headers={"800000": "00" * 32})


@unittest.skipUnless(_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TheVerifierRefusesWhatTheBuilderDoesNotWrite(unittest.TestCase):
    def test_positive_control_a_built_pack_reaches_the_proof(self):
        from proofbundle.evidence_pack import verify_evidence_pack
        res = verify_evidence_pack(_pack())
        self.assertEqual(res["status"], "pending", res)

    def test_a_foreign_member_is_refused_and_named(self):
        from proofbundle.evidence_pack import verify_evidence_pack
        for name in ("extra", "Proof", "verified"):
            with self.subTest(member=name):
                pack = _pack()
                pack[name] = True
                res = verify_evidence_pack(pack)
                self.assertIs(res["ok"], False)
                self.assertEqual(res["status"], "malformed_pack", res)
                self.assertIn(repr(name), res["detail"])

    def test_another_type_or_version_is_refused(self):
        from proofbundle.evidence_pack import verify_evidence_pack
        for feld, wert in (("type", "something-else"), ("packVersion", "v9.9"), ("type", None),
                           ("packVersion", None)):
            with self.subTest(field=feld, value=wert):
                pack = _pack()
                if wert is None:
                    del pack[feld]
                else:
                    pack[feld] = wert
                res = verify_evidence_pack(pack)
                self.assertEqual(res["status"], "malformed_pack", res)
                self.assertIn(feld, res["detail"])

    def test_the_seed_pack_of_the_public_surface_still_verifies(self):
        """The pack in tests/fixtures/public_surface_seeds.json omits the optional members; the
        closed set must not refuse what the builder may leave out."""
        from proofbundle.evidence_pack import verify_evidence_pack
        pack = _pack()
        for optional in ("declaredCalendars", "declaredCalendarOperators",
                         "declaredCalendarsVerified", "frozen"):
            pack.pop(optional)
        self.assertEqual(verify_evidence_pack(pack)["status"], "pending")


if __name__ == "__main__":
    unittest.main()
