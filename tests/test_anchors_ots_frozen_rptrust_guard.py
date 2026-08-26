"""iter9 Fix-the-Class (Deep-Gate Linse 3): anchors_ots.verify_opentimestamps liefert fuer JEDEN Wert
seiner container-typisierten Eingaben (frozen, rp_trust) ein VERDIKT oder eine ProofBundleError — ein
Nicht-Mapping darf nie ein blankes `.get` erreichen (roher AttributeError). Dieselbe Typ-Konfusions-
Klasse wie iter8, an einem dict-Argument statt am dekodierten JSON-Blatt. anchors_rfc3161 + verify_anchor
hatten den Guard, OTS/markovian nicht."""
import hashlib
import unittest

from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.serialize import BytesSerializationContext
from proofbundle.anchors_ots import verify_opentimestamps


def _upgraded_proof(root: bytes) -> bytes:
    """Ein form-gueltiger UPGRADED OTS-Proof (Bitcoin-Attest unter einer Hash-Op) — nur so wird der
    frozen/rp_trust-Pfad ueberhaupt erreicht (has_bitcoin=True; garbage returnt vorher)."""
    ts = Timestamp(root)
    child = ts.ops.add(OpAppend(b"\x01"))
    gc = child.ops.add(OpSHA256())
    gc.attestations.add(BitcoinBlockHeaderAttestation(700000))
    dtf = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


class TestOtsFrozenRpTrustGuard(unittest.TestCase):
    def setUp(self):
        self.root = hashlib.sha256(b"target").digest()
        self.proof = _upgraded_proof(self.root)

    def test_kontrolle_sauberer_proof_liefert_verdikt(self):
        r = verify_opentimestamps(self.proof, self.root, frozen={}, rp_trust={})
        self.assertIsInstance(r, dict)
        self.assertEqual(r["status"], "needs_rp_trust")   # ohne RP-Header, korrekt

    def test_frozen_liste_liefert_verdikt(self):        # Lens-3-Exploit 1
        r = verify_opentimestamps(self.proof, self.root, frozen=[])
        self.assertIsInstance(r, dict)
        self.assertEqual(r["status"], "malformed")

    def test_frozen_none_liefert_verdikt(self):
        r = verify_opentimestamps(self.proof, self.root, frozen=None)
        self.assertIsInstance(r, dict)
        self.assertEqual(r["status"], "malformed")

    def test_rp_trust_mit_listen_wert_liefert_verdikt(self):   # Lens-3-Exploit 2
        r = verify_opentimestamps(self.proof, self.root, frozen={},
                                  rp_trust={"bitcoin_block_headers": [1, 2]})
        self.assertIsInstance(r, dict)
        self.assertEqual(r["status"], "malformed")

    def test_rp_trust_nicht_mapping_liefert_verdikt(self):
        r = verify_opentimestamps(self.proof, self.root, frozen={}, rp_trust=[1, 2])
        self.assertIsInstance(r, dict)
        self.assertEqual(r["status"], "malformed")


if __name__ == "__main__":
    unittest.main()
