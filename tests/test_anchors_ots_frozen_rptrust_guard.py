"""iter9 Fix-the-Class (Deep-Gate Linse 3): anchors_ots.verify_opentimestamps liefert fuer JEDEN Wert
seiner container-typisierten Eingaben (frozen, rp_trust) ein VERDIKT oder eine ProofBundleError — ein
Nicht-Mapping darf nie ein blankes `.get` erreichen (roher AttributeError). Dieselbe Typ-Konfusions-
Klasse wie iter8, an einem dict-Argument statt am dekodierten JSON-Blatt. anchors_rfc3161 + verify_anchor
hatten den Guard, OTS/markovian nicht."""
import hashlib
import unittest

# anchors OTS test: the opentimestamps names live in the [anchors] extra. Guard the import so the
# module COLLECTS without the extra and its OTS classes SKIP — never a collection ImportError under
# pytest (published-artifact-gate installs [test]) nor a discover error under `unittest discover`
# (ci.yml installs [dev], both anchor-free). unittest- AND pytest-compatible; matches the 8 sibling
# OTS modules' _HAS_OTS pattern.
try:
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256, OpAppend
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False
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


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
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


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestRpHeaderValueGuard(unittest.TestCase):
    """iter9 fix-the-class, eine Ebene tiefer: rp_headers IST ein Mapping, aber seine WERTE muessen
    keine Hex-Strings sein. `bytes.fromhex(<Nicht-str>)` wirft TypeError (nicht ValueError) — der
    Fang muss beide fassen, sonst crasht ein Listen-/int-Wert roh (der Nachbar des Guards)."""
    def setUp(self):
        self.root = hashlib.sha256(b"target").digest()
        self.proof = _upgraded_proof(self.root)

    def test_rp_header_listen_wert_liefert_verdikt(self):
        r = verify_opentimestamps(self.proof, self.root, frozen={},
                                  rp_trust={"bitcoin_block_headers": {"700000": [1, 2]}})
        self.assertIsInstance(r, dict)
        self.assertNotIn(r.get("status"), (None,))   # ein Verdikt, kein Crash

    def test_rp_header_int_wert_liefert_verdikt(self):
        r = verify_opentimestamps(self.proof, self.root, frozen={},
                                  rp_trust={"bitcoin_block_headers": {"700000": 123}})
        self.assertIsInstance(r, dict)

    def test_rp_header_bad_hex_liefert_verdikt(self):
        r = verify_opentimestamps(self.proof, self.root, frozen={},
                                  rp_trust={"bitcoin_block_headers": {"700000": "xyz"}})
        self.assertIsInstance(r, dict)
