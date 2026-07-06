"""markovian-provenance/v1 — a third-party anchor type demonstrating register_anchor_type.

Same discipline as the built-in types: fail-closed everywhere, PENDING is a WARN (inherited from the
composed OpenTimestamps verifier), the wallet<->data binding is enforced, and a real Bitcoin-confirmed
fixture (block 956857) verifies through the generic layer. Skipped without the [anchors] extra."""
import base64
import hashlib
import json
import pathlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle import anchors

_ROOT = hashlib.sha256(b"markovian-prereg-root").digest()
_SALT = "00112233445566778899aabbccddeeff"
_WALLET = "1MKVtestWa11etAAAAAAAAAAAAAAAAAAAA"
_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "markovian_anchor_confirmed.json"


def _serialize(dtf) -> bytes:
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _pending_ots(msg=_ROOT) -> bytes:
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _upgraded_ots(msg=_ROOT, height=850000) -> bytes:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _envelope(ots: bytes, *, data_hash=_ROOT.hex(), salt=_SALT, wallet=_WALLET,
              merkle_root=None, schema="markovian-provenance/v1") -> bytes:
    if merkle_root is None:
        merkle_root = hashlib.sha256(f"{data_hash}:{salt}:{wallet}".encode()).hexdigest()
    env = {"schema": schema, "data_hash": data_hash, "salt": salt, "wallet": wallet,
           "merkle_root": merkle_root, "block_height": 77810,
           "ots": base64.b64encode(ots).decode()}
    return json.dumps(env).encode()


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestMarkovianVerifier(unittest.TestCase):
    def setUp(self):
        from proofbundle.anchors_markovian import verify_markovian
        self.verify = verify_markovian

    def test_confirmed_synthetic(self):
        # upgraded OTS whose attestation sits on the root + supplied block merkle root == root -> confirmed
        frozen = {"bitcoinBlockHeaderMerkleRootsByHeight": {"850000": _ROOT.hex()}}
        res = self.verify(_envelope(_upgraded_ots(height=850000)), _ROOT, frozen=frozen)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")
        self.assertIn(_WALLET, res["detail"])          # PASS names the committing wallet

    def test_pending_is_warn_never_pass(self):
        res = self.verify(_envelope(_pending_ots()), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertTrue(res["warn"])                    # inherited from the OTS lifecycle
        self.assertEqual(res["status"], "pending")

    def test_unbound_data_hash_fails(self):
        # envelope commits to a DIFFERENT data_hash than the target canonical root
        other = hashlib.sha256(b"different").hexdigest()
        res = self.verify(_envelope(_upgraded_ots(), data_hash=other), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "unbound")

    def test_envelope_tampered_fails(self):
        # merkle_root does not equal sha256(data_hash:salt:wallet) -> inconsistent envelope
        res = self.verify(_envelope(_upgraded_ots(), merkle_root="00" * 32), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "envelope_mismatch")

    def test_wallet_swap_breaks_binding(self):
        # swapping the wallet without recomputing merkle_root is caught (the wallet is bound to the data)
        env = json.loads(_envelope(_upgraded_ots()))
        env["wallet"] = "1ATTACKERwa11etAAAAAAAAAAAAAAAAAAA"
        res = self.verify(json.dumps(env).encode(), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "envelope_mismatch")

    def test_bad_schema_fails(self):
        res = self.verify(_envelope(_upgraded_ots(), schema="not-markovian"), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "bad_schema")

    def test_malformed_fails_closed(self):
        res = self.verify(b"not json at all", _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "malformed")

    def test_upgraded_without_header_is_honest_not_pass(self):
        # inherits the OTS "upgraded but unverifiable offline without a header" honest report
        res = self.verify(_envelope(_upgraded_ots()), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "upgraded_unverified")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestMarkovianThroughGenericLayer(unittest.TestCase):
    def setUp(self):
        from proofbundle.anchors_markovian import register
        register()   # third-party type is opt-in; register it before the generic layer will dispatch to it

    def test_real_confirmed_fixture_passes(self):
        # the real fixture: our block-956857 Bitcoin-confirmed OpenTimestamps proof wrapped in a
        # markovian-provenance/v1 stamp, verified end to end through anchors.verify_anchors.
        anchor = json.loads(_FIXTURE.read_text())
        root = base64.b64decode(anchor["canonicalRoot"])
        res = anchors.verify_anchors([anchor], target_roots={"preRegistration": root})
        self.assertEqual(res["status"], "PASS", res["detail"])
        self.assertTrue(res["results"][0]["ok"])

    def test_confirmed_fixture_satisfies_require_anchor(self):
        anchor = json.loads(_FIXTURE.read_text())
        root = base64.b64decode(anchor["canonicalRoot"])
        res = anchors.verify_anchors([anchor], target_roots={"preRegistration": root},
                                     require="markovian-provenance/v1")
        self.assertEqual(res["status"], "PASS", res["detail"])

    def test_cross_target_root_mismatch_hard_fails(self):
        # a preRegistration anchor must never validate against a different root
        anchor = json.loads(_FIXTURE.read_text())
        res = anchors.verify_anchors([anchor], target_roots={"preRegistration": b"\x00" * 32})
        self.assertEqual(res["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
