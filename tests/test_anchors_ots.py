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


# Null-Op hardening (2026-07-17): a REAL upgraded proof attests the block merkle root at the END of an op
# chain (append a nonce, then SHA-256) below the file digest, so the attested value DIFFERS from the file
# digest. verify_opentimestamps now refuses a leaf==root Null-Op branch, so the synthetic helpers must
# build the genuine shape and confirm tests must supply the ATTESTED root (not the file digest) as the
# relying-party header. `_btc_root` / `_multi_btc_root` compute exactly the value the helpers attest.
def _btc_root(msg=_ROOT, nonce=b"\x00") -> bytes:
    return hashlib.sha256(msg + nonce).digest()


def _multi_btc_root(index, msg=_ROOT) -> bytes:
    return hashlib.sha256(msg + bytes([index + 1])).digest()


def _pending_proof(msg=_ROOT) -> bytes:
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _upgraded_proof(msg=_ROOT, height=800000, nonce=b"\x00") -> bytes:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    # a real op chain below the file digest (append a nonce, then SHA-256): the attested block merkle root
    # is sha256(msg ‖ nonce) != file_digest — a genuine proof shape, not a refused leaf==root Null-Op.
    leaf = ts.ops.add(OpAppend(nonce)).ops.add(OpSHA256())
    leaf.attestations.add(BitcoinBlockHeaderAttestation(height))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _multi_bitcoin_proof(msg=_ROOT, heights=(111, 222)) -> bytes:
    """A proof carrying SEVERAL Bitcoin attestations (independent branches), each at the end of its OWN real
    op chain (append a distinct nonce, then SHA-256) below the SAME file digest — so any branch whose
    attested block matches confirms, and none is a leaf==root Null-Op. Branch #i attests `_multi_btc_root(i)`."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    for i, h in enumerate(heights):
        leaf = ts.ops.add(OpAppend(bytes([i + 1]))).ops.add(OpSHA256())
        leaf.attestations.add(BitcoinBlockHeaderAttestation(h))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestMultiBranchAttestationScan(unittest.TestCase):
    """Berkeley audit 2026-07-16 (MAJOR): the attestation loop returned on the FIRST relying-party-covered
    height, so one wrong/tampered branch masked a genuinely confirmable one (False-REJECT / DoS). The fix
    scans ALL covered branches and confirms as soon as any matches. Both orderings are asserted because the
    library's iteration order is not caller-controlled — whichever ordering puts the WRONG branch first is
    the one the old code fails on."""

    def test_wrong_branch_never_masks_a_confirmable_one_case_a(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        proof = _multi_bitcoin_proof()
        rp = {"bitcoin_block_headers": {"111": "00" * 32,
                                        "222": _multi_btc_root(1).hex()}}  # 111 wrong, 222 right
        res = verify_opentimestamps(proof, _ROOT, frozen={}, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["trustedTime"], {"source": "bitcoin_block", "height": 222})

    def test_wrong_branch_never_masks_a_confirmable_one_case_b(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        proof = _multi_bitcoin_proof()
        rp = {"bitcoin_block_headers": {"111": _multi_btc_root(0).hex(),
                                        "222": "00" * 32}}  # 111 right, 222 wrong
        res = verify_opentimestamps(proof, _ROOT, frozen={}, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["trustedTime"], {"source": "bitcoin_block", "height": 111})

    def test_all_covered_branches_wrong_is_block_mismatch_listing_every_height(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        proof = _multi_bitcoin_proof()
        rp = {"bitcoin_block_headers": {"111": "00" * 32, "222": "11" * 32}}   # both present-and-wrong
        res = verify_opentimestamps(proof, _ROOT, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "block_mismatch")
        self.assertEqual(res["mismatchHeights"], [111, 222])   # per-branch tamper diagnostic retained

    def test_bad_hex_branch_does_not_mask_a_confirmable_one(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        proof = _multi_bitcoin_proof()
        rp = {"bitcoin_block_headers": {"222": "not-hex",
                                        "111": _multi_btc_root(0).hex()}}  # 222 malformed, 111 right
        res = verify_opentimestamps(proof, _ROOT, frozen={}, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])                # a bad-hex branch never blocks a good one
        self.assertEqual(res["status"], "confirmed")

    def test_only_bad_hex_covered_is_bad_header_not_confirmed(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        proof = _multi_bitcoin_proof()
        rp = {"bitcoin_block_headers": {"222": "not-hex"}}        # only covered height has bad hex
        res = verify_opentimestamps(proof, _ROOT, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "bad_header")
        self.assertEqual(res["badHeaderHeights"], [222])


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestOpenTimestampsVerifier(unittest.TestCase):
    def test_pending_is_warn_never_pass(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(_pending_proof(), _ROOT, frozen={})
        self.assertFalse(res["ok"])       # a pending proof is NOT a verified anchor
        self.assertTrue(res["warn"])      # but it is a WARN, not a hard fail
        self.assertEqual(res["status"], "pending")

    def test_upgraded_without_rp_header_is_honest_not_pass(self):   # WP-A1 re-pin
        # No relying-party header → not confirmed. WP-A1: a frozen header in the bundle is NOT trust,
        # so even with one present the verdict without rp_trust is needs_rp_trust.
        from proofbundle.anchors_ots import verify_opentimestamps
        frozen = {"bitcoinBlockHeaderMerkleRootsByHeight": {"800000": _ROOT.hex()}}
        res = verify_opentimestamps(_upgraded_proof(height=800000), _ROOT, frozen=frozen)
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "needs_rp_trust")
        self.assertTrue(res["needs_rp_trust"])
        self.assertTrue(res["frozenEvidence"])        # the frozen header is reported as evidence…
        self.assertIn("relying-party", res["detail"])  # …but never trusted

    def test_confirmed_only_against_relying_party_block_merkle_root(self):   # WP-A1 re-pin
        # An upgraded proof + the block's Merkle root supplied by the RELYING PARTY → confirmed. The same
        # value frozen in the bundle does NOT confirm (frozen is producer-controlled = not trust).
        from proofbundle.anchors_ots import verify_opentimestamps
        frozen = {"bitcoinBlockHeaderMerkleRootsByHeight": {"800000": _btc_root().hex()}}
        rp = {"bitcoin_block_headers": {"800000": _btc_root().hex()}}
        confirmed = verify_opentimestamps(_upgraded_proof(height=800000), _ROOT, frozen={}, rp_trust=rp)
        self.assertTrue(confirmed["ok"], confirmed["detail"])
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertTrue(confirmed["rp_trusted"])
        # frozen-only (no rp_trust) with the SAME value must NOT confirm — the whole point of A-1
        frozen_only = verify_opentimestamps(_upgraded_proof(height=800000), _ROOT, frozen=frozen)
        self.assertFalse(frozen_only["ok"])
        self.assertEqual(frozen_only["status"], "needs_rp_trust")

    def test_block_mismatch_when_relying_party_root_is_wrong(self):   # WP-A1 re-pin
        from proofbundle.anchors_ots import verify_opentimestamps
        rp = {"bitcoin_block_headers": {"800000": ("00" * 32)}}
        res = verify_opentimestamps(_upgraded_proof(height=800000), _ROOT, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "block_mismatch")   # present-and-wrong (RP material supplied)

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


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestNullOpAndChainConfusionHardening(unittest.TestCase):
    """WP-A1.c (2026-07-17). Two adversarial branches the 6-lens re-review reproduced live:
      * a self-fabricated NULL-OP pack (a Bitcoin attestation planted DIRECTLY on the canonical root —
        leaf==root, no cryptographic op chain) must never confirm, even when its attested value equals the
        relying-party header a producer supplies (the producer controls file_digest, canonicalRoot AND the
        header, so a leaf==root pack proves nothing);
      * only a BitcoinBlockHeaderAttestation confirms Bitcoin — a Litecoin attestation with a COLLIDING
        integer height (which the old getattr(att,'height') loop counted) is not a Bitcoin confirmation."""

    def _null_op_proof(self, msg=_ROOT, height=800000) -> bytes:
        # the exact attack shape: the attestation sits DIRECTLY on the file digest, no ops between.
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        ts = Timestamp(msg)
        ts.attestations.add(BitcoinBlockHeaderAttestation(height))
        return _serialize(DetachedTimestampFile(OpSHA256(), ts))

    def test_null_op_leaf_equals_root_never_confirms(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        # canonical_root == file_digest == the attested value == the RP header: the fabricator controls all.
        rp = {"bitcoin_block_headers": {"800000": _ROOT.hex()}}
        res = verify_opentimestamps(self._null_op_proof(), _ROOT, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"])                        # the zero-effort fabrication is refused
        self.assertEqual(res["status"], "null_op")
        self.assertEqual(res["nullOpHeights"], [800000])

    def test_real_op_chain_still_confirms_no_over_fire(self):
        # the genuine shape (a real op chain) with its attested root confirms — the fix is not over-firing.
        from proofbundle.anchors_ots import verify_opentimestamps
        rp = {"bitcoin_block_headers": {"800000": _btc_root().hex()}}
        res = verify_opentimestamps(_upgraded_proof(height=800000), _ROOT, frozen={}, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")

    def test_litecoin_attestation_with_colliding_height_is_not_a_bitcoin_confirmation(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,
                                                LitecoinBlockHeaderAttestation)
        from opentimestamps.core.op import OpAppend, OpSHA256
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        ts = Timestamp(_ROOT)
        # a genuine BITCOIN branch at a height the relying party does NOT cover …
        b_leaf = ts.ops.add(OpAppend(b"\x01")).ops.add(OpSHA256())
        b_leaf.attestations.add(BitcoinBlockHeaderAttestation(700000))
        # … and a LITECOIN branch at height 800000 whose attested value the RP header (for Bitcoin 800000)
        # matches. A getattr(att,'height') loop confirms it as Bitcoin; the isinstance filter must not.
        l_leaf = ts.ops.add(OpAppend(b"\x02")).ops.add(OpSHA256())
        l_leaf.attestations.add(LitecoinBlockHeaderAttestation(800000))
        proof = _serialize(DetachedTimestampFile(OpSHA256(), ts))
        rp = {"bitcoin_block_headers": {"800000": _multi_btc_root(1).hex()}}  # == sha256(_ROOT ‖ b"\x02")
        res = verify_opentimestamps(proof, _ROOT, frozen={}, rp_trust=rp)
        self.assertFalse(res["ok"], res)                   # a Litecoin branch is not a Bitcoin anchor
        self.assertNotEqual(res["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
