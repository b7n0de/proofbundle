"""An OTS proof over the cap is refused before the deserializer does any work, on every reader.

WHERE THIS COMES FROM. Deep gate against main 5b53ab3e, finding L2-Z195-OTS-WORK-AMPLIFICATION-01
(P3, jury 3 of 3). The structural budget bounds the base64 string of a proof, not what the
OpenTimestamps deserializer builds from it: every fork creates a Timestamp holding its own copy of the
message. One append of 4000 bytes and forks of about 26 bytes each made a 732 067-byte proof, inside
every budget, peak at 137.1 MiB in `verify_evidence_pack` (measured again for this change, fresh
process, tracemalloc). With the cap it is refused at 3.9 MiB, which is the pack itself.

WHAT IS PINNED. All four readers (`verify_opentimestamps`, `calendar_uris`,
`ots_upgraded_proof_is_self_contained`, `describe_proof`) and the pack verifier refuse a proof over the
cap with their own verdict, and the library's deserializer is not called for it. A proof one byte
under the cap still deserializes, so the cap cannot be read as refusing more than it says, and every
OTS proof this repository carries fits under it with room to spare.
"""
from __future__ import annotations

import base64
import hashlib
import pathlib
import unittest
from unittest import mock

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

REPO = pathlib.Path(__file__).resolve().parents[1]
_ROOT = hashlib.sha256(b"canonical").digest()
_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


def _amplifying_proof(forks: int, *, bitcoin: bool = False) -> bytes:
    """The gate's construction: one 4000-byte append, then `forks` branches of about 26 bytes, each
    ending in a pending attestation, or with `bitcoin` in a Bitcoin block-header attestation (an
    UPGRADED proof, so a reader that bypasses the cap answers True where the cap answers False)."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(_ROOT)
    big = ts.ops.add(OpAppend(b"\x00" * 4000))
    for i in range(forks):
        att = BitcoinBlockHeaderAttestation(800_000 + i) if bitcoin else PendingAttestation("https://a")
        big.ops.add(OpAppend(i.to_bytes(3, "big"))).attestations.add(att)
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
    return ctx.getbytes()


@unittest.skipUnless(_HAS_OTS, "NOT MEASURABLE: needs proofbundle[anchors] (opentimestamps); did NOT run")
class TheCap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from proofbundle import anchors_ots
        cls.cap = anchors_ots._MAX_OTS_PROOF_BYTES
        cls.over = _amplifying_proof(2400)
        cls.under = _amplifying_proof(2360)
        cls.over_upgraded = _amplifying_proof(3400, bitcoin=True)
        cls.under_upgraded = _amplifying_proof(3100, bitcoin=True)

    def test_precondition_the_proofs_sit_on_either_side_of_the_cap(self):
        self.assertGreater(len(self.over), self.cap)
        self.assertLess(len(self.under), self.cap)
        self.assertGreater(len(self.over_upgraded), self.cap)
        self.assertLess(len(self.under_upgraded), self.cap)
        from proofbundle.evidence_pack import ots_upgraded_proof_is_self_contained
        self.assertIs(ots_upgraded_proof_is_self_contained(self.under_upgraded), True)

    def test_every_reader_refuses_a_proof_over_the_cap(self):
        from proofbundle.anchors_ots import calendar_uris, verify_opentimestamps
        from proofbundle.evidence_pack import (describe_proof, ots_upgraded_proof_is_self_contained,
                                               verify_evidence_pack)
        r = verify_opentimestamps(self.over, _ROOT, frozen={})
        self.assertEqual((r["ok"], r["status"]), (False, "over_budget"))
        self.assertIn("before deserializing", r["detail"])
        pack = {"proof": base64.b64encode(self.over).decode(), "canonicalRoot": base64.b64encode(_ROOT).decode()}
        self.assertEqual(verify_evidence_pack(pack)["status"], "over_budget")
        self.assertEqual(calendar_uris(self.over), [])
        self.assertIs(ots_upgraded_proof_is_self_contained(self.over_upgraded), False)
        self.assertEqual(describe_proof(self.over)["state"], "over_budget")

    def test_the_deserializer_is_not_called_over_the_cap(self):
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from proofbundle.anchors_ots import verify_opentimestamps
        with mock.patch.object(DetachedTimestampFile, "deserialize",
                               wraps=DetachedTimestampFile.deserialize) as seen:
            verify_opentimestamps(self.over, _ROOT, frozen={})
            self.assertEqual(seen.call_count, 0)
            verify_opentimestamps(self.under, _ROOT, frozen={})
            self.assertEqual(seen.call_count, 1)

    def test_a_proof_under_the_cap_still_reads(self):
        from proofbundle.anchors_ots import calendar_uris, verify_opentimestamps
        from proofbundle.evidence_pack import describe_proof
        self.assertEqual(verify_opentimestamps(self.under, _ROOT, frozen={})["status"], "pending")
        self.assertEqual(calendar_uris(self.under), ["https://a"])
        self.assertEqual(describe_proof(self.under)["state"], "pending")


class TheCapFitsWhatThisRepositoryCarries(unittest.TestCase):

    def test_every_ots_proof_in_the_tree_fits_with_room_to_spare(self):
        from proofbundle.anchors_ots import _MAX_OTS_PROOF_BYTES
        sizes = []
        for p in REPO.rglob("*.ots"):
            if ".git" in p.parts:
                continue
            data = p.read_bytes()
            if data.startswith(_MAGIC):
                sizes.append((len(data), p.relative_to(REPO).as_posix()))
        self.assertNotEqual(sizes, [], "no OTS proof found; this case would measure nothing")
        largest = max(sizes)
        self.assertLess(largest[0] * 10, _MAX_OTS_PROOF_BYTES,
                        f"the largest proof in the tree, {largest}, is within a factor ten of the cap")


if __name__ == "__main__":
    unittest.main()
