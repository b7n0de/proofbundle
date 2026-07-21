"""Second-implementation conformance test for MarkovianProtocol's rootcommit vectors (v1 + v2-sig).

proofbundle's OWN `anchors_rootcommit` verifier reproduces the upstream expected outcomes over the 9
vendored vectors, fully offline (no calendar, no Bitcoin node), by independently rebuilding the
domain-separated preimage from each checkpoint's own (origin, size, root) plus the wallet in the anchor
line, recomputing SHA-256(preimage), and reusing proofbundle's OpenTimestamps binding verifier.

Dependency split: the v1 verify and the v2-sig BINDING checks need only proofbundle[anchors]
(opentimestamps); the v2-sig SIGNATURE checks (EIP-191 recovery) additionally need a secp256k1+keccak
backend and skip cleanly if none is installed (never a silent pass). Vendored data + provenance pins are
covered by tests/test_anchors_markovian.py::TestRootcommitVectorsManifest.
"""
from __future__ import annotations

import pathlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle import anchors_rootcommit as rc

_FIXDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "tlog_bitcoin_anchor" / "rootcommit"
_COMMITMENT = "4d1cc236c3872701bb27f9e27fad315e153eeb43a767a2cae958a3bb4014e771"
_WALLET = "0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273"


def _read(rel: str) -> str:
    return (_FIXDIR / rel).read_text()


def _has_sig_backend() -> bool:
    try:
        rc.eip191_recover_address("probe", b"\x00" * 65)   # returns None (bad sig) if a backend exists
        return True
    except rc._NoSigLib:
        return False


_HAS_SIG = _has_sig_backend()


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestRootcommitV1(unittest.TestCase):
    def test_01_valid_binds_through_our_preimage(self):
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-01-valid.txt"))
        self.assertEqual(res["known_anchors"], 1)
        # SECOND-IMPLEMENTATION: our independently rebuilt preimage hashes to the upstream committed value
        self.assertEqual(res["commitment"], _COMMITMENT)
        self.assertEqual(res["wallet"].lower(), _WALLET.lower())
        self.assertTrue(res["binding"], res["detail"])     # OTS proof commits exactly our commitment
        self.assertFalse(res["reject"])

    def test_02_tampered_root_rejects(self):
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-02-tampered-root.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertNotEqual(res["commitment"], _COMMITMENT)  # altered root → different preimage
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])
        self.assertEqual(res["status"], "unbound")

    def test_03_tampered_wallet_rejects(self):
        # the property ots/v1 does NOT have: mutating the wallet (in the opaque) breaks the binding
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-03-tampered-wallet.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertNotEqual(res["commitment"], _COMMITMENT)
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])
        self.assertEqual(res["status"], "unbound")

    def test_04_tampered_proof_rejects(self):
        res = rc.verify_rootcommit_v1(_read("vectors/rootcommit-04-tampered-proof.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])
        self.assertIn(res["status"], ("unbound", "malformed"))

    def test_multiple_anchors_rejected_fail_closed(self):
        # Berkeley MEDIUM (wf_391ec78f): the anchor is a 0xff signed-note signature that does NOT sign the
        # note body, so an attacker can PREPEND a forged rootcommit anchor carrying THEIR wallet without
        # invalidating the genuine witness cosignatures. The verifier must count ALL anchors and fail closed,
        # never silently pick opaques[0] and report known_anchors=1. (The 9 vendored vectors carry exactly one
        # anchor each, so this multiplicity is only exercised here.)
        import base64
        text = _read("vectors/rootcommit-01-valid.txt")
        id_v1 = rc.ID_V1.encode()
        attacker = b"0xATTACKERwa11etAAAAAAAAAAAAAAAAAAAAAAAAAA"
        opaque = b"\x01" + bytes([len(attacker)]) + attacker + b"\x00\x00\x00"   # well-formed line, junk ots
        payload = rc.expected_key_id(id_v1) + bytes([rc.SIG_TYPE]) + bytes([len(id_v1)]) + id_v1 + opaque
        forged = f"— {rc.KEY_NAME} " + base64.b64encode(payload).decode()
        body, sigs = text.split("\n\n", 1)
        tampered = body + "\n\n" + forged + "\n" + sigs   # prepend the forged anchor before the genuine one
        res = rc.verify_rootcommit_v1(tampered)
        self.assertEqual(res["known_anchors"], 2)          # the REAL count, not a hardcoded 1
        self.assertTrue(res["reject"])
        self.assertEqual(res["status"], "multiple_anchors")
        self.assertFalse(res["binding"])
        self.assertNotIn("wallet", res)                    # no single-wallet attribution on multiplicity


class TestRootcommitNeverRaise(unittest.TestCase):
    """Berkeley learned class RT-04 (never-raise), caught by the canonical self-learning pre-sweep (the ad-hoc
    gate missed it): the public verify surfaces return a stable dict carrying the core verdict keys on ANY
    untrusted input (incl. non-str), never a raw exception. No OTS needed (malformed inputs return early)."""
    _CORE = {"known_anchors", "binding", "reject", "status"}

    def test_verify_surfaces_never_raise_on_untrusted_input(self):
        bad_inputs = ["", "no separator", "a\n\nb", "\n\n\n", "x" * 50000,
                      "a.b.c\n\n— markovianprotocol.com/bitcoin-anchor !!notb64!!",
                      b"bytes", None, 123, ["list"], {"d": 1}]
        for fn in (rc.verify_rootcommit_v1, rc.verify_rootcommit_v2sig):
            for bad in bad_inputs:
                res = fn(bad)
                self.assertIsInstance(res, dict)
                self.assertTrue(self._CORE <= set(res),
                                f"{fn.__name__}({bad!r:.20}) missing core verdict keys: {set(res)}")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestRootcommitV2SigBinding(unittest.TestCase):
    """The BINDING half of v2-sig is dep-free (same OTS commit check as v1). The three tamper-of-binding
    vectors reject on binding alone, no signature backend needed."""

    def test_01_valid_binds(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-01-valid.txt"))
        self.assertEqual(res["known_anchors"], 1)
        self.assertEqual(res["commitment"], _COMMITMENT)
        self.assertTrue(res["binding"], res.get("detail"))

    def test_02_tampered_root_rejects_on_binding(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-02-tampered-root.txt"))
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])

    def test_03_tampered_wallet_rejects_on_binding(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-03-tampered-wallet.txt"))
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])

    def test_05_tampered_proof_rejects_on_binding(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-05-tampered-proof.txt"))
        self.assertFalse(res["binding"])
        self.assertTrue(res["reject"])

    def test_no_silent_pass_without_sig_backend(self):
        # honest degradation: without a secp256k1+keccak backend, sig_ok is None (never a silent True)
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-01-valid.txt"))
        if not _HAS_SIG:
            self.assertIsNone(res["sig_ok"])
            self.assertEqual(res["sig_status"], "no_sig_lib")


@unittest.skipUnless(_HAS_OTS and _HAS_SIG, "needs proofbundle[anchors] + a secp256k1/keccak backend")
class TestRootcommitV2SigSignature(unittest.TestCase):
    """The SIGNATURE half of v2-sig: EIP-191 recovery to the bound wallet. Needs a secp256k1+keccak backend."""

    def test_01_valid_signature_recovers_to_wallet(self):
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-01-valid.txt"))
        self.assertTrue(res["binding"])
        self.assertTrue(res["sig_ok"])
        self.assertFalse(res["reject"])

    def test_04_tampered_signature_rejects(self):
        # binding still holds (root/wallet intact) but the corrupted signature no longer recovers the wallet
        res = rc.verify_rootcommit_v2sig(_read("vectors_sig/v2sig-04-tampered-sig.txt"))
        self.assertTrue(res["binding"])
        self.assertFalse(res["sig_ok"])
        self.assertTrue(res["reject"])


if __name__ == "__main__":
    unittest.main()
