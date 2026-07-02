"""Public-beacon audit challenges (v1.9) — reproducibility, binding, red matrix."""
import hashlib
import unittest

from proofbundle.beacon import (AuditRequest, beacon_audit_challenge, beacon_nonce)
from proofbundle.errors import BundleFormatError
from proofbundle.persample import audit_challenge, build_sample_tree

SECRET = bytes(range(32))
PULSE = bytes(range(32))          # a 32-byte drand-style randomness
ROOT = None


def _tree():
    recs = [{"id": i, "epoch": 1, "ok": i % 2 == 0} for i in range(50)]
    return build_sample_tree(recs, SECRET)


class TestBeaconNonce(unittest.TestCase):
    def test_nonce_binds_beacon_and_round(self):
        a = beacon_nonce(PULSE, "drand:abc", 100)
        self.assertEqual(len(a), 32)
        # different round or beacon → different nonce
        self.assertNotEqual(a, beacon_nonce(PULSE, "drand:abc", 101))
        self.assertNotEqual(a, beacon_nonce(PULSE, "nist", 100))
        self.assertNotEqual(a, beacon_nonce(bytes(range(1, 33)), "drand:abc", 100))

    def test_nonce_is_pinned_construction(self):
        # SHA-256(domain ‖ beacon ‖ 0x00 ‖ u64(round) ‖ pulse) — reproduced independently.
        expected = hashlib.sha256(
            b"proofbundle/v1.9/beacon-nonce\x00" + b"drand:abc" + b"\x00"
            + (100).to_bytes(8, "big") + PULSE).digest()
        self.assertEqual(beacon_nonce(PULSE, "drand:abc", 100), expected)

    def test_red_short_pulse(self):
        with self.assertRaises(BundleFormatError):
            beacon_nonce(b"tooShort", "drand:abc", 100)

    def test_red_bad_round(self):
        for bad in (-1, True, "5"):
            with self.assertRaises(BundleFormatError):
                beacon_nonce(PULSE, "drand:abc", bad)

    def test_red_bad_beacon(self):
        with self.assertRaises(BundleFormatError):
            beacon_nonce(PULSE, "", 100)
        with self.assertRaises(BundleFormatError):
            beacon_nonce(PULSE, "has\x00nul", 100)


class TestBeaconChallenge(unittest.TestCase):
    def test_reproducible_and_matches_manual_nonce(self):
        tree = _tree()
        req = beacon_audit_challenge(tree["root_b64"], tree["n"], 5,
                                     pulse_randomness=PULSE, beacon="drand:abc", round_=100)
        self.assertIsInstance(req, AuditRequest)
        self.assertEqual(len(req.indices), 5)
        self.assertEqual(len(set(req.indices)), 5)          # distinct
        # anyone with the same pulse re-derives the same indices
        again = beacon_audit_challenge(tree["root_b64"], tree["n"], 5,
                                       pulse_randomness=PULSE, beacon="drand:abc", round_=100)
        self.assertEqual(req.indices, again.indices)
        # equals audit_challenge with the derived nonce (beacon mode IS a nonce mode)
        nonce = beacon_nonce(PULSE, "drand:abc", 100)
        self.assertEqual(req.indices, audit_challenge(tree["root_b64"], tree["n"], 5, nonce))

    def test_as_dict_is_publishable(self):
        tree = _tree()
        req = beacon_audit_challenge(tree["root_b64"], tree["n"], 3,
                                     pulse_randomness=PULSE, beacon="nist", round_=7)
        d = req.as_dict()
        self.assertEqual(d["beacon"], "nist")
        self.assertEqual(d["round"], 7)
        self.assertEqual(d["indices"], req.indices)

    def test_different_pulse_different_challenge(self):
        tree = _tree()
        a = beacon_audit_challenge(tree["root_b64"], tree["n"], 5, pulse_randomness=PULSE,
                                   beacon="drand:abc", round_=100).indices
        b = beacon_audit_challenge(tree["root_b64"], tree["n"], 5,
                                   pulse_randomness=bytes(range(1, 33)),
                                   beacon="drand:abc", round_=100).indices
        self.assertNotEqual(a, b)

    def test_cli_beacon_mode(self):
        import contextlib
        import io
        import json
        from proofbundle.cli import main
        tree = _tree()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["audit-challenge", tree["root_b64"], str(tree["n"]), "5",
                       "--beacon-randomness", PULSE.hex(), "--beacon", "drand:abc",
                       "--round", "100", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["mode"], "beacon")
        self.assertEqual(data["beacon"], "drand:abc")
        self.assertEqual(data["round"], 100)
        expected = beacon_audit_challenge(tree["root_b64"], tree["n"], 5, pulse_randomness=PULSE,
                                          beacon="drand:abc", round_=100).indices
        self.assertEqual(data["indices"], expected)

    def test_cli_beacon_requires_round(self):
        import contextlib
        import io
        from proofbundle.cli import main
        tree = _tree()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["audit-challenge", tree["root_b64"], str(tree["n"]), "5",
                                   "--beacon-randomness", PULSE.hex()]), 2)


if __name__ == "__main__":
    unittest.main()
