"""C2SP tlog-checkpoint (v0.9): byte-exact note, em-dash, keyID formula, round-trip, tamper, '+'-in-key."""
import base64
import hashlib
import unittest

from proofbundle import checkpoint as cp
from proofbundle.emit import _raw_pub, generate_signer

ORIGIN = "proofbundle.example/log"
ROOT = bytes(range(32))


class TestCheckpoint(unittest.TestCase):
    def test_note_format(self):
        note = cp.checkpoint_note(ORIGIN, 42, ROOT)
        lines = note.split("\n")
        self.assertEqual(lines[0], ORIGIN)
        self.assertEqual(lines[1], "42")                     # decimal, no leading zeros
        self.assertEqual(lines[2], base64.b64encode(ROOT).decode())   # standard base64
        self.assertNotIn("-", lines[2])                      # not base64url
        self.assertNotIn("_", lines[2])
        self.assertTrue(note.endswith("\n"))

    def test_key_id_formula(self):
        pub = _raw_pub(generate_signer())
        expected = hashlib.sha256(ORIGIN.encode() + b"\n" + bytes([0x01]) + pub).digest()[:4]
        self.assertEqual(cp.key_id(ORIGIN, pub), expected)

    def test_signature_line_is_em_dash(self):
        signer = generate_signer()
        sn = cp.sign_checkpoint(ORIGIN, 42, ROOT, signer, ORIGIN)
        sig_line = [ln for ln in sn.split("\n") if ln][-1]
        self.assertTrue(sig_line.startswith("— "))      # EM DASH U+2014, not '-'
        self.assertNotIn("DSSEv1", sn)                       # raw note bytes, no PAE

    def test_roundtrip(self):
        signer = generate_signer()
        sn = cp.sign_checkpoint(ORIGIN, 42, ROOT, signer, ORIGIN)
        r = cp.verify_checkpoint(sn, cp.vkey(ORIGIN, _raw_pub(signer)))
        self.assertTrue(r["ok"])
        self.assertEqual(r["tree_size"], 42)
        self.assertEqual(r["root"], ROOT)

    def test_roundtrip_with_plus_in_keymaterial(self):
        # standard base64 can contain '+'; vkey parsing must not over-split on it
        signer = None
        for _ in range(300):
            s = generate_signer()
            if "+" in cp.vkey(ORIGIN, _raw_pub(s)).split("+", 2)[2]:
                signer = s
                break
        self.assertIsNotNone(signer, "could not find a key with '+' in its base64 material")
        sn = cp.sign_checkpoint(ORIGIN, 7, ROOT, signer, ORIGIN)
        self.assertTrue(cp.verify_checkpoint(sn, cp.vkey(ORIGIN, _raw_pub(signer)))["ok"])

    def test_tamper_and_foreign_key_rejected(self):
        signer = generate_signer()
        sn = cp.sign_checkpoint(ORIGIN, 42, ROOT, signer, ORIGIN)
        vk = cp.vkey(ORIGIN, _raw_pub(signer))
        parts = sn.split("\n")
        parts[2] = base64.b64encode(bytes(32)).decode()      # tamper the root
        self.assertFalse(cp.verify_checkpoint("\n".join(parts), vk)["ok"])
        self.assertFalse(cp.verify_checkpoint(sn, cp.vkey(ORIGIN, _raw_pub(generate_signer())))["ok"])

    def test_leading_zero_size_rejected(self):
        signer = generate_signer()
        sn = cp.sign_checkpoint(ORIGIN, 42, ROOT, signer, ORIGIN).replace("\n42\n", "\n042\n", 1)
        with self.assertRaises(Exception):
            cp.verify_checkpoint(sn, cp.vkey(ORIGIN, _raw_pub(signer)))
