"""ML-DSA-44 witness cosignatures (C2SP type 0x06, FIPS 204) — green + red matrix (v1.3).

Skips cleanly when the cryptography build lacks ML-DSA (needs >=48 on OpenSSL 3.5+, the `[pq]`
extra) — but the UnsupportedError fail-closed contract is tested regardless.
"""
import base64
import hashlib
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import checkpoint as cp
from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError, UnsupportedError

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    mldsa.MLDSA44PrivateKey.generate  # probe
    HAVE_MLDSA = True
except (ImportError, AttributeError):
    HAVE_MLDSA = False

TS = 1_780_000_000
ROOT = hashlib.sha256(b"leaf").digest()
ORIGIN = "example.com/log"


def _raw(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _note():
    log_key = generate_signer()
    note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
    return note, cp.vkey(ORIGIN, _raw(log_key))


@unittest.skipUnless(HAVE_MLDSA, "cryptography build without ML-DSA (install proofbundle[pq])")
class TestMldsaCosign(unittest.TestCase):
    def setUp(self):
        self.note, self.log_vkey = _note()
        self.wk = mldsa.MLDSA44PrivateKey.generate()
        self.wname = "witness.example/pq"
        self.wpub = self.wk.public_key().public_bytes_raw()
        self.cosigned = cp.cosign_checkpoint_mldsa(self.note, self.wk, self.wname, TS)
        self.wvkey = cp.cosign_vkey_mldsa(self.wname, self.wpub)

    def test_green_roundtrip(self):
        res = cp.verify_cosignature(self.cosigned, self.wvkey)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["alg"], "ml-dsa-44")
        self.assertEqual(res["timestamp"], TS)

    def test_green_mixed_quorum(self):
        # One Ed25519 witness + one ML-DSA witness, threshold 2 — algorithms mix freely.
        ed = generate_signer()
        note = cp.cosign_checkpoint(self.cosigned, ed, "w-ed.example/w", TS + 1)
        res = cp.verify_witnessed_checkpoint(
            note, self.log_vkey,
            [self.wvkey, cp.cosign_vkey("w-ed.example/w", _raw(ed))], threshold=2)
        self.assertTrue(res["ok"], res)

    def test_blob_length_exact(self):
        line = self.cosigned.rstrip("\n").split("\n")[-1]
        payload = base64.b64decode(line.split(" ")[2])
        self.assertEqual(len(payload), 4 + 8 + 2420)

    def test_message_commits_to_name(self):
        # Unlike Ed25519, the ML-DSA message commits to the cosigner NAME: a signature made
        # under one name must not verify when presented under another name with the same key.
        other_name = "witness.example/other"
        line = self.cosigned.rstrip("\n").split("\n")[-1]
        payload_b64 = line.split(" ")[2]
        # graft the signature line under a vkey with the other name (recompute its keyID so the
        # keyID check passes and the SIGNATURE is what must fail)
        kid_other = cp.cosign_key_id_mldsa(other_name, self.wpub)
        blob = base64.b64decode(payload_b64)
        forged_blob = kid_other + blob[4:]
        forged_line = f"{cp.EM_DASH} {other_name} {base64.b64encode(forged_blob).decode()}\n"
        forged_note = self.note + forged_line
        res = cp.verify_cosignature(forged_note, cp.cosign_vkey_mldsa(other_name, self.wpub))
        self.assertFalse(res["ok"])

    def test_red_body_tamper(self):
        tampered = self.cosigned.replace("\n7\n", "\n8\n")
        self.assertFalse(cp.verify_cosignature(tampered, self.wvkey)["ok"])

    def test_red_timestamp_tamper(self):
        lines = self.cosigned.rstrip("\n").split("\n")
        payload = base64.b64decode(lines[-1].split(" ")[2])
        ts = int.from_bytes(payload[4:12], "big") + 1
        lines[-1] = (f"{cp.EM_DASH} {self.wname} "
                     + base64.b64encode(payload[:4] + ts.to_bytes(8, "big") + payload[12:]).decode())
        self.assertFalse(cp.verify_cosignature("\n".join(lines) + "\n", self.wvkey)["ok"])

    def test_red_wrong_witness_key(self):
        other = mldsa.MLDSA44PrivateKey.generate()
        other_vkey = cp.cosign_vkey_mldsa(self.wname, other.public_key().public_bytes_raw())
        self.assertFalse(cp.verify_cosignature(self.cosigned, other_vkey)["ok"])

    def test_red_keyid_domain_separation(self):
        # 0x06 keyID differs from a hypothetical 0x04 keyID for the same name (different alg byte).
        self.assertNotEqual(cp.cosign_key_id_mldsa(self.wname, self.wpub),
                            hashlib.sha256(self.wname.encode() + b"\n\x04" + self.wpub).digest()[:4])

    def test_red_vkey_guards(self):
        with self.assertRaises(BundleFormatError):
            cp.cosign_key_id_mldsa(self.wname, b"short")
        with self.assertRaises(BundleFormatError):
            cp.verify_cosignature(self.cosigned, self.log_vkey)   # 0x01 log key never a witness


class TestMldsaMessageKAT(unittest.TestCase):
    """Byte-exact pin of the cosigned_message serialization AGAINST THE SPEC, independent of any
    emit/verify roundtrip. A roundtrip alone is a self-consistency tautology: mutating the shared
    label constant would still roundtrip — this KAT is what kills that mutant."""

    def test_cosigned_message_bytes(self):
        msg = cp._mldsa_cosigned_message("w.example/pq", 1_780_000_000,
                                         "example.com/log", 7, ROOT)
        expected = (b"subtree/v1\n\x00"                                  # label[12], spec-fixed
                    + bytes([len(b"w.example/pq")]) + b"w.example/pq"    # opaque<1..2^8-1> name
                    + (1_780_000_000).to_bytes(8, "big")                 # u64 timestamp
                    + bytes([len(b"example.com/log")]) + b"example.com/log"
                    + (0).to_bytes(8, "big")                             # start = 0 (checkpoint)
                    + (7).to_bytes(8, "big")                             # end = tree size
                    + ROOT)                                              # hash[32]
        self.assertEqual(msg, expected)

    def test_keyid_kat(self):
        # keyID = SHA-256(name ‖ 0x0A ‖ 0x06 ‖ pubkey)[:4] — pinned with a synthetic key.
        pub = bytes(range(256)) * 5 + bytes(32)                          # 1312 bytes
        expected = hashlib.sha256(b"w.example/pq" + b"\n" + b"\x06" + pub).digest()[:4]
        self.assertEqual(cp.cosign_key_id_mldsa("w.example/pq", pub), expected)


class TestMldsaUnavailableFailsClosed(unittest.TestCase):
    def test_unsupported_raises_not_false(self):
        """A 0x06 vkey on a system without ML-DSA must raise UnsupportedError (clear, fail-closed)
        — never return ok=False as if the signature were checked and invalid."""
        note, _ = _note()
        fake_vkey = (ORIGIN + "+00000000+"
                     + base64.b64encode(bytes([0x06]) + b"\x00" * 1312).decode())
        if HAVE_MLDSA:
            # With PQ available the path proceeds to (correctly) not find a matching line.
            self.assertFalse(cp.verify_cosignature(note, fake_vkey)["ok"])
        else:
            with self.assertRaises(UnsupportedError):
                cp.verify_cosignature(note, fake_vkey)


if __name__ == "__main__":
    unittest.main()
