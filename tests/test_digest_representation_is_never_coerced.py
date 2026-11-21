"""A digest is compared in the representation its field declares, in Python and in pb_verify_rs.

Raw 32-byte octets, bare lowercase hex text and prefixed text are three representations, and none is
silently turned into another before a comparison or before a Merkle leaf is built. These tests hold the
sites where a bundle's digests are read:

- `merkle.verify_inclusion` takes the leaf as the data bytes and the root as 32 raw bytes. The hex
  text of the same leaf or root, as str or as ASCII bytes, is another value and never verifies.
- A bundle's inclusion steps and root are standard base64 with one spelling. A step of another
  length than 32 bytes is a failed inclusion, a root with other pad bits or in the URL-safe alphabet
  is malformed input, and both verifiers give the same exit.
- `pb_verify_rs merkle-root` takes leaf HASHES as hex and builds the RFC 6962 head over them; over
  `leaf_hash(d)` it equals `merkle.merkle_tree_hash(d)` for every size from 0 to 17.

Expected roots come from a reference written here from RFC 9162 section 2.1.1, not from the code
under test.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import merkle
from proofbundle.bundle import verify_bundle
from proofbundle.errors import ProofBundleError

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs


def _ref_leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _ref_head(hashes: list) -> bytes:
    """MTH over leaf hashes, RFC 9162 section 2.1.1, split at the largest power of two below n."""
    if not hashes:
        return hashlib.sha256(b"").digest()
    if len(hashes) == 1:
        return hashes[0]
    k = 1 << ((len(hashes) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + _ref_head(hashes[:k]) + _ref_head(hashes[k:])).digest()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _other_pad_bits(b64: str) -> str:
    """The same 32 bytes in standard base64 with a non-zero pad bit, a second spelling."""
    assert b64.endswith("=") and not b64.endswith("==")
    return b64[:-2] + _ALPHABET[_ALPHABET.index(b64[-2]) | 1] + "="


class InclusionTakesRawBytes(unittest.TestCase):

    def setUp(self):
        self.d = [hashlib.sha256(f"d{i}".encode()).digest() for i in range(5)]
        self.root = _ref_head([_ref_leaf(x) for x in self.d])
        self.proof = merkle.inclusion_proof(self.d, 2)

    def test_raw_leaf_and_raw_root_verify(self):
        self.assertTrue(merkle.verify_inclusion(self.d[2], 2, 5, self.proof, self.root))

    def test_hex_text_of_the_leaf_is_another_leaf(self):
        for leaf in (self.d[2].hex(), self.d[2].hex().encode("ascii"), self.d[2].hex().upper().encode("ascii")):
            with self.subTest(leaf=type(leaf).__name__):
                self.assertFalse(merkle.verify_inclusion(leaf, 2, 5, self.proof, self.root))

    def test_hex_or_prefixed_text_of_the_root_is_no_root(self):
        for root in (self.root.hex(), self.root.hex().encode("ascii"), "sha256:" + self.root.hex(),
                     _b64(self.root), _b64(self.root).encode("ascii")):
            with self.subTest(root=root[:12]):
                self.assertFalse(merkle.verify_inclusion(self.d[2], 2, 5, self.proof, root))


class BundleDigestsHaveOneSpelling(unittest.TestCase):

    def _cases(self):
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"digest-representation-key").digest())
        payload = b"payload-digest-representation"
        leaves = [b"a", b"b", payload]
        root = _ref_head([_ref_leaf(x) for x in leaves])
        proof = merkle.inclusion_proof(leaves, 2)

        def bundle(steps, root_b64):
            return {"schema": "proofbundle/v0.1", "payload_b64": _b64(payload),
                    "signature": {"alg": "ed25519", "public_key_b64": _b64(key.public_key().public_bytes_raw()),
                                  "sig_b64": _b64(key.sign(payload))},
                    "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": 2, "tree_size": 3,
                               "inclusion_proof_b64": steps, "root_b64": root_b64}}

        good = [_b64(p) for p in proof]
        return {
            "control": (bundle(good, _b64(root)), 0),
            "step_31_bytes": (bundle([_b64(proof[0][:31])] + good[1:], _b64(root)), 1),
            "step_33_bytes": (bundle([_b64(proof[0] + b"\x00")] + good[1:], _b64(root)), 1),
            "step_as_hex_text": (bundle([_b64(proof[0].hex().encode())] + good[1:], _b64(root)), 1),
            "root_as_hex_text": (bundle(good, _b64(root.hex().encode())), 1),
            "root_other_pad_bits": (bundle(good, _other_pad_bits(_b64(root))), 2),
            "root_urlsafe_alphabet": (bundle(good, base64.urlsafe_b64encode(root).decode()), 2),
            "root_without_padding": (bundle(good, _b64(root).rstrip("=")), 2),
        }

    def test_python_and_rust_give_the_same_exit(self):
        binary = _pb_verify_rs.binary_or_skip()
        with tempfile.TemporaryDirectory() as tmp:
            for name, (b, want) in self._cases().items():
                path = pathlib.Path(tmp) / f"{name}.json"
                path.write_text(json.dumps(b), encoding="utf-8")
                with self.subTest(case=name):
                    try:
                        py = 0 if verify_bundle(str(path)).ok else 1
                    except ProofBundleError:
                        py = 2
                    rs = subprocess.run([str(binary), "verify-bundle", str(path)],
                                        capture_output=True, text=True, timeout=60).returncode
                    self.assertEqual((py, rs), (want, want))


class RustMerkleRootIsTheRfcHead(unittest.TestCase):

    def test_over_leaf_hashes_it_equals_the_python_tree_and_the_reference(self):
        binary = _pb_verify_rs.binary_or_skip()
        for n in range(0, 18):
            data = [f"head-{n}-{i}".encode() for i in range(n)]
            hashes = [_ref_leaf(x) for x in data]
            with self.subTest(n=n):
                out = subprocess.run([str(binary), "merkle-root", *[h.hex() for h in hashes]],
                                     capture_output=True, text=True, timeout=60)
                self.assertEqual(out.returncode, 0, out.stderr)
                want = _ref_head(hashes).hex()
                self.assertEqual(out.stdout.strip(), want)
                self.assertEqual(merkle.merkle_tree_hash(data).hex(), want)

    def test_a_prefixed_leaf_is_refused(self):
        binary = _pb_verify_rs.binary_or_skip()
        out = subprocess.run([str(binary), "merkle-root", "sha256:" + _ref_leaf(b"x").hex()],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 2)


if __name__ == "__main__":
    unittest.main()
