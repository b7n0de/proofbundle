"""The audit path of an inclusion proof has the length RFC 9162 gives it, in Python and in pb_verify_rs.

The last leaf of a tree whose size is no power of two has a shorter path than the leaves before it.
For tree_size 5 and index 4 the path holds one element: the tree splits at 4 (RFC 9162 section 2.1.1),
leaf 4 is the whole right subtree, and its one sibling is MTH(D[0:4]) (section 2.1.3.1). A verifier
that takes the side of every sibling from the bits of the index, as in a tree padded to a power of
two, expects three elements there and refuses the valid proof; one that ignores the length accepts a
path padded to three.

The expected values below come from a reference written here from the text of RFC 9162 sections
2.1.1 and 2.1.3.1 (recursive MTH and PATH), not from `proofbundle.merkle`. The reference builds the
tree and the path; the verdict it expects is the definition of an inclusion proof: the path PATH(m,
D[n]) verifies and nothing else does. Every tree size from 1 to 17 and every index is checked with
the valid path, a path one element too long, and a path one element too short. The same bytes go to
`verify_bundle` and to `pb_verify_rs verify-bundle`, which must give the same exit.
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

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs

MAX_SIZE = 17


# --- reference, RFC 9162 section 2.1.1 and 2.1.3.1, independent of proofbundle.merkle -------------

def _ref_leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _ref_node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _ref_k(n: int) -> int:
    """The largest power of two smaller than n (n > 1), RFC 9162 section 2.1.1."""
    return 1 << ((n - 1).bit_length() - 1)


def _ref_mth(d: list) -> bytes:
    if len(d) == 1:
        return _ref_leaf(d[0])
    k = _ref_k(len(d))
    return _ref_node(_ref_mth(d[:k]), _ref_mth(d[k:]))


def _ref_path(m: int, d: list) -> list:
    """PATH(m, D[n]), siblings from the leaf to the root."""
    if len(d) == 1:
        return []
    k = _ref_k(len(d))
    if m < k:
        return _ref_path(m, d[:k]) + [_ref_mth(d[k:])]
    return _ref_path(m - k, d[k:]) + [_ref_mth(d[:k])]


def _leaves(n: int) -> list:
    return [f"rfc9162-leaf-{n}-{i}".encode() for i in range(n)]


def _filler(tag: str) -> bytes:
    return hashlib.sha256(b"filler/" + tag.encode()).digest()


def _cases():
    """(name, tree_size, index, leaves, path, root, expected verdict) for every size 1..17 and index."""
    for n in range(1, MAX_SIZE + 1):
        d = _leaves(n)
        root = _ref_mth(d)
        for m in range(n):
            path = _ref_path(m, d)
            yield (f"n{n}-m{m}-valid", n, m, d, path, root, True)
            yield (f"n{n}-m{m}-long-tail", n, m, d, path + [_filler(f"{n}/{m}/tail")], root, False)
            yield (f"n{n}-m{m}-long-head", n, m, d, [_filler(f"{n}/{m}/head")] + path, root, False)
            if path:
                yield (f"n{n}-m{m}-short-tail", n, m, d, path[:-1], root, False)
                yield (f"n{n}-m{m}-short-head", n, m, d, path[1:], root, False)


def _padded_5_4():
    """The proof of leaf 4 in a tree of 5, padded to the length of a tree of 8, both ways round."""
    d = _leaves(5)
    path = _ref_path(4, d)
    pad1, pad2 = _filler("pad/1"), _filler("pad/2")
    return d, _ref_mth(d), path, [[pad1, pad2] + path, path + [pad1, pad2]]


class TheReferenceIsTheRfc(unittest.TestCase):
    """The reference itself, checked against what RFC 9162 says in words."""

    def test_tree_5_index_4_has_one_sibling_the_root_of_the_first_four(self):
        d = _leaves(5)
        self.assertEqual(_ref_path(4, d), [_ref_mth(d[:4])])
        self.assertEqual(_ref_mth(d), _ref_node(_ref_mth(d[:4]), _ref_leaf(d[4])))

    def test_path_lengths_follow_the_split(self):
        # A power of two has log2(n) everywhere; the last leaf of 5, 6 (pair), 9 and 17 is short.
        expect = {(1, 0): 0, (2, 1): 1, (4, 3): 2, (5, 4): 1, (5, 0): 3, (6, 5): 2, (8, 7): 3, (9, 8): 1,
                  (16, 15): 4, (17, 16): 1, (17, 0): 5}
        for (n, m), length in expect.items():
            with self.subTest(n=n, m=m):
                self.assertEqual(len(_ref_path(m, _leaves(n))), length)


class PythonInclusion(unittest.TestCase):

    def test_every_size_to_17_and_every_index(self):
        count = 0
        for name, n, m, d, path, root, ok in _cases():
            with self.subTest(case=name):
                self.assertIs(merkle.verify_inclusion(d[m], m, n, path, root), ok)
                count += 1
        self.assertEqual(count, 763)

    def test_the_generator_gives_the_reference_path_and_root(self):
        for n in range(1, MAX_SIZE + 1):
            d = _leaves(n)
            self.assertEqual(merkle.merkle_tree_hash(d), _ref_mth(d), n)
            for m in range(n):
                self.assertEqual(merkle.inclusion_proof(d, m), _ref_path(m, d), (n, m))

    def test_tree_5_index_4_padded_to_three_is_refused_as_too_long(self):
        d, root, path, padded = _padded_5_4()
        self.assertEqual(len(path), 1)
        self.assertTrue(merkle.verify_inclusion(d[4], 4, 5, path, root))
        for p in padded:
            with self.subTest(path=[x.hex()[:8] for x in p]):
                self.assertEqual(len(p), 3)
                self.assertFalse(merkle.verify_inclusion(d[4], 4, 5, p, root))
                with self.assertRaisesRegex(ValueError, "inclusion proof too long"):
                    merkle.root_from_inclusion(4, 5, _ref_leaf(d[4]), p)

    def test_too_short_and_too_long_are_named_by_the_recomputation(self):
        for name, n, m, d, path, root, ok in _cases():
            if ok:
                continue
            with self.subTest(case=name):
                want = "too long" if "long" in name else "too short"
                with self.assertRaisesRegex(ValueError, want):
                    merkle.root_from_inclusion(m, n, _ref_leaf(d[m]), path)


# --- the same bytes as bundles, for verify_bundle and pb_verify_rs ----------------------------------

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _bundle(key, n, m, d, path, root) -> dict:
    payload = d[m]
    return {
        "schema": "proofbundle/v0.1",
        "payload_b64": _b64(payload),
        "signature": {
            "alg": "ed25519",
            "public_key_b64": _b64(key.public_key().public_bytes_raw()),
            "sig_b64": _b64(key.sign(payload)),
        },
        "merkle": {
            "hash_alg": "sha256-rfc6962",
            "leaf_index": m,
            "tree_size": n,
            "inclusion_proof_b64": [_b64(p) for p in path],
            "root_b64": _b64(root),
        },
    }


def _bundle_cases():
    # A seed written out in the source: tests/test_sdist_ohne_signierwerkzeug.py refuses a key loaded
    # from anything else in a shipped file, a hash call included.
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    for name, n, m, d, path, root, ok in _cases():
        yield name, _bundle(key, n, m, d, path, root), ok
    d, root, _path, padded = _padded_5_4()
    for i, p in enumerate(padded):
        yield f"n5-m4-padded-to-3-{i}", _bundle(key, 5, 4, d, p, root), False


class BothVerifiersOnTheSameBytes(unittest.TestCase):

    def test_python_and_rust_give_the_expected_exit_for_every_case(self):
        binary = _pb_verify_rs.binary_or_skip()
        count = 0
        with tempfile.TemporaryDirectory() as tmp:
            for name, bundle, ok in _bundle_cases():
                path = pathlib.Path(tmp) / f"{name}.json"
                path.write_text(json.dumps(bundle), encoding="utf-8")
                with self.subTest(case=name):
                    py = verify_bundle(str(path))
                    rs = subprocess.run([str(binary), "verify-bundle", str(path)],
                                        capture_output=True, text=True, timeout=60)
                    self.assertIs(py.ok, ok)
                    self.assertEqual((rs.returncode, rs.stdout.strip()), (0, "OK") if ok else (1, "FAIL"))
                    count += 1
        self.assertEqual(count, 765)


if __name__ == "__main__":
    unittest.main()
