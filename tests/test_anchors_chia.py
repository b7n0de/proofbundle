"""chia-datalayer/v1 anchor — the offline Merkle verifier (level i), tested against a REAL captured
DataLayer get_proof (5-level tree, store 05f7c6f1...) plus synthetic edge cases. This verifier is PURE
SHA-256 (no Chia software, no extra) so this whole module runs in the base test job — the offline honesty
of the extension must never depend on the [chia] extra."""
import copy
import hashlib
import json
import pathlib
import unittest

from proofbundle import anchors
from proofbundle.anchors_chia import (
    ANCHOR_TYPE,
    clvm_atom_hash,
    leaf_node_hash,
    merkle_root_from_layers,
    verify_chia_datalayer,
)

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "anchors" / "chia_datalayer_proof.json"


def _hb(hexstr):
    return bytes.fromhex(hexstr[2:] if hexstr[:2] in ("0x", "0X") else hexstr)


def _load():
    obj = json.loads(FIXTURE.read_text())
    canonical_root = _hb(obj["value_digest"])
    return obj, canonical_root


def _pbytes(obj):
    return json.dumps(obj).encode()


class TestChiaOfflineMerkle(unittest.TestCase):
    def setUp(self):
        self.obj, self.root = _load()

    # 1 — real multi-level proof verifies offline
    def test_real_multilevel_proof_passes(self):
        self.assertGreaterEqual(len(self.obj["inclusion_layers"]), 3, "fixture must be a multi-level tree")
        r = verify_chia_datalayer(_pbytes(self.obj), self.root)
        self.assertTrue(r["ok"], r["detail"])
        self.assertEqual(r["status"], "pass")

    # cross-check: pure-python recompute reproduces the on-chain published_root
    def test_recomputed_root_equals_published_root(self):
        leaf = leaf_node_hash(_hb(self.obj["key_clvm_hash"]), _hb(self.obj["value_clvm_hash"]))
        root = merkle_root_from_layers(leaf, self.obj["inclusion_layers"])
        self.assertEqual(root, _hb(self.obj["published_root"]))

    # 2 — tampered other_hash must FAIL
    def test_tampered_other_hash_fails(self):
        bad = copy.deepcopy(self.obj)
        bad["inclusion_layers"][0]["other_hash"] = "0x" + "00" * 32
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # 2b — tampered combined_hash must FAIL (self-consistency of each layer)
    def test_tampered_combined_hash_fails(self):
        bad = copy.deepcopy(self.obj)
        bad["inclusion_layers"][1]["combined_hash"] = "0x" + "ab" * 32
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # tampered node_hash must FAIL
    def test_tampered_node_hash_fails(self):
        bad = copy.deepcopy(self.obj)
        bad["node_hash"] = "0x" + "11" * 32
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # tampered published_root must FAIL (ascent no longer reproduces it)
    def test_tampered_published_root_fails(self):
        bad = copy.deepcopy(self.obj)
        bad["published_root"] = "0x" + "de" * 32
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # 3 — value_digest != canonicalRoot must FAIL (cross-target / tamper)
    def test_value_digest_mismatch_fails(self):
        self.assertFalse(verify_chia_datalayer(_pbytes(self.obj), b"\xaa" * 32)["ok"])

    # raw value present but clvm hash mismatch -> FAIL
    def test_value_clvm_mismatch_fails(self):
        bad = copy.deepcopy(self.obj)
        bad["value"] = "0x" + "cc" * 32   # a value whose clvm hash won't match value_clvm_hash
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # malformed proof: bad hex, wrong length, missing field -> FAIL, never raise
    def test_malformed_hex_fails_closed(self):
        for mut in ("key_clvm_hash", "value_clvm_hash", "published_root"):
            bad = copy.deepcopy(self.obj)
            bad[mut] = "0xzz"   # not hex
            r = verify_chia_datalayer(_pbytes(bad), self.root)
            self.assertFalse(r["ok"], mut)

    def test_missing_field_fails_closed(self):
        bad = copy.deepcopy(self.obj)
        del bad["published_root"]
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # non-JSON / non-object proof bytes -> FAIL
    def test_non_json_proof_fails(self):
        self.assertFalse(verify_chia_datalayer(b"\x00\x01not json", self.root)["ok"])
        self.assertFalse(verify_chia_datalayer(b"[1,2,3]", self.root)["ok"])
        self.assertFalse(verify_chia_datalayer("not bytes", self.root)["ok"])  # type: ignore[arg-type]

    # bad other_hash_side (not 0/1) -> FAIL
    def test_bad_side_fails(self):
        bad = copy.deepcopy(self.obj)
        bad["inclusion_layers"][0]["other_hash_side"] = 2
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # 9 — trivial single-leaf tree: layers == [] means node_hash IS the root
    def test_trivial_single_leaf_tree(self):
        key = b"only-key"
        # value_digest == canonicalRoot is always a 32-byte sha256; use a real 32-byte value here
        value = hashlib.sha256(b"only-value").digest()
        kc = clvm_atom_hash(key)
        vc = clvm_atom_hash(value)
        leaf = leaf_node_hash(kc, vc)
        obj = {
            "key": "0x" + key.hex(), "value": "0x" + value.hex(),
            "key_clvm_hash": "0x" + kc.hex(), "value_clvm_hash": "0x" + vc.hex(),
            "node_hash": "0x" + leaf.hex(), "inclusion_layers": [],
            "published_root": "0x" + leaf.hex(), "value_digest": "0x" + value.hex(),
        }
        r = verify_chia_datalayer(_pbytes(obj), value)
        self.assertTrue(r["ok"], r["detail"])
        # and with a wrong root it fails
        obj["published_root"] = "0x" + "00" * 32
        self.assertFalse(verify_chia_datalayer(_pbytes(obj), value)["ok"])


class TestChiaAnchorRegistration(unittest.TestCase):
    """10 — the type registers into the anchor framework and verify_anchor drives it end-to-end (base
    install, no [chia] extra needed for the offline path)."""

    def test_type_is_registered(self):
        self.assertIn(ANCHOR_TYPE, anchors.registered_anchor_types())

    def test_verify_anchor_end_to_end(self):
        import base64
        obj, root = _load()
        anchor = {
            "type": ANCHOR_TYPE, "target": "receipt",
            "canonicalRoot": base64.b64encode(root).decode(),
            "proof": base64.b64encode(_pbytes(obj)).decode(),
        }
        out = anchors.verify_anchor(anchor, target_roots={"receipt": root})
        self.assertTrue(out["ok"], out["detail"])
        # cross-target: same anchor against a preRegistration root it does not stamp -> FAIL
        out2 = anchors.verify_anchor(anchor, target_roots={"receipt": b"\x09" * 32})
        self.assertFalse(out2["ok"])


if __name__ == "__main__":
    unittest.main()
