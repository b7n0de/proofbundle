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
    canonical_root = _hb(obj["key"])   # the DataLayer key IS the canonicalRoot (the binding)
    return obj, canonical_root


def _pbytes(obj):
    return json.dumps(obj).encode()


class TestChiaOfflineMerkle(unittest.TestCase):
    def setUp(self):
        self.obj, self.root = _load()

    # 1 — real multi-level proof verifies offline as level i: ok=True (inclusion proven) but warn=True
    # (level i is NOT external time/chain evidence — the honest boundary; see the 6-lens api finding).
    def test_real_multilevel_proof_passes(self):
        self.assertGreaterEqual(len(self.obj["inclusion_layers"]), 2, "fixture must be a multi-level tree (ascent exercised)")
        r = verify_chia_datalayer(_pbytes(self.obj), self.root)
        self.assertTrue(r["ok"], r["detail"])
        self.assertTrue(r["warn"], "level-i-only must warn (not a full external-time anchor)")
        self.assertEqual(r["status"], "warn")

    # a level-i chia anchor must NOT satisfy --require-anchor (it carries zero external-time evidence — a
    # self-fabricated offline tree passes level i). require gates on ok AND NOT warn.
    def test_level_i_does_not_satisfy_require_anchor(self):
        import base64
        obj, root = _load()
        anchor = {"type": ANCHOR_TYPE, "target": "receipt",
                  "canonicalRoot": base64.b64encode(root).decode(),
                  "proof": base64.b64encode(_pbytes(obj)).decode()}
        # present + valid inclusion → aggregate WARN, never a clean PASS
        out = anchors.verify_anchors([anchor], target_roots={"receipt": root})
        self.assertEqual(out["status"], "WARN", out)
        # --require-anchor demands a full external-time anchor → a level-i-only anchor FAILs the requirement
        req_any = anchors.verify_anchors([anchor], target_roots={"receipt": root}, require="any")
        self.assertEqual(req_any["status"], "FAIL", req_any)
        req_type = anchors.verify_anchors([anchor], target_roots={"receipt": root}, require=ANCHOR_TYPE)
        self.assertEqual(req_type["status"], "FAIL", req_type)

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

    # 3 — key != canonicalRoot must FAIL (cross-target / relabel forgery, Lens 4): a valid proof for one
    # target cannot be relabelled to another, because the key (== the real canonicalRoot) will not match.
    def test_wrong_canonical_root_fails(self):
        self.assertFalse(verify_chia_datalayer(_pbytes(self.obj), b"\xaa" * 32)["ok"])

    # the raw key MUST be present (it carries the binding) — a proof without it fails closed
    def test_missing_raw_key_fails(self):
        bad = copy.deepcopy(self.obj)
        del bad["key"]
        self.assertFalse(verify_chia_datalayer(_pbytes(bad), self.root)["ok"])

    # anti-relabel forgery (6-lens HIGH, 2026-07-06): a proof whose key == canonicalRoot but whose
    # key_clvm_hash is a valid-but-WRONG clvm hash (of a DIFFERENT atom), with node_hash + root built
    # self-consistently from that wrong key_clvm, must be REJECTED by the sha256(0x01||key)==key_clvm_hash
    # binding — which is the SOLE guard here (checks 1/3/4 all pass on the internally-consistent data). An
    # attacker with a genuine single-leaf proof for their own key K' could otherwise relabel it onto any
    # victim canonicalRoot C by swapping only the `key` field while keeping the genuine key_clvm_hash.
    def test_key_clvm_binding_rejects_relabel_forgery(self):
        cr = hashlib.sha256(b"victim-canonical-root-in-no-store").digest()   # key == canonicalRoot
        wrong_atom = hashlib.sha256(b"attacker-owned-key").digest()          # a DIFFERENT atom
        kc_wrong = clvm_atom_hash(wrong_atom)                                # key_clvm_hash of the WRONG atom
        vc = clvm_atom_hash(cr)
        leaf = leaf_node_hash(kc_wrong, vc)                                  # node/root from the wrong key_clvm
        forged = {
            "key": "0x" + cr.hex(), "value": "0x" + cr.hex(),
            "key_clvm_hash": "0x" + kc_wrong.hex(), "value_clvm_hash": "0x" + vc.hex(),
            "node_hash": "0x" + leaf.hex(), "inclusion_layers": [],
            "published_root": "0x" + leaf.hex(),
        }
        # key==canonicalRoot (check 1) passes, leaf (check 3) + ascent (check 4) pass on the consistent
        # data; ONLY sha256(0x01||key) != key_clvm_hash rejects it. If that binding is dropped this verifies.
        self.assertFalse(verify_chia_datalayer(_pbytes(forged), cr)["ok"])

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

    # 9 — trivial single-leaf tree: layers == [] means node_hash IS the root. key == canonicalRoot (32-byte).
    def test_trivial_single_leaf_tree(self):
        cr = hashlib.sha256(b"only-canonical-root").digest()   # key == value == canonicalRoot
        kc = clvm_atom_hash(cr)
        vc = clvm_atom_hash(cr)
        leaf = leaf_node_hash(kc, vc)
        obj = {
            "key": "0x" + cr.hex(), "value": "0x" + cr.hex(),
            "key_clvm_hash": "0x" + kc.hex(), "value_clvm_hash": "0x" + vc.hex(),
            "node_hash": "0x" + leaf.hex(), "inclusion_layers": [],
            "published_root": "0x" + leaf.hex(),
        }
        r = verify_chia_datalayer(_pbytes(obj), cr)
        self.assertTrue(r["ok"], r["detail"])
        # and with a wrong root it fails
        obj["published_root"] = "0x" + "00" * 32
        self.assertFalse(verify_chia_datalayer(_pbytes(obj), cr)["ok"])

    # DoS / fail-closed backstop (Lens 2): deeply nested JSON must NOT crash the verifier
    def test_deeply_nested_json_fails_closed(self):
        r = verify_chia_datalayer(b"[" * 5000, self.root)   # would RecursionError without the backstop
        self.assertFalse(r["ok"])
        r2 = verify_chia_datalayer(b"x" * (200 * 1024), self.root)   # over the byte cap
        self.assertFalse(r2["ok"])

    # 6-lens LOW (packaging): the SHIPPED example files must be pinned by a verdict regression test — else a
    # future chia-datalayer/v2 wire change or an accidental edit that flips them (invalid verifies / valid
    # stops verifying) leaves CI green and misleads a user who copies the shipped "valid"/"invalid" example.
    def test_shipped_examples_verify_as_documented(self):
        exdir = pathlib.Path(__file__).resolve().parent.parent / "examples" / "anchors"
        valid = json.loads((exdir / "chia-datalayer-valid.json").read_text())
        invalid = json.loads((exdir / "chia-datalayer-invalid-root.json").read_text())
        self.assertTrue(verify_chia_datalayer(_pbytes(valid), _hb(valid["key"]))["ok"],
                        "the shipped chia-datalayer-valid.json example must verify (level i)")
        self.assertFalse(verify_chia_datalayer(_pbytes(invalid), _hb(invalid["key"]))["ok"],
                         "the shipped chia-datalayer-invalid-root.json example must REJECT (tampered root)")


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
