"""Second-implementation conformance test for a LIVE third-party tlog-proof.

The `rootcommit` vectors (tests/test_anchors_rootcommit.py) cover MarkovianProtocol's offline anchor
layering. This covers its live counterpart: one real `c2sp.org/tlog-proof` bundle issued by a log we
do not operate (`markovianprotocol.com/log`, leaf 7271), frozen as pure data under
tests/fixtures/anchors/markovian_log/proof_7271/ and verified with witness keys taken from parties
OTHER than that log.

SECOND IMPLEMENTATION: `_root_from_inclusion` below is written from RFC 6962 section 2.1.1 with plain
hashlib and does NOT call proofbundle.merkle. It self-tests against synthetic trees, then reproduces
the bundle's checkpoint root from the leaf bytes BEFORE proofbundle.tlogproof is consulted at all, and
one test asserts the two derivations agree. If proofbundle's canonicalization ever drifts, this fails.

NO-OVERCLAIM, mirrored from MANIFEST.json and locked by TestMarkovianLogFixtureManifest:
leaf 7271 is the log's own stream statement, so `POST /submit` is NOT exercised here; the three
ML-DSA-44 lines are NOT verified (needs the optional [pq] backend); rgdd.se/poc-witness and
witness1.smartit.nu/witness1 cosigned but their keys are deliberately not carried, so they count
toward nothing; and one bundle is a snapshot that says nothing about split-view behaviour over time.

No optional extra is needed: Ed25519 checkpoint and cosignature verification uses `cryptography`,
which is a hard dependency.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import unittest

from proofbundle import merkle
from proofbundle.tlogproof import MAGIC, parse_tlog_proof, verify_tlog_proof

_FIXDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "markovian_log" / "proof_7271"
_ORIGIN = "markovianprotocol.com/log"
_INDEX = 7271
_TREE_SIZE = 7341
_PATH_NODES = 11
_LEAF_HASH_B64 = "Du6/Bku7hKc7cSeQ/+yA0uFbq8hzafGWQSNHRHJEwDQ="
_ROOT_B64 = "uNXWHpdGz73l2cku1fdg/u3Uff0NdKOGOfjHkTiZPjE="
_THRESHOLD = 4
_TAMPER_OFFSET = 365          # the byte the recorded counter-test flipped (ERGEBNIS_negativ.json)


def _manifest() -> dict:
    return json.loads((_FIXDIR / "MANIFEST.json").read_text())


def _bundle_text() -> str:
    return (_FIXDIR / "proof_7271.tlog-proof").read_text()


def _leaf_bytes() -> bytes:
    return (_FIXDIR / "leaf_7271.raw").read_bytes()


def _tampered_leaf() -> bytes:
    # generated here, never vendored: exactly one authoritative copy of the leaf bytes exists
    raw = bytearray(_leaf_bytes())
    raw[_TAMPER_OFFSET] ^= 0x01
    return bytes(raw)


def _keys() -> "tuple[str, list[str]]":
    log_vkey, witnesses = None, []
    for line in (_FIXDIR / "keys_unabhaengig.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(_ORIGIN + "+"):
            log_vkey = line
        else:
            witnesses.append(line)
    return log_vkey, witnesses


def _checkpoint_root(checkpoint: str) -> bytes:
    """Third line of a C2SP checkpoint note body, read directly rather than via verify_checkpoint."""
    return base64.b64decode(checkpoint.split("\n\n", 1)[0].split("\n")[2])


# --- standalone RFC 6962, written from the spec, deliberately NOT proofbundle.merkle ----------------

def _h_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _h_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root_from_inclusion(leaf_hash: bytes, index: int, tree_size: int, path) -> bytes:
    fn, sn = index, tree_size - 1
    node = leaf_hash
    for sibling in path:
        if sn == 0:
            raise ValueError("inclusion path longer than the tree allows")
        if (fn & 1) or (fn == sn):
            node = _h_node(sibling, node)
            while (fn != 0) and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            node = _h_node(node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion path too short for this tree")
    return node


class TestStandaloneRfc6962SelfCheck(unittest.TestCase):
    """The second implementation proves itself on synthetic trees before it judges a vendored file."""

    def test_reproduces_every_root_over_small_trees(self):
        for size in range(1, 65):
            leaves = [_h_leaf(f"leaf-{i}".encode()) for i in range(size)]
            root = merkle.merkle_tree_hash([f"leaf-{i}".encode() for i in range(size)])
            for index in range(size):
                path = merkle.inclusion_proof([f"leaf-{i}".encode() for i in range(size)], index)
                got = _root_from_inclusion(leaves[index], index, size, path)
                self.assertEqual(got, root, f"standalone recomputation failed at size={size} i={index}")

    def test_wrong_index_does_not_reproduce_the_root(self):
        data = [f"leaf-{i}".encode() for i in range(9)]
        root = merkle.merkle_tree_hash(data)
        path = merkle.inclusion_proof(data, 3)
        self.assertEqual(_root_from_inclusion(_h_leaf(data[3]), 3, 9, path), root)
        # teeth: the same path under a different index must NOT land on the root
        self.assertNotEqual(_root_from_inclusion(_h_leaf(data[3]), 4, 9, path), root)


class TestMarkovianLogFixtureManifest(unittest.TestCase):
    """G1 mechanism: every vendored file is digest-pinned; a single changed byte fails this test."""

    def test_manifest_digests_pinned(self):
        manifest = _manifest()
        self.assertEqual(len(manifest["files"]), 5)
        for entry in manifest["files"]:
            raw = (_FIXDIR / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"],
                             f"vendored {entry['path']} drifted from its MANIFEST digest pin")
            self.assertEqual(len(raw), entry["bytes"],
                             f"vendored {entry['path']} drifted from its MANIFEST byte count")

    def test_manifest_carries_provenance(self):
        up = _manifest()["upstream"]                     # No-Fake provenance / attribution present
        self.assertEqual(up["log_origin"], _ORIGIN)
        self.assertEqual(up["retrieved_at_utc"], "2026-08-14T07:31:09Z")
        self.assertEqual(up["license"], "MIT")
        # a live endpoint has no upstream commit; the manifest must say so rather than fake one
        self.assertNotIn("commit", up)
        self.assertIn("live endpoint", up["provenance_note"])

    def test_manifest_declares_no_overclaim(self):
        manifest = _manifest()
        purpose = manifest["purpose"]
        self.assertIn("NO-OVERCLAIM", purpose)
        self.assertIn("SECOND IMPLEMENTATION", purpose)
        self.assertIn("POST /submit", purpose)           # the untested path is named, not hidden
        self.assertIn("proofbundle[pq]", purpose)        # ML-DSA gate is honest, never a silent pass
        # the two cosigning witnesses we deliberately do not carry are named with a reason
        not_carried = {w["name"] for w in manifest["witnesses_present_but_not_carried"]}
        self.assertEqual(not_carried, {"rgdd.se/poc-witness", "witness1.smartit.nu/witness1"})
        # five carried witnesses is above, not equal to, the declared threshold
        self.assertEqual(len(manifest["witnesses_verified"]), 5)
        self.assertGreater(len(manifest["witnesses_verified"]), manifest["witness_threshold"])


class TestMarkovianLogSecondImplementation(unittest.TestCase):
    """Reproduce the bundle's own checkpoint root from the leaf bytes without proofbundle.merkle."""

    def setUp(self):
        self.parsed = parse_tlog_proof(_bundle_text())

    def test_header_and_index(self):
        self.assertTrue(_bundle_text().startswith(MAGIC + "\n"))
        self.assertEqual(self.parsed["index"], _INDEX)
        self.assertEqual(self.parsed["checkpoint"].split("\n")[0], _ORIGIN)
        self.assertEqual(int(self.parsed["checkpoint"].split("\n")[1]), _TREE_SIZE)

    def test_inclusion_path_length_is_exactly_what_the_tree_requires(self):
        self.assertEqual(len(self.parsed["proof"]), _PATH_NODES)

    def test_leaf_hash_matches_the_recorded_value(self):
        self.assertEqual(base64.b64encode(_h_leaf(_leaf_bytes())).decode(), _LEAF_HASH_B64)

    def test_recomputed_root_matches_the_checkpoint(self):
        got = _root_from_inclusion(_h_leaf(_leaf_bytes()), _INDEX, _TREE_SIZE, self.parsed["proof"])
        self.assertEqual(base64.b64encode(got).decode(), _ROOT_B64)
        self.assertEqual(got, _checkpoint_root(self.parsed["checkpoint"]))

    def test_two_implementations_agree(self):
        standalone = _root_from_inclusion(_h_leaf(_leaf_bytes()), _INDEX, _TREE_SIZE,
                                          self.parsed["proof"])
        library = merkle.root_from_inclusion(_INDEX, _TREE_SIZE, merkle.leaf_hash(_leaf_bytes()),
                                             self.parsed["proof"])
        self.assertEqual(standalone, library)

    def test_tampered_leaf_does_not_reproduce_the_root(self):
        got = _root_from_inclusion(_h_leaf(_tampered_leaf()), _INDEX, _TREE_SIZE,
                                   self.parsed["proof"])
        self.assertNotEqual(got, _checkpoint_root(self.parsed["checkpoint"]))


class TestMarkovianLogKeyProvenance(unittest.TestCase):
    """Every carried key ID recomputes from its own vkey; none of them comes from the log's /policy."""

    @staticmethod
    def _key_id(name: str, keybytes: bytes) -> bytes:
        digest = hashlib.sha256()
        digest.update(name.encode())
        digest.update(b"\x0a")
        digest.update(keybytes)
        return digest.digest()[:4]

    def test_key_ids_recompute(self):
        log_vkey, witnesses = _keys()
        self.assertIsNotNone(log_vkey)
        self.assertEqual(len(witnesses), 5)
        for vkey in [log_vkey] + witnesses:
            name, hex_id, b64 = vkey.split("+", 2)
            self.assertEqual(self._key_id(name, base64.b64decode(b64)).hex(), hex_id,
                             f"key ID in {name} does not match its own key material")

    def test_manifest_key_ids_match_the_key_file(self):
        _, witnesses = _keys()
        from_file = {v.split("+", 2)[0]: v.split("+", 2)[1] for v in witnesses}
        for entry in _manifest()["witnesses_verified"]:
            self.assertEqual(from_file[entry["name"]], entry["key_id"])


class TestMarkovianLogThroughProofbundle(unittest.TestCase):
    """proofbundle's own verifier over the frozen bundle, positive and counter-test."""

    def setUp(self):
        self.log_vkey, self.witness_vkeys = _keys()

    def _verify(self, leaf: bytes, **kwargs):
        return verify_tlog_proof(_bundle_text(), leaf, self.log_vkey, self.witness_vkeys,
                                 threshold=_THRESHOLD, **kwargs)

    def test_positive_verdict_matches_the_recorded_run(self):
        res = self._verify(_leaf_bytes())
        recorded = json.loads((_FIXDIR / "ERGEBNIS.json").read_text())
        for key in ("ok", "log_ok", "witnesses_ok", "inclusion_ok", "origin", "tree_size", "index"):
            self.assertEqual(res[key], recorded[key], f"{key} drifted from the recorded run")
        self.assertTrue(res["ok"])
        self.assertEqual(base64.b64encode(res["root"]).decode(), _ROOT_B64)

    def test_recorded_witnesses_still_verify(self):
        res = self._verify(_leaf_bytes())
        recorded = json.loads((_FIXDIR / "ERGEBNIS.json").read_text())["witnesses"]
        self.assertEqual(set(res["witnesses"]), set(recorded))
        for name, entry in recorded.items():
            self.assertTrue(res["witnesses"][name]["ok"], name)
            self.assertEqual(res["witnesses"][name]["alg"], entry["alg"])
            self.assertEqual(res["witnesses"][name]["timestamp"], entry["timestamp"])

    def test_tampered_payload_splits_the_verdict(self):
        res = self._verify(_tampered_leaf())
        recorded = json.loads((_FIXDIR / "ERGEBNIS_negativ.json").read_text())
        for key in ("ok", "log_ok", "witnesses_ok", "inclusion_ok"):
            self.assertEqual(res[key], recorded[key], f"{key} drifted from the recorded counter-test")
        # the point of the counter-test: signatures stay valid, only membership fails
        self.assertFalse(res["ok"])
        self.assertFalse(res["inclusion_ok"])
        self.assertTrue(res["log_ok"])
        self.assertTrue(res["witnesses_ok"])

    def test_expected_origin_is_enforced(self):
        self.assertTrue(self._verify(_leaf_bytes(), expected_origin=_ORIGIN)["ok"])
        wrong = self._verify(_leaf_bytes(), expected_origin="attacker.example/log")
        self.assertFalse(wrong["log_ok"])       # a validly signed checkpoint from another origin
        self.assertFalse(wrong["ok"])
        self.assertTrue(wrong["inclusion_ok"])  # the tree membership itself is untouched

    def test_threshold_above_the_carried_witnesses_fails_closed(self):
        res = verify_tlog_proof(_bundle_text(), _leaf_bytes(), self.log_vkey, self.witness_vkeys,
                                threshold=6)
        self.assertFalse(res["witnesses_ok"])   # only five keys are carried, six can never be met
        self.assertFalse(res["ok"])

    def test_no_witness_keys_still_reports_the_log_signature(self):
        res = verify_tlog_proof(_bundle_text(), _leaf_bytes(), self.log_vkey)
        self.assertTrue(res["log_ok"])
        self.assertTrue(res["inclusion_ok"])
        self.assertTrue(res["ok"])              # threshold defaults to 0, documented behaviour


class TestMarkovianLogSignatureLines(unittest.TestCase):
    """The line inventory in MANIFEST.json is a claim about the bundle; measure it, do not trust it."""

    @staticmethod
    def _lines():
        found = {"note": 0, "cosig": 0, "mldsa": 0, "other": 0}
        for line in (_FIXDIR / "proof_7271.tlog-proof").read_bytes().split(b"\n"):
            if not line.startswith("— ".encode()):
                continue
            parts = line[4:].split(b" ")
            if len(parts) < 2:
                found["other"] += 1
                continue
            try:
                blob = base64.b64decode(parts[1])
            except Exception:
                found["other"] += 1
                continue
            if len(blob) == 68:
                found["note"] += 1
            elif len(blob) == 76:
                found["cosig"] += 1
            elif len(blob) > 2000:
                found["mldsa"] += 1
            else:
                found["other"] += 1
        return found

    def test_inventory_matches_the_manifest(self):
        declared = _manifest()["signature_lines"]
        found = self._lines()
        self.assertEqual(found["note"], declared["ed25519_note_signature"])
        self.assertEqual(found["cosig"], declared["ed25519_cosignature_v1"])
        self.assertEqual(found["mldsa"], declared["ml_dsa_44"])
        self.assertEqual(found["other"], 0)
        self.assertEqual(sum(found.values()), declared["total"])

    def test_more_cosignatures_are_present_than_keys_we_carry(self):
        # the honest gap: seven witnesses cosigned, we carry five keys and count only those
        _, witnesses = _keys()
        self.assertEqual(self._lines()["cosig"], 7)
        self.assertEqual(len(witnesses), 5)


if __name__ == "__main__":
    unittest.main()
