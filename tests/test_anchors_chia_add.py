"""chia-datalayer/v1 WRITER (anchors_chia_add) — node-independent tests. Every Chia RPC is mocked
(monkeypatched ``_rpc``), so the whole write/export/confirm/idempotency/error surface is exercised WITHOUT
a live node — mirroring how tests/test_anchors_rfc3161.py mocks urllib for its TSA writer.

The mock returns a SYNTHETIC but genuinely valid single-leaf proof built with the real hash functions, so
the writer's self-verify-before-emit (No-Fake) really runs and really passes on the happy path."""
import hashlib
import unittest
from unittest import mock

from proofbundle import anchors
from proofbundle.anchors_chia import ANCHOR_TYPE, clvm_atom_hash, leaf_node_hash
from proofbundle import anchors_chia_add
from proofbundle.anchors_chia_add import (
    ChiaRpcError,
    anchor_add,
    export_anchor,
)

STORE = "05f7c6f179a32e6f450ff1940235550a641fa8d9f478c409f3980b981dd3529e"


def _synthetic_proof(key_hex: str, value_hex: str):
    """A valid single-leaf (layers==[]) proof for (key,value), computed with the real hash functions."""
    key = bytes.fromhex(key_hex[2:] if key_hex.startswith("0x") else key_hex)
    value = bytes.fromhex(value_hex[2:] if value_hex.startswith("0x") else value_hex)
    kc = clvm_atom_hash(key)
    vc = clvm_atom_hash(value)
    leaf = leaf_node_hash(kc, vc)
    return {
        "key_clvm_hash": "0x" + kc.hex(), "value_clvm_hash": "0x" + vc.hex(),
        "node_hash": "0x" + leaf.hex(), "layers": [],
    }, "0x" + leaf.hex()   # published_root == node_hash for a single leaf


def _mock_rpc_factory(*, published_root, proof, prev_root=None, batch_error=None, coin=True):
    """Build a fake ``_rpc(service, method, payload, *, timeout=...)``."""
    calls = {"get_root": 0}

    def fake(service, method, payload, *, timeout=60):
        if method == "get_root":
            calls["get_root"] += 1
            # first call returns prev_root (pre-insert), later calls the confirmed root
            root = prev_root if (prev_root is not None and calls["get_root"] == 1) else published_root
            return {"hash": root, "confirmed": True}
        if method == "batch_update":
            if batch_error:
                raise ChiaRpcError(batch_error)
            return {"success": True, "tx_id": "0x" + "ab" * 32}
        if method == "get_proof":
            return {"proof": {"store_proofs": {"proofs": [proof]},
                              "coin_id": "0x" + "cd" * 32, "inner_puzzle_hash": "0x" + "ef" * 32}}
        if method == "get_coin_record_by_name":
            if not coin:
                raise ChiaRpcError("no coin record")
            return {"coin_record": {"confirmed_block_index": 8967863, "timestamp": 1783330051}}
        raise AssertionError(f"unexpected rpc {method}")
    return fake


class TestExportAnchor(unittest.TestCase):
    def test_export_produces_verifiable_anchor(self):
        cr_hex = "0x" + hashlib.sha256(b"cr").hexdigest()
        proof, root = _synthetic_proof(cr_hex, cr_hex)
        fake = _mock_rpc_factory(published_root=root, proof=proof)
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            anchor = export_anchor(STORE, canonical_root=bytes.fromhex(cr_hex[2:]),
                                   target="receipt", network="mainnet", value=cr_hex)
        self.assertEqual(anchor["type"], ANCHOR_TYPE)
        out = anchors.verify_anchor(anchor, target_roots={"receipt": bytes.fromhex(cr_hex[2:])})
        self.assertTrue(out["ok"], out["detail"])

    def test_export_self_verify_rejects_bad_proof(self):
        # No-Fake: if the built anchor does not verify offline, export raises rather than emit it.
        cr_hex = "0x" + hashlib.sha256(b"cr2").hexdigest()
        proof, root = _synthetic_proof(cr_hex, cr_hex)
        proof["node_hash"] = "0x" + "00" * 32   # break it → self-verify must fail
        fake = _mock_rpc_factory(published_root=root, proof=proof)
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            with self.assertRaises(ChiaRpcError):
                export_anchor(STORE, canonical_root=bytes.fromhex(cr_hex[2:]), value=cr_hex)

    def test_export_fails_when_no_proof(self):
        fake = lambda s, m, p, timeout=60: (   # noqa: E731
            {"hash": "0x" + "11" * 32, "confirmed": True} if m == "get_root"
            else {"proof": {"store_proofs": {"proofs": []}}})
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            with self.assertRaises(ChiaRpcError):
                export_anchor(STORE, canonical_root=b"\x22" * 32)

    def test_export_unconfirmed_root_rejected(self):
        cr_hex = "0x" + hashlib.sha256(b"cr3").hexdigest()
        proof, _ = _synthetic_proof(cr_hex, cr_hex)
        fake = _mock_rpc_factory(published_root="0x" + "00" * 32, proof=proof)   # genesis/empty root
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            with self.assertRaises(ChiaRpcError):
                export_anchor(STORE, canonical_root=bytes.fromhex(cr_hex[2:]), value=cr_hex)


class TestAnchorAdd(unittest.TestCase):
    def test_input_validation_rejects_non_32_byte_root(self):
        with self.assertRaises(ValueError):
            anchor_add("0xabcd", store_id=STORE)   # 2 bytes, not 32

    def test_happy_path_writes_and_exports(self):
        cr_hex = "0x" + hashlib.sha256(b"add").hexdigest()
        proof, root = _synthetic_proof(cr_hex, cr_hex)
        fake = _mock_rpc_factory(published_root=root, proof=proof, prev_root="0x" + "00" * 32)
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            anchor = anchor_add(cr_hex, store_id=STORE, wait=True)
        out = anchors.verify_anchor(anchor, target_roots={"receipt": bytes.fromhex(cr_hex[2:])})
        self.assertTrue(out["ok"], out["detail"])

    def test_idempotent_already_present(self):
        cr_hex = "0x" + hashlib.sha256(b"idem").hexdigest()
        proof, root = _synthetic_proof(cr_hex, cr_hex)
        fake = _mock_rpc_factory(published_root=root, proof=proof,
                                 batch_error="Error: Key already present in the store")
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            anchor = anchor_add(cr_hex, store_id=STORE, wait=True)   # already-present → re-export, no crash
        out = anchors.verify_anchor(anchor, target_roots={"receipt": bytes.fromhex(cr_hex[2:])})
        self.assertTrue(out["ok"], out["detail"])

    def test_network_error_aborts_clean(self):
        cr_hex = "0x" + hashlib.sha256(b"neterr").hexdigest()
        fake = _mock_rpc_factory(published_root="0x" + "aa" * 32, proof={},
                                 batch_error="chia rpc data_layer batch_update exit 1: connection refused")
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            with self.assertRaises(ChiaRpcError):
                anchor_add(cr_hex, store_id=STORE, wait=True)   # non-"already present" error → clean abort

    def test_wait_confirmed_times_out(self):
        # get_root never advances past prev_root → _wait_confirmed raises within the bound
        stuck = "0x" + "77" * 32
        fake = lambda s, m, p, timeout=60: {"hash": stuck, "confirmed": True}  # noqa: E731
        with mock.patch.object(anchors_chia_add, "_rpc", fake):
            with self.assertRaises(ChiaRpcError):
                anchors_chia_add._wait_confirmed(STORE, stuck, timeout=1, poll=0)


class TestRpcErrorPaths(unittest.TestCase):
    def _run(self, completed):
        with mock.patch("subprocess.run", return_value=completed):
            return anchors_chia_add._rpc("data_layer", "get_root", {"id": STORE})

    def test_rpc_nonzero_exit_raises(self):
        cp = mock.Mock(returncode=1, stdout="", stderr="boom")
        with self.assertRaises(ChiaRpcError):
            self._run(cp)

    def test_rpc_non_json_raises(self):
        cp = mock.Mock(returncode=0, stdout="not json", stderr="")
        with self.assertRaises(ChiaRpcError):
            self._run(cp)

    def test_rpc_success_false_raises(self):
        cp = mock.Mock(returncode=0, stdout='{"success": false, "error": "nope"}', stderr="")
        with self.assertRaises(ChiaRpcError):
            self._run(cp)

    def test_rpc_missing_binary_raises(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(ChiaRpcError):
                anchors_chia_add._rpc("data_layer", "get_root", {"id": STORE})


if __name__ == "__main__":
    unittest.main()
