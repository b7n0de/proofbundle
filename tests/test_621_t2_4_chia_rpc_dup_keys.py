"""6.2.1 T2-4: the Chia RPC reader in anchors_chia_add rejects a response with a duplicate JSON key.

PROPERTY: `_rpc` is the choke point that turns a node answer into "succeeded" or ChiaRpcError. A
response that names `success` twice has no single meaning; a last-wins reader takes the last value and
a first-wins reader the first. Measured at 419e07f2: `{"success": false, "success": true}` and the
escape spelling `\\u0073uccess` return normally from `_rpc`, and `anchor_add(wait=False)` exports an
anchor after a batch_update answer whose first `success` is false. The exported anchor is still
self-verified against get_proof (control), so this test pins the reader, not the anchor's validity.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

import pytest

from proofbundle import anchors_chia_add
from proofbundle.anchors_chia_add import ChiaRpcError, anchor_add

from test_anchors_chia_add import STORE, _synthetic_proof

DUP = {
    "success_false_then_true": '{"success": false, "error": "nope", "success": true}',
    "success_escaped": '{"success": false, "error": "nope", "\\u0073uccess": true}',
    "hash_twice": '{"hash": "0x' + "00" * 32 + '", "hash": "0x' + "ab" * 32 + '"}',
    "nested_twice": '{"proof": {"coin_id": "0x01", "coin_id": "0x02"}}',
}


def _call(stdout: str):
    cp = mock.Mock(returncode=0, stdout=stdout, stderr="")
    with mock.patch("subprocess.run", return_value=cp):
        return anchors_chia_add._rpc("data_layer", "get_root", {"id": STORE})


@pytest.mark.parametrize("case", sorted(DUP))
def test_rpc_rejects_duplicate_key(case):
    with pytest.raises(ChiaRpcError):
        _call(DUP[case])


def test_control_success_false_raises():
    with pytest.raises(ChiaRpcError):
        _call('{"success": false, "error": "nope"}')


def test_control_unique_response_returns():
    assert _call('{"success": true, "hash": "0x' + "ab" * 32 + '"}')["success"] is True


def _subprocess_dispatch(batch_stdout: str, key: str, value: str):
    proof, root = _synthetic_proof(key, value)
    answers = {
        "get_root": json.dumps({"hash": root, "confirmed": True, "success": True}),
        "batch_update": batch_stdout,
        "get_proof": json.dumps({"proof": {"store_proofs": {"proofs": [proof]},
                                           "coin_id": "0x" + "cd" * 32,
                                           "inner_puzzle_hash": "0x" + "ef" * 32}, "success": True}),
        "get_coin_record_by_name": json.dumps({"coin_record": {"confirmed_block_index": 1,
                                                               "timestamp": 1783330051},
                                               "success": True}),
    }

    def run(argv, **_kw):
        return mock.Mock(returncode=0, stdout=answers[argv[3]], stderr="")
    return run


def test_anchor_add_aborts_on_duplicate_success_in_batch_update():
    key = "0x" + "11" * 32
    run = _subprocess_dispatch(DUP["success_false_then_true"], key, key)
    with mock.patch("subprocess.run", side_effect=run):
        with pytest.raises(ChiaRpcError):
            anchor_add(key, store_id=STORE, wait=False)


def test_control_anchor_add_exports_on_unique_success():
    key = "0x" + "11" * 32
    run = _subprocess_dispatch('{"success": true, "tx_id": "0x' + "ab" * 32 + '"}', key, key)
    with mock.patch("subprocess.run", side_effect=run):
        anchor = anchor_add(key, store_id=STORE, wait=False)
    assert anchor["type"] == anchors_chia_add.ANCHOR_TYPE


def test_control_anchor_add_aborts_on_unique_failure():
    key = "0x" + "11" * 32
    run = _subprocess_dispatch('{"success": false, "error": "insufficient funds"}', key, key)
    with mock.patch("subprocess.run", side_effect=run):
        with pytest.raises(ChiaRpcError):
            anchor_add(key, store_id=STORE, wait=False)


if __name__ == "__main__":
    unittest.main()
