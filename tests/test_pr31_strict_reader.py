"""The strict reader of tools/scitt_ccf_external/pr31_strict_reader on all 36 receipts next to it.

Pull request 31 to the CCF receipt profile requires a Verifier to reject a proof that is not valid CBOR, in particular
one whose map has a duplicate key (commits eb01db3f and 820c5e4e), and a receipt whose vdp map is not valid CBOR or
does not match verifiable-proofs (commit f6d4eb04). The data-hash preimage carries an empty unprotected header map,
which this reader writes as the one byte a0.

Every receipt in ``probes/index.json`` and ``vectors/vectors.json`` is read and its verdict held against the file,
and the reasons that matter for pull request 31 are held by name. The twins are the controls. Two counter-probes run
the earlier reading on the same bytes and show that these cases would be green against it: without the check of the
whole vdp map, and, where cbor2 is installed, with cbor2 decoding, where the last value of a duplicate key wins.
"""
from __future__ import annotations

import importlib.util
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HERE = REPO / "tools" / "scitt_ccf_external" / "pr31_strict_reader"
PROBES = json.loads((HERE / "probes" / "index.json").read_text(encoding="utf-8"))
VECTORS = json.loads((HERE / "vectors" / "vectors.json").read_text(encoding="utf-8"))


def _reader():
    spec = importlib.util.spec_from_file_location("_pr31_strict_reader", HERE / "reader.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


READER = _reader()


def _probe(name: str, reader=READER) -> str:
    entry = PROBES["probes"][name]
    return reader.verdict((HERE / "probes" / entry["file"]).read_bytes(), (HERE / "probes" / "keys.cbor").read_bytes(),
                          digest=bytes.fromhex(PROBES["data_hash_hex"]))


def _vector(name: str, reader=READER) -> str:
    entry = VECTORS[name]
    receipt = (HERE / "vectors" / f"{name}.cose").read_bytes()
    keys = (HERE / "vectors" / "keys.cbor").read_bytes()
    if entry.get("statement"):
        return reader.verdict(receipt, keys, statement_raw=(HERE / "vectors" / entry["statement"]).read_bytes())
    return reader.verdict(receipt, keys, digest=bytes.fromhex(entry["data_hash_hex"]))


def test_the_files_carry_24_probes_and_12_vectors():
    assert len(PROBES["probes"]) == 24
    assert len(VECTORS) == 12


@pytest.mark.parametrize("name", sorted(PROBES["probes"]))
def test_every_probe_gets_its_strict_verdict(name):
    assert _probe(name).split()[0] == PROBES["probes"][name]["expected_strict"]


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_every_vector_gets_its_strict_verdict(name):
    assert _vector(name).split()[0] == VECTORS[name]["strict"]


@pytest.mark.parametrize("name, reason", [
    ("duplicate_key_2", "FAIL cbor_proof: duplicate map key 2"),
    ("plus_empty_consistency_array", "FAIL vdp_empty"),
    ("bytes_after_the_proof", "FAIL cbor_proof: 1 byte(s) after the data item"),
    ("evidence_invalid_utf8", "FAIL cbor_proof: text string is not valid UTF-8"),
])
def test_the_probes_of_pull_request_31_are_refused_for_their_reason(name, reason):
    assert _probe(name) == reason


@pytest.mark.parametrize("name, reason", [
    ("dup_leaf_first", "FAIL cbor_proof: duplicate map key 1"),
    ("dup_leaf_last", "FAIL cbor_proof: duplicate map key 1"),
    ("dup_path_first", "FAIL cbor_proof: duplicate map key 2"),
    ("dup_path_last", "FAIL cbor_proof: duplicate map key 2"),
    ("vdp_duplicate_key", "FAIL cbor_receipt: duplicate map key -1"),
    ("vdp_empty_consistency", "FAIL vdp_empty"),
    ("vdp_unknown_key", "FAIL vdp_key"),
    ("empty_map_b8_00", "FAIL digest_mismatch"),
    ("empty_map_bf_ff", "FAIL digest_mismatch"),
])
def test_the_vectors_are_refused_for_their_reason(name, reason):
    assert _vector(name) == reason


@pytest.mark.parametrize("name", ["dup_twin", "vdp_twin", "empty_map_a0"])
def test_control_the_twins_and_the_a0_preimage_pass(name):
    assert _vector(name).startswith("PASS ")


def test_counter_probe_without_the_vdp_check_the_vdp_cases_pass(monkeypatch):
    """The earlier reading checked only the inclusion-proof array; it passed these receipts (measured 2026-10-15)."""
    monkeypatch.setattr(READER, "_check_vdp", lambda unprotected: unprotected.get(READER.VDP))
    assert _probe("plus_empty_consistency_array").startswith("PASS ")
    assert _vector("vdp_empty_consistency").startswith("PASS ")
    assert _vector("vdp_unknown_key").startswith("PASS ")


def test_counter_probe_with_cbor2_the_last_value_of_a_duplicate_key_wins(monkeypatch):
    """With cbor2 in place of the strict helper, a duplicate key no longer stops the reader: the receipt signed for
    the last value passes, the one signed for the first fails on its signature. That is the earlier reading."""
    cbor2 = pytest.importorskip("cbor2")

    def lift(v):
        # cbor2 6 returns an array under a tag as a tuple and a map there as a frozendict (measured with 6.1.4);
        # both are read back as the strict helper's list and dict.
        if isinstance(v, cbor2.CBORTag):
            return READER.Tag(v.tag, lift(v.value))
        if isinstance(v, (list, tuple)):
            return [lift(x) for x in v]
        if isinstance(v, Mapping):
            return {k: lift(x) for k, x in v.items()}
        return v

    monkeypatch.setattr(READER, "strict", lambda b, what: lift(cbor2.loads(b)))
    assert _probe("duplicate_key_2").startswith("PASS ")
    assert _vector("dup_leaf_last").startswith("PASS ")
    assert _vector("dup_path_last").startswith("PASS ")
    assert _vector("dup_leaf_first") == "FAIL signature"
    assert _vector("dup_path_first") == "FAIL signature"
