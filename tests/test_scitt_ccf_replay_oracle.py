"""The independent oracle of the replay package, against the accepted rows of rounds 1 to 3.

tools/scitt_ccf_external/replay_earlier_build/oracle.py rebuilds C(n) from a request's bytes alone: tag 18, a
four-element array of the protected bstr content, an empty map, the payload content and the signature content,
each bstr in preferred framing. It hashes it with SHA-256, holds that against the receipt's data-hash, verifies
the receipt under the service's key set, and cross-checks the rebuilt object against the returned statement with
label 394 removed. It imports nothing from proofbundle and gives no profile verdict.

These tests run it over every accepted row of the three stored rounds, 62 rows, and over planted deviations: a
changed signature byte, the key set of another round, a changed returned statement, a refused row without a
receipt, and a request in non-preferred outer framing.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "scitt_ccf_external"
ORACLE = TOOLS / "replay_earlier_build" / "oracle.py"

needs_cryptography = pytest.mark.skipif(importlib.util.find_spec("cryptography") is None,
                                        reason="the oracle verifies the receipt's ECDSA signature with cryptography")


def _oracle():
    name = "_scitt_ccf_replay_oracle"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ORACLE)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _hex(p: Path) -> bytes:
    return bytes.fromhex(p.read_text(encoding="ascii").strip())


def _accepted_rows() -> list[tuple[str, Path, Path]]:
    """(row id, vector directory, key set file) for every stored vector with a receipt."""
    rows = []
    for rnd, d in (("r1", "differential_corpus"), ("r2", "differential_corpus_round2"),
                   ("r3", "differential_corpus_round3")):
        for v in sorted((TOOLS / d / "vectors").iterdir()):
            if not (v / "receipt.hex").exists():
                continue
            if rnd == "r2":
                keyset = TOOLS / d / json.loads((v / "record.json").read_text(encoding="utf-8"))["phase"]["keyset"]
            else:
                keyset = TOOLS / d / "scitt-keys.hex"
            rows.append((f"{rnd}/{v.name}", v, keyset))
    return rows


ROWS = _accepted_rows()


def test_there_are_62_accepted_rows():
    assert len(ROWS) == 62


def test_the_oracle_imports_nothing_from_proofbundle():
    tree = ast.parse(ORACLE.read_text(encoding="utf-8"))
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [n for n in names if n.split(".")[0] == "proofbundle"], names


@needs_cryptography
@pytest.mark.parametrize("row, vec, keyset", ROWS, ids=[r[0] for r in ROWS])
def test_the_oracle_rebuilds_the_data_hash_of_every_accepted_row(row, vec, keyset):
    rep = _oracle().check(_hex(vec / "request.hex"), receipt=_hex(vec / "receipt.hex"),
                          returned=_hex(vec / "statement.hex"), keyset=_hex(keyset))
    assert rep["data_hash_match"] is True, rep
    assert rep["receipt_signature_valid"] is True, rep
    assert rep["rebuilt_equals_returned_minus_394"] is True, rep
    assert rep["rebuilt_sha256"] == rep["receipt_data_hash"]
    assert rep["returned_statement_sha256"] == hashlib.sha256(_hex(vec / "statement.hex")).hexdigest()
    assert "profile" not in json.dumps(rep).lower()


@needs_cryptography
def test_a_changed_signature_byte_breaks_the_data_hash():
    _, vec, keyset = ROWS[0]
    req = bytearray(_hex(vec / "request.hex"))
    req[-1] ^= 0x01
    rep = _oracle().check(bytes(req), receipt=_hex(vec / "receipt.hex"), returned=_hex(vec / "statement.hex"),
                          keyset=_hex(keyset))
    assert rep["data_hash_match"] is False
    assert rep["receipt_signature_valid"] is True       # the receipt itself is unchanged
    assert rep["rebuilt_equals_returned_minus_394"] is False


@needs_cryptography
def test_the_key_set_of_another_round_does_not_verify_the_receipt():
    r3 = [r for r in ROWS if r[0] == "r3/control"][0]
    r1_keys = TOOLS / "differential_corpus" / "scitt-keys.hex"
    rep = _oracle().check(_hex(r3[1] / "request.hex"), receipt=_hex(r3[1] / "receipt.hex"),
                          returned=_hex(r3[1] / "statement.hex"), keyset=_hex(r1_keys))
    assert rep["data_hash_match"] is True
    assert rep["receipt_signature_valid"] is not True
    assert "kid" in rep["receipt_signature_note"]


@needs_cryptography
def test_a_changed_returned_statement_fails_the_cross_check():
    _, vec, keyset = ROWS[0]
    ret = bytearray(_hex(vec / "statement.hex"))
    ret[-1] ^= 0x01
    rep = _oracle().check(_hex(vec / "request.hex"), receipt=_hex(vec / "receipt.hex"), returned=bytes(ret),
                          keyset=_hex(keyset))
    assert rep["data_hash_match"] is True
    assert rep["rebuilt_equals_returned_minus_394"] is False


def test_a_refused_row_carries_no_commitment_result():
    vec = TOOLS / "differential_corpus_round3" / "vectors" / "m-u15"
    rep = _oracle().check(_hex(vec / "request.hex"))
    assert rep["receipt_data_hash"] is None
    assert rep["data_hash_match"] is None
    assert rep["receipt_signature_valid"] is None
    assert len(rep["rebuilt_sha256"]) == 64


def test_non_preferred_outer_framing_is_rebuilt_in_preferred_framing():
    o = _oracle()
    vec = TOOLS / "differential_corpus_round3" / "vectors" / "control"
    req = _hex(vec / "request.hex")
    parts = o.sign1_parts(req)
    sig = parts["signature"]
    wide = req[: len(req) - len(sig) - 2] + b"\x59" + len(sig).to_bytes(2, "big") + sig   # 58 40 -> 59 00 40
    assert len(sig) == 64 and req[len(req) - len(sig) - 2: len(req) - len(sig)] == b"\x58\x40"
    assert o.rebuild(wide) == o.rebuild(req)
    assert hashlib.sha256(o.rebuild(wide)).hexdigest() == hashlib.sha256(req).hexdigest()


def test_an_untagged_or_indefinite_request_is_refused_by_the_oracle():
    o = _oracle()
    req = _hex(TOOLS / "differential_corpus_round3" / "vectors" / "control" / "request.hex")
    with pytest.raises(o.NotCoseSign1):
        o.rebuild(req[1:])                                  # tag 18 removed
    with pytest.raises(o.NotCoseSign1):
        o.rebuild(b"\xd2\x9f" + req[2:] + b"\xff")          # indefinite outer array
