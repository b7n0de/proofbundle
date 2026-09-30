"""The receipt-level vectors for section 4 of draft-ietf-scitt-receipts-ccf-profile-05.

tools/scitt_ccf_external/section4_vectors/ holds one file per vector. Each records the result under
reading A (Figure 9 of 4.2, as written) and under reading B (every sentence of 4, 4.1 and 5 the
receipt carries enough to check). This test runs the directory's own checker, which imports nothing
from proofbundle, runs proofbundle's reader over the same vectors, and flips one byte in the
signature, a tag, the anchor and the path of each vector: the result must then change or be a
rejection.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the vectors need cbor2 (the [scitt] extra)")

REPO = Path(__file__).resolve().parents[1]
DIR = REPO / "tools" / "scitt_ccf_external" / "section4_vectors"
IDS = [f"S4-{i:02d}" for i in range(1, 16)]


def _checker():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("section4_check_vectors", DIR / "check_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vectors() -> list:
    return [json.loads((DIR / f"{i}.json").read_text(encoding="utf-8")) for i in IDS]


def _reader_status(v: dict, receipt: bytes) -> str:
    from proofbundle import scitt_ccf
    key = v["public_key"]
    trust = {"scitt_ccf_services": {key["issuer"]: [{"spki": bytes.fromhex(key["spki_der_hex"]),
                                                      "kid": key["kid"].encode("ascii")}]}}
    return scitt_ccf.verify_consistency_receipt(receipt, older_root=bytes.fromhex(v["older_root_hex"]),
                                                older_issuer=key["issuer"], rp_trust=trust).status


def test_the_directory_holds_exactly_the_fifteen_vectors_and_its_manifest_matches():
    assert sorted(p.stem for p in DIR.glob("S4-*.json")) == IDS
    checker = _checker()
    assert checker.check_manifest(DIR) == []


def test_the_checker_reproduces_both_readings_of_every_vector():
    checker = _checker()
    rows = [checker.check_vector(v) for v in _vectors()]
    assert [r["id"] for r in rows if not (r["a_matches"] and r["b_matches"])] == []
    assert all(r["kid_matches"] and r["decoded_matches"] for r in rows)
    assert checker.main(["--dir", str(DIR)]) == 0


def test_the_checker_imports_nothing_from_proofbundle():
    tree = ast.parse((DIR / "check_vectors.py").read_text(encoding="utf-8"))
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert "proofbundle" not in names
    assert names <= {"__future__", "argparse", "hashlib", "json", "sys", "collections", "pathlib", "cbor2",
                     "cryptography"}, names


def test_the_reader_gives_the_status_each_vector_records():
    got = {v["id"]: _reader_status(v, bytes.fromhex(v["receipt_hex"])) for v in _vectors()}
    assert got == {v["id"]: v["proofbundle_reader"]["status"] for v in _vectors()}


def test_the_checkers_tag_rule_matches_the_proofs_built_from_the_ledger():
    checker = _checker()
    seen = 0
    for v in _vectors():
        if v["reading_b"]["result"] != "accept":
            continue
        for proof, size in zip(v["consistency_proofs_decoded"], v["generator_tree_sizes"] or []):
            if size and size["n"] is not None:
                assert [left for left, _h in proof["path"]] == checker.canonical_tags(size["m"], size["n"])
                seen += 1
    assert seen == 5


def _mutations(v: dict, cbor2) -> dict:
    """One flipped byte per site; None where the vector has no such site."""
    tag = cbor2.loads(bytes.fromhex(v["receipt_hex"]))
    prot, unprot, payload, sig = tag.value
    vdp = dict(unprot[396])
    proofs = list(vdp.get(-2, []))

    def with_(vdp_=None, sig_=None) -> bytes:
        return b"\xd2" + cbor2.dumps([prot, {396: vdp_ if vdp_ is not None else vdp}, payload,
                                      sig_ if sig_ is not None else sig])

    def first_proof(edit) -> bytes | None:
        if not proofs:
            return None
        d = cbor2.loads(proofs[0])
        anchor, path = d[1], [list(e) for e in d[2]]
        anchor, path = edit(anchor, path)
        return with_({**vdp, -2: [cbor2.dumps({1: anchor, 2: path})] + proofs[1:]})

    def flip(b: bytes) -> bytes:
        return bytes([b[0] ^ 1]) + b[1:]
    return {
        "signature": with_(sig_=flip(sig)),
        "tag": first_proof(lambda a, p: (a, [[not p[0][0], p[0][1]]] + p[1:])),
        "anchor": first_proof(lambda a, p: (flip(a), p)),
        "path": first_proof(lambda a, p: (a, [[p[0][0], flip(p[0][1])]] + p[1:])),
    }


def test_one_flipped_byte_changes_the_result_or_is_refused():
    import cbor2
    checker = _checker()
    counts = {"mutated": 0, "not_applicable": 0}
    held = []
    for v in _vectors():
        older = bytes.fromhex(v["older_root_hex"])
        spki = bytes.fromhex(v["public_key"]["spki_der_hex"])
        before_a = v["reading_a"]["result"]
        before_b = v["reading_b"]["result"]
        before_r = v["proofbundle_reader"]["status"]
        for site, receipt in _mutations(v, cbor2).items():
            if receipt is None:
                counts["not_applicable"] += 1
                continue
            counts["mutated"] += 1
            a = checker.reading_a(receipt, older, spki)[0]
            b = checker.reading_b(receipt, older, spki, v["generator_tree_sizes"])[0]
            r = _reader_status(v, receipt)
            if not (a != before_a or a == "reject"):
                held.append((v["id"], site, "reading A", a))
            if not (b != before_b or b == "reject"):
                held.append((v["id"], site, "reading B", b))
            if not (r != before_r or r != "confirmed"):
                held.append((v["id"], site, "reader", r))
    assert held == []
    assert counts == {"mutated": 57, "not_applicable": 3}


def test_the_one_test_key_is_labelled_test_only_and_signs_deterministically():
    import cbor2
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    pems = sorted(p.name for p in DIR.iterdir() if p.suffix == ".pem")
    assert pems == ["TEST_ONLY_es384_private_key.pem"]
    key = serialization.load_pem_private_key((DIR / pems[0]).read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp384r1"
    signed = [v for v in _vectors() if v["provenance"]["signer"] == "test key"]
    assert [v["id"] for v in signed] == ["S4-10"]
    for v in signed:
        prot, _unprot, _payload, sig = cbor2.loads(bytes.fromhex(v["receipt_hex"])).value
        newer = bytes.fromhex(v["consistency_proofs_decoded"][0]["anchor_hex"])
        for left, h in v["consistency_proofs_decoded"][0]["path"]:
            newer = hashlib.sha256((bytes.fromhex(h) + newer) if left else (newer + bytes.fromhex(h))).digest()
        tbs = cbor2.dumps(["Signature1", prot, b"", newer])
        r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA384(), deterministic_signing=True)))
        assert r.to_bytes(48, "big") + s.to_bytes(48, "big") == sig
