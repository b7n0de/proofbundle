"""The receipt-level vectors for section 4 of draft-ietf-scitt-receipts-ccf-profile-05.

tools/scitt_ccf_external/section4_vectors/ holds one file per vector. Each records the result under
reading A (Figure 9 of 4.2, as written) and under reading B (every sentence of 4, 4.1 and 5 the
listed wire, root-binding and signature checks), size-free and size-aware with the vector's tree sizes. This test
runs the directory's own checker, which imports nothing from proofbundle, runs proofbundle's reader
over the same vectors without and with the sizes, and flips one byte in the signature, a tag, the
anchor and the path of each vector: the result must then change or be a rejection.
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
SUCCESS = ("confirmed", "confirmed_without_tree_sizes")


def _checker():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("section4_check_vectors", DIR / "check_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vectors() -> list:
    return [json.loads((DIR / f"{i}.json").read_text(encoding="utf-8")) for i in IDS]


def _reader_status(v: dict, receipt: bytes, sizes: bool = False) -> str:
    from proofbundle import scitt_ccf
    key = v["public_key"]
    trust = {"scitt_ccf_services": {key["issuer"]: [{"spki": bytes.fromhex(key["spki_der_hex"]),
                                                      "kid": key["kid"].encode("ascii")}]}}
    kw = dict(older_size=v["older_size"], newer_size=v["newer_size"]) if sizes else {}
    return scitt_ccf.verify_consistency_receipt(receipt, older_root=bytes.fromhex(v["older_root_hex"]),
                                                older_issuer=key["issuer"], rp_trust=trust, **kw).status


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


def test_the_reader_gives_the_status_each_vector_records_without_and_with_the_sizes():
    for sizes, key in ((False, "status_without_sizes"), (True, "status_with_sizes")):
        got = {v["id"]: _reader_status(v, bytes.fromhex(v["receipt_hex"]), sizes) for v in _vectors()}
        assert got == {v["id"]: v["proofbundle_reader"][key] for v in _vectors()}, key


def test_without_sizes_nothing_is_confirmed_and_the_sizes_decide_s4_08_to_s4_10():
    vs = {v["id"]: v for v in _vectors()}
    assert not [i for i, v in vs.items() if v["proofbundle_reader"]["status_without_sizes"] == "confirmed"]
    got = {i: (vs[i]["older_size"], vs[i]["newer_size"], vs[i]["proofbundle_reader"]["status_without_sizes"],
               vs[i]["proofbundle_reader"]["status_with_sizes"], vs[i]["reading_b_size_free"]["result"],
               vs[i]["reading_b_size_aware"]["result"]) for i in ("S4-08", "S4-09", "S4-10")}
    assert got == {
        "S4-08": (24, 24, "consistency_anchor_not_canonical", "consistency_tree_sizes_invalid", "reject", "reject"),
        "S4-09": (22, 24, "consistency_anchor_not_canonical", "consistency_anchor_position_mismatch", "reject",
                  "reject"),
        "S4-10": (6, 7, "confirmed_without_tree_sizes", "consistency_anchor_position_mismatch",
                  "passes_size_free_checks", "reject"),
    }


def test_the_checkers_tag_rule_matches_the_proofs_built_from_the_ledger():
    checker = _checker()
    seen = 0
    for v in _vectors():
        if v["reading_b_size_aware"]["result"] != "accept":
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
        m, n = v["older_size"], v["newer_size"]
        before = {"reading A": v["reading_a"]["result"], "reading B": v["reading_b_size_free"]["result"],
                  "reading B with sizes": v["reading_b_size_aware"]["result"],
                  "reader": v["proofbundle_reader"]["status_without_sizes"],
                  "reader with sizes": v["proofbundle_reader"]["status_with_sizes"]}
        for site, receipt in _mutations(v, cbor2).items():
            if receipt is None:
                counts["not_applicable"] += 1
                continue
            counts["mutated"] += 1
            after = {"reading A": checker.reading_a(receipt, older, spki)[0],
                     "reading B": checker.reading_b_size_free(receipt, older, spki)[0],
                     "reading B with sizes": checker.reading_b_size_aware(receipt, older, spki, m, n)[0],
                     "reader": _reader_status(v, receipt), "reader with sizes": _reader_status(v, receipt, True)}
            for who, got in after.items():
                refused = got not in SUCCESS if who.startswith("reader") else got == "reject"
                if not (got != before[who] or refused):
                    held.append((v["id"], site, who, got))
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


def _test_key_receipt(vdp: dict, prot: dict, cbor2) -> tuple:
    """A receipt over S4-01's newer root signed with the directory's TEST ONLY key: (bytes, spki)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    key = serialization.load_pem_private_key((DIR / "TEST_ONLY_es384_private_key.pem").read_bytes(), password=None)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    s401 = json.loads((DIR / "S4-01.json").read_text(encoding="utf-8"))
    newer = bytes.fromhex(s401["consistency_proofs_decoded"][0]["anchor_hex"])
    for left, h in s401["consistency_proofs_decoded"][0]["path"]:
        newer = hashlib.sha256((bytes.fromhex(h) + newer) if left else (newer + bytes.fromhex(h))).digest()
    prot_b = cbor2.dumps(prot)
    r, s = utils.decode_dss_signature(key.sign(cbor2.dumps(["Signature1", prot_b, b"", newer]),
                                               ec.ECDSA(hashes.SHA384(), deterministic_signing=True)))
    return b"\xd2" + cbor2.dumps([prot_b, {396: vdp}, None, r.to_bytes(48, "big") + s.to_bytes(48, "big")]), spki


def _s401_parts(cbor2) -> tuple:
    s401 = json.loads((DIR / "S4-01.json").read_text(encoding="utf-8"))
    tag = cbor2.loads(bytes.fromhex(s401["receipt_hex"]))
    return s401, tag.value, dict(tag.value[1][396])


@pytest.mark.parametrize("vds", [2.0, "2", True, None, 2], ids=["float", "text", "bool", "null", "control"])
def test_the_checker_takes_vds_only_as_the_int_2(vds):
    """B1: vds (395) => int, TBD_1 = 2. Python's 2.0 == 2 must not let a float through."""
    import cbor2
    _s401, _parts, vdp = _s401_parts(cbor2)
    prot = {1: -35, 4: b"test-only", 15: {1: "test-only.section4-vectors.invalid"}, "ccf.v1": {"txid": "2.24"}}
    if vds is not None:
        prot[395] = vds
    receipt, spki = _test_key_receipt({-2: list(vdp[-2])}, prot, cbor2)
    older = bytes.fromhex(_s401["older_root_hex"])
    got = _checker().reading_b_size_free(receipt, older, spki)
    is_int_2 = isinstance(vds, int) and not isinstance(vds, bool) and vds == 2
    assert got == (("passes_size_free_checks", "B1 to B13 hold") if is_int_2 else ("reject", "B1")), got


@pytest.mark.parametrize("alg", [-35.0, True, "-35"], ids=["float", "bool", "text"])
def test_the_checkers_verify_cose_takes_alg_only_as_an_int(alg):
    """Reading A reaches verify_cose, which looked alg up in a dict: -35.0 hashes like -35."""
    import cbor2
    s401, _parts, vdp = _s401_parts(cbor2)
    prot = {1: alg, 4: b"test-only", 15: {1: "test-only.section4-vectors.invalid"}, 395: 2}
    receipt, spki = _test_key_receipt({-2: list(vdp[-2])}, prot, cbor2)
    older = bytes.fromhex(s401["older_root_hex"])
    assert _checker().reading_a(receipt, older, spki) == ("reject", "assert(verify_cose(consistency_receipt, payload))")


@pytest.mark.parametrize("value", [None, {}, [], b"", 0], ids=["null", "map", "empty", "bstr", "int"])
def test_the_checker_takes_a_present_inclusion_key_as_present(value):
    """B6: a -1 in vdp must be an array of one or more inclusion proofs; -1 with null is not absent."""
    import cbor2
    s401, (prot_b, _u, payload, sig), vdp = _s401_parts(cbor2)
    receipt = b"\xd2" + cbor2.dumps([prot_b, {396: {**vdp, -1: value}}, payload, sig])
    got = _checker().reading_b_size_free(receipt, bytes.fromhex(s401["older_root_hex"]),
                               bytes.fromhex(s401["public_key"]["spki_der_hex"]))
    assert got == ("reject", "B6"), got
    sized = _checker().reading_b_size_aware(receipt, bytes.fromhex(s401["older_root_hex"]),
                                            bytes.fromhex(s401["public_key"]["spki_der_hex"]), 19, 24)
    assert sized == ("reject", "B6"), sized


def test_the_size_free_result_uses_no_size_and_names_its_pass_alike():
    """Nachtrag 2, point 1: the size-free result takes no size at all, and every vector that passes
    B1 to B13 reads passes_size_free_checks, S4-10 included; only the size-aware result adds B14."""
    import inspect
    checker = _checker()
    assert list(inspect.signature(checker.reading_b_size_free).parameters) == ["receipt", "older_root", "spki"]
    passing = sorted(v["id"] for v in _vectors() if v["reading_b_size_free"]["result"] == "passes_size_free_checks")
    assert passing == ["S4-01", "S4-02", "S4-04", "S4-07", "S4-10"]
    assert {v["reading_b_size_free"]["result"] for v in _vectors()} == {"passes_size_free_checks", "reject"}
    aware = {v["id"]: (v["reading_b_size_aware"]["result"], v["reading_b_size_aware"]["rule"]) for v in _vectors()}
    assert aware["S4-10"] == ("reject", "B14")
    assert [i for i in passing if aware[i][0] == "accept"] == ["S4-01", "S4-02", "S4-04", "S4-07"]


def test_thirteen_unchanged_service_signatures_one_flipped_and_one_test_key():
    """Nachtrag 2, point 5: the fixture's signature over R_24, byte for byte, in 13 vectors; S4-14
    carries it with one bit flipped; S4-10 is signed with the test key."""
    import cbor2
    from proofbundle._wire_b64 import decode_b64
    fixture = json.loads((REPO / "tests" / "fixtures" / "scitt_ccf" / "local_ledger_consistency.json").read_text())
    service_sig = cbor2.loads(decode_b64(fixture["newer_receipt_b64"])).value[3]
    signer = {v["id"]: v["provenance"]["signer"] for v in _vectors()}
    sig = {v["id"]: cbor2.loads(bytes.fromhex(v["receipt_hex"])).value[3] for v in _vectors()}
    unchanged = sorted(i for i in IDS if sig[i] == service_sig)
    assert unchanged == sorted(i for i in IDS if signer[i] == "service") and len(unchanged) == 13
    assert signer["S4-14"] == "service, one signature bit flipped"
    assert sum(bin(a ^ b).count("1") for a, b in zip(sig["S4-14"], service_sig)) == 1
    assert [i for i in IDS if signer[i] == "test key"] == ["S4-10"]


def test_s4_10_names_its_newer_size_as_asserted_by_the_synthetic_txid_not_measured():
    """Nachtrag 4, point 1: the test-key txid 2.7 is an assertion; only the service's txids were measured."""
    notes = {v["id"]: v["tree_sizes_note"] for v in _vectors()}
    assert notes.pop("S4-10") == ("older_size: 6 from the constructed older tree; newer_size: 7 asserted by the "
                                  "synthetic test-key header txid 2.7; the signed N1 is not the canonical root R_7.")
    assert all("as measured on CCF 7.0.17" in n for n in notes.values()) and len(notes) == 14
