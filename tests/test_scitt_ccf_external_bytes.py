"""The scitt-ccf reader on third-party bytes, committed as labelled JSON fixtures (ADR 0009, AP4, N3 b).

The bytes are copies of files from two MIT-licensed repositories at pinned commits, written by
tools/scitt_ccf_external/fetch_external.py --write-fixtures into
tests/fixtures/scitt_ccf/third_party_*.json. They are not proofbundle's: every entry is labelled
"third-party bytes" with its source address and licence, and each file carries the licence text.
The labels and pins are checked in both environments; the reader cases need the [scitt] extra. The
recorded comparison of the same bytes with microsoft/scitt-verifier is
tools/scitt_ccf_external/rust_crosscheck.json (58 values equal, 0 differ).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from proofbundle import scitt_ccf as S
from proofbundle._wire_b64 import decode_b64

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "scitt_ccf"
PROVENANCE = FIXTURES / "PROVENANCE.json"
THIRD_PARTY = "third-party bytes"
MST = "mst-test-scitt-verifier.confidential-ledger.azure.com"
needs_extra = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                 reason="the scitt-ccf reader needs the [scitt] extra")


def _fetcher():
    """The fetcher's own pins, used here, not copied: two pin lists would be two truths."""
    name = "_scitt_ccf_fetch_external"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, REPO / "tools" / "scitt_ccf_external" / "fetch_external.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _documents() -> dict:
    return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(FIXTURES.glob("third_party_*.json"))}


def _bytes() -> dict:
    return {name: decode_b64(e["bytes_b64"]) for doc in _documents().values() for name, e in doc["files"].items()}


# ------------------------------------------------------------------------------------------------
# Labels and pins, in both environments
# ------------------------------------------------------------------------------------------------
def test_every_file_in_the_fixture_directory_has_an_origin_and_a_pin():
    prov = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    entries = {e["filename"]: e for e in prov["files"]}
    present = {p.name for p in FIXTURES.iterdir() if p.is_file() and p.name != "PROVENANCE.json"}
    assert present and present == set(entries)
    for name, e in entries.items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == e["sha256"], name
        assert e["origin"] in (THIRD_PARTY, "made here"), name
        if e["origin"] == THIRD_PARTY:
            assert e["license"] == "MIT" and e["source_url"].startswith("https://github.com/microsoft/"), name
    assert {n for n, e in entries.items() if e["origin"] == THIRD_PARTY} == set(_documents())


def test_every_third_party_entry_is_labelled_with_origin_source_and_licence():
    fx = _fetcher()
    docs = _documents()
    assert set(docs) == {f"third_party_{s.replace('-', '_')}.json" for s in fx.VENDORED}
    for fname, doc in docs.items():
        source = next(s for s in fx.VENDORED if fname == f"third_party_{s.replace('-', '_')}.json")
        repo, commit = fx.REPOSITORIES[source]
        licence_name, names = fx.VENDORED[source]
        assert (doc["origin"], doc["licence"], doc["commit"]) == (THIRD_PARTY, "MIT", commit), fname
        assert doc["repository"] == f"https://github.com/{repo}"
        text = doc["licence_text"].encode("utf-8")
        assert hashlib.sha256(text).hexdigest() == doc["licence_sha256"] == fx.EXPECTED[licence_name][3]
        assert b"MIT License" in text and b"Copyright (c) Microsoft Corporation." in text
        assert b"shall be included in all" in text      # the condition this copy is made under
        assert sorted(doc["files"]) == sorted(names), fname
        for name, e in doc["files"].items():
            _src, path, size, digest = fx.EXPECTED[name]
            assert e["origin"] == THIRD_PARTY, name
            assert e["source"] == f"https://github.com/{repo}/blob/{commit}/{path}", name
            assert e["licence"].startswith("MIT, ") and e["licence"].endswith(fx.EXPECTED[licence_name][1]), name
            raw = decode_b64(e["bytes_b64"])
            assert (len(raw), hashlib.sha256(raw).hexdigest()) == (e["size"], e["sha256"]) == (size, digest), name


def test_the_committed_fixtures_are_exactly_what_the_fetcher_writes():
    fx = _fetcher()
    docs = _documents()
    fetched = _bytes()
    for source, (licence_name, _names) in fx.VENDORED.items():
        doc = docs[f"third_party_{source.replace('-', '_')}.json"]
        fetched[licence_name] = doc["licence_text"].encode("utf-8")
        assert fx.fixture_document(source, fetched) == doc, source


def test_a_one_byte_change_is_not_the_pinned_file():
    raw = bytearray(_bytes()["transparent-statement.cose"])
    raw[100] ^= 0x01
    assert hashlib.sha256(bytes(raw)).hexdigest() != _fetcher().EXPECTED["transparent-statement.cose"][3]


# ------------------------------------------------------------------------------------------------
# The reader on the real bytes
# ------------------------------------------------------------------------------------------------
def _mst(f):
    return {"scitt_ccf_services": {MST: S.load_cose_keyset(f["mst-test-scitt-keys.cbor"])}}


def _receipts(f, name, rp):
    return [c.status for c in S.verify_transparent_statement(f[name], canonical_root=b"\x00" * 32,
                                                              rp_trust=rp).receipts]


@needs_extra
def test_real_receipts_of_the_test_service():
    f = _bytes()
    rp = _mst(f)
    assert _receipts(f, "transparent-statement.cose", rp) == ["confirmed"]
    assert _receipts(f, "appended-receipt.cose", rp) == ["confirmed", "signature_invalid"]
    assert _receipts(f, "payload-tampered.cose", rp) == ["receipt_not_bound"]
    assert _receipts(f, "tampered-statement.cose", rp) == ["signature_invalid"]
    other = {"scitt_ccf_services": {MST: S.load_cose_keyset(f["other-service-scitt-keys.cbor"])}}
    assert _receipts(f, "transparent-statement.cose", other) == ["needs_rp_trust"]
    # none of them is a v1 hash envelope, so the statement side keeps every entry outside the profile
    assert S.verify_transparent_statement(f["transparent-statement.cose"], canonical_root=b"\x00" * 32,
                                          rp_trust=rp).status == "outside_profile"


@needs_extra
def test_real_data_hashes_equal_the_upstream_pin_and_the_leaf():
    f = _bytes()
    assert S.recompute_data_hash(f["transparent-statement.cose"]).hex() == \
        "6f7607e4d68fd01298c47897357a093944de8c033c99bbb3284b8243aa0e6d11"
    r = S.verify_transparent_statement(f["transparent-statement.cose"], canonical_root=b"\x00" * 32,
                                       rp_trust=_mst(f))
    assert r.receipts[0].merkle_root.hex() == "c8dee06dcaa9268cd2910ca78d24a18490789a9d24acba96534dfe8f3b788c14"


@needs_extra
def test_real_production_receipt_over_a_hash_envelope():
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    f = _bytes()
    store = json.loads(f["esrp-cts-db.json"])
    keys = [x509.load_der_x509_certificate(decode_b64(p["serviceCertificate"])).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for p in store["parameters"]]
    rp = {"scitt_ccf_services": {"esrp-cts-db.confidential-ledger.azure.com": keys}}
    r = S.verify_transparent_statement(f["uvm_0.2.10.cose"], canonical_root=b"\x00" * 32, rp_trust=rp)
    assert [c.status for c in r.receipts] == ["confirmed"]
    assert r.receipts[0].kid_bound_to_key is True and r.receipts[0].receipt_iat == 1766437888
    assert r.status == "outside_profile" and "-16" in r.detail          # SHA-384 envelope, not v1
    assert S.recompute_data_hash(f["uvm_0.2.10.cose"]).hex().startswith("a60138fb1591")


@needs_extra
def test_real_forms_v1_refuses():
    f = _bytes()
    assert S.verify_transparent_statement(f["nested-sign1.cose"], canonical_root=b"\x00" * 32,
                                          rp_trust=_mst(f)).status == "malformed"      # nested tag 18
    assert _receipts(f, "cts-hashv-cwtclaims-b64url.cose", _mst(f)) == ["malformed"]  # legacy receipt


def _chain_spkis(statement: bytes) -> list:
    """The SPKI of every x5chain certificate, read with cbor2 and cryptography directly, not with
    the module under test."""
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    protected = cbor2.loads(cbor2.loads(statement).value[0])
    return [x509.load_der_x509_certificate(c).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for c in protected[33]]


@needs_extra
@pytest.mark.parametrize("name, alg", [("transparent-statement.cose", -37), ("uvm_0.2.10.cose", -38),
                                       ("cts-hashv-cwtclaims-b64url.cose", -37)])
def test_real_statement_signer_is_selected_by_its_protected_x5chain(name, alg):
    """Owner answer N4 b on real bytes: every real statement measured carries a protected x5chain."""
    f = _bytes()
    ts = f[name]
    assert S.decode_cose_sign1(ts).protected[1] == alg
    leaf, issuer, *_ = _chain_spkis(ts)
    assert S.verify_statement_signature(ts, statement_keys=[leaf]) == ("confirmed", True)
    assert S.verify_statement_signature(ts, statement_keys=[issuer, leaf]) == ("confirmed", True)
    # the key the RP holds is not the one the statement names: missing trust, not a failed signature
    assert S.verify_statement_signature(ts, statement_keys=[issuer]) == ("needs_rp_trust", None)


@needs_extra
def test_real_payload_change_under_the_selected_key_is_a_failed_signature():
    f = _bytes()
    leaf = _chain_spkis(f["payload-tampered.cose"])[0]
    assert leaf == _chain_spkis(f["transparent-statement.cose"])[0]
    assert S.verify_statement_signature(f["payload-tampered.cose"], statement_keys=[leaf]) == \
        ("statement_signature_invalid", False)
