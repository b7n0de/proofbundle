"""The scitt-ccf reader on third-party bytes, when they have been fetched (ADR 0009, AP4).

The bytes are not vendored: tools/scitt_ccf_external/fetch_external.py fetches them at pinned
commits and checks size and sha256. Where they are absent this module skips with that reason; CI
does not fetch, so there it is a skip, and the recorded run of the same checks is
tools/scitt_ccf_external/rust_crosscheck.json (58 values equal to microsoft/scitt-verifier, 0 differ).
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

# A module-wide skip mark, not a module-level importorskip: without the extra the cases must still be
# COLLECTED, so the mutation gate's collector sees this file (test_mutationstor_sammler_...py).
pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

from proofbundle import scitt_ccf as S  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402

FETCHED = Path(__file__).resolve().parents[1] / "tools" / "scitt_ccf_external" / "fetched"
PINS = {  # name -> sha256, the same pins as fetch_external.py
    "transparent-statement.cose": "4bb50fe1a92f74cd85405a15508f560f1bfd77a43e1d00d4b3d718cf5d112377",
    "mst-test-scitt-keys.cbor": "b146b954b2ba79eec5e59748d96064b5f18dfe4b13f90cf5868207985d6faf0e",
    "other-service-scitt-keys.cbor": "f113c423176de67543c5f8d55e18c5779506e3ab16d1f3122a4365f7d0301d40",
    "payload-tampered.cose": "0b16482599ab0209bbb2b7cb605e71ab8df823cd865c1c172727ecad239503d1",
    "tampered-statement.cose": "075797b10f73d15f699f907c2ac7150ab87b4afe8d979238d650d497982cec2a",
    "appended-receipt.cose": "871109cfb997a19187df71106c7507abb39171194bf88a722dbdee0f0bdeb56c",
    "nested-sign1.cose": "9f04814fd5d21c4e921c72369d3b68ed01cdeef4dfed00965160dd56c88c42c1",
    "uvm_0.2.10.cose": "f4f5321316ac3cf876292f41cb7bdcd1056aef3a815fb137887a4ef93c3210bc",
    "esrp-cts-db.json": "295b5824129179cb6a0699b2759ce408c0fe13b364e7a59ad226a68f7265a490",
    "cts-hashv-cwtclaims-b64url.cose": "213105fdc0da9022c20e8f49195d0bb621cedf87fdee29aad80e2e605af94c87",
}
MST = "mst-test-scitt-verifier.confidential-ledger.azure.com"


def _files():
    if not FETCHED.is_dir():
        pytest.skip("NOT MEASURABLE here: run tools/scitt_ccf_external/fetch_external.py first")
    out = {}
    for name, digest in PINS.items():
        p = FETCHED / name
        if not p.is_file():
            pytest.skip(f"NOT MEASURABLE here: {name} has not been fetched")
        raw = p.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, f"{name} is not the pinned file"
        out[name] = raw
    return out


def _mst(f):
    return {"scitt_ccf_services": {MST: S.load_cose_keyset(f["mst-test-scitt-keys.cbor"])}}


def _receipts(f, name, rp):
    return [c.status for c in S.verify_transparent_statement(f[name], canonical_root=b"\x00" * 32,
                                                              rp_trust=rp).receipts]


def test_real_receipts_of_the_test_service():
    f = _files()
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


def test_real_data_hashes_equal_the_upstream_pin_and_the_leaf():
    f = _files()
    assert S.recompute_data_hash(f["transparent-statement.cose"]).hex() == \
        "6f7607e4d68fd01298c47897357a093944de8c033c99bbb3284b8243aa0e6d11"
    r = S.verify_transparent_statement(f["transparent-statement.cose"], canonical_root=b"\x00" * 32,
                                       rp_trust=_mst(f))
    assert r.receipts[0].merkle_root.hex() == "c8dee06dcaa9268cd2910ca78d24a18490789a9d24acba96534dfe8f3b788c14"


def test_real_production_receipt_over_a_hash_envelope():
    import json
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    f = _files()
    store = json.loads(f["esrp-cts-db.json"])
    keys = [x509.load_der_x509_certificate(decode_b64(p["serviceCertificate"])).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for p in store["parameters"]]
    rp = {"scitt_ccf_services": {"esrp-cts-db.confidential-ledger.azure.com": keys}}
    r = S.verify_transparent_statement(f["uvm_0.2.10.cose"], canonical_root=b"\x00" * 32, rp_trust=rp)
    assert [c.status for c in r.receipts] == ["confirmed"]
    assert r.receipts[0].kid_bound_to_key is True and r.receipts[0].receipt_iat == 1766437888
    assert r.status == "outside_profile" and "-16" in r.detail          # SHA-384 envelope, not v1
    assert S.recompute_data_hash(f["uvm_0.2.10.cose"]).hex().startswith("a60138fb1591")


def test_real_forms_v1_refuses():
    f = _files()
    assert S.verify_transparent_statement(f["nested-sign1.cose"], canonical_root=b"\x00" * 32,
                                          rp_trust=_mst(f)).status == "malformed"      # nested tag 18
    assert _receipts(f, "cts-hashv-cwtclaims-b64url.cose", _mst(f)) == ["malformed"]  # legacy receipt
