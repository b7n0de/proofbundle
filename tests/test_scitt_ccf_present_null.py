"""A present key with the value null is not an absent key (Nachtrag 3 to Z332). Needs the [scitt] extra.

The -05 CDDL maps vdp (396) to a map and its -1 and -2 to arrays of one or more proofs; RFC 9052
gives crit (2) a non-empty array of labels; a COSE_Key's kid (2) is a byte string. A present key
whose value is null violates each of these, so the reader refuses it with the status a wrong value
gets there, and never reads it as the key being absent. The receipts are the committed local-ledger
vector (tests/fixtures/scitt_ccf/local_ledger_consistency.json); only its unprotected headers are
changed, which the service's signatures do not cover, except where a case signs anew.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

from proofbundle import scitt_ccf as S  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402

VECTOR = Path(__file__).resolve().parent / "fixtures" / "scitt_ccf" / "local_ledger_consistency.json"
OTHER = ec.generate_private_key(ec.SECP384R1())


def _cbor2():
    import cbor2
    return cbor2


def _fixture():
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    rp = {"scitt_ccf_services": {v["issuer"]: S.load_cose_keyset(decode_b64(v["service_keyset_b64"]))},
          "scitt_statement_keys": [decode_b64(v["statement_signer_spki_b64"])]}
    return v, rp


def _statement(v, *, receipt_unprot=None, prot_extra=None) -> bytes:
    cbor2 = _cbor2()
    prot, unprot, payload, sig = cbor2.loads(decode_b64(v["states"]["older"]["transparent_statement_b64"])).value
    r_prot, r_unprot, r_payload, r_sig = cbor2.loads(unprot[394][0]).value
    r_unprot = dict(r_unprot)
    if receipt_unprot is not None:
        r_unprot = receipt_unprot(r_unprot)
    unprot = {**dict(unprot), 394: [b"\xd2" + cbor2.dumps([r_prot, r_unprot, r_payload, r_sig])]}
    if prot_extra is not None:
        prot = cbor2.dumps({**cbor2.loads(prot), **prot_extra})
    return b"\xd2" + cbor2.dumps([prot, unprot, payload, sig])


def _inclusion(v, rp, **kw) -> tuple:
    r = S.verify_transparent_statement(_statement(v, **kw), canonical_root=bytes.fromhex(v["canonical_root_hex"]),
                                       rp_trust=rp)
    return r.status, tuple(c.status for c in r.receipts)


def _vdp(extra):
    return lambda u: {**u, 396: {**dict(u[396]), **extra}}


def _consistency(v, rp, unprot, *, prot=None, key=None) -> str:
    """The service's COSE_Sign1 over R_24 with this unprotected header; with prot, signed anew by key."""
    cbor2 = _cbor2()
    older = S.verify_transparent_statement(_statement(v), canonical_root=bytes.fromhex(v["canonical_root_hex"]),
                                           rp_trust=rp).receipts[0]
    n_prot, _u, _p, n_sig = cbor2.loads(decode_b64(v["newer_receipt_b64"])).value
    if prot is not None:
        n_prot = cbor2.dumps(prot)
        newer = bytes.fromhex(v["states"]["newer"]["root_hex"])
        r, s = utils.decode_dss_signature(key.sign(cbor2.dumps(["Signature1", n_prot, b"", newer]),
                                                   ec.ECDSA(hashes.SHA384())))
        n_sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        rp = {"scitt_ccf_services": {v["issuer"]: [{"spki": spki, "kid": prot[4]}]}}
    raw = b"\xd2" + cbor2.dumps([n_prot, unprot, None, n_sig])
    return S.verify_consistency_receipt(raw, older_root=older.merkle_root, older_issuer=older.issuer,
                                        rp_trust=rp, older_size=19).status


def _p1924(v):
    return decode_b64(v["proofs_b64"]["19->24"])


# ------------------------------------------------------------------------------------------------
# vdp and the proof families of an inclusion receipt (_receipt)
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("change, status", [
    (None, ("confirmed", ("confirmed",))),
    (lambda u: {**u, 396: None}, ("malformed", ("malformed",))),
    (_vdp({-1: None}), ("malformed", ("malformed",))),
    (_vdp({-2: None}), ("malformed", ("malformed",))),
], ids=["control", "vdp-null", "inclusion-null", "consistency-null"])
def test_an_inclusion_receipt_refuses_a_present_null_in_vdp(change, status):
    v, rp = _fixture()
    assert _inclusion(v, rp, receipt_unprot=change) == status


# ------------------------------------------------------------------------------------------------
# vdp and the proof families of a consistency receipt (verify_consistency_receipt)
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("unprot, status", [
    (lambda p: {396: {-2: [p]}}, "confirmed"),
    (lambda p: {396: None}, "malformed"),
    (lambda p: {396: {-2: [p], -1: None}}, "malformed"),
    (lambda p: {396: {-2: None}}, "malformed"),
    (lambda p: {}, "consistency_proof_missing"),                # absent vdp keeps its own status
], ids=["control", "vdp-null", "inclusion-null", "consistency-null", "vdp-absent"])
def test_a_consistency_receipt_refuses_a_present_null_in_vdp(unprot, status):
    v, rp = _fixture()
    assert _consistency(v, rp, unprot(_p1924(v))) == status


# ------------------------------------------------------------------------------------------------
# crit in a protected header (_crit_ok), statement and receipt
# ------------------------------------------------------------------------------------------------
def test_a_statement_refuses_a_present_null_crit():
    """Any change to the statement's protected header breaks its signature; the profile decides first,
    so an unknown label that is not crit reads statement_signature_invalid and a null crit
    outside_profile, as an empty crit already did."""
    v, rp = _fixture()
    assert _inclusion(v, rp, prot_extra={99: 1})[0] == "statement_signature_invalid"
    assert _inclusion(v, rp, prot_extra={2: []})[0] == "outside_profile"
    assert _inclusion(v, rp, prot_extra={2: None})[0] == "outside_profile"


def test_a_receipt_refuses_a_present_null_crit():
    v, rp = _fixture()
    cbor2 = _cbor2()
    prot = dict(cbor2.loads(cbor2.loads(decode_b64(v["newer_receipt_b64"])).value[0]))
    unprot = {396: {-2: [_p1924(v)]}}
    assert _consistency(v, rp, unprot, prot=prot, key=OTHER) == "confirmed"
    assert _consistency(v, rp, unprot, prot={**prot, 2: None}, key=OTHER) == "outside_profile"
    assert _consistency(v, rp, unprot, prot={**prot, 2: []}, key=OTHER) == "outside_profile"


# ------------------------------------------------------------------------------------------------
# kid in a COSE_Key of a relying party's key set (load_cose_keyset)
# ------------------------------------------------------------------------------------------------
def test_a_cose_key_with_a_present_null_kid_is_dropped_like_any_malformed_key():
    v, _rp = _fixture()
    cbor2 = _cbor2()
    key = dict(cbor2.loads(decode_b64(v["service_keyset_b64"]))[0])
    absent = {k: x for k, x in key.items() if k != 2}
    assert [bool(k["kid"]) for k in S.load_cose_keyset(cbor2.dumps([key]))] == [True]
    assert [k["kid"] for k in S.load_cose_keyset(cbor2.dumps([absent]))] == [None]     # absent: no kid
    assert S.load_cose_keyset(cbor2.dumps([{**key, 2: None}])) == []                   # null: not a kid
    assert S.load_cose_keyset(cbor2.dumps([{**key, 2: "text"}])) == []
    kept = S.load_cose_keyset(cbor2.dumps([{**key, 2: None}, key]))
    assert [hashlib.sha256(k["spki"]).hexdigest() == hashlib.sha256(kept[0]["spki"]).hexdigest() for k in kept] == [True]
