"""The 6.4.0 producer's cross-check, held offline to its stored bytes.

tools/scitt_ccf_external/producer_crosscheck.json was written by producer_crosscheck.py against a local
scitt-ccf-ledger and microsoft/scitt-verifier at bd6fb8ba (a foreign tool). These cases need neither:
they re-read the stored Transparent Statement with the stored service key set and statement key, and
hold the recorded verdicts of the foreign tool and the ledger to what the file says.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cbor2") is None or importlib.util.find_spec("rfc8785") is None,
    reason="needs the [scitt] extra and the RFC 8785 canonicalizer")

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "tools" / "scitt_ccf_external" / "producer_crosscheck.json"


def _doc() -> dict:
    return json.loads(DOC.read_text(encoding="utf-8"))


def _root() -> bytes:
    from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
    bundle = json.loads((REPO / "examples" / "example_bundle.json").read_text(encoding="utf-8"))
    return receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})


def test_the_target_is_the_example_bundles_anchor_root():
    assert bytes.fromhex(_doc()["target"]["receipt_canonical_root"]) == _root()


def test_the_returned_es256_statement_confirms_offline_under_the_stored_trust():
    from proofbundle import scitt_ccf as S  # noqa: PLC0415
    from proofbundle.scitt_statement import check_signed_statement  # noqa: PLC0415
    d = _doc()
    es = d["statements"]["es256"]
    served = bytes.fromhex(es["ledger"]["returned_statement_hex"])
    spki = bytes.fromhex(es["statement_key_spki_hex"])
    trust = {"scitt_ccf_services": {es["ledger"]["service_issuer"]:
                                    S.load_cose_keyset(bytes.fromhex(d["service_keyset_hex"]))},
             "scitt_statement_keys": [spki]}
    r = S.verify_transparent_statement(served, canonical_root=_root(), rp_trust=trust)
    assert (r.status, r.readable, r.signature_valid, r.profile_satisfied) == ("confirmed", True, True, True)
    c = check_signed_statement(served, canonical_root=_root(), statement_keys=[spki], rp_trust=trust)
    assert (c.status, c.registration) == ("confirmed", "confirmed")


def test_the_ledger_returned_the_submitted_statement_with_only_receipts_added():
    from proofbundle import scitt_ccf as S  # noqa: PLC0415
    es = _doc()["statements"]["es256"]
    sent = S.decode_cose_sign1(bytes.fromhex(es["statement_hex"]))
    back = S.decode_cose_sign1(bytes.fromhex(es["ledger"]["returned_statement_hex"]))
    assert (back.protected_raw, back.payload, back.signature) == (sent.protected_raw, sent.payload, sent.signature)
    assert sent.unprotected == {} and list(back.unprotected) == [394]


def test_the_recorded_verdicts():
    d = _doc()
    assert d["foreign_tool"]["commit"] == "bd6fb8ba79dbb521257b7f09682c03c6681dc3d0"
    es, ed = d["statements"]["es256"], d["statements"]["eddsa"]
    assert es["returned"]["v1_reader"]["status"] == "confirmed"
    assert es["returned"]["proofbundle_verify"]["exit_code"] == 0
    assert "SCITT-REGISTRATION: CONFIRMED (confirmed)" in es["returned"]["proofbundle_verify"]["stdout"]
    sv = es["returned"]["scitt_verifier"]
    assert (sv["verdict"], sv["exit_code"], sv["errors"]) == ("statement-transparent", 0, [])
    assert sv["signed_statement"]["signatureValid"] is True and sv["receipts"][0]["bound"] is True
    # the EdDSA default: confirmed by the producer's own check, outside the v1 reader (owner answer N7 b),
    # not evaluated by scitt-verifier, and refused by this ledger, which requires an x5chain
    assert ed["offline"]["check_signed_statement"]["status"] == "confirmed"
    assert ed["offline"]["v1_reader_statement_signature"] == ["outside_profile", None]
    assert ed["offline"]["scitt_verifier_on_the_signed_statement"]["signed_statement"]["signatureValid"] is None
    assert ed["ledger"]["accepted"] is False and "must contain an x5chain" in ed["ledger"]["error"]
