"""Ein behaupteter Hash ohne Bytes ist nicht messbar — kein TypeError, kein erfundener Befund.

GEMESSEN 04.09.2026. mypy in der CI von PR 185 meldete an zwei Stellen
`Unsupported operand types for in ("str | None" and "str")`; zur Laufzeit nachgestellt:
`check_on_receipt` mit `request_bytes="req"` (str statt bytes) und einem Beleg, der
`request_hash` behauptet, fiel mit `TypeError: 'in <string>' requires string as left operand,
not NoneType`. Die Regressionsklammer aus 6ac2041 deckte nur Belege OHNE Hash-Behauptung; die
Kombination "behauptet, aber Bytes vom falschen Typ" hatte niemand gefahren. Der Typpruefer sah
sie, der Fuzz nicht.

Dieser Test war auf dem alten Code ROT (rohe Ausnahme), nicht erst nach einem Mutanten.
"""
from __future__ import annotations

import warnings

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from proofbundle.experimental import attested_inference as ai

_BELEG = {"provider": "x", "nonce": "n0nce", "request_hash": "deadbeef", "response_hash": "cafe",
          "signed": {"nonce": "n0nce"}}
_KAPUTT = ["req", None, 5, [], {}, 1.5]


def _lauf(request_bytes, response_bytes):
    return ai.check_on_receipt(dict(_BELEG), provider="x", nonce="n0nce",
                               request_bytes=request_bytes, response_bytes=response_bytes)


def test_kontrolle_mit_bytes_werden_beide_hashes_gemessen():
    r = _lauf(b"req", b"res")
    assert ai.REASON_REQUEST_HASH in r["reasons"] and ai.REASON_RESPONSE_HASH in r["reasons"]
    assert ai.REASON_BYTES_NOT_BYTES not in r["not_measurable"]


@pytest.mark.parametrize("kaputt", _KAPUTT, ids=[type(k).__name__ for k in _KAPUTT])
def test_behaupteter_hash_ohne_bytes_ist_nicht_messbar_und_wirft_nicht(kaputt):
    r = _lauf(kaputt, kaputt)
    assert ai.REASON_BYTES_NOT_BYTES in r["not_measurable"]
    for achse in (ai.REASON_REQUEST_HASH, ai.REASON_RESPONSE_HASH):
        assert achse in r["not_measurable"], achse
        assert achse not in r["reasons"], "eine Ablehnung ueber Ungemessenes"


@pytest.mark.parametrize("kaputt", _KAPUTT, ids=[type(k).__name__ for k in _KAPUTT])
def test_eine_kaputte_achse_nimmt_der_anderen_nicht_die_messung(kaputt):
    r = _lauf(b"req", kaputt)
    assert ai.REASON_REQUEST_HASH in r["reasons"], "die Anfrage war messbar und stimmt nicht"
    assert ai.REASON_RESPONSE_HASH in r["not_measurable"]
    assert ai.REASON_RESPONSE_HASH not in r["reasons"]
    r2 = _lauf(kaputt, b"res")
    assert ai.REASON_RESPONSE_HASH in r2["reasons"]
    assert ai.REASON_REQUEST_HASH in r2["not_measurable"]


def test_ohne_behauptung_bleibt_die_achse_nicht_messbar_wie_bisher():
    beleg = {"provider": "x", "nonce": "n0nce", "signed": {"nonce": "n0nce"}}
    r = ai.check_on_receipt(beleg, provider="x", nonce="n0nce", request_bytes=b"a", response_bytes=b"b")
    assert ai.REASON_REQUEST_HASH in r["not_measurable"]
    assert ai.REASON_REQUEST_HASH not in r["reasons"]
