"""Lauf 14, Linse L1, F1 (11.09.2026): `resolve_receipt_chain` las die DSSE-Payload mit rohem
`json.loads` statt mit `loads_strict` — dem einen Parse-Chokepoint, durch den JEDER Verifier dieses
Moduls geht (`verify_agent_review`, `verify_agent_review_v02`, `verify_agent_review_any`).

Gemessen am Kopf f6c5c8a, drei Formen, alle drei am ausgelieferten Wheel reproduziert:
  * 3000-fach verschachtelte `supersession` -> ein ROHER RecursionError entkam dem Aufloeser
    (die except-Klausel fing `ValueError, KeyError, TypeError`; RecursionError ist keines davon);
  * ein einsames Surrogat in `priorDigest.sha256` wurde ANGENOMMEN und ordnete die Kette
    (`corrected=['\\ud800AAAA']`), waehrend `loads_strict` dieselben Bytes abweist;
  * ein doppelter Schluessel `sha256` wurde last-wins gelesen (`BBBB`), statt abgewiesen (WP-C1).

Der Aufloeser ordnet, welches Receipt JETZT gilt. Bytes, die der Verifier als malformed ablehnt,
duerfen diese Ordnung nicht bestimmen — und ein unlesbarer Umschlag ist kein Schweigen, sondern
zaehlt gegen `integrity_ok` (dieselbe Regel wie `unaddressable`).
"""
from __future__ import annotations

import base64

import pytest

from proofbundle import agent_review as AR


def _env(text: str) -> dict:
    return {"payloadType": AR.INTOTO_STATEMENT_PAYLOAD_TYPE,
            "payload": base64.b64encode(text.encode("utf-8", "surrogatepass")).decode("ascii"),
            "signatures": [{"sig": "AA=="}]}


def test_tiefe_verschachtelung_ist_ein_verdikt_kein_recursionerror():
    tief = '{"predicate": {"supersession": ' + '{"a":' * 3000 + '1' + '}' * 3000 + '}}'
    e = _env(tief)
    d = AR.receipt_digest(e)
    try:
        k = AR.resolve_receipt_chain([e], verified={d})
    except RecursionError:  # pragma: no cover - genau der Fund
        pytest.fail("RecursionError entkommt resolve_receipt_chain roh (Lauf 14 L1 F1)")
    assert k["integrity_ok"] is False
    assert k["unaddressable"], "ein unlesbarer Umschlag muss benannt werden, nicht verschwiegen"


def test_einsames_surrogat_ordnet_die_kette_nicht():
    sur = '{"predicate":{"supersession":{"corrects":[{"priorDigest":{"sha256":"\ud800AAAA"}}]}}}'
    e = _env(sur)
    k = AR.resolve_receipt_chain([e], verified={AR.receipt_digest(e)})
    assert "\ud800AAAA" not in k["corrected"]
    assert k["integrity_ok"] is False
    assert k["unaddressable"]


def test_doppelter_schluessel_ist_nicht_last_wins():
    dup = '{"predicate":{"supersession":{"corrects":[{"priorDigest":{"sha256":"AAAA","sha256":"BBBB"}}]}}}'
    e = _env(dup)
    k = AR.resolve_receipt_chain([e], verified={AR.receipt_digest(e)})
    assert k["corrected"] == [], "WP-C1: ein doppelter Schluessel wird abgewiesen, nicht last-wins gelesen"
    assert k["integrity_ok"] is False


def test_positivkontrolle_ein_lesbarer_umschlag_bleibt_lesbar():
    e = _env('{"predicate": {"supersession": {}}}')
    d = AR.receipt_digest(e)
    k = AR.resolve_receipt_chain([e], verified={d})
    assert k["integrity_ok"] is True
    assert k["unaddressable"] == []
    assert k["current"] == d
