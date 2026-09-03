"""Die totale Grenze `verify_anchor` laesst keine rohe Ausnahme aus fremdem Verifier-Ergebnis.

ANLASS (2026-09-03, Phase 2 des Zweischicht-Vertrags, Schritte 2 und 6). Am Stand 621b049 stand der
Verifier-Aufruf im `try`, aber `res.get(...)` DAHINTER. Ausfuehrbar belegt: ein registrierter
Verifier mit `return None` liess `AttributeError: 'NoneType' object has no attribute 'get'` aus
`verify_anchor` austreten.

Invariante I1 des Reviews verbietet das: kein roher Fehler aus einer totalen Verify-Grenze. Der
Plugin-Vertrag in docs/ANCHORS.md verlangt vom Fremdverifier ein Mapping mit {"ok", "detail"} —
wer das nicht liefert, ist selbst der Defekt, aber ein Plugin-Defekt darf die Grenze nicht
durchbrechen.

DAZU I3: `MappingProxyType` MUSS als `frozen` akzeptiert werden. Der vorherige
`isinstance(_frozen, dict)` verwarf ihn STILL auf `{}` — gemessen ist MappingProxyType nicht
isinstance(dict), aber sehr wohl isinstance(Mapping). Ein read-only frozen-Block waere also nie
beim Verifier angekommen, und zwar ohne jede Meldung.
"""
from __future__ import annotations

import base64
import hashlib
from collections import OrderedDict
from types import MappingProxyType

import pytest

from proofbundle import anchors

ROOT = hashlib.sha256(b"never-raise-contract").digest()


def _anker(typ: str, **extra) -> dict:
    a = {"type": typ, "target": "receipt",
         "canonicalRoot": base64.b64encode(ROOT).decode(),
         "proof": base64.b64encode(b"proof").decode()}
    a.update(extra)
    return a


def _verify(a: dict) -> dict:
    return anchors.verify_anchor(a, target_roots={"receipt": ROOT}, now=None, rp_trust=None)


@pytest.mark.parametrize("rueckgabe,name", [
    (None, "None"), ([], "list"), (42, "int"), ("ok", "str"), (object(), "object"),
])
def test_ein_verifier_mit_falscher_rueckgabeform_bricht_die_grenze_nicht(rueckgabe, name, request):
    """Kein roher Fehler, sondern ein strukturiertes FAIL, dessen Grund die FORM benennt."""
    typ = f"formtest-{request.node.callspec.id}"
    anchors.register_anchor_type(typ, lambda p, c, *, frozen, now, _r=rueckgabe: _r)
    r = _verify(_anker(typ))
    assert r["ok"] is False, r
    assert "non-mapping" in r["detail"], (
        f"der Grund muss die FORM benennen, nicht schlechte Evidenz suggerieren: {r['detail']!r}"
    )
    assert name.lower() in r["detail"].lower() or type(rueckgabe).__name__ in r["detail"], r["detail"]


def test_ein_werfender_verifier_bleibt_gefangen():
    """Die bestehende Zusage darf durch den neuen Zweig nicht verloren gehen."""
    def wirft(p, c, *, frozen, now):
        raise RuntimeError("kaputt")
    anchors.register_anchor_type("werfer-testtyp", wirft)
    r = _verify(_anker("werfer-testtyp"))
    assert r["ok"] is False and "fail-closed" in r["detail"], r


def test_ein_gueltiges_mapping_geht_weiterhin_durch():
    """Gegenrichtung: die Formpruefung darf gueltige Ergebnisse nicht abweisen."""
    anchors.register_anchor_type("gut-testtyp", lambda p, c, *, frozen, now: {"ok": True, "detail": "verifiziert"})
    r = _verify(_anker("gut-testtyp"))
    assert r["ok"] is True and r["detail"] == "verifiziert", r


@pytest.mark.parametrize("bauer,name", [
    (lambda: {"quelle": "tsa"}, "dict"),
    (lambda: OrderedDict(quelle="tsa"), "OrderedDict"),
    (lambda: MappingProxyType({"quelle": "tsa"}), "MappingProxyType"),
])
def test_I3_jeder_Mapping_typ_erreicht_den_verifier(bauer, name):
    """I3 woertlich: Mapping statt konkretem dict, MappingProxyType und OrderedDict werden
    akzeptiert. Vorher fiel genau MappingProxyType still auf {}."""
    gesehen: dict = {}

    def merkt(p, c, *, frozen, now):
        gesehen["frozen"] = dict(frozen)
        return {"ok": True, "detail": "x"}

    typ = f"frozentest-{name}"
    anchors.register_anchor_type(typ, merkt)
    _verify(_anker(typ, frozen=bauer()))
    assert gesehen.get("frozen") == {"quelle": "tsa"}, (
        f"{name}: der frozen-Block kam beim Verifier nicht an — er wurde still verworfen"
    )


@pytest.mark.parametrize("wert", [None, "text", ["a"], 7])
def test_ein_NICHT_mapping_frozen_wird_weiterhin_auf_leer_normalisiert(wert):
    """Gegenrichtung zu I3: die Oeffnung auf Mapping darf keinen falschen Typ durchlassen. Ein
    Verifier soll nie ein str oder eine Liste als frozen sehen."""
    gesehen: dict = {}

    def merkt(p, c, *, frozen, now):
        gesehen["frozen"] = frozen
        return {"ok": True, "detail": "x"}

    typ = f"frozenbad-{type(wert).__name__}"
    anchors.register_anchor_type(typ, merkt)
    _verify(_anker(typ, frozen=wert))
    assert gesehen.get("frozen") == {}, f"{wert!r} haette auf {{}} normalisiert werden muessen"
