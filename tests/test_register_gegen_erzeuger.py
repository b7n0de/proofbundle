"""Das SIGNIERTE Register wird mit seinem ERZEUGER verglichen — die dritte Zahl im Umlauf.

DIE KLASSE, und sie ist dieselbe wie bei den zwei Nachbarn, eine Ebene hoeher. Am 2026-09-08
entstand ``tests/test_register_population_gegen_restrisiko.py``, weil drei Dokumente zwei Zahlen
fuehrten und keines das andere ansah. Der Riegel schloss die Luecke zwischen ``RESTRISIKO_600.md``
und ``scripts/gen_findings_register.py::FINDINGS``.

Gemessen am 2026-09-12 stand die naechste Luecke daneben, ungemessen:

    RESTRISIKO_600.md                                    N1..N21
    scripts/gen_findings_register.py::FINDINGS           N1..N21   (seit Commit 5a301d5)
    audit_artifacts/findings_register_361.json           N1..N20   (seit Commit 8d34f2a)

Der Erzeuger und das ERZEUGTE gingen auseinander, und ueber alle Register-Tests des Zweigs
ausgezaehlt las KEINER beide: zwei lesen nur den Erzeuger, zwei nur das signierte Artefakt.

WARUM DAS AM TOR NICHT AUFFAELLT — dieselbe Mechanik, die der Nachbar beschreibt: ``C12.2`` zaehlt
OFFENE ``P0``/``P1`` im signierten Register. Ein Fund, der dort GAR NICHT STEHT, kann nicht offen
sein. Die fehlende Zeile ist fuer diese Pruefung unsichtbar, egal wie gross die Luecke wird.

RICHTUNG DES URTEILS, bewusst asymmetrisch wie bei beiden Nachbarn: ein Fund im ERZEUGER, der im
signierten Artefakt FEHLT, ist ein Fehler — das Artefakt behauptet dann eine Vollstaendigkeit, die
es nicht hat, und es ist das Artefakt, das entscheidet. Umgekehrt ist ein Eintrag im Artefakt ohne
Gegenstueck im Erzeuger KEIN Fehler dieses Tests: er kann aus einer aelteren, gueltig signierten
Fassung stammen. Er wird gemeldet.

WAS DIESER TEST NICHT TUT: er verlangt keine Neusignatur. Das Register kann nur der Owner
signieren (schluessellose emit/assemble-Form, die private Haelfte liegt am Mac). Der Test sagt,
DASS die beiden auseinander sind, und nennt die Differenz — was daraus folgt, entscheidet der
Owner. Ein Riegel, der eine Owner-Handlung erzwingen wollte, waere an der falschen Stelle.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ERZEUGER = REPO / "scripts" / "gen_findings_register.py"
ARTEFAKT = REPO / "audit_artifacts" / "findings_register_361.json"


def _erzeuger_ids() -> tuple[set[str], str]:
    if not ERZEUGER.is_file():
        pytest.skip("scripts/gen_findings_register.py liegt hier nicht")
    spec = importlib.util.spec_from_file_location("_gen_vergleich", str(ERZEUGER))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_gen_vergleich"] = mod
    spec.loader.exec_module(mod)
    return {str(f["id"]) for f in mod.FINDINGS}, str(mod.VERSION)


def _artefakt_ids() -> tuple[set[str], str]:
    if not ARTEFAKT.is_file():
        pytest.skip("audit_artifacts/findings_register_361.json liegt hier nicht")
    d = json.loads(ARTEFAKT.read_text(encoding="utf-8"))
    return {str(f.get("id")) for f in d.get("findings", [])}, str(d.get("version"))


def _nr(s: str) -> int:
    ziffern = "".join(c for c in s if c.isdigit())
    return int(ziffern) if ziffern else 0


def test_kein_fund_des_erzeugers_fehlt_im_signierten_register():
    """Die Frage, die bisher zwischen den beiden Riegeln hindurchfiel."""
    erz, erz_v = _erzeuger_ids()
    art, art_v = _artefakt_ids()
    assert erz, "der Erzeuger fuehrt keine Funde — der Test misst dann nichts"
    fehlend = sorted(erz - art, key=_nr)
    assert not fehlend, (
        f"{len(fehlend)} Fund(e) stehen in scripts/gen_findings_register.py::FINDINGS, aber NICHT "
        f"im signierten Register audit_artifacts/findings_register_361.json: {fehlend}.\n"
        f"  Erzeuger  : {len(erz)} Funde, version {erz_v}\n"
        f"  Artefakt  : {len(art)} Funde, version {art_v}\n"
        f"Das signierte Artefakt entscheidet (C12.2 zaehlt offene P0/P1 DARIN), und eine fehlende "
        f"Zeile kann dort nicht offen sein — die Luecke ist fuer das Tor unsichtbar.\n"
        f"AUFLOESUNG: das Register neu erzeugen und vom Owner signieren lassen (emit/assemble, die "
        f"private Schluesselhaelfte liegt am Mac). Dieser Test erzwingt das nicht und kann es "
        f"nicht; er sagt nur, dass die beiden auseinander sind.")


def test_die_versionen_der_beiden_stimmen_ueberein():
    """Zwei Populationen ueber verschiedene Fassungen zu vergleichen misst nichts."""
    _, erz_v = _erzeuger_ids()
    _, art_v = _artefakt_ids()
    assert erz_v == art_v, (
        f"Erzeuger spricht ueber {erz_v!r}, das signierte Artefakt ueber {art_v!r}. Ein "
        f"Populationsvergleich ueber zwei Fassungen hinweg ist keine Aussage — erst die Bindung "
        f"macht die Differenz lesbar.")


def test_eintraege_nur_im_artefakt_werden_gemeldet_nicht_bestraft(capsys):
    """Die Gegenrichtung: gemeldet, nicht rot.

    Ein Eintrag im signierten Artefakt ohne Gegenstueck im Erzeuger kann aus einer aelteren,
    gueltig signierten Fassung stammen. Ihn durchfallen zu lassen wuerde erzwingen, dass beide
    Dokumente deckungsgleich gehalten werden — mehr, als die Sache verlangt, und die Art
    Ueberbindung, die spaeter jemand mit einer Ausnahme aufweicht.
    """
    erz, _ = _erzeuger_ids()
    art, _ = _artefakt_ids()
    nur_artefakt = sorted(art - erz, key=_nr)
    if nur_artefakt:
        print(f"HINWEIS, kein Fehler: {len(nur_artefakt)} Eintrag/Eintraege stehen nur im "
              f"signierten Artefakt: {nur_artefakt}")
    assert True
