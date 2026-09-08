"""Der Schreiber des Budget-Achsen-Belegs darf keine ZWEITE Wahrheit erzeugen.

Der Beleg existiert wegen der Owner-Karte `OA-dc37e26295`: die Budget-Achse wird auf einem Bauhost
sichtbar uebersprungen, und damit sie nicht NIRGENDS mehr belegt ist, muss sie auf der
Referenzmaschine ins Release-Buendel. Ein Schreiber, der das Urteil NACHRECHNET statt es
aufzuzeichnen, waere dabei die gefaehrlichste Loesung: er koennte gruen melden, waehrend die
Zusicherung rot ist, und der Unterschied waere von aussen unsichtbar. Genau das wird hier gebunden.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest
from _pytest.outcomes import Skipped

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "_budget_axis", REPO / "scripts" / "budget_axis_measurement.py")
bam = importlib.util.module_from_spec(_spec)
sys.modules["_budget_axis"] = bam
_spec.loader.exec_module(bam)


class _Dim:
    def __init__(self, name, achsen=1):
        self.name = name
        self.was = "flaeche." + name
        self.achsen = achsen


def _falschmodul(urteil_je_achse: dict, marke: str = "", kombi_urteil: str = "BESTANDEN"):
    """Ein Ersatz fuer das Testmodul: dieselben Namen, gestellte Ausgaenge.

    KEIN echter Messlauf — der kostet auf der Referenzmaschine rund eine Minute je Aufruf, und was
    hier geprueft wird, ist der SCHREIBER, nicht die Messung.
    """
    m = types.SimpleNamespace()
    m.DIMENSIONEN = [_Dim(n) for n in urteil_je_achse]
    m.KOMBIS = [("a x b", 2, lambda: (None, {}))]
    m.GRENZE_S, m.EXPONENT_MAX, m.SPEICHER_GRENZE_BYTES = 1.0, 1.2, 32 * 1024 * 1024
    m.LATTE_AUS_DER_KLAMMER = "schnellstes_ende"
    m._REFERENZ_FARMER_S = (0.067, 0.068, 0.069)
    m._REFERENZ_HIER = [0.067, 0.068, 0.069]
    m._bauhost = lambda: marke
    m._referenz_werte = lambda: list(m._REFERENZ_HIER)
    m._maschinenfaktor = lambda w=None: 1.0
    m._faktor_spanne = lambda w=None: (1.0, 1.0)
    m._faktor_deckel = lambda ausser: 7.95
    m._messung = lambda dim: {
        "limit": 10, "kosten_am_limit_max": 0.5, "kosten_am_limit": 0.4,
        "referenz_klammer": list(m._REFERENZ_HIER), "exponent_zeit": 1.0,
        "exponent_arbeit": 1.0, "arbeit_empfindlich": True, "speicher_peak_am_limit": 1234,
    }
    m._kombi_messung = lambda name, bau: {"dauer_max": 1.0, "erreicht": {}, "speicher_peak": 99}

    def _mach(urteil):
        def ruf(*a, **k):
            if urteil == "GERISSEN":
                raise AssertionError("die Schranke laesst mehr zu, als sie zu begrenzen behauptet")
            if urteil == "UEBERSPRUNGEN":
                raise Skipped("UEBERSPRUNGEN (referenzmaschinengebunden, Owner-Karte OA-dc37e26295)")
        return ruf

    class _Einzel:
        def test_kosten_am_limit_unter_der_obergrenze(self, dim):
            _mach(urteil_je_achse[dim.name])()

    class _Kombi:
        def test_kombi_bleibt_unter_der_summe_der_obergrenzen(self, name, achsen, bau):
            _mach(kombi_urteil)()

    m.TestObergrenzeAmGroesstenZugelassenenWert = _Einzel
    m.TestKombinierteAchsen = _Kombi
    return m


def _messe_mit(monkeypatch, **kw):
    monkeypatch.setattr(bam, "_testmodul", lambda: _falschmodul(**kw))
    return bam.messe()


class TestDerSchreiberZeichnetAufUndRechnetNichtNach:
    def test_ein_gerissenes_urteil_erscheint_als_GERISSEN(self, monkeypatch):
        """DIE KERNBINDUNG. Waere das Urteil im Schreiber nachgerechnet, koennte er hier gruen
        melden — die Messwerte sind ja allesamt unauffaellig (0,5 s gegen eine Latte von 1,0 s).
        Nur weil er die ECHTE Zusicherung ruft, sieht er den Riss."""
        d = _messe_mit(monkeypatch, urteil_je_achse={"input_bytes": "GERISSEN",
                                                     "json_nodes": "BESTANDEN"})
        urteile = {a["name"]: a["urteil"] for a in d["achsen"]}
        assert urteile == {"input_bytes": "GERISSEN", "json_nodes": "BESTANDEN"}, (
            f"Der Schreiber meldet {urteile}. Die Messwerte sind unauffaellig (0,5 s gegen 1,0 s "
            f"Latte) — wer sie NACHRECHNET, kommt auf 'bestanden'. Nur der Aufruf der echten "
            f"Zusicherung sieht den Riss, und genau deshalb darf hier nichts nachgerechnet werden.")
        assert d["ok"] is False
        meldung = next(a["meldung"] for a in d["achsen"] if a["name"] == "input_bytes")
        assert "begrenzen behauptet" in meldung, (
            f"Die Meldung der gerissenen Zusicherung wird nicht mitgeschrieben ({meldung!r}) — "
            f"dann steht im Beleg ein Urteil ohne seinen Grund, und wer ihn liest, muss den "
            f"Testlauf noch einmal fahren, um zu erfahren, WAS gerissen ist.")

    def test_eine_uebersprungene_achse_ist_KEIN_erfolg(self, monkeypatch):
        """Ein Beleg, der Abstinenzen als Erfolg zaehlt, ist der stumme Riegel selbst — nur eine
        Ebene hoeher, und mit einer Unterschrift darunter."""
        d = _messe_mit(monkeypatch, urteil_je_achse={"input_bytes": "UEBERSPRUNGEN",
                                                     "json_nodes": "BESTANDEN"})
        assert d["achsen_uebersprungen"] == 1 and d["achsen_bestanden"] == 1
        assert d["ok"] is False, (
            "Eine uebersprungene Achse laesst ok=true. Dann traegt das Release-Buendel einen "
            "signierten Beleg, der eine Abstinenz als Messung ausgibt.")

    def test_auf_einem_BAUHOST_ist_es_keine_referenzmessung(self, monkeypatch):
        """Die Karte verlangt die Messung AUF DER REFERENZMASCHINE. Ein Beleg von einem Bauhost
        darf sich nicht als solcher ausgeben — und ein Leser muss es an der Datei selbst sehen,
        nicht am Ort, an dem er sie gefunden hat."""
        d = _messe_mit(monkeypatch, marke="GITHUB_ACTIONS",
                       urteil_je_achse={"input_bytes": "BESTANDEN", "json_nodes": "BESTANDEN"})
        assert d["bauhost_marke"] == "GITHUB_ACTIONS"
        assert d["ist_referenzmessung"] is False
        assert d["ok"] is False, (
            "Auf einem Bauhost meldet der Beleg ok=true. Selbst wenn dort jede Achse bestuende, "
            "waere das keine Referenzmessung — und die Karte verlangt ausdruecklich diese.")

    def test_der_beleg_nennt_die_karten_und_die_stellung_des_schalters(self, monkeypatch):
        """Ohne beides ist der Beleg nicht einzuordnen: dieselben Zahlen bedeuten unter `median`
        und unter `schnellstes_ende` verschiedene Latten."""
        d = _messe_mit(monkeypatch, urteil_je_achse={"input_bytes": "BESTANDEN"})
        assert "OA-dc37e26295" in d["owner_karten"] and "OA-133b901337" in d["owner_karten"]
        assert d["latte_aus_der_klammer"] == "schnellstes_ende"
        assert d["maschinenfaktor_schnellstes_ende"] == pytest.approx(1.0, rel=0.01)
        assert d["referenzlast_aufzeichnung_s"] and d["referenzlast_hier_s"], (
            "Beide Referenzreihen gehoeren in den Beleg — ohne sie ist der Faktor eine Zahl ohne "
            "Herkunft, und die Karte verlangt ausdruecklich 'keine getippte Zahl'.")

    def test_alles_gruen_auf_der_referenzmaschine_ergibt_ok(self, monkeypatch):
        """Die Gegenrichtung: ein Beleg, der NIE ok meldet, hat die Aussage abgeschafft statt sie
        eingegrenzt."""
        d = _messe_mit(monkeypatch, urteil_je_achse={"input_bytes": "BESTANDEN",
                                                     "json_nodes": "BESTANDEN"})
        assert d["ok"] is True and d["ist_referenzmessung"] is True
